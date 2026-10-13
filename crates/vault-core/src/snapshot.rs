//! Encrypted database snapshot container (`vault.db`), format v1.
//!
//! | offset | len | field                                         |
//! |-------:|----:|-----------------------------------------------|
//! |      0 |   8 | magic `"USNADB\0\0"`                          |
//! |      8 |   2 | format version (`1`)                          |
//! |     10 |   2 | flags (must be `0`)                           |
//! |     12 |  16 | vault id                                      |
//! |     28 |   4 | vault-key generation                          |
//! |     32 |   8 | revision (u64, increases on every save)       |
//! |     40 |  24 | nonce (random)                                |
//! |     64 |   n | XChaCha20-Poly1305(database subkey) of padded |
//! |        |     | plaintext, then 16-byte tag                   |
//!
//! Padded plaintext = `u64_le(len) || data || zeros`, padded to a multiple of 4096 bytes so the file
//! size reveals only a coarse size bucket. Bytes `0..40` are AAD (after a domain label), so the
//! generation, vault id and revision cannot be altered without detection. The container does not
//! interpret the plaintext. See docs/VAULT_FORMAT.md §5.

use zeroize::Zeroizing;

use crate::{
    aead,
    error::{Error, Result},
    header::FORMAT_VERSION,
    keys::KeySet,
    rng,
};

/// Magic bytes at the start of `vault.db`.
pub const SNAPSHOT_MAGIC: [u8; 8] = *b"USNADB\0\0";
const PREFIX_LEN: usize = 40;
const PAD: usize = 4096;
const AAD_SNAPSHOT: &[u8] = b"USNA Secure v1/snapshot";

/// Cleartext facts about a snapshot (these are not secret and are used for crash recovery).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SnapshotInfo {
    /// Format version.
    pub format_version: u16,
    /// Vault id the snapshot claims to belong to (unauthenticated until opened).
    pub vault_id: [u8; 16],
    /// Vault-key generation the snapshot claims to be sealed under (unauthenticated until opened).
    pub vk_generation: u32,
    /// Revision counter (unauthenticated until opened).
    pub revision: u64,
}

/// Structurally validate a snapshot and read its cleartext fields. Does not authenticate.
pub fn inspect_snapshot(bytes: &[u8]) -> Result<SnapshotInfo> {
    let overhead = PREFIX_LEN + aead::NONCE_LEN + aead::TAG_LEN;
    if bytes.len() < overhead + PAD {
        return Err(Error::MalformedSnapshot("too short"));
    }
    if (bytes.len() - overhead) % PAD != 0 {
        return Err(Error::MalformedSnapshot(
            "length is not a multiple of the padding unit",
        ));
    }
    if bytes[0..8] != SNAPSHOT_MAGIC[..] {
        return Err(Error::BadMagic);
    }
    let version = u16::from_le_bytes([bytes[8], bytes[9]]);
    if version != FORMAT_VERSION {
        return Err(Error::UnsupportedVersion(version));
    }
    if bytes[10] != 0 || bytes[11] != 0 {
        return Err(Error::MalformedSnapshot("reserved flags set"));
    }
    let mut vault_id = [0u8; 16];
    vault_id.copy_from_slice(&bytes[12..28]);
    let vk_generation = u32::from_le_bytes([bytes[28], bytes[29], bytes[30], bytes[31]]);
    let mut rev = [0u8; 8];
    rev.copy_from_slice(&bytes[32..40]);
    Ok(SnapshotInfo {
        format_version: version,
        vault_id,
        vk_generation,
        revision: u64::from_le_bytes(rev),
    })
}

fn pad(plaintext: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    let len = u64::try_from(plaintext.len()).map_err(|_| Error::TooLarge)?;
    let unpadded = plaintext.len().checked_add(8).ok_or(Error::TooLarge)?;
    let total = unpadded
        .div_ceil(PAD)
        .checked_mul(PAD)
        .ok_or(Error::TooLarge)?;
    let mut buf = Zeroizing::new(Vec::with_capacity(total));
    buf.extend_from_slice(&len.to_le_bytes());
    buf.extend_from_slice(plaintext);
    buf.resize(total, 0);
    Ok(buf)
}

fn unpad(inner: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    if inner.len() < 8 {
        return Err(Error::MalformedSealed("snapshot payload too short"));
    }
    let (head, body) = inner.split_at(8);
    let mut l = [0u8; 8];
    l.copy_from_slice(head);
    let len = usize::try_from(u64::from_le_bytes(l))
        .map_err(|_| Error::MalformedSealed("snapshot length"))?;
    if len > body.len() {
        return Err(Error::MalformedSealed("snapshot length exceeds payload"));
    }
    let (data, padding) = body.split_at(len);
    if padding.iter().any(|b| *b != 0) {
        return Err(Error::MalformedSealed("non-zero snapshot padding"));
    }
    Ok(Zeroizing::new(data.to_vec()))
}

fn encode_prefix(vault_id: &[u8; 16], generation: u32, revision: u64) -> [u8; PREFIX_LEN] {
    let mut p = [0u8; PREFIX_LEN];
    p[0..8].copy_from_slice(&SNAPSHOT_MAGIC);
    p[8..10].copy_from_slice(&FORMAT_VERSION.to_le_bytes());
    p[12..28].copy_from_slice(vault_id);
    p[28..32].copy_from_slice(&generation.to_le_bytes());
    p[32..40].copy_from_slice(&revision.to_le_bytes());
    p
}

fn aad(prefix: &[u8]) -> Vec<u8> {
    let mut a = Vec::with_capacity(AAD_SNAPSHOT.len() + prefix.len());
    a.extend_from_slice(AAD_SNAPSHOT);
    a.extend_from_slice(prefix);
    a
}

impl KeySet {
    pub(crate) fn seal_snapshot_with_nonce(
        &self,
        revision: u64,
        plaintext: &[u8],
        nonce: &[u8; aead::NONCE_LEN],
    ) -> Result<Vec<u8>> {
        let prefix = encode_prefix(&self.vault_id, self.generation, revision);
        let inner = pad(plaintext)?;
        let ct = aead::encrypt_with_nonce(&self.subkeys.database, nonce, &aad(&prefix), &inner)?;
        let mut out = Vec::with_capacity(PREFIX_LEN + aead::NONCE_LEN + ct.len());
        out.extend_from_slice(&prefix);
        out.extend_from_slice(nonce);
        out.extend_from_slice(&ct);
        Ok(out)
    }

    pub(crate) fn seal_snapshot(&self, revision: u64, plaintext: &[u8]) -> Result<Vec<u8>> {
        let nonce = rng::array::<{ aead::NONCE_LEN }>()?;
        self.seal_snapshot_with_nonce(revision, plaintext, &nonce)
    }

    pub(crate) fn open_snapshot(&self, blob: &[u8]) -> Result<(u64, Zeroizing<Vec<u8>>)> {
        let info = inspect_snapshot(blob)?;
        if info.vault_id != self.vault_id {
            return Err(Error::SnapshotMismatch("vault id differs"));
        }
        if info.vk_generation != self.generation {
            return Err(Error::SnapshotMismatch("vault key generation differs"));
        }
        let (prefix, rest) = blob.split_at(PREFIX_LEN);
        let (n, ct) = rest.split_at(aead::NONCE_LEN);
        let mut nonce = [0u8; aead::NONCE_LEN];
        nonce.copy_from_slice(n);
        let inner = aead::decrypt_with_nonce(&self.subkeys.database, &nonce, &aad(prefix), ct)?;
        Ok((info.revision, unpad(&inner)?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{secret::SecretKey, test_vectors as kat};
    use sha2::{Digest, Sha256};

    fn keyset() -> KeySet {
        let vk = SecretKey::from_slice(&hex::decode(kat::VK).unwrap()).unwrap();
        KeySet::new(
            &vk,
            hex::decode(kat::VAULT_ID).unwrap().try_into().unwrap(),
            1,
        )
        .unwrap()
    }

    #[test]
    fn snapshot_known_answer() {
        let nonce: [u8; 24] = hex::decode(kat::SNAPSHOT_NONCE)
            .unwrap()
            .try_into()
            .unwrap();
        let blob = keyset()
            .seal_snapshot_with_nonce(kat::SNAPSHOT_REVISION, kat::SNAPSHOT_PLAINTEXT, &nonce)
            .unwrap();
        assert_eq!(blob.len(), kat::SNAPSHOT_LEN);
        assert_eq!(hex::encode(Sha256::digest(&blob)), kat::SNAPSHOT_SHA256);
        let (rev, pt) = keyset().open_snapshot(&blob).unwrap();
        assert_eq!(rev, kat::SNAPSHOT_REVISION);
        assert_eq!(pt.as_slice(), kat::SNAPSHOT_PLAINTEXT);
    }

    #[test]
    fn padding_boundaries() {
        // 4096 - 8 = 4088 bytes fit in one block; one more byte needs two.
        assert_eq!(pad(&[]).unwrap().len(), 4096);
        assert_eq!(pad(&[1u8; 4088]).unwrap().len(), 4096);
        assert_eq!(pad(&[1u8; 4089]).unwrap().len(), 8192);
        for n in [0usize, 1, 4087, 4088, 4089, 9000] {
            let data = vec![0xAB; n];
            assert_eq!(
                unpad(&pad(&data).unwrap()).unwrap().as_slice(),
                data.as_slice()
            );
        }
    }

    #[test]
    fn unpad_rejects_bad_length_and_padding() {
        let mut p = pad(b"abc").unwrap().to_vec();
        p[100] = 1; // non-zero padding
        assert!(unpad(&p).is_err());
        let mut p = pad(b"abc").unwrap().to_vec();
        p[0..8].copy_from_slice(&u64::MAX.to_le_bytes());
        assert!(unpad(&p).is_err());
    }
}
