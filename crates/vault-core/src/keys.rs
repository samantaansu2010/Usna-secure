//! Key hierarchy below the password:
//!
//! ```text
//! Argon2id(password, salt) = PDK
//! HKDF-SHA256(salt = vault_id, ikm = PDK, info = "USNA Secure v1/kek") = KEK   (wraps the VK)
//! VK  (random 256-bit, never derived from the password)
//! HKDF-SHA256(salt = vault_id, ikm = VK, info = label || generation_le32) = subkeys
//!       database | filekey-wrap
//! (A third subkey, `manifest`, is reserved for the backup manifest. It is deliberately not derived
//! yet, so no unused key material is held in memory; its derivation is specified in VAULT_FORMAT §4.)
//! ```
//! See docs/VAULT_FORMAT.md §4.

use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroize;

use crate::{
    error::{Error, Result},
    secret::{SecretKey, KEY_LEN},
};

pub(crate) const INFO_KEK: &[u8] = b"USNA Secure v1/kek";
const INFO_DATABASE: &[u8] = b"USNA Secure v1/subkey/database";
const INFO_FILEKEY_WRAP: &[u8] = b"USNA Secure v1/subkey/filekey-wrap";

fn hkdf_sha256(ikm: &[u8], salt: &[u8], info: &[u8]) -> Result<SecretKey> {
    let hk = Hkdf::<Sha256>::new(Some(salt), ikm);
    let mut out = [0u8; KEY_LEN];
    hk.expand(info, &mut out)
        .map_err(|_| Error::Internal("hkdf expand"))?;
    let key = SecretKey::from_bytes(out);
    out.zeroize();
    Ok(key)
}

/// KEK = HKDF(PDK). The extra step gives domain separation, so additional key slots
/// (e.g. a recovery key) can wrap the same VK later without key reuse across purposes.
pub(crate) fn derive_kek(pdk: &SecretKey, vault_id: &[u8; 16]) -> Result<SecretKey> {
    hkdf_sha256(pdk.expose(), vault_id, INFO_KEK)
}

fn subkey(vk: &SecretKey, vault_id: &[u8; 16], label: &[u8], generation: u32) -> Result<SecretKey> {
    let mut info = Vec::with_capacity(label.len() + 4);
    info.extend_from_slice(label);
    info.extend_from_slice(&generation.to_le_bytes());
    hkdf_sha256(vk.expose(), vault_id, &info)
}

/// Purpose-separated keys derived from the VK.
pub(crate) struct Subkeys {
    pub(crate) database: SecretKey,
    pub(crate) filekey_wrap: SecretKey,
}

impl Subkeys {
    fn derive(vk: &SecretKey, vault_id: &[u8; 16], generation: u32) -> Result<Self> {
        Ok(Self {
            database: subkey(vk, vault_id, INFO_DATABASE, generation)?,
            filekey_wrap: subkey(vk, vault_id, INFO_FILEKEY_WRAP, generation)?,
        })
    }

    fn duplicate(&self) -> Self {
        Self {
            database: self.database.duplicate(),
            filekey_wrap: self.filekey_wrap.duplicate(),
        }
    }
}

/// Everything needed to seal/open vault objects for one `(vault_id, generation)`.
pub(crate) struct KeySet {
    pub(crate) vault_id: [u8; 16],
    pub(crate) generation: u32,
    pub(crate) subkeys: Subkeys,
}

impl KeySet {
    pub(crate) fn new(vk: &SecretKey, vault_id: [u8; 16], generation: u32) -> Result<Self> {
        Ok(Self {
            vault_id,
            generation,
            subkeys: Subkeys::derive(vk, &vault_id, generation)?,
        })
    }

    pub(crate) fn duplicate(&self) -> Self {
        Self {
            vault_id: self.vault_id,
            generation: self.generation,
            subkeys: self.subkeys.duplicate(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_vectors as kat;

    fn key(h: &str) -> SecretKey {
        SecretKey::from_slice(&hex::decode(h).unwrap()).unwrap()
    }
    fn vault_id() -> [u8; 16] {
        hex::decode(kat::VAULT_ID).unwrap().try_into().unwrap()
    }

    #[test]
    fn kek_known_answer() {
        let kek = derive_kek(&key(kat::PDK), &vault_id()).unwrap();
        assert_eq!(hex::encode(kek.expose()), kat::KEK);
    }

    #[test]
    fn subkeys_known_answer() {
        let ks = KeySet::new(&key(kat::VK), vault_id(), 1).unwrap();
        assert_eq!(
            hex::encode(ks.subkeys.database.expose()),
            kat::SUBKEY_DATABASE
        );
        assert_eq!(
            hex::encode(ks.subkeys.filekey_wrap.expose()),
            kat::SUBKEY_FILEKEY_WRAP
        );
    }

    #[test]
    fn subkeys_are_distinct_and_generation_bound() {
        let vk = SecretKey::generate().unwrap();
        let a = KeySet::new(&vk, [7u8; 16], 1).unwrap();
        let b = KeySet::new(&vk, [7u8; 16], 2).unwrap();
        assert!(a.subkeys.database != a.subkeys.filekey_wrap);
        assert!(a.subkeys.database != b.subkeys.database);
    }
}
