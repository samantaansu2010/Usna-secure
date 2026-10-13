//! Vault header (`vault.header`), format v1, exactly 149 bytes, little-endian.
//!
//! | offset | len | field                                            |
//! |-------:|----:|--------------------------------------------------|
//! |      0 |   8 | magic `"USNAVLT\0"`                              |
//! |      8 |   2 | format version (`1`)                             |
//! |     10 |   2 | flags (must be `0`)                              |
//! |     12 |  16 | vault id (random)                                |
//! |     28 |   4 | vault-key generation (starts at 1)               |
//! |     32 |   1 | KDF id (`1` = Argon2id v1.3)                     |
//! |     33 |   4 | Argon2 memory cost, KiB                          |
//! |     37 |   4 | Argon2 time cost                                 |
//! |     41 |   4 | Argon2 parallelism                               |
//! |     45 |  32 | KDF salt (random)                                |
//! |     77 |  24 | wrap nonce (random)                              |
//! |    101 |  48 | wrapped VK: XChaCha20-Poly1305(KEK) of the VK    |
//!
//! Bytes `0..77` are the AAD of the VK wrap, so every field is authenticated by the AEAD tag.
//! There is no separate header MAC. See docs/VAULT_FORMAT.md §3.

use crate::{
    error::{Error, Result},
    kdf::{KdfParams, KDF_ID_ARGON2ID_V13},
};

/// Magic bytes at the start of `vault.header`.
pub const HEADER_MAGIC: [u8; 8] = *b"USNAVLT\0";
/// The only format version this build understands.
pub const FORMAT_VERSION: u16 = 1;
/// Exact byte length of a v1 header.
pub const HEADER_LEN: usize = 149;
/// KDF salt length.
pub const SALT_LEN: usize = 32;
/// Length of the authenticated prefix (bytes `0..77`).
pub(crate) const PREFIX_LEN: usize = 77;

const OFF_VERSION: usize = 8;
const OFF_FLAGS: usize = 10;
const OFF_VAULT_ID: usize = 12;
const OFF_GENERATION: usize = 28;
const OFF_KDF_ID: usize = 32;
const OFF_M: usize = 33;
const OFF_T: usize = 37;
const OFF_P: usize = 41;
const OFF_SALT: usize = 45;
const OFF_NONCE: usize = 77;
const OFF_WRAPPED: usize = 101;

fn le_u16(b: &[u8], off: usize) -> u16 {
    let mut a = [0u8; 2];
    a.copy_from_slice(&b[off..off + 2]);
    u16::from_le_bytes(a)
}
fn le_u32(b: &[u8], off: usize) -> u32 {
    let mut a = [0u8; 4];
    a.copy_from_slice(&b[off..off + 4]);
    u32::from_le_bytes(a)
}

/// A parsed, structurally validated header. Contains no secrets (the VK is wrapped), but it is
/// **not authenticated** until the VK has been unwrapped with the right password.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Header {
    pub(crate) vault_id: [u8; 16],
    pub(crate) vk_generation: u32,
    pub(crate) kdf: KdfParams,
    pub(crate) salt: [u8; SALT_LEN],
    pub(crate) wrap_nonce: [u8; 24],
    pub(crate) wrapped_vk: [u8; 48],
}

impl Header {
    /// Encode the authenticated prefix (bytes `0..77`).
    pub(crate) fn encode_prefix(
        vault_id: &[u8; 16],
        vk_generation: u32,
        kdf: &KdfParams,
        salt: &[u8; SALT_LEN],
    ) -> [u8; PREFIX_LEN] {
        let mut o = [0u8; PREFIX_LEN];
        o[0..8].copy_from_slice(&HEADER_MAGIC);
        o[OFF_VERSION..OFF_VERSION + 2].copy_from_slice(&FORMAT_VERSION.to_le_bytes());
        // flags stay zero
        o[OFF_VAULT_ID..OFF_VAULT_ID + 16].copy_from_slice(vault_id);
        o[OFF_GENERATION..OFF_GENERATION + 4].copy_from_slice(&vk_generation.to_le_bytes());
        o[OFF_KDF_ID] = KDF_ID_ARGON2ID_V13;
        o[OFF_M..OFF_M + 4].copy_from_slice(&kdf.m_cost_kib.to_le_bytes());
        o[OFF_T..OFF_T + 4].copy_from_slice(&kdf.t_cost.to_le_bytes());
        o[OFF_P..OFF_P + 4].copy_from_slice(&kdf.parallelism.to_le_bytes());
        o[OFF_SALT..OFF_SALT + SALT_LEN].copy_from_slice(salt);
        o
    }

    pub(crate) fn prefix(&self) -> [u8; PREFIX_LEN] {
        Self::encode_prefix(&self.vault_id, self.vk_generation, &self.kdf, &self.salt)
    }

    /// Serialize to the on-disk form.
    pub fn to_bytes(&self) -> [u8; HEADER_LEN] {
        let mut o = [0u8; HEADER_LEN];
        o[..PREFIX_LEN].copy_from_slice(&self.prefix());
        o[OFF_NONCE..OFF_NONCE + 24].copy_from_slice(&self.wrap_nonce);
        o[OFF_WRAPPED..OFF_WRAPPED + 48].copy_from_slice(&self.wrapped_vk);
        o
    }

    /// Parse and structurally validate. Rejects wrong length, magic, version, reserved flags,
    /// unknown KDF ids, zero generation and out-of-policy KDF parameters, all before any
    /// expensive work. Does **not** authenticate; that happens during unlock.
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != HEADER_LEN {
            return Err(Error::MalformedHeader("unexpected length"));
        }
        if bytes[0..8] != HEADER_MAGIC[..] {
            return Err(Error::BadMagic);
        }
        let version = le_u16(bytes, OFF_VERSION);
        if version != FORMAT_VERSION {
            return Err(Error::UnsupportedVersion(version));
        }
        if le_u16(bytes, OFF_FLAGS) != 0 {
            return Err(Error::MalformedHeader("reserved flags set"));
        }
        if bytes[OFF_KDF_ID] != KDF_ID_ARGON2ID_V13 {
            return Err(Error::MalformedHeader("unknown KDF id"));
        }
        let vk_generation = le_u32(bytes, OFF_GENERATION);
        if vk_generation == 0 {
            return Err(Error::MalformedHeader("zero key generation"));
        }
        let kdf = KdfParams {
            m_cost_kib: le_u32(bytes, OFF_M),
            t_cost: le_u32(bytes, OFF_T),
            parallelism: le_u32(bytes, OFF_P),
        };
        kdf.validate()?;

        let mut vault_id = [0u8; 16];
        vault_id.copy_from_slice(&bytes[OFF_VAULT_ID..OFF_VAULT_ID + 16]);
        let mut salt = [0u8; SALT_LEN];
        salt.copy_from_slice(&bytes[OFF_SALT..OFF_SALT + SALT_LEN]);
        let mut wrap_nonce = [0u8; 24];
        wrap_nonce.copy_from_slice(&bytes[OFF_NONCE..OFF_NONCE + 24]);
        let mut wrapped_vk = [0u8; 48];
        wrapped_vk.copy_from_slice(&bytes[OFF_WRAPPED..OFF_WRAPPED + 48]);
        Ok(Self {
            vault_id,
            vk_generation,
            kdf,
            salt,
            wrap_nonce,
            wrapped_vk,
        })
    }

    /// Random vault identifier.
    pub fn vault_id(&self) -> &[u8; 16] {
        &self.vault_id
    }
    /// Current vault-key generation.
    pub fn vk_generation(&self) -> u32 {
        self.vk_generation
    }
    /// Stored KDF parameters.
    pub fn kdf_params(&self) -> KdfParams {
        self.kdf
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_vectors as kat;

    fn golden() -> Vec<u8> {
        hex::decode(kat::HEADER).unwrap()
    }

    #[test]
    fn golden_roundtrip() {
        let h = Header::parse(&golden()).unwrap();
        assert_eq!(h.to_bytes().as_slice(), golden().as_slice());
        assert_eq!(h.vk_generation(), 1);
        assert_eq!(h.kdf_params(), KdfParams::INSECURE_TEST);
    }

    #[test]
    fn rejects_structural_problems() {
        let g = golden();
        assert_eq!(
            Header::parse(&g[..148]).unwrap_err(),
            Error::MalformedHeader("unexpected length")
        );
        let mut long = g.clone();
        long.push(0);
        assert!(Header::parse(&long).is_err());
        let mut b = g.clone();
        b[0] ^= 1;
        assert_eq!(Header::parse(&b).unwrap_err(), Error::BadMagic);
        let mut b = g.clone();
        b[OFF_VERSION] = 2;
        assert_eq!(Header::parse(&b).unwrap_err(), Error::UnsupportedVersion(2));
        let mut b = g.clone();
        b[OFF_FLAGS] = 1;
        assert!(matches!(Header::parse(&b), Err(Error::MalformedHeader(_))));
        let mut b = g.clone();
        b[OFF_KDF_ID] = 9;
        assert!(matches!(Header::parse(&b), Err(Error::MalformedHeader(_))));
        let mut b = g.clone();
        b[OFF_GENERATION..OFF_GENERATION + 4].copy_from_slice(&0u32.to_le_bytes());
        assert!(matches!(Header::parse(&b), Err(Error::MalformedHeader(_))));
        let mut b = g;
        b[OFF_M..OFF_M + 4].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(matches!(Header::parse(&b), Err(Error::InvalidKdfParams(_))));
    }
}
