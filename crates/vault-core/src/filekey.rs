//! Per-object file keys and their wrapping.
//!
//! Every file object gets its own random 256-bit [`FileKey`]. The wrapped form is stored in the
//! (encrypted) database snapshot, so only wrapped keys sit in memory while the vault is unlocked;
//! a key is unwrapped on demand and zeroized when dropped. The wrap binds
//! `(vault_id, vk_generation, object_id)` as AAD, so a wrapped key cannot be moved to another
//! object, vault or key generation.

use crate::{
    aead,
    error::{Error, Result},
    keys::KeySet,
    rng,
    secret::SecretKey,
};

/// Length of an object identifier.
pub const OBJECT_ID_LEN: usize = 16;
/// Length of a wrapped file key: 24-byte nonce + 32-byte key + 16-byte tag.
pub const WRAPPED_FILE_KEY_LEN: usize = 72;

const AAD_FILEKEY: &[u8] = b"USNA Secure v1/filekey";

/// Random 128-bit identifier of a stored file object (also its on-disk name).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ObjectId([u8; OBJECT_ID_LEN]);

impl ObjectId {
    /// Generate a random identifier.
    pub fn generate() -> Result<Self> {
        Ok(Self(rng::array()?))
    }
    /// Wrap existing bytes.
    pub fn from_bytes(bytes: [u8; OBJECT_ID_LEN]) -> Self {
        Self(bytes)
    }
    /// The raw bytes.
    pub fn as_bytes(&self) -> &[u8; OBJECT_ID_LEN] {
        &self.0
    }
}

/// A per-file 256-bit encryption key. Zeroized on drop; `Debug` is redacted.
#[derive(Debug, PartialEq, Eq)]
pub struct FileKey(SecretKey);

impl FileKey {
    /// Generate a fresh random key.
    pub fn generate() -> Result<Self> {
        Ok(Self(SecretKey::generate()?))
    }
    /// Build from raw bytes (e.g. when restoring). The caller should zeroize its copy.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(SecretKey::from_bytes(bytes))
    }
}

impl FileKey {
    /// The inner key, for the object cipher (crate-internal on purpose).
    pub(crate) fn secret(&self) -> &SecretKey {
        &self.0
    }
}

/// A file key encrypted under the vault's `filekey-wrap` subkey. Safe to store in the database.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WrappedFileKey([u8; WRAPPED_FILE_KEY_LEN]);

impl WrappedFileKey {
    /// Serialized form (`nonce || ciphertext || tag`).
    pub fn as_bytes(&self) -> &[u8; WRAPPED_FILE_KEY_LEN] {
        &self.0
    }
    /// Parse from bytes; only the length is checked here, authenticity is checked on unwrap.
    pub fn from_slice(bytes: &[u8]) -> Result<Self> {
        let arr: [u8; WRAPPED_FILE_KEY_LEN] = bytes
            .try_into()
            .map_err(|_| Error::MalformedSealed("wrapped file key has wrong length"))?;
        Ok(Self(arr))
    }
}

fn aad(vault_id: &[u8; 16], generation: u32, object: &ObjectId) -> Vec<u8> {
    let mut a = Vec::with_capacity(AAD_FILEKEY.len() + 16 + 4 + OBJECT_ID_LEN);
    a.extend_from_slice(AAD_FILEKEY);
    a.extend_from_slice(vault_id);
    a.extend_from_slice(&generation.to_le_bytes());
    a.extend_from_slice(object.as_bytes());
    a
}

impl KeySet {
    pub(crate) fn wrap_file_key_with_nonce(
        &self,
        key: &FileKey,
        object: &ObjectId,
        nonce: &[u8; aead::NONCE_LEN],
    ) -> Result<WrappedFileKey> {
        let a = aad(&self.vault_id, self.generation, object);
        let sealed = aead::seal_with_nonce(&self.subkeys.filekey_wrap, nonce, &a, key.0.expose())?;
        WrappedFileKey::from_slice(&sealed).map_err(|_| Error::Internal("wrapped key length"))
    }

    pub(crate) fn wrap_file_key(&self, key: &FileKey, object: &ObjectId) -> Result<WrappedFileKey> {
        let nonce = rng::array::<{ aead::NONCE_LEN }>()?;
        self.wrap_file_key_with_nonce(key, object, &nonce)
    }

    pub(crate) fn unwrap_file_key(
        &self,
        wrapped: &WrappedFileKey,
        object: &ObjectId,
    ) -> Result<FileKey> {
        let a = aad(&self.vault_id, self.generation, object);
        let pt = aead::open(&self.subkeys.filekey_wrap, &a, wrapped.as_bytes())?;
        let key = SecretKey::from_slice(&pt).ok_or(Error::MalformedSealed("file key length"))?;
        Ok(FileKey(key))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_vectors as kat;

    #[test]
    fn wrapped_filekey_known_answer() {
        let vk = SecretKey::from_slice(&hex::decode(kat::VK).unwrap()).unwrap();
        let vault_id: [u8; 16] = hex::decode(kat::VAULT_ID).unwrap().try_into().unwrap();
        let ks = KeySet::new(&vk, vault_id, 1).unwrap();
        let fk = FileKey::from_bytes(hex::decode(kat::FILE_KEY).unwrap().try_into().unwrap());
        let oid = ObjectId::from_bytes(hex::decode(kat::OBJECT_ID).unwrap().try_into().unwrap());
        let nonce: [u8; 24] = hex::decode(kat::FILEKEY_WRAP_NONCE)
            .unwrap()
            .try_into()
            .unwrap();
        let w = ks.wrap_file_key_with_nonce(&fk, &oid, &nonce).unwrap();
        assert_eq!(hex::encode(w.as_bytes()), kat::WRAPPED_FILEKEY);
        assert!(ks.unwrap_file_key(&w, &oid).unwrap() == fk);
    }

    #[test]
    fn debug_is_redacted() {
        let fk = FileKey::generate().unwrap();
        assert_eq!(format!("{fk:?}"), "FileKey(SecretKey(<redacted>))");
    }
}
