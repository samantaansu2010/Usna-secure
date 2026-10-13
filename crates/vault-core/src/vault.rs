//! Vault lifecycle: create, unlock, change password, rotate the vault key.
//!
//! The core is deliberately stateless and does no I/O. It returns the bytes the storage layer
//! must persist, and the caller decides when they are durable. The two-phase commit protocol for
//! rotation is specified in docs/VAULT_FORMAT.md §7.

use core::fmt;

use crate::{
    aead,
    error::{Error, Result},
    filekey::{FileKey, ObjectId, WrappedFileKey},
    header::{Header, HEADER_LEN, PREFIX_LEN, SALT_LEN},
    kdf::KdfParams,
    keys::{derive_kek, KeySet},
    password::Password,
    rng,
    secret::SecretKey,
};

const AAD_VK_WRAP: &[u8] = b"USNA Secure v1/vk-wrap";

fn vk_wrap_aad(prefix: &[u8; PREFIX_LEN]) -> Vec<u8> {
    let mut a = Vec::with_capacity(AAD_VK_WRAP.len() + PREFIX_LEN);
    a.extend_from_slice(AAD_VK_WRAP);
    a.extend_from_slice(prefix);
    a
}

fn kek_for(
    password: &Password,
    kdf: &KdfParams,
    salt: &[u8; SALT_LEN],
    vault_id: &[u8; 16],
) -> Result<SecretKey> {
    let pdk = kdf.derive(password, salt)?;
    derive_kek(&pdk, vault_id)
}

fn build_header(
    vk: &SecretKey,
    kek: &SecretKey,
    vault_id: [u8; 16],
    vk_generation: u32,
    kdf: KdfParams,
    salt: [u8; SALT_LEN],
    wrap_nonce: [u8; aead::NONCE_LEN],
) -> Result<Header> {
    let prefix = Header::encode_prefix(&vault_id, vk_generation, &kdf, &salt);
    let ct = aead::encrypt_with_nonce(kek, &wrap_nonce, &vk_wrap_aad(&prefix), vk.expose())?;
    let wrapped_vk: [u8; 48] = ct
        .try_into()
        .map_err(|_| Error::Internal("wrapped VK length"))?;
    Ok(Header {
        vault_id,
        vk_generation,
        kdf,
        salt,
        wrap_nonce,
        wrapped_vk,
    })
}

fn unwrap_vk(kek: &SecretKey, header: &Header) -> Result<SecretKey> {
    let pt = aead::decrypt_with_nonce(
        kek,
        &header.wrap_nonce,
        &vk_wrap_aad(&header.prefix()),
        &header.wrapped_vk,
    )?;
    SecretKey::from_slice(&pt).ok_or(Error::AuthenticationFailed)
}

/// A header produced by [`UnlockedVault::prepare_password_change`], not yet adopted.
///
/// Persist [`HeaderUpdate::bytes`] atomically, then call [`UnlockedVault::commit_header_update`].
#[derive(Debug)]
pub struct HeaderUpdate {
    header: Header,
}

impl HeaderUpdate {
    /// The new on-disk header.
    pub fn bytes(&self) -> [u8; HEADER_LEN] {
        self.header.to_bytes()
    }
}

/// An unlocked vault: holds the vault key and derived subkeys in (zeroize-on-drop) memory.
/// Dropping it, or calling [`UnlockedVault::lock`], wipes them (best effort).
pub struct UnlockedVault {
    header: Header,
    vk: SecretKey,
    keys: KeySet,
}

impl fmt::Debug for UnlockedVault {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UnlockedVault")
            .field("vk_generation", &self.header.vk_generation)
            .field("keys", &"<redacted>")
            .finish()
    }
}

impl UnlockedVault {
    /// Create a new vault. Returns the unlocked vault and the header bytes to persist.
    pub fn create(password: &Password, kdf: KdfParams) -> Result<(Self, Vec<u8>)> {
        kdf.validate()?;
        Self::create_with_material(
            password,
            kdf,
            rng::array()?,
            rng::array()?,
            rng::array()?,
            SecretKey::generate()?,
        )
    }

    pub(crate) fn create_with_material(
        password: &Password,
        kdf: KdfParams,
        vault_id: [u8; 16],
        salt: [u8; SALT_LEN],
        wrap_nonce: [u8; aead::NONCE_LEN],
        vk: SecretKey,
    ) -> Result<(Self, Vec<u8>)> {
        let kek = kek_for(password, &kdf, &salt, &vault_id)?;
        let header = build_header(&vk, &kek, vault_id, 1, kdf, salt, wrap_nonce)?;
        let keys = KeySet::new(&vk, vault_id, 1)?;
        let bytes = header.to_bytes().to_vec();
        Ok((Self { header, vk, keys }, bytes))
    }

    /// Unlock from header bytes. Wrong password and modified header are indistinguishable
    /// (`Error::AuthenticationFailed`). The core cannot rate-limit offline guessing: Argon2id
    /// cost is the defence (docs/THREAT_MODEL.md, T4).
    pub fn unlock(header_bytes: &[u8], password: &Password) -> Result<Self> {
        let header = Header::parse(header_bytes)?;
        let kek = kek_for(password, &header.kdf, &header.salt, &header.vault_id)?;
        let vk = unwrap_vk(&kek, &header)?;
        let keys = KeySet::new(&vk, header.vault_id, header.vk_generation)?;
        Ok(Self { header, vk, keys })
    }

    /// Wipe key material (equivalent to dropping the value).
    pub fn lock(self) {}

    /// Vault id.
    pub fn vault_id(&self) -> &[u8; 16] {
        &self.header.vault_id
    }
    /// Current vault-key generation.
    pub fn vk_generation(&self) -> u32 {
        self.header.vk_generation
    }
    /// KDF parameters in the in-memory header.
    pub fn kdf_params(&self) -> KdfParams {
        self.header.kdf
    }
    /// The in-memory header as it would be written to disk.
    pub fn header_bytes(&self) -> [u8; HEADER_LEN] {
        self.header.to_bytes()
    }

    fn reauthenticate(&self, password: &Password) -> Result<SecretKey> {
        let kek = kek_for(
            password,
            &self.header.kdf,
            &self.header.salt,
            &self.header.vault_id,
        )?;
        let proof = unwrap_vk(&kek, &self.header)?;
        if proof != self.vk {
            return Err(Error::AuthenticationFailed);
        }
        Ok(kek)
    }

    /// Re-wrap the *same* vault key under a new password (fresh salt and nonce, new KDF params).
    ///
    /// The VK, subkeys, database snapshot and all file objects are untouched. Requires the
    /// current password again (re-authentication). Nothing changes in memory until
    /// [`commit_header_update`](Self::commit_header_update).
    ///
    /// **This does not revoke the old password.** Any older copy of the header (backups, cloud
    /// copies) still unwraps the same vault key with the old password, and that key still decrypts
    /// the current snapshot. If the old password may be compromised, also rotate the vault key (and
    /// file keys) and replace old backups (docs/DESIGN_REVIEW.md, R2).
    pub fn prepare_password_change(
        &self,
        current: &Password,
        new: &Password,
        new_kdf: KdfParams,
    ) -> Result<HeaderUpdate> {
        new_kdf.validate()?;
        drop(self.reauthenticate(current)?);
        let salt = rng::array::<SALT_LEN>()?;
        let nonce = rng::array::<{ aead::NONCE_LEN }>()?;
        let new_kek = kek_for(new, &new_kdf, &salt, &self.header.vault_id)?;
        let header = build_header(
            &self.vk,
            &new_kek,
            self.header.vault_id,
            self.header.vk_generation,
            new_kdf,
            salt,
            nonce,
        )?;
        Ok(HeaderUpdate { header })
    }

    /// Adopt a header after it has been durably persisted.
    pub fn commit_header_update(&mut self, update: HeaderUpdate) -> Result<()> {
        if update.header.vault_id != self.header.vault_id
            || update.header.vk_generation != self.header.vk_generation
        {
            return Err(Error::HeaderUpdateMismatch);
        }
        self.header = update.header;
        Ok(())
    }

    /// Seal a database snapshot under the current generation.
    pub fn seal_snapshot(&self, revision: u64, plaintext: &[u8]) -> Result<Vec<u8>> {
        self.keys.seal_snapshot(revision, plaintext)
    }
    /// Authenticate and decrypt a snapshot. Returns `(revision, plaintext)`.
    pub fn open_snapshot(&self, blob: &[u8]) -> Result<(u64, zeroize::Zeroizing<Vec<u8>>)> {
        self.keys.open_snapshot(blob)
    }

    /// Generate a new file key together with its wrapped form for `object`.
    pub fn new_file_key(&self, object: &ObjectId) -> Result<(FileKey, WrappedFileKey)> {
        let key = FileKey::generate()?;
        let wrapped = self.keys.wrap_file_key(&key, object)?;
        Ok((key, wrapped))
    }
    /// Wrap an existing file key for `object`.
    pub fn wrap_file_key(&self, key: &FileKey, object: &ObjectId) -> Result<WrappedFileKey> {
        self.keys.wrap_file_key(key, object)
    }
    /// Unwrap a file key for `object`; fails if it was wrapped for another object, vault or generation.
    pub fn unwrap_file_key(&self, wrapped: &WrappedFileKey, object: &ObjectId) -> Result<FileKey> {
        self.keys.unwrap_file_key(wrapped, object)
    }

    /// Begin rotating the vault key. Re-authenticates with the password, generates a new VK with
    /// generation + 1 and prepares the new header. Nothing is persisted and `self` is unchanged.
    /// Use the returned [`VaultKeyRotation`] to open the old snapshot, re-wrap every file key,
    /// seal the updated snapshot, then follow the commit protocol in docs/VAULT_FORMAT.md §7.
    ///
    /// File *contents* are not re-encrypted. A party who held the old VK and an old copy of the
    /// vault can still unwrap old file keys from that old copy; rotation protects data written
    /// after it, not data already exposed. Re-encrypting a file under a new file key is a separate
    /// operation (docs/VAULT_FORMAT.md §6).
    pub fn begin_vault_key_rotation(&self, password: &Password) -> Result<VaultKeyRotation> {
        let kek = self.reauthenticate(password)?;
        let new_generation = self
            .header
            .vk_generation
            .checked_add(1)
            .ok_or(Error::GenerationOverflow)?;
        let new_vk = SecretKey::generate()?;
        let nonce = rng::array::<{ aead::NONCE_LEN }>()?;
        // Same password, salt and KEK; fresh VK and fresh random nonce, so the wrap is a new AEAD
        // message under a key that has wrapped at most a handful of messages.
        let new_header = build_header(
            &new_vk,
            &kek,
            self.header.vault_id,
            new_generation,
            self.header.kdf,
            self.header.salt,
            nonce,
        )?;
        let new_keys = KeySet::new(&new_vk, self.header.vault_id, new_generation)?;
        let new_header_bytes = new_header.to_bytes().to_vec();
        Ok(VaultKeyRotation {
            old_keys: self.keys.duplicate(),
            new_vault: UnlockedVault {
                header: new_header,
                vk: new_vk,
                keys: new_keys,
            },
            new_header_bytes,
        })
    }
}

/// An in-progress vault-key rotation. Holds both the old and the new keys in memory.
pub struct VaultKeyRotation {
    old_keys: KeySet,
    new_vault: UnlockedVault,
    new_header_bytes: Vec<u8>,
}

impl fmt::Debug for VaultKeyRotation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("VaultKeyRotation(<redacted>)")
    }
}

impl VaultKeyRotation {
    /// The new header to persist at the commit point.
    pub fn new_header_bytes(&self) -> &[u8] {
        &self.new_header_bytes
    }
    /// The generation after rotation.
    pub fn new_generation(&self) -> u32 {
        self.new_vault.header.vk_generation
    }
    /// Re-wrap a file key from the old generation to the new one. The file key itself, and
    /// therefore the file object, is unchanged.
    pub fn rewrap_file_key(
        &self,
        wrapped: &WrappedFileKey,
        object: &ObjectId,
    ) -> Result<WrappedFileKey> {
        let key = self.old_keys.unwrap_file_key(wrapped, object)?;
        self.new_vault.keys.wrap_file_key(&key, object)
    }
    /// Authenticate and decrypt a snapshot sealed under the **old** generation.
    /// Returns `(revision, plaintext)`.
    pub fn open_old_snapshot(&self, old_blob: &[u8]) -> Result<(u64, zeroize::Zeroizing<Vec<u8>>)> {
        self.old_keys.open_snapshot(old_blob)
    }
    /// Seal `plaintext` under the **new** generation with the given revision (use the old
    /// revision + 1).
    ///
    /// **Caller obligation:** the snapshot plaintext contains the wrapped file keys, and those
    /// are bound to the old generation. Deserialize the plaintext, replace every wrapped key with
    /// [`rewrap_file_key`](Self::rewrap_file_key), re-serialize, and only then call this. Sealing
    /// the old plaintext unchanged produces a vault whose file keys cannot be unwrapped.
    pub fn seal_new_snapshot(&self, revision: u64, plaintext: &[u8]) -> Result<Vec<u8>> {
        self.new_vault.keys.seal_snapshot(revision, plaintext)
    }
    /// Finish: drop the old keys and continue with the unlocked vault of the new generation.
    /// Call only after the commit protocol has completed durably.
    pub fn into_new_vault(self) -> UnlockedVault {
        self.new_vault
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_vectors as kat;

    #[test]
    fn deterministic_create_reproduces_golden_header() {
        let pw = Password::new(kat::PASSWORD).unwrap();
        let (vault, bytes) = UnlockedVault::create_with_material(
            &pw,
            KdfParams::INSECURE_TEST,
            hex::decode(kat::VAULT_ID).unwrap().try_into().unwrap(),
            hex::decode(kat::SALT).unwrap().try_into().unwrap(),
            hex::decode(kat::WRAP_NONCE).unwrap().try_into().unwrap(),
            SecretKey::from_slice(&hex::decode(kat::VK).unwrap()).unwrap(),
        )
        .unwrap();
        assert_eq!(hex::encode(&bytes), kat::HEADER);
        assert_eq!(vault.vk_generation(), 1);
    }

    #[test]
    fn unlock_golden_header() {
        let pw = Password::new(kat::PASSWORD).unwrap();
        let v = UnlockedVault::unlock(&hex::decode(kat::HEADER).unwrap(), &pw).unwrap();
        assert!(v.vk == SecretKey::from_slice(&hex::decode(kat::VK).unwrap()).unwrap());
    }
}
