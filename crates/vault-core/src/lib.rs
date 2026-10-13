//! # usna-vault-core
//!
//! Security-critical core of USNA Secure: key hierarchy, authenticated vault header, encrypted
//! database snapshots and per-object file-key wrapping. No UI, no Tauri, no network, no I/O.
//!
//! **Status: milestone 1, pre-review.** Not audited; do not use for real secrets yet.
//! Design documents live in `docs/`; start with `docs/VAULT_FORMAT.md`.
//!
//! ```no_run
//! use usna_vault_core::{KdfParams, Password, UnlockedVault};
//!
//! let pw = Password::new("a long passphrase")?;
//! let (vault, header_bytes) = UnlockedVault::create(&pw, KdfParams::RECOMMENDED)?;
//! // ... persist `header_bytes` to vault.header atomically ...
//! let blob = vault.seal_snapshot(1, b"serialized database")?;
//! vault.lock();
//!
//! let vault = UnlockedVault::unlock(&header_bytes, &pw)?;
//! let (revision, plaintext) = vault.open_snapshot(&blob)?;
//! assert_eq!((revision, plaintext.as_slice()), (1, &b"serialized database"[..]));
//! # Ok::<(), usna_vault_core::Error>(())
//! ```

#[cfg(all(feature = "insecure-test-params", not(debug_assertions)))]
compile_error!(
    "feature `insecure-test-params` weakens the KDF and must never be enabled in release builds"
);

mod aead;
mod error;
mod filekey;
mod header;
mod kdf;
mod keys;
mod object;
mod password;
mod rng;
mod secret;
mod snapshot;
mod vault;

#[cfg(test)]
mod test_vectors;

pub use error::{Error, Result};
pub use filekey::{FileKey, ObjectId, WrappedFileKey, OBJECT_ID_LEN, WRAPPED_FILE_KEY_LEN};
pub use header::{Header, FORMAT_VERSION, HEADER_LEN, HEADER_MAGIC, SALT_LEN};
pub use kdf::KdfParams;
pub use object::{
    ObjectReader, ObjectWriter, DEFAULT_CHUNK_SIZE, MAX_CHUNK_SIZE, MIN_CHUNK_SIZE,
    OBJECT_HEADER_LEN, OBJECT_MAGIC,
};
pub use password::{Password, MAX_PASSWORD_BYTES};
pub use snapshot::{inspect_snapshot, SnapshotInfo, SNAPSHOT_MAGIC};
pub use vault::{HeaderUpdate, UnlockedVault, VaultKeyRotation};
