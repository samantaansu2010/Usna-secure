//! Error type for `usna-vault-core`.
//!
//! Errors never contain secret material. Wrong-password and tampered-ciphertext failures are
//! deliberately the same variant (`AuthenticationFailed`): they are cryptographically
//! indistinguishable and must not be distinguishable by callers.

use thiserror::Error;

/// Result alias used throughout the crate.
pub type Result<T> = core::result::Result<T, Error>;

/// All failures the core can report.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum Error {
    /// The input does not start with the expected magic bytes.
    #[error("unrecognized magic bytes (not a USNA Secure file)")]
    BadMagic,
    /// The format version is not supported by this build.
    #[error("unsupported format version {0}")]
    UnsupportedVersion(u16),
    /// The vault header is structurally invalid.
    #[error("malformed vault header: {0}")]
    MalformedHeader(&'static str),
    /// A database snapshot is structurally invalid.
    #[error("malformed snapshot: {0}")]
    MalformedSnapshot(&'static str),
    /// Authenticated data is structurally invalid (after successful authentication).
    #[error("malformed sealed data: {0}")]
    MalformedSealed(&'static str),
    /// KDF parameters are outside the permitted range.
    #[error("invalid KDF parameters: {0}")]
    InvalidKdfParams(&'static str),
    /// The password was rejected before any derivation.
    #[error("invalid password: {0}")]
    InvalidPassword(&'static str),
    /// Wrong password, or the data was modified/corrupted. Intentionally not distinguishable.
    #[error("authentication failed (wrong password or modified/corrupted data)")]
    AuthenticationFailed,
    /// The snapshot belongs to a different vault or key generation.
    #[error("snapshot does not match this vault: {0}")]
    SnapshotMismatch(&'static str),
    /// A pending header update does not belong to this vault state.
    #[error("header update does not match this vault")]
    HeaderUpdateMismatch,
    /// Argon2id failed (e.g. memory allocation).
    #[error("key derivation failed")]
    KdfFailure,
    /// The OS random number generator failed.
    #[error("random number generator failure")]
    RngFailure,
    /// AEAD encryption failed.
    #[error("encryption failed")]
    EncryptionFailure,
    /// Input too large to encode.
    #[error("input too large")]
    TooLarge,
    /// The key generation counter would overflow.
    #[error("key generation counter overflow")]
    GenerationOverflow,
    /// Internal invariant violated (a bug, not a user error).
    #[error("internal error: {0}")]
    Internal(&'static str),
}
