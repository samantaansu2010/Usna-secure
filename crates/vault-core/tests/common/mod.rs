//! Shared helpers. Integration tests need weak Argon2 parameters, so they only build with
//! `--features insecure-test-params` (or `--all-features`).
//!
//! `dead_code` is allowed here only because every test binary includes this module and each one
//! uses a different subset of the helpers.
#![allow(dead_code)]

#[cfg(not(feature = "insecure-test-params"))]
compile_error!("run the tests with: cargo test --all-features");

use usna_vault_core::{KdfParams, ObjectId, Password, UnlockedVault, VaultKeyRotation};

pub const PW: &str = "correct horse battery staple";

pub fn fast() -> KdfParams {
    KdfParams::INSECURE_TEST
}

pub fn pw(s: &str) -> Password {
    Password::new(s).unwrap()
}

/// New vault with the standard test password. Returns `(vault, header_bytes)`.
pub fn new_vault() -> (UnlockedVault, Vec<u8>) {
    UnlockedVault::create(&pw(PW), fast()).unwrap()
}

pub fn oid() -> ObjectId {
    ObjectId::generate().unwrap()
}

/// Open `old` under the rotation's old keys and seal the same plaintext under the new keys with
/// revision + 1. Only valid for test data that embeds no wrapped file keys.
pub fn reseal(rot: &VaultKeyRotation, old: &[u8]) -> Vec<u8> {
    let (rev, pt) = rot.open_old_snapshot(old).unwrap();
    rot.seal_new_snapshot(rev + 1, &pt).unwrap()
}
