//! Golden files produced by an independent implementation (tools/gen_vectors.py). These bytes are
//! frozen: every future version of the core MUST keep opening them (format v1 compatibility).
// Test crate: panicking on a failed fixture or assertion is intended (docs/TESTING.md, "Lint policy for tests").
#![allow(clippy::unwrap_used, clippy::expect_used)]
mod common;
use common::*;
use usna_vault_core::{FileKey, ObjectId, UnlockedVault, WrappedFileKey};

const HEADER: &[u8] = include_bytes!("vectors/header_v1.bin");
const SNAPSHOT: &[u8] = include_bytes!("vectors/snapshot_v1.bin");
const WRAPPED: &[u8] = include_bytes!("vectors/wrapped_filekey_v1.bin");

fn arr<const N: usize>(h: &str) -> [u8; N] {
    hex::decode(h).unwrap().try_into().unwrap()
}

#[test]
fn golden_v1_header_snapshot_and_filekey_open_with_the_current_code() {
    let vault = UnlockedVault::unlock(HEADER, &pw("correct horse battery staple")).unwrap();
    assert_eq!(vault.vk_generation(), 1);
    assert_eq!(
        hex::encode(vault.vault_id()),
        "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf"
    );

    let (rev, pt) = vault.open_snapshot(SNAPSHOT).unwrap();
    assert_eq!(rev, 7);
    assert_eq!(pt.as_slice(), b"USNA Secure snapshot vector");

    let oid = ObjectId::from_bytes(arr("e0e1e2e3e4e5e6e7e8e9eaebecedeeef"));
    let wrapped = WrappedFileKey::from_slice(WRAPPED).unwrap();
    let key = vault.unwrap_file_key(&wrapped, &oid).unwrap();
    let expected = FileKey::from_bytes(arr(
        "101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f",
    ));
    assert!(key == expected);
}

#[test]
fn golden_v1_wrong_password_still_fails() {
    assert!(UnlockedVault::unlock(HEADER, &pw("not the password")).is_err());
}
