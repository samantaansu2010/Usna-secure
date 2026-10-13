//! Randomness: uniqueness of nonces, salts and vault ids across many operations.
// Test crate: panicking on a failed fixture or assertion is intended (docs/TESTING.md, "Lint policy for tests").
#![allow(clippy::unwrap_used, clippy::expect_used)]
mod common;
use common::*;
use std::collections::HashSet;
use usna_vault_core::UnlockedVault;

#[test]
fn snapshot_nonces_are_unique() {
    let (v, _h) = new_vault();
    let mut seen = HashSet::new();
    for _ in 0..5_000 {
        let blob = v.seal_snapshot(1, b"same plaintext every time").unwrap();
        assert!(seen.insert(blob[40..64].to_vec()), "nonce repeated");
    }
}

#[test]
fn identical_plaintext_yields_different_ciphertext() {
    let (v, _h) = new_vault();
    let a = v.seal_snapshot(1, b"same").unwrap();
    let b = v.seal_snapshot(1, b"same").unwrap();
    assert_ne!(a[64..], b[64..]);
}

#[test]
fn wrapped_key_nonces_are_unique() {
    let (v, _h) = new_vault();
    let id = oid();
    let key = usna_vault_core::FileKey::generate().unwrap();
    let mut seen = HashSet::new();
    for _ in 0..5_000 {
        let w = v.wrap_file_key(&key, &id).unwrap();
        assert!(seen.insert(w.as_bytes()[..24].to_vec()), "nonce repeated");
    }
}

#[test]
fn header_salts_nonces_and_ids_are_unique_across_vaults() {
    let (mut ids, mut salts, mut nonces) = (HashSet::new(), HashSet::new(), HashSet::new());
    for _ in 0..200 {
        let (_v, h) = UnlockedVault::create(&pw(PW), fast()).unwrap();
        assert!(ids.insert(h[12..28].to_vec()));
        assert!(salts.insert(h[45..77].to_vec()));
        assert!(nonces.insert(h[77..101].to_vec()));
    }
}
