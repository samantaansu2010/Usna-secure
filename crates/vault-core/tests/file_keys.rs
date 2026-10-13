//! Per-object file keys: wrapping, binding to object and vault, and corruption detection.
// Test crate: panicking on a failed fixture or assertion is intended (docs/TESTING.md, "Lint policy for tests").
#![allow(clippy::unwrap_used, clippy::expect_used)]
#![allow(clippy::needless_range_loop)]
mod common;
use common::*;
use usna_vault_core::{Error, FileKey, WrappedFileKey, WRAPPED_FILE_KEY_LEN};

#[test]
fn wrap_unwrap_roundtrip() {
    let (v, _h) = new_vault();
    let id = oid();
    let (key, wrapped) = v.new_file_key(&id).unwrap();
    assert_eq!(wrapped.as_bytes().len(), WRAPPED_FILE_KEY_LEN);
    assert!(v.unwrap_file_key(&wrapped, &id).unwrap() == key);
}

#[test]
fn wrapped_key_is_bound_to_object_vault_and_every_bit() {
    let (a, _) = new_vault();
    let (b, _) = new_vault();
    let (id, other) = (oid(), oid());
    let (_k, w) = a.new_file_key(&id).unwrap();
    assert_eq!(
        a.unwrap_file_key(&w, &other).unwrap_err(),
        Error::AuthenticationFailed
    );
    assert_eq!(
        b.unwrap_file_key(&w, &id).unwrap_err(),
        Error::AuthenticationFailed
    );
    for byte in 0..WRAPPED_FILE_KEY_LEN {
        for bit in 0..8 {
            let mut m = *w.as_bytes();
            m[byte] ^= 1 << bit;
            let m = WrappedFileKey::from_slice(&m).unwrap();
            assert!(a.unwrap_file_key(&m, &id).is_err(), "byte {byte} bit {bit}");
        }
    }
}

#[test]
fn wrong_length_is_rejected() {
    assert!(WrappedFileKey::from_slice(&[0u8; 71]).is_err());
    assert!(WrappedFileKey::from_slice(&[0u8; 73]).is_err());
}

#[test]
fn file_keys_are_unique_and_never_printed() {
    let keys: Vec<_> = (0..200).map(|_| FileKey::generate().unwrap()).collect();
    for (i, a) in keys.iter().enumerate() {
        for b in &keys[i + 1..] {
            assert!(a != b);
        }
    }
    assert!(format!("{:?}", keys[0]).contains("redacted"));
}

#[test]
fn replacing_a_file_means_a_new_object_id_and_a_new_key() {
    let (v, _h) = new_vault();
    let (old_id, new_id) = (oid(), oid());
    let (k_old, w_old) = v.new_file_key(&old_id).unwrap();
    let (k_new, _w_new) = v.new_file_key(&new_id).unwrap();
    assert!(k_old != k_new);
    // The old wrapped key cannot be presented for the new object.
    assert!(v.unwrap_file_key(&w_old, &new_id).is_err());
}
