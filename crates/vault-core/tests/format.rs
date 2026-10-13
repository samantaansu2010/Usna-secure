//! Format conformance: header and snapshot layout, version handling, padding, serialization round-trips.
// Test crate: panicking on a failed fixture or assertion is intended (docs/TESTING.md, "Lint policy for tests").
#![allow(clippy::unwrap_used, clippy::expect_used)]
mod common;
use common::*;
use usna_vault_core::{
    inspect_snapshot, Error, Header, UnlockedVault, FORMAT_VERSION, HEADER_LEN, HEADER_MAGIC,
    SNAPSHOT_MAGIC,
};

#[test]
fn header_serialization_roundtrip_and_layout() {
    let (_v, bytes) = new_vault();
    let h = Header::parse(&bytes).unwrap();
    assert_eq!(h.to_bytes().as_slice(), bytes.as_slice());
    assert_eq!(&bytes[0..8], &HEADER_MAGIC);
    assert_eq!(u16::from_le_bytes([bytes[8], bytes[9]]), FORMAT_VERSION);
    assert_eq!(&bytes[10..12], &[0, 0]);
    assert_eq!(&bytes[12..28], h.vault_id());
    assert_eq!(u32::from_le_bytes(bytes[28..32].try_into().unwrap()), 1);
    assert_eq!(bytes[32], 1);
    assert_eq!(bytes.len(), HEADER_LEN);
}

#[test]
fn future_and_unknown_versions_are_refused_cleanly() {
    let (_v, mut bytes) = new_vault();
    bytes[8..10].copy_from_slice(&2u16.to_le_bytes());
    assert_eq!(
        UnlockedVault::unlock(&bytes, &pw(PW)).unwrap_err(),
        Error::UnsupportedVersion(2)
    );
    bytes[8..10].copy_from_slice(&0u16.to_le_bytes());
    assert_eq!(
        UnlockedVault::unlock(&bytes, &pw(PW)).unwrap_err(),
        Error::UnsupportedVersion(0)
    );
}

#[test]
fn foreign_files_are_not_mistaken_for_vaults() {
    assert_eq!(
        Header::parse(&[0u8; HEADER_LEN]).unwrap_err(),
        Error::BadMagic
    );
    assert!(Header::parse(b"PK\x03\x04").is_err());
}

#[test]
fn snapshot_layout_and_padding() {
    let (v, _h) = new_vault();
    let blob = v.seal_snapshot(42, b"hello").unwrap();
    assert_eq!(&blob[0..8], &SNAPSHOT_MAGIC);
    let info = inspect_snapshot(&blob).unwrap();
    assert_eq!(info.revision, 42);
    assert_eq!(info.vk_generation, 1);
    assert_eq!(&info.vault_id, v.vault_id());
    assert_eq!(blob.len(), 40 + 24 + 4096 + 16);
    // 5 bytes and 4000 bytes are indistinguishable by size; 5000 bytes is the next bucket.
    assert_eq!(v.seal_snapshot(1, &[1u8; 4000]).unwrap().len(), blob.len());
    assert_eq!(
        v.seal_snapshot(1, &[1u8; 5000]).unwrap().len(),
        blob.len() + 4096
    );
}

#[test]
fn snapshot_roundtrip_for_boundary_sizes() {
    let (v, _h) = new_vault();
    for n in [0usize, 1, 4087, 4088, 4089, 8191, 8192, 100_000] {
        let data = vec![0x5A; n];
        let blob = v.seal_snapshot(9, &data).unwrap();
        let (rev, pt) = v.open_snapshot(&blob).unwrap();
        assert_eq!(rev, 9);
        assert_eq!(pt.as_slice(), data.as_slice());
    }
}

#[test]
fn plaintext_does_not_appear_in_snapshot_bytes() {
    let (v, _h) = new_vault();
    let marker = b"MARKER-PLAINTEXT-MARKER-0123456789";
    let blob = v.seal_snapshot(1, marker).unwrap();
    assert!(!blob.windows(marker.len()).any(|w| w == marker));
}
