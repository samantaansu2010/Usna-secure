//! Tamper detection: exhaustive bit and byte corruption of headers and snapshots, truncation, splicing, cross-vault use.
// Test crate: panicking on a failed fixture or assertion is intended (docs/TESTING.md, "Lint policy for tests").
#![allow(clippy::unwrap_used, clippy::expect_used)]
#![allow(clippy::needless_range_loop)]
mod common;
use common::*;
use usna_vault_core::{inspect_snapshot, Error, Header, UnlockedVault, HEADER_LEN};

fn rejects(header: &[u8]) -> bool {
    UnlockedVault::unlock(header, &pw(PW)).is_err()
}

#[test]
fn every_single_bit_flip_in_the_header_is_rejected() {
    let (_v, header) = new_vault();
    assert!(!rejects(&header), "control: untouched header must unlock");
    for byte in 0..HEADER_LEN {
        for bit in 0..8 {
            let mut h = header.clone();
            h[byte] ^= 1 << bit;
            // A flipped memory-cost bit can yield a *valid but expensive* Argon2 setting (up to
            // 512 MiB). Those are skipped here to keep the suite fast; the AEAD binding of the
            // KDF parameters is covered by `modified_kdf_parameters_fail_authentication...`.
            if let Ok(parsed) = Header::parse(&h) {
                if parsed.kdf_params().m_cost_kib > 1024 {
                    continue;
                }
            }
            assert!(rejects(&h), "flip of bit {bit} in byte {byte} was accepted");
        }
    }
}

#[test]
fn truncated_and_extended_headers_are_rejected() {
    let (_v, header) = new_vault();
    for len in [0, 1, 8, 76, 77, 100, HEADER_LEN - 1] {
        assert!(rejects(&header[..len]), "len {len}");
    }
    let mut longer = header.clone();
    longer.push(0);
    assert!(rejects(&longer));
}

#[test]
fn modified_kdf_parameters_fail_authentication_not_just_parsing() {
    // 33..37 is the memory cost. 8 -> 16 KiB is a *valid* parameter set, so parsing succeeds;
    // only the AEAD binding of the header prefix can catch it.
    let (_v, header) = new_vault();
    let mut h = header.clone();
    h[33..37].copy_from_slice(&16u32.to_le_bytes());
    assert!(Header::parse(&h).is_ok());
    assert_eq!(
        UnlockedVault::unlock(&h, &pw(PW)).unwrap_err(),
        Error::AuthenticationFailed
    );
}

#[test]
fn hostile_kdf_parameters_are_refused_before_argon2_runs() {
    let (_v, header) = new_vault();
    let mut h = header;
    h[33..37].copy_from_slice(&u32::MAX.to_le_bytes()); // ~4 TiB request
    assert!(matches!(
        UnlockedVault::unlock(&h, &pw(PW)),
        Err(Error::InvalidKdfParams(_))
    ));
}

#[test]
fn snapshot_corruption_is_detected_everywhere() {
    let (vault, _h) = new_vault();
    let blob = vault.seal_snapshot(3, b"apps, notes, folder tree").unwrap();
    assert!(vault.open_snapshot(&blob).is_ok());
    // every byte (xor 0x01) across the whole snapshot
    for i in 0..blob.len() {
        let mut b = blob.clone();
        b[i] ^= 0x01;
        assert!(
            vault.open_snapshot(&b).is_err(),
            "byte {i} modification accepted"
        );
    }
    // every bit of the cleartext prefix, nonce and tag
    for i in (0..64).chain(blob.len() - 16..blob.len()) {
        for bit in 0..8 {
            let mut b = blob.clone();
            b[i] ^= 1 << bit;
            assert!(
                vault.open_snapshot(&b).is_err(),
                "bit {bit} of byte {i} accepted"
            );
        }
    }
}

#[test]
fn snapshot_truncation_and_extension_are_rejected() {
    let (vault, _h) = new_vault();
    let blob = vault.seal_snapshot(1, b"x").unwrap();
    assert!(vault.open_snapshot(&blob[..blob.len() - 1]).is_err());
    assert!(vault.open_snapshot(&blob[..blob.len() - 4096]).is_err());
    let mut longer = blob.clone();
    longer.extend_from_slice(&[0u8; 4096]);
    assert!(vault.open_snapshot(&longer).is_err());
    assert!(vault.open_snapshot(&[]).is_err());
}

#[test]
fn snapshot_from_another_vault_is_rejected() {
    let (a, _) = new_vault();
    let (b, _) = new_vault();
    let blob = a.seal_snapshot(1, b"secret of A").unwrap();
    assert!(matches!(
        b.open_snapshot(&blob),
        Err(Error::SnapshotMismatch(_))
    ));
}

#[test]
fn rewriting_the_cleartext_revision_is_detected() {
    let (vault, _h) = new_vault();
    let mut blob = vault.seal_snapshot(5, b"data").unwrap();
    blob[32..40].copy_from_slice(&6u64.to_le_bytes());
    assert_eq!(inspect_snapshot(&blob).unwrap().revision, 6);
    assert_eq!(
        vault.open_snapshot(&blob).unwrap_err(),
        Error::AuthenticationFailed
    );
}

#[test]
fn header_swap_between_vaults_does_not_unlock() {
    let (_a, ha) = new_vault();
    let (_b, hb) = new_vault();
    // splice B's wrapped VK into A's header
    let mut spliced = ha.clone();
    spliced[77..HEADER_LEN].copy_from_slice(&hb[77..HEADER_LEN]);
    assert!(rejects(&spliced));
}
