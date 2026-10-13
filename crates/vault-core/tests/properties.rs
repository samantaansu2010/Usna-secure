//! Property-based tests: round-trips, single-bit-flip detection, parser robustness, arbitrary valid KDF parameters.
// Test crate: panicking on a failed fixture or assertion is intended (docs/TESTING.md, "Lint policy for tests").
#![allow(clippy::unwrap_used, clippy::expect_used)]
mod common;
use common::*;
use proptest::prelude::*;
use std::sync::OnceLock;
use usna_vault_core::{
    inspect_snapshot, Error, FileKey, Header, KdfParams, ObjectId, Password, UnlockedVault,
};

fn fixture() -> &'static UnlockedVault {
    static F: OnceLock<UnlockedVault> = OnceLock::new();
    F.get_or_init(|| new_vault().0)
}

/// Cleartext prefix (40) + nonce (24) + Poly1305 tag (16): a snapshot is this overhead plus a whole number of
/// 4096-byte padded blocks (docs/VAULT_FORMAT.md section 5).
const SNAPSHOT_OVERHEAD: usize = 40 + 24 + 16;

/// 64 cases by default; `PROPTEST_CASES=1000 cargo test ...` runs deeper.
fn cfg() -> ProptestConfig {
    let cases = std::env::var("PROPTEST_CASES")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(64);
    ProptestConfig {
        cases,
        ..ProptestConfig::default()
    }
}

proptest! {
    #![proptest_config(cfg())]

    #[test]
    fn snapshot_roundtrip(data in proptest::collection::vec(any::<u8>(), 0..20_000), rev in any::<u64>()) {
        let v = fixture();
        let blob = v.seal_snapshot(rev, &data).unwrap();
        let (r, pt) = v.open_snapshot(&blob).unwrap();
        prop_assert_eq!(r, rev);
        prop_assert_eq!(pt.as_slice(), data.as_slice());
        prop_assert!(blob.len() >= SNAPSHOT_OVERHEAD, "snapshot shorter than its fixed overhead");
        prop_assert_eq!((blob.len() - SNAPSHOT_OVERHEAD) % 4096, 0, "length must be overhead plus whole 4096-byte blocks");
    }

    #[test]
    fn any_single_bit_flip_in_a_snapshot_is_detected(
        data in proptest::collection::vec(any::<u8>(), 0..6_000),
        pos in any::<prop::sample::Index>(),
        bit in 0u8..8,
    ) {
        let v = fixture();
        let mut blob = v.seal_snapshot(1, &data).unwrap();
        let i = pos.index(blob.len());
        blob[i] ^= 1 << bit;
        prop_assert!(v.open_snapshot(&blob).is_err());
    }

    #[test]
    fn file_key_wrap_roundtrip_and_binding(key in any::<[u8; 32]>(), id in any::<[u8; 16]>(), other in any::<[u8; 16]>()) {
        let v = fixture();
        let (fk, oid) = (FileKey::from_bytes(key), ObjectId::from_bytes(id));
        let w = v.wrap_file_key(&fk, &oid).unwrap();
        prop_assert!(v.unwrap_file_key(&w, &oid).unwrap() == fk);
        if other != id {
            prop_assert!(v.unwrap_file_key(&w, &ObjectId::from_bytes(other)).is_err());
        }
    }

    #[test]
    fn parsers_never_panic_on_arbitrary_input(bytes in proptest::collection::vec(any::<u8>(), 0..9_000)) {
        let _ = Header::parse(&bytes);
        let _ = inspect_snapshot(&bytes);
        let _ = fixture().open_snapshot(&bytes);
        let _ = usna_vault_core::WrappedFileKey::from_slice(&bytes);
    }

    #[test]
    fn mutated_headers_never_unlock(pos in 0usize..149, mask in 1u8..=255) {
        // Cheap parameter-preserving property; the exhaustive bit-flip test lives in tamper.rs.
        let (_v, mut h) = new_vault();
        h[pos] ^= mask;
        // Skip mutations that turn into a (valid) very expensive KDF configuration.
        if let Ok(parsed) = Header::parse(&h) {
            prop_assume!(parsed.kdf_params().m_cost_kib <= 1024);
        }
        prop_assert!(UnlockedVault::unlock(&h, &pw(PW)).is_err());
    }

    #[test]
    fn any_valid_kdf_parameters_roundtrip(m_blocks in 1u32..=8, t in 1u32..=3, p in 1u32..=8) {
        prop_assume!(p <= m_blocks);
        let params = KdfParams { m_cost_kib: m_blocks * 8, t_cost: t, parallelism: p };
        let (v, h) = UnlockedVault::create(&pw(PW), params).unwrap();
        prop_assert_eq!(Header::parse(&h).unwrap().kdf_params(), params);
        let again = UnlockedVault::unlock(&h, &pw(PW)).unwrap();
        prop_assert_eq!(again.vault_id(), v.vault_id());
    }

    #[test]
    fn password_constructor_never_panics(s in any::<String>()) {
        match Password::new(&s) {
            Ok(_) => prop_assert!(!s.is_empty()),
            Err(e) => prop_assert!(matches!(e, Error::InvalidPassword(_))),
        }
    }
}
