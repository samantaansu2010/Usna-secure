#![no_main]
use libfuzzer_sys::fuzz_target;
use std::sync::OnceLock;
use usna_vault_core::{Password, UnlockedVault};

const HEADER: &[u8] = include_bytes!("../../tests/vectors/header_v1.bin");

fn vault() -> &'static UnlockedVault {
    static V: OnceLock<UnlockedVault> = OnceLock::new();
    V.get_or_init(|| {
        let pw = Password::new("correct horse battery staple").unwrap();
        UnlockedVault::unlock(HEADER, &pw).unwrap()
    })
}

fuzz_target!(|data: &[u8]| {
    // Arbitrary bytes must be rejected (never accepted, never panic).
    assert!(vault().open_snapshot(data).is_err());
});
