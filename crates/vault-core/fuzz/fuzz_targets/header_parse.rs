#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Structural parsing must never panic or allocate based on attacker-controlled sizes.
    let _ = usna_vault_core::Header::parse(data);
    let _ = usna_vault_core::inspect_snapshot(data);
});
