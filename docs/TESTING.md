# Testing and Security-Testing Strategy (decision 11)

Exact commands, toolchain and known issues: **docs/VERIFICATION.md**. In short (from the repo root; **all-features is required**, integration tests refuse to compile otherwise,
so a green run can never mean "tests silently skipped"):

```
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test  --workspace --all-features
```

**Status of this milestone's tests: written, not yet executed.** The authoring environment had no Rust
toolchain or network. Expect to fix compile errors and possibly mismatched assumptions on the first
run. The known-answer vectors were produced independently of the Rust code, so a vector mismatch
points at a real discrepancy between code and spec, to be resolved against `VAULT_FORMAT.md`.

## Requirement → test map

| Required test | Where | Milestone |
|---|---|---|
| Vault creation | `lifecycle.rs`, `lifecycle_on_disk.rs` (real files), `vault.rs::deterministic_create_reproduces_golden_header` | 1 |
| Correct unlock / incorrect password | `lifecycle.rs` | 1 |
| Corrupted header | `tamper.rs` (every bit of all 149 bytes; truncation; extension; KDF-parameter edits; splice) + `format.rs` | 1 |
| Corrupted ciphertext / database | `tamper.rs` (every byte, plus every bit of prefix/nonce/tag, truncation, cross-vault, revision rewrite), `properties.rs` | 1 (container). Whole-DB schema corruption: M4 |
| Corrupted file chunks | `objects.rs`: every byte modified, every truncation length, chunk-boundary truncation (final flag), append, swap, duplicate, remove-middle, wrong key/object/vault, chunk-size and nonce-prefix edits, odd write/read sizes, random access, property tests | 2 (written, not yet run) |
| Password rotation | `rotation.rs` | 1 |
| Vault-key rotation | `rotation.rs` | 1 |
| File-key wrapping / rewrap | `file_keys.rs`, `rotation.rs` | 1 |
| File-key rotation (re-encrypt object) | not built | 2 |
| Backup restoration | `backup_restore.rs` (+ known-limitation test for rollback) | 1 (semantics). Archive format: 3 |
| TOTP RFC 6238 vectors | table in DATA_MODEL.md, verified independently | 4 |
| Random nonce uniqueness | `nonces.rs` (5 000 snapshot nonces, 5 000 wrap nonces, 200 vaults' salts/ids/nonces) | 1 |
| Serialization / deserialization | `format.rs`, `header.rs` unit tests, `properties.rs` | 1 |
| Version compatibility | `golden_v1.rs` (frozen independently generated files), `format.rs` (v0/v2 refused) | 1 |
| Property-based | `properties.rs` (roundtrips, single-bit-flip detection, parser no-panic, any valid KDF params, password constructor) | 1 |
| Fuzzing | `crates/vault-core/fuzz` targets `header_parse`, `snapshot_open` (Linux/WSL, nightly; `--dev` if the release guard trips) | 1 (targets), run in CI later |

## App tests (`cd src-tauri; cargo test`)
Unit tests for TOTP (RFC 6238 vectors), the model (including **every mutation followed by its undo restores the model
byte-for-byte**), the store (instance lock, leftover cleanup, id validation) and the transactional session
(`commands.rs`: injected write failures for each mutating operation). The session tests use the core's weak-KDF feature
through a **dev-dependency**, so they run in milliseconds in a normal debug `cargo test`; `cargo test --release` is not
supported for the app (the core refuses that feature without debug assertions). None of these have been run by the author.

## Cryptographic known-answer tests
* XChaCha20-Poly1305: draft-irtf-cfrg-xchacha-03 A.3.1 (`aead.rs`).
* Argon2id, HKDF (KEK, three subkeys), header, snapshot, wrapped file key: values from
  `tools/gen_vectors.py`, an independent OpenSSL-backed implementation, itself validated against the
  draft's HChaCha20 and AEAD vectors.
* Regenerate with `python3 tools/gen_vectors.py` (needs `cryptography` ≥ 44). Regenerating changes the
  golden files; doing so is a **format change** unless the output is byte-identical.

## Security-focused practices
* `clippy::unwrap_used/expect_used/print_*` denied in library code; `unsafe` forbidden.
* Secret types: no `Clone`, redacted `Debug`, constant-time `Eq`; tests assert redaction.
* CI (planned): Windows + Linux matrix, `cargo audit`, doc tests, coverage via `cargo-llvm-cov`.
* Later milestones: a test that plants a marker password, locks, and scans process memory (best-effort
  evidence only); scan logs and temp directories for the marker after a full workflow; crash-injection
  tests around the commit protocol (kill between each step in VAULT_FORMAT §7); large-file chunk
  tampering matrix; independent security review before any "production" language.

## Lint policy for tests
Production code is held to `unwrap_used`, `expect_used`, `print_stdout`, `print_stderr`, `dbg_macro` and `todo` as errors
(workspace lints in the root `Cargo.toml`). That is unchanged and has no exceptions: `src/` and `examples/` contain no
`allow` for these lints.

In tests, panicking on a failed fixture or assertion is the intended behaviour (it gives a backtrace at the exact line),
so `unwrap()` and `expect()` are used freely. `clippy.toml` sets `allow-unwrap-in-tests` and `allow-expect-in-tests`, which is
enough for unit tests inside `src/` (`#[test]` functions and `#[cfg(test)]` modules) but **not** for helper functions in
integration-test crates under `tests/` (for example `common::new_vault`, `golden_v1::arr`, `TempDir::new`), as the first Windows
Clippy run showed. Each of the 11 integration-test crates therefore carries an explicit, narrow allowance at its crate root:

```rust
#![allow(clippy::unwrap_used, clippy::expect_used)]
```

It names only those two lints, applies only to that test crate (never to the library or the example), and is repeated rather
than set globally on purpose, so a new test crate has to opt in consciously. Alternatives considered: converting every test and
helper to return `Result` (large, risky churn that adds noise without improving the failure message) and weakening the
workspace lints (rejected: it would weaken production code).

Related, already documented exceptions: `#![allow(clippy::needless_range_loop)]` in the exhaustive byte-loop tests
(`tamper.rs`, `file_keys.rs`, `objects.rs`) and `#![allow(dead_code)]` in the shared test helper modules.

## What these tests cannot show
Absence of side channels, correctness of third-party crates, OS-level memory residue, or resistance
to a compromised host. Tests reduce the chance of mistakes; they are not a proof.

## Known weak spots to watch on first run
`tamper.rs` is the slowest test (debug-build Argon2 on valid-but-larger cost settings is skipped above
1 MiB by design). `properties.rs` default 64 cases per property; set `PROPTEST_CASES=1000` for deeper runs (the tests read it).
