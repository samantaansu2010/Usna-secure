# Dependencies (decision 13)

Policy: `default-features = false` where possible; no network-capable crates in `vault-core`; no
`unsafe` in our code (`forbid`); every crypto or secret-handling dependency justified here; commit
`Cargo.lock`; run `cargo audit` in CI; review each upgrade diff for crypto crates.

## Verification status (honest ledger)

Checked against the published manifests (via docs.rs and GitHub, during review):

| Crate | Result |
|---|---|
| `argon2` 0.5.3 | features `alloc`, `zeroize`, `password-hash`, `rand`, `std`, `simple` exist; `zeroize` wipes the working memory when `alloc` is active. **0.6.0 also exists** (edition 2024, rust-version 1.85, different feature set); we stay on `^0.5` deliberately |
| `chacha20poly1305` 0.10.1 | `alloc` feature exists; defaults are `alloc` + `getrandom`; it enables `zeroize` on its inner `chacha20` dependency; edition 2021 |
| `secrecy` 0.8.0 | `Secret<S: Zeroize>`, `ExposeSecret`; default feature `alloc`. 0.10 has a different API (`SecretBox`), deliberately not used |
| `proptest` | rust-version 1.65 on the 1.4/1.5 lines; newer releases exist whose MSRV was **not** checked |
| `totp-rs` | see DATA_MODEL; MIT; features `otpauth`, `qr`, `serde_support`, `gen_secret`, `steam`, `zeroize` on 5.x |
| `zeroize` `derive` feature | seen in use by third-party manifests, not read from zeroize's own manifest |
| `hkdf` 0.12 / `sha2` 0.10 | seen only in third-party manifests |
| `getrandom` 0.2, `subtle` 2, `thiserror` 1, `unicode-normalization` 0.1, `hex` 0.4 | **not checked** in this review. Local `cargo generate-lockfile` + `cargo build` will confirm names immediately |

Newer majors exist for `getrandom` (0.3+), `thiserror` (2) and `secrecy` (0.10). We pin the older majors on
purpose to match the code written and reviewed; upgrading is a separate, deliberate change.

**No `Cargo.lock` exists yet** (no network in the authoring environment). Generate it locally (docs/VERIFICATION.md),
inspect `cargo tree -e features`, and commit it.

## `usna-vault-core` runtime

| Crate | Purpose | Justification / notes |
|---|---|---|
| `argon2` 0.5 (RustCrypto) | Argon2id | Pure Rust, widely used. `default-features = false, features = ["alloc", "zeroize"]` drops `password-hash`/`rand_core`; `zeroize` wipes its working memory. No `parallel`/rayon, hence default p = 1 |
| `chacha20poly1305` 0.10 (RustCrypto) | XChaCha20-Poly1305 | Pure Rust AEAD with 192-bit nonces (safe random nonces). `default-features = false, features = ["alloc"]` removes its own RNG |
| `hkdf` 0.12 + `sha2` 0.10 | Key separation | Standard RFC 5869 |
| `zeroize` 1 (derive) | Wipe secrets on drop | Standard; best-effort semantics documented |
| `secrecy` 0.8 | `Secret<Vec<u8>>` for the password | Redacted Debug, zeroize on drop. Pinned to 0.8 API; 0.10 changed types, revisit deliberately |
| `getrandom` 0.2 | OS CSPRNG | No userland PRNG; the Windows API used depends on the crate version (check the resolved version's docs) |
| `subtle` 2 | Constant-time equality | Key comparison without early exit |
| `unicode-normalization` 0.1 | NFC for passwords | Same passphrase must derive the same key regardless of composition; pure Rust |
| `thiserror` 1 | Error derive | No runtime effect |

**Considered and rejected:** `aes-gcm` (96-bit nonce reuse risk with random nonces at vault scale);
`ring`/OpenSSL bindings (C/asm build complexity on Windows, second stack); `libsodium` bindings
(C dependency; `sodiumoxide` is unmaintained); SQLCipher (ARCHITECTURE §3).

## Dev-only
`proptest` (property tests), `hex` (vector decoding). Planned: `cargo-fuzz` (libFuzzer, Linux/WSL),
`cargo-audit`, `cargo-llvm-cov`.

## Planned later (not in this milestone)
`ciborium` (snapshot serialization), `zxcvbn` (strength estimate), `totp-rs` (TOTP; fallback `hmac` + `sha1`), `arboard` or direct Win32 (clipboard with history exclusion),
`windows` (VirtualLock, MoveFileExW write-through), `tauri` 2 (app layer only, never in `vault-core`).
