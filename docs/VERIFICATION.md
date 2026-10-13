# Verification Guide (Windows)

**Status: nothing in this repository has been compiled or tested.** The authoring environment had no Rust
toolchain. Results come only from running the steps below. Do not treat any test as passing until you have
seen it run.

## Toolchain requirements

| Item | Requirement |
|---|---|
| OS | Windows 10/11 x64 |
| Rust | **stable, 1.85.0 or newer** (declared `rust-version`; not yet verified by a build). Cargo 1.84 or newer is required for `resolver = "3"` |
| Target | `x86_64-pc-windows-msvc` (the rustup default on Windows) |
| C++ build tools | Visual Studio 2022 Build Tools with the "Desktop development with C++" workload and a Windows 10/11 SDK |
| Components | `rustfmt`, `clippy` (declared in `rust-toolchain.toml`) |
| Optional | Python 3.10 or newer with `cryptography` (46.0.6 was used) only to regenerate vectors; the golden files are already committed. Linux/WSL, nightly and `cargo-fuzz` for fuzzing |

After the first fully green run, pin the exact version in `rust-toolchain.toml` and record it here.
Verified toolchain: **none yet**.

**The desktop app (`src-tauri`) additionally needs Rust 1.89 or newer** (it uses `std::fs::File::try_lock` for the single-instance
lock). If your toolchain is older, run `rustup update stable`.

## Commands (from the repo root)

Easiest: `powershell -ExecutionPolicy Bypass -File scripts\verify.ps1`, then `echo $LASTEXITCODE`. The script runs the
steps below in order and, for every step, records the command, its output and its **real exit code** in
`verification-report.txt`. A missing command counts as a failure. At the end it prints a summary with the summed
test counts and **exits 1 if any required step failed** (0 only if all succeeded). `cargo.lock` is generated once if
absent; every later step uses `--locked` so versions cannot drift silently. Manual equivalents:

| # | Command | What it does |
|---|---|---|
| 1 | `rustc --version --verbose` and `cargo --version` | Records the toolchain actually in use |
| 2 | `cargo generate-lockfile` | Resolves all dependencies and writes `Cargo.lock`. This is the first real check that crate names and feature flags exist. Commit the lockfile afterwards |
| 3 | `cargo tree -p usna-vault-core -e features` | Shows the resolved dependency tree with enabled features. Compare with docs/DEPENDENCIES.md |
| 4 | `cargo tree -d` | Lists crates present in more than one version |
| 5 | `cargo fmt --all` | Rewrites source files to the project style. Run once; some lines were written longer than 100 columns |
| 6 | `cargo fmt --all -- --check` | Fails if any file is not formatted; changes nothing |
| 7 | `cargo build --locked --workspace --all-features` | Compiles the library. Must succeed before anything else is meaningful |
| 8 | `cargo clippy --locked --workspace --all-targets --all-features -- -D warnings` | Lints everything and turns warnings into errors (unsafe is forbidden; unwrap and print denied in library code) |
| 9 | `cargo test --locked --workspace --all-features` | Runs unit, integration, property and doc tests. `--all-features` is mandatory (see issue 2) |

| 10 | `cargo run --release --locked -p usna-vault-core --example lifecycle_demo -- <dir>` | Runs the local lifecycle demonstration (below) with the real 256 MiB Argon2id parameters |

Optional afterwards:
* `cargo install cargo-audit --locked` then `cargo audit` checks the lockfile for known vulnerabilities.
* Deeper property runs: in PowerShell `$env:PROPTEST_CASES=1000; cargo test --workspace --all-features`.

## What to expect from the app tests
`scripts\build-app.ps1` runs `cargo test --locked` inside `src-tauri`. That includes the transactional-save tests. If one
fails, it is most likely either a compile error (the code is unrun) or a genuine consistency bug; send the failing test name
and message.

## Known build and test issues (expected, not yet observed)

1. **Compile errors are likely on the first build.** The code was written without a compiler. Report the exact output.
2. **`cargo test` without `--all-features` fails on purpose.** Integration tests contain `compile_error!` so they can
   never be silently skipped. They need the weak-KDF feature `insecure-test-params`.
3. **`--release` together with `--all-features` fails on purpose.** The library refuses to compile with the weak-KDF
   feature when debug assertions are off. Do not release-test with it.
4. **`cargo fmt --check` fails until `cargo fmt --all` has been run once.**
5. **Clippy may flag items I could not predict**, and lint sets change between Rust releases.
6. **Dependency names and features are only partly verified** (see the ledger in docs/DEPENDENCIES.md). The most
   likely failures are a wrong feature name or API drift in `hkdf`, `getrandom` or `secrecy`; the error will be explicit.
   If `argon2` fails to build with `default-features = false`, restore its default features and report it.
7. **A known-answer vector mismatch** would mean code and spec disagree. Compare with docs/VAULT_FORMAT.md before
   changing any vector.
8. **`tamper.rs` is the slowest test** (thousands of unlock attempts); it skips flipped KDF settings above 1 MiB.
9. **`proptest` writes `proptest-regressions/` files on failure.** Keep them and report the seed.
10. **Fuzz targets** build only on Linux/WSL with nightly and may need `--dev`; they are not part of the Windows run.
11. **Windows Defender** can slow the first test run noticeably (many small binaries). This is cosmetic.

## Verification log
Results are recorded here as **reported by the project owner** from `scripts\verify.ps1` on Windows. The author of this
repository has no Rust toolchain and has not run any of them.

| Run | fmt | build | clippy (`-D warnings`) | tests | demo | Notes |
|---|---|---|---|---|---|---|
| Report 1 (before the lint fix) | passed | passed | **failed, exit 101** | 108 passed, 0 failed | passed | `unwrap_used` in 11 integration-test crates; `identity_op` at `properties.rs` |
| After the lint fix | not yet run | not yet run | **not yet run** | not yet run | not yet run | Re-run `scripts\verify.ps1` and record the result here |

## What to send back

`verification-report.txt` (from the script), or the full output of steps 1 to 9, plus the first failing message
of any step that fails.

## Local lifecycle demonstration

**What the current core can do** (public API, no I/O): `UnlockedVault::create` returns the unlocked vault and the header
bytes to persist; `seal_snapshot` / `open_snapshot` encrypt and authenticate arbitrary bytes; `unlock` takes header bytes
plus a password; `lock` wipes the keys. That is enough to demonstrate create → store an encrypted entry → lock →
reopen → recover, with the files written by the caller.

**What it cannot do yet (so the demo does not pretend to):**
* no entry or field model, no serialization of apps/passwords (milestone 4); the demo uses a throwaway three-string
  encoding, marked as demo-only in `tests/support/demo_entry.rs`;
* no storage layer *in the core*: no atomic commit with write-through, no lock file, no crash recovery, no `vault verify` (the desktop app's `store.rs` adds an instance lock, leftover cleanup and an integrity check, but still no write-through)
  (milestone 3); the demo writes `vault.header` and `vault.db` with plain `std::fs` (temp file, flush, rename);
* no encrypted file objects (milestone 2), no backups (milestone 3);
* **no desktop application**: there is no UI, Tauri shell or command API, and nothing here is a runnable app.

Two ways to run it (each is real, nothing is mocked; the cryptography is the production code path):

| What | Command (PowerShell, repo root) | Notes |
|---|---|---|
| Integration test with real files | `cargo test --locked -p usna-vault-core --all-features --test lifecycle_on_disk` | Weak test KDF parameters; temp directory removed afterwards |
| Runnable demo | `cargo run --release --locked -p usna-vault-core --example lifecycle_demo -- C:\temp\usna-demo` | Real parameters (256 MiB Argon2id, 3 passes); needs `--release`; target directory must not exist or be empty; left in place for inspection |

Demo password: set `$env:USNA_DEMO_PASSWORD = "your passphrase"` first, otherwise a fixed demo password is used. The demo
prints a pass/fail line for each of: no plaintext in the files, wrong password rejected, entry recovered identically,
tampering detected, and exits with an error if any check fails. After a run you can inspect `vault.header` (149 bytes)
and `vault.db` (4176 bytes for a small entry) with any hex viewer.
