# USNA Secure

A local, offline, encrypted vault for Windows. It stores app credentials, authenticator (TOTP) secrets, secure
notes, passkey records and, eventually, encrypted private files. There is no account, no cloud, no telemetry and no
network code. You download it, create a vault, and use it entirely offline.

> **Read this first: honest status**
>
> * The **cryptographic core** (`crates/vault-core`) has a full test suite. The project owner reported the
>   milestone-1 verification run as green; the author of this document has not run it independently.
> * The **desktop app** (`src-tauri/`, `ui/`) is written but **has not been compiled or run yet**. Expect compile
>   errors on its first build.
> * Nothing here has been security-reviewed or audited. **Do not store real secrets in it yet.** It is not
>   production-ready and makes no claim of being unbreakable.
> * Encrypted files and folders are now **written** (core format + app screens) but the author has **not compiled or run** them. Backups and
>   vault-key rotation in the app are **not implemented** (designed, not built).

License: Apache License 2.0 (see `LICENSE`).

---

## Table of contents

1. [What it does today](#1-what-it-does-today)
2. [Quick start (Windows)](#2-quick-start-windows)
3. [Repository map](#3-repository-map)
4. [Architecture](#4-architecture)
5. [Cryptographic design](#5-cryptographic-design)
6. [On-disk formats](#6-on-disk-formats)
7. [The core's public API](#7-the-cores-public-api)
8. [The desktop app](#8-the-desktop-app)
9. [Threat model in one page](#9-threat-model-in-one-page)
10. [Testing](#10-testing)
11. [Developer workflow](#11-developer-workflow)
12. [Rules for changing this codebase](#12-rules-for-changing-this-codebase)
13. [Roadmap and feature backlog](#13-roadmap-and-feature-backlog)
14. [Recipes: how to add things](#14-recipes-how-to-add-things)
15. [Known limitations and open decisions](#15-known-limitations-and-open-decisions)
16. [Troubleshooting](#16-troubleshooting)
17. [Glossary](#17-glossary)

---

## 1. What it does today

| Area | State |
|---|---|
| Create, unlock and lock a vault (core) | Implemented and tested |
| Argon2id key derivation, random vault key, HKDF subkeys, XChaCha20-Poly1305 | Implemented and tested |
| Authenticated header, tamper detection, version handling | Implemented and tested |
| Encrypted database snapshot (padded, authenticated) | Implemented and tested |
| Password change (re-wrap the vault key) | Implemented and tested |
| Vault-key rotation (core API) | Implemented and tested; **not exposed in the app** |
| Per-file key generation and wrapping (core API) | Implemented and tested; no file storage yet |
| Desktop app: first-run setup, unlock, lock, inactivity lock | Written, **not yet compiled** |
| Desktop app: apps and notes, search, favorites, edit, delete | Written, not yet compiled |
| Desktop app: live TOTP code, password generator, timed clipboard clearing | Written, not yet compiled |
| Encrypted file objects in the core (streaming, random access, tamper matrix) | Written, **not yet compiled** |
| Desktop app: folders, import/export, image preview, integrity check, single-instance lock, unlock back-off | Written, **not yet compiled** |
| Transactional saves: a failed write reverts the live model; files are deleted only after the new snapshot is committed | Written with failure-injection tests (unrun); fixes a bug found in review (`docs/DESIGN_REVIEW.md` R15) |
| Streaming video/PDF preview (`usna://`), file-key rotation | Not built |
| Encrypted backup/export (`.usnabak`) and restore | Specified only (`docs/BACKUP_FORMAT.md`) |
| Real passkey (WebAuthn) support | Out of scope for now; only a record flag |

---

## 2. Quick start (Windows)

### 2.1 Install the prerequisites

| Need | Details |
|---|---|
| Rust | Stable **1.85.0 or newer** for the core, **1.89.0 or newer** for the desktop app, via https://rustup.rs (target `x86_64-pc-windows-msvc`). Cargo 1.84+ is needed for the dependency-resolver setting used here |
| C++ build tools | Visual Studio 2022 Build Tools, workload "Desktop development with C++", with a Windows 10/11 SDK |
| WebView2 | Preinstalled on current Windows 10/11; needed to run the app window |
| Optional | Python 3.10+ with `cryptography` only to regenerate test vectors (golden files are already committed) |

**What is Cargo?** Cargo is Rust's build tool. It downloads the libraries a project needs, compiles the code,
runs the tests and builds the program. It is installed together with Rust.

### 2.2 Verify the core, then build the app

Run from the repository root in PowerShell:

```powershell
# 1. Core: format, build, lint (warnings are errors), full test suite, lifecycle demo.
powershell -ExecutionPolicy Bypass -File scripts\verify.ps1
echo $LASTEXITCODE        # 0 means every required step succeeded

# 2. App: unit tests, then the desktop app and Windows installer.
powershell -ExecutionPolicy Bypass -File scripts\build-app.ps1

# 3. Run it.
src-tauri\target\release\usna-secure-app.exe
```

Both scripts record every command, its output and its real exit code in `verification-report.txt` and
`app-build-report.txt`, and exit with status 1 if any required step failed. Send those files with any bug report.

### 2.3 Run just the core demonstration

```powershell
cargo run --release -p usna-vault-core --example lifecycle_demo -- C:\temp\usna-demo
```

It creates a vault with real parameters, stores an encrypted test entry, locks, rejects a wrong password, reopens,
verifies the entry is recovered exactly, and verifies that one flipped bit is detected.

### 2.4 Manual command reference

| Command | What it does |
|---|---|
| `cargo generate-lockfile` | Resolves dependencies and writes `Cargo.lock` (first time only; commit it) |
| `cargo fmt --all` / `cargo fmt --all -- --check` | Formats the code / fails if anything is unformatted |
| `cargo build --locked --workspace --all-features` | Compiles the core |
| `cargo clippy --locked --workspace --all-targets --all-features -- -D warnings` | Lints, with warnings treated as errors |
| `cargo test --locked --workspace --all-features` | Runs all core tests. **`--all-features` is mandatory** (weak KDF parameters for tests) |
| `cd src-tauri; cargo test` | Runs the app's unit tests (TOTP RFC vectors, model, generator) |
| `cargo tauri dev` (repo root) | Runs the app in development mode (needs `cargo install tauri-cli --version "^2" --locked`) |

Deliberate failures (not bugs): `cargo test` without `--all-features` and `--release` with `--all-features` both
refuse to compile, so tests can never be silently skipped and weak test parameters can never reach a release build.

---

## 3. Repository map

```
usna-secure/
├── LICENSE                      Apache-2.0
├── README.md                    this file
├── Cargo.toml                   workspace for the core only (resolver 3, workspace lints)
├── rust-toolchain.toml          stable + rustfmt + clippy (pin an exact version after the first green run)
├── rustfmt.toml, clippy.toml
├── .github/workflows/ci.yml     Windows + Linux CI: fmt, clippy, tests, cargo-audit (never run yet)
├── scripts/
│   ├── verify.ps1               core verification with real exit codes
│   └── build-app.ps1            app tests + build + installer with real exit codes
├── tools/
│   ├── xchacha_ref.py           independent XChaCha20-Poly1305 reference (checked against draft vectors)
│   └── gen_vectors.py           generates golden files + src/test_vectors.rs from independent crypto
├── docs/                        design documents (see below)
├── crates/vault-core/           THE SECURITY-CRITICAL CORE
│   ├── src/
│   │   ├── lib.rs               public re-exports, release-build guard for test parameters
│   │   ├── error.rs             Error enum (never contains secrets)
│   │   ├── secret.rs            SecretKey: zeroize on drop, no Clone, redacted Debug, constant-time Eq
│   │   ├── rng.rs               OS randomness only (getrandom)
│   │   ├── password.rs          Password: Unicode NFC normalization, zeroized
│   │   ├── kdf.rs               Argon2id parameters, policy floors/ceilings, derivation
│   │   ├── keys.rs              KEK and subkey derivation (HKDF), KeySet
│   │   ├── aead.rs              XChaCha20-Poly1305 wrappers
│   │   ├── header.rs            149-byte authenticated vault header
│   │   ├── snapshot.rs          sealed, padded database snapshot container
│   │   ├── filekey.rs           per-object file keys and their wrapping
│   │   ├── object.rs            encrypted file objects: ObjectWriter / ObjectReader (streaming, random access)
│   │   ├── vault.rs             UnlockedVault: create, unlock, password change, key rotation
│   │   └── test_vectors.rs      generated known-answer vectors (test builds only)
│   ├── tests/                   integration tests (see section 10)
│   ├── examples/lifecycle_demo.rs
│   └── fuzz/                    cargo-fuzz targets (Linux/WSL, nightly)
├── src-tauri/                   DESKTOP APP BACKEND (separate Cargo workspace and lockfile)
│   ├── src/main.rs              Tauri setup, window-close lock, command registration
│   ├── src/commands.rs          the narrow UI-to-core command API
│   ├── src/model.rs             interim data model (items, settings, DTOs)
│   ├── src/store.rs             vault directory: header/snapshot files, file objects, instance lock, cleanup
│   ├── src/util.rs              hex and base64 helpers
│   ├── src/totp.rs              RFC 6238 TOTP with tests
│   ├── tauri.conf.json          window, CSP, bundle config
│   ├── capabilities/default.json
│   └── icons/
└── ui/                          DESKTOP APP FRONTEND (plain HTML/CSS/JS; no keys ever)
    ├── index.html  style.css  app.js
```

### Design documents (`docs/`)

| File | Read it for |
|---|---|
| `ARCHITECTURE.md` | Layers, trust boundary, command boundary, storage comparison (SQLCipher vs SQLite vs snapshot), what an attacker learns |
| `THREAT_MODEL.md` | 14 threats with verdicts: protected, partial, or out of scope |
| `VAULT_FORMAT.md` | **Normative** byte-level spec: header, key hierarchy, snapshot, commit and crash recovery, versioning |
| `FILE_FORMAT.md` | Encrypted file objects: chunking, nonces, authenticated index, final flag (not implemented yet) |
| `BACKUP_FORMAT.md` | `.usnabak` single-file backup and reliable restore (not implemented yet) |
| `DATA_MODEL.md` | Entry and field model, TOTP design with RFC vectors, passkey record |
| `DEPENDENCIES.md` | Every dependency, why it is there, and a ledger of what was verified against manifests |
| `TESTING.md` | Requirement-to-test map, practices, what tests cannot show |
| `VERIFICATION.md` | Toolchain, commands, known build issues, the lifecycle demo |
| `DESIGN_REVIEW.md` | Findings R1 to R12 with status, and the two pending decisions |
| `APP.md` | Desktop app status and its deliberate deviations |
| `ROADMAP.md` | Milestones 1 to 8 with exit gates |

If code and `VAULT_FORMAT.md` disagree, that is a bug to resolve before release; the format is never improvised in code.

---

## 4. Architecture

```
┌──────────────────────────── Tauri 2 desktop process ─────────────────────────────┐
│  WebView2 (ui/)                        │  Rust backend (src-tauri/)               │
│  - renders view models                 │   commands.rs   narrow command API       │
│  - holds NO keys                       │   model.rs      items, settings          │
│  - sees a secret only when the user    │   store.rs      interim file store       │
│    types it or presses Show            │   totp.rs       TOTP                     │
│                                        │        │                                 │
│     invoke("command") ────────────────▶│        ▼                                 │
│     ◀──── view model without secrets   │  crates/vault-core  (the security core)  │
└──────────────────────────────────────────────────────────────────────────────────┘
```

Principles:

1. **Rust owns every secret.** Keys, TOTP secrets, password generation, clipboard writes and lock state live in Rust.
2. **The command surface is narrow.** No command returns a key, a raw TOTP secret or the whole decrypted vault.
   `reveal_password` is the only one that returns a secret, and only on an explicit user action.
3. **The core is pure.** `vault-core` does no file or network I/O and has no UI or Tauri dependency, so it is
   independently testable and reviewable. It returns the bytes to persist; the caller persists them.
4. **One cryptographic stack and one key hierarchy.** No second library such as SQLCipher is involved.
5. **Hardening of the shell:** strict content security policy (no inline scripts, no remote origins, no `eval`),
   no fs/shell/http/opener plugin, no fonts or scripts from the internet.

Unavoidable exposure, stated plainly: when you reveal a password, that text exists in the WebView process. The app
minimizes it (one field, on demand, cleared on lock) but cannot eliminate it.

---

## 5. Cryptographic design

No custom primitives. Only established algorithms from reviewed RustCrypto crates.

| Purpose | Primitive | Notes |
|---|---|---|
| Password to key | **Argon2id** v1.3 (RFC 9106) | Default 256 MiB, 3 passes, 1 lane; 32-byte salt; stored in the header |
| Key separation | **HKDF-SHA256** | Salt is the vault id; distinct `info` label per purpose |
| Encryption | **XChaCha20-Poly1305** | 192-bit random nonces, 128-bit tags, AAD binds context |
| Randomness | OS CSPRNG via `getrandom` | No userland PRNG |

### Key hierarchy

```
Master password            (NFC-normalized UTF-8, 1 to 4096 bytes)
   │  Argon2id(salt, m, t, p)
   ▼
PDK  ──HKDF──▶  KEK        (wraps the vault key; never stored)
                 │ XChaCha20-Poly1305
                 ▼
VK   = 32 random bytes     (NEVER derived from the password; stored only wrapped in the header)
   ├─HKDF──▶ K_db           encrypts the database snapshot
   ├─HKDF──▶ K_filekey_wrap wraps per-file keys
   └─ (K_manifest reserved for backups; derived on demand later, not held in memory now)

Per file object: FileKey = 32 random bytes, wrapped under K_filekey_wrap, bound to
(vault id, key generation, object id)
```

Why this shape:

* Because the vault key is random and only *wrapped* by the password-derived key, **changing the password re-wraps
  one 48-byte value** instead of re-encrypting anything.
* **Vault-key rotation** creates a new vault key and generation, re-seals the snapshot, and re-wraps each file key
  (about 72 bytes each). **File contents are not re-encrypted.**
* Every encryption binds a domain label and context into the AAD, and every derivation has its own label. A key is
  never used for two purposes.

Policy:

* Argon2 floors: memory at least 19 456 KiB, time at least 2, and at least 8 KiB per lane. Ceilings: 1 GiB, 16
  passes, 16 lanes. They are checked **before** Argon2 runs, so a hostile vault file cannot force a huge allocation.
* The KDF parameters are authenticated: they are part of the AAD of the vault-key wrap, so downgrading them fails.
* Wrong password and tampered data return the same error (`AuthenticationFailed`) on purpose.

Honest limits of this design:

* Changing the password does **not** revoke the old password for old copies of the header (backups, cloud copies).
  Those still unwrap the same vault key. See finding R2 in `docs/DESIGN_REVIEW.md`.
* Vault-key rotation does not re-encrypt files; someone with an old vault copy and the old key can still read old files.
* Nothing in the core can detect that an attacker swapped in an older authentic copy of the vault (rollback).
* `zeroize` is best-effort. It cannot reach OS copies (pagefile, hibernation, crash dumps) or library internals.

---

## 6. On-disk formats

### Vault directory

```
MyVault/
├── vault.header        149 bytes, authenticated header
├── vault.db            sealed snapshot (all structured data)
└── objects/ab/<id>.obj encrypted file objects (specified, not implemented)
```

The app currently keeps its vault in `%APPDATA%\org.usna.secure\vault\`.

### Header (`vault.header`), exactly 149 bytes, little-endian

| Offset | Len | Field |
|---:|---:|---|
| 0 | 8 | magic `"USNAVLT\0"` |
| 8 | 2 | format version (`1`) |
| 10 | 2 | flags (must be 0) |
| 12 | 16 | vault id (random) |
| 28 | 4 | vault-key generation (starts at 1) |
| 32 | 1 | KDF id (`1` = Argon2id v1.3) |
| 33 / 37 / 41 | 4 each | Argon2 memory (KiB) / time / lanes |
| 45 | 32 | KDF salt |
| 77 | 24 | wrap nonce |
| 101 | 48 | wrapped vault key (32 bytes + 16-byte tag) |

Bytes 0 to 76 are the AAD of the wrap, so every field is authenticated.

### Snapshot (`vault.db`)

40-byte cleartext prefix (magic, version, flags, vault id, generation, revision), a 24-byte nonce, then the
ciphertext of `u64 length || data || zero padding` (padded to a multiple of 4096) and a 16-byte tag. The prefix is
AAD. File size is `80 + 4096 * k`, so it reveals only a coarse size bucket.

### What an attacker holding the files can learn

Cleartext: that it is a USNA Secure vault, the format version, a random vault id, the Argon2 parameters and salt,
the key generation, the snapshot revision, a 4 KiB size bucket, and (later) the number and size of file objects.
Always encrypted: titles, names, usernames, URLs, notes, TOTP secrets, folder structure, file names and types, and
file contents. Full detail in `docs/ARCHITECTURE.md` section 4.

### Crash safety

Single-file writes use temp file, flush, rename. A vault-key rotation changes two files, so the spec defines a commit
order (`header.new` renamed as the commit point) and a recovery table in `docs/VAULT_FORMAT.md` section 7. The
interim app store does **not** implement the recovery table yet because the app never rotates the vault key.

---

## 7. The core's public API

All in `crates/vault-core/src/lib.rs`. The core never touches files; it returns bytes.

```rust
use usna_vault_core::{KdfParams, Password, UnlockedVault};

let pw = Password::new("a long passphrase")?;
let (vault, header_bytes) = UnlockedVault::create(&pw, KdfParams::RECOMMENDED)?;   // persist header_bytes
let blob = vault.seal_snapshot(1, b"serialized database")?;                         // persist blob
vault.lock();                                                                       // keys wiped (best effort)

let vault = UnlockedVault::unlock(&header_bytes, &pw)?;
let (revision, plaintext) = vault.open_snapshot(&blob)?;
```

| Item | Purpose |
|---|---|
| `Password::new(&str)` | Normalizes to NFC, rejects empty or over-long, zeroized, redacted `Debug` |
| `KdfParams::{RECOMMENDED, validate}` | Argon2id parameters and policy check |
| `UnlockedVault::create / unlock / lock` | Lifecycle |
| `seal_snapshot / open_snapshot` | Encrypt and authenticate the database blob |
| `prepare_password_change` then `commit_header_update` | Re-wrap the vault key; persist `update.bytes()` first, then commit |
| `begin_vault_key_rotation` returning `VaultKeyRotation` | Rotation: `open_old_snapshot`, `rewrap_file_key`, `seal_new_snapshot`, `new_header_bytes`, `into_new_vault` |
| `new_file_key / wrap_file_key / unwrap_file_key` | Per-object keys bound to `ObjectId` |
| `inspect_snapshot`, `Header::parse` | Read cleartext facts (generation, revision) for recovery logic |
| `Error` | `AuthenticationFailed`, `UnsupportedVersion`, `SnapshotMismatch`, `InvalidKdfParams`, ... |

**Rotation caller obligation:** the snapshot plaintext contains wrapped file keys that are bound to the old
generation. Open the old snapshot, rewrap **every** key with `rewrap_file_key`, serialize, then `seal_new_snapshot`.
Sealing the old plaintext unchanged loses every file key (there is a regression test for exactly this).

---

## 8. The desktop app

### Commands (the UI's entire power)

| Command | Returns | Notes |
|---|---|---|
| `vault_status` | `{exists, unlocked}` | |
| `vault_create(password)` | nothing | Enforces 12+ characters; async so the UI stays responsive |
| `vault_unlock(password)` | nothing | Friendly errors: wrong password vs unsupported version |
| `vault_lock` | nothing | Drops keys, wipes the model, clears our clipboard value |
| `change_password(current, new)` | nothing | Persists the header before adopting it in memory |
| `touch` | nothing | Keeps the inactivity timer alive |
| `list_items`, `get_item(id)` | summaries, views | **No secrets** |
| `reveal_password(id)` | the password | The only secret-returning command |
| `save_item(input)`, `delete_item(id)`, `set_favorite` | id or nothing | Each re-seals the snapshot |
| `totp_now(id)` | `{code, remaining}` | Secret never leaves Rust |
| `copy_field(id, field)` | nothing | Writes the clipboard in Rust; clears after the configured time if unchanged |
| `generate_password(length)` | string | Rejection sampling (no modulo bias) |
| `get_settings`, `set_settings` | settings | Stored inside the encrypted snapshot |

Events: `vault-locked` (Rust to UI) when the inactivity timer expires.

### Interim pieces you should replace

* `store.rs`: header and snapshot files (temp + flush + rename), encrypted file objects, an OS instance lock, leftover cleanup. **Still missing:** write-through rename and the rotation recovery table. All saves go through `Session::commit` (mutate, write, revert on failure); see `docs/APP.md`.
* `model.rs`: simplified JSON model. Decrypted strings are ordinary `String`s while unlocked (wiped best-effort on lock).
* `ui/`: plain JavaScript. Every interaction is a `data-act` attribute handled by one delegated listener, because
  the content security policy forbids inline handlers.

---

## 9. Threat model in one page

| Threat | Verdict |
|---|---|
| Attacker obtains the vault files | **Protected**, bounded by password strength (Argon2id cost, random vault key) |
| Attacker modifies the vault | **Detected**, not prevented (AEAD everywhere; deletion cannot be prevented, backups are the remedy) |
| Old backup or rollback | **Partial**: mixed generations are detected; an authentic older copy is not |
| Brute-forcing the master password | **Mitigated**, not eliminated: offline guessing is limited only by Argon2id cost and entropy |
| Malware running as the user, compromised OS | **Out of scope** |
| Stolen unlocked computer | **Partial**: auto-lock shortens the window |
| Clipboard leakage | **Reduced**: Rust-side copy, timed clear; other apps can read it during the window |
| Temporary plaintext files | **Avoided by design** (no plaintext temp files) |
| Crash dumps, logs, pagefile | **Reduced**, best effort; mitigations scheduled for milestone 7 |
| Lost master password | **Not recoverable, by design** |

Full table with mechanisms and limits: `docs/THREAT_MODEL.md`. Project language rule: never say "unhackable",
"military-grade" or "perfectly secure". Use precise statements.

---

## 10. Testing

### What exists (core, `crates/vault-core`)

| File | Covers |
|---|---|
| `src/*` unit tests | Known-answer vectors for Argon2id, HKDF, XChaCha20-Poly1305 (draft vector), header, snapshot, wrapped file key; padding; password normalization |
| `tests/lifecycle.rs` | Create, unlock, wrong password, normalization, KDF policy, redaction |
| `tests/lifecycle_on_disk.rs` | The same lifecycle on real files, including tamper detection after reopen |
| `tests/tamper.rs` | Every bit of the header, every byte of a snapshot, truncation, splicing, cross-vault |
| `tests/format.rs` | Header and snapshot layout, version refusal, padding buckets, round-trips |
| `tests/rotation.rs` | Password change, vault-key rotation, the key-rewrap obligation |
| `tests/file_keys.rs` | Wrap, unwrap, binding to object and vault, every bit flipped |
| `src-tauri` session tests | Inject write failures and check that the live session always equals the last committed snapshot, that failed deletes remove nothing from disk, and that objects are deleted only after the commit |
| `tests/objects.rs` | Encrypted file objects: boundary sizes, random access, and the full tamper matrix (corrupt, truncate, extend, reorder, duplicate, wrong key/object/vault) |
| `tests/nonces.rs` | Uniqueness of 5 000 snapshot nonces, 5 000 wrap nonces, 200 vault ids and salts |
| `tests/backup_restore.rs` | Restore semantics and the **known rollback limitation** (asserted, not hidden) |
| `tests/properties.rs` | Property tests: round-trips, single-bit flips, parsers never panic, arbitrary valid KDF parameters |
| `tests/golden_v1.rs` | Frozen files from an independent implementation; must open forever |
| `fuzz/` | `header_parse` and `snapshot_open` targets (Linux/WSL, nightly) |

### What exists (app, `src-tauri`)

TOTP against all 18 RFC 6238 Appendix B values (SHA-1, SHA-256, SHA-512), base32 handling, the data model
(create/update/keep/delete, validation, views never contain secrets, forward-compatible JSON), the generator.

### Independent vectors

`tools/gen_vectors.py` uses OpenSSL-backed Argon2id, HKDF and ChaCha20-Poly1305 plus a short HChaCha20 (checked
against the published draft vectors) so the Rust code is cross-checked against a different implementation.
Regenerating changes the golden files, and doing so is a **format change** unless the output is byte-identical.

### Not tested yet

The Tauri window and UI flow, crash injection around commits, large-file streaming, memory-residue scans, and
anything in milestones 2 to 8.

### What tests cannot show

Absence of side channels, correctness of third-party crates, OS memory residue, or resistance to a compromised host.

---

## 11. Developer workflow

1. `scripts\verify.ps1` must be green before you build anything on top of the core.
2. Make a change. Run `cargo fmt --all`, then the manual commands in 2.4 (or the script).
3. If you touch a **format** (header, snapshot, file object, backup): update the spec in `docs/` first, add or
   update known-answer vectors, bump the format version if old readers cannot read the new form, and keep every
   golden file opening.
4. If you touch a **command**: keep it narrow, return no secrets by default, and add a unit test.
5. Write findings you cannot resolve into `docs/DESIGN_REVIEW.md` instead of leaving them in your head.

CI (`.github/workflows/ci.yml`) runs fmt, clippy, tests on Windows and Linux and `cargo audit`. It has never run.

---

## 12. Rules for changing this codebase

These come from the project's founding requirements. Treat them as hard rules.

* **Never invent cryptography.** Use established algorithms from reviewed crates. Do not hash the password with a
  fast hash and use it as a key.
* **No telemetry, analytics, accounts, cloud assumptions, or network code.** The app must work with no internet.
* **No weakening for convenience** without writing down the trade-off in the docs.
* **Core code:** `unsafe` is forbidden; `unwrap`/`expect` and `println!` are denied in library code (so a secret
  cannot be logged by accident); secret types have no `Clone`, a redacted `Debug` and zeroize on drop.
* **Errors never contain secrets.** Wrong password and tampering stay indistinguishable.
* **Do not suppress a lint or warning without a written reason** next to it. (Two `dead_code` allowances exist for
  test-only shared code, each with its reason.)
* **Every nonce is random per message.** Never reuse a (key, nonce) pair. Writers of file objects must use a fresh
  key and nonce prefix per write attempt; resuming a write is forbidden.
* **Secrets never travel to the UI** except on an explicit user action; copy-to-clipboard happens in Rust.
* **Do not claim** the project is production-ready until it has had an independent security review.
* **Do not mark tests as passing** unless they ran. Report real exit codes.

Review checklist for any security-sensitive change: what key or secret does this touch, where is it zeroized,
what is bound into the AAD, what happens on crash halfway, what does an attacker with the files learn, and which test
fails if this is wrong.

---

## 13. Roadmap and feature backlog

### Milestones (`docs/ROADMAP.md`)

| M | Scope |
|---|---|
| 1 | `vault-core` (done; verified by the owner) |
| 2 | Encrypted file objects: streaming reader/writer and random access written (uncompiled); file-key rotation open |
| 3 | Real storage layer: commits with write-through, lock file, crash recovery, `vault verify`, `.usnabak` backup and restore |
| 4 | Full data model, TOTP via an established crate if it passes the gate, otpauth import |
| 5 | Tauri shell hardening: preview protocol, security checklist (first version exists) |
| 6 | Full UI: folders, import/export, field editor, usability pass |
| 7 | Hardening: dump/pagefile mitigations, clipboard-history exclusion, back-off, memory-residue tests |
| 8 | Installer, portable build, signed releases, **independent security review** |

### Feature ideas, with where to build them and what to watch

| Feature | Where | Difficulty | Watch out for |
|---|---|---|---|
| Video/PDF streaming preview | `usna://` protocol handler in `src-tauri` over `ObjectReader` | High | Range requests map to chunk reads; revoke URLs on lock; plaintext reaches the WebView |
| File-key rotation | core `object.rs`, store | Medium | Stream-decrypt into a new object with a new key, commit, delete old |
| Move files, drag-and-drop, import a whole folder | commands, UI | Low to Medium | Keep each import atomic (object first, snapshot second) |
| Streaming image/video preview | `usna://` protocol handler in `src-tauri` | High | Range requests map to chunk reads; revoke URLs on lock; plaintext reaches the WebView |
| `.usnabak` backup and restore | store crate, commands | High | Restore never in place; verify before announcing success; see `docs/BACKUP_FORMAT.md` |
| Real storage layer | new `usna-store` crate | Medium | `MoveFileExW` with write-through; recovery table in `VAULT_FORMAT.md` section 7 |
| Vault-key and file-key rotation in the app | commands, store | Medium | Needs the two-file commit; guided "password compromised" flow (finding R2) |
| `otpauth://` URI import, QR import | `totp.rs`, UI | Medium | Parse algorithm, digits, period; decode QR locally only, never via a web service |
| TOTP algorithm/digits/period per entry | `totp.rs`, `model.rs`, UI | Low | The code already supports SHA-256/512 and 6 to 8 digits |
| Password history, custom fields, recovery-code lists | `model.rs`, UI | Medium | Follow the field model in `DATA_MODEL.md`; migrate the schema version |
| Passphrase (word list) generator | `commands.rs` | Low | Ship the word list inside the app; no network |
| Password strength estimator | `commands.rs` | Low | Use a vetted estimator (zxcvbn-style); no pseudo-precise "years to crack" claims |
| Clipboard-history exclusion on Windows | `commands.rs` | Low | Verify the actual API on current Windows before relying on it |
| Unlock back-off | `commands.rs` | Low | UX only; offline guessing is bounded by Argon2id regardless |
| Recovery key (second key slot) | core, new format version | High | Format v2; domain separation already prepared by the KEK step |
| Rollback warning (high-water mark) | store | Low to Medium | Advisory only; stored outside the vault; document single-writer use |
| Portable build, signed installer | build config | Medium | Code signing; no auto-update (it would add network code) |
| Port UI to React + TypeScript | `ui/` | Medium | Keep the command boundary; keep the strict CSP (no inline scripts) |
| Accessibility and localization | `ui/` | Medium | Keyboard focus is visible; reduced-motion is respected |
| Real passkey authenticator | new design | Very high | Needs its own threat model (OS/browser integration); out of scope until after milestone 8 |

---

## 14. Recipes: how to add things

### Add a new field to an item (for example "website URL")

1. `src-tauri/src/model.rs`: add `pub url: String` to `Item` (the `#[serde(default)]` makes old vaults load),
   to `ItemView`/`ItemInput`, and map it in `view()` and `upsert()`. Add a unit test.
2. `ui/index.html`: add the input to the item dialog. `ui/app.js`: read it in the submit handler and show it in
   `renderDetail()`.
3. If the field is a secret, return only a mask or length in `ItemView`, like the password.

### Add a new Tauri command

1. Write `#[tauri::command] pub fn my_command(state: State<'_, AppState>, ...) -> Result<T, String>` in `commands.rs`.
   Go through `with_session` so it requires an unlocked vault and refreshes the inactivity timer.
2. Register it in `main.rs` inside `generate_handler![...]`.
3. Call it from `ui/app.js` with `invoke('my_command', { ... })` (argument names are camelCase in JavaScript).
4. Ask: does it return a secret? If yes, it needs an explicit user action and a strong reason.

### Add a UI action

Add a button with `data-act="myAction"` and a handler `async myAction(d) {...}` in the `A` object in `app.js`.
Do not use `onclick=`; the CSP blocks inline handlers by design.

### Change a persisted format

Update `docs/VAULT_FORMAT.md` first. Update code. Regenerate vectors with `tools/gen_vectors.py` only if the format
legitimately changed, bump `FORMAT_VERSION`, keep a golden file for the old version, and write a migration that never
rewrites in place (write new, verify it opens, swap atomically, keep the old copy until confirmed).

### Add a test vector

Extend `tools/gen_vectors.py` so an independent implementation produces it, rerun it, and commit the generated
files. Never hand-edit `src/test_vectors.rs`.

---

## 15. Known limitations and open decisions

### Limitations (by design or by current state)

* The app has not been compiled or run. The core tests have been run only by the project owner.
* Interim storage: instance lock and leftover cleanup exist, but there is no write-through rename and no rotation recovery table.
* No backups and no vault-key rotation in the app; file previews are images only (up to 25 MiB), other files are export-only.
* Passkeys are a record only. The app is not a passkey authenticator.
* No Windows clipboard-history exclusion, no `VirtualLock`, no dump exclusion, no write-through rename yet (unlock back-off now exists).
* No password recovery. A lost master password means lost data.
* Some crate and feature names were not checked against their manifests (see `docs/DEPENDENCIES.md`).

### Decisions waiting for the project owner (`docs/DESIGN_REVIEW.md`)

* **R2, password change vs compromise.** Recommended: "Change password" re-wraps only and says old backups still
  open with the old password; a separate "my password may be compromised" flow does a password change **plus**
  vault-key rotation **plus** file-key rotation, and asks you to replace old backups.
* **R3, rollback.** Recommended: an advisory high-water mark stored outside the vault, a documented single-writer
  rule, and no merge logic for version 1.

---

## 16. Troubleshooting

| Symptom | Likely cause and fix |
|---|---|
| `cargo` is not recognized | Rust is not installed or the terminal was not reopened. Install via rustup.rs and open a new PowerShell |
| `link.exe not found` or MSVC errors | Install Visual Studio 2022 Build Tools with the C++ workload and a Windows SDK |
| Tests fail to compile with "run the tests with: cargo test --all-features" | You forgot `--all-features`. That is intentional |
| Release build with `--all-features` fails | Intentional guard against shipping weak test KDF parameters |
| `cargo fmt --check` fails | Run `cargo fmt --all` once |
| First build errors in the app | The app has never been compiled. Send the exact output (or `app-build-report.txt`) |
| `argon2` feature error | Restore its default features in `crates/vault-core/Cargo.toml` and report it |
| App window is blank or an error mentions WebView2 | Install the WebView2 runtime from Microsoft |
| Create or unlock takes about a second | Expected: Argon2id with 256 MiB is deliberately slow |
| "Wrong password, or the vault files were modified or damaged" | Wrong password or a changed file. The two cases are indistinguishable by design |
| Clipboard did not clear | It clears only if it still holds the copied value; copying something else cancels it |

---

## 17. Glossary

| Term | Meaning |
|---|---|
| **Cargo** | Rust's build tool: downloads dependencies, compiles, tests, builds |
| **Core (`vault-core`)** | The crate that does all the cryptography and key handling; no UI, no file or network I/O |
| **Vault key (VK)** | Random 256-bit key that protects the data; stored only wrapped by the password-derived key |
| **KEK / PDK** | Key-encrypting key / password-derived key; the chain from your password to the vault key |
| **Subkey** | A key derived from the vault key for one purpose (database, file-key wrapping) |
| **File key** | A random key per stored file; stored wrapped inside the encrypted database |
| **Snapshot** | The sealed, padded blob holding all structured vault data (`vault.db`) |
| **Generation** | Counter that increases on every vault-key rotation; bound into encryption context |
| **Revision** | Counter that increases on every save of the snapshot |
| **AEAD / AAD** | Authenticated encryption / the extra context data it authenticates |
| **Nonce** | A number used once per encryption; here 192 bits, random |
| **TOTP** | Time-based one-time password (RFC 6238), the six-digit authenticator code |
| **Passkey** | A WebAuthn credential (public-key based). Not a password string; here only a record |
| **Golden file** | A frozen sample of the format that every future version must keep opening |
| **Known-answer vector** | An expected output for fixed inputs, produced by an independent implementation |
| **Rollback** | Replacing the vault with an older authentic copy |
| **Zeroize** | Overwriting secret memory when it is no longer needed (best effort) |
| **MSRV** | Minimum supported Rust version (declared as 1.85) |
