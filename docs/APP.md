# Desktop App (Tauri 2 shell): status, run instructions, honest limits

**Status: written, not yet compiled or run.** Like milestone 1 before its first local run, nothing here
has been built. Expect compile errors on the first try and report them.

## What it is
`src-tauri/` (Rust, Tauri 2) is a thin command layer over `usna-vault-core`; `ui/` is the interface. It is a
separate Cargo workspace with its own lockfile, so the verified core pipeline never depends on it.

* First launch: create a vault (master password, 12+ characters enforced by the app; the core only rejects empty).
  Key derivation uses `KdfParams::RECOMMENDED` (256 MiB Argon2id), so create and unlock take about a second.
* Unlock, lock now, `Ctrl+L`, lock on window close, inactivity lock (a Rust timer; the UI is told through the
  `vault-locked` event).
* Folders and encrypted files: create, rename and delete folders; **import** (native file dialog, streaming encryption into a new
  object), **export** (explicit decrypt-to-disk, with a warning), **inline preview of PNG/JPEG/GIF/WebP up to 25 MiB**, delete.
  Names, types, folders and wrapped file keys live only inside the sealed snapshot.
* Storage safety: an OS file lock stops two processes opening one vault (released automatically if the process dies);
  leftover temp files from a crash are cleaned on unlock; **Check vault integrity** in Settings verifies header, snapshot and every
  file object (all chunks authenticated) and reports unreferenced objects.
* Unlock back-off: after 3 wrong attempts the response is delayed 1, 2, 4, then 8 seconds (UI friction only).
* Items: apps and secure notes with username, password, optional TOTP secret, passkey *record*, notes; search,
  favorites, edit, delete. Everything is sealed into the vault snapshot after each change.
* Live TOTP code and countdown (computed in Rust, RFC 6238 tested), password generator (Rust, no modulo bias),
  copy with timed clipboard clearing (Rust, cleared only if the clipboard still holds our value),
  change master password (re-wraps the same vault key).

## Transactional saves (how the live session stays equal to the disk)
Every change to the vault model goes through one function, `Session::commit`: (1) mutate the live model, which also yields an
exact **undo token** (values are *moved* into it, not copied; the only duplicate of secret data is the previous value of
the single item being edited, wiped afterwards); (2) seal and write the new snapshot; (3) on any failure, revert the model
from the token and return the error. A rejected operation (validation failure) changes nothing and writes nothing. Counters
(`next_id`, `next_folder_id`, `next_file_id`) are restored too. Why undo tokens and not a candidate copy of the model: a
full copy would duplicate every stored password on every save.

Ordering rules that follow from it: a file object is deleted only **after** the snapshot without its record is committed;
an import writes the object first and the snapshot second and removes the object again if the snapshot commit fails;
a password change writes the header first and adopts it in memory second.

All of this logic lives on `Session` behind a small `Backend` trait (`write_db`, `write_header`, `read_*`, `remove_object`).
`Store` is the real backend; the tests use one that can fail on demand. The tests (unrun) check, for each of
create/rename/delete folder, delete file, add file, every item operation, settings and change-password: the live model is
byte-identical to before the failed attempt, the on-disk snapshot decrypts to exactly the live model, the revision did not
advance, no object was deleted, and a later successful save is correct (for example, a failed folder deletion does not make
its file records vanish from a later save).

Known limit: the integrity check is a point-in-time report. Header and snapshot are checked under the session lock; file
objects are verified outside it, so a delete that happens *during* a scan can make an object look unreferenced. Run it while idle.

## The command boundary (what the UI can and cannot do)
The UI receives no keys. `list_items` and `get_item` return no secrets. `reveal_password` is the only command
that returns a secret, and only when the user presses Show. Copy happens in Rust. See
`src-tauri/src/commands.rs`. The CSP forbids inline scripts, remote origins and `eval`; no fs, shell, http or opener
plugin is enabled.

## Run it (PowerShell, repo root)
```
powershell -ExecutionPolicy Bypass -File scripts\verify.ps1        # core must pass first
powershell -ExecutionPolicy Bypass -File scripts\build-app.ps1     # tests + builds the app and installer
src-tauri\target\release\usna-secure-app.exe
```
Developer loop: `cargo install tauri-cli --version "^2" --locked`, then `cargo tauri dev` from the repo root.
Needs the WebView2 runtime (preinstalled on current Windows 10/11). Vault data lives in
`%APPDATA%\org.usna.secure\vault\` (`vault.header`, `vault.db`).

## Deliberate deviations and limits (read these)
| Item | Reality | Planned fix |
|---|---|---|
| Frontend | Plain HTML/CSS/JS, not React/TypeScript. No Node toolchain to install or break; the security-relevant boundary (Rust commands) is unchanged | Port to React + TS when the UI stabilizes |
| Storage | `store.rs`: temp file + flush + rename; instance lock; leftover cleanup; integrity check. **Still missing:** Windows write-through rename (needs `unsafe` FFI, which this project forbids; a safe route is open), full crash-recovery table for rotation (the app never rotates keys) | Milestone 3 |
| Data model | Simplified JSON model, not the full DATA_MODEL schema. Decrypted strings live in ordinary `String`s while unlocked and are wiped best-effort on lock | Milestone 4 (`Zeroizing` types) |
| Files and folders | Implemented but **uncompiled**. No video/PDF preview (export only), no `usna://` streaming protocol, no file-key rotation, no drag-and-drop, no moving files between folders, no import of whole folders | Milestone 6 |
| Backups | **Not implemented** (`.usnabak` is specified, not built) | Milestone 3 |
| Vault-key rotation | Core supports it; the app does not expose it (needs the milestone-3 two-file commit and recovery) | Milestone 3 |
| Passkeys | A record flag only. The app does not act as a passkey authenticator | Beyond milestone 8 |
| Clipboard | Written with `arboard` using default flags; Windows clipboard-history/cloud-sync **exclusion is not set yet** | Milestone 7 |
| Unlock attempts | UI back-off added (1, 2, 4, 8 s after 3 failures). Offline guessing is bounded by Argon2id cost either way (docs/THREAT_MODEL.md T4) | done |
| Memory/crash dumps | No `VirtualLock`, no dump exclusion yet | Milestone 7 |
| TOTP crate | Own 15-line RFC 4226 truncation over RustCrypto HMAC (the documented fallback), not `totp-rs` | Reconsider at M4 gate |
| Rust version | The app needs **Rust 1.89 or newer** (`File::try_lock` for the instance lock); the core still declares 1.85 | Pin after first green run |
| New dependency | `tauri-plugin-dialog` 2 (native open/save dialogs, invoked from Rust only; no dialog permission is granted to the WebView). Name and API not yet checked against the crate | `cargo generate-lockfile` will say |
| Crate/feature names | `tauri` 2, `arboard` 3 with `default-features = false`, `hmac` 0.12, `sha1` 0.10 were **not** checked against their manifests | `cargo generate-lockfile` will say |

## Not claimed
Not audited, not production-ready, and not "unhackable". It is an early build of an offline vault whose
cryptographic core has a test suite you have run and whose application layer has not yet been compiled.
