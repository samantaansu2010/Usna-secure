# USNA Secure: Architecture

Status: design, milestone 1. Nothing here has been security-reviewed.

## 1. Layers and trust boundary

```
┌──────────────────────────── Tauri 2 desktop process ─────────────────────────────┐
│  WebView2 (React + TypeScript)         │  Rust backend                           │
│  untrusted-by-design UI                │  trusted computing base                 │
│  - renders view models                 │  ┌─ usna-app  (Tauri commands, state)   │
│  - never holds keys                    │  │   ├─ session (lock state, timers)    │
│  - sees a secret only when the user    │  │   ├─ clipboard (copy + auto-clear)   │
│    explicitly reveals that one field   │  │   └─ preview protocol (usna://)      │
│                                        │  ├─ usna-store (planned, M3)            │
│        invoke("command", args) ───────▶│  │   dir layout, atomic commits,        │
│        ◀─── DTO without secrets        │  │   crash recovery, backup             │
│                                        │  ├─ usna-model (planned, M4)            │
│                                        │  │   apps/fields/notes, TOTP, generator │
│                                        │  └─ usna-vault-core  (THIS MILESTONE)   │
│                                        │      KDF, key hierarchy, header,        │
│                                        │      snapshot, key wrapping, zeroize    │
└──────────────────────────────────────────────────────────────────────────────────┘
```

`usna-vault-core` has no dependency on Tauri, React, the filesystem or the network. It is a pure
function of its inputs plus the OS random number generator, which is what makes it testable and
reviewable in isolation.

> **Current implementation note:** the shell in `src-tauri/` + `ui/` uses a plain JavaScript frontend rather than React/TypeScript for now (docs/APP.md). The Rust command boundary described here is unchanged.

## 2. Rust owns the secrets (decision 1)

| Concern | Owner |
|---|---|
| Argon2id, KEK, vault key, subkeys, file keys | Rust (`vault-core`) |
| Encrypt/decrypt of header, database, file chunks | Rust |
| TOTP secrets and code generation | Rust. UI receives only `{code, seconds_remaining}` |
| Password generation and strength estimate | Rust (`getrandom` + rejection sampling; `zxcvbn`) |
| Copy to clipboard and timed clearing | Rust. The secret never crosses IPC for "copy" |
| Lock state, inactivity timer, lock-on-close | Rust (`session`); the UI only reflects it |

### Narrow command boundary (draft, finalized in M5)

Commands take ids and user input, and return view models. There is **no** command that returns the
vault key, a file key, a raw TOTP secret, or the whole decrypted database.

```
vault_create(path, password) / vault_unlock(path, password) / vault_lock()
list_entries(filter) -> [EntrySummary]           // titles, kinds, favorite; no field values
get_entry(id) -> EntryView                       // secret fields appear as {kind, masked: true}
reveal_field(entry_id, field_id) -> string       // ONE secret, on explicit user action, audited in-memory only
copy_field(entry_id, field_id)                   // Rust writes clipboard, schedules clear
save_entry(EntryInput)                           // secrets flow UI -> Rust only when the user types/pastes them
totp_now(entry_id, field_id) -> {code, remaining}
generate_password(options) -> string             // returned to UI only for display/accept
import_file(src_path, folder_id) / export_file(file_id, dest_path)   // explicit decrypt-to-disk
preview_url(file_id) -> "usna://…"               // streamed, decrypted per Range request
change_password / rotate_vault_key / create_backup / restore_backup
```

Unavoidable exposure, stated plainly: when a user reveals a password or previews an image/video, that
plaintext exists in the WebView2 renderer process. We minimize it (reveal one field, on demand,
clear DOM on lock, revoke preview URLs on lock) but cannot eliminate it. This is a deliberate
trade-off of using a WebView UI.

### Tauri hardening (checked in review)

Strict CSP (`default-src 'self'`, no `unsafe-eval`, no remote origins); no `fs`, `shell`, `http`
or `opener` plugins exposed to the WebView; capabilities limited to the app's own commands;
devtools off in release; no remote content, fonts, analytics or update checks; no
`dangerouslySetInnerHTML`; secrets rendered as text nodes only.

## 3. Storage design (decision 2)

| | A. SQLCipher | B. Plain SQLite + per-record AEAD | C. **Encrypted snapshot + separate file objects** |
|---|---|---|---|
| Cipher / KDF | AES-256-CBC + HMAC per page, its own KDF unless a raw key is passed | Ours (XChaCha20-Poly1305) | Ours |
| Second crypto stack | **Yes** (OpenSSL or vendored libcrypto, C build on Windows) | No | No |
| Binds record to vault, generation, revision | No (page-level only) | Yes, via AAD | Yes, via AAD |
| Rollback within file | Not detected | Not detected | Revision visible, not enforced |
| Leaks | file size at page granularity, page-level change patterns | row count, per-row size, update patterns | one size bucket (4 KiB), revision count |
| Search | SQL on plaintext inside process | decrypt rows or in-memory | in-memory |
| Scale | large | large | a few thousand entries / tens of MB comfortably |
| Complexity / build | high (C toolchain, licensing) | medium (schema, padding) | **low** |

**Decision: C.** All structured data (apps, fields, notes, folder tree, file index including wrapped
file keys) is one serialized document, sealed as a single authenticated blob (`vault.db`, see
VAULT_FORMAT §5). It is decrypted into memory on unlock and re-sealed atomically on save. Large
files are separate objects (FILE_FORMAT). SQLite is **not** used at rest.

Why: it reuses exactly one cryptographic stack and one key hierarchy, leaks the least, binds
everything to `(vault_id, generation, revision)`, and is the easiest to specify and test. The cost is
rewriting the snapshot on each save, which is cheap at personal-vault scale (a 5 MB snapshot seals in
milliseconds). If scale ever demands it, option B can sit behind the same `Store` trait without a format
change to keys or file objects. A and the vault's own crypto would otherwise have to be reconciled.

### On-disk layout (a vault is a directory)

```
MyVault.usna/
├── vault.header            149 B   authenticated header (VAULT_FORMAT §3)
├── vault.db                        sealed snapshot            (§5)
├── vault.header.new        }       exist only during a commit (§7)
├── vault.db.new            }
├── objects/ab/<32 hex>.obj         encrypted file objects      (FILE_FORMAT)
└── .lock                           advisory single-writer lock; no secrets
```

Backups and transfers use a single-file `.usnabak` archive (BACKUP_FORMAT.md).

### Directory (active vault) vs single file (backup/export): decision and trade-offs

| | Active vault as one file | **Active vault as a directory (chosen)** |
|---|---|---|
| Saving a small change | rewrite everything, or implement an internal allocator and journal | rewrite only `vault.db` (and `vault.header` on password change) |
| Adding or removing a 2 GB video | rewrite or compact a multi-GB container | write one new immutable object; delete one |
| Crash safety | needs our own journaling | atomic replace of two small files plus the recovery table in VAULT_FORMAT §7 |
| Objects never modified in place | no | **yes**, so an object cannot be rolled back independently |
| User copies it somewhere | one thing to copy | many files; a partial copy is possible (mitigated by `vault verify`, which checks that every object referenced by the snapshot exists with valid geometry) |
| Transfer and backup | native | via `.usnabak`, which is itself a single verified file |

The cost of the directory is the partial-copy risk. The archive is the supported way to move or
back up a vault, and the application never asks the user to copy the directory by hand.

## 4. What an attacker holding the vault learns (decision 3)

**Cleartext by necessity or by design:**

| Item | Where | Why it is cleartext |
|---|---|---|
| "This is a USNA Secure vault", format version | magic, version | needed to parse |
| Vault id (random 128-bit) | header, snapshot, objects | binds artifacts together, detects mix-ups; reveals nothing about the user |
| Argon2id parameters, salt | header | needed to derive the KEK; not secret by design |
| Vault-key generation | header, snapshot | crash recovery; reveals how many VK rotations happened |
| Snapshot revision | snapshot prefix | recovery and rollback hints; reveals roughly how often the vault was saved |
| Snapshot size, rounded to 4 KiB | file size | coarse bucket of total structured-data size |
| Number of file objects, **each object's size** (±16 B per chunk), mtime | `objects/` | files need separate storage; sizes allow fingerprinting of known large files |
| File system timestamps of every vault file | OS | outside our control |

**Always encrypted** (inside the sealed snapshot or object chunks): app names, folder names, file
names, MIME types, usernames, e-mail addresses, URLs, notes, TOTP secrets and parameters, passkey
metadata, tags, favorites, entry count, folder structure, which object belongs to which folder,
every file's plaintext, and each file's wrapped key.

**Not hidden:** that a vault exists at that path, total number and sizes of file objects, and
activity timing. Object-size padding is an optional future hardening (it costs space).

## 5. Locking, clipboard, temp files, memory

* **Lock** = drop `UnlockedVault`, the decrypted model and any unwrapped file keys; revoke preview
  URLs; clear the DOM. Triggers: manual, shortcut, inactivity, window close, system lock/suspend (M7).
* **Clipboard:** written from Rust; on Windows marked to be excluded from clipboard history/cloud
  sync; cleared after the configured delay **only if the clipboard still holds our value**.
* **Plaintext on disk:** none by design. No decrypted temp files. Preview is in-memory streaming.
  "Export" and "open in external app" are explicit decrypt-to-disk actions with a warning.
* **Memory:** `zeroize` on drop for every key type; `Debug` redacted; no secrets in logs. This is
  best-effort (THREAT_MODEL "Memory").
