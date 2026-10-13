# Design Review Findings (milestone 1)

Scope: rotation, nonce uniqueness, authenticated chunking, backup restoration, rollback, and cross-document
consistency. Severity is the security impact if left uncorrected.
Status: **Fixed** (changed in this revision), **Decision** (needs the project owner), **Planned** (assigned to a milestone).

| ID | Sev | Finding | Status |
|---|---|---|---|
| R1 | High | `VaultKeyRotation::reseal_snapshot` re-encrypted the old snapshot plaintext unchanged, but that plaintext holds the wrapped file keys, which are bound to the old generation. Using it would silently lose every file key. | **Fixed**: replaced by `open_old_snapshot` + `seal_new_snapshot`; caller obligation documented; regression test `keys_embedded_in_the_snapshot_must_be_rewrapped_by_the_caller`; VAULT_FORMAT §7 updated |
| R2 | High | **Changing the password does not revoke the old one.** The vault key is unchanged, so any old copy of the header (backup, cloud copy) plus the *old* password still yields the key that decrypts the *current* snapshot and files. After a suspected password compromise, a password change alone gives false assurance. | **Decision** (below) |
| R3 | Med | The core cannot detect replacement with an older authentic vault. A copy-edit-copy-back workflow across machines silently loses updates. | **Decision** + Planned M3 (advisory high-water mark, single-writer rule) |
| R4 | Med | The backup design was unspecified, and restore reliability depends on it. | **Fixed (spec)**: BACKUP_FORMAT.md (two-level verification, verify before success, restore never in place); implementation in M3 |
| R5 | Med | File format: a writer could reuse (key, nonce) by resuming a write; readers were not required to check object and vault id. | **Fixed (spec)**: mandatory rules added to FILE_FORMAT |
| R6 | Med | Docs claimed `BCryptGenRandom` for `getrandom` 0.2; not verified. | **Fixed**: wording is now version-neutral |
| R7 | Low | Docs said `PROPTEST_CASES` raises case counts, but `with_cases(64)` overrode it. | **Fixed**: `cfg()` reads the variable |
| R8 | Low | The declared MSRV 1.75 was unverified, and some current crates use edition 2024. | **Fixed**: `rust-version = 1.85`, `resolver = "3"`; to be confirmed by a build |
| R9 | Low | Dependency claims (features, versions) were from memory. | **Fixed**: ledger in DEPENDENCIES.md; `argon2` reduced to `alloc` + `zeroize` |
| R10 | Info | The vault uses a non-key-committing AEAD. | Accepted: it matters only with an online decryption oracle, which does not exist here |
| R12 | Low | Unjustified lint suppressions: unused `aead::seal` (flagged by Clippy), `FileKey::expose` and an eagerly derived, unused `manifest` subkey (extra key material held in memory for nothing). | **Fixed**: `seal` removed (each production caller draws its own nonce, so the known-answer tests exercise the same path); `expose` removed until milestone 2 needs it; `manifest` subkey no longer derived until backups need it. Two `dead_code` allowances remain, both for test-only shared code, each with a written reason |
| R13 | Low | The app's two-file commit uses temp file + flush + rename without Windows write-through; true write-through needs `unsafe` FFI, which the project forbids. | Open: evaluate a safe route (or a narrowly scoped, reviewed `unsafe` module) in milestone 3 |
| R14 | Info | Previewing an image sends its decrypted bytes to the WebView as a `data:` URL (capped at 25 MiB, SVG excluded). Larger or video files are export-only. | Accepted for now; replaced by the `usna://` streaming protocol later |
| R15 | High | **Mutate-then-persist bug.** `save_item`, `delete_item`, `set_favorite`, `set_settings`, `create_folder`, `rename_folder`, `delete_folder`, `delete_file` changed the live model and then called `persist(s)?`; a failed save left the session ahead of the disk (a failed folder deletion would have dropped the records from a later save). `import_file` popped the new record on failure but left `next_file_id` bumped. Reported by the project owner. | **Fixed (unrun)**: all model mutations return an undo token and go through `Session::commit` (revert on failed save); objects are removed only after a successful commit; failure-injection tests added |
| R16 | Med | Integrity check: header/snapshot were compared against session state after reading outside the session lock (race with a save → false "revision mismatch"); the snapshot was only inspected, not authenticated; an object of an import in progress could be reported as an orphan; a failed object commit left its temp file. | **Fixed (unrun)**: metadata checked under the lock and the snapshot fully authenticated; in-flight imports excluded from the orphan count; temp file discarded on commit failure. Remaining: a delete during a scan can look like an orphan (documented) |
| R11 | Info | Random nonces assume the OS RNG state is not cloned (for example a restored VM snapshot). | Accepted; documented as an environment limitation |

## Rotation
The design is sound: a new random vault key, generation + 1, new HKDF subkeys, the same KEK and salt with a fresh
random wrap nonce, and a two-file commit with a defined recovery table. R1 was a real defect and is corrected.
Remaining caveat, already stated in VAULT_FORMAT §4: rotation does not re-encrypt file contents. If the vault key may
have leaked, rotate file keys as well (M2).

## Nonce uniqueness
All AEAD nonces are 192-bit random (XChaCha20-Poly1305): header wrap (fresh per header write), snapshot (fresh per
seal), file-key wrap (fresh per wrap). The salt is regenerated on every password change. Reusing the KEK for the two
wraps in a rotation is safe (different nonces and AAD). For chunks the nonce is `random prefix || counter`, unique
within an object because the counter never repeats under one FileKey, and every object has its own random FileKey;
R5 forbids resumed writes. Collision probability for random 192-bit nonces is negligible at any realistic message
count. Tests: `nonces.rs`. No correction needed beyond R5 and R11.

## Authenticated chunking
The index in nonce and AAD defeats reorder, duplicate and swap; the `final` flag defeats truncation and extension;
the geometry check defeats removed middle chunks; the whole header in AAD defeats header edits; the last chunk is
authenticated at open. Objects are immutable (replace means new id and new key), so per-object rollback cannot
happen. No security correction needed; R5 adds the reader and writer rules.

## Backup restoration and rollback
See BACKUP_FORMAT.md, R3 and R4. A restore returns the password in force at backup time and the vault as it was,
and the core can never detect that this state is stale.

## Decisions requested

**R2 (password change vs compromise).** Recommended policy, with no format change:
* "Change password" re-wraps only, with a clear notice that old backups still open with the old password.
* "My password may be compromised" means password change **plus vault-key rotation plus file-key rotation (M2)**,
  followed by creating a new backup and deleting old ones, offered as one guided flow.

**R3 (rollback).** Recommended: an advisory high-water mark stored outside the vault (warns on accidental restore or
sync conflict), documented single-writer / last-copy-wins, no merge, for v1.

## Cross-document consistency
Re-checked between docs and code: header offsets (149 bytes), AAD labels, HKDF info strings, snapshot layout and
padding, file-key AAD, rotation procedure, recovery table, directory layout, command names, dependency list.
Corrected: R1 in VAULT_FORMAT §7, R6 wording, R7 in TESTING, MSRV in README and Cargo.toml, the TOTP choice in
DATA_MODEL and ROADMAP, backup references in ARCHITECTURE, VAULT_FORMAT and ROADMAP. This was a read-through, not a
mechanical check, so a reviewer should still compare the header table in `header.rs` against VAULT_FORMAT §3 and the vectors.
