# Development Roadmap (decision: staged, incremental)

Each milestone ends with a gate. Nothing is called "production-ready" before an independent security review.

| M | Scope | Gate to leave the milestone |
|---|---|---|
| **1 (this)** | `vault-core`: format spec, Argon2id, VK, wrapping, HKDF subkeys, XChaCha20-Poly1305, authenticated header, snapshot container, password change, VK rotation, file-key wrapping, tests, golden vectors, fuzz targets | `fmt`/`clippy -D warnings`/`test --all-features` green on Windows **and** Linux; vectors reproduce; format doc reviewed by a second person |
| 2 | Chunked file objects (FILE_FORMAT): streaming writer/reader, random access, file-key rotation, chunk tamper tests, fuzzing. **Writer/reader, random access and the tamper matrix are written (uncompiled); file-key rotation and object fuzz targets remain** | tamper matrix green; 1 GiB streaming test with bounded memory |
| 3 | `usna-store`: directory layout, atomic commits (`MoveFileExW` write-through), lock file, crash recovery per VAULT_FORMAT §7, `vault verify`/GC, `.usnabak` backup and restore per BACKUP_FORMAT.md, advisory rollback high-water mark | crash-injection tests at every commit step; backup→restore→verify round-trip on a clean machine; every restore-failure case in BACKUP_FORMAT §7 |
| 4 | `usna-model`: snapshot schema, apps/fields/notes/folders, TOTP via `totp-rs` if it passes the gate in DATA_MODEL (+ RFC vectors), password generator/strength, otpauth parser, Passkey record | model round-trip + migration tests; TOTP vectors |
| 5 | Tauri shell: narrow command API, session/lock, clipboard, preview protocol; minimal UI (unlock, list, entry view). **First version written ahead of schedule (see docs/APP.md); preview protocol still open** | security checklist for IPC/CSP/capabilities |
| 6 | Full UI: sidebar, search, cards, field editor, favorites, settings, import/export | usability pass; no secrets in DOM after lock |
| 7 | Hardening: auto-lock triggers, dump/WER/VirtualLock evaluation, logging audit, memory-residue tests, dependency audit | written residual-risk statement |
| 8 | Installer, portable build, signed GitHub Releases, reproducibility notes, **independent security review** | review findings resolved |

Out of scope until after M8: real WebAuthn/passkey authenticator support, recovery-key slot (format v2),
object padding, rollback-protection counter, QR scanning beyond import.
