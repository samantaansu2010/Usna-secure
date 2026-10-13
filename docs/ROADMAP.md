# Development Roadmap (decision: staged, incremental)

Each milestone ends with a gate. Nothing is called "production-ready" before an independent security review.

| M | Scope | Gate to leave the milestone |
|---|---|---|
| **1 (this)** | `vault-core`: format spec, Argon2id, VK, wrapping, HKDF subkeys, XChaCha20-Poly1305, authenticated header, snapshot container, password change, VK rotation, file-key wrapping, tests, golden vectors, fuzz targets | `fmt`/`clippy -D warnings`/`test --all-features` green on Windows **and** Linux; vectors reproduce; format doc reviewed by a second person |
| 2 | Chunked file objects (FILE_FORMAT): streaming writer/reader, random access and tamper matrix | Core file-object tests passed in the project owner's baseline verification; file-key rotation and object fuzz targets remain |
| 3 | Vault directory, atomic snapshot writes, single-instance lock, integrity check and encrypted file storage are implemented. Remaining: Windows write-through rename, full crash-recovery table, encrypted `.usnabak` backup/restore and advisory rollback high-water mark | crash-injection tests at every commit step; backup→restore→verify round-trip on a clean machine; every restore-failure case in BACKUP_FORMAT §7 |
| 4 | Current interim JSON model includes apps, notes, settings, folders/files, TOTP, passkey-record metadata, per-account recovery codes, portable JSON import/export and legacy deserialization defaults. Remaining: the full modular field schema, otpauth URI/QR import and strength estimator improvements | model round-trip and migration tests; TOTP RFC vectors; independent data-model review |
| 5 | Tauri shell, narrow command API, session/lock, clipboard, encrypted file preview/import/export and integrity check | security checklist for IPC/CSP/capabilities; Windows app build and test suite green |
| 6 | Obsidian-inspired workspace, responsive sidebar/cards/detail panel, metadata-only account search, account editor, favorites, local light/dark theme preference, grouped settings, recovery-code management, account JSON import/export | latest Windows app CI green; manual usability pass; reveal-state cleared on lock, navigation and window blur; test account import/export round-trip |
| 7 | Hardening: auto-lock triggers, dump/WER/VirtualLock evaluation, logging audit, memory-residue tests, dependency audit | written residual-risk statement |
| 8 | Installer, portable build, signed GitHub Releases, reproducibility notes, **independent security review** | review findings resolved |

Out of scope until after M8: real WebAuthn/passkey authenticator support, a separate recovery-key slot (format v2),
object padding, rollback-protection counter and QR scanning. Per-account service recovery codes are distinct from a vault recovery key.
