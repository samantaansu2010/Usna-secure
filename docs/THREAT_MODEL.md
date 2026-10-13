# USNA Secure: Threat Model

Scope: a single-user, fully offline vault on Windows 10/11. Pre-review draft.

## Assets
Vault contents (credentials, TOTP secrets, notes, passkey records, private files), the master
password, the vault key and derived keys while unlocked, and the integrity of the vault.

## Attacker capabilities considered
Read access to vault files (theft, cloud-copied backup, stolen drive). Write access to vault files
(modify, delete, replace with older copies). Brief physical access to a locked or unlocked machine.
Unprivileged local software that can read files and the clipboard. These are separated from a
compromised OS or privileged malware, which is out of scope.

## Summary table

| # | Threat | Verdict | Mechanism / limit |
|---|---|---|---|
| T1 | Attacker obtains the vault file | **Protected**, bounded by password strength | Everything sensitive is AEAD-encrypted under a random VK; the VK is wrapped by an Argon2id-derived key. Leaks: see ARCHITECTURE §4 |
| T2 | Attacker modifies the vault | **Detected** (not prevented) | Header fields are AEAD-authenticated; snapshot prefix and every object chunk are authenticated. Deletion/corruption (availability) cannot be prevented; backups are the remedy |
| T3 | Attacker supplies an **old** copy / old backup | **Partly** | Mixed header/snapshot generations are detected. Replacing the whole vault with an older, authentic one is **not detectable** by the core; revision numbers are exposed so the app can warn. An old backup also restores the old password |
| T4 | Brute-forcing the master password | **Mitigated**, not eliminated | Offline guessing is limited only by Argon2id cost and password entropy. Attempt counters/lockouts are not a security boundary (the attacker has the file); the app may add UI back-off against casual guessing only |
| T5 | Malicious software running as the user | **Out of scope** | It can read process memory, keylog, capture the screen, read the clipboard, and tamper with the app. We reduce exposure windows only |
| T6 | Compromised OS / admin / kernel / hypervisor | **Out of scope** | No software-only vault defends against this |
| T7 | Stolen **unlocked** computer | **Partly** | Auto-lock (inactivity, lock-on-close, suspend/screen-lock hooks, shortcut) shortens the window. While unlocked, data is accessible |
| T8 | Clipboard leakage | **Reduced** | Copy from Rust, excluded from Windows clipboard history/cloud sync, timed clear if unchanged. Other apps can read the clipboard during the window |
| T9 | Temporary decrypted files | **Avoided by design** | No plaintext temp files; in-memory preview. Explicit export or external-open writes plaintext by user choice; SSD/journal remnants of deleted plaintext cannot be guaranteed erased |
| T10 | Logs and crash dumps | **Reduced** | No secrets in logs (redacted types, `print_*` lints, no secret-bearing format strings). Minidumps/WER, pagefile and hibernation can contain key bytes; mitigations (dump exclusion, `VirtualLock`, BitLocker advice) are scheduled for M7 and are best-effort |
| T11 | Screen capture / shoulder surfing | **Out of scope** (optional later hardening) | e.g. capture exclusion for the window |
| T12 | Malicious build or dependency | **Process controls** | No auto-update, no network code; lockfile review, `cargo audit`, signed releases, reproducible-build effort. Not a guarantee |
| T13 | UI injection (XSS in the WebView) | **Reduced** | Strict CSP, no remote content, text-node rendering, narrow command API, secrets on demand only |
| T14 | Loss of the master password | **Not protected, by design** | No backdoor, no recovery. A recovery-key slot is a future, opt-in feature |

## Notes per threat

**T1.** An attacker with the file can mount unlimited offline guesses. Work per guess is one Argon2id
evaluation (default 256 MiB, 3 passes). Cost scales with password entropy, so the app should push a
long random passphrase over any complexity rule. We make no numeric claim about "years to crack".

**T2/T3.** Detection is cryptographic; response policy (refuse, offer recovery from `.new` files,
suggest restoring a backup) belongs to the storage layer. Rollback protection needs state outside the
vault (for example a counter stored elsewhere); v1 does not provide it. M3 adds an *advisory* high-water mark (last seen `(vault_id, generation, revision)`, stored outside the vault) to warn after an accidental restore or sync conflict; it is not a security boundary because anyone who can edit the vault can edit it. Multi-device use is single-writer, last-copy-wins, with no merge. The test
`core_alone_cannot_detect_rollback_to_an_older_revision` pins this down.

**T4.** KDF parameters are authenticated and bounded (floor and ceiling) so a hostile file can neither
downgrade silently nor trigger a huge allocation before authentication.

## Memory (T5/T6/T10 detail)
`zeroize` overwrites our copy with writes the compiler may not elide. It **cannot** guarantee the
absence of key bytes elsewhere: copies in library internals (Argon2 working memory is zeroized via its
feature, but HKDF/AEAD internals are best-effort), stack spills, allocator reuse after reallocation,
the pagefile, hibernation file, crash dumps, or the WebView renderer process. Memory locking narrows
swap exposure but not hibernation. We therefore state **"best-effort key hygiene"**, never "memory is
securely erased".

## Explicitly out of scope
Malware or a debugger controlling the machine; hardware attacks (cold boot, DMA, bus sniffing);
a hostile OS or hypervisor; keyloggers; coercion; side channels beyond using constant-time primitives
and `subtle` comparisons; protection of data after the user exports it.

## Security properties targeted (not claims of perfection)
Confidentiality and integrity of vault data at rest against an attacker without the master password;
tamper detection with explicit domain separation; no key reuse across purposes; crash-safe commits;
no network surface; no telemetry.
