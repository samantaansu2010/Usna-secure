# USNA Secure: Backup / Export Format (`.usnabak`) v1

Specification only; implemented in milestone 3. The active vault is a directory (ARCHITECTURE §3); a
backup is one verified file.

## Goals
One file; contains **only already-encrypted vault data** (nothing is decrypted or re-encrypted in v1);
streams (no whole-vault RAM); detects accidental corruption **without** the password; authenticates the exact
set of contents **with** the password; restore is reliable, never in place, and never destroys the existing vault.

## Container

```
Backup header, 40 bytes, cleartext
  0  8  magic "USNABAK\0"
  8  2  format version 1            10 2  flags 0 (unknown bits refused)
  12 16 vault id                    28 4  VK generation of the included vault
  32 8  snapshot revision of the included vault

Records, in this order:  type u8 | length u64 LE | payload
  1 HEADER    payload = vault.header bytes (149)
  2 SNAPSHOT  payload = vault.db bytes
  3 OBJECT    payload = object_id (16) || object file bytes      (one record per object, sorted by id)
  4 MANIFEST  payload = nonce(24) || XChaCha20-Poly1305(K_manifest, nonce, AAD, manifest) || tag
  5 END       payload = SHA-256 of every file byte before this record's type byte
```
No bytes may follow END.

`MANIFEST` AAD = `"USNA Secure v1/backup-manifest" || backup header (40 bytes)`. Plaintext = record count (u64),
then for each record before MANIFEST: `type u8 || object_id (16, zero for non-objects) || length u64 || SHA-256(payload)`.
`K_manifest` is the reserved HKDF subkey of the included vault's generation (VAULT_FORMAT §4). Creating a backup
therefore requires an unlocked vault, and verifying one requires its password.

### Two levels of verification
1. **Without a password:** recompute SHA-256 up to END and compare. Detects truncation and accidental
   corruption ("is this file intact?"). This is *not* authentication; an attacker can recompute it.
2. **With the password:** unlock from the HEADER record, open and verify the MANIFEST, compare every record's
   length and hash, open the snapshot, check that every object the snapshot references is present, and
   optionally (default for restore) stream-verify every object's chunk tags (FILE_FORMAT).

## Credentials
A v1 backup opens with the master password **in force when the backup was made**, because it contains that
header. The cleartext header shows generation and revision so the UI can say "this backup is from vault
version N" without revealing anything secret. A separate backup-only password (a second key slot wrapping
the same vault key) is deliberately **not** in v1: it adds another way to the live vault key and needs its own
review.

## Creating a backup
1. Hold the store's commit lock (no snapshot commit or object deletion during the backup; new objects are harmless).
2. Write to `NAME.usnabak.partial`; hash while writing; append MANIFEST and END; fsync.
3. **Verify before announcing success** (default on): re-read the file, check END, then do a full restore into a
   temporary directory and verify (level 2), then delete the temporary directory.
4. Atomically rename to `NAME.usnabak`. Never overwrite an existing backup; use a new name.

An interrupted backup leaves only a `.partial` file, never something that looks valid.

## Restoring (reliably, never in place)
1. The target must be a **new or empty** directory; refuse otherwise. Check free space (backup size + margin).
2. Stream into `TARGET.restoring/`, hashing as it goes. Verify END. On mismatch: delete `TARGET.restoring/`, stop.
3. Ask for the password. Unlock from the restored header; verify MANIFEST against what was written; open the
   snapshot (generation must equal the header's); check every referenced object exists; deep-verify objects.
4. Only after every check passes, atomically rename `TARGET.restoring/` to `TARGET`.
5. Show what was restored: vault generation, revision, and the **rollback warning** if an existing vault on this
   machine has a higher revision for the same vault id (VAULT_FORMAT §8, THREAT_MODEL T3).
6. The existing vault is never modified or deleted by restore. A "test restore" action performs steps 1–4 into
   a temporary directory and discards it.

## What a backup file reveals
Cleartext header (vault id, generation, revision), file size, and record lengths (hence number and size of
file objects). Same exposure class as the vault directory (ARCHITECTURE §4).

## Failure cases that must be tested (milestone 3)
Truncation at every record boundary and mid-record; every-byte flip; duplicate, missing, reordered and
extra records; object from another vault injected; manifest from another backup; wrong password; corrupted
header record; restore into a non-empty directory (refused); crash at every restore step leaves no directory
under the final name; backup of an older generation; backup larger than free space; multi-GB streaming with
bounded memory; round-trip on a clean machine.

## Known limits
Rollback: an authentic older backup restores an authentic older vault. Confidentiality is exactly that of the
vault itself. v1 cannot add a backup-only password, split archives, or make incremental backups.
