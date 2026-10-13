# USNA Secure: Encrypted File Object Format v1

**This document is the specification.** The format itself (header, chunking, nonces, AAD, final flag, geometry, reader
and writer rules) is implemented in `crates/vault-core/src/object.rs` (`ObjectWriter`, `ObjectReader`) and exercised by the
tamper matrix in `crates/vault-core/tests/objects.rs`. **Neither the code nor those tests have been run by the author of
this document** (no Rust toolchain was available while writing them); treat them as unverified until your own
`scripts\verify.ps1` run says otherwise.

Implementation status of what this document describes:

| Item | Status |
|---|---|
| Object header, chunk AEAD, nonces, AAD, final flag, geometry validation | Implemented in the core; unverified |
| Random access reads, last chunk authenticated at `open` | Implemented in the core; unverified |
| Writer rules (fresh key and nonce prefix per object, never resume) | Enforced by construction: `ObjectWriter::new` draws a fresh prefix, the app mints a fresh key per import and never reopens an object for writing |
| Reader rules (check vault id and object id before decrypting) | Implemented in `ObjectReader::open` |
| Import ordering (object committed first, snapshot second) | Implemented in the app; a failed snapshot commit reverts the record and removes the object |
| Delete ordering (snapshot without the record committed first, object removed after) | Implemented in the app (`Session::commit`, then `remove_object`); covered by failure-injection tests in `src-tauri/src/commands.rs` (unrun) |
| Reclaiming orphaned objects | **Not implemented.** "Check vault integrity" only *reports* unreferenced objects; nothing deletes them automatically |
| Replace a file (new id + new key) | **Not implemented in the app** (no replace feature); the rule still applies when it is added |
| `usna://` streaming preview with HTTP `Range` | **Not implemented.** The app previews PNG/JPEG/GIF/WebP up to 25 MiB through a `data:` URL; everything else is export-only |
| File-key rotation (re-encrypt an object under a new key) | **Not implemented** |
| Fuzz targets for object parsing | **Not implemented** (core fuzz targets cover only the header and snapshot) |

## Goals
Never load a whole file into RAM; authenticate every byte before releasing it; detect modified,
missing, duplicated, reordered, truncated or extended chunks; allow efficient random access (video
seeking); leak no names or types.

## Object file (`objects/<xx>/<32 hex object id>.obj`)

### Object header, 64 bytes, cleartext

| Off | Len | Field |
|---:|---:|---|
| 0 | 8 | magic `"USNAOBJ\0"` |
| 8 | 2 | format version `1` |
| 10 | 2 | flags `0` |
| 12 | 16 | vault id |
| 28 | 16 | object id |
| 44 | 4 | chunk size C: plaintext bytes per full chunk; power of two, 4 KiB ≤ C ≤ 16 MiB; default 1 MiB |
| 48 | 16 | nonce prefix (random per object) |

### Body: chunks

Chunk `i` (0-based) is `XChaCha20-Poly1305(FileKey, nonce_i, aad_i, plaintext_i)` = ciphertext || 16-byte tag, with

```
nonce_i = nonce_prefix(16) || i (u64 LE)                          // 24 bytes, unique per chunk within the object
aad_i   = "USNA Secure v1/object-chunk" || header(64) || i (u64 LE) || final (1 byte: 0 or 1)
```

Rules:
* Every chunk except the last holds exactly C plaintext bytes. The last chunk holds 1..=C bytes,
  except for an **empty file**, which is one final chunk with 0 bytes.
  A file whose size is an exact multiple of C ends with a *full* final chunk (no trailing empty chunk).
* The last chunk has `final = 1`, all others `final = 0`.
* `FileKey` is the per-object random key whose wrapped form lives in the snapshot (VAULT_FORMAT §4).
  It is unique per object, so (key, nonce) pairs never repeat even without the random prefix; the prefix
  is defense in depth.

### Geometry (all derivable from file size S)
```
stride = C + 16;  body = S − 64;  n = ceil(body / stride)
last   = body − (n−1)·stride            must satisfy 16 ≤ last ≤ stride; last == 16 only if n == 1
plaintext_len = body − 16·n
chunk i at file offset 64 + i·stride
```
Anything not satisfying these constraints is rejected before any decryption.

## Integrity properties

| Attack | Detected by |
|---|---|
| Flip any bit in header or chunk | AAD binds the whole header; tag covers ciphertext |
| Swap/reorder chunks | index in nonce **and** AAD |
| Duplicate a chunk | same |
| Drop a middle chunk | geometry check, then index mismatch |
| Truncate at a chunk boundary | new last chunk was sealed with `final = 0`; read as final it fails |
| Append chunks | old last chunk was sealed with `final = 1`; read as non-final it fails |
| Move chunks/object to another object or vault | object id and vault id in header AAD; different FileKey |
| Unauthenticated plaintext released | never: a chunk is returned only after its tag verifies |

`open()` MUST authenticate the final chunk before returning a handle, so truncation is detected up
front even if the caller only reads the middle (video scrubbing).

## Mandatory reader and writer rules
* **Writers** MUST generate a fresh `FileKey` and a fresh nonce prefix for every write attempt. Resuming,
  appending to or overwriting an existing object is forbidden (it would reuse (key, nonce) pairs). A
  failed import is deleted and restarted from scratch.
* **Readers** MUST check `header.vault_id` and `header.object_id` against the expected vault and the
  requested object before decrypting. (The wrong file would fail authentication anyway, but this gives a
  precise error and prevents silent confusion when files are renamed or swapped.)
* Objects are never rewritten in place, so an old version of an object under the same id is
  byte-identical to the current one; per-object rollback is not possible.

## Streaming and random access
Reader keeps one chunk buffer (≤ C bytes, zeroized after use). A range read `[a, b)` decrypts chunks
`⌊a/C⌋ ..= ⌊(b−1)/C⌋`. Writer buffers C bytes, emits chunk, and defers the `final` decision until EOF,
by holding back the most recent chunk until it knows whether another follows. Overhead 16 B per chunk
(0.0015 % at 1 MiB).

## Store/lifecycle rules (status in brackets)
* **Import:** write `<id>.obj.tmp` → fsync → rename to `<id>.obj` → then commit the snapshot that references it.
  A failed stream or failed rename deletes the temp file; a failed snapshot commit reverts the record and removes the
  object. A crash between the object rename and the snapshot commit leaves one unreferenced object, which the integrity
  check **reports** (it is unreadable without its key and harmless). [implemented; orphans are not auto-reclaimed]
* **Replace:** new object id + new FileKey; commit; delete old object. Never rewrite an object in place. [not implemented in the app]
* **Delete:** commit the snapshot without the entry; **only after that commit succeeds** delete the object file. If the
  commit fails the entry stays in the live session and nothing is deleted. [implemented and tested with injected write
  failures; unrun]
* **Metadata:** name, MIME type, folder, size, wrapped FileKey are only in the snapshot. The object file reveals its
  (random) id, chunk size and size only. (Timestamps are not stored.)
* **Preview:** target design: a custom `usna://` protocol handler answers HTTP `Range` requests by decrypting only the
  needed chunks; the URL is session-scoped and revoked on lock. [not implemented; see status table] The decrypted bytes
  necessarily reach the WebView renderer (ARCHITECTURE §2).
* **Size leakage:** ciphertext size ≈ plaintext size. Optional padding of objects to size buckets is a future hardening
  with a space cost.
