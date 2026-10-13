# USNA Secure: Data Model, Fields, TOTP, Passkeys

Proposed for milestone 4. The snapshot plaintext (VAULT_FORMAT §5) is one versioned document.
Serialization: CBOR via `ciborium` is proposed (self-describing, native binary fields, tolerant of
unknown fields); to be confirmed in M4 before the schema is frozen. The snapshot **container** is
independent of this choice.

```
Snapshot {
  schema_version: u32,
  entries: Map<EntryId, Entry>,   folders: Map<FolderId, Folder>,   files: Map<FileId, FileRecord>,
  settings: { auto_lock_secs, clipboard_clear_secs, ... }
}
Entry   { id, kind: App | SecureNote, title, favorite, created, modified, fields: [Field] /* ordered */ }
Folder  { id, parent: Option<FolderId>, name }
FileRecord { id, folder, name, mime, size, object_id, wrapped_file_key[72], chunk_size, created, modified }
```

## Fields (modular, orderable)
`fields` is an ordered list; add/remove/reorder is list editing. Titles and labels are encrypted
with everything else.

```
Field { id: FieldId, label: String, kind: FieldKind, value: FieldValue }
FieldKind  = Email | Username | Password | Url | Text | Secret | RecoveryCodes | Totp | Passkey | Custom
FieldValue = Text(String)                       // Email, Username, Url, Text, Custom
           | Secret(Zeroizing<String>)          // Password, Secret
           | RecoveryCodes([{ code, used }])
           | Totp(TotpConfig)
           | Passkey(PasskeyRecord)
```
Secret-bearing variants are masked in view models and revealed one field at a time.

Passwords: generator in Rust (`getrandom`, rejection sampling so there is no modulo bias; length,
classes, ambiguous-character exclusion, optional word-list passphrase); strength via a `zxcvbn`-style
estimator in Rust with qualitative labels only (no pseudo-precise "years to crack" claim).

## TOTP (RFC 6238 over RFC 4226)

```
TotpConfig { secret: bytes (≥ 10 bytes), algorithm: SHA1|SHA256|SHA512, digits: 6..=8, period: 1..=300 s (default 30),
             issuer, account }
code = HOTP(secret, counter = floor(unix_time / period))
HOTP  : mac = HMAC-alg(secret, counter as 8-byte big-endian); offset = mac[last] & 0x0f;
        bin = (mac[offset..offset+4] as big-endian u32) & 0x7fffffff; code = bin mod 10^digits, zero-padded
remaining = period − (unix_time mod period)
```
* The secret is stored only inside the sealed snapshot; never logged; zeroized after use. The UI
  receives `{code, remaining}` once per second, never the secret.
* Base32 input is tolerant (spaces, lowercase, missing padding). `otpauth://totp/...` URI import
  (`secret`, `issuer`, `algorithm`, `digits`, `period`) and QR import come after the core path works.
* **Implementation choice (decided, gated at M4):** prefer the established `totp-rs` crate over our own
  code. Facts checked from its manifests: MIT licensed; no default features; core dependencies are
  `hmac`, `sha1`, `sha2`, `base32`, `constant_time_eq` (the same RustCrypto primitives we already use);
  an optional `zeroize` feature; `otpauth` pulls in `url` and `urlencoding`, and `qr` generates QR codes
  (we need QR *decoding*, so we do not need `qr`). Both a 5.x line and a newer 6.0 release with a different
  API exist; **the major version is chosen at M4** after reading its changelog and rerunning the vectors.
  Acceptance gate (all must hold, otherwise fall back to `hmac` + `sha1`/`sha2` directly, about 15 lines of
  RFC 4226 truncation, with the same tests): (1) passes all RFC 6238 vectors below for SHA-1/256/512;
  (2) the secret is zeroized on drop with the `zeroize` feature enabled (verified by reading the source and
  a test); (3) accepts the 80-bit secrets some services issue (the crate enforces a 128-bit minimum on its
  checked constructor and offers an unchecked one; to be confirmed); (4) `cargo tree` shows no network or
  async dependencies; (5) `cargo audit` is clean. `otpauth://` parsing may use the crate's `otpauth` feature or
  our own small parser, decided on the dependency cost of `url`.
* Offline caveat: codes depend on the system clock; the app cannot correct a wrong clock without a
  network. A large-drift hint can be shown but not fixed.

**RFC 6238 Appendix B vectors (8 digits), required to pass:**

| Time (s) | SHA-1 (`12345678901234567890`) | SHA-256 (`…012` 32 B) | SHA-512 (`…234` 64 B) |
|---:|---|---|---|
| 59 | 94287082 | 46119246 | 90693936 |
| 1111111109 | 07081804 | 68084774 | 25091201 |
| 1111111111 | 14050471 | 67062674 | 99943326 |
| 1234567890 | 89005924 | 91819424 | 93441116 |
| 2000000000 | 69279037 | 90698825 | 38618901 |
| 20000000000 | 65353130 | 77737706 | 47863826 |

(Seeds are the ASCII strings from the RFC repeated to 20, 32 and 64 bytes: `1234567890` repeated.)
Verified during design with an independent HMAC computation (Python `hmac`/`hashlib`); all 18 values match.

## Passkeys (decisions 8)

A passkey is a WebAuthn/FIDO2 credential: an asymmetric key pair created by an authenticator for one
relying party. Logging in means signing a server challenge; there is no password string to store.
Therefore `Passkey` is its own typed record, and **v1 stores credential metadata/reference only**:

```
PasskeyRecord {
  schema_version: u16,
  rp_id: String, rp_name: Option<String>,
  user_handle: bytes, user_name: String, user_display_name: Option<String>,
  credential_id: bytes,
  public_key_cose: Option<bytes>, cose_algorithm: Option<i32>,
  sign_count: Option<u32>, transports: [String],
  discoverable: Option<bool>, backup_eligible: Option<bool>, backup_state: Option<bool>,
  storage: ExternalAuthenticator | VaultHeld,      // v1 writes ExternalAuthenticator only
  private_key: Option<Zeroizing<bytes>>,           // reserved; None in v1; only with storage = VaultHeld
  created: Option<timestamp>, notes: Option<String>
}
```
Everything lives inside the sealed snapshot. The reserved `private_key` and `VaultHeld` variant are
there so real support is an additive schema change, not a redesign. Acting as an authenticator
(registration, assertion, user verification, attestation policy) needs an OS or browser integration
layer, for example a Windows third-party passkey provider API, a browser extension with native
messaging, or CTAP2 emulation. These are **not decided or researched here** and each needs its own
threat model; they are deferred past the first milestones.
