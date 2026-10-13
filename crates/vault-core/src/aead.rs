//! XChaCha20-Poly1305 (draft-irtf-cfrg-xchacha) via the RustCrypto `chacha20poly1305` crate.
//!
//! 192-bit random nonces make accidental nonce reuse negligible without a counter, which matters
//! for a vault that is copied, restored from backups and edited on several machines.
//! Every call site binds a domain-separation label and its context into the AAD.
//!
//! There is deliberately no "seal with a random nonce" helper here: each production caller
//! (`KeySet::seal_snapshot`, `KeySet::wrap_file_key`, header creation) draws its own nonce from
//! `rng` and passes it in, so the identical code path is exercised by the known-answer tests.

use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    XChaCha20Poly1305, XNonce,
};
use zeroize::Zeroizing;

use crate::{
    error::{Error, Result},
    secret::SecretKey,
};

/// XChaCha20 nonce length.
pub(crate) const NONCE_LEN: usize = 24;
/// Poly1305 tag length.
pub(crate) const TAG_LEN: usize = 16;

fn cipher(key: &SecretKey) -> Result<XChaCha20Poly1305> {
    XChaCha20Poly1305::new_from_slice(key.expose().as_slice())
        .map_err(|_| Error::Internal("invalid AEAD key length"))
}

/// Encrypt with an explicit nonce. Returns `ciphertext || tag`.
///
/// Callers outside tests must use a fresh random nonce per (key, message).
pub(crate) fn encrypt_with_nonce(
    key: &SecretKey,
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    cipher(key)?
        .encrypt(
            &XNonce::from(*nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| Error::EncryptionFailure)
}

/// Decrypt `ciphertext || tag`. Any failure is `AuthenticationFailed`.
pub(crate) fn decrypt_with_nonce(
    key: &SecretKey,
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    cipher(key)?
        .decrypt(
            &XNonce::from(*nonce),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map(Zeroizing::new)
        .map_err(|_| Error::AuthenticationFailed)
}

/// Encrypt with a caller-supplied nonce and return `nonce || ciphertext || tag`.
pub(crate) fn seal_with_nonce(
    key: &SecretKey,
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    let ct = encrypt_with_nonce(key, nonce, aad, plaintext)?;
    let mut out = Vec::with_capacity(NONCE_LEN + ct.len());
    out.extend_from_slice(nonce);
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Open `nonce || ciphertext || tag`.
pub(crate) fn open(key: &SecretKey, aad: &[u8], blob: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    if blob.len() < NONCE_LEN + TAG_LEN {
        return Err(Error::MalformedSealed("shorter than nonce plus tag"));
    }
    let (n, ct) = blob.split_at(NONCE_LEN);
    let mut nonce = [0u8; NONCE_LEN];
    nonce.copy_from_slice(n);
    decrypt_with_nonce(key, &nonce, aad, ct)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// draft-irtf-cfrg-xchacha-03, Appendix A.3.1.
    #[test]
    fn xchacha20poly1305_draft_vector() {
        let key = SecretKey::from_slice(
            &hex::decode("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f")
                .unwrap(),
        )
        .unwrap();
        let nonce: [u8; 24] = hex::decode("404142434445464748494a4b4c4d4e4f5051525354555657")
            .unwrap()
            .try_into()
            .unwrap();
        let aad = hex::decode("50515253c0c1c2c3c4c5c6c7").unwrap();
        let pt = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
        let expected_ct = "bd6d179d3e83d43b9576579493c0e939572a1700252bfaccbed2902c21396cbb731c7f1b0b4aa6440bf3a82f4eda7e39ae64c6708c54c216cb96b72e1213b4522f8c9ba40db5d945b11b69b982c1bb9e3f3fac2bc369488f76b2383565d3fff921f9664c97637da9768812f615c68b13b52e";
        let expected_tag = "c0875924c1c7987947deafd8780acf49";
        let out = encrypt_with_nonce(&key, &nonce, &aad, pt).unwrap();
        assert_eq!(hex::encode(&out[..out.len() - TAG_LEN]), expected_ct);
        assert_eq!(hex::encode(&out[out.len() - TAG_LEN..]), expected_tag);
        let back = decrypt_with_nonce(&key, &nonce, &aad, &out).unwrap();
        assert_eq!(back.as_slice(), pt.as_slice());
    }

    #[test]
    fn seal_open_roundtrip_and_aad_binding() {
        let key = SecretKey::generate().unwrap();
        let nonce = crate::rng::array::<NONCE_LEN>().unwrap();
        let blob = seal_with_nonce(&key, &nonce, b"ctx-a", b"secret").unwrap();
        assert_eq!(open(&key, b"ctx-a", &blob).unwrap().as_slice(), b"secret");
        assert_eq!(
            open(&key, b"ctx-b", &blob).unwrap_err(),
            Error::AuthenticationFailed
        );
    }

    #[test]
    fn open_rejects_short_input() {
        let key = SecretKey::generate().unwrap();
        assert!(matches!(
            open(&key, b"", &[0u8; 39]),
            Err(Error::MalformedSealed(_))
        ));
    }
}
