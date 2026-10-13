//! Master password handling.
//!
//! The password is normalized to Unicode NFC before use so that the same visible passphrase
//! derives the same key regardless of how a platform/IME composes characters. Normalization is
//! part of the format: changing it would lock users out (see docs/VAULT_FORMAT.md §3).

use core::fmt;

use secrecy::{ExposeSecret, Secret};
use unicode_normalization::UnicodeNormalization;
use zeroize::Zeroize;

use crate::error::{Error, Result};

/// Upper bound on the normalized password length in bytes.
pub const MAX_PASSWORD_BYTES: usize = 4096;

/// A master password (NFC-normalized UTF-8), zeroized on drop.
///
/// Strength policy (length, zxcvbn-style scoring) belongs to the application layer; the core only
/// rejects empty or absurdly long input.
pub struct Password(Secret<Vec<u8>>);

impl Password {
    /// Normalize and wrap `input`.
    ///
    /// Best-effort hygiene: the caller's `&str` is not ours to wipe, and the normalization buffer
    /// is pre-sized to avoid reallocation copies in the common case.
    pub fn new(input: &str) -> Result<Self> {
        if input.is_empty() {
            return Err(Error::InvalidPassword("empty"));
        }
        let mut normalized = String::with_capacity(input.len().saturating_mul(3));
        normalized.extend(input.nfc());
        if normalized.len() > MAX_PASSWORD_BYTES {
            normalized.zeroize();
            return Err(Error::InvalidPassword("too long"));
        }
        Ok(Self(Secret::new(normalized.into_bytes())))
    }

    pub(crate) fn expose(&self) -> &[u8] {
        self.0.expose_secret().as_slice()
    }
}

impl fmt::Debug for Password {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Password(<redacted>)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_empty() {
        assert_eq!(
            Password::new("").unwrap_err(),
            Error::InvalidPassword("empty")
        );
    }

    #[test]
    fn nfc_equivalence() {
        // "é" precomposed (U+00E9) vs "e" + combining acute (U+0065 U+0301).
        let a = Password::new("caf\u{e9}").unwrap();
        let b = Password::new("cafe\u{301}").unwrap();
        assert_eq!(a.expose(), b.expose());
    }

    #[test]
    fn rejects_too_long() {
        let s = "a".repeat(MAX_PASSWORD_BYTES + 1);
        assert_eq!(
            Password::new(&s).unwrap_err(),
            Error::InvalidPassword("too long")
        );
    }

    #[test]
    fn debug_is_redacted() {
        let p = Password::new("hunter2hunter2").unwrap();
        assert!(!format!("{p:?}").contains("hunter2"));
    }
}
