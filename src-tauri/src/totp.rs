//! TOTP (RFC 6238) over HOTP (RFC 4226), built on RustCrypto `hmac` + `sha1`/`sha2`.
//!
//! Why not a TOTP crate: docs/DATA_MODEL.md prefers `totp-rs` subject to an acceptance gate that has
//! not been run yet (a 6.0 release with a different API exists). This is the documented fallback: the
//! cryptography is the established HMAC; only the ~15-line RFC 4226 truncation is ours, and it is
//! tested against all RFC 6238 Appendix B vectors below.

use hmac::{Hmac, Mac};
use sha1::Sha1;
use sha2::{Sha256, Sha512};

// `dead_code` is allowed: SHA-256/512 are implemented and RFC-tested, but the UI only creates SHA-1
// secrets until `otpauth://` import (which carries the algorithm) is added.
#[allow(dead_code)]
#[derive(Clone, Copy, Debug)]
pub enum Algo {
    Sha1,
    Sha256,
    Sha512,
}

fn mac(algo: Algo, key: &[u8], msg: &[u8]) -> Option<Vec<u8>> {
    match algo {
        Algo::Sha1 => {
            let mut m = Hmac::<Sha1>::new_from_slice(key).ok()?;
            m.update(msg);
            Some(m.finalize().into_bytes().to_vec())
        }
        Algo::Sha256 => {
            let mut m = Hmac::<Sha256>::new_from_slice(key).ok()?;
            m.update(msg);
            Some(m.finalize().into_bytes().to_vec())
        }
        Algo::Sha512 => {
            let mut m = Hmac::<Sha512>::new_from_slice(key).ok()?;
            m.update(msg);
            Some(m.finalize().into_bytes().to_vec())
        }
    }
}

/// HOTP value for `counter`, `digits` in 6..=8.
pub fn hotp(secret: &[u8], counter: u64, algo: Algo, digits: u32) -> Option<String> {
    if !(6..=8).contains(&digits) {
        return None;
    }
    let h = mac(algo, secret, &counter.to_be_bytes())?;
    let offset = usize::from(*h.last()? & 0x0f);
    let bytes = h.get(offset..offset + 4)?;
    let bin = u32::from_be_bytes([bytes[0] & 0x7f, bytes[1], bytes[2], bytes[3]]);
    let code = bin % 10u32.pow(digits);
    Some(format!("{code:0width$}", width = digits as usize))
}

/// TOTP at `unix_time` seconds.
pub fn totp(secret: &[u8], unix_time: u64, period: u64, algo: Algo, digits: u32) -> Option<String> {
    if period == 0 {
        return None;
    }
    hotp(secret, unix_time / period, algo, digits)
}

/// Tolerant Base32 decoding (RFC 4648): ignores spaces, hyphens and padding, case-insensitive.
pub fn decode_base32(input: &str) -> Option<Vec<u8>> {
    let mut bits: u32 = 0;
    let mut nbits: u32 = 0;
    let mut out = Vec::new();
    for c in input.chars() {
        let v = match c {
            'A'..='Z' => c as u32 - 'A' as u32,
            'a'..='z' => c as u32 - 'a' as u32,
            '2'..='7' => c as u32 - '2' as u32 + 26,
            ' ' | '-' | '=' => continue,
            _ => return None,
        };
        bits = (bits << 5) | v;
        nbits += 5;
        if nbits >= 8 {
            nbits -= 8;
            out.push(((bits >> nbits) & 0xff) as u8);
            bits &= (1 << nbits) - 1;
        }
    }
    // Some services issue 80-bit secrets, so the floor is 10 bytes rather than RFC 4226's 16.
    if out.len() < 10 {
        return None;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    const TIMES: [u64; 6] = [59, 1_111_111_109, 1_111_111_111, 1_234_567_890, 2_000_000_000, 20_000_000_000];

    fn check(algo: Algo, seed: &[u8], expected: [&str; 6]) {
        for (t, want) in TIMES.iter().zip(expected) {
            assert_eq!(totp(seed, *t, 30, algo, 8).unwrap(), want, "t={t}");
        }
    }

    // RFC 6238 Appendix B (independently re-verified with Python hmac/hashlib).
    #[test]
    fn rfc6238_sha1() {
        check(Algo::Sha1, b"12345678901234567890",
            ["94287082", "07081804", "14050471", "89005924", "69279037", "65353130"]);
    }
    #[test]
    fn rfc6238_sha256() {
        check(Algo::Sha256, b"12345678901234567890123456789012",
            ["46119246", "68084774", "67062674", "91819424", "90698825", "77737706"]);
    }
    #[test]
    fn rfc6238_sha512() {
        check(Algo::Sha512, b"1234567890123456789012345678901234567890123456789012345678901234",
            ["90693936", "25091201", "99943326", "93441116", "38618901", "47863826"]);
    }

    #[test]
    fn six_digit_codes_are_truncations_of_the_same_value() {
        let c6 = totp(b"12345678901234567890", 59, 30, Algo::Sha1, 6).unwrap();
        assert_eq!(c6, "287082");
    }

    #[test]
    fn rejects_bad_parameters() {
        assert!(hotp(b"k", 0, Algo::Sha1, 5).is_none());
        assert!(hotp(b"k", 0, Algo::Sha1, 9).is_none());
        assert!(totp(b"k", 1, 0, Algo::Sha1, 6).is_none());
    }

    #[test]
    fn base32_decoding() {
        // "Hello!\xDE\xAD\xBE\xEF" = JBSWY3DPEHPK3PXP
        assert_eq!(decode_base32("JBSWY3DPEHPK3PXP").unwrap(), b"Hello!\xDE\xAD\xBE\xEF");
        assert_eq!(decode_base32("jbsw y3dp-ehpk 3pxp==").unwrap(), b"Hello!\xDE\xAD\xBE\xEF");
        assert!(decode_base32("not base32!").is_none());
        assert!(decode_base32("ME").is_none()); // too short
        assert!(decode_base32("").is_none());
    }
}
