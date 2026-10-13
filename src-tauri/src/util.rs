//! Small dependency-free helpers: hex and base64.

pub fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

pub fn from_hex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) || !s.is_ascii() {
        return None;
    }
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok()).collect()
}

/// Parse a 32-hex-character id into 16 bytes.
pub fn from_hex16(s: &str) -> Option<[u8; 16]> {
    from_hex(s)?.try_into().ok()
}

/// Standard base64 with padding (for `data:` URLs).
pub fn base64(data: &[u8]) -> String {
    const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for c in data.chunks(3) {
        let n = (u32::from(c[0]) << 16) | (u32::from(*c.get(1).unwrap_or(&0)) << 8) | u32::from(*c.get(2).unwrap_or(&0));
        out.push(char::from(A[(n >> 18) as usize & 63]));
        out.push(char::from(A[(n >> 12) as usize & 63]));
        out.push(if c.len() > 1 { char::from(A[(n >> 6) as usize & 63]) } else { '=' });
        out.push(if c.len() > 2 { char::from(A[n as usize & 63]) } else { '=' });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_roundtrip() {
        let data = [0u8, 1, 0xab, 0xff, 0x10];
        assert_eq!(to_hex(&data), "0001abff10");
        assert_eq!(from_hex("0001abff10").unwrap(), data);
        assert!(from_hex("abc").is_none());
        assert!(from_hex("zz").is_none());
        assert!(from_hex16("00").is_none());
        assert_eq!(from_hex16(&"ab".repeat(16)).unwrap(), [0xab; 16]);
    }

    #[test]
    fn base64_known_answers() {
        // RFC 4648 section 10 test vectors
        for (input, want) in [("", ""), ("f", "Zg=="), ("fo", "Zm8="), ("foo", "Zm9v"), ("foob", "Zm9vYg=="), ("fooba", "Zm9vYmE="), ("foobar", "Zm9vYmFy")] {
            assert_eq!(base64(input.as_bytes()), want);
        }
    }
}
