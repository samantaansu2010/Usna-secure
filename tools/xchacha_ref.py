"""Independent reference implementation helpers used ONLY to generate/cross-check
known-answer test vectors for vault-core. Built from OpenSSL-backed primitives in the
`cryptography` package plus a ~20-line HChaCha20 (draft-irtf-cfrg-xchacha-03, section 2.2).
Not shipped in the application."""
import struct
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

def _rotl(v, n): return ((v << n) & 0xffffffff) | (v >> (32 - n))

def _qr(s, a, b, c, d):
    s[a] = (s[a] + s[b]) & 0xffffffff; s[d] = _rotl(s[d] ^ s[a], 16)
    s[c] = (s[c] + s[d]) & 0xffffffff; s[b] = _rotl(s[b] ^ s[c], 12)
    s[a] = (s[a] + s[b]) & 0xffffffff; s[d] = _rotl(s[d] ^ s[a], 8)
    s[c] = (s[c] + s[d]) & 0xffffffff; s[b] = _rotl(s[b] ^ s[c], 7)

def hchacha20(key: bytes, nonce16: bytes) -> bytes:
    assert len(key) == 32 and len(nonce16) == 16
    s = list(struct.unpack("<4I", b"expand 32-byte k")) \
        + list(struct.unpack("<8I", key)) + list(struct.unpack("<4I", nonce16))
    for _ in range(10):
        _qr(s, 0, 4, 8, 12); _qr(s, 1, 5, 9, 13); _qr(s, 2, 6, 10, 14); _qr(s, 3, 7, 11, 15)
        _qr(s, 0, 5, 10, 15); _qr(s, 1, 6, 11, 12); _qr(s, 2, 7, 8, 13); _qr(s, 3, 4, 9, 14)
    return struct.pack("<8I", *(s[0:4] + s[12:16]))

def xchacha_encrypt(key: bytes, nonce24: bytes, aad: bytes, pt: bytes) -> bytes:
    assert len(nonce24) == 24
    subkey = hchacha20(key, nonce24[:16])
    return ChaCha20Poly1305(subkey).encrypt(b"\x00" * 4 + nonce24[16:], pt, aad)  # ct || tag

def xchacha_decrypt(key, nonce24, aad, ct):
    subkey = hchacha20(key, nonce24[:16])
    return ChaCha20Poly1305(subkey).decrypt(b"\x00" * 4 + nonce24[16:], ct, aad)

if __name__ == "__main__":
    # draft-irtf-cfrg-xchacha-03 A.2.1: HChaCha20 test vector
    k = bytes(range(32)); n = bytes.fromhex("000000090000004a0000000031415927")
    got = hchacha20(k, n).hex()
    exp = "82413b4227b27bfed30e42508a877d73a0f9e4d58a74a853c12ec41326d3ecdc"
    print("HChaCha20 draft vector:", "MATCH" if got == exp else f"MISMATCH {got}")
    # draft A.3.1: XChaCha20-Poly1305 AEAD test vector
    pt = (b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip "
          b"for the future, sunscreen would be it.")
    aad = bytes.fromhex("50515253c0c1c2c3c4c5c6c7")
    key = bytes(range(0x80, 0xa0)); nonce = bytes(range(0x40, 0x58))
    out = xchacha_encrypt(key, nonce, aad, pt)
    print("AEAD ct prefix:", out[:16].hex(), "(draft: bd6d179d3e83d43b9576579493c0e939)")
    print("AEAD tag      :", out[-16:].hex(), "(draft: c0875924c1c7987947deafd8780acf49)")
    print("AEAD full ct  :", out[:-16].hex())
