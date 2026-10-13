//! Encrypted file objects, format v1 (docs/FILE_FORMAT.md): chunked, per-chunk nonce, authenticated
//! chunk index and final flag, random access, no whole-file buffering.
//!
//! * Writer: [`ObjectWriter`] implements `Write`; call [`ObjectWriter::finish`] to emit the final chunk.
//!   Always use a **fresh `FileKey` per object** and never resume or append to an existing object.
//! * Reader: [`ObjectReader`] implements `Read + Seek` over plaintext offsets. `open` authenticates the
//!   final chunk first, so truncation is detected up front; every chunk is authenticated before any of
//!   its bytes are returned.
//!
//! Authentication failures surface as `io::ErrorKind::InvalidData`.

use std::io::{self, Read, Seek, SeekFrom, Write};

use zeroize::{Zeroize, Zeroizing};

use crate::{
    aead,
    filekey::{FileKey, ObjectId},
    header::FORMAT_VERSION,
    rng,
    secret::SecretKey,
};

/// Magic bytes at the start of an object file.
pub const OBJECT_MAGIC: [u8; 8] = *b"USNAOBJ\0";
/// Length of the cleartext object header.
pub const OBJECT_HEADER_LEN: usize = 64;
/// Default plaintext bytes per chunk (1 MiB).
pub const DEFAULT_CHUNK_SIZE: u32 = 1 << 20;
/// Smallest allowed chunk size.
pub const MIN_CHUNK_SIZE: u32 = 4096;
/// Largest allowed chunk size.
pub const MAX_CHUNK_SIZE: u32 = 16 << 20;

const TAG: u64 = aead::TAG_LEN as u64;
const AAD_CHUNK: &[u8] = b"USNA Secure v1/object-chunk";

fn invalid(msg: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg)
}

fn valid_chunk_size(cs: u32) -> bool {
    cs.is_power_of_two() && (MIN_CHUNK_SIZE..=MAX_CHUNK_SIZE).contains(&cs)
}

/// `nonce_i = nonce_prefix(16) || i (u64 LE)`
fn chunk_nonce(prefix: &[u8; 16], index: u64) -> [u8; aead::NONCE_LEN] {
    let mut n = [0u8; aead::NONCE_LEN];
    n[..16].copy_from_slice(prefix);
    n[16..].copy_from_slice(&index.to_le_bytes());
    n
}

/// `aad_i = label || header(64) || i (u64 LE) || final (1 byte)`
fn chunk_aad(header: &[u8; OBJECT_HEADER_LEN], index: u64, last: bool) -> Vec<u8> {
    let mut a = Vec::with_capacity(AAD_CHUNK.len() + OBJECT_HEADER_LEN + 9);
    a.extend_from_slice(AAD_CHUNK);
    a.extend_from_slice(header);
    a.extend_from_slice(&index.to_le_bytes());
    a.push(u8::from(last));
    a
}

fn encode_header(
    vault_id: &[u8; 16],
    object: &ObjectId,
    chunk_size: u32,
    prefix: &[u8; 16],
) -> [u8; OBJECT_HEADER_LEN] {
    let mut h = [0u8; OBJECT_HEADER_LEN];
    h[0..8].copy_from_slice(&OBJECT_MAGIC);
    h[8..10].copy_from_slice(&FORMAT_VERSION.to_le_bytes());
    // flags (10..12) stay zero
    h[12..28].copy_from_slice(vault_id);
    h[28..44].copy_from_slice(object.as_bytes());
    h[44..48].copy_from_slice(&chunk_size.to_le_bytes());
    h[48..64].copy_from_slice(prefix);
    h
}

/// Streaming encryptor. Holds back at most one chunk of plaintext (zeroized) until it knows
/// whether more data follows, so the last chunk can be sealed with `final = 1`.
pub struct ObjectWriter<W: Write> {
    inner: W,
    key: SecretKey,
    header: [u8; OBJECT_HEADER_LEN],
    prefix: [u8; 16],
    chunk_size: usize,
    buf: Zeroizing<Vec<u8>>,
    index: u64,
}

impl<W: Write> ObjectWriter<W> {
    /// Start a new object and write its header. `chunk_size` must be a power of two between 4 KiB and 16 MiB.
    pub fn new(
        mut inner: W,
        vault_id: &[u8; 16],
        object: &ObjectId,
        key: &FileKey,
        chunk_size: u32,
    ) -> io::Result<Self> {
        if !valid_chunk_size(chunk_size) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "chunk size must be a power of two between 4 KiB and 16 MiB",
            ));
        }
        let prefix =
            rng::array::<16>().map_err(|_| io::Error::other("random generator failure"))?;
        let header = encode_header(vault_id, object, chunk_size, &prefix);
        inner.write_all(&header)?;
        let cs = chunk_size as usize;
        Ok(Self {
            inner,
            key: key.secret().duplicate(),
            header,
            prefix,
            chunk_size: cs,
            buf: Zeroizing::new(Vec::with_capacity(cs)),
            index: 0,
        })
    }

    fn emit(&mut self, last: bool) -> io::Result<()> {
        let nonce = chunk_nonce(&self.prefix, self.index);
        let aad = chunk_aad(&self.header, self.index, last);
        let ct = aead::encrypt_with_nonce(&self.key, &nonce, &aad, &self.buf)
            .map_err(|_| io::Error::other("encryption failed"))?;
        self.inner.write_all(&ct)?;
        self.buf.zeroize();
        self.index = self
            .index
            .checked_add(1)
            .ok_or_else(|| io::Error::other("too many chunks"))?;
        Ok(())
    }

    /// Seal the final chunk and return the underlying writer. Required: without it the object is incomplete.
    pub fn finish(mut self) -> io::Result<W> {
        self.emit(true)?;
        Ok(self.inner)
    }
}

impl<W: Write> Write for ObjectWriter<W> {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        let mut rest = data;
        while !rest.is_empty() {
            if self.buf.len() == self.chunk_size {
                self.emit(false)?; // more data follows, so this chunk is not the last
            }
            let take = (self.chunk_size - self.buf.len()).min(rest.len());
            self.buf.extend_from_slice(&rest[..take]);
            rest = &rest[take..];
        }
        Ok(data.len())
    }

    /// No-op: a partial chunk cannot be flushed because the final-flag decision is deferred to `finish`.
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Random-access decryptor over plaintext offsets.
pub struct ObjectReader<R: Read + Seek> {
    inner: R,
    key: SecretKey,
    header: [u8; OBJECT_HEADER_LEN],
    prefix: [u8; 16],
    chunk_size: u64,
    chunks: u64,
    last_ct_len: u64,
    plaintext_len: u64,
    cache: Option<(u64, Zeroizing<Vec<u8>>)>,
    pos: u64,
}

impl<R: Read + Seek> ObjectReader<R> {
    /// Parse the header, validate the geometry, check that the object belongs to this vault and
    /// object id, and authenticate the final chunk.
    pub fn open(
        mut inner: R,
        vault_id: &[u8; 16],
        object: &ObjectId,
        key: &FileKey,
    ) -> io::Result<Self> {
        let size = inner.seek(SeekFrom::End(0))?;
        if size < OBJECT_HEADER_LEN as u64 + TAG {
            return Err(invalid("object file is too short"));
        }
        inner.seek(SeekFrom::Start(0))?;
        let mut header = [0u8; OBJECT_HEADER_LEN];
        inner.read_exact(&mut header)?;
        if header[0..8] != OBJECT_MAGIC[..] {
            return Err(invalid("not a USNA Secure object file"));
        }
        if u16::from_le_bytes([header[8], header[9]]) != FORMAT_VERSION {
            return Err(invalid("unsupported object format version"));
        }
        if header[10] != 0 || header[11] != 0 {
            return Err(invalid("reserved object flags set"));
        }
        if header[12..28] != vault_id[..] {
            return Err(invalid("object belongs to a different vault"));
        }
        if header[28..44] != object.as_bytes()[..] {
            return Err(invalid("object id does not match the requested object"));
        }
        let cs = u32::from_le_bytes([header[44], header[45], header[46], header[47]]);
        if !valid_chunk_size(cs) {
            return Err(invalid("invalid chunk size"));
        }
        let mut prefix = [0u8; 16];
        prefix.copy_from_slice(&header[48..64]);

        // Geometry (docs/FILE_FORMAT.md): validated before any decryption.
        let stride = u64::from(cs) + TAG;
        let body = size - OBJECT_HEADER_LEN as u64;
        let chunks = body.div_ceil(stride);
        let last_ct_len = body - (chunks - 1) * stride;
        if last_ct_len < TAG || (last_ct_len == TAG && chunks > 1) {
            return Err(invalid("invalid object geometry (truncated or extended)"));
        }
        let plaintext_len = body - TAG * chunks;

        let mut r = Self {
            inner,
            key: key.secret().duplicate(),
            header,
            prefix,
            chunk_size: u64::from(cs),
            chunks,
            last_ct_len,
            plaintext_len,
            cache: None,
            pos: 0,
        };
        r.load(chunks - 1)?; // authenticate the final chunk now: detects truncation immediately
        Ok(r)
    }

    /// Plaintext length in bytes.
    pub fn len(&self) -> u64 {
        self.plaintext_len
    }

    /// True for an empty file.
    pub fn is_empty(&self) -> bool {
        self.plaintext_len == 0
    }

    fn load(&mut self, i: u64) -> io::Result<()> {
        if matches!(&self.cache, Some((c, _)) if *c == i) {
            return Ok(());
        }
        if i >= self.chunks {
            return Err(invalid("chunk index out of range"));
        }
        let stride = self.chunk_size + TAG;
        let last = i == self.chunks - 1;
        let ct_len = if last { self.last_ct_len } else { stride };
        let offset = OBJECT_HEADER_LEN as u64 + i * stride;
        self.inner.seek(SeekFrom::Start(offset))?;
        let mut ct = vec![0u8; usize::try_from(ct_len).map_err(|_| invalid("chunk too large"))?];
        self.inner.read_exact(&mut ct)?;
        let nonce = chunk_nonce(&self.prefix, i);
        let aad = chunk_aad(&self.header, i, last);
        let pt = aead::decrypt_with_nonce(&self.key, &nonce, &aad, &ct)
            .map_err(|_| invalid("chunk authentication failed (object modified or corrupted)"))?;
        self.cache = Some((i, pt));
        Ok(())
    }

    /// Authenticate every chunk. Returns the plaintext length. Does not move the read position.
    pub fn verify_all(&mut self) -> io::Result<u64> {
        for i in 0..self.chunks {
            self.load(i)?;
        }
        Ok(self.plaintext_len)
    }
}

impl<R: Read + Seek> Read for ObjectReader<R> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if out.is_empty() || self.pos >= self.plaintext_len {
            return Ok(0);
        }
        let ci = self.pos / self.chunk_size;
        self.load(ci)?;
        let off =
            usize::try_from(self.pos % self.chunk_size).map_err(|_| invalid("offset overflow"))?;
        let n = match &self.cache {
            Some((_, pt)) => {
                let n = pt.len().saturating_sub(off).min(out.len());
                out[..n].copy_from_slice(&pt[off..off + n]);
                n
            }
            None => return Err(invalid("internal error: chunk cache is empty")),
        };
        self.pos += n as u64;
        Ok(n)
    }
}

impl<R: Read + Seek> Seek for ObjectReader<R> {
    fn seek(&mut self, from: SeekFrom) -> io::Result<u64> {
        let target: i128 = match from {
            SeekFrom::Start(p) => i128::from(p),
            SeekFrom::Current(d) => i128::from(self.pos) + i128::from(d),
            SeekFrom::End(d) => i128::from(self.plaintext_len) + i128::from(d),
        };
        if target < 0 {
            return Err(invalid("seek before the start of the file"));
        }
        self.pos = u64::try_from(target).map_err(|_| invalid("seek position overflow"))?;
        Ok(self.pos)
    }
}
