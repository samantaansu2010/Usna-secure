//! Helpers shared by `examples/lifecycle_demo.rs` and `tests/lifecycle_on_disk.rs`.
//!
//! DEMO ONLY. `DemoEntry` and its encoding are NOT the vault data model (docs/DATA_MODEL.md,
//! milestone 4) and `write_atomic` is NOT the storage layer (milestone 3: write-through renames,
//! lock file, crash recovery). They exist so the current core can be exercised end to end with real
//! files, without pretending those milestones are done.
//!
//! `dead_code` is allowed because the example and the test each use a different subset.
#![allow(dead_code)]

use std::{fs, io::Write, path::Path};

/// A throwaway "entry": three strings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DemoEntry {
    pub title: String,
    pub username: String,
    pub password: String,
}

impl DemoEntry {
    /// `u32_le(len) || bytes` for title, username, password, in that order.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        for field in [&self.title, &self.username, &self.password] {
            out.extend_from_slice(&(field.len() as u32).to_le_bytes());
            out.extend_from_slice(field.as_bytes());
        }
        out
    }

    /// Strict inverse of [`DemoEntry::encode`]: rejects truncation, invalid UTF-8 and trailing bytes.
    pub fn decode(mut bytes: &[u8]) -> Result<Self, String> {
        let mut fields: Vec<String> = Vec::with_capacity(3);
        for _ in 0..3 {
            if bytes.len() < 4 {
                return Err("truncated length prefix".into());
            }
            let (len_bytes, rest) = bytes.split_at(4);
            let len = u32::from_le_bytes([len_bytes[0], len_bytes[1], len_bytes[2], len_bytes[3]])
                as usize;
            if rest.len() < len {
                return Err("truncated field".into());
            }
            let (data, rest) = rest.split_at(len);
            fields.push(String::from_utf8(data.to_vec()).map_err(|_| "invalid UTF-8".to_string())?);
            bytes = rest;
        }
        if !bytes.is_empty() {
            return Err("trailing bytes".into());
        }
        let mut it = fields.into_iter();
        match (it.next(), it.next(), it.next()) {
            (Some(title), Some(username), Some(password)) => Ok(Self {
                title,
                username,
                password,
            }),
            _ => Err("missing field".into()),
        }
    }
}

/// Write `<name>.tmp`, flush it to disk, then rename over `path` (replace-on-rename also on Windows).
/// Demo-grade: it does not request write-through semantics.
pub fn write_atomic(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("file");
    let tmp = path.with_file_name(format!("{name}.tmp"));
    let mut f = fs::File::create(&tmp)?;
    f.write_all(bytes)?;
    f.sync_all()?;
    drop(f);
    fs::rename(&tmp, path)
}

/// True if `needle` occurs anywhere in `haystack`.
pub fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && haystack.windows(needle.len()).any(|w| w == needle)
}
