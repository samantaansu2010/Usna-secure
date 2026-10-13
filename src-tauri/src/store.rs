//! Vault directory access: header and snapshot files, encrypted file objects, single-instance lock.
//!
//! Still an interim store (docs/APP.md): single-file writes are temp file + flush + rename, without
//! Windows write-through (that needs `unsafe` FFI, which this project forbids; a safe route is open).
//! There is no vault-key rotation in the app, so the two-file rotation commit is not needed yet.
//! New in this revision: an OS file lock that stops two processes opening the same vault (released
//! automatically if the process dies, so there is no stale-lock problem), cleanup of leftover temp
//! files after a crash, and storage of encrypted file objects.

use std::{
    fs::{self, File, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
};

/// The narrow storage interface a session needs to commit changes. `Store` is the real implementation;
/// tests substitute one that can fail on demand to prove that failed saves leave the session consistent.
pub trait Backend: Send {
    fn write_db(&self, bytes: &[u8]) -> Result<(), String>;
    fn write_header(&self, bytes: &[u8]) -> Result<(), String>;
    fn read_header(&self) -> Result<Vec<u8>, String>;
    fn read_db(&self) -> Result<Vec<u8>, String>;
    /// Best effort; must only be called after the snapshot that no longer references the object is committed.
    fn remove_object(&self, hex: &str);
}

impl Backend for Store {
    fn write_db(&self, bytes: &[u8]) -> Result<(), String> {
        Store::write_db(self, bytes)
    }
    fn write_header(&self, bytes: &[u8]) -> Result<(), String> {
        Store::write_header(self, bytes)
    }
    fn read_header(&self) -> Result<Vec<u8>, String> {
        Store::read_header(self)
    }
    fn read_db(&self) -> Result<Vec<u8>, String> {
        Store::read_db(self)
    }
    fn remove_object(&self, hex: &str) {
        Store::remove_object(self, hex)
    }
}

pub struct Store {
    dir: PathBuf,
}

fn write_atomic(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("file");
    let tmp = path.with_file_name(format!("{name}.tmp"));
    let mut f = File::create(&tmp)?;
    f.write_all(bytes)?;
    f.sync_all()?;
    drop(f);
    fs::rename(&tmp, path)
}

/// Object ids are 32 lowercase hex characters; anything else is refused (no path tricks).
fn valid_id(hex: &str) -> bool {
    hex.len() == 32 && hex.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

impl Store {
    pub fn new(dir: PathBuf) -> Self {
        Self { dir }
    }
    fn header_path(&self) -> PathBuf {
        self.dir.join("vault.header")
    }
    fn db_path(&self) -> PathBuf {
        self.dir.join("vault.db")
    }
    fn objects_dir(&self) -> PathBuf {
        self.dir.join("objects")
    }
    /// A vault "exists" once its header exists (the header is written last on creation).
    pub fn exists(&self) -> bool {
        self.header_path().is_file()
    }
    pub fn init_dir(&self) -> Result<(), String> {
        fs::create_dir_all(&self.dir).map_err(|e| format!("Cannot create the vault folder: {e}"))
    }

    /// Take the exclusive OS lock on `.lock`. Keep the returned file alive while the vault is open;
    /// dropping it (or the process dying) releases the lock. Needs Rust 1.89+ (`File::try_lock`).
    pub fn acquire_instance_lock(&self) -> Result<File, String> {
        let f = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(false)
            .open(self.dir.join(".lock"))
            .map_err(|e| format!("Cannot open the vault lock file: {e}"))?;
        match f.try_lock() {
            Ok(()) => Ok(f),
            Err(fs::TryLockError::WouldBlock) => {
                Err("This vault is already open in another USNA Secure window or process.".to_string())
            }
            Err(fs::TryLockError::Error(e)) => Err(format!("Cannot lock the vault folder: {e}")),
        }
    }

    /// Delete temp files left behind by an interrupted save or import. Returns how many were removed.
    pub fn clean_leftovers(&self) -> usize {
        let mut removed = 0;
        for name in ["vault.header.tmp", "vault.db.tmp"] {
            if fs::remove_file(self.dir.join(name)).is_ok() {
                removed += 1;
            }
        }
        if let Ok(shards) = fs::read_dir(self.objects_dir()) {
            for shard in shards.flatten() {
                if let Ok(files) = fs::read_dir(shard.path()) {
                    for f in files.flatten() {
                        if f.file_name().to_string_lossy().ends_with(".obj.tmp") && fs::remove_file(f.path()).is_ok() {
                            removed += 1;
                        }
                    }
                }
            }
        }
        removed
    }

    pub fn read_header(&self) -> Result<Vec<u8>, String> {
        fs::read(self.header_path()).map_err(|e| format!("Cannot read vault.header: {e}"))
    }
    pub fn read_db(&self) -> Result<Vec<u8>, String> {
        fs::read(self.db_path()).map_err(|e| format!("The vault is incomplete (cannot read vault.db): {e}"))
    }
    pub fn write_header(&self, bytes: &[u8]) -> Result<(), String> {
        write_atomic(&self.header_path(), bytes).map_err(|e| format!("Cannot write vault.header: {e}"))
    }
    pub fn write_db(&self, bytes: &[u8]) -> Result<(), String> {
        write_atomic(&self.db_path(), bytes).map_err(|e| format!("Cannot write vault.db: {e}"))
    }

    // ---- encrypted file objects ------------------------------------------------------------------

    fn object_path(&self, hex: &str) -> Result<PathBuf, String> {
        if !valid_id(hex) {
            return Err("Invalid object id.".into());
        }
        Ok(self.objects_dir().join(&hex[..2]).join(format!("{hex}.obj")))
    }

    /// Create `<id>.obj.tmp` for writing. Commit with [`Store::commit_object`] or discard it.
    pub fn begin_object(&self, hex: &str) -> Result<(File, PathBuf), String> {
        let final_path = self.object_path(hex)?;
        let dir = final_path.parent().ok_or_else(|| "Invalid object path.".to_string())?;
        fs::create_dir_all(dir).map_err(|e| format!("Cannot create the objects folder: {e}"))?;
        let tmp = dir.join(format!("{hex}.obj.tmp"));
        let f = File::create(&tmp).map_err(|e| format!("Cannot create the encrypted file: {e}"))?;
        Ok((f, tmp))
    }
    pub fn commit_object(&self, tmp: &Path, hex: &str) -> Result<(), String> {
        fs::rename(tmp, self.object_path(hex)?).map_err(|e| format!("Cannot finalize the encrypted file: {e}"))
    }
    pub fn discard_tmp(&self, tmp: &Path) {
        let _ = fs::remove_file(tmp);
    }
    pub fn open_object(&self, hex: &str) -> Result<File, String> {
        File::open(self.object_path(hex)?).map_err(|e| format!("Cannot open the encrypted file: {e}"))
    }
    /// Best effort: a leftover object is harmless (it is unreadable without its key) and is reported by verify.
    pub fn remove_object(&self, hex: &str) {
        if let Ok(p) = self.object_path(hex) {
            let _ = fs::remove_file(p);
        }
    }
    /// Ids of all committed objects on disk.
    pub fn list_objects(&self) -> Vec<String> {
        let mut ids = Vec::new();
        if let Ok(shards) = fs::read_dir(self.objects_dir()) {
            for shard in shards.flatten() {
                if let Ok(files) = fs::read_dir(shard.path()) {
                    for f in files.flatten() {
                        let name = f.file_name().to_string_lossy().to_string();
                        if let Some(id) = name.strip_suffix(".obj") {
                            if valid_id(id) {
                                ids.push(id.to_string());
                            }
                        }
                    }
                }
            }
        }
        ids
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_store(tag: &str) -> Store {
        let dir = std::env::temp_dir().join(format!("usna-store-test-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        Store::new(dir)
    }

    #[test]
    fn id_validation_blocks_path_tricks() {
        assert!(valid_id(&"ab".repeat(16)));
        for bad in ["", "../../etc/passwd", &"AB".repeat(16), &"ab".repeat(15), &"zz".repeat(16)] {
            assert!(!valid_id(bad), "{bad}");
        }
        let s = temp_store("ids");
        assert!(s.begin_object("../x").is_err());
        assert!(s.open_object("short").is_err());
    }

    #[test]
    fn object_lifecycle_and_leftover_cleanup() {
        let s = temp_store("obj");
        let id = "0123456789abcdef0123456789abcdef";
        let (mut f, tmp) = s.begin_object(id).unwrap();
        f.write_all(b"data").unwrap();
        drop(f);
        assert!(s.list_objects().is_empty(), "an uncommitted object is not listed");
        assert_eq!(s.clean_leftovers(), 1, "an interrupted import is cleaned up");
        assert!(!tmp.exists());

        let (mut f, tmp) = s.begin_object(id).unwrap();
        f.write_all(b"data").unwrap();
        drop(f);
        s.commit_object(&tmp, id).unwrap();
        assert_eq!(s.list_objects(), vec![id.to_string()]);
        assert!(s.open_object(id).is_ok());
        s.remove_object(id);
        assert!(s.list_objects().is_empty());
    }

    #[test]
    fn second_lock_is_refused_until_the_first_is_released() {
        let s = temp_store("lock");
        let first = s.acquire_instance_lock().unwrap();
        let err = s.acquire_instance_lock().unwrap_err();
        assert!(err.contains("already open"), "{err}");
        drop(first);
        assert!(s.acquire_instance_lock().is_ok());
    }

    #[test]
    fn atomic_writes_replace_and_leave_no_temp_file() {
        let s = temp_store("atomic");
        s.write_db(b"one").unwrap();
        s.write_db(b"two").unwrap();
        assert_eq!(s.read_db().unwrap(), b"two");
        assert!(!s.db_path().with_file_name("vault.db.tmp").exists());
    }
}
