//! End-to-end lifecycle on real files: create, store an encrypted entry, lock, reopen, recover,
//! update, and detect on-disk tampering. Uses only the public API plus `std::fs` (the storage layer
//! is milestone 3, so the files are written by the test itself).
// Test crate: panicking on a failed fixture or assertion is intended (docs/TESTING.md, "Lint policy for tests").
#![allow(clippy::unwrap_used, clippy::expect_used)]
mod common;
#[path = "support/demo_entry.rs"]
mod demo_entry;

use common::*;
use demo_entry::{contains_bytes, write_atomic, DemoEntry};
use std::{fs, path::PathBuf};
use usna_vault_core::{Error, UnlockedVault};

/// Unique temp directory, removed on drop.
struct TempDir(PathBuf);
impl TempDir {
    fn new() -> Self {
        let id: String = oid()
            .as_bytes()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        let dir = std::env::temp_dir().join(format!("usna-lifecycle-test-{id}"));
        fs::create_dir_all(&dir).unwrap();
        Self(dir)
    }
}
impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn entry(password: &str) -> DemoEntry {
    DemoEntry {
        title: "GitHub".into(),
        username: "alice@example.com".into(),
        password: password.into(),
    }
}

#[test]
fn create_store_lock_reopen_and_recover_an_entry_from_disk() {
    let tmp = TempDir::new();
    let (header_path, db_path) = (tmp.0.join("vault.header"), tmp.0.join("vault.db"));
    let original = entry("S3cret-Passw0rd-MARKER");

    // create + unlock (create returns the unlocked vault) + store
    let (vault, header_bytes) = new_vault();
    let snapshot = vault.seal_snapshot(1, &original.encode()).unwrap();
    write_atomic(&header_path, &header_bytes).unwrap();
    write_atomic(&db_path, &snapshot).unwrap();

    // what is on disk is not plaintext
    let on_disk = [fs::read(&header_path).unwrap(), fs::read(&db_path).unwrap()].concat();
    for secret in [&original.password, &original.username, &original.title] {
        assert!(
            !contains_bytes(&on_disk, secret.as_bytes()),
            "plaintext leaked: {secret}"
        );
    }
    assert_eq!(fs::read(&header_path).unwrap().len(), 149);

    // lock: keys wiped, nothing usable remains in memory but the files
    vault.lock();

    // wrong password is refused
    let header = fs::read(&header_path).unwrap();
    assert_eq!(
        UnlockedVault::unlock(&header, &pw("not the password")).unwrap_err(),
        Error::AuthenticationFailed
    );

    // reopen with the right password and recover exactly what was stored
    let reopened = UnlockedVault::unlock(&header, &pw(PW)).unwrap();
    let (revision, plaintext) = reopened
        .open_snapshot(&fs::read(&db_path).unwrap())
        .unwrap();
    assert_eq!(revision, 1);
    assert_eq!(DemoEntry::decode(&plaintext).unwrap(), original);
}

#[test]
fn updating_the_entry_persists_across_lock_and_reopen() {
    let tmp = TempDir::new();
    let (header_path, db_path) = (tmp.0.join("vault.header"), tmp.0.join("vault.db"));
    let (vault, header_bytes) = new_vault();
    write_atomic(&header_path, &header_bytes).unwrap();
    write_atomic(
        &db_path,
        &vault.seal_snapshot(1, &entry("old").encode()).unwrap(),
    )
    .unwrap();

    write_atomic(
        &db_path,
        &vault
            .seal_snapshot(2, &entry("new-password").encode())
            .unwrap(),
    )
    .unwrap();
    vault.lock();

    let v = UnlockedVault::unlock(&fs::read(&header_path).unwrap(), &pw(PW)).unwrap();
    let (revision, plaintext) = v.open_snapshot(&fs::read(&db_path).unwrap()).unwrap();
    assert_eq!(revision, 2);
    assert_eq!(
        DemoEntry::decode(&plaintext).unwrap().password,
        "new-password"
    );
}

#[test]
fn on_disk_tampering_is_detected_after_reopen() {
    let tmp = TempDir::new();
    let (header_path, db_path) = (tmp.0.join("vault.header"), tmp.0.join("vault.db"));
    let (vault, header_bytes) = new_vault();
    write_atomic(&header_path, &header_bytes).unwrap();
    write_atomic(
        &db_path,
        &vault.seal_snapshot(1, &entry("x").encode()).unwrap(),
    )
    .unwrap();
    vault.lock();

    // flip one bit in the middle of the database file
    let mut db = fs::read(&db_path).unwrap();
    let mid = db.len() / 2;
    db[mid] ^= 0x01;
    write_atomic(&db_path, &db).unwrap();
    let v = UnlockedVault::unlock(&fs::read(&header_path).unwrap(), &pw(PW)).unwrap();
    assert_eq!(
        v.open_snapshot(&fs::read(&db_path).unwrap()).unwrap_err(),
        Error::AuthenticationFailed
    );

    // flip one bit in the header file
    let mut header = fs::read(&header_path).unwrap();
    header[60] ^= 0x01; // inside the KDF salt
    assert!(UnlockedVault::unlock(&header, &pw(PW)).is_err());
}
