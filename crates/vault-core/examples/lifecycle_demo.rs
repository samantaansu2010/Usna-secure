//! Local lifecycle demonstration of `usna-vault-core` on real files.
//!
//! create vault -> store an encrypted test entry -> lock -> wrong-password check -> reopen ->
//! verify the entry is recovered exactly -> verify tampering is detected.
//!
//! This is a demonstration of the CORE, not the application: there is no UI, no entry model
//! (milestone 4) and no storage layer (milestone 3). The "entry" is a throwaway encoding and the files
//! are written with plain `std::fs`. It uses `KdfParams::RECOMMENDED` (256 MiB Argon2id, 3 passes), so
//! run it with `--release`; a debug build of Argon2 is very slow.
//!
//! Usage: cargo run --release -p usna-vault-core --example lifecycle_demo -- [DIRECTORY]
//! The master password is read from USNA_DEMO_PASSWORD, otherwise a fixed DEMO password is used.
//! The directory must not exist or must be empty; it is left in place afterwards for inspection.
//!
//! `print_stdout` is allowed in this file only: it is the demo's user-facing output. The only secret
//! it ever prints is the length of the demo password; the entry's password is never printed.
#![allow(clippy::print_stdout)]

#[path = "../tests/support/demo_entry.rs"]
mod demo_entry;

use std::{error::Error, fs, path::PathBuf, time::Instant};

use demo_entry::{contains_bytes, write_atomic, DemoEntry};
use usna_vault_core::{Error as CoreError, KdfParams, Password, UnlockedVault};

const DEMO_PASSWORD: &str = "demo-only master passphrase, do not reuse";

fn check(ok: bool, what: &str) -> Result<(), Box<dyn Error>> {
    println!("  [{}] {what}", if ok { "ok" } else { "FAIL" });
    if ok {
        Ok(())
    } else {
        Err(format!("check failed: {what}").into())
    }
}

fn main() -> Result<(), Box<dyn Error>> {
    let dir: PathBuf = std::env::args_os()
        .nth(1)
        .map(PathBuf::from)
        .unwrap_or_else(|| std::env::temp_dir().join("usna-demo-vault"));
    if dir.exists() && fs::read_dir(&dir)?.next().is_some() {
        return Err(format!(
            "{} exists and is not empty; choose another path",
            dir.display()
        )
        .into());
    }
    fs::create_dir_all(&dir)?;
    let (header_path, db_path) = (dir.join("vault.header"), dir.join("vault.db"));

    let master = std::env::var("USNA_DEMO_PASSWORD").unwrap_or_else(|_| DEMO_PASSWORD.to_string());
    let password = Password::new(&master)?;
    let entry = DemoEntry {
        title: "GitHub".into(),
        username: "alice@example.com".into(),
        password: "correct-horse-MARKER-7f3a9c".into(),
    };
    println!(
        "USNA Secure core lifecycle demo\nvault directory: {}\n",
        dir.display()
    );

    println!("1. create vault (Argon2id 256 MiB, 3 passes)");
    let t = Instant::now();
    let (vault, header_bytes) = UnlockedVault::create(&password, KdfParams::RECOMMENDED)?;
    println!("  key derivation took {:.2?}", t.elapsed());

    println!("2. store one encrypted test entry");
    let snapshot = vault.seal_snapshot(1, &entry.encode())?;
    write_atomic(&header_path, &header_bytes)?;
    write_atomic(&db_path, &snapshot)?;
    println!(
        "  vault.header: {} bytes, vault.db: {} bytes",
        header_bytes.len(),
        snapshot.len()
    );
    let on_disk = [fs::read(&header_path)?, fs::read(&db_path)?].concat();
    check(
        !contains_bytes(&on_disk, entry.password.as_bytes()),
        "entry password does not appear in the files",
    )?;
    check(
        !contains_bytes(&on_disk, entry.username.as_bytes()),
        "username does not appear in the files",
    )?;
    check(
        !contains_bytes(&on_disk, entry.title.as_bytes()),
        "title does not appear in the files",
    )?;

    println!("3. lock (key material dropped and wiped, best effort)");
    vault.lock();

    println!("4. wrong password is rejected");
    let header = fs::read(&header_path)?;
    let wrong = Password::new("definitely not the password")?;
    check(
        matches!(
            UnlockedVault::unlock(&header, &wrong),
            Err(CoreError::AuthenticationFailed)
        ),
        "wrong password gives AuthenticationFailed",
    )?;

    println!("5. reopen with the correct password and recover the entry");
    let reopened = UnlockedVault::unlock(&header, &password)?;
    let (revision, plaintext) = reopened.open_snapshot(&fs::read(&db_path)?)?;
    let recovered = DemoEntry::decode(&plaintext)?;
    check(revision == 1, "snapshot revision is 1")?;
    check(
        recovered == entry,
        "recovered entry is identical to the stored entry",
    )?;
    println!(
        "  recovered: title={:?} username={:?} password=<{} chars, not printed>",
        recovered.title,
        recovered.username,
        recovered.password.len()
    );

    println!("6. tampering is detected");
    let mut tampered = fs::read(&db_path)?;
    let mid = tampered.len() / 2;
    tampered[mid] ^= 0x01;
    check(
        matches!(
            reopened.open_snapshot(&tampered),
            Err(CoreError::AuthenticationFailed)
        ),
        "one flipped bit in vault.db is rejected",
    )?;

    println!(
        "\nALL CHECKS PASSED. Files left in {} (delete the directory when done).",
        dir.display()
    );
    Ok(())
}
