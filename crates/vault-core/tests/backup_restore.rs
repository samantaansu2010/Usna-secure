//! A backup is a byte-for-byte copy of {header, snapshot, objects}. These tests pin down what
//! restoring such copies does and does not guarantee (docs/VAULT_FORMAT.md §8).
// Test crate: panicking on a failed fixture or assertion is intended (docs/TESTING.md, "Lint policy for tests").
#![allow(clippy::unwrap_used, clippy::expect_used)]
mod common;
use common::*;
use usna_vault_core::{inspect_snapshot, Error, UnlockedVault};

#[test]
fn restoring_a_consistent_backup_restores_the_exact_state() {
    let (v, header) = new_vault();
    let id = oid();
    let (key, wrapped) = v.new_file_key(&id).unwrap();
    let snapshot = v.seal_snapshot(10, b"state at backup time").unwrap();
    let (backup_header, backup_snapshot) = (header.clone(), snapshot.clone());

    // ... the live vault then moves on (new revisions) and is lost ...
    let _later = v.seal_snapshot(11, b"later state").unwrap();

    let restored = UnlockedVault::unlock(&backup_header, &pw(PW)).unwrap();
    let (rev, pt) = restored.open_snapshot(&backup_snapshot).unwrap();
    assert_eq!((rev, pt.as_slice()), (10, &b"state at backup time"[..]));
    assert!(restored.unwrap_file_key(&wrapped, &id).unwrap() == key);
}

#[test]
fn restoring_an_old_backup_brings_back_the_old_password() {
    let (mut v, backup_header) = new_vault();
    let upd = v
        .prepare_password_change(&pw(PW), &pw("rotated passphrase"), fast())
        .unwrap();
    v.commit_header_update(upd).unwrap();
    // The backup predates the change: it opens with the OLD password only.
    assert!(UnlockedVault::unlock(&backup_header, &pw(PW)).is_ok());
    assert_eq!(
        UnlockedVault::unlock(&backup_header, &pw("rotated passphrase")).unwrap_err(),
        Error::AuthenticationFailed
    );
}

#[test]
fn mixing_header_and_snapshot_from_different_generations_is_detected() {
    let (v, h_old) = new_vault();
    let s_old = v.seal_snapshot(1, b"gen1").unwrap();
    let rot = v.begin_vault_key_rotation(&pw(PW)).unwrap();
    let s_new = reseal(&rot, &s_old);
    let h_new = rot.new_header_bytes().to_vec();

    let old = UnlockedVault::unlock(&h_old, &pw(PW)).unwrap();
    let new = UnlockedVault::unlock(&h_new, &pw(PW)).unwrap();
    assert!(old.open_snapshot(&s_old).is_ok());
    assert!(new.open_snapshot(&s_new).is_ok());
    // half-restored vaults fail loudly instead of returning garbage
    assert!(matches!(
        old.open_snapshot(&s_new),
        Err(Error::SnapshotMismatch(_))
    ));
    assert!(matches!(
        new.open_snapshot(&s_old),
        Err(Error::SnapshotMismatch(_))
    ));
    // cleartext fields let the storage layer decide how to recover (finish or roll back)
    assert_eq!(inspect_snapshot(&s_old).unwrap().vk_generation, 1);
    assert_eq!(inspect_snapshot(&s_new).unwrap().vk_generation, 2);
}

#[test]
fn core_alone_cannot_detect_rollback_to_an_older_revision() {
    // KNOWN LIMITATION, asserted so nobody mistakes it for a guarantee: an attacker who can
    // replace files can substitute an older authentic snapshot of the same generation. The core
    // exposes `revision`; detecting rollback needs state outside the vault (docs/THREAT_MODEL.md, T3).
    let (v, _h) = new_vault();
    let old = v.seal_snapshot(1, b"before deleting the entry").unwrap();
    let _newer = v.seal_snapshot(2, b"after deleting the entry").unwrap();
    let (rev, pt) = v.open_snapshot(&old).unwrap();
    assert_eq!(rev, 1);
    assert_eq!(pt.as_slice(), b"before deleting the entry");
}

#[test]
fn backups_of_different_vaults_never_cross_unlock() {
    let (_a, ha) = UnlockedVault::create(&pw("password for vault A"), fast()).unwrap();
    let (_b, hb) = UnlockedVault::create(&pw("password for vault B"), fast()).unwrap();
    assert!(UnlockedVault::unlock(&ha, &pw("password for vault B")).is_err());
    assert!(UnlockedVault::unlock(&hb, &pw("password for vault A")).is_err());
}
