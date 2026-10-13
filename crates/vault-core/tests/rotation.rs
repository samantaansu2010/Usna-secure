//! Password change and vault-key rotation, including the rewrap obligations for keys embedded in the snapshot.
// Test crate: panicking on a failed fixture or assertion is intended (docs/TESTING.md, "Lint policy for tests").
#![allow(clippy::unwrap_used, clippy::expect_used)]
mod common;
use common::*;
use usna_vault_core::{Error, Header, KdfParams, UnlockedVault, WrappedFileKey};

// ---------------------------------------------------------------- password change --------

#[test]
fn password_change_rewraps_the_same_vault_key() {
    let (mut v, h0) = new_vault();
    let blob = v.seal_snapshot(1, b"data").unwrap();
    let id = oid();
    let (fk, wrapped) = v.new_file_key(&id).unwrap();

    let upd = v
        .prepare_password_change(&pw(PW), &pw("a brand new passphrase"), fast())
        .unwrap();
    // Nothing changes until the caller has persisted the header and commits.
    assert_eq!(v.header_bytes().as_slice(), h0.as_slice());
    let h1 = upd.bytes().to_vec();
    v.commit_header_update(upd).unwrap();
    assert_eq!(v.header_bytes().as_slice(), h1.as_slice());

    // Credentials replaced.
    assert_eq!(
        UnlockedVault::unlock(&h1, &pw(PW)).unwrap_err(),
        Error::AuthenticationFailed
    );
    let v2 = UnlockedVault::unlock(&h1, &pw("a brand new passphrase")).unwrap();

    // Same VK: existing database and wrapped file keys remain valid with NO re-encryption.
    assert_eq!(v2.open_snapshot(&blob).unwrap().1.as_slice(), b"data");
    assert!(v2.unwrap_file_key(&wrapped, &id).unwrap() == fk);

    // Identity and generation unchanged; salt, nonce and wrapped VK all fresh.
    assert_eq!(h0[12..32], h1[12..32]);
    assert_ne!(h0[45..77], h1[45..77]);
    assert_ne!(h0[77..101], h1[77..101]);
    assert_ne!(h0[101..149], h1[101..149]);
}

#[test]
fn password_change_can_change_kdf_parameters() {
    let (v, _h) = new_vault();
    let stronger = KdfParams {
        m_cost_kib: 16,
        t_cost: 2,
        parallelism: 1,
    };
    let upd = v
        .prepare_password_change(&pw(PW), &pw("another passphrase"), stronger)
        .unwrap();
    assert_eq!(Header::parse(&upd.bytes()).unwrap().kdf_params(), stronger);
}

#[test]
fn password_change_requires_the_current_password() {
    let (v, h0) = new_vault();
    let r = v.prepare_password_change(&pw("not it"), &pw("new passphrase"), fast());
    assert_eq!(r.unwrap_err(), Error::AuthenticationFailed);
    assert_eq!(v.header_bytes().as_slice(), h0.as_slice());
}

#[test]
fn password_change_rejects_invalid_kdf_parameters() {
    let (v, _h) = new_vault();
    let bad = KdfParams {
        m_cost_kib: 1,
        t_cost: 1,
        parallelism: 1,
    };
    assert!(matches!(
        v.prepare_password_change(&pw(PW), &pw("x passphrase"), bad),
        Err(Error::InvalidKdfParams(_))
    ));
}

#[test]
fn header_update_for_another_vault_cannot_be_committed() {
    let (mut a, _) = new_vault();
    let (b, _) = new_vault();
    let upd = b
        .prepare_password_change(&pw(PW), &pw("new passphrase"), fast())
        .unwrap();
    assert_eq!(
        a.commit_header_update(upd).unwrap_err(),
        Error::HeaderUpdateMismatch
    );
}

#[test]
fn old_header_still_opens_with_the_old_password() {
    // Documented behaviour (docs/VAULT_FORMAT.md §8): a copy of the old header, e.g. inside an old
    // backup, keeps working with the OLD password. Changing a password does not revoke old copies.
    let (mut v, h0) = new_vault();
    let upd = v
        .prepare_password_change(&pw(PW), &pw("new passphrase"), fast())
        .unwrap();
    v.commit_header_update(upd).unwrap();
    assert!(UnlockedVault::unlock(&h0, &pw(PW)).is_ok());
}

// ---------------------------------------------------------------- vault-key rotation ------

#[test]
fn vault_key_rotation_rewraps_file_keys_and_reseals_the_database() {
    let (v, h0) = new_vault();
    let blob0 = v.seal_snapshot(4, b"db v1").unwrap();
    let files: Vec<_> = (0..3)
        .map(|_| {
            let id = oid();
            let (k, w) = v.new_file_key(&id).unwrap();
            (id, k, w)
        })
        .collect();

    let rot = v.begin_vault_key_rotation(&pw(PW)).unwrap();
    assert_eq!(rot.new_generation(), 2);
    let h1 = rot.new_header_bytes().to_vec();
    let blob1 = reseal(&rot, &blob0);
    let rewrapped: Vec<_> = files
        .iter()
        .map(|(id, _, w)| rot.rewrap_file_key(w, id).unwrap())
        .collect();
    let _new = rot.into_new_vault();

    // Same password, new generation, same vault identity, same salt and KDF parameters.
    let v2 = UnlockedVault::unlock(&h1, &pw(PW)).unwrap();
    assert_eq!(v2.vk_generation(), 2);
    assert_eq!(v2.vault_id(), v.vault_id());
    assert_eq!(h0[33..77], h1[33..77]);
    assert_ne!(h0[101..149], h1[101..149]); // a different VK is wrapped

    // Database: revision bumped, content preserved.
    let (rev, pt) = v2.open_snapshot(&blob1).unwrap();
    assert_eq!((rev, pt.as_slice()), (5, &b"db v1"[..]));

    // File keys: identical keys (so file objects need no re-encryption), new wrapping.
    for ((id, key, old_wrapped), new_wrapped) in files.iter().zip(&rewrapped) {
        assert_ne!(old_wrapped, new_wrapped);
        assert!(v2.unwrap_file_key(new_wrapped, id).unwrap() == *key);
        // Old wrapped keys are unusable under the new generation.
        assert_eq!(
            v2.unwrap_file_key(old_wrapped, id).unwrap_err(),
            Error::AuthenticationFailed
        );
    }

    // Old artifacts are rejected by the new vault and vice versa (mixed-generation detection).
    assert!(matches!(
        v2.open_snapshot(&blob0),
        Err(Error::SnapshotMismatch(_))
    ));
    assert!(matches!(
        v.open_snapshot(&blob1),
        Err(Error::SnapshotMismatch(_))
    ));
}

#[test]
fn vault_key_rotation_requires_the_password_and_leaves_the_vault_untouched() {
    let (v, h0) = new_vault();
    let blob = v.seal_snapshot(1, b"x").unwrap();
    assert_eq!(
        v.begin_vault_key_rotation(&pw("nope")).unwrap_err(),
        Error::AuthenticationFailed
    );
    assert_eq!(v.header_bytes().as_slice(), h0.as_slice());
    assert!(v.open_snapshot(&blob).is_ok());
}

#[test]
fn rotation_can_be_abandoned_without_side_effects() {
    let (v, h0) = new_vault();
    let blob = v.seal_snapshot(1, b"x").unwrap();
    let rot = v.begin_vault_key_rotation(&pw(PW)).unwrap();
    drop(rot); // crash before commit: on-disk state is still generation 1
    assert!(UnlockedVault::unlock(&h0, &pw(PW))
        .unwrap()
        .open_snapshot(&blob)
        .is_ok());
}

#[test]
fn rotation_can_be_repeated() {
    let (v, _h) = new_vault();
    let blob = v.seal_snapshot(1, b"persisted").unwrap();
    let r1 = v.begin_vault_key_rotation(&pw(PW)).unwrap();
    let b1 = reseal(&r1, &blob);
    let v1 = r1.into_new_vault();
    let r2 = v1.begin_vault_key_rotation(&pw(PW)).unwrap();
    assert_eq!(r2.new_generation(), 3);
    let b2 = reseal(&r2, &b1);
    let v2 = UnlockedVault::unlock(r2.new_header_bytes(), &pw(PW)).unwrap();
    let (rev, pt) = v2.open_snapshot(&b2).unwrap();
    assert_eq!((rev, pt.as_slice()), (3, &b"persisted"[..]));
}

#[test]
fn rewrap_is_bound_to_the_object_id() {
    let (v, _h) = new_vault();
    let (id, other) = (oid(), oid());
    let (_k, w) = v.new_file_key(&id).unwrap();
    let rot = v.begin_vault_key_rotation(&pw(PW)).unwrap();
    assert_eq!(
        rot.rewrap_file_key(&w, &other).unwrap_err(),
        Error::AuthenticationFailed
    );
}

#[test]
fn reseal_rejects_a_snapshot_of_the_wrong_generation() {
    let (v, _h) = new_vault();
    let blob = v.seal_snapshot(1, b"x").unwrap();
    let r1 = v.begin_vault_key_rotation(&pw(PW)).unwrap();
    let v1 = r1.into_new_vault();
    let r2 = v1.begin_vault_key_rotation(&pw(PW)).unwrap();
    // `blob` is generation 1 but r2 starts from generation 2
    assert!(matches!(
        r2.open_old_snapshot(&blob),
        Err(Error::SnapshotMismatch(_))
    ));
}

#[test]
fn keys_embedded_in_the_snapshot_must_be_rewrapped_by_the_caller() {
    // Documents the footgun the API split exists to prevent: the snapshot plaintext carries wrapped
    // file keys bound to the OLD generation. Sealing it unchanged "works" but loses every file key.
    let (v, _h) = new_vault();
    let id = oid();
    let (key, wrapped) = v.new_file_key(&id).unwrap();
    let blob = v.seal_snapshot(1, wrapped.as_bytes()).unwrap(); // snapshot plaintext = the wrapped key

    let rot = v.begin_vault_key_rotation(&pw(PW)).unwrap();
    let (_rev, pt) = rot.open_old_snapshot(&blob).unwrap();
    let naive = rot.seal_new_snapshot(2, &pt).unwrap(); // WRONG: stale wrapped key
    let rewrapped = rot
        .rewrap_file_key(&WrappedFileKey::from_slice(&pt).unwrap(), &id)
        .unwrap();
    let good = rot.seal_new_snapshot(2, rewrapped.as_bytes()).unwrap(); // RIGHT

    let v2 = UnlockedVault::unlock(rot.new_header_bytes(), &pw(PW)).unwrap();
    let (_r, naive_pt) = v2.open_snapshot(&naive).unwrap();
    let stale = WrappedFileKey::from_slice(&naive_pt).unwrap();
    assert_eq!(
        v2.unwrap_file_key(&stale, &id).unwrap_err(),
        Error::AuthenticationFailed
    );
    let (_r, good_pt) = v2.open_snapshot(&good).unwrap();
    let fresh = WrappedFileKey::from_slice(&good_pt).unwrap();
    assert!(v2.unwrap_file_key(&fresh, &id).unwrap() == key);
}
