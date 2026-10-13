//! Vault lifecycle: create, unlock, wrong password, normalization, KDF policy, redaction.
// Test crate: panicking on a failed fixture or assertion is intended (docs/TESTING.md, "Lint policy for tests").
#![allow(clippy::unwrap_used, clippy::expect_used)]
mod common;
use common::*;
use usna_vault_core::{Error, KdfParams, Password, UnlockedVault, HEADER_LEN};

#[test]
fn create_then_unlock_with_correct_password() {
    let (vault, header) = new_vault();
    assert_eq!(header.len(), HEADER_LEN);
    assert_eq!(vault.vk_generation(), 1);
    let id = *vault.vault_id();
    vault.lock();
    let again = UnlockedVault::unlock(&header, &pw(PW)).unwrap();
    assert_eq!(*again.vault_id(), id);
    assert_eq!(again.header_bytes().as_slice(), header.as_slice());
}

#[test]
fn wrong_password_fails_with_authentication_failed() {
    let (_v, header) = new_vault();
    for wrong in [
        "wrong",
        "Correct horse battery staple",
        "correct horse battery staple ",
    ] {
        assert_eq!(
            UnlockedVault::unlock(&header, &pw(wrong)).unwrap_err(),
            Error::AuthenticationFailed
        );
    }
}

#[test]
fn empty_password_is_rejected_before_any_derivation() {
    assert!(matches!(Password::new(""), Err(Error::InvalidPassword(_))));
}

#[test]
fn unicode_normalization_is_applied_to_the_password() {
    let (_v, header) = UnlockedVault::create(&pw("caf\u{e9} passphrase"), fast()).unwrap();
    assert!(UnlockedVault::unlock(&header, &pw("cafe\u{301} passphrase")).is_ok());
}

#[test]
fn two_vaults_share_no_identifying_material() {
    let (a, ha) = new_vault();
    let (b, hb) = new_vault();
    assert_ne!(a.vault_id(), b.vault_id());
    assert_ne!(ha, hb);
    // salt (45..77), nonce (77..101) and wrapped VK (101..149) must all differ
    assert_ne!(ha[45..77], hb[45..77]);
    assert_ne!(ha[77..101], hb[77..101]);
    assert_ne!(ha[101..149], hb[101..149]);
}

#[test]
fn weak_kdf_parameters_are_refused_by_policy() {
    let too_weak = KdfParams {
        m_cost_kib: 7,
        t_cost: 1,
        parallelism: 1,
    };
    assert!(matches!(
        UnlockedVault::create(&pw(PW), too_weak),
        Err(Error::InvalidKdfParams(_))
    ));
}

#[test]
fn debug_output_never_contains_key_material() {
    let (v, header) = new_vault();
    let dbg = format!("{v:?}");
    assert!(dbg.contains("redacted"));
    let p = pw("super secret master password");
    assert!(!format!("{p:?}").contains("super"));
    drop(header);
}
