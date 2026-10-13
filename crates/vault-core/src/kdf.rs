//! Password-based key derivation: Argon2id (RFC 9106), version 0x13.
//!
//! Parameters are stored in the (authenticated) header. They are validated against hard floors
//! and ceilings *before* Argon2 runs, so a hostile vault file cannot force a multi-gigabyte
//! allocation (denial of service) or silently select trivially weak parameters.

use zeroize::Zeroize;

use crate::{
    error::{Error, Result},
    password::Password,
    secret::{SecretKey, KEY_LEN},
};

/// Header identifier for "Argon2id, version 0x13".
pub(crate) const KDF_ID_ARGON2ID_V13: u8 = 1;

/// Argon2id cost parameters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KdfParams {
    /// Memory cost in KiB.
    pub m_cost_kib: u32,
    /// Number of passes.
    pub t_cost: u32,
    /// Lanes. The core runs lanes sequentially (no `rayon`), so higher values cost the defender
    /// wall-clock time without the multi-core speedup; the default is 1. See docs/DEPENDENCIES.md.
    pub parallelism: u32,
}

impl KdfParams {
    /// Default for new vaults: 256 MiB, 3 passes, 1 lane.
    ///
    /// This is a starting point, not a measured guarantee. The app should benchmark the host at
    /// vault creation and store tuned values (target roughly 0.5–1 s), never going below the floor.
    pub const RECOMMENDED: Self = Self {
        m_cost_kib: 262_144,
        t_cost: 3,
        parallelism: 1,
    };

    /// Very weak parameters for fast tests. Not available in normal builds.
    #[cfg(any(test, feature = "insecure-test-params"))]
    pub const INSECURE_TEST: Self = Self {
        m_cost_kib: 8,
        t_cost: 1,
        parallelism: 1,
    };

    const MIN_M_KIB: u32 = if cfg!(any(test, feature = "insecure-test-params")) {
        8
    } else {
        19_456
    };
    const MIN_T: u32 = if cfg!(any(test, feature = "insecure-test-params")) {
        1
    } else {
        2
    };
    const MAX_M_KIB: u32 = 1_048_576; // 1 GiB
    const MAX_T: u32 = 16;
    const MAX_P: u32 = 16;

    /// Check the parameters against the policy floors and ceilings.
    pub fn validate(&self) -> Result<()> {
        if self.parallelism == 0 || self.parallelism > Self::MAX_P {
            return Err(Error::InvalidKdfParams("parallelism out of range"));
        }
        if self.m_cost_kib < Self::MIN_M_KIB {
            return Err(Error::InvalidKdfParams("memory cost below minimum"));
        }
        if self.m_cost_kib > Self::MAX_M_KIB {
            return Err(Error::InvalidKdfParams("memory cost above maximum"));
        }
        if self.m_cost_kib < self.parallelism.saturating_mul(8) {
            return Err(Error::InvalidKdfParams(
                "memory cost must be at least 8 KiB per lane",
            ));
        }
        if self.t_cost < Self::MIN_T || self.t_cost > Self::MAX_T {
            return Err(Error::InvalidKdfParams("time cost out of range"));
        }
        Ok(())
    }

    /// Derive the 32-byte password-derived key (PDK).
    pub(crate) fn derive(&self, password: &Password, salt: &[u8; 32]) -> Result<SecretKey> {
        self.validate()?;
        let params = argon2::Params::new(
            self.m_cost_kib,
            self.t_cost,
            self.parallelism,
            Some(KEY_LEN),
        )
        .map_err(|_| Error::InvalidKdfParams("rejected by Argon2 implementation"))?;
        let ctx = argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
        let mut out = [0u8; KEY_LEN];
        ctx.hash_password_into(password.expose(), salt, &mut out)
            .map_err(|_| Error::KdfFailure)?;
        let key = SecretKey::from_bytes(out);
        out.zeroize();
        Ok(key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_vectors as kat;

    #[test]
    fn argon2id_known_answer() {
        let pw = Password::new(kat::PASSWORD).unwrap();
        let salt: [u8; 32] = hex::decode(kat::SALT).unwrap().try_into().unwrap();
        let pdk = KdfParams::INSECURE_TEST.derive(&pw, &salt).unwrap();
        assert_eq!(hex::encode(pdk.expose()), kat::PDK);
    }

    #[test]
    fn validation_bounds() {
        let ok = KdfParams::INSECURE_TEST;
        assert!(ok.validate().is_ok());
        assert!(KdfParams {
            parallelism: 0,
            ..ok
        }
        .validate()
        .is_err());
        assert!(KdfParams {
            parallelism: 17,
            ..ok
        }
        .validate()
        .is_err());
        assert!(KdfParams {
            m_cost_kib: 7,
            ..ok
        }
        .validate()
        .is_err());
        assert!(KdfParams {
            m_cost_kib: u32::MAX,
            ..ok
        }
        .validate()
        .is_err());
        assert!(KdfParams { t_cost: 0, ..ok }.validate().is_err());
        assert!(KdfParams { t_cost: 17, ..ok }.validate().is_err());
        assert!(KdfParams {
            m_cost_kib: 8,
            parallelism: 2,
            ..ok
        }
        .validate()
        .is_err());
    }

    #[test]
    fn recommended_passes_validation() {
        assert!(KdfParams::RECOMMENDED.validate().is_ok());
    }
}
