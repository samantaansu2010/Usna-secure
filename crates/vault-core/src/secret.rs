//! Secret key container: zeroized on drop, not `Clone`, redacted `Debug`, constant-time `Eq`.
//!
//! Zeroization is best-effort: it wipes *this* copy. It cannot reach copies made by the OS
//! (swap, hibernation, crash dumps) or inside third-party library internals. See
//! docs/THREAT_MODEL.md, "Memory".

use core::fmt;

use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{error::Result, rng};

/// Length of every symmetric key in the hierarchy (256 bits).
pub(crate) const KEY_LEN: usize = 32;

/// A 256-bit secret key.
#[derive(Zeroize, ZeroizeOnDrop)]
pub(crate) struct SecretKey([u8; KEY_LEN]);

impl SecretKey {
    pub(crate) fn from_bytes(bytes: [u8; KEY_LEN]) -> Self {
        Self(bytes)
    }

    /// `None` unless `bytes` is exactly 32 bytes.
    pub(crate) fn from_slice(bytes: &[u8]) -> Option<Self> {
        let mut a = [0u8; KEY_LEN];
        if bytes.len() != KEY_LEN {
            return None;
        }
        a.copy_from_slice(bytes);
        let k = Self(a);
        a.zeroize();
        Some(k)
    }

    pub(crate) fn generate() -> Result<Self> {
        let mut b = rng::array::<KEY_LEN>()?;
        let k = Self(b);
        b.zeroize();
        Ok(k)
    }

    pub(crate) fn expose(&self) -> &[u8; KEY_LEN] {
        &self.0
    }

    /// Explicit copy (there is deliberately no `Clone`).
    pub(crate) fn duplicate(&self) -> Self {
        Self(self.0)
    }
}

impl PartialEq for SecretKey {
    fn eq(&self, other: &Self) -> bool {
        bool::from(self.0[..].ct_eq(&other.0[..]))
    }
}
impl Eq for SecretKey {}

impl fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretKey(<redacted>)")
    }
}
