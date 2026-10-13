//! Randomness. All randomness comes from the operating system CSPRNG via `getrandom`
//! (the Windows backend depends on the resolved `getrandom` version). There is no userland PRNG
//! and no seeding API.

use crate::error::{Error, Result};

/// Fill `buf` with OS-provided random bytes.
pub(crate) fn fill(buf: &mut [u8]) -> Result<()> {
    getrandom::getrandom(buf).map_err(|_| Error::RngFailure)
}

/// Return `N` random bytes.
pub(crate) fn array<const N: usize>() -> Result<[u8; N]> {
    let mut a = [0u8; N];
    fill(&mut a)?;
    Ok(a)
}
