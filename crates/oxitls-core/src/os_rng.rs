//! OS-entropy CSPRNG adapters (see [`OsRng`]).
//!
//! These exist so the COOLJAPAN crypto crates (`rsa` 0.9, `ed25519-dalek` 2.x,
//! `x25519-dalek` 2.x) — which bind to the `rand_core` 0.6 traits — get an RNG
//! decoupled from the workspace `rand`/`rand_core` 0.10 versions. Entropy is
//! sourced from the `getrandom` crate.

/// OS CSPRNG implementing the `rand_core` 0.6 traits required by `rsa` 0.9,
/// `ed25519-dalek` 2.x and `x25519-dalek` 2.x. Entropy comes from `getrandom`,
/// so this type is independent of the workspace `rand`/`rand_core` 0.10 versions.
#[derive(Clone, Copy, Debug, Default)]
pub struct OsRng;

impl rand_core::RngCore for OsRng {
    fn next_u32(&mut self) -> u32 {
        let mut b = [0u8; 4];
        self.fill_bytes(&mut b);
        u32::from_ne_bytes(b)
    }
    fn next_u64(&mut self) -> u64 {
        let mut b = [0u8; 8];
        self.fill_bytes(&mut b);
        u64::from_ne_bytes(b)
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        getrandom::fill(dest).expect("OS CSPRNG (getrandom) failure");
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

impl rand_core::CryptoRng for OsRng {}
