//! CSPRNG seam: production code draws from the operating system, tests inject determinism.
//!
//! Every random value in the auth crate (OTP codes, pending-auth ids, token bodies, refresh
//! secrets) flows through [`RandomSource`], so unit and integration tests can pin exact
//! outputs without touching global state.

use std::sync::Mutex;

/// Source of cryptographically secure random bytes.
///
/// The contract is CSPRNG-quality output in production ([`OsRandom`]); test doubles trade
/// that away for determinism on purpose.
pub trait RandomSource: Send + Sync {
    /// Fills `buf` entirely with random bytes.
    fn fill(&self, buf: &mut [u8]);
}

/// Operating-system CSPRNG (getrandom: `getrandom(2)` / `SecRandomCopyBytes` / …).
pub struct OsRandom;

impl RandomSource for OsRandom {
    fn fill(&self, buf: &mut [u8]) {
        // An unavailable OS CSPRNG is unrecoverable for an auth system — abort loudly rather
        // than degrade to predictable secrets.
        getrandom::fill(buf).expect("operating system CSPRNG unavailable");
    }
}

/// Deterministic test double: replays a fixed byte sequence, cycling when exhausted.
///
/// Lives in the library (not `#[cfg(test)]`) so integration tests of dependent crates can
/// inject it too. Never use outside tests.
pub struct FixedRandom {
    bytes: Vec<u8>,
    cursor: Mutex<usize>,
}

impl FixedRandom {
    /// A source replaying `bytes` cyclically. Panics on an empty sequence.
    pub fn new(bytes: Vec<u8>) -> Self {
        assert!(!bytes.is_empty(), "FixedRandom needs at least one byte");
        Self { bytes, cursor: Mutex::new(0) }
    }
}

impl RandomSource for FixedRandom {
    fn fill(&self, buf: &mut [u8]) {
        let mut cursor = self.cursor.lock().expect("cursor mutex poisoned");
        for slot in buf.iter_mut() {
            *slot = self.bytes[*cursor % self.bytes.len()];
            *cursor += 1;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn os_random_fills_and_varies() {
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        OsRandom.fill(&mut a);
        OsRandom.fill(&mut b);
        // 2^-256 false-negative probability — acceptable.
        assert_ne!(a, b, "two OS draws must differ");
    }

    #[test]
    fn fixed_random_replays_and_cycles() {
        let rng = FixedRandom::new(vec![1, 2, 3]);
        let mut buf = [0u8; 7];
        rng.fill(&mut buf);
        assert_eq!(buf, [1, 2, 3, 1, 2, 3, 1]);
        let mut next = [0u8; 2];
        rng.fill(&mut next);
        assert_eq!(next, [2, 3], "the cursor must persist across calls");
    }
}
