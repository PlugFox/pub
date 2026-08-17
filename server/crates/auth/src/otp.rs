//! Email OTP primitives (S-03).
//!
//! An OTP is an 8-digit CSPRNG code. At rest only `HMAC-SHA-256(code, pepper)` (hex) is kept,
//! inside a pending-auth record stored in KV under an opaque 128-bit id — the client holds
//! that id and must present it together with the email and code, so a phished code cannot be
//! redeemed from a different flow (S-03 binding). Comparison is constant-time.
//!
//! Policy constants live here so flows and tests share one source of truth: 10-minute expiry,
//! ≤5 verify attempts per code, resends ≥60 s apart (a resend invalidates the prior record),
//! single-use.

use chrono::{DateTime, Duration, Utc};
use hmac::{Hmac, KeyInit as _, Mac as _};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use subtle::ConstantTimeEq as _;

use crate::hex;
use crate::random::RandomSource;

/// Number of decimal digits in a code (S-03).
pub const CODE_DIGITS: usize = 8;

/// Pending-auth record lifetime — also the code expiry (S-03: 10 min).
pub const PENDING_TTL: Duration = Duration::minutes(10);

/// Wrong-code budget per pending record; hitting it kills the record, never the account.
pub const MAX_ATTEMPTS: u32 = 5;

/// Minimum spacing between two OTP requests for the same email (S-03 resend policy).
pub const RESEND_INTERVAL: Duration = Duration::seconds(60);

/// Number of random bytes in a pending-auth id (opaque 128-bit id, hex-encoded).
const PENDING_ID_BYTES: usize = 16;

/// Server-side pending-auth record, stored as JSON in KV under `otp:pending:{id}`.
///
/// The wrong-attempt budget deliberately does **not** live here: it is an atomic KV counter
/// under [`attempt_key`], because a read-modify-write of this record would let concurrent
/// verifications share one increment and blow straight through [`MAX_ATTEMPTS`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingAuth {
    /// Normalized (lowercase) email the flow is bound to.
    pub email: String,
    /// `HMAC-SHA-256(code, pepper)` hex — the code itself is never stored (S-03).
    pub code_hmac: String,
    /// Issue time (UTC); expiry is `created_at + PENDING_TTL`.
    pub created_at: DateTime<Utc>,
    /// Id of the record this one replaced, when the request was a resend.
    pub resend_of: Option<String>,
}

/// Generates an 8-digit code from the CSPRNG, bias-free.
pub fn generate_code(rng: &dyn RandomSource) -> String {
    // Rejection sampling: 4.2e9 is the largest multiple of 1e8 below 2^32, so a uniform u32
    // below that bound reduces to a uniform 8-digit number.
    const BOUND: u32 = 4_200_000_000;
    loop {
        let mut buf = [0u8; 4];
        rng.fill(&mut buf);
        let draw = u32::from_be_bytes(buf);
        if draw < BOUND {
            return format!("{:08}", draw % 100_000_000);
        }
    }
}

/// Mints an opaque 128-bit pending-auth id (32 hex chars).
pub fn generate_pending_id(rng: &dyn RandomSource) -> String {
    let mut buf = [0u8; PENDING_ID_BYTES];
    rng.fill(&mut buf);
    hex(&buf)
}

/// The storage form of a code: `HMAC-SHA-256(code, pepper)` hex (S-03).
pub fn code_hmac(code: &str, pepper: &[u8]) -> String {
    let mut mac = Hmac::<Sha256>::new_from_slice(pepper).expect("HMAC accepts any key length");
    mac.update(code.as_bytes());
    hex(&mac.finalize().into_bytes())
}

/// Constant-time check of a presented code against the stored HMAC hex.
pub fn verify_code(code: &str, pepper: &[u8], stored_hmac_hex: &str) -> bool {
    let computed = code_hmac(code, pepper);
    // Same-length hex strings — byte comparison in constant time.
    computed.as_bytes().ct_eq(stored_hmac_hex.as_bytes()).into()
}

/// KV key of a pending-auth record.
pub fn pending_key(pending_id: &str) -> String {
    format!("otp:pending:{pending_id}")
}

/// KV key of the atomic wrong-attempt counter for a pending record (S-03: ≤5 per code).
///
/// Separate from the record so the budget can be spent with a single atomic increment
/// ([`pub_core::traits::Kv::incr`]) *before* the code is compared — parallel guesses each
/// consume their own attempt instead of racing over one snapshot.
pub fn attempt_key(pending_id: &str) -> String {
    format!("otp:attempts:{pending_id}")
}

/// KV key tracking the latest pending record per email (resend throttle + invalidation).
pub fn last_request_key(email: &str) -> String {
    format!("otp:last:{email}")
}

/// Server-side record of an email change awaiting confirmation
/// ([S-03.b](../../../docs/security.md#1-authentication)), stored as JSON in KV under
/// `email_change:pending:{id}`.
///
/// Deliberately a **distinct type and a distinct key space** from [`PendingAuth`] rather than a
/// nullable `user_id` on that one. The two records authorize different things — one opens a
/// session for whoever holds the code, the other moves an address on an account that is already
/// signed in — and a single struct with an optional field is one `if` away from a code minted for
/// one purpose being redeemed for the other.
///
/// It carries the account it belongs to, so redemption can require that the *same* account
/// presents it: a code lifted from an inbox is worthless without the session that asked for it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingEmailChange {
    /// The account this change belongs to, as a string (the crate does not depend on ids).
    pub user_id: String,
    /// Normalized (lowercase) address the account would move to.
    pub email: String,
    /// `HMAC-SHA-256(code, pepper)` hex — the code itself is never stored (S-03).
    pub code_hmac: String,
    /// Issue time (UTC); expiry is `created_at + PENDING_TTL`.
    pub created_at: DateTime<Utc>,
}

/// KV key of a pending email-change record.
pub fn email_change_key(pending_id: &str) -> String {
    format!("email_change:pending:{pending_id}")
}

/// KV key of the atomic wrong-attempt counter for an email change (S-03.a's budget, same shape).
pub fn email_change_attempt_key(pending_id: &str) -> String {
    format!("email_change:attempts:{pending_id}")
}

/// KV key tracking the latest email-change request **per account** (resend throttle).
///
/// Keyed on the account rather than on the target address on purpose: the address is chosen by
/// the requester, so a per-address key would let one account start an unbounded number of
/// changes by varying it. The address still has a bound — it shares the per-address hourly
/// budget with sign-in codes, because that budget is about somebody's inbox rather than about
/// which flow reached it.
pub fn email_change_last_request_key(user_id: &str) -> String {
    format!("email_change:last:{user_id}")
}

#[cfg(test)]
mod tests {
    use chrono::TimeZone as _;

    use super::*;
    use crate::random::{FixedRandom, OsRandom};

    #[test]
    fn code_is_exactly_eight_digits() {
        for _ in 0..64 {
            let code = generate_code(&OsRandom);
            assert_eq!(code.len(), CODE_DIGITS);
            assert!(code.bytes().all(|b| b.is_ascii_digit()), "non-digit in {code:?}");
        }
    }

    #[test]
    fn code_is_deterministic_under_injected_randomness() {
        // 0x00000001 → 1 → zero-padded.
        let rng = FixedRandom::new(vec![0, 0, 0, 1]);
        assert_eq!(generate_code(&rng), "00000001");
    }

    #[test]
    fn rejection_sampling_skips_biased_draws() {
        // First draw 0xFFFFFFFF (≥ 4.2e9, rejected), second draw 0x00000000 (accepted).
        let rng = FixedRandom::new(vec![0xFF, 0xFF, 0xFF, 0xFF, 0, 0, 0, 0]);
        assert_eq!(generate_code(&rng), "00000000");
    }

    #[test]
    fn pending_id_is_32_hex_chars() {
        let id = generate_pending_id(&OsRandom);
        assert_eq!(id.len(), 32);
        assert!(id.bytes().all(|b| b.is_ascii_hexdigit()));
        assert_ne!(id, generate_pending_id(&OsRandom));
    }

    #[test]
    fn hmac_is_sha256_hex_and_pepper_dependent() {
        let a = code_hmac("12345678", b"pepper-a");
        assert_eq!(a.len(), 64);
        assert!(a.bytes().all(|b| b.is_ascii_hexdigit()));
        // Same code, same pepper → stable; different pepper or code → different.
        assert_eq!(a, code_hmac("12345678", b"pepper-a"));
        assert_ne!(a, code_hmac("12345678", b"pepper-b"));
        assert_ne!(a, code_hmac("12345679", b"pepper-a"));
    }

    #[test]
    fn verify_code_accepts_match_and_rejects_everything_else() {
        let stored = code_hmac("31337000", b"pepper");
        assert!(verify_code("31337000", b"pepper", &stored));
        assert!(!verify_code("31337001", b"pepper", &stored));
        assert!(!verify_code("31337000", b"other-pepper", &stored));
        assert!(!verify_code("31337000", b"pepper", "deadbeef"));
        assert!(!verify_code("", b"pepper", &stored));
    }

    #[test]
    fn pending_auth_round_trips_through_json() {
        let record = PendingAuth {
            email: "dev@corp.com".to_owned(),
            code_hmac: code_hmac("00112233", b"p"),
            created_at: Utc.with_ymd_and_hms(2026, 8, 6, 12, 0, 0).unwrap(),
            resend_of: Some("aabbccdd".repeat(4)),
        };
        let json = serde_json::to_string(&record).unwrap();
        assert_eq!(serde_json::from_str::<PendingAuth>(&json).unwrap(), record);
    }

    #[test]
    fn s03_pending_record_never_carries_the_code_or_the_budget() {
        // The record is the only thing an attacker with KV read access sees: no plaintext
        // code, and no attempt counter they could rewind by racing a write.
        let record = PendingAuth {
            email: "dev@corp.com".to_owned(),
            code_hmac: code_hmac("31337000", b"pepper"),
            created_at: Utc.with_ymd_and_hms(2026, 8, 6, 12, 0, 0).unwrap(),
            resend_of: None,
        };
        let json = serde_json::to_string(&record).unwrap();
        assert!(!json.contains("31337000"), "code leaked into the stored record: {json}");
        assert!(!json.contains("attempts"), "the budget must live in the atomic counter: {json}");
    }

    #[test]
    fn attempt_key_is_bound_to_one_pending_record() {
        assert_eq!(attempt_key("abc"), "otp:attempts:abc");
        assert_ne!(attempt_key("abc"), attempt_key("abd"));
        assert_ne!(attempt_key("abc"), pending_key("abc"));
    }

    #[test]
    fn policy_constants_match_s03() {
        assert_eq!(CODE_DIGITS, 8);
        assert_eq!(PENDING_TTL, Duration::minutes(10));
        assert_eq!(MAX_ATTEMPTS, 5);
        assert_eq!(RESEND_INTERVAL, Duration::seconds(60));
    }
}
