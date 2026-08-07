//! TOTP second factor primitives (S-05): RFC 6238 codes, KEK sealing, recovery codes.
//!
//! - Codes: HMAC-SHA-1 dynamic truncation (RFC 4226 §5.3), 30-second steps, 6 digits,
//!   160-bit seed. Verification tolerates ±1 step of skew but only ever accepts a step
//!   **strictly above** the stored replay floor — the floor advance is an atomic
//!   compare-and-set in the credential repository.
//! - Sealing: the seed is stored AES-256-GCM-encrypted with the boot KEK
//!   (`nonce ‖ ciphertext‖tag`); the plaintext seed exists only transiently in memory.
//! - Recovery codes: 10 single-use codes (`XXXXX-XXXXX`, Crockford-style alphabet without
//!   look-alikes), argon2id-hashed at rest, shown exactly once at enrollment.

use argon2::Argon2;
use argon2::password_hash::{PasswordHash, PasswordHasher as _, PasswordVerifier as _, SaltString};
use chrono::{DateTime, Duration, Utc};
use hmac::{Hmac, Mac as _};
use pub_core::{Error, Result};
use sha1::Sha1;
use subtle::ConstantTimeEq as _;

use crate::random::RandomSource;

/// TOTP seed length in bytes (S-05: 160-bit).
pub const SECRET_BYTES: usize = 20;

/// Decimal digits per code (RFC 6238 default).
pub const CODE_DIGITS: u32 = 6;

/// Time-step length (RFC 6238 default).
pub const STEP_SECONDS: i64 = 30;

/// Accepted clock skew, in steps, on either side of "now" (S-05: ±1).
pub const SKEW_STEPS: i64 = 1;

/// Number of recovery codes issued at enrollment (S-05: 8–10; we issue 10).
pub const RECOVERY_CODES: usize = 10;

/// Failed TOTP / recovery / step-up verifications tolerated per pending attempt before
/// exponential backoff kicks in (S-05/S-24).
pub const MAX_MFA_FAILURES: u64 = 5;

/// Backoff ceiling — exponential growth stops here (10 minutes).
pub const MFA_BACKOFF_CAP_SECS: u64 = 600;

/// Lifetime of a pending enrollment (KV record between `enroll` and `confirm`).
pub const ENROLL_TTL: Duration = Duration::minutes(15);

/// Lifetime of a pending-MFA login handle (between the first factor and the TOTP step).
pub const MFA_PENDING_TTL: Duration = Duration::minutes(5);

/// Recovery-code alphabet: Crockford base32 without the look-alikes I/L/O/U.
const RECOVERY_ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/// RFC 4648 base32 alphabet (no padding) — the `otpauth://` secret encoding.
const BASE32_ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/// Generates a fresh 160-bit TOTP seed.
pub fn generate_secret(rng: &dyn RandomSource) -> Vec<u8> {
    let mut seed = vec![0u8; SECRET_BYTES];
    rng.fill(&mut seed);
    seed
}

/// The RFC 6238 time-step for an instant.
pub fn step_at(now: DateTime<Utc>) -> i64 {
    now.timestamp().div_euclid(STEP_SECONDS)
}

/// The 6-digit code for `secret` at time-step `step` (RFC 4226 dynamic truncation over
/// HMAC-SHA-1 of the big-endian step counter).
pub fn code_at(secret: &[u8], step: i64) -> String {
    let mut mac = <Hmac<Sha1> as hmac::KeyInit>::new_from_slice(secret).expect("HMAC accepts any key length");
    mac.update(&step.to_be_bytes());
    let digest = mac.finalize().into_bytes();
    let offset = usize::from(digest[19] & 0x0F);
    let binary = (u32::from(digest[offset]) & 0x7F) << 24
        | u32::from(digest[offset + 1]) << 16
        | u32::from(digest[offset + 2]) << 8
        | u32::from(digest[offset + 3]);
    format!("{:06}", binary % 10u32.pow(CODE_DIGITS))
}

/// Verifies `code` against `secret` around `now` with ±[`SKEW_STEPS`] tolerance, honouring
/// the replay floor: only steps **strictly above** `last_step` are candidates (S-05).
///
/// Returns the accepted step so the caller can commit it atomically, or `None` on any
/// mismatch. Every candidate is compared in constant time and all candidates are always
/// evaluated — no early exit leaks which step matched.
pub fn verify_at(secret: &[u8], code: &str, now: DateTime<Utc>, last_step: Option<i64>) -> Option<i64> {
    let current = step_at(now);
    let floor = last_step.unwrap_or(i64::MIN);
    let mut accepted = None;
    for candidate in (current - SKEW_STEPS)..=(current + SKEW_STEPS) {
        let expected = code_at(secret, candidate);
        let matches: bool = expected.as_bytes().ct_eq(code.as_bytes()).into();
        if matches && candidate > floor && accepted.is_none() {
            accepted = Some(candidate);
        }
    }
    accepted
}

/// RFC 4648 base32 (uppercase, no padding) — authenticator apps expect this encoding.
pub fn base32_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(5) * 8);
    for chunk in bytes.chunks(5) {
        let mut buf = [0u8; 5];
        buf[..chunk.len()].copy_from_slice(chunk);
        let value = u64::from(buf[0]) << 32
            | u64::from(buf[1]) << 24
            | u64::from(buf[2]) << 16
            | u64::from(buf[3]) << 8
            | u64::from(buf[4]);
        let quintets = (chunk.len() * 8).div_ceil(5);
        for slot in 0..quintets {
            let shift = 35 - slot * 5;
            out.push(BASE32_ALPHABET[((value >> shift) & 0x1F) as usize] as char);
        }
    }
    out
}

/// Decodes RFC 4648 base32 (case-insensitive, no padding). `None` on foreign characters.
pub fn base32_decode(text: &str) -> Option<Vec<u8>> {
    let mut bits: u64 = 0;
    let mut bit_count = 0u32;
    let mut out = Vec::with_capacity(text.len() * 5 / 8);
    for ch in text.bytes() {
        let upper = ch.to_ascii_uppercase();
        let value = BASE32_ALPHABET.iter().position(|&c| c == upper)? as u64;
        bits = (bits << 5) | value;
        bit_count += 5;
        if bit_count >= 8 {
            bit_count -= 8;
            out.push((bits >> bit_count) as u8);
        }
    }
    Some(out)
}

/// The `otpauth://totp/...` provisioning URL (issuer + account label, standard parameters).
pub fn otpauth_url(issuer: &str, account: &str, secret: &[u8]) -> String {
    let encode = |raw: &str| {
        // Minimal percent-encoding for the label/query: keep unreserved characters only.
        let mut out = String::with_capacity(raw.len());
        for byte in raw.bytes() {
            match byte {
                b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => out.push(byte as char),
                other => out.push_str(&format!("%{other:02X}")),
            }
        }
        out
    };
    format!(
        "otpauth://totp/{issuer}:{account}?secret={secret}&issuer={issuer}&algorithm=SHA1&digits={digits}&period={period}",
        issuer = encode(issuer),
        account = encode(account),
        secret = base32_encode(secret),
        digits = CODE_DIGITS,
        period = STEP_SECONDS,
    )
}

/// KEK sealing for the TOTP seed at rest (S-05) — the shared AEAD of [`crate::secretbox`].
///
/// Re-exported here rather than reimplemented: the settings table seals the runtime SMTP
/// password with the same construction (S-26), and two copies of an AEAD framing is how two
/// nonce policies appear.
pub use crate::secretbox::{open, seal};

/// Generates one `XXXXX-XXXXX` recovery code (50 bits, look-alike-free alphabet).
pub fn generate_recovery_code(rng: &dyn RandomSource) -> String {
    // Rejection sampling: bytes ≥ 224 would bias the low alphabet slots.
    const BOUND: u8 = 224;
    let mut chars = Vec::with_capacity(10);
    let mut buf = [0u8; 16];
    while chars.len() < 10 {
        rng.fill(&mut buf);
        for &byte in &buf {
            if byte < BOUND && chars.len() < 10 {
                chars.push(RECOVERY_ALPHABET[usize::from(byte % 32)]);
            }
        }
    }
    let text: String = chars.iter().map(|&b| b as char).collect();
    format!("{}-{}", &text[..5], &text[5..])
}

/// Normalizes a user-typed recovery code: uppercase, dashes/spaces stripped.
pub fn normalize_recovery_code(raw: &str) -> String {
    raw.chars().filter(|c| !matches!(c, '-' | ' ')).map(|c| c.to_ascii_uppercase()).collect()
}

/// argon2id PHC hash of a (normalized) recovery code (S-05).
pub fn hash_recovery_code(code: &str, rng: &dyn RandomSource) -> Result<String> {
    let mut salt_bytes = [0u8; 16];
    rng.fill(&mut salt_bytes);
    let salt = SaltString::encode_b64(&salt_bytes)
        .map_err(|err| Error::Internal { message: format!("recovery salt encoding failed: {err}") })?;
    Argon2::default()
        .hash_password(normalize_recovery_code(code).as_bytes(), &salt)
        .map(|hash| hash.to_string())
        .map_err(|err| Error::Internal { message: format!("recovery code hashing failed: {err}") })
}

/// Verifies a (raw, user-typed) recovery code against a stored PHC string.
pub fn verify_recovery_code(code: &str, phc: &str) -> bool {
    let Ok(parsed) = PasswordHash::new(phc) else {
        return false;
    };
    Argon2::default().verify_password(normalize_recovery_code(code).as_bytes(), &parsed).is_ok()
}

/// KV key of a pending enrollment (sealed seed awaiting confirmation).
pub fn enroll_key(user: pub_core::UserId) -> String {
    format!("totp:enroll:{user}")
}

/// KV key of a pending-MFA login handle (first factor passed, TOTP outstanding).
pub fn mfa_pending_key(mfa_token: &str) -> String {
    format!("mfa:pending:{mfa_token}")
}

/// KV key of the failed-attempt counter for one MFA scope (pending login, sid, enrollment).
pub fn mfa_attempt_key(scope: &str) -> String {
    format!("mfa:attempts:{scope}")
}

/// KV key of the not-before mark once a scope enters backoff.
pub fn mfa_backoff_key(scope: &str) -> String {
    format!("mfa:backoff:{scope}")
}

/// KV key of the step-up freshness mark for a session (S-06).
pub fn step_up_key(sid: pub_core::SessionId) -> String {
    format!("stepup:{sid}")
}

/// Backoff delay after the `failures`-th failed attempt: nothing during the free budget,
/// then 2 s doubling per failure up to [`MFA_BACKOFF_CAP_SECS`] (S-05).
pub fn backoff_after(failures: u64) -> Option<u64> {
    if failures < MAX_MFA_FAILURES {
        return None;
    }
    let exponent = (failures - MAX_MFA_FAILURES).min(31) as u32;
    Some((2u64 << exponent).min(MFA_BACKOFF_CAP_SECS))
}

#[cfg(test)]
mod tests {
    use chrono::TimeZone as _;

    use super::*;
    use crate::random::{FixedRandom, OsRandom};

    fn t0() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 8, 6, 12, 0, 0).unwrap()
    }

    #[test]
    fn rfc6238_sha1_reference_vectors() {
        // RFC 6238 Appendix B, the SHA-1 rows: seed "12345678901234567890", 8 digits. Our
        // codes are the low 6 digits of the same dynamic truncation.
        let seed = b"12345678901234567890";
        for (unix, expected8) in
            [(59, "94287082"), (1_111_111_109, "07081804"), (1_234_567_890, "89005924"), (2_000_000_000, "69279037")]
        {
            let step = unix / 30;
            assert_eq!(code_at(seed, step), &expected8[2..], "unix {unix}");
        }
    }

    #[test]
    fn s05_verify_accepts_pm1_skew_and_rejects_pm2() {
        let secret = generate_secret(&OsRandom);
        let now = t0();
        let current = step_at(now);
        for (delta, ok) in [(-2i64, false), (-1, true), (0, true), (1, true), (2, false)] {
            let code = code_at(&secret, current + delta);
            let verdict = verify_at(&secret, &code, now, None);
            assert_eq!(verdict.is_some(), ok, "delta {delta}");
            if let Some(step) = verdict {
                assert_eq!(step, current + delta);
            }
        }
    }

    #[test]
    fn s05_replay_floor_blocks_same_and_older_steps() {
        let secret = generate_secret(&OsRandom);
        let now = t0();
        let current = step_at(now);
        let code = code_at(&secret, current);
        assert_eq!(verify_at(&secret, &code, now, Some(current)), None, "same step is a replay");
        assert_eq!(verify_at(&secret, &code, now, Some(current + 5)), None, "older step is a replay");
        assert_eq!(verify_at(&secret, &code, now, Some(current - 1)), Some(current));
        // The floor never blocks a *newer* matching step.
        let next = code_at(&secret, current + 1);
        assert_eq!(verify_at(&secret, &next, now, Some(current)), Some(current + 1));
    }

    #[test]
    fn verify_rejects_wrong_and_malformed_codes() {
        let secret = generate_secret(&OsRandom);
        let good = code_at(&secret, step_at(t0()));
        let bad = if good == "000000" { "000001" } else { "000000" };
        assert_eq!(verify_at(&secret, bad, t0(), None), None);
        assert_eq!(verify_at(&secret, "", t0(), None), None);
        assert_eq!(verify_at(&secret, "12345", t0(), None), None);
        assert_eq!(verify_at(&secret, &good[..5], t0(), None), None);
    }

    #[test]
    fn base32_round_trips_rfc4648_vectors() {
        // RFC 4648 §10 test vectors, padding stripped.
        for (raw, encoded) in
            [("", ""), ("f", "MY"), ("fo", "MZXQ"), ("foo", "MZXW6"), ("foob", "MZXW6YQ"), ("fooba", "MZXW6YTB")]
        {
            assert_eq!(base32_encode(raw.as_bytes()), encoded);
            assert_eq!(base32_decode(encoded).unwrap(), raw.as_bytes());
        }
        assert_eq!(base32_decode("mzxw6"), Some(b"foo".to_vec()), "decoding is case-insensitive");
        assert_eq!(base32_decode("1!"), None);
        let seed = generate_secret(&OsRandom);
        assert_eq!(base32_decode(&base32_encode(&seed)).unwrap(), seed);
    }

    #[test]
    fn otpauth_url_carries_the_standard_parameters() {
        let url = otpauth_url("Pub", "dev@corp.com", b"12345678901234567890");
        assert!(url.starts_with("otpauth://totp/Pub:dev%40corp.com?secret="));
        assert!(url.contains("issuer=Pub"));
        assert!(url.contains("algorithm=SHA1"));
        assert!(url.contains("digits=6"));
        assert!(url.contains("period=30"));
        assert!(url.contains(&format!("secret={}", base32_encode(b"12345678901234567890"))));
    }

    #[test]
    fn s05_seal_open_round_trip_and_tamper_rejection() {
        let kek = [7u8; 32];
        let seed = generate_secret(&OsRandom);
        let sealed = seal(&kek, &OsRandom, &seed).unwrap();
        // The ciphertext never contains the seed and two seals of one seed differ (nonce).
        assert!(!sealed.windows(seed.len()).any(|w| w == seed), "seed leaked into ciphertext");
        assert_ne!(sealed, seal(&kek, &OsRandom, &seed).unwrap());
        assert_eq!(open(&kek, &sealed).unwrap(), seed);

        // Bit-flip anywhere fails authentication.
        let mut tampered = sealed.clone();
        *tampered.last_mut().unwrap() ^= 1;
        assert!(open(&kek, &tampered).is_err());
        // A foreign KEK fails too.
        assert!(open(&[8u8; 32], &sealed).is_err());
        // Truncated blobs are rejected, not panicked on.
        assert!(open(&kek, &sealed[..8]).is_err());
        // A wrong-size KEK is a config error.
        assert_eq!(seal(&[1u8; 16], &OsRandom, &seed).unwrap_err().code(), "config_invalid");
    }

    #[test]
    fn recovery_codes_have_the_documented_shape() {
        let code = generate_recovery_code(&OsRandom);
        assert_eq!(code.len(), 11);
        assert_eq!(code.as_bytes()[5], b'-');
        for half in code.split('-') {
            assert_eq!(half.len(), 5);
            assert!(half.bytes().all(|b| RECOVERY_ALPHABET.contains(&b)), "foreign char in {code}");
        }
        assert_ne!(generate_recovery_code(&OsRandom), generate_recovery_code(&OsRandom));
        // Deterministic under injected randomness.
        assert_eq!(generate_recovery_code(&FixedRandom::new(vec![0])), "00000-00000");
    }

    #[test]
    fn s05_recovery_hash_verifies_and_is_argon2id() {
        let code = generate_recovery_code(&OsRandom);
        let phc = hash_recovery_code(&code, &OsRandom).unwrap();
        assert!(phc.starts_with("$argon2id$"), "wrong algorithm: {phc}");
        assert!(!phc.contains(&normalize_recovery_code(&code)), "plaintext leaked into the hash");
        assert!(verify_recovery_code(&code, &phc));
        // Dashes, spaces, and case are forgiven on entry.
        assert!(verify_recovery_code(&code.to_ascii_lowercase().replace('-', " "), &phc));
        assert!(!verify_recovery_code("AAAAA-AAAAA", &phc));
        assert!(!verify_recovery_code(&code, "not-a-phc-string"));
    }

    #[test]
    fn s05_backoff_starts_after_the_budget_and_caps() {
        assert_eq!(backoff_after(0), None);
        assert_eq!(backoff_after(4), None);
        assert_eq!(backoff_after(5), Some(2));
        assert_eq!(backoff_after(6), Some(4));
        assert_eq!(backoff_after(7), Some(8));
        assert_eq!(backoff_after(13), Some(512));
        assert_eq!(backoff_after(14), Some(MFA_BACKOFF_CAP_SECS));
        assert_eq!(backoff_after(1000), Some(MFA_BACKOFF_CAP_SECS), "huge counters must not overflow");
    }

    #[test]
    fn policy_constants_match_s05() {
        assert_eq!(SECRET_BYTES * 8, 160);
        assert_eq!(CODE_DIGITS, 6);
        assert_eq!(STEP_SECONDS, 30);
        assert_eq!(SKEW_STEPS, 1);
        assert_eq!(RECOVERY_CODES, 10);
        assert_eq!(MAX_MFA_FAILURES, 5);
    }
}
