//! Authentication and credential management (docs/security.md; decisions 03, 12, 13).
//!
//! Modules:
//! - [`jwt`] — Ed25519 access-token keyring with `kid` rotation (S-07);
//! - [`otp`] — email OTP codes: CSPRNG generation, peppered HMAC storage form, pending-auth
//!   records (S-03);
//! - [`token`] — CLI/API token format `<prefix>_<base62×30><crc32-base62×6>` (S-13,
//!   decisions 13/17);
//! - [`ratelimit`] — fixed-window counters over the [`pub_core::traits::Kv`] seam (S-24);
//! - [`flows`] — request/verify/refresh/logout orchestrations over the core traits;
//! - [`random`] — the CSPRNG seam ([`random::RandomSource`]) so tests inject determinism.
//!
//! OIDC and TOTP land in later slices; the flows are shaped so they plug into the same
//! [`flows::AuthService`] without reshaping the API layer. Two credential planes (web
//! sessions vs CLI tokens) are never mixed.

pub mod flows;
pub mod jwt;
pub mod otp;
pub mod random;
pub mod ratelimit;
pub mod token;

/// Lowercase hex encoding of arbitrary bytes (digest storage forms, opaque ids).
pub(crate) fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(char::from_digit(u32::from(byte >> 4), 16).expect("nibble < 16"));
        out.push(char::from_digit(u32::from(byte & 0x0F), 16).expect("nibble < 16"));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::hex;

    #[test]
    fn hex_encodes_lowercase() {
        assert_eq!(hex(&[0x00, 0xAB, 0xFF]), "00abff");
        assert_eq!(hex(&[]), "");
    }
}
