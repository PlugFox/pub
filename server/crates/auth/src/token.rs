//! CLI/API token format (S-13, decisions 13 & 17): `<prefix><base62×30><crc32-base62×6>`.
//!
//! The default prefix is `pub_` and is instance-configurable. The 30 base62 chars carry
//! ~178 bits of CSPRNG entropy; the trailing 6 base62 chars are the CRC32 of the random part,
//! which lets secret scanners and the server itself reject damaged or fabricated strings
//! **offline** — no database roundtrip, no oracle. Storage is SHA-256 hex plus a first-8-chars
//! display hint; the plaintext is shown exactly once at mint time.

use pub_core::{Error, Result};
use sha2::{Digest as _, Sha256};

use crate::hex;
use crate::random::RandomSource;

/// Default token prefix (decision 17; instance-configurable).
pub const DEFAULT_PREFIX: &str = "pub_";

/// Number of random base62 characters.
pub const RANDOM_LEN: usize = 30;

/// Number of base62 characters encoding the CRC32 checksum.
pub const CHECKSUM_LEN: usize = 6;

/// Length of the display hint stored for the token list UI (S-13).
pub const HINT_LEN: usize = 8;

/// Base62 alphabet in ASCII order (digits, uppercase, lowercase).
const BASE62: &[u8; 62] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

/// A freshly minted token: the show-once secret plus everything the server persists.
///
/// [`Debug`] is hand-written: `secret` is the live credential and show-once by contract, so it
/// must not be reachable through a `{:?}` in a log line or a panic message (S-13/S-25). The
/// display hint is safe — it is exactly what the token list already shows.
#[derive(Clone, PartialEq, Eq)]
pub struct MintedToken {
    /// The full plaintext secret — returned to the user once, never stored (S-13).
    pub secret: String,
    /// SHA-256 hex of the plaintext; the at-rest form and the lookup key.
    pub hash: String,
    /// First [`HINT_LEN`] characters of the plaintext, for the token list UI.
    pub display_hint: String,
}

impl std::fmt::Debug for MintedToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MintedToken")
            .field("secret", &"<redacted>")
            .field("hash", &self.hash)
            .field("display_hint", &self.display_hint)
            .finish()
    }
}

/// Mints a token under `prefix` (e.g. `pub_`) from the CSPRNG.
pub fn mint(prefix: &str, rng: &dyn RandomSource) -> MintedToken {
    let random: String = random_base62(RANDOM_LEN, rng);
    let checksum = encode_crc(crc32fast::hash(random.as_bytes()));
    let secret = format!("{prefix}{random}{checksum}");
    MintedToken { hash: sha256_hex(&secret), display_hint: secret.chars().take(HINT_LEN).collect(), secret }
}

/// Offline validation of a presented secret: prefix, length, charset, and CRC32 checksum.
///
/// Rejections are [`Error::Unauthorized`] — the pub auth path treats a malformed token
/// exactly like an unknown one (uniform 401, S-14), and no variant reveals which check
/// tripped to the caller. This runs before any database lookup.
pub fn validate(secret: &str, prefix: &str) -> Result<()> {
    let rejected = || Error::Unauthorized { message: "malformed token".into() };
    let body = secret.strip_prefix(prefix).ok_or_else(rejected)?;
    if body.len() != RANDOM_LEN + CHECKSUM_LEN {
        return Err(rejected());
    }
    if !body.bytes().all(|b| BASE62.contains(&b)) {
        return Err(rejected());
    }
    let (random, checksum) = body.split_at(RANDOM_LEN);
    let expected = decode_crc(checksum).ok_or_else(rejected)?;
    if crc32fast::hash(random.as_bytes()) != expected {
        return Err(rejected());
    }
    Ok(())
}

/// SHA-256 hex of a secret — the at-rest form for CLI tokens and refresh tokens (S-08/S-13).
pub fn sha256_hex(secret: &str) -> String {
    hex(&Sha256::digest(secret.as_bytes()))
}

/// Uniform random base62 string of `len` characters (rejection sampling, bias-free).
fn random_base62(len: usize, rng: &dyn RandomSource) -> String {
    // 248 is the largest multiple of 62 below 256: bytes above it would bias the low values.
    const BOUND: u8 = 248;
    let mut out = String::with_capacity(len);
    let mut buf = [0u8; 64];
    while out.len() < len {
        rng.fill(&mut buf);
        for &byte in &buf {
            if byte < BOUND && out.len() < len {
                out.push(BASE62[usize::from(byte % 62)] as char);
            }
        }
    }
    out
}

/// Fixed-width big-endian base62 encoding of a CRC32 value.
fn encode_crc(crc: u32) -> String {
    let mut out = [b'0'; CHECKSUM_LEN];
    let mut rest = u64::from(crc);
    for slot in out.iter_mut().rev() {
        *slot = BASE62[(rest % 62) as usize];
        rest /= 62;
    }
    String::from_utf8(out.to_vec()).expect("base62 alphabet is ASCII")
}

/// Decodes a 6-char base62 checksum; `None` when it overflows u32 (impossible for genuine
/// checksums, so an overflow is a fabricated string).
fn decode_crc(checksum: &str) -> Option<u32> {
    let mut value: u64 = 0;
    for byte in checksum.bytes() {
        let digit = BASE62.iter().position(|&c| c == byte)? as u64;
        value = value * 62 + digit;
    }
    u32::try_from(value).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::random::{FixedRandom, OsRandom};

    #[test]
    fn minted_token_has_documented_shape() {
        let minted = mint(DEFAULT_PREFIX, &OsRandom);
        assert_eq!(minted.secret.len(), DEFAULT_PREFIX.len() + RANDOM_LEN + CHECKSUM_LEN);
        assert!(minted.secret.starts_with("pub_"));
        assert!(minted.secret["pub_".len()..].bytes().all(|b| BASE62.contains(&b)));
        assert_eq!(minted.display_hint, &minted.secret[..HINT_LEN]);
        assert_eq!(minted.hash, sha256_hex(&minted.secret));
        assert_eq!(minted.hash.len(), 64);
        validate(&minted.secret, DEFAULT_PREFIX).expect("fresh mint must validate offline");
    }

    #[test]
    fn mint_is_deterministic_under_injected_randomness() {
        let a = mint(DEFAULT_PREFIX, &FixedRandom::new(vec![0, 1, 2, 3, 4, 5]));
        let b = mint(DEFAULT_PREFIX, &FixedRandom::new(vec![0, 1, 2, 3, 4, 5]));
        assert_eq!(a, b);
    }

    #[test]
    fn two_mints_differ() {
        assert_ne!(mint(DEFAULT_PREFIX, &OsRandom).secret, mint(DEFAULT_PREFIX, &OsRandom).secret);
    }

    #[test]
    fn checksum_tamper_is_rejected() {
        let minted = mint(DEFAULT_PREFIX, &OsRandom);
        let mut bytes = minted.secret.into_bytes();
        // Flip the final checksum character to a different base62 char.
        let last = bytes.last_mut().unwrap();
        *last = if *last == b'0' { b'1' } else { b'0' };
        let tampered = String::from_utf8(bytes).unwrap();
        assert_eq!(validate(&tampered, DEFAULT_PREFIX).unwrap_err().code(), "unauthorized");
    }

    #[test]
    fn random_part_tamper_is_rejected() {
        let minted = mint(DEFAULT_PREFIX, &OsRandom);
        let mut bytes = minted.secret.into_bytes();
        let target = DEFAULT_PREFIX.len(); // first char of the random part
        bytes[target] = if bytes[target] == b'A' { b'B' } else { b'A' };
        let tampered = String::from_utf8(bytes).unwrap();
        assert_eq!(validate(&tampered, DEFAULT_PREFIX).unwrap_err().code(), "unauthorized");
    }

    #[test]
    fn wrong_length_is_rejected() {
        let minted = mint(DEFAULT_PREFIX, &OsRandom);
        let short = &minted.secret[..minted.secret.len() - 1];
        assert!(validate(short, DEFAULT_PREFIX).is_err());
        let long = format!("{}0", minted.secret);
        assert!(validate(&long, DEFAULT_PREFIX).is_err());
        assert!(validate("pub_", DEFAULT_PREFIX).is_err());
        assert!(validate("", DEFAULT_PREFIX).is_err());
    }

    #[test]
    fn foreign_prefix_is_rejected() {
        let minted = mint("acme_", &OsRandom);
        assert!(validate(&minted.secret, "acme_").is_ok());
        assert!(validate(&minted.secret, DEFAULT_PREFIX).is_err(), "acme_ token must not pass as pub_");
        let ours = mint(DEFAULT_PREFIX, &OsRandom);
        assert!(validate(&ours.secret, "acme_").is_err());
    }

    #[test]
    fn bad_charset_is_rejected() {
        let minted = mint(DEFAULT_PREFIX, &OsRandom);
        let mut bytes = minted.secret.into_bytes();
        bytes[DEFAULT_PREFIX.len() + 3] = b'!';
        let bad = String::from_utf8(bytes).unwrap();
        assert!(validate(&bad, DEFAULT_PREFIX).is_err());
    }

    #[test]
    fn crc_base62_round_trips_and_pads() {
        for crc in [0u32, 1, 61, 62, u32::MAX, 0xDEAD_BEEF] {
            let encoded = encode_crc(crc);
            assert_eq!(encoded.len(), CHECKSUM_LEN);
            assert_eq!(decode_crc(&encoded), Some(crc), "round trip failed for {crc}");
        }
        // 'zzzzzz' = 62^6 - 1 > u32::MAX — overflow means fabricated input.
        assert_eq!(decode_crc("zzzzzz"), None);
        assert_eq!(decode_crc("!!!!!!"), None);
    }
}
