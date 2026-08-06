//! Ed25519 access-token keyring (S-07, decision 03).
//!
//! Config supplies one signing key and N additional verify keys — base64-encoded 32-byte
//! seeds, each under a `kid`. Rotation is `kid` overlap (S-27): a new signing key is deployed
//! while the previous kid stays in the verify set until every token signed with it has
//! expired.
//!
//! Verification is deliberately strict: the algorithm is pinned to `EdDSA` (a token saying
//! `none` or anything else is rejected before any key lookup), keys resolve **only** by `kid`
//! (no trial verification against every key), and `exp`/`iat` are enforced with a small skew.
//! Every failure maps to [`Error::Unauthorized`] — callers never learn which check failed.

use std::collections::{BTreeMap, HashMap};

use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD as B64, URL_SAFE_NO_PAD as B64URL};
use chrono::{DateTime, Duration, Utc};
use ed25519_dalek::{Signature, Signer as _, SigningKey, VerifyingKey};
use pub_core::{Error, OrgId, Result, SessionId, UserId};
use serde::{Deserialize, Serialize};

use crate::random::RandomSource;

/// Clock skew tolerated on `exp` and `iat` ("small skew" — S-07).
pub const CLOCK_SKEW: Duration = Duration::seconds(30);

/// The `kid` used by ephemeral dev keyrings ([`Keyring::ephemeral`]).
pub const EPHEMERAL_KID: &str = "dev-ephemeral";

/// Access-token claims (S-07: `sub`, `sid`, org role levels, timestamps — no other PII).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Claims {
    /// Authenticated user.
    pub sub: UserId,
    /// Web session backing this token; checked against the revoked-`sid` fast path (S-09).
    pub sid: SessionId,
    /// Org memberships as raw role levels (decision 19; wire names are a UI concern).
    pub orgs: BTreeMap<OrgId, u8>,
    /// Issued-at, seconds since the Unix epoch.
    pub iat: i64,
    /// Expiry, seconds since the Unix epoch. TTL ≤ 15 min (S-07), enforced by config.
    pub exp: i64,
}

/// JOSE header. Only `alg: EdDSA` with a known `kid` ever verifies.
#[derive(Debug, Serialize, Deserialize)]
struct Header<'a> {
    alg: &'a str,
    typ: &'a str,
    kid: &'a str,
}

/// The boot keyring: one signing key plus every key still allowed to verify.
pub struct Keyring {
    signing_kid: String,
    signing: SigningKey,
    verify: HashMap<String, VerifyingKey>,
}

impl std::fmt::Debug for Keyring {
    /// Kids only — key material never reaches logs (S-25).
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Keyring")
            .field("signing_kid", &self.signing_kid)
            .field("verify_kids", &self.verify_kids())
            .finish_non_exhaustive()
    }
}

impl Keyring {
    /// Builds a keyring from raw 32-byte seeds. The signing key verifies its own tokens;
    /// `verify_seeds` adds previous-generation keys for rotation overlap (S-27).
    ///
    /// Duplicate kids are a configuration error — silently shadowing a key would make
    /// "which key verified this token" ambiguous.
    pub fn new(signing_kid: &str, signing_seed: [u8; 32], verify_seeds: &[(String, [u8; 32])]) -> Result<Self> {
        if signing_kid.is_empty() {
            return Err(Error::Config { message: "jwt signing key kid must not be empty".into() });
        }
        let signing = SigningKey::from_bytes(&signing_seed);
        let mut verify = HashMap::new();
        verify.insert(signing_kid.to_owned(), signing.verifying_key());
        for (kid, seed) in verify_seeds {
            let key = SigningKey::from_bytes(seed).verifying_key();
            if verify.insert(kid.clone(), key).is_some() {
                return Err(Error::Config { message: format!("duplicate jwt kid '{kid}' in keyring") });
            }
        }
        Ok(Self { signing_kid: signing_kid.to_owned(), signing, verify })
    }

    /// Builds a keyring from base64-encoded 32-byte seeds (the config wire format, S-25).
    pub fn from_base64(signing_kid: &str, signing_seed_b64: &str, verify_keys: &[(String, String)]) -> Result<Self> {
        let signing_seed = decode_seed(signing_kid, signing_seed_b64)?;
        let verify_seeds = verify_keys
            .iter()
            .map(|(kid, seed)| Ok((kid.clone(), decode_seed(kid, seed)?)))
            .collect::<Result<Vec<_>>>()?;
        Self::new(signing_kid, signing_seed, &verify_seeds)
    }

    /// A fresh random keyring for dev mode — every restart invalidates all outstanding
    /// tokens. The caller is responsible for the loud warning.
    pub fn ephemeral(rng: &dyn RandomSource) -> Self {
        let mut seed = [0u8; 32];
        rng.fill(&mut seed);
        Self::new(EPHEMERAL_KID, seed, &[]).expect("static kid is valid")
    }

    /// The `kid` new tokens are signed with.
    pub fn signing_kid(&self) -> &str {
        &self.signing_kid
    }

    /// The kids this keyring accepts for verification (signing kid included).
    pub fn verify_kids(&self) -> Vec<&str> {
        let mut kids: Vec<&str> = self.verify.keys().map(String::as_str).collect();
        kids.sort_unstable();
        kids
    }

    /// Signs `claims` into a compact JWS, embedding the signing `kid`.
    pub fn sign(&self, claims: &Claims) -> Result<String> {
        let header = Header { alg: "EdDSA", typ: "JWT", kid: &self.signing_kid };
        let header_json = serde_json::to_vec(&header)
            .map_err(|err| Error::Internal { message: format!("jwt header serialization failed: {err}") })?;
        let claims_json = serde_json::to_vec(claims)
            .map_err(|err| Error::Internal { message: format!("jwt claims serialization failed: {err}") })?;
        let signing_input = format!("{}.{}", B64URL.encode(header_json), B64URL.encode(claims_json));
        let signature = self.signing.sign(signing_input.as_bytes());
        Ok(format!("{signing_input}.{}", B64URL.encode(signature.to_bytes())))
    }

    /// Verifies a compact JWS and returns its claims.
    ///
    /// Rejects — always as [`Error::Unauthorized`]: malformed tokens, `alg` other than
    /// `EdDSA` (incl. `none`), unknown or retired kids, invalid signatures, expired tokens,
    /// and `iat` in the future (both with [`CLOCK_SKEW`] tolerance).
    pub fn verify(&self, token: &str, now: DateTime<Utc>) -> Result<Claims> {
        let mut parts = token.split('.');
        let (Some(header_b64), Some(claims_b64), Some(sig_b64), None) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            return Err(unauthorized("malformed token"));
        };

        let header_json = B64URL.decode(header_b64).map_err(|_| unauthorized("malformed header"))?;
        let header: Header = serde_json::from_slice(&header_json).map_err(|_| unauthorized("malformed header"))?;
        // Pin the algorithm before touching any key material (S-07).
        if header.alg != "EdDSA" {
            return Err(unauthorized("algorithm not allowed"));
        }
        // Strict kid resolution: no kid, or a kid outside the boot keyring, never verifies.
        let key = self.verify.get(header.kid).ok_or_else(|| unauthorized("unknown kid"))?;

        let sig_bytes = B64URL.decode(sig_b64).map_err(|_| unauthorized("malformed signature"))?;
        let sig_array: [u8; 64] = sig_bytes.try_into().map_err(|_| unauthorized("malformed signature"))?;
        let signing_input = format!("{header_b64}.{claims_b64}");
        key.verify_strict(signing_input.as_bytes(), &Signature::from_bytes(&sig_array))
            .map_err(|_| unauthorized("signature mismatch"))?;

        let claims_json = B64URL.decode(claims_b64).map_err(|_| unauthorized("malformed claims"))?;
        let claims: Claims = serde_json::from_slice(&claims_json).map_err(|_| unauthorized("malformed claims"))?;

        let now_ts = now.timestamp();
        if now_ts > claims.exp + CLOCK_SKEW.num_seconds() {
            return Err(unauthorized("token expired"));
        }
        if claims.iat > now_ts + CLOCK_SKEW.num_seconds() {
            return Err(unauthorized("token issued in the future"));
        }
        Ok(claims)
    }
}

/// Decodes one base64 seed, insisting on exactly 32 bytes.
fn decode_seed(kid: &str, b64: &str) -> Result<[u8; 32]> {
    let bytes =
        B64.decode(b64).map_err(|_| Error::Config { message: format!("jwt key '{kid}' is not valid base64") })?;
    bytes.try_into().map_err(|_| Error::Config { message: format!("jwt key '{kid}' must decode to exactly 32 bytes") })
}

fn unauthorized(message: &str) -> Error {
    Error::Unauthorized { message: format!("invalid access token: {message}") }
}

#[cfg(test)]
mod tests {
    use chrono::TimeZone as _;

    use super::*;

    fn t0() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 8, 6, 12, 0, 0).unwrap()
    }

    fn keyring() -> Keyring {
        Keyring::new("k1", [7u8; 32], &[]).unwrap()
    }

    fn claims(now: DateTime<Utc>) -> Claims {
        Claims {
            sub: UserId::new(),
            sid: SessionId::new(),
            orgs: BTreeMap::from([(OrgId::new(), 250u8)]),
            iat: now.timestamp(),
            exp: (now + Duration::minutes(15)).timestamp(),
        }
    }

    #[test]
    fn sign_verify_round_trip_preserves_claims() {
        let ring = keyring();
        let original = claims(t0());
        let token = ring.sign(&original).unwrap();
        assert_eq!(token.split('.').count(), 3);
        let verified = ring.verify(&token, t0() + Duration::minutes(1)).unwrap();
        assert_eq!(verified, original);
    }

    #[test]
    fn header_embeds_the_signing_kid() {
        let token = keyring().sign(&claims(t0())).unwrap();
        let header_json = B64URL.decode(token.split('.').next().unwrap()).unwrap();
        let header: serde_json::Value = serde_json::from_slice(&header_json).unwrap();
        assert_eq!(header["kid"], "k1");
        assert_eq!(header["alg"], "EdDSA");
    }

    #[test]
    fn expired_token_is_rejected_beyond_skew_only() {
        let ring = keyring();
        let token = ring.sign(&claims(t0())).unwrap();
        let exp = t0() + Duration::minutes(15);
        // Inside the skew window still verifies…
        assert!(ring.verify(&token, exp + CLOCK_SKEW).is_ok());
        // …one second past it does not.
        let err = ring.verify(&token, exp + CLOCK_SKEW + Duration::seconds(1)).unwrap_err();
        assert_eq!(err.code(), "unauthorized");
    }

    #[test]
    fn future_iat_is_rejected_beyond_skew_only() {
        let ring = keyring();
        let token = ring.sign(&claims(t0())).unwrap();
        assert!(ring.verify(&token, t0() - CLOCK_SKEW).is_ok());
        let err = ring.verify(&token, t0() - CLOCK_SKEW - Duration::seconds(1)).unwrap_err();
        assert_eq!(err.code(), "unauthorized");
    }

    #[test]
    fn alg_none_is_rejected() {
        let ring = keyring();
        let header = B64URL.encode(br#"{"alg":"none","typ":"JWT","kid":"k1"}"#);
        let body = B64URL.encode(serde_json::to_vec(&claims(t0())).unwrap());
        for forged in [format!("{header}.{body}."), format!("{header}.{body}.{}", B64URL.encode([0u8; 64]))] {
            assert_eq!(ring.verify(&forged, t0()).unwrap_err().code(), "unauthorized");
        }
    }

    #[test]
    fn foreign_algorithms_are_rejected_even_with_known_kid() {
        let ring = keyring();
        let header = B64URL.encode(br#"{"alg":"HS256","typ":"JWT","kid":"k1"}"#);
        let body = B64URL.encode(serde_json::to_vec(&claims(t0())).unwrap());
        let forged = format!("{header}.{body}.{}", B64URL.encode([0u8; 32]));
        assert_eq!(ring.verify(&forged, t0()).unwrap_err().code(), "unauthorized");
    }

    #[test]
    fn unknown_and_missing_kid_are_rejected() {
        let ring = keyring();
        // Signed with a key the ring never had, under a foreign kid.
        let rogue = Keyring::new("rogue", [9u8; 32], &[]).unwrap();
        let token = rogue.sign(&claims(t0())).unwrap();
        assert_eq!(ring.verify(&token, t0()).unwrap_err().code(), "unauthorized");
        // No kid at all.
        let header = B64URL.encode(br#"{"alg":"EdDSA","typ":"JWT"}"#);
        let body = B64URL.encode(serde_json::to_vec(&claims(t0())).unwrap());
        let missing = format!("{header}.{body}.{}", B64URL.encode([0u8; 64]));
        assert_eq!(ring.verify(&missing, t0()).unwrap_err().code(), "unauthorized");
    }

    #[test]
    fn tampered_payload_or_signature_is_rejected() {
        let ring = keyring();
        let token = ring.sign(&claims(t0())).unwrap();
        let parts: Vec<&str> = token.split('.').collect();

        // Payload swap: same signature, different claims.
        let other = B64URL.encode(serde_json::to_vec(&claims(t0() + Duration::hours(1))).unwrap());
        let swapped = format!("{}.{other}.{}", parts[0], parts[2]);
        assert_eq!(ring.verify(&swapped, t0()).unwrap_err().code(), "unauthorized");

        // Signature bit-flip.
        let mut sig = B64URL.decode(parts[2]).unwrap();
        sig[0] ^= 0x01;
        let flipped = format!("{}.{}.{}", parts[0], parts[1], B64URL.encode(sig));
        assert_eq!(ring.verify(&flipped, t0()).unwrap_err().code(), "unauthorized");
    }

    #[test]
    fn malformed_tokens_are_rejected() {
        let ring = keyring();
        for garbage in ["", "abc", "a.b", "a.b.c.d", "!!!.???.###", "a.b.c"] {
            assert_eq!(ring.verify(garbage, t0()).unwrap_err().code(), "unauthorized", "accepted {garbage:?}");
        }
    }

    #[test]
    fn rotation_overlap_verifies_old_kid_tokens() {
        let old = Keyring::new("gen1", [1u8; 32], &[]).unwrap();
        let token = old.sign(&claims(t0())).unwrap();
        // New keyring signs with gen2 but still verifies gen1.
        let new = Keyring::new("gen2", [2u8; 32], &[("gen1".to_owned(), [1u8; 32])]).unwrap();
        assert!(new.verify(&token, t0()).is_ok());
        // A keyring without the overlap rejects the retired kid.
        let final_ring = Keyring::new("gen2", [2u8; 32], &[]).unwrap();
        assert_eq!(final_ring.verify(&token, t0()).unwrap_err().code(), "unauthorized");
    }

    #[test]
    fn from_base64_validates_seed_shape() {
        use base64::engine::general_purpose::STANDARD;
        let good = STANDARD.encode([5u8; 32]);
        assert!(Keyring::from_base64("k", &good, &[]).is_ok());
        // Wrong length.
        let short = STANDARD.encode([5u8; 16]);
        assert_eq!(Keyring::from_base64("k", &short, &[]).unwrap_err().code(), "config_invalid");
        // Not base64 at all.
        assert_eq!(Keyring::from_base64("k", "not-base64!!!", &[]).unwrap_err().code(), "config_invalid");
        // Broken verify key is caught too.
        let err = Keyring::from_base64("k", &good, &[("v".to_owned(), "xx".to_owned())]).unwrap_err();
        assert_eq!(err.code(), "config_invalid");
    }

    #[test]
    fn duplicate_kid_is_a_config_error() {
        let err = Keyring::new("k1", [1u8; 32], &[("k1".to_owned(), [2u8; 32])]).unwrap_err();
        assert_eq!(err.code(), "config_invalid");
    }

    #[test]
    fn ephemeral_keyring_signs_and_verifies() {
        let ring = Keyring::ephemeral(&crate::random::OsRandom);
        assert_eq!(ring.signing_kid(), EPHEMERAL_KID);
        let token = ring.sign(&claims(t0())).unwrap();
        assert!(ring.verify(&token, t0()).is_ok());
    }
}
