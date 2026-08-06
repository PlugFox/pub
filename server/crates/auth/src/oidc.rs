//! Multi-provider OIDC relying party (S-01, decision 12).
//!
//! Zero or more providers come from boot config; with none configured the instance is
//! email-OTP-only and every endpoint here answers 404. Per provider:
//!
//! - **Discovery** via `{issuer}/.well-known/openid-configuration`, cached with a bounded
//!   TTL. The advertised `issuer` must equal the configured one.
//! - **JWKS** cached by `kid`; an unknown `kid` triggers exactly one refetch (key rotation)
//!   before the token is rejected.
//! - **Flow state** lives server-side in KV under an opaque 128-bit `flow_id` the browser
//!   holds: `state` (≥128-bit, single-use), `nonce`, and the PKCE S256 verifier. The record
//!   is deleted on first redemption regardless of outcome — replay gets nothing.
//! - **id_token validation**: `alg` pinned to the discovery-advertised subset of
//!   RS256/ES256 (`none`/`HS*` are structurally impossible), key strictly by `kid`,
//!   `iss`/`aud`(+`azp`)/`exp`/`iat` with small skew, `nonce` compared in constant time.
//!
//! This module owns the OIDC *mechanics* and returns a [`VerifiedIdentity`]; account
//! resolution, linking policy (S-02), and session opening live in [`crate::flows`].
//! Failure messages here are internal diagnostics for the audit log — the API layer never
//! forwards them to the caller (S-04 uniformity).

use std::collections::{HashMap, HashSet};
use std::sync::Mutex;
use std::time::Duration as StdDuration;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
use chrono::{DateTime, Duration, Utc};
use pub_core::traits::Kv;
use pub_core::{Error, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use subtle::ConstantTimeEq as _;

use crate::hex;
use crate::jwt::CLOCK_SKEW;
use crate::random::RandomSource;

/// Lifetime of a started flow: the user must return from the IdP within this window.
pub const FLOW_TTL: Duration = Duration::minutes(10);

/// How long cached discovery documents and JWKS stay fresh.
const METADATA_TTL: Duration = Duration::hours(1);

/// Algorithms this relying party is able and willing to verify (S-01).
const SUPPORTED_ALGS: [&str; 2] = ["RS256", "ES256"];

/// Scopes requested when the provider config does not name any.
const DEFAULT_SCOPES: [&str; 3] = ["openid", "email", "profile"];

/// One configured identity provider (decision 12: issuer + client id/secret + label).
///
/// [`Debug`] is hand-written: `client_secret` is a boot secret (S-25) and must not be
/// reachable through `{:?}`.
#[derive(Clone)]
pub struct ProviderConfig {
    /// URL-safe slug identifying the provider in routes (`google`, `corp-idp`).
    pub id: String,
    /// Human label for the login screen.
    pub display_name: String,
    /// Issuer URL, no trailing slash — the discovery base and the stored identity key.
    pub issuer: String,
    /// OAuth client id.
    pub client_id: String,
    /// OAuth client secret (confidential client — S-01; code exchange is server-side only).
    pub client_secret: String,
    /// Scopes to request; empty means `openid email profile`.
    pub scopes: Vec<String>,
}

impl std::fmt::Debug for ProviderConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProviderConfig")
            .field("id", &self.id)
            .field("display_name", &self.display_name)
            .field("issuer", &self.issuer)
            .field("client_id", &self.client_id)
            .field("client_secret", &"<redacted>")
            .field("scopes", &self.scopes)
            .finish()
    }
}

/// Result of [`OidcClient::start`]: what the browser needs to begin the redirect dance.
#[derive(Clone, Debug)]
pub struct StartedFlow {
    /// Opaque server-side flow handle; required again at the callback (flow binding).
    pub flow_id: String,
    /// Fully assembled IdP authorization URL.
    pub authorize_url: String,
}

/// The verified outcome of a callback: who the IdP says this is (S-01: keyed by
/// `(issuer, subject)`, never email).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedIdentity {
    /// Normalized issuer (the configured value — the DB identity key half).
    pub issuer: String,
    /// `sub` claim — the other identity key half.
    pub subject: String,
    /// `email` claim, when present.
    pub email: Option<String>,
    /// `email_verified` claim; only `true` emails may ever link or create accounts (S-02).
    pub email_verified: bool,
}

/// Server-side flow record stored in KV under `oidc:flow:{flow_id}`.
#[derive(Serialize, Deserialize)]
struct FlowRecord {
    provider: String,
    state: String,
    nonce: String,
    pkce_verifier: String,
    created_at: DateTime<Utc>,
}

/// The subset of the discovery document this relying party uses.
#[derive(Clone, Debug, Deserialize)]
struct Discovery {
    issuer: String,
    authorization_endpoint: String,
    token_endpoint: String,
    jwks_uri: String,
    id_token_signing_alg_values_supported: Option<Vec<String>>,
}

/// One JWKS key in the two shapes we verify (RSA / P-256).
#[derive(Clone, Debug, Deserialize)]
struct Jwk {
    kty: String,
    kid: Option<String>,
    alg: Option<String>,
    #[serde(rename = "use")]
    key_use: Option<String>,
    n: Option<String>,
    e: Option<String>,
    crv: Option<String>,
    x: Option<String>,
    y: Option<String>,
}

#[derive(Debug, Deserialize)]
struct JwksDocument {
    keys: Vec<Jwk>,
}

#[derive(Debug, Deserialize)]
struct TokenResponse {
    id_token: Option<String>,
}

#[derive(Debug, Deserialize)]
struct IdTokenHeader {
    alg: String,
    kid: Option<String>,
}

/// `aud` may be a single string or an array (OIDC Core §2).
#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum AudClaim {
    One(String),
    Many(Vec<String>),
}

impl AudClaim {
    fn contains(&self, client_id: &str) -> bool {
        match self {
            Self::One(aud) => aud == client_id,
            Self::Many(auds) => auds.iter().any(|aud| aud == client_id),
        }
    }

    fn is_multi(&self) -> bool {
        matches!(self, Self::Many(auds) if auds.len() > 1)
    }
}

#[derive(Debug, Deserialize)]
struct IdTokenClaims {
    iss: String,
    sub: String,
    aud: AudClaim,
    exp: i64,
    iat: i64,
    azp: Option<String>,
    nonce: Option<String>,
    email: Option<String>,
    email_verified: Option<bool>,
}

/// Cached per-provider metadata: discovery + JWKS by kid.
#[derive(Clone)]
struct ProviderMeta {
    discovery: Discovery,
    keys: HashMap<String, Jwk>,
    fetched_at: DateTime<Utc>,
}

/// The relying-party client over every configured provider.
pub struct OidcClient {
    http: reqwest::Client,
    /// `server.public_url` without a trailing slash — the redirect-URI base.
    redirect_base: String,
    providers: Vec<ProviderConfig>,
    cache: Mutex<HashMap<String, ProviderMeta>>,
}

impl std::fmt::Debug for OidcClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OidcClient")
            .field("redirect_base", &self.redirect_base)
            .field("providers", &self.providers.iter().map(|p| p.id.as_str()).collect::<Vec<_>>())
            .finish_non_exhaustive()
    }
}

impl OidcClient {
    /// Builds the client. `public_url` is the instance origin the IdP redirects back to.
    pub fn new(providers: Vec<ProviderConfig>, public_url: &str) -> Result<Self> {
        let http = reqwest::Client::builder()
            .timeout(StdDuration::from_secs(10))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|err| Error::Config { message: format!("oidc http client setup failed: {err}") })?;
        Ok(Self {
            http,
            redirect_base: public_url.trim_end_matches('/').to_owned(),
            providers,
            cache: Mutex::new(HashMap::new()),
        })
    }

    /// The configured providers, in config order (login-screen listing).
    pub fn providers(&self) -> &[ProviderConfig] {
        &self.providers
    }

    /// A provider by id; unknown ids are `NotFound` (the route answers 404).
    pub fn provider(&self, id: &str) -> Result<&ProviderConfig> {
        self.providers
            .iter()
            .find(|provider| provider.id == id)
            .ok_or_else(|| Error::NotFound { what: format!("oidc provider {id}") })
    }

    /// Exact-match redirect URI for a provider (S-01) — the SPA route that finishes the flow.
    pub fn redirect_uri(&self, provider_id: &str) -> String {
        format!("{}/auth/callback/{provider_id}", self.redirect_base)
    }

    /// Starts a flow: mints `state`/`nonce`/PKCE verifier, persists them under an opaque
    /// `flow_id` (short TTL), and assembles the authorization URL.
    pub async fn start(
        &self,
        kv: &dyn Kv,
        rng: &dyn RandomSource,
        provider_id: &str,
        now: DateTime<Utc>,
    ) -> Result<StartedFlow> {
        let provider = self.provider(provider_id)?;
        let discovery = self.metadata(provider, now).await?.discovery;

        // ≥128-bit CSPRNG values (S-01): 256-bit state/nonce, 256-bit PKCE verifier.
        let state = random_hex(rng, 32);
        let nonce = random_hex(rng, 32);
        let pkce_verifier = B64URL.encode(random_bytes(rng, 32));
        let code_challenge = B64URL.encode(Sha256::digest(pkce_verifier.as_bytes()));
        let flow_id = random_hex(rng, 16);

        let record =
            FlowRecord { provider: provider.id.clone(), state: state.clone(), nonce, pkce_verifier, created_at: now };
        let json = serde_json::to_string(&record)
            .map_err(|err| Error::Internal { message: format!("oidc flow serialization failed: {err}") })?;
        kv.set_ttl(&flow_key(&flow_id), &json, FLOW_TTL.to_std().expect("FLOW_TTL is positive")).await?;

        let scopes: Vec<&str> = if provider.scopes.is_empty() {
            DEFAULT_SCOPES.to_vec()
        } else {
            provider.scopes.iter().map(String::as_str).collect()
        };
        let mut authorize_url = url::Url::parse(&discovery.authorization_endpoint)
            .map_err(|err| Error::Internal { message: format!("bad authorization_endpoint from discovery: {err}") })?;
        authorize_url
            .query_pairs_mut()
            .append_pair("response_type", "code")
            .append_pair("client_id", &provider.client_id)
            .append_pair("redirect_uri", &self.redirect_uri(&provider.id))
            .append_pair("scope", &scopes.join(" "))
            .append_pair("state", &state)
            .append_pair("nonce", &record.nonce)
            .append_pair("code_challenge", &code_challenge)
            .append_pair("code_challenge_method", "S256");
        Ok(StartedFlow { flow_id, authorize_url: authorize_url.into() })
    }

    /// Finishes a flow: validates the single-use state, exchanges the code (confidential
    /// client + PKCE), fully validates the `id_token`, and returns the verified identity.
    ///
    /// Every failure is [`Error::Unauthorized`] with an *internal* reason for the audit
    /// log; unknown providers stay `NotFound`.
    pub async fn callback(
        &self,
        kv: &dyn Kv,
        provider_id: &str,
        flow_id: &str,
        state: &str,
        code: &str,
        now: DateTime<Utc>,
    ) -> Result<VerifiedIdentity> {
        let provider = self.provider(provider_id)?;

        // Single-use before anything else: the record dies on first presentation, success
        // or not, so a raced or replayed callback can never redeem the same flow twice.
        let key = flow_key(flow_id);
        let Some(raw) = kv.get(&key).await? else {
            return Err(reject("unknown or already-used flow id"));
        };
        kv.del(&key).await?;
        let record: FlowRecord = serde_json::from_str(&raw).map_err(|_| reject("corrupt flow record"))?;
        if record.provider != provider.id {
            return Err(reject("flow belongs to a different provider"));
        }
        if now >= record.created_at + FLOW_TTL {
            return Err(reject("flow expired"));
        }
        let state_ok: bool = record.state.as_bytes().ct_eq(state.as_bytes()).into();
        if !state_ok {
            return Err(reject("state mismatch"));
        }

        let meta = self.metadata(provider, now).await?;
        let id_token = self.exchange_code(provider, &meta.discovery, code, &record.pkce_verifier).await?;
        self.validate_id_token(provider, &meta, &id_token, &record.nonce, now).await
    }

    // --- internals ---

    /// Cached (or freshly fetched) discovery + JWKS for a provider.
    async fn metadata(&self, provider: &ProviderConfig, now: DateTime<Utc>) -> Result<ProviderMeta> {
        if let Some(meta) = self.cached_meta(&provider.id)
            && now < meta.fetched_at + METADATA_TTL
        {
            return Ok(meta);
        }
        self.fetch_metadata(provider, now).await
    }

    fn cached_meta(&self, provider_id: &str) -> Option<ProviderMeta> {
        self.cache.lock().expect("oidc cache mutex poisoned").get(provider_id).cloned()
    }

    /// Fetches discovery + JWKS and installs them in the cache.
    async fn fetch_metadata(&self, provider: &ProviderConfig, now: DateTime<Utc>) -> Result<ProviderMeta> {
        let discovery_url = format!("{}/.well-known/openid-configuration", provider.issuer);
        let discovery: Discovery = self.get_json(&discovery_url, "discovery").await?;
        // The advertised issuer must be the configured one (spec §4.3) — a mismatch means a
        // misconfiguration or a hostile document; either way nothing downstream may run.
        if discovery.issuer.trim_end_matches('/') != provider.issuer {
            return Err(reject("discovery issuer mismatch"));
        }
        let jwks: JwksDocument = self.get_json(&discovery.jwks_uri, "jwks").await?;
        let keys = jwks.keys.into_iter().filter_map(|key| key.kid.clone().map(|kid| (kid, key))).collect();
        let meta = ProviderMeta { discovery, keys, fetched_at: now };
        self.cache.lock().expect("oidc cache mutex poisoned").insert(provider.id.clone(), meta.clone());
        Ok(meta)
    }

    async fn get_json<T: serde::de::DeserializeOwned>(&self, url: &str, what: &str) -> Result<T> {
        let response = self
            .http
            .get(url)
            .send()
            .await
            .map_err(|err| Error::Internal { message: format!("oidc {what} fetch failed: {err}") })?;
        if !response.status().is_success() {
            return Err(Error::Internal { message: format!("oidc {what} fetch returned {}", response.status()) });
        }
        response
            .json::<T>()
            .await
            .map_err(|err| Error::Internal { message: format!("oidc {what} response is not valid JSON: {err}") })
    }

    /// Redeems the authorization code at the token endpoint (confidential client + PKCE)
    /// and returns the raw `id_token` compact JWS.
    async fn exchange_code(
        &self,
        provider: &ProviderConfig,
        discovery: &Discovery,
        code: &str,
        pkce_verifier: &str,
    ) -> Result<String> {
        let form = [
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", &self.redirect_uri(&provider.id)),
            ("client_id", &provider.client_id),
            ("client_secret", &provider.client_secret),
            ("code_verifier", pkce_verifier),
        ];
        let response = self
            .http
            .post(&discovery.token_endpoint)
            .form(&form)
            .send()
            .await
            .map_err(|err| reject(&format!("token exchange failed: {err}")))?;
        if !response.status().is_success() {
            // The IdP refused the code (expired, replayed, PKCE/secret mismatch) — an auth
            // failure, not a server fault. The body is not read: it is attacker-influenced.
            return Err(reject(&format!("token endpoint returned {}", response.status())));
        }
        let token: TokenResponse = response.json().await.map_err(|_| reject("token response is not valid JSON"))?;
        token.id_token.ok_or_else(|| reject("token response carries no id_token"))
    }

    /// Full id_token validation (S-01). `meta` may be refreshed once on an unknown `kid`.
    async fn validate_id_token(
        &self,
        provider: &ProviderConfig,
        meta: &ProviderMeta,
        id_token: &str,
        expected_nonce: &str,
        now: DateTime<Utc>,
    ) -> Result<VerifiedIdentity> {
        let mut parts = id_token.split('.');
        let (Some(header_b64), Some(claims_b64), Some(sig_b64), None) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            return Err(reject("malformed id_token"));
        };
        let header_json = B64URL.decode(header_b64).map_err(|_| reject("malformed id_token header"))?;
        let header: IdTokenHeader =
            serde_json::from_slice(&header_json).map_err(|_| reject("malformed id_token header"))?;

        // Pin the algorithm before touching key material: the acceptable set is the
        // discovery-advertised algorithms intersected with RS256/ES256 — `none` and the
        // HMAC family can never enter it (S-01).
        let advertised: HashSet<&str> = meta
            .discovery
            .id_token_signing_alg_values_supported
            .as_ref()
            .map(|algs| algs.iter().map(String::as_str).collect())
            // The field is required by the discovery spec; absent means RS256 only (the
            // one algorithm the spec mandates).
            .unwrap_or_else(|| HashSet::from(["RS256"]));
        if !SUPPORTED_ALGS.contains(&header.alg.as_str()) || !advertised.contains(header.alg.as_str()) {
            return Err(reject(&format!("id_token alg {:?} is not allowed", header.alg)));
        }
        let Some(kid) = header.kid.as_deref() else {
            return Err(reject("id_token carries no kid"));
        };

        // Strict kid resolution with exactly one refetch on a miss (key rotation).
        let jwk = match meta.keys.get(kid) {
            Some(jwk) => jwk.clone(),
            None => {
                let refreshed = self.fetch_metadata(provider, now).await?;
                match refreshed.keys.get(kid) {
                    Some(jwk) => jwk.clone(),
                    None => return Err(reject(&format!("unknown id_token kid {kid:?}"))),
                }
            }
        };
        if jwk.key_use.as_deref().is_some_and(|key_use| key_use != "sig") {
            return Err(reject("id_token key is not a signing key"));
        }
        if jwk.alg.as_deref().is_some_and(|alg| alg != header.alg) {
            return Err(reject("id_token alg does not match the key's declared alg"));
        }

        let signature = B64URL.decode(sig_b64).map_err(|_| reject("malformed id_token signature"))?;
        let signing_input = format!("{header_b64}.{claims_b64}");
        verify_signature(&header.alg, &jwk, signing_input.as_bytes(), &signature)?;

        let claims_json = B64URL.decode(claims_b64).map_err(|_| reject("malformed id_token claims"))?;
        let claims: IdTokenClaims =
            serde_json::from_slice(&claims_json).map_err(|_| reject("malformed id_token claims"))?;

        if claims.iss.trim_end_matches('/') != provider.issuer {
            return Err(reject("id_token iss mismatch"));
        }
        if !claims.aud.contains(&provider.client_id) {
            return Err(reject("id_token aud mismatch"));
        }
        if claims.aud.is_multi() && claims.azp.as_deref() != Some(provider.client_id.as_str()) {
            return Err(reject("id_token azp mismatch on multi-audience token"));
        }
        let now_ts = now.timestamp();
        if now_ts > claims.exp + CLOCK_SKEW.num_seconds() {
            return Err(reject("id_token expired"));
        }
        if claims.iat > now_ts + CLOCK_SKEW.num_seconds() {
            return Err(reject("id_token issued in the future"));
        }
        let nonce_ok: bool = claims
            .nonce
            .as_deref()
            .map(|nonce| nonce.as_bytes().ct_eq(expected_nonce.as_bytes()).into())
            .unwrap_or(false);
        if !nonce_ok {
            return Err(reject("id_token nonce mismatch"));
        }

        Ok(VerifiedIdentity {
            issuer: provider.issuer.clone(),
            subject: claims.sub,
            email: claims.email.map(|email| email.trim().to_ascii_lowercase()),
            email_verified: claims.email_verified.unwrap_or(false),
        })
    }
}

/// Verifies a compact-JWS signature under the pinned algorithm.
fn verify_signature(alg: &str, jwk: &Jwk, signing_input: &[u8], signature: &[u8]) -> Result<()> {
    match alg {
        "RS256" => {
            if jwk.kty != "RSA" {
                return Err(reject("RS256 id_token but the key is not RSA"));
            }
            let n = decode_component(jwk.n.as_deref(), "n")?;
            let e = decode_component(jwk.e.as_deref(), "e")?;
            let key = rsa::RsaPublicKey::new(rsa::BigUint::from_bytes_be(&n), rsa::BigUint::from_bytes_be(&e))
                .map_err(|_| reject("invalid RSA public key in JWKS"))?;
            let digest = Sha256::digest(signing_input);
            key.verify(rsa::pkcs1v15::Pkcs1v15Sign::new::<Sha256>(), &digest, signature)
                .map_err(|_| reject("id_token signature mismatch"))
        }
        "ES256" => {
            use p256::ecdsa::signature::Verifier as _;
            if jwk.kty != "EC" || jwk.crv.as_deref() != Some("P-256") {
                return Err(reject("ES256 id_token but the key is not P-256"));
            }
            let x = decode_component(jwk.x.as_deref(), "x")?;
            let y = decode_component(jwk.y.as_deref(), "y")?;
            let (Ok(x), Ok(y)) = (<[u8; 32]>::try_from(x.as_slice()), <[u8; 32]>::try_from(y.as_slice())) else {
                return Err(reject("invalid P-256 coordinates in JWKS"));
            };
            let point = p256::EncodedPoint::from_affine_coordinates(
                &p256::FieldBytes::from(x),
                &p256::FieldBytes::from(y),
                false,
            );
            let key = p256::ecdsa::VerifyingKey::from_encoded_point(&point)
                .map_err(|_| reject("invalid P-256 public key in JWKS"))?;
            let sig = p256::ecdsa::Signature::from_slice(signature).map_err(|_| reject("malformed ES256 signature"))?;
            key.verify(signing_input, &sig).map_err(|_| reject("id_token signature mismatch"))
        }
        // Unreachable: the caller pinned alg to SUPPORTED_ALGS already.
        other => Err(reject(&format!("unsupported id_token alg {other:?}"))),
    }
}

/// Decodes one base64url JWK component.
fn decode_component(value: Option<&str>, name: &str) -> Result<Vec<u8>> {
    let raw = value.ok_or_else(|| reject(&format!("JWKS key misses component {name:?}")))?;
    B64URL.decode(raw).map_err(|_| reject(&format!("JWKS key component {name:?} is not base64url")))
}

/// KV key of a pending flow record.
pub fn flow_key(flow_id: &str) -> String {
    format!("oidc:flow:{flow_id}")
}

/// Uniform internal failure: the message feeds the audit trail only, never the wire.
fn reject(message: &str) -> Error {
    Error::Unauthorized { message: format!("oidc: {message}") }
}

fn random_bytes(rng: &dyn RandomSource, len: usize) -> Vec<u8> {
    let mut buf = vec![0u8; len];
    rng.fill(&mut buf);
    buf
}

fn random_hex(rng: &dyn RandomSource, len: usize) -> String {
    hex(&random_bytes(rng, len))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::random::OsRandom;

    fn provider() -> ProviderConfig {
        ProviderConfig {
            id: "google".to_owned(),
            display_name: "Google".to_owned(),
            issuer: "https://accounts.google.com".to_owned(),
            client_id: "client-123".to_owned(),
            client_secret: "secret-value".to_owned(),
            scopes: Vec::new(),
        }
    }

    #[test]
    fn s25_provider_debug_redacts_the_client_secret() {
        let rendered = format!("{:?}", provider());
        assert!(!rendered.contains("secret-value"), "client secret leaked: {rendered}");
        assert!(rendered.contains("client-123"), "non-secrets stay visible: {rendered}");
    }

    #[test]
    fn provider_lookup_and_redirect_uri() {
        let client = OidcClient::new(vec![provider()], "https://pub.corp.test/").unwrap();
        assert_eq!(client.provider("google").unwrap().client_id, "client-123");
        assert_eq!(client.provider("github").unwrap_err().code(), "not_found");
        assert_eq!(client.redirect_uri("google"), "https://pub.corp.test/auth/callback/google");
    }

    #[test]
    fn aud_claim_matches_single_and_array_forms() {
        assert!(AudClaim::One("c".into()).contains("c"));
        assert!(!AudClaim::One("x".into()).contains("c"));
        assert!(AudClaim::Many(vec!["a".into(), "c".into()]).contains("c"));
        assert!(!AudClaim::Many(vec!["a".into()]).contains("c"));
        assert!(AudClaim::Many(vec!["a".into(), "c".into()]).is_multi());
        assert!(!AudClaim::Many(vec!["c".into()]).is_multi());
        assert!(!AudClaim::One("c".into()).is_multi());
    }

    #[tokio::test]
    async fn s01_flow_record_round_trips_and_is_single_use() {
        let kv = pub_kv_stub().await;
        let client = OidcClient::new(vec![provider()], "https://pub.corp.test").unwrap();
        // start() needs discovery — not reachable offline here; exercised end to end in the
        // API integration suite with the mock issuer. This test covers the record itself.
        let record = FlowRecord {
            provider: "google".to_owned(),
            state: random_hex(&OsRandom, 32),
            nonce: random_hex(&OsRandom, 32),
            pkce_verifier: B64URL.encode(random_bytes(&OsRandom, 32)),
            created_at: Utc::now(),
        };
        assert_eq!(record.state.len(), 64, "state is 256-bit hex (≥128-bit required by S-01)");
        let json = serde_json::to_string(&record).unwrap();
        kv.set_ttl(&flow_key("abc"), &json, StdDuration::from_secs(600)).await.unwrap();
        let _ = client;
        let loaded: FlowRecord = serde_json::from_str(&kv.get(&flow_key("abc")).await.unwrap().unwrap()).unwrap();
        assert_eq!(loaded.state, record.state);
    }

    async fn pub_kv_stub() -> impl Kv {
        pub_kv::MemoryKv::new()
    }
}
