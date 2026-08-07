//! In-process mock OIDC issuer for the S-01/S-02 integration suite.
//!
//! A real axum server on a `127.0.0.1` ephemeral port serving discovery, JWKS, and the
//! token endpoint, signing genuine RS256 id_tokens with a throwaway process-wide RSA key —
//! the whole relying-party path (reqwest → discovery → exchange → JWKS → signature) runs
//! offline. Tests mint authorization codes directly via [`MockIssuer::issue_code`] (the
//! browser leg of the redirect dance is the IdP's UI, not our code) and the token endpoint
//! enforces PKCE S256 + the client secret exactly like a real IdP.

use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

use axum::extract::{Form, State};
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{Json, Router};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
use pub_auth::oidc::ProviderConfig;
use rsa::RsaPrivateKey;
use rsa::pkcs1v15::Pkcs1v15Sign;
use rsa::traits::PublicKeyParts as _;
use sha2::{Digest as _, Sha256};

/// The kid the issuer signs with (and lists in its JWKS) unless a test rotates it.
pub const DEFAULT_KID: &str = "mock-key-1";

/// The throwaway RSA-2048 signing key — generated once per test process.
pub fn test_rsa_key() -> &'static RsaPrivateKey {
    static KEY: OnceLock<RsaPrivateKey> = OnceLock::new();
    KEY.get_or_init(|| RsaPrivateKey::new(&mut rand::thread_rng(), 2048).expect("rsa keygen"))
}

/// One authorization code the issuer is willing to redeem.
struct IssuedCode {
    /// Claims the id_token will carry, verbatim.
    claims: serde_json::Value,
    /// The `code_challenge` from the authorize URL — PKCE S256 is enforced at exchange.
    code_challenge: String,
}

struct IssuerState {
    issuer: String,
    client_id: String,
    client_secret: String,
    codes: Mutex<HashMap<String, IssuedCode>>,
    /// Which kids the JWKS endpoint currently exposes.
    jwks_kids: Mutex<Vec<String>>,
    /// The kid embedded in signed id_tokens.
    signing_kid: Mutex<String>,
    /// When set, the token endpoint returns this string verbatim as the id_token.
    id_token_override: Mutex<Option<String>>,
    jwks_hits: AtomicUsize,
}

/// Handle to a running mock issuer.
pub struct MockIssuer {
    /// `http://127.0.0.1:{port}` — use as the provider's issuer URL.
    pub issuer: String,
    state: Arc<IssuerState>,
}

impl MockIssuer {
    /// Binds an ephemeral port and serves the issuer for the rest of the test.
    pub async fn spawn(client_id: &str, client_secret: &str) -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind mock issuer");
        let issuer = format!("http://{}", listener.local_addr().expect("local addr"));
        let state = Arc::new(IssuerState {
            issuer: issuer.clone(),
            client_id: client_id.to_owned(),
            client_secret: client_secret.to_owned(),
            codes: Mutex::new(HashMap::new()),
            jwks_kids: Mutex::new(vec![DEFAULT_KID.to_owned()]),
            signing_kid: Mutex::new(DEFAULT_KID.to_owned()),
            id_token_override: Mutex::new(None),
            jwks_hits: AtomicUsize::new(0),
        });
        let router = Router::new()
            .route("/.well-known/openid-configuration", get(discovery))
            .route("/jwks", get(jwks))
            .route("/token", post(token))
            .with_state(Arc::clone(&state));
        tokio::spawn(async move {
            axum::serve(listener, router).await.expect("mock issuer serve");
        });
        Self { issuer, state }
    }

    /// The provider entry pointing a [`super::TestApp`] at this issuer.
    pub fn provider_config(&self, id: &str) -> ProviderConfig {
        ProviderConfig {
            id: id.to_owned(),
            display_name: format!("Mock {id}"),
            issuer: self.issuer.clone(),
            client_id: self.state.client_id.clone(),
            client_secret: self.state.client_secret.clone(),
            scopes: Vec::new(),
        }
    }

    /// Standard claims for a login of `sub`, correct for this issuer/client.
    pub fn claims(
        &self,
        sub: &str,
        email: Option<&str>,
        email_verified: bool,
        nonce: &str,
        now: chrono::DateTime<chrono::Utc>,
    ) -> serde_json::Value {
        let mut claims = serde_json::json!({
            "iss": self.issuer,
            "sub": sub,
            "aud": self.state.client_id,
            "iat": now.timestamp(),
            "exp": now.timestamp() + 300,
            "nonce": nonce,
        });
        if let Some(email) = email {
            claims["email"] = email.into();
            claims["email_verified"] = email_verified.into();
        }
        claims
    }

    /// Registers an authorization code redeemable exactly once for an id_token with these
    /// claims, bound to the given PKCE challenge.
    pub fn issue_code(&self, claims: serde_json::Value, code_challenge: &str) -> String {
        let code = format!("code-{}", self.state.codes.lock().unwrap().len() + rand::random::<u32>() as usize);
        self.state
            .codes
            .lock()
            .unwrap()
            .insert(code.clone(), IssuedCode { claims, code_challenge: code_challenge.to_owned() });
        code
    }

    /// Signs id_tokens with this kid from now on (JWKS is *not* updated automatically).
    pub fn set_signing_kid(&self, kid: &str) {
        *self.state.signing_kid.lock().unwrap() = kid.to_owned();
    }

    /// Replaces the set of kids the JWKS endpoint exposes (all share the one RSA key).
    pub fn set_jwks_kids(&self, kids: &[&str]) {
        *self.state.jwks_kids.lock().unwrap() = kids.iter().map(|&k| k.to_owned()).collect();
    }

    /// Makes the token endpoint return this exact string as the id_token (forgery tests).
    pub fn override_id_token(&self, token: Option<String>) {
        *self.state.id_token_override.lock().unwrap() = token;
    }

    /// How many times the JWKS endpoint was fetched.
    pub fn jwks_hits(&self) -> usize {
        self.state.jwks_hits.load(Ordering::SeqCst)
    }
}

/// Signs `claims` as an RS256 compact JWS under `kid` with the process-wide test key.
pub fn sign_rs256(kid: &str, claims: &serde_json::Value) -> String {
    let header = serde_json::json!({ "alg": "RS256", "typ": "JWT", "kid": kid });
    let signing_input = format!(
        "{}.{}",
        B64URL.encode(serde_json::to_vec(&header).unwrap()),
        B64URL.encode(serde_json::to_vec(claims).unwrap())
    );
    // rsa 0.9 still speaks the digest-0.10 generation — the hash type parameter must come
    // from its own `rsa::sha2` re-export.
    use rsa::sha2::Digest as _;
    let digest = rsa::sha2::Sha256::digest(signing_input.as_bytes());
    let signature = test_rsa_key().sign(Pkcs1v15Sign::new::<rsa::sha2::Sha256>(), &digest).expect("rsa sign");
    format!("{signing_input}.{}", B64URL.encode(signature))
}

async fn discovery(State(state): State<Arc<IssuerState>>) -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "issuer": state.issuer,
        "authorization_endpoint": format!("{}/authorize", state.issuer),
        "token_endpoint": format!("{}/token", state.issuer),
        "jwks_uri": format!("{}/jwks", state.issuer),
        "id_token_signing_alg_values_supported": ["RS256"],
        "response_types_supported": ["code"],
        "subject_types_supported": ["public"],
    }))
}

async fn jwks(State(state): State<Arc<IssuerState>>) -> Json<serde_json::Value> {
    state.jwks_hits.fetch_add(1, Ordering::SeqCst);
    let public = test_rsa_key().to_public_key();
    let n = B64URL.encode(public.n().to_bytes_be());
    let e = B64URL.encode(public.e().to_bytes_be());
    let keys: Vec<serde_json::Value> = state
        .jwks_kids
        .lock()
        .unwrap()
        .iter()
        .map(|kid| serde_json::json!({ "kty": "RSA", "use": "sig", "alg": "RS256", "kid": kid, "n": n, "e": e }))
        .collect();
    Json(serde_json::json!({ "keys": keys }))
}

/// The token endpoint: enforces client credentials, single-use codes, and PKCE S256 —
/// the parts of a real IdP the relying party's security depends on.
async fn token(
    State(state): State<Arc<IssuerState>>,
    Form(form): Form<HashMap<String, String>>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let field = |name: &str| form.get(name).cloned().unwrap_or_default();
    if field("grant_type") != "authorization_code" {
        return Err(StatusCode::BAD_REQUEST);
    }
    if field("client_id") != state.client_id || field("client_secret") != state.client_secret {
        return Err(StatusCode::UNAUTHORIZED);
    }
    let Some(issued) = state.codes.lock().unwrap().remove(&field("code")) else {
        return Err(StatusCode::BAD_REQUEST);
    };
    let challenge = B64URL.encode(Sha256::digest(field("code_verifier").as_bytes()));
    if challenge != issued.code_challenge {
        return Err(StatusCode::BAD_REQUEST);
    }
    let id_token = match state.id_token_override.lock().unwrap().clone() {
        Some(forged) => forged,
        None => sign_rs256(&state.signing_kid.lock().unwrap(), &issued.claims),
    };
    Ok(Json(serde_json::json!({
        "access_token": "mock-access-token",
        "token_type": "Bearer",
        "expires_in": 3600,
        "id_token": id_token,
    })))
}
