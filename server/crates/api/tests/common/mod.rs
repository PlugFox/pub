//! Shared integration-test harness: full router over in-memory backends with a controllable
//! clock (docs/rules/rust.md — no containers, deterministic time).
//!
//! Not every test binary uses every helper — silence per-binary dead-code noise.
#![allow(dead_code)]

pub mod oidc;

use std::sync::{Arc, Mutex};
use std::time::Duration as StdDuration;

use axum::Router;
use axum::body::Body;
use axum::http::{HeaderMap, Method, Request, StatusCode, header};
use chrono::{DateTime, Duration, TimeZone as _, Utc};
use http_body_util::BodyExt as _;
use pub_api::AppState;
use pub_auth::flows::{AuthPolicy, AuthService};
use pub_auth::jwt::Keyring;
use pub_auth::oidc::{OidcClient, ProviderConfig};
use pub_auth::random::OsRandom;
use pub_blob::ObjectStoreBlob;
use pub_config::{BlobKind, DatabaseConfig, DatabaseKind, KvKind, Settings};
use pub_core::session::SessionLimits;
use pub_core::traits::{Kv, Mailer, Repositories};
use pub_db_sqlite::SqliteDb;
use pub_kv::MemoryKv;
use pub_mail::InMemoryMailer;
use tower::ServiceExt as _;

/// Deterministic base instant shared by every scenario.
pub fn t0() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 8, 6, 12, 0, 0).unwrap()
}

/// The signing seed of the test keyring — tests craft rogue tokens against it.
pub const TEST_JWT_SEED: [u8; 32] = [42u8; 32];

/// The kid of the test keyring.
pub const TEST_KID: &str = "test-kid";

/// The OTP pepper of the test policy.
pub const TEST_PEPPER: &[u8] = b"integration-test-pepper";

/// The KEK of the test policy (S-05 sealing); tests unseal stored blobs with it.
pub const TEST_KEK: [u8; 32] = [7u8; 32];

/// Policy knobs a scenario can override.
pub struct TestOptions {
    /// Whether first-login registration is allowed.
    pub allow_registration: bool,
    /// S-31 domain allowlist; empty = allow all.
    pub allowed_email_domains: Vec<String>,
    /// S-24 credential-redemption cap per IP per minute.
    pub login_per_ip_minute: u32,
    /// Whether the instance believes `X-Forwarded-For` (S-24 trusted-proxy stance). The
    /// harness defaults to `true` because the test transport has no socket peer to fall back
    /// to; the attack tests flip it to prove the untrusted default ignores the header.
    pub trust_proxy_headers: bool,
    /// KV backend override — the attack suite injects failing stores to prove fail-closed.
    pub kv: Option<Arc<dyn Kv>>,
    /// OIDC providers (S-01); the oidc suite points these at an in-process mock issuer.
    pub oidc_providers: Vec<ProviderConfig>,
    /// S-06 step-up window in minutes.
    pub step_up_minutes: u64,
}

impl Default for TestOptions {
    fn default() -> Self {
        Self {
            allow_registration: true,
            allowed_email_domains: Vec::new(),
            login_per_ip_minute: 10,
            trust_proxy_headers: true,
            kv: None,
            oidc_providers: Vec::new(),
            step_up_minutes: 15,
        }
    }
}

/// A [`Kv`] that answers every operation with [`Error::Kv`], simulating a Redis outage.
///
/// Exists so the S-09/S-24 "fail closed" clauses are provable: with the in-memory KV nothing
/// ever fails, so the fallback path would otherwise be dead code that no test ever reaches.
pub struct FailingKv;

#[async_trait::async_trait]
impl Kv for FailingKv {
    async fn ping(&self) -> pub_core::Result<()> {
        Err(down())
    }

    async fn get(&self, _key: &str) -> pub_core::Result<Option<String>> {
        Err(down())
    }

    async fn set_ttl(&self, _key: &str, _value: &str, _ttl: StdDuration) -> pub_core::Result<()> {
        Err(down())
    }

    async fn incr(&self, _key: &str, _ttl: StdDuration) -> pub_core::Result<u64> {
        Err(down())
    }

    async fn del(&self, _key: &str) -> pub_core::Result<()> {
        Err(down())
    }

    async fn publish(&self, _topic: &str, _payload: &str) -> pub_core::Result<()> {
        Err(down())
    }

    async fn subscribe(&self, _topic: &str) -> pub_core::Result<pub_core::traits::MessageStream> {
        Err(down())
    }
}

fn down() -> pub_core::Error {
    pub_core::Error::Kv { message: "simulated kv outage".to_owned() }
}

/// Full in-memory application under test.
pub struct TestApp {
    /// The complete router (middleware included).
    pub router: Router,
    /// Repository handles for direct state assertions.
    pub repos: Repositories,
    /// The KV store backing blocklists and rate counters.
    pub kv: Arc<MemoryKv>,
    /// The outbox — OTP codes are read from here.
    pub mailer: Arc<InMemoryMailer>,
    clock: Arc<Mutex<DateTime<Utc>>>,
}

impl TestApp {
    /// Default app: registration open, no domain allowlist.
    pub async fn new() -> Self {
        Self::with_options(TestOptions::default()).await
    }

    /// App with scenario-specific policy knobs.
    pub async fn with_options(options: TestOptions) -> Self {
        let mut settings = Settings {
            database: DatabaseConfig { kind: DatabaseKind::Sqlite, url: None, path: ":memory:".to_owned() },
            ..Settings::default()
        };
        settings.blob.kind = BlobKind::Memory;
        settings.kv.kind = KvKind::Memory;
        settings.server.trust_proxy_headers = options.trust_proxy_headers;
        settings.server.public_url = INSTANCE_ORIGIN.to_owned();

        let db = SqliteDb::connect(&settings.database).await.expect("connect :memory:");
        db.run_migrations().await.expect("migrate");
        let repos = db.repositories();

        let kv = Arc::new(MemoryKv::new());
        let kv_handle: Arc<dyn Kv> = options.kv.clone().unwrap_or_else(|| Arc::clone(&kv) as Arc<dyn Kv>);
        let mailer = Arc::new(InMemoryMailer::new());
        let keyring = Keyring::new(TEST_KID, TEST_JWT_SEED, &[]).expect("test keyring");
        let policy = AuthPolicy {
            access_ttl: StdDuration::from_secs(15 * 60),
            session_limits: SessionLimits::DEFAULT,
            otp_pepper: TEST_PEPPER.to_vec(),
            token_prefix: "pub_".to_owned(),
            allow_registration: options.allow_registration,
            allowed_email_domains: options.allowed_email_domains,
            otp_per_email_hour: 5,
            otp_per_ip_hour: 20,
            login_per_ip_minute: options.login_per_ip_minute,
            kek: TEST_KEK.to_vec(),
            step_up_window: StdDuration::from_secs(options.step_up_minutes * 60),
            totp_issuer: "Pub".to_owned(),
        };
        let oidc = OidcClient::new(options.oidc_providers, INSTANCE_ORIGIN).expect("oidc client");
        let auth = Arc::new(AuthService::new(
            repos.clone(),
            Arc::clone(&kv_handle),
            Arc::clone(&mailer) as Arc<dyn Mailer>,
            keyring,
            policy,
            Arc::new(OsRandom),
            oidc,
        ));

        let clock = Arc::new(Mutex::new(t0()));
        let clock_handle = Arc::clone(&clock);
        let state = AppState::new(settings, repos.clone(), Arc::new(ObjectStoreBlob::memory()), kv_handle, auth)
            .with_clock(Arc::new(move || *clock_handle.lock().expect("clock mutex")));
        Self { router: pub_api::router(state), repos, kv, mailer, clock }
    }

    /// The injected current time.
    pub fn now(&self) -> DateTime<Utc> {
        *self.clock.lock().expect("clock mutex")
    }

    /// Advances the injected clock.
    pub fn advance(&self, delta: Duration) {
        *self.clock.lock().expect("clock mutex") += delta;
    }

    /// Sends a request and parses the JSON body (`null` for empty bodies).
    pub async fn send(&self, request: Request<Body>) -> ApiResponse {
        let response = self.router.clone().oneshot(request).await.expect("infallible router");
        let (parts, body) = response.into_parts();
        let bytes = body.collect().await.expect("read body").to_bytes();
        let json = if bytes.is_empty() {
            serde_json::Value::Null
        } else {
            serde_json::from_slice(&bytes).expect("response body must be valid JSON")
        };
        ApiResponse { status: parts.status, headers: parts.headers, json }
    }

    /// Fires every request concurrently on the shared router and returns the responses in
    /// completion-independent order (index = input order). Used by the race tests.
    pub async fn send_concurrent(&self, requests: Vec<Request<Body>>) -> Vec<ApiResponse> {
        let mut set = tokio::task::JoinSet::new();
        for (index, request) in requests.into_iter().enumerate() {
            let router = self.router.clone();
            set.spawn(async move {
                let response = router.oneshot(request).await.expect("infallible router");
                let (parts, body) = response.into_parts();
                let bytes = body.collect().await.expect("read body").to_bytes();
                let json = if bytes.is_empty() {
                    serde_json::Value::Null
                } else {
                    serde_json::from_slice(&bytes).expect("response body must be valid JSON")
                };
                (index, ApiResponse { status: parts.status, headers: parts.headers, json })
            });
        }
        let mut done = set.join_all().await;
        done.sort_by_key(|(index, _)| *index);
        done.into_iter().map(|(_, response)| response).collect()
    }

    /// The raw KV value under `key` (attack tests inspect counters and pending records).
    pub async fn kv_get(&self, key: &str) -> Option<String> {
        use pub_core::traits::Kv as _;
        self.kv.get(key).await.expect("in-memory kv never fails")
    }

    /// JSON request with the S-12 custom header, from the given client IP.
    pub fn request(
        &self,
        method: Method,
        path: &str,
        bearer: Option<&str>,
        body: Option<serde_json::Value>,
        ip: &str,
    ) -> Request<Body> {
        let mut builder = Request::builder()
            .method(method)
            .uri(path)
            .header("x-pub-request", "1")
            .header("x-forwarded-for", ip)
            .header(header::USER_AGENT, "pub-tests/1.0");
        if let Some(token) = bearer {
            builder = builder.header(header::AUTHORIZATION, format!("Bearer {token}"));
        }
        match body {
            Some(json) => builder
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(serde_json::to_vec(&json).expect("serialize body")))
                .expect("build request"),
            None => builder.body(Body::empty()).expect("build request"),
        }
    }

    /// POST with a JSON body from the default test IP.
    pub async fn post(&self, path: &str, bearer: Option<&str>, body: serde_json::Value) -> ApiResponse {
        self.send(self.request(Method::POST, path, bearer, Some(body), DEFAULT_IP)).await
    }

    /// Bodiless POST (logout, revoke-all).
    pub async fn post_empty(&self, path: &str, bearer: Option<&str>) -> ApiResponse {
        self.send(self.request(Method::POST, path, bearer, None, DEFAULT_IP)).await
    }

    /// GET.
    pub async fn get(&self, path: &str, bearer: Option<&str>) -> ApiResponse {
        self.send(self.request(Method::GET, path, bearer, None, DEFAULT_IP)).await
    }

    /// DELETE.
    pub async fn delete(&self, path: &str, bearer: Option<&str>) -> ApiResponse {
        self.send(self.request(Method::DELETE, path, bearer, None, DEFAULT_IP)).await
    }

    /// Requests an OTP for `email` and returns `(pending_id, code)` — the code is read from
    /// the in-memory outbox like a user reading their inbox.
    pub async fn request_otp(&self, email: &str) -> (String, String) {
        let sent_before = self.mailer.sent().len();
        let response = self.post("/api/v1/auth/otp/request", None, serde_json::json!({ "email": email })).await;
        assert_eq!(response.status, StatusCode::OK, "otp request failed: {:?}", response.json);
        let pending_id = response.json["data"]["pending_id"].as_str().expect("pending_id").to_owned();
        let sent = self.mailer.sent();
        assert_eq!(sent.len(), sent_before + 1, "exactly one mail must be sent");
        let code = extract_code(&sent.last().expect("mail").text);
        (pending_id, code)
    }

    /// Full OTP login; returns the login payload (`data` object).
    pub async fn login(&self, email: &str) -> serde_json::Value {
        let (pending_id, code) = self.request_otp(email).await;
        let response = self
            .post(
                "/api/v1/auth/otp/verify",
                None,
                serde_json::json!({ "pending_id": pending_id, "email": email, "code": code }),
            )
            .await;
        assert_eq!(response.status, StatusCode::OK, "otp verify failed: {:?}", response.json);
        response.json["data"].clone()
    }
}

/// Default client IP for requests (documentation range).
pub const DEFAULT_IP: &str = "203.0.113.7";

/// The instance's configured public origin — the S-12 cross-site guard compares against it.
pub const INSTANCE_ORIGIN: &str = "https://pub.corp.test";

/// Parsed response triple.
pub struct ApiResponse {
    /// HTTP status.
    pub status: StatusCode,
    /// Response headers.
    pub headers: HeaderMap,
    /// Parsed JSON body (`null` when empty).
    pub json: serde_json::Value,
}

impl ApiResponse {
    /// The envelope error code, panicking on non-error shapes.
    pub fn error_code(&self) -> &str {
        self.json["error"]["code"].as_str().expect("error envelope with code")
    }
}

/// Pulls the 8-digit code out of an OTP email body.
pub fn extract_code(text: &str) -> String {
    text.split(|c: char| !c.is_ascii_digit())
        .find(|run| run.len() == 8)
        .unwrap_or_else(|| panic!("no 8-digit code in mail body:\n{text}"))
        .to_owned()
}

/// A code guaranteed to differ from `code` while staying 8 digits.
pub fn wrong_code(code: &str) -> String {
    if code == "00000000" { "00000001".to_owned() } else { "00000000".to_owned() }
}
