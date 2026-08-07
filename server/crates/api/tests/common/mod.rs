//! Shared integration-test harness: full router over in-memory backends with a controllable
//! clock (docs/rules/rust.md — no containers, deterministic time).
//!
//! Not every test binary uses every helper — silence per-binary dead-code noise.
#![allow(dead_code)]

pub mod oidc;
pub mod upstream;

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
use pub_core::event::{EventSink, NoopEventSink};
use pub_core::session::SessionLimits;
use pub_core::token::{NewToken, TokenScope};
use pub_core::traits::JobLock;
use pub_core::traits::{BlobStore, Kv, Mailer, Repositories};
use pub_core::{OrgId, UserId};
use pub_db_sqlite::SqliteDb;
use pub_jobs::InMemoryJobLock;
use pub_kv::MemoryKv;
use pub_mail::InMemoryMailer;
use pub_registry::{RegistryPolicy, RegistryService, UpstreamClient, UpstreamService, UpstreamServicePolicy};
use tower::ServiceExt as _;

use upstream::MockUpstream;

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
    /// The instance's public URL. The protocol suite points it at a reverse-proxy subpath to
    /// prove sharp edge 8.
    pub public_url: String,
    /// Decision 05: flip the pub protocol to token-only reads.
    pub require_auth_for_read: bool,
    /// Blob backend override — the protocol suite runs byte-stability against fs as well as
    /// the in-memory store.
    pub blob: Option<Arc<dyn BlobStore>>,
    /// S-24 failed-token-auth budget per IP per minute.
    pub token_auth_fail_per_ip_minute: u32,
    /// S-24 publish-upload budget per org per hour.
    pub publish_per_hour_org: u32,
    /// Decision 07: attach the read-through proxy over a scripted upstream. `false` leaves
    /// `AppState::upstream` empty, which is what `[upstream].enabled = false` produces.
    pub upstream: bool,
    /// How long a proxied listing stays fresh before upstream is re-asked.
    pub upstream_listing_ttl_secs: i64,
    /// Largest archive accepted from upstream.
    pub upstream_max_archive_bytes: u64,
    /// Consecutive upstream failures that trip the circuit breaker.
    pub upstream_circuit_failure_threshold: u32,
    /// How long the breaker stays open before letting a probe through.
    pub upstream_circuit_open_secs: i64,
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
            public_url: INSTANCE_ORIGIN.to_owned(),
            require_auth_for_read: false,
            blob: None,
            token_auth_fail_per_ip_minute: 30,
            publish_per_hour_org: 30,
            upstream: false,
            upstream_listing_ttl_secs: 300,
            upstream_max_archive_bytes: 100 * 1024 * 1024,
            upstream_circuit_failure_threshold: 5,
            upstream_circuit_open_secs: 30,
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
    /// The assembled state, so a scenario can rebuild the app over the same backends.
    pub state: AppState,
    /// The scripted upstream, when the scenario enabled the proxy.
    pub upstream: Option<Arc<MockUpstream>>,
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
        settings.server.public_url = options.public_url.clone();
        settings.registry.require_auth_for_read = options.require_auth_for_read;
        settings.registry.rate_limit.publish_per_hour_org = options.publish_per_hour_org;

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
            token_auth_fail_per_ip_minute: options.token_auth_fail_per_ip_minute,
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
        let blob: Arc<dyn BlobStore> =
            options.blob.clone().unwrap_or_else(|| Arc::new(ObjectStoreBlob::memory()) as Arc<dyn BlobStore>);
        let registry = Arc::new(RegistryService::new(
            repos.clone(),
            Arc::clone(&blob),
            Arc::new(InMemoryJobLock::new()) as Arc<dyn JobLock>,
            Arc::new(NoopEventSink) as Arc<dyn EventSink>,
            RegistryPolicy::default(),
        ));
        let mock_upstream = options.upstream.then(|| Arc::new(MockUpstream::default()));
        let proxy = mock_upstream.as_ref().map(|mock| {
            Arc::new(UpstreamService::new(
                repos.clone(),
                Arc::clone(&blob),
                Arc::clone(mock) as Arc<dyn UpstreamClient>,
                Arc::new(NoopEventSink) as Arc<dyn EventSink>,
                UpstreamServicePolicy {
                    listing_ttl: Duration::seconds(options.upstream_listing_ttl_secs),
                    max_archive_bytes: options.upstream_max_archive_bytes,
                    circuit_failure_threshold: options.upstream_circuit_failure_threshold,
                    circuit_open: Duration::seconds(options.upstream_circuit_open_secs),
                    max_concurrent_fetches: 8,
                },
            ))
        });

        let state = AppState::new(settings, repos.clone(), blob, kv_handle, auth, registry)
            .with_upstream(proxy)
            .with_clock(Arc::new(move || *clock_handle.lock().expect("clock mutex")));
        Self { router: pub_api::router(state.clone()), repos, kv, mailer, state, upstream: mock_upstream, clock }
    }

    /// The scripted upstream; panics when the scenario did not enable the proxy.
    pub fn mock_upstream(&self) -> &MockUpstream {
        self.upstream.as_deref().expect("this scenario did not enable the upstream proxy")
    }

    /// Rebuilds the whole application over the **same** backends, as a process restart would.
    ///
    /// The point is what survives: the database rows, the blob objects, and the KV entries are
    /// the durable state, and every in-process cache, lock, and router is thrown away. The
    /// byte-stability conformance test publishes on one instance and downloads from another.
    pub fn restart(&self) -> Self {
        let settings = (*self.state.settings).clone();
        let registry = Arc::new(RegistryService::new(
            self.state.repos.clone(),
            Arc::clone(&self.state.blob),
            Arc::new(InMemoryJobLock::new()) as Arc<dyn JobLock>,
            Arc::new(NoopEventSink) as Arc<dyn EventSink>,
            RegistryPolicy::default(),
        ));
        let clock_handle = Arc::clone(&self.clock);
        let state = AppState::new(
            settings,
            self.state.repos.clone(),
            Arc::clone(&self.state.blob),
            Arc::clone(&self.state.kv),
            Arc::clone(&self.state.auth),
            registry,
        )
        .with_upstream(self.state.upstream.clone())
        .with_clock(Arc::new(move || *clock_handle.lock().expect("clock mutex")));
        Self {
            router: pub_api::router(state.clone()),
            repos: self.repos.clone(),
            kv: Arc::clone(&self.kv),
            mailer: Arc::clone(&self.mailer),
            state,
            upstream: self.upstream.clone(),
            clock: Arc::clone(&self.clock),
        }
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
        let raw = self.send_raw(request).await;
        let json = if raw.body.is_empty() {
            serde_json::Value::Null
        } else {
            serde_json::from_slice(&raw.body).unwrap_or_else(|err| {
                panic!("response body must be valid JSON ({err}): {:?}", String::from_utf8_lossy(&raw.body))
            })
        };
        ApiResponse { status: raw.status, headers: raw.headers, json }
    }

    /// Sends a request and keeps the body as bytes (archives are not JSON).
    pub async fn send_raw(&self, request: Request<Body>) -> RawResponse {
        let response = self.router.clone().oneshot(request).await.expect("infallible router");
        let (parts, body) = response.into_parts();
        let bytes = body.collect().await.expect("read body").to_bytes();
        RawResponse { status: parts.status, headers: parts.headers, body: bytes.to_vec() }
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

// --- pub protocol (docs/protocol.md) ---

/// The `Accept` header the real `dart pub` client sends on API requests.
pub const PUB_ACCEPT: &str = "application/vnd.pub.v2+json";

/// The media type every pub-protocol JSON response must carry.
pub const PUB_MEDIA_TYPE: &str = "application/vnd.pub.v2+json";

impl TestApp {
    /// A request shaped like the pub client's: bearer via `Authorization`, `Accept` per the
    /// spec, and **none** of the app-API headers (`x-pub-request`, JSON content types) — the
    /// CLI cannot send those, so a pub route that needed one would be unusable.
    pub fn pub_request(&self, method: Method, path: &str, token: Option<&str>, accept: Option<&str>) -> Request<Body> {
        let mut builder = Request::builder()
            .method(method)
            .uri(path)
            .header("x-forwarded-for", DEFAULT_IP)
            .header(header::USER_AGENT, "Dart pub 3.9.0");
        if let Some(accept) = accept {
            builder = builder.header(header::ACCEPT, accept);
        }
        if let Some(token) = token {
            builder = builder.header(header::AUTHORIZATION, format!("Bearer {token}"));
        }
        builder.body(Body::empty()).expect("build request")
    }

    /// GET a pub-protocol JSON endpoint with the client's own `Accept`.
    pub async fn pub_get(&self, path: &str, token: Option<&str>) -> ApiResponse {
        self.send(self.pub_request(Method::GET, path, token, Some(PUB_ACCEPT))).await
    }

    /// GET with an explicit (or absent) `Accept` — sharp edge 6.
    pub async fn pub_get_accepting(&self, path: &str, token: Option<&str>, accept: Option<&str>) -> ApiResponse {
        self.send(self.pub_request(Method::GET, path, token, accept)).await
    }

    /// GET keeping the raw bytes (archive downloads).
    pub async fn pub_get_raw(&self, path: &str, token: Option<&str>) -> RawResponse {
        self.send_raw(self.pub_request(Method::GET, path, token, None)).await
    }

    /// POST a `multipart/form-data` body with the archive in field `file`, exactly as
    /// `http.MultipartRequest` builds it in the client.
    pub async fn pub_upload(&self, path: &str, token: Option<&str>, archive: &[u8]) -> RawResponse {
        const BOUNDARY: &str = "dart-pub-boundary-4242";
        let mut body = Vec::new();
        body.extend_from_slice(format!("--{BOUNDARY}\r\n").as_bytes());
        body.extend_from_slice(
            b"content-disposition: form-data; name=\"file\"; filename=\"package.tar.gz\"\r\n\
              content-type: application/octet-stream\r\n\r\n",
        );
        body.extend_from_slice(archive);
        body.extend_from_slice(format!("\r\n--{BOUNDARY}--\r\n").as_bytes());

        let mut builder = Request::builder()
            .method(Method::POST)
            .uri(path)
            .header("x-forwarded-for", DEFAULT_IP)
            .header(header::USER_AGENT, "Dart pub 3.9.0")
            .header(header::CONTENT_TYPE, format!("multipart/form-data; boundary={BOUNDARY}"));
        if let Some(token) = token {
            builder = builder.header(header::AUTHORIZATION, format!("Bearer {token}"));
        }
        self.send_raw(builder.body(Body::from(body)).expect("build request")).await
    }

    /// Turns an absolute URL the server advertised into the path its listener actually sees.
    ///
    /// This *is* the reverse proxy of docs/protocol.md sharp edge 8: it asserts the URL starts
    /// with the instance's configured public URL — **path prefix included** — and strips
    /// exactly that much, which is what nginx does when the app is mounted under a subpath.
    /// A URL that escapes the public base fails the assertion instead of quietly 404ing.
    pub fn proxied(&self, url: &str) -> String {
        let public = self.state.settings.server.public_url.trim_end_matches('/');
        let rest =
            url.strip_prefix(public).unwrap_or_else(|| panic!("{url} is not under the instance public url {public}"));
        if rest.is_empty() { "/".to_owned() } else { rest.to_owned() }
    }

    /// Runs the three-step publish flow against `base` and returns the finalize response.
    ///
    /// Deliberately follows the client's own algorithm — GET the ticket, POST to whatever
    /// `url` it names, GET whatever `Location` comes back — so a change to any of those URLs
    /// is caught here rather than by a hardcoded path.
    pub async fn publish(&self, base: &str, token: &str, archive: &[u8]) -> ApiResponse {
        let ticket = self.pub_get(&format!("{base}/api/packages/versions/new"), Some(token)).await;
        assert_eq!(ticket.status, StatusCode::OK, "publish step 1 failed: {:?}", ticket.json);
        let url = ticket.json["url"].as_str().expect("upload url").to_owned();
        let upload = self.pub_upload(&self.proxied(&url), Some(token), archive).await;
        assert_eq!(upload.status, StatusCode::NO_CONTENT, "publish step 2 must answer 204");
        let location = upload.headers[header::LOCATION].to_str().expect("location").to_owned();
        self.pub_get(&self.proxied(&location), Some(token)).await
    }

    /// Signs `email` in, creates org `slug`, and returns `(access_token, org_id)`.
    pub async fn org_owner(&self, email: &str, slug: &str) -> (String, OrgId) {
        let login = self.login(email).await;
        let access = login["access_token"].as_str().expect("access token").to_owned();
        let created = self.post("/api/v1/orgs", Some(&access), serde_json::json!({ "name": slug, "slug": slug })).await;
        assert_eq!(created.status, StatusCode::OK, "org creation failed: {:?}", created.json);
        let org: OrgId = created.json["data"]["id"].as_str().expect("org id").parse().expect("uuid");
        (access, org)
    }

    /// Mints a CLI token through the real app API (S-13 show-once path).
    pub async fn mint_token(&self, access: &str, org: OrgId, scopes: &[&str]) -> String {
        let body = serde_json::json!({ "org_id": org.to_string(), "scopes": scopes, "label": "conformance" });
        let response = self.post("/api/v1/tokens", Some(access), body).await;
        assert_eq!(response.status, StatusCode::OK, "token mint failed: {:?}", response.json);
        response.json["data"]["secret"].as_str().expect("secret").to_owned()
    }

    /// Inserts a CLI token straight into the repository, returning its plaintext.
    ///
    /// The mint API does not expose package patterns or custom expiry yet; the conformance
    /// suite needs both to exercise S-13 narrowing and expired-credential handling.
    pub async fn insert_token(
        &self,
        user: UserId,
        org: OrgId,
        scopes: &[TokenScope],
        patterns: &[&str],
        expires_at: Option<DateTime<Utc>>,
    ) -> String {
        let minted = pub_auth::token::mint("pub_", &OsRandom);
        self.repos
            .tokens
            .create(
                NewToken {
                    user_id: user,
                    org_id: org,
                    name: "direct".to_owned(),
                    token_hash: minted.hash.clone(),
                    display_hint: minted.display_hint.clone(),
                    scopes: scopes.to_vec(),
                    package_patterns: patterns.iter().map(|p| (*p).to_owned()).collect(),
                    expires_at,
                },
                self.now(),
            )
            .await
            .expect("insert token");
        minted.secret
    }

    /// The user id behind an access token's session (tests seed memberships directly).
    pub async fn user_of(&self, email: &str) -> UserId {
        self.repos.users.find_by_email(email).await.expect("lookup").expect("user exists").id
    }
}

/// A response whose body was not parsed.
pub struct RawResponse {
    /// HTTP status.
    pub status: StatusCode,
    /// Response headers.
    pub headers: HeaderMap,
    /// Raw body bytes.
    pub body: Vec<u8>,
}

/// Builds a `.tar.gz` package archive with a minimal valid pubspec.
pub fn package_archive(name: &str, version: &str) -> Vec<u8> {
    use std::io::Write as _;

    let pubspec = format!("name: {name}\nversion: {version}\ndescription: Conformance fixture.\n");
    let mut builder = tar::Builder::new(Vec::new());
    let mut append = |path: &str, content: &str| {
        let mut header = tar::Header::new_gnu();
        header.set_size(content.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        builder.append_data(&mut header, path, content.as_bytes()).expect("append");
    };
    append("pubspec.yaml", &pubspec);
    append("README.md", &format!("# {name}\n\nFixture package.\n"));
    let tar = builder.into_inner().expect("finish tar");
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    encoder.write_all(&tar).expect("gzip");
    encoder.finish().expect("finish gzip")
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
