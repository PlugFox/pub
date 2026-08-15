//! Request guards: the S-12 mutation guard (custom header + JSON-only bodies), the KV-backed
//! auth rate-limit layer (S-24), the read-path buckets (S-24.f) and the write-path buckets
//! (S-24.g).
//!
//! Middleware order (docs/rules/api.md): request-id → tracing → security headers → CORS →
//! load-shed → timeout → body cap → rate limit → auth extractors. The S-12 guard and the auth
//! buckets scope themselves to app-API paths — the pub protocol surface (`/o/…`, `/pub/…`) has
//! its own contract and must never inherit those checks. The **read** bucket is the one guard
//! that deliberately spans both planes: `dart pub get` is where the read volume actually is,
//! and a limit the protocol plane does not have is not a limit. The **write** bucket is the
//! mirror image — app API only, mounted *inside* the S-12 guard so a cross-origin request the
//! guard refuses spends nothing.
//!
//! One identity per request (decision 32, closes D58). `RequestIdentity` is resolved from the
//! request alone, at most once, and stashed in the request extensions; the read bucket, the
//! write bucket and [`crate::extract::AuthContext`] all consume that one resolution. What the
//! stash carries is a **verified signature**, never an authorization verdict: the extractor
//! still runs revocation (S-09), suspension, step-up (S-06) and scope on every request.
//!
//! The stash is unforgeable by construction rather than by validation: `http::Extensions` is a
//! per-request typemap that nothing on the wire can reach — there is no header, body or URL
//! form that becomes an extension — and the only two writers of this type are the two functions
//! below. The type itself is **private to this module**, so nothing else in the crate can even
//! name it to insert one.

use axum::Json;
use axum::extract::{Request, State};
use axum::http::{Extensions, HeaderMap, Method, StatusCode, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use chrono::Duration;
use pub_auth::jwt::Claims;
use pub_auth::ratelimit::{self, Decision};
use pub_core::Error;
use pub_core::audit::{AuditActor, AuditResult, NewAuditEvent};

use crate::envelope::ErrorEnvelope;
use crate::error::ApiError;
use crate::extract::{client_ip, client_meta};
use crate::state::AppState;

/// Custom header every state-changing app-API request must carry (S-12): forces a CORS
/// preflight, so cross-origin form posts and no-cors fetches can never mutate state.
pub const CUSTOM_HEADER: &str = "x-pub-request";

/// S-12 guard for app-API mutations: `Origin`/`Sec-Fetch-Site` verification, the custom
/// header, and JSON-only bodies.
///
/// The three checks are independent layers on purpose. The custom header forces a CORS
/// preflight (which, with no permissive CORS layer configured, browsers fail) — but it relies
/// on the browser to enforce it. The `Origin`/`Sec-Fetch-Site` comparison is decided
/// *server-side* against the instance's own public URL and therefore also covers a browser
/// that never sends the preflight. Non-browser clients (CLI, curl, CI) send neither header and
/// are unaffected: absence is not evidence of a cross-site request, presence of a *foreign*
/// value is.
///
/// **What "the app-API plane" means is [`crate::hygiene::is_app_api`], not a local spelling of
/// it.** This guard and [`write_rate_limit`] are mounted as an outer/inner pair whose whole
/// contract is that the inner one never sees a request the outer one would refuse; two
/// spellings of the plane break that contract on exactly the paths where they differ, in
/// silence. See that function for the one such path this codebase actually had.
pub async fn mutation_guard(State(state): State<AppState>, request: Request, next: Next) -> Response {
    let is_api = crate::hygiene::is_app_api(request.uri().path());
    let is_mutation = !matches!(*request.method(), Method::GET | Method::HEAD | Method::OPTIONS);
    if is_api && is_mutation {
        if let Some(denial) = cross_site_denial(request.headers(), &state.settings.server.public_url) {
            let body = ErrorEnvelope::new("forbidden", denial);
            return (StatusCode::FORBIDDEN, Json(body)).into_response();
        }
        let header_ok =
            request.headers().get(CUSTOM_HEADER).and_then(|value| value.to_str().ok()).is_some_and(|v| v == "1");
        if !header_ok {
            let body = ErrorEnvelope::new("forbidden", format!("state-changing requests require {CUSTOM_HEADER}: 1"));
            return (StatusCode::FORBIDDEN, Json(body)).into_response();
        }
        // Reject non-JSON content types (S-12). A missing content type on a bodiless
        // mutation (logout, revoke-all) is fine; routes with bodies enforce JSON via `Json`.
        if let Some(content_type) = request.headers().get(header::CONTENT_TYPE) {
            let json_ok = content_type
                .to_str()
                .map(|value| value.trim().to_ascii_lowercase().starts_with("application/json"))
                .unwrap_or(false);
            if !json_ok {
                let body = ErrorEnvelope::new("unsupported_media_type", "state-changing requests must send JSON");
                return (StatusCode::UNSUPPORTED_MEDIA_TYPE, Json(body)).into_response();
            }
        }
    }
    next.run(request).await
}

/// Server-side cross-site verdict for a mutation (S-12); `Some(reason)` means reject.
///
/// `Sec-Fetch-Site` is authoritative when present — browsers set it and page script cannot
/// forge it. `Origin` is then compared against the instance's configured public origin;
/// `null` (sandboxed iframe, some redirects) never matches and is rejected.
fn cross_site_denial(headers: &axum::http::HeaderMap, public_url: &str) -> Option<String> {
    if let Some(site) = headers.get("sec-fetch-site").and_then(|value| value.to_str().ok())
        && !matches!(site, "same-origin" | "same-site" | "none")
    {
        return Some(format!("cross-site request rejected (Sec-Fetch-Site: {site})"));
    }
    let origin = headers.get(header::ORIGIN).and_then(|value| value.to_str().ok())?;
    let actual = origin_of(origin);
    if actual.is_some() && actual == origin_of(public_url) {
        return None;
    }
    Some("cross-origin request rejected (Origin does not match this instance)".to_owned())
}

/// Scheme + host + port of a URL, as the comparable origin triple.
fn origin_of(raw: &str) -> Option<(String, String, Option<u16>)> {
    let parsed = url::Url::parse(raw).ok()?;
    let host = parsed.host_str()?.to_ascii_lowercase();
    Some((parsed.scheme().to_ascii_lowercase(), host, parsed.port_or_known_default()))
}

/// Per-IP rate limits on the unauthenticated auth plane (S-24), KV-backed.
///
/// Two buckets, because the two endpoint classes are abused differently:
/// - **OTP request** — 20/h/IP: mail-bomb and enumeration budget (the per-email 5/h cap lives
///   inside the flow, where the parsed body is available).
/// - **Credential redemption** (`otp/verify`, `refresh`, `totp/verify`, and the OIDC
///   start/callback pair) — 10/min/IP, S-24's "login" limit. Without it the only brake on
///   online code guessing is the per-code budget, which an attacker sidesteps simply by
///   requesting fresh codes; a stolen refresh token could be probed unthrottled; and
///   unthrottled OIDC starts would mint unlimited KV flow records. The per-attempt MFA
///   backoff (S-05) stacks on top of this bucket for `totp/verify`.
///
/// KV outage → the error propagates as 503: auth-abuse limiting fails **closed** (S-24).
pub async fn auth_rate_limit(State(state): State<AppState>, request: Request, next: Next) -> Response {
    // Runtime settings (decision 09), read per request: an admin lowering a limit takes effect
    // on the next request, not on the next restart.
    let limits = state.runtime.current().rate_limits;
    let bucket = credential_bucket(request.method(), request.uri().path()).map(|bucket| match bucket {
        CredentialBucket::Otp => ("otp_per_ip", "otp", limits.otp_per_ip_hour, Duration::hours(1)),
        CredentialBucket::Login => ("login_per_ip", "login", limits.login_per_ip_minute, Duration::minutes(1)),
    });

    if let Some((limit_name, bucket_name, limit, window)) = bucket {
        let now = (state.clock)();
        // Unresolvable IPs share one bucket — still bounded, never a bypass.
        let ip = client_ip(request.headers(), request.extensions(), state.trust_proxy_headers())
            .unwrap_or_else(|| "unknown".to_owned());
        let key = format!("rl:{bucket_name}:ip:{ip}");
        // Fails closed onto this instance's own table when the KV is unreachable (S-24.e): the
        // former `Err(err) => 503` took sign-in down instance-wide for the length of a Redis
        // blip, which is the one thing an abuse limiter must never do.
        let decision = ratelimit::hit_or_fallback(
            state.kv.as_ref(),
            state.auth.rate_limit_fallback(),
            limit_name,
            &key,
            limit,
            window,
            now,
        )
        .await;
        if let Decision::Limited { retry_after_secs, .. } = decision {
            trip(
                &state,
                client_meta(request.headers(), request.extensions(), state.trust_proxy_headers()),
                AUTH_THROTTLED,
                limit_name,
                decision,
                now,
            )
            .await;
            return ApiError(Error::RateLimited { retry_after_secs }).into_response();
        }
    }
    next.run(request).await
}

/// Audit action for a credential-plane throttle trip: sign-in, redemption, token auth.
///
/// Kept distinct from [`READ_THROTTLED`] because an operator filtering the audit log for
/// credential abuse must not have that signal diluted by a scraper hitting the read quota —
/// which, with the read path bucketed, is by far the more common trip.
const AUTH_THROTTLED: &str = "auth.throttled";

/// Audit action for a read-path throttle trip (S-24.f).
const READ_THROTTLED: &str = "read.throttled";

/// Audit action for a write-path throttle trip (S-24.g).
///
/// A third name rather than a reused one, for [`READ_THROTTLED`]'s reason in the other
/// direction: an operator filtering the log for refused credentials must not have to read past
/// refused writes, and a refused write is not evidence about the credential plane.
const WRITE_THROTTLED: &str = "write.throttled";

/// Which of the six credential-plane buckets a request spends, if any (S-24, S-24.g).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CredentialBucket {
    /// `otp/request` — 20/h/IP, the mail-bomb and enumeration budget.
    Otp,
    /// Credential redemption — 10/min/IP, S-24's "login" limit.
    Login,
}

/// The credential bucket this request spends, or `None`.
///
/// **One predicate, two readers.** [`auth_rate_limit`] charges what this returns and
/// [`write_rate_limit`] exempts exactly the same set (S-24.g: "the six credential endpoints are
/// excluded, not charged twice"). Two lists would drift, and the drift is silent in both
/// directions — a mutation charged by an open bucket *and* a closed one, or one charged by
/// neither.
fn credential_bucket(method: &Method, path: &str) -> Option<CredentialBucket> {
    if method != Method::POST {
        return None;
    }
    if path == "/api/v1/auth/otp/request" {
        return Some(CredentialBucket::Otp);
    }
    is_credential_redemption(path).then_some(CredentialBucket::Login)
}

/// Records a throttle trip: always a counter, an audit row only on the window's **first**
/// refusal (S-22, S-24).
///
/// One row per refused *request* would hand an attacker the row count of a table that has no
/// retention yet — the throttle would become a cheaper way to fill `audit_log` than the traffic
/// it refuses. One row per bucket per window says the same thing; the counter carries volume.
///
/// Takes the client metadata **by value**, not the `Request` it came from: `&Request<Body>` is
/// not `Send` (the body is not `Sync`), so holding one across the audit `await` would make this
/// middleware's future non-`Send` — which axum reports as an unrelated `Service` bound failure
/// on the whole router, sixty lines away from the cause.
async fn trip(
    state: &AppState,
    meta: pub_auth::flows::ClientMeta,
    action: &'static str,
    limit_name: &'static str,
    decision: Decision,
    now: chrono::DateTime<chrono::Utc>,
) {
    metrics::counter!("rate_limit_trips_total", "limit" => limit_name).increment(1);
    if !decision.is_first_refusal() {
        return;
    }
    let event = NewAuditEvent {
        actor: AuditActor::System,
        ip: meta.ip,
        user_agent: meta.user_agent,
        org_id: None,
        action: action.to_owned(),
        target: None,
        result: AuditResult::Failure,
        metadata: Some(serde_json::json!({ "limit": limit_name })),
    };
    // Failures must not mask the 429 the caller is about to receive.
    if let Err(err) = state.repos.audit.append(event, now).await {
        tracing::error!(error = %err, "audit append failed for throttle trip");
    }
}

/// An access token whose **signature** has been verified, plus the exact credential string it
/// was verified from.
///
/// The credential is kept so a consumer can prove the claims belong to *its* reading of the
/// `Authorization` header rather than to some other reading of it. That is not a security
/// control — extensions are ours alone (see [`RequestIdentity`]) — it is a drift control:
/// this middleware matches the `Bearer` scheme case-insensitively and trims, while
/// [`crate::extract::AuthContext`] requires a literal `Bearer ` prefix and does not. Handing
/// the extractor claims it would not have accepted the credential for would silently widen an
/// auth surface by way of an optimization.
///
/// [`Debug`] is hand-written: `credential` is a live access token, and a derived `Debug` is
/// exactly how one reaches a `tracing` field or a panic message (S-25.a).
#[derive(Clone)]
struct VerifiedAccess {
    credential: String,
    claims: Claims,
}

impl std::fmt::Debug for VerifiedAccess {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VerifiedAccess").field("credential", &"<redacted>").field("sub", &self.claims.sub).finish()
    }
}

/// The identity a rate-limit bucket is keyed on (S-24.f, S-24.g, S-13.b, decisions 27 and 32).
///
/// Resolved from the request alone — **no database read** — which is what lets this run in
/// middleware on the hot path of every `dart pub get`, and resolved **once**: the value is
/// stashed in the request extensions by [`resolve_identity`] and every later consumer reads it
/// back instead of repeating the work (closes D58).
#[derive(Debug, Clone)]
enum RequestIdentity {
    /// A syntactically valid CLI token, keyed on a truncated hash of the secret.
    ///
    /// The offline gate (`token::validate`: prefix, length, charset, CRC32) is the same one
    /// `authenticate_cli_token` runs before it touches the database, so an *unknown* token is
    /// keyed like a known one. That is deliberate and bounded: on the protocol plane an unknown
    /// token fails authentication and spends `token_auth_fail_per_ip_minute` (30/min/IP), and on
    /// the app API a CLI token never authenticates at all. See S-13.b for the coupling.
    Token(String),
    /// A **verified** access token, keyed on its subject. Verification is local (Ed25519
    /// against the keyring, no I/O); an unverified `sub` would let anyone spend a chosen
    /// victim's budget by asserting their user id.
    User(Box<VerifiedAccess>),
    /// Everything else, including a credential that is neither of the above.
    Ip(String),
}

/// Which of the two identity-keyed buckets is being spent.
///
/// An enum rather than a `&str`, so a keyspace and its metric label cannot be selected by two
/// different spellings of the same word: a typo would silently merge the read and write budgets
/// into one bucket, which is the one failure this split exists to prevent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Plane {
    /// S-24.f, both request planes.
    Read,
    /// S-24.g, app API only.
    Write,
}

impl RequestIdentity {
    /// Bucket key on `plane`. The two planes are two keyspaces, so a `dart pub get` storm
    /// cannot spend the budget that bounds mutations, or vice versa.
    fn key(&self, plane: Plane) -> String {
        let plane = match plane {
            Plane::Read => "read",
            Plane::Write => "write",
        };
        match self {
            Self::Token(hash) => format!("rl:{plane}:tok:{hash}"),
            Self::User(access) => format!("rl:{plane}:usr:{}", access.claims.sub),
            Self::Ip(ip) => format!("rl:{plane}:ip:{ip}"),
        }
    }

    /// Whether this request carries an identity of its own (and so rides the larger budget).
    fn is_identified(&self) -> bool {
        !matches!(self, Self::Ip(_))
    }

    /// The audit/metric label — a bucket family, never the identity itself.
    fn label(&self, plane: Plane) -> &'static str {
        match (plane, self) {
            (Plane::Read, Self::Token(_)) => "read_per_token",
            (Plane::Read, Self::User(_)) => "read_per_user",
            (Plane::Read, Self::Ip(_)) => "read_per_ip",
            (Plane::Write, Self::Token(_)) => "write_per_token",
            (Plane::Write, Self::User(_)) => "write_per_user",
            (Plane::Write, Self::Ip(_)) => "write_per_ip",
        }
    }

    /// The verified claims, **iff** they were verified from exactly `credential`.
    fn claims_for(&self, credential: &str) -> Option<&Claims> {
        match self {
            Self::User(access) if access.credential == credential => Some(&access.claims),
            _ => None,
        }
    }
}

/// The claims this request's identity layer already verified for `credential`, if any.
///
/// The one door [`crate::extract::AuthContext`] uses to skip a *second* Ed25519 verification of
/// a token this process verified microseconds earlier (decision 32, closes D58). It answers
/// `None` for every credential the layer did not verify — a CLI token, an unverifiable string,
/// a different reading of the header — so the extractor's fallback is the unchanged
/// `verify_access` path.
pub(crate) fn stashed_claims(extensions: &Extensions, credential: &str) -> Option<Claims> {
    extensions.get::<RequestIdentity>()?.claims_for(credential).cloned()
}

/// Read-path abuse limits on both planes (S-24.f), keyed by identity and failing **open**.
///
/// Scope: `GET`/`HEAD` under `/api/…` or a registry base. Deliberately excluded —
///
/// - **`/healthz`**, because S-24 exempts health checks; its cost is bounded by the handler's
///   own one-second memo instead.
/// - **the SSE stream**, because it is one request per session rather than a rate; its bound is
///   the S-32 heartbeat, exactly as for the request deadline.
/// - **static assets**, which are embedded, immutable and served from memory.
///
/// A KV error allows the request and logs. This bucket is a quota on cost, not an access gate:
/// closing it would let a KV outage take package resolution down for every client of the
/// instance, which is a strictly worse failure than an unenforced quota for the same minutes.
pub async fn read_rate_limit(State(state): State<AppState>, mut request: Request, next: Next) -> Response {
    if !matches!(*request.method(), Method::GET | Method::HEAD) || !is_read_limited_path(request.uri().path()) {
        return next.run(request).await;
    }

    let now = (state.clock)();
    let identity = resolve_identity(&state, &mut request);
    let limits = state.runtime.current().rate_limits;
    let limit = if identity.is_identified() { limits.read_per_identity_minute } else { limits.read_per_ip_minute };

    match ratelimit::hit(state.kv.as_ref(), &identity.key(Plane::Read), limit, Duration::minutes(1), now).await {
        Ok(Decision::Allowed) => {}
        Ok(decision @ Decision::Limited { retry_after_secs, .. }) => {
            trip(
                &state,
                client_meta(request.headers(), request.extensions(), state.trust_proxy_headers()),
                READ_THROTTLED,
                identity.label(Plane::Read),
                decision,
                now,
            )
            .await;
            return refusal(request.uri().path(), retry_after_secs);
        }
        // Fail open (S-24.f). Logged at warn, not error: the request succeeded.
        Err(err) => tracing::warn!(error = %err, "read-path rate limit unavailable; allowing the request (S-24.f)"),
    }
    next.run(request).await
}

/// Write-path abuse limits on the **app API** (S-24.g), keyed by identity and failing **open**.
///
/// Everything that mutates through `/api/…` spends one bucket, with two exclusions and one
/// mounting rule that are all load-bearing:
///
/// - **The pub protocol plane is excluded.** Its single write already spends S-24.c's per-org
///   publish budget at the upload step; a second bucket would answer 429 for two unrelated
///   reasons with two different `Retry-After` values on one `dart pub publish`.
/// - **The six credential endpoints are excluded, not charged twice.** They spend their own
///   buckets, which fail *closed* onto S-24.e's in-process table; an open bucket beside a closed
///   one on the same request only makes the closed one harder to reason about. The exemption is
///   the same [`credential_bucket`] predicate that charges them.
/// - **It is mounted innermost, after [`mutation_guard`]**, so a cross-origin request the S-12
///   guard refuses spends nothing. The other order lets a page a user merely visits drain that
///   user's own `ip:` write budget by firing mutations the guard was always going to reject.
///   The ordering only delivers that if both layers scope themselves to the *same* plane, which
///   is why both call [`crate::hygiene::is_app_api`] instead of testing a prefix each.
///
/// A KV error allows the request and logs, for the read bucket's reason: this is a quota on
/// cost, not an access gate. The gates that must fail closed are the credential endpoints, and
/// they already do.
pub async fn write_rate_limit(State(state): State<AppState>, mut request: Request, next: Next) -> Response {
    // App-API plane only, through the **same** predicate [`mutation_guard`] scopes itself with
    // (`hygiene::is_app_api`) — the pairing is only sound while the two agree exactly. Checked
    // before anything else so the pub protocol's hot paths — a resolve, a download, a publish
    // upload — do not even resolve an identity here.
    if !crate::hygiene::is_app_api(request.uri().path()) {
        return next.run(request).await;
    }

    // Resolved for **every** app-API method, including the reads and the exempt writes, because
    // the stash is what `AuthContext` consumes downstream: "one verification per request" is a
    // property of the request, not of the bucket. On a GET the read bucket has already resolved
    // it and this is a clone; on a mutation this is the only resolution there is.
    let identity = resolve_identity(&state, &mut request);
    if !is_write_limited(request.method(), request.uri().path()) {
        return next.run(request).await;
    }

    let now = (state.clock)();
    let limits = state.runtime.current().rate_limits;
    let limit = if identity.is_identified() { limits.write_per_identity_minute } else { limits.write_per_ip_minute };

    match ratelimit::hit(state.kv.as_ref(), &identity.key(Plane::Write), limit, Duration::minutes(1), now).await {
        Ok(Decision::Allowed) => {}
        Ok(decision @ Decision::Limited { retry_after_secs, .. }) => {
            trip(
                &state,
                client_meta(request.headers(), request.extensions(), state.trust_proxy_headers()),
                WRITE_THROTTLED,
                identity.label(Plane::Write),
                decision,
                now,
            )
            .await;
            return refusal(request.uri().path(), retry_after_secs);
        }
        // Fail open (S-24.g), like the read bucket and for the same stated reason.
        Err(err) => tracing::warn!(error = %err, "write-path rate limit unavailable; allowing the request (S-24.g)"),
    }
    next.run(request).await
}

/// Whether this app-API request spends a write bucket (S-24.g).
///
/// `OPTIONS` is not a mutation (a preflight carries no state change and is normally answered by
/// the CORS layer before it reaches here); `GET`/`HEAD` ride the read bucket instead.
fn is_write_limited(method: &Method, path: &str) -> bool {
    if matches!(*method, Method::GET | Method::HEAD | Method::OPTIONS) {
        return false;
    }
    credential_bucket(method, path).is_none()
}

/// The 429, in the shape of the plane that asked.
///
/// The read bucket is the first guard to span **both** planes, and the two speak different
/// dialects (docs/rules/api.md — "never mix them"). The app envelope and the pub spec error
/// happen to share a JSON *structure*, so a wrong choice here is invisible to a body assertion
/// and visible to the client, which decides by media type: `dart pub` parses the body of every
/// failure, and unparseable bytes turn a clear "slow down" into a decoding error. The auth
/// guards next door can use the envelope unconditionally only because they scope themselves to
/// `/api/…`.
fn refusal(path: &str, retry_after_secs: u64) -> Response {
    let error = Error::RateLimited { retry_after_secs };
    match crate::hygiene::family_of(path) {
        crate::hygiene::Family::Pub => crate::protocol::error::ProtocolError::from_domain(error).into_response(),
        _ => ApiError(error).into_response(),
    }
}

/// Whether a path spends a read bucket. See [`read_rate_limit`] for what each exclusion buys.
fn is_read_limited_path(path: &str) -> bool {
    if path == crate::hygiene::HEALTH_PATH || path == crate::hygiene::SSE_PATH {
        return false;
    }
    matches!(crate::hygiene::family_of(path), crate::hygiene::Family::Api | crate::hygiene::Family::Pub)
}

/// The request's identity, resolved at most **once** per request (decision 32, closes D58).
///
/// The first caller classifies the credential and stashes the result in the request extensions;
/// every later caller — the other bucket, and `AuthContext` through [`stashed_claims`] — reads
/// it back. Before this, an authenticated read verified its access token twice (D58) and adding
/// a write bucket naively would have made it three times on a write.
fn resolve_identity(state: &AppState, request: &mut Request) -> RequestIdentity {
    if let Some(identity) = request.extensions().get::<RequestIdentity>() {
        return identity.clone();
    }
    let plane = crate::hygiene::family_of(request.uri().path());
    let identity = classify_identity(state, plane, request.headers(), request.extensions());
    request.extensions_mut().insert(identity.clone());
    identity
}

/// Classifies the request's credential into a [`RequestIdentity`].
///
/// **A CLI token is an identity only on the plane that accepts one.** On the pub protocol a
/// bearer token is the credential, and [decision 27] accepted that anyone can mint unlimited
/// CRC32-valid strings — and therefore unlimited `tok:` buckets — because every such request
/// fails `authenticate_cli_token`, which spends `token_auth_fail_per_ip_minute` (30/min/IP).
/// That decision named the condition under which the trade stops holding: *"this is the clause
/// to re-check if a future plane starts accepting CLI tokens without spending the failure
/// budget."* The app API is that plane. It never authenticates a CLI token at all — the
/// extractor refuses it before any lookup — so it charges no failure budget, and a caller
/// rotating a fresh fake token per request would get a fresh `write_per_identity_minute`
/// bucket each time, making `write_per_ip_minute` unenforceable from one address and pinning a
/// KV key per rotation for two windows.
///
/// So on `Family::Api` a token-shaped credential is **not** an identity: it is an
/// unauthenticated caller, and it belongs in the per-IP bucket with every other one. This is
/// the read path's hole too — it predates the write bucket — and it closes on both.
///
/// [decision 27]: ../../../../docs/decisions.md#27--rate-limit-identity-what-a-bucket-is-keyed-on-and-what-happens-when-the-kv-is-down
fn classify_identity(
    state: &AppState,
    plane: crate::hygiene::Family,
    headers: &HeaderMap,
    extensions: &Extensions,
) -> RequestIdentity {
    let anonymous = || {
        // Unresolvable IPs share one bucket — still bounded, never a bypass.
        RequestIdentity::Ip(
            client_ip(headers, extensions, state.trust_proxy_headers()).unwrap_or_else(|| "unknown".to_owned()),
        )
    };
    let Some(secret) = bearer(headers) else {
        return anonymous();
    };

    if plane == crate::hygiene::Family::Pub
        && pub_auth::token::validate(secret, &state.auth.policy().token_prefix).is_ok()
    {
        // 16 hex characters of the same SHA-256 the database stores — enough to separate
        // tokens, and never a credential-equivalent value in a second system. A collision
        // merges two budgets, which only ever refuses more.
        let hash = pub_auth::token::sha256_hex(secret);
        return RequestIdentity::Token(hash[..16].to_owned());
    }
    match state.auth.verify_access(secret, (state.clock)()) {
        Ok(claims) => RequestIdentity::User(Box::new(VerifiedAccess { credential: secret.to_owned(), claims })),
        Err(_) => anonymous(),
    }
}

/// The bearer credential, with the scheme matched case-insensitively.
///
/// Case-insensitive per RFC 9110 §11.1 and S-14.a — the protocol plane already accepts
/// `bearer`, so keying on `Bearer` alone would quietly drop those callers into the anonymous
/// per-IP bucket and throttle a legitimate CI fleet at the wrong number.
fn bearer(headers: &axum::http::HeaderMap) -> Option<&str> {
    let value = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    let (scheme, rest) = value.split_once(' ')?;
    scheme.eq_ignore_ascii_case("bearer").then(|| rest.trim()).filter(|token| !token.is_empty())
}

/// Whether a path is a credential-redemption endpoint under the S-24 "login" bucket.
fn is_credential_redemption(path: &str) -> bool {
    matches!(path, "/api/v1/auth/otp/verify" | "/api/v1/auth/refresh" | "/api/v1/auth/totp/verify")
        || (path
            .strip_prefix("/api/v1/auth/oidc/")
            .is_some_and(|rest| rest.ends_with("/start") || rest.ends_with("/callback")))
}

#[cfg(test)]
mod tests {
    use axum::http::{HeaderMap, HeaderValue};

    use super::*;

    const INSTANCE: &str = "https://pub.corp.com";

    fn headers(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut map = HeaderMap::new();
        for (name, value) in pairs {
            map.insert(
                axum::http::HeaderName::from_bytes(name.as_bytes()).unwrap(),
                HeaderValue::from_str(value).unwrap(),
            );
        }
        map
    }

    #[test]
    fn s24_login_bucket_covers_every_redemption_path() {
        for path in [
            "/api/v1/auth/otp/verify",
            "/api/v1/auth/refresh",
            "/api/v1/auth/totp/verify",
            "/api/v1/auth/oidc/google/start",
            "/api/v1/auth/oidc/corp-idp/callback",
        ] {
            assert!(is_credential_redemption(path), "{path} must ride the login bucket");
        }
        for path in
            ["/api/v1/auth/otp/request", "/api/v1/auth/logout", "/api/v1/auth/oidc/google/other", "/api/v1/tokens"]
        {
            assert!(!is_credential_redemption(path), "{path} must not ride the login bucket");
        }
    }

    /// **S-24.g.** The write bucket's exemption list *is* the credential plane's charge list —
    /// same predicate, so the two can never drift into a mutation charged twice or not at all.
    #[test]
    fn s24_g_the_write_bucket_exempts_exactly_the_six_credential_endpoints() {
        for path in [
            "/api/v1/auth/otp/request",
            "/api/v1/auth/otp/verify",
            "/api/v1/auth/refresh",
            "/api/v1/auth/totp/verify",
            "/api/v1/auth/oidc/google/start",
            "/api/v1/auth/oidc/corp-idp/callback",
        ] {
            assert!(credential_bucket(&Method::POST, path).is_some(), "{path} must spend its own closed bucket");
            assert!(!is_write_limited(&Method::POST, path), "{path} must not also spend the open write bucket");
        }
        // Everything else that mutates through /api does spend it — including the auth-family
        // routes that are *not* one of the six.
        for path in ["/api/v1/orgs", "/api/v1/tokens", "/api/v1/admin/settings", "/api/v1/auth/logout"] {
            assert!(is_write_limited(&Method::POST, path), "{path} must spend the write bucket");
        }
        for method in [Method::PATCH, Method::PUT, Method::DELETE] {
            assert!(is_write_limited(&method, "/api/v1/orgs/acme"), "{method} is a mutation");
        }
    }

    /// **S-24.g.** Reads and preflights are not writes: a `GET` rides the S-24.f bucket and an
    /// `OPTIONS` carries no state change at all.
    #[test]
    fn s24_g_reads_and_preflights_do_not_spend_the_write_bucket() {
        for method in [Method::GET, Method::HEAD, Method::OPTIONS] {
            assert!(!is_write_limited(&method, "/api/v1/orgs"), "{method} must not spend a write bucket");
        }
    }

    /// **S-24.g / decision 27.** The two planes are two keyspaces, and the key never carries a
    /// credential — a truncated hash for a token, the subject for a session, the IP otherwise.
    #[test]
    fn s24_g_read_and_write_keys_are_separate_keyspaces() {
        let token = RequestIdentity::Token("0123456789abcdef".to_owned());
        assert_eq!(token.key(Plane::Read), "rl:read:tok:0123456789abcdef");
        assert_eq!(token.key(Plane::Write), "rl:write:tok:0123456789abcdef");
        assert_ne!(token.key(Plane::Read), token.key(Plane::Write), "a read storm must not spend the write budget");
        let ip = RequestIdentity::Ip("203.0.113.7".to_owned());
        assert_eq!(ip.key(Plane::Write), "rl:write:ip:203.0.113.7");
        assert!(!ip.is_identified(), "an anonymous request rides the smaller number");
        assert!(token.is_identified());
        assert_eq!(token.label(Plane::Write), "write_per_token");
        assert_eq!(ip.label(Plane::Read), "read_per_ip");
    }

    /// **D58.** The stash hands claims back only for the *exact* credential they were verified
    /// from. This middleware matches `Bearer` case-insensitively and trims; `AuthContext` does
    /// neither — so an unconditional stash would silently widen what the extractor accepts.
    #[test]
    fn d58_the_claims_stash_is_bound_to_the_credential_it_verified() {
        let claims = Claims {
            sub: pub_core::UserId::new(),
            sid: pub_core::SessionId::new(),
            orgs: Default::default(),
            iat: 0,
            exp: 0,
        };
        let identity =
            RequestIdentity::User(Box::new(VerifiedAccess { credential: "header.body.sig".to_owned(), claims }));
        let mut extensions = Extensions::new();
        extensions.insert(identity);

        assert!(stashed_claims(&extensions, "header.body.sig").is_some(), "the same credential reuses the claims");
        for other in ["header.body.sig ", " header.body.sig", "header.body.other", ""] {
            assert!(stashed_claims(&extensions, other).is_none(), "a different credential must re-verify: {other:?}");
        }
        // An identity that is not a verified session carries no claims to reuse at all.
        let mut token_only = Extensions::new();
        token_only.insert(RequestIdentity::Token("0123456789abcdef".to_owned()));
        assert!(stashed_claims(&token_only, "pub_whatever").is_none());
        assert!(stashed_claims(&Extensions::new(), "anything").is_none(), "no stash means the extractor verifies");
    }

    #[test]
    fn s12_bare_requests_pass_so_cli_clients_keep_working() {
        // No Origin, no Sec-Fetch-Site: curl / CI / the pub CLI.
        assert_eq!(cross_site_denial(&HeaderMap::new(), INSTANCE), None);
    }

    #[test]
    fn s12_same_origin_browser_requests_pass() {
        let ok = headers(&[("origin", INSTANCE), ("sec-fetch-site", "same-origin")]);
        assert_eq!(cross_site_denial(&ok, INSTANCE), None);
        // Default ports are equivalent to their explicit form.
        let explicit = headers(&[("origin", "https://pub.corp.com:443")]);
        assert_eq!(cross_site_denial(&explicit, INSTANCE), None);
        // The public URL may carry a path; only the origin triple is compared.
        assert_eq!(cross_site_denial(&ok, "https://pub.corp.com/base/"), None);
    }

    #[test]
    fn s12_foreign_origin_is_rejected_server_side() {
        for hostile in ["https://evil.example", "http://pub.corp.com", "https://pub.corp.com.evil.example", "null"] {
            let map = headers(&[("origin", hostile)]);
            assert!(cross_site_denial(&map, INSTANCE).is_some(), "accepted Origin {hostile}");
        }
    }

    #[test]
    fn s12_cross_site_fetch_metadata_is_rejected_even_without_origin() {
        for site in ["cross-site", "same-site-typo"] {
            let map = headers(&[("sec-fetch-site", site)]);
            assert!(cross_site_denial(&map, INSTANCE).is_some(), "accepted Sec-Fetch-Site {site}");
        }
        // A same-origin fetch-metadata value with a matching Origin is fine.
        let ok = headers(&[("sec-fetch-site", "same-origin"), ("origin", INSTANCE)]);
        assert_eq!(cross_site_denial(&ok, INSTANCE), None);
    }
}
