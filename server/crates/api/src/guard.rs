//! Request guards: the S-12 mutation guard (custom header + JSON-only bodies), the KV-backed
//! auth rate-limit layer (S-24), and the read-path buckets (S-24.f).
//!
//! Middleware order (docs/rules/api.md): request-id → tracing → security headers → CORS →
//! load-shed → timeout → body cap → rate limit → auth extractors. The S-12 guard and the auth
//! buckets scope themselves to app-API paths — the pub protocol surface (`/o/…`, `/pub/…`) has
//! its own contract and must never inherit those checks. The **read** bucket is the one guard
//! that deliberately spans both planes: `dart pub get` is where the read volume actually is,
//! and a limit the protocol plane does not have is not a limit.

use axum::Json;
use axum::extract::{Request, State};
use axum::http::{Method, StatusCode, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use chrono::Duration;
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

/// S-12 guard for `/api/` mutations: `Origin`/`Sec-Fetch-Site` verification, the custom
/// header, and JSON-only bodies.
///
/// The three checks are independent layers on purpose. The custom header forces a CORS
/// preflight (which, with no permissive CORS layer configured, browsers fail) — but it relies
/// on the browser to enforce it. The `Origin`/`Sec-Fetch-Site` comparison is decided
/// *server-side* against the instance's own public URL and therefore also covers a browser
/// that never sends the preflight. Non-browser clients (CLI, curl, CI) send neither header and
/// are unaffected: absence is not evidence of a cross-site request, presence of a *foreign*
/// value is.
pub async fn mutation_guard(State(state): State<AppState>, request: Request, next: Next) -> Response {
    let is_api = request.uri().path().starts_with("/api/");
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
    let is_post = request.method() == Method::POST;
    // Runtime settings (decision 09), read per request: an admin lowering a limit takes effect
    // on the next request, not on the next restart.
    let limits = state.runtime.current().rate_limits;
    let bucket = match request.uri().path() {
        "/api/v1/auth/otp/request" if is_post => {
            Some(("otp_per_ip", "otp", limits.otp_per_ip_hour, Duration::hours(1)))
        }
        path if is_post && is_credential_redemption(path) => {
            Some(("login_per_ip", "login", limits.login_per_ip_minute, Duration::minutes(1)))
        }
        _ => None,
    };

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

/// The identity a read bucket is keyed on (S-24.f, S-13.b, decision 27).
///
/// Resolved from the request alone — **no database read** — which is what lets this run in
/// middleware on the hot path of every `dart pub get`.
#[derive(Debug, PartialEq, Eq)]
enum ReadIdentity {
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
    /// victim's read budget by asserting their user id.
    User(String),
    /// Everything else, including a credential that is neither of the above.
    Ip(String),
}

impl ReadIdentity {
    /// Bucket key and the limit class this identity spends.
    fn key(&self) -> String {
        match self {
            Self::Token(hash) => format!("rl:read:tok:{hash}"),
            Self::User(sub) => format!("rl:read:usr:{sub}"),
            Self::Ip(ip) => format!("rl:read:ip:{ip}"),
        }
    }

    /// Whether this request carries an identity of its own (and so rides the larger budget).
    fn is_identified(&self) -> bool {
        !matches!(self, Self::Ip(_))
    }

    /// The audit/metric label — a bucket family, never the identity itself.
    fn label(&self) -> &'static str {
        match self {
            Self::Token(_) => "read_per_token",
            Self::User(_) => "read_per_user",
            Self::Ip(_) => "read_per_ip",
        }
    }
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
pub async fn read_rate_limit(State(state): State<AppState>, request: Request, next: Next) -> Response {
    if !matches!(*request.method(), Method::GET | Method::HEAD) || !is_read_limited_path(request.uri().path()) {
        return next.run(request).await;
    }

    let now = (state.clock)();
    let identity = read_identity(&state, &request);
    let limits = state.runtime.current().rate_limits;
    let limit = if identity.is_identified() { limits.read_per_identity_minute } else { limits.read_per_ip_minute };

    match ratelimit::hit(state.kv.as_ref(), &identity.key(), limit, Duration::minutes(1), now).await {
        Ok(Decision::Allowed) => {}
        Ok(decision @ Decision::Limited { retry_after_secs, .. }) => {
            trip(
                &state,
                client_meta(request.headers(), request.extensions(), state.trust_proxy_headers()),
                READ_THROTTLED,
                identity.label(),
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

/// Classifies the request's credential into a [`ReadIdentity`].
fn read_identity(state: &AppState, request: &Request) -> ReadIdentity {
    let anonymous = || {
        // Unresolvable IPs share one bucket — still bounded, never a bypass.
        ReadIdentity::Ip(
            client_ip(request.headers(), request.extensions(), state.trust_proxy_headers())
                .unwrap_or_else(|| "unknown".to_owned()),
        )
    };
    let Some(secret) = bearer(request.headers()) else {
        return anonymous();
    };

    if pub_auth::token::validate(secret, &state.auth.policy().token_prefix).is_ok() {
        // 16 hex characters of the same SHA-256 the database stores — enough to separate
        // tokens, and never a credential-equivalent value in a second system. A collision
        // merges two budgets, which only ever refuses more.
        let hash = pub_auth::token::sha256_hex(secret);
        return ReadIdentity::Token(hash[..16].to_owned());
    }
    match state.auth.verify_access(secret, (state.clock)()) {
        Ok(claims) => ReadIdentity::User(claims.sub.to_string()),
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
