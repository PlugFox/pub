//! Request guards: the S-12 mutation guard (custom header + JSON-only bodies) and the
//! KV-backed auth rate-limit layer (S-24).
//!
//! Middleware order (docs/rules/api.md): request-id → tracing → security headers → rate
//! limit → auth extractors. Both guards scope themselves to app-API paths — the pub protocol
//! surface (`/o/…`, `/pub/…`) has its own contract and must never inherit these checks.

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
    let policy = state.auth.policy();
    let bucket = match request.uri().path() {
        "/api/v1/auth/otp/request" if is_post => {
            Some(("otp_per_ip", "otp", policy.otp_per_ip_hour, Duration::hours(1)))
        }
        path if is_post && is_credential_redemption(path) => {
            Some(("login_per_ip", "login", policy.login_per_ip_minute, Duration::minutes(1)))
        }
        _ => None,
    };

    if let Some((limit_name, bucket_name, limit, window)) = bucket {
        let now = (state.clock)();
        // Unresolvable IPs share one bucket — still bounded, never a bypass.
        let ip = client_ip(request.headers(), request.extensions(), state.trust_proxy_headers())
            .unwrap_or_else(|| "unknown".to_owned());
        let key = format!("rl:{bucket_name}:ip:{ip}");
        match ratelimit::hit(state.kv.as_ref(), &key, limit, window, now).await {
            Ok(Decision::Allowed) => {}
            Ok(Decision::Limited { retry_after_secs }) => {
                // S-24: throttle trips are audit-logged; failures must not mask the 429.
                let meta = client_meta(request.headers(), request.extensions(), state.trust_proxy_headers());
                let event = NewAuditEvent {
                    actor: AuditActor::System,
                    ip: meta.ip,
                    user_agent: meta.user_agent,
                    org_id: None,
                    action: "auth.throttled".to_owned(),
                    target: None,
                    result: AuditResult::Failure,
                    metadata: Some(serde_json::json!({ "limit": limit_name })),
                };
                if let Err(err) = state.repos.audit.append(event, now).await {
                    tracing::error!(error = %err, "audit append failed for throttle trip");
                }
                return ApiError(Error::RateLimited { retry_after_secs }).into_response();
            }
            Err(err) => return ApiError(err).into_response(),
        }
    }
    next.run(request).await
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
