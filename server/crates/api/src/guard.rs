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

/// S-12 guard for `/api/` mutations: require `X-Pub-Request: 1` and reject non-JSON bodies.
pub async fn mutation_guard(request: Request, next: Next) -> Response {
    let is_api = request.uri().path().starts_with("/api/");
    let is_mutation = !matches!(*request.method(), Method::GET | Method::HEAD | Method::OPTIONS);
    if is_api && is_mutation {
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

/// Per-IP rate limit on the OTP request endpoint (S-24: 20/h/IP), KV-backed.
///
/// KV outage → the error propagates as 503: auth-abuse limiting fails **closed** (S-24).
/// The per-email cap lives inside the flow, where the parsed body is available.
pub async fn auth_rate_limit(State(state): State<AppState>, request: Request, next: Next) -> Response {
    let is_otp_request = request.method() == Method::POST && request.uri().path() == "/api/v1/auth/otp/request";
    if is_otp_request {
        let now = (state.clock)();
        // Unresolvable IPs share one bucket — still bounded, never a bypass.
        let ip = client_ip(request.headers()).unwrap_or_else(|| "unknown".to_owned());
        let key = format!("rl:otp:ip:{ip}");
        let limit = state.auth.policy().otp_per_ip_hour;
        match ratelimit::hit(state.kv.as_ref(), &key, limit, Duration::hours(1), now).await {
            Ok(Decision::Allowed) => {}
            Ok(Decision::Limited { retry_after_secs }) => {
                // S-24: throttle trips are audit-logged; failures must not mask the 429.
                let meta = client_meta(request.headers());
                let event = NewAuditEvent {
                    actor: AuditActor::System,
                    ip: meta.ip,
                    user_agent: meta.user_agent,
                    org_id: None,
                    action: "auth.throttled".to_owned(),
                    target: None,
                    result: AuditResult::Failure,
                    metadata: Some(serde_json::json!({ "limit": "otp_per_ip" })),
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
