//! HTTP hygiene (roadmap D8+D13): per-request deadlines, a global concurrency ceiling with
//! load shedding, the family reshaping of bare body-cap 413s, and the response-header pass
//! (S-28 transport headers, no-store cache tiers).
//!
//! Everything here is **family-aware**. The server speaks three response dialects
//! (docs/rules/api.md) and a middleware that answers for a handler must speak the right one:
//! the pub protocol gets the spec error shape `{"error":{"code","message"}}` with the v2 media
//! type — the client parses every failure body, and `spec_shape_bare_statuses` lives *inside*
//! the protocol router, so a bare response from this layer would bypass it — the app API gets
//! the envelope, and everything else gets plain text.
//!
//! Status choices are the pub client's retry table (docs/protocol.md sharp edge 2): 408 and
//! 503 are both retried up to 7 attempts, which is **correct** here — a genuine timeout and a
//! shed request are exactly the transient failures a retry can heal.

use std::sync::Arc;
use std::time::Duration;

use axum::Json;
use axum::extract::{Request, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use tokio::sync::Semaphore;

use crate::envelope::ErrorEnvelope;
use crate::protocol::error::{PUB_V2_MEDIA_TYPE, SpecError, SpecErrorBody};
use crate::state::AppState;

/// The SSE stream (S-32) — exempt from the request deadline, see [`budget_for`].
const SSE_PATH: &str = "/api/v1/events";

/// Suffix of the publish-upload path on both virtual bases (docs/protocol.md endpoint 3).
const UPLOAD_SUFFIX: &str = "/api/packages/versions/newUpload";

/// Infix of the publish-finalize path (docs/protocol.md endpoint 4): the session id follows,
/// so the path can only be matched by containment, never by suffix.
const FINALIZE_INFIX: &str = "/api/packages/versions/newUploadFinish/";

/// Liveness must answer while the instance is melting — S-24 exempts health checks from
/// limits, and the same logic exempts them from the shed.
const HEALTH_PATH: &str = "/healthz";

/// `Strict-Transport-Security` value sent on https deployments (S-28): two years, subdomains
/// included — the instance origin is dedicated to the registry.
const HSTS: &str = "max-age=63072000; includeSubDomains";

// ------------------------------------------------------------------------- response families

/// Which wire dialect a path answers in (docs/rules/api.md — "never mix them").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Family {
    /// `/pub/…` and `/o/{org}/pub/…`: spec error shape, pub v2 media type.
    Pub,
    /// `/api/…`: the app envelope.
    Api,
    /// Assets and system routes: plain text is the only honest shape.
    Other,
}

/// Classifies a request path into its response family.
fn family_of(path: &str) -> Family {
    if path == "/pub" || path.starts_with("/pub/") || is_org_pub(path) {
        Family::Pub
    } else if path == "/api" || path.starts_with("/api/") {
        Family::Api
    } else {
        Family::Other
    }
}

/// Whether `path` sits under an org's virtual registry base `/o/{org}/pub` (decision 01).
fn is_org_pub(path: &str) -> bool {
    let Some(rest) = path.strip_prefix("/o/") else {
        return false;
    };
    let mut segments = rest.split('/');
    matches!((segments.next(), segments.next()), (Some(org), Some("pub")) if !org.is_empty())
}

/// The path relative to its pub registry base (`/pub` or `/o/{org}/pub`), when under one.
fn pub_relative(path: &str) -> Option<&str> {
    let tail = if let Some(rest) = path.strip_prefix("/pub") {
        rest
    } else {
        let rest = path.strip_prefix("/o/")?;
        let (org, tail) = rest.split_once('/')?;
        if org.is_empty() {
            return None;
        }
        tail.strip_prefix("pub")?
    };
    (tail.is_empty() || tail.starts_with('/')).then_some(tail)
}

/// Whether `path` is a pub archive download — the current route (`B/api/archives/{file}`) or
/// the legacy one (`B/packages/{name}/versions/{file}`), docs/protocol.md endpoints 5 and 7.
fn is_archive_download(path: &str) -> bool {
    let Some(relative) = pub_relative(path) else {
        return false;
    };
    relative.starts_with("/api/archives/") || (relative.starts_with("/packages/") && relative.contains("/versions/"))
}

/// A middleware-made error response in the family's own shape.
fn family_error(path: &str, status: StatusCode, code: &'static str, message: &str) -> Response {
    match family_of(path) {
        Family::Pub => {
            let body = SpecError { error: SpecErrorBody { code: code.to_owned(), message: message.to_owned() } };
            let mut response = (status, Json(body)).into_response();
            response.headers_mut().insert(header::CONTENT_TYPE, HeaderValue::from_static(PUB_V2_MEDIA_TYPE));
            response
        }
        Family::Api => (status, Json(ErrorEnvelope::new(code, message))).into_response(),
        Family::Other => (status, message.to_owned()).into_response(),
    }
}

// ------------------------------------------------------------------------- request deadlines

/// The deadline for this path, or `None` for the SSE exemption.
///
/// `/api/v1/events` holds its response open for the life of the stream **by design**; a
/// deadline would sever every stream mid-session. Its bound exists elsewhere and is tighter
/// than any timeout: the heartbeat re-checks session revocation and the access-token expiry,
/// so a stream lives at most one heartbeat past its token (S-32).
fn budget_for(path: &str, settings: &pub_config::Settings) -> Option<Duration> {
    let http = &settings.http;
    if path == SSE_PATH {
        return None;
    }
    let secs = if path.ends_with(UPLOAD_SUFFIX) || path.contains(FINALIZE_INFIX) {
        // Upload: the multipart read happens inside the handler future, so this deadline
        // genuinely bounds a client dribbling a 100 MB archive — a slow-loris upload cannot
        // hold the connection past it. Finalize: the same order of work in the other
        // direction — it re-reads the staged archive (up to `registry.max_archive_bytes`)
        // from blob storage, hashes and unpacks it, and writes the rows, so the ordinary
        // budget would expire mid-finalize on a slow blob backend and burn the whole upload.
        http.upload_timeout_secs
    } else if is_archive_download(path) {
        // A cold-cache proxied archive is fetched from upstream *inside* the response head
        // (decision 07), and the operator sized that fetch with
        // `upstream.archive_timeout_secs` — a request budget below it would make the knob
        // unreachable dead config. `max`, not a replacement: the archive budget must never
        // undercut the ordinary one, and warm-cache downloads stream after the head anyway.
        http.request_timeout_secs.max(settings.upstream.archive_timeout_secs)
    } else {
        http.request_timeout_secs
    };
    Some(Duration::from_secs(secs))
}

/// Path-aware request deadline (D13).
///
/// Bounds the **response head**, not body streaming: `next.run` resolves when the handler
/// returns a `Response`, so a streaming archive download that has started is never killed
/// mid-stream (the same semantics tower-http's `TimeoutLayer` would have). 408 is retried by
/// the pub client, which is the correct behavior for a genuine timeout.
pub async fn request_timeout(State(state): State<AppState>, request: Request, next: Next) -> Response {
    let Some(budget) = budget_for(request.uri().path(), &state.settings) else {
        return next.run(request).await;
    };
    let path = request.uri().path().to_owned();
    enforce_deadline(budget, path, request, next).await
}

/// Runs the rest of the stack under `budget`; elapsing answers 408 in the family's shape.
async fn enforce_deadline(budget: Duration, path: String, request: Request, next: Next) -> Response {
    match tokio::time::timeout(budget, next.run(request)).await {
        Ok(response) => response,
        Err(_elapsed) => {
            tracing::warn!(%path, budget_secs = budget.as_secs(), "request deadline elapsed");
            family_error(
                &path,
                StatusCode::REQUEST_TIMEOUT,
                "timeout",
                "the server did not finish handling the request in time; retrying may succeed",
            )
        }
    }
}

// ----------------------------------------------------------------------------- load shedding

/// Global concurrency ceiling with load shedding (D8).
///
/// `try_acquire`, never `acquire`: a saturated server must answer `503 + Retry-After` *now*,
/// not queue requests into the very overload the ceiling exists to survive. The permit spans
/// the response head only — a long-lived SSE stream or a streaming download releases its slot
/// once the head is written, so slow readers cannot pin the budget.
pub async fn concurrency_shed(capacity: Arc<Semaphore>, request: Request, next: Next) -> Response {
    let path = request.uri().path();
    if path == HEALTH_PATH {
        // Liveness answers under load (S-24 exempts health checks from limits): an orchestrator
        // that cannot tell "shedding" from "dead" restarts an instance that only needed a second.
        return next.run(request).await;
    }
    match capacity.try_acquire_owned() {
        Ok(_permit) => next.run(request).await,
        Err(_exhausted) => {
            tracing::warn!(%path, "concurrency limit reached; shedding request");
            let mut response = family_error(
                path,
                StatusCode::SERVICE_UNAVAILABLE,
                "overloaded",
                "the server is handling its maximum number of concurrent requests; retry shortly",
            );
            response.headers_mut().insert(header::RETRY_AFTER, HeaderValue::from_static("1"));
            response
        }
    }
}

// -------------------------------------------------------------------------- response headers

/// Reshapes bare body-cap rejections into the family's own error body.
///
/// Axum's length-limit rejection is a plain-text 413, which would be an unrecorded break of
/// the every-route-answers-its-family contract: `/api` answers the envelope and the pub bases
/// the spec shape, whichever layer produced the status — the same rule the middleware-made
/// 408/503 bodies follow (docs/rules/api.md). Layered *inside* the CORS layer (unlike
/// [`response_headers`]) so the reshaped response still picks up its CORS headers; the
/// JSON-body guard keeps it from double-wrapping a 413 a handler already shaped.
pub async fn reshape_body_limit(request: Request, next: Next) -> Response {
    let path = request.uri().path().to_owned();
    let response = next.run(request).await;
    if response.status() == StatusCode::PAYLOAD_TOO_LARGE
        && family_of(&path) != Family::Other
        && !is_json_body(&response)
    {
        return family_error(
            &path,
            StatusCode::PAYLOAD_TOO_LARGE,
            "payload_too_large",
            "the request body exceeds this route's size limit",
        );
    }
    response
}

/// Response-header pass: HSTS on https deployments and the no-store cache tier (S-28).
///
/// - **HSTS** is derived from `server.public_url`'s scheme, no knob: a browser ignores the
///   header over plain http anyway, so sending it there would only be noise, and an operator
///   who terminates TLS at a proxy has an https public URL by construction.
/// - **`Cache-Control: no-store`** on the app API, `/healthz`, and pub-protocol JSON — every
///   one of these can carry per-principal data (S-28 "cookieless API responses marked
///   no-store where sensitive"). Only set when the handler set nothing: archive downloads and
///   embedded assets choose their own tier (content-addressed and immutable, S-18).
pub async fn response_headers(State(state): State<AppState>, request: Request, next: Next) -> Response {
    let no_store = {
        let path = request.uri().path();
        path == HEALTH_PATH || family_of(path) != Family::Other
    };
    let mut response = next.run(request).await;
    let headers = response.headers_mut();
    if https_public_url(&state.settings.server.public_url) {
        headers.insert(header::STRICT_TRANSPORT_SECURITY, HeaderValue::from_static(HSTS));
    }
    if no_store && !headers.contains_key(header::CACHE_CONTROL) {
        headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    }
    response
}

/// Whether the configured public URL is https (drives HSTS).
fn https_public_url(public_url: &str) -> bool {
    public_url.get(..8).is_some_and(|scheme| scheme.eq_ignore_ascii_case("https://"))
}

/// Whether a response already carries a JSON body (either JSON media type) — the guard that
/// keeps the 413 reshape from double-wrapping an error a handler shaped itself.
fn is_json_body(response: &Response) -> bool {
    response
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|content_type| content_type.contains("json"))
}

#[cfg(test)]
mod tests {
    use axum::Router;
    use axum::body::Body;
    use axum::routing::{get, post};
    use http_body_util::BodyExt as _;
    use tower::ServiceExt as _;

    use super::*;

    #[test]
    fn every_registry_base_is_the_pub_family() {
        for path in ["/pub", "/pub/api/packages/foo", "/o/acme/pub", "/o/acme/pub/api/packages/foo"] {
            assert_eq!(family_of(path), Family::Pub, "{path}");
        }
    }

    #[test]
    fn app_api_and_asset_paths_are_not_the_pub_family() {
        for path in ["/api/v1/ping", "/api", "/api/openapi.json"] {
            assert_eq!(family_of(path), Family::Api, "{path}");
        }
        for path in ["/", "/healthz", "/publisher", "/o/acme", "/o//pub", "/o/acme/publish", "/app/orgs"] {
            assert_eq!(family_of(path), Family::Other, "{path}");
        }
    }

    #[test]
    fn the_sse_stream_is_exempt_and_the_upload_rides_its_own_budget() {
        let settings = pub_config::Settings::default();
        assert_eq!(budget_for(SSE_PATH, &settings), None, "a deadline would sever every stream mid-session");
        assert_eq!(
            budget_for("/o/acme/pub/api/packages/versions/newUpload", &settings),
            Some(Duration::from_secs(settings.http.upload_timeout_secs))
        );
        assert_eq!(
            budget_for("/pub/api/packages/versions/newUpload", &settings),
            Some(Duration::from_secs(settings.http.upload_timeout_secs))
        );
        assert_eq!(
            budget_for("/api/v1/ping", &settings),
            Some(Duration::from_secs(settings.http.request_timeout_secs))
        );
    }

    #[test]
    fn the_finalize_step_rides_the_upload_budget() {
        // Finalize moves the staged archive out of blob storage, validates it, and writes the
        // rows — the ordinary 30s budget can expire mid-finalize on a slow blob backend, and
        // that expiry burns a whole staged upload.
        let settings = pub_config::Settings::default();
        let upload = Some(Duration::from_secs(settings.http.upload_timeout_secs));
        assert_eq!(budget_for("/pub/api/packages/versions/newUploadFinish/deadbeef", &settings), upload);
        assert_eq!(budget_for("/o/acme/pub/api/packages/versions/newUploadFinish/deadbeef", &settings), upload);
        // The step-1 ticket is an ordinary request: no archive moves.
        assert_eq!(
            budget_for("/pub/api/packages/versions/new", &settings),
            Some(Duration::from_secs(settings.http.request_timeout_secs))
        );
    }

    #[test]
    fn archive_downloads_ride_the_larger_of_request_and_upstream_archive_budgets() {
        // A cold-cache proxied archive legitimately needs up to `upstream.archive_timeout_secs`
        // inside the response head; the classification is what keeps that knob reachable.
        let mut settings = pub_config::Settings::default();
        settings.http.request_timeout_secs = 30;
        settings.upstream.archive_timeout_secs = 300;
        let archive = Some(Duration::from_secs(300));
        for path in [
            "/pub/api/archives/acme_core-1.0.0.tar.gz",
            "/o/acme/pub/api/archives/acme_core-1.0.0.tar.gz",
            "/pub/packages/acme_core/versions/1.0.0.tar.gz",
            "/o/acme/pub/packages/acme_core/versions/1.0.0.tar.gz",
        ] {
            assert_eq!(budget_for(path, &settings), archive, "{path}");
        }
        // `max`, never a swap: the archive budget must not undercut the ordinary one.
        settings.upstream.archive_timeout_secs = 5;
        assert_eq!(budget_for("/pub/api/archives/acme_core-1.0.0.tar.gz", &settings), Some(Duration::from_secs(30)));
        // Non-archive pub routes and archive-looking paths outside a pub base stay ordinary.
        settings.upstream.archive_timeout_secs = 300;
        let ordinary = Some(Duration::from_secs(30));
        assert_eq!(budget_for("/pub/api/packages/acme_core", &settings), ordinary);
        assert_eq!(budget_for("/api/archives/acme_core-1.0.0.tar.gz", &settings), ordinary);
        assert_eq!(budget_for("/packages/acme_core/versions/1.0.0.tar.gz", &settings), ordinary);
        assert_eq!(budget_for("/o//pub/api/archives/x-1.0.0.tar.gz", &settings), ordinary);
    }

    #[test]
    fn hsts_derivation_reads_only_the_scheme() {
        assert!(https_public_url("https://pub.corp.test"));
        assert!(https_public_url("HTTPS://pub.corp.test"));
        assert!(!https_public_url("http://localhost:8080"));
        assert!(!https_public_url(""));
    }

    /// A tiny router whose handlers outlast a millisecond deadline, wrapped in the deadline
    /// middleware exactly as [`crate::router`] wraps the real stack.
    fn slow_router(budget: Duration) -> Router {
        async fn slow() -> &'static str {
            tokio::time::sleep(Duration::from_secs(5)).await;
            "too late"
        }
        Router::new()
            .route("/pub/api/packages/{name}", get(slow))
            .route("/api/v1/slow", get(slow))
            .route("/slow", get(slow))
            .layer(axum::middleware::from_fn(move |request: Request, next: Next| {
                let path = request.uri().path().to_owned();
                enforce_deadline(budget, path, request, next)
            }))
    }

    async fn body_json(response: Response) -> serde_json::Value {
        let bytes = response.into_body().collect().await.expect("body").to_bytes();
        serde_json::from_slice(&bytes).expect("json body")
    }

    #[tokio::test(start_paused = true)]
    async fn a_slow_pub_request_times_out_with_the_spec_error_shape() {
        let router = slow_router(Duration::from_millis(50));
        let request = Request::builder().uri("/pub/api/packages/foo").body(Body::empty()).unwrap();
        let response = router.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::REQUEST_TIMEOUT);
        assert_eq!(response.headers()[header::CONTENT_TYPE], PUB_V2_MEDIA_TYPE);
        let json = body_json(response).await;
        assert_eq!(json["error"]["code"], "timeout", "spec shape, not the envelope: {json}");
        assert!(json.get("status").is_none(), "the envelope leaked onto a pub route: {json}");
    }

    #[tokio::test(start_paused = true)]
    async fn a_slow_app_api_request_times_out_with_the_envelope() {
        let router = slow_router(Duration::from_millis(50));
        let request = Request::builder().uri("/api/v1/slow").body(Body::empty()).unwrap();
        let response = router.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::REQUEST_TIMEOUT);
        let json = body_json(response).await;
        assert_eq!(json["status"], "error");
        assert_eq!(json["error"]["code"], "timeout");
    }

    #[tokio::test(start_paused = true)]
    async fn a_slow_asset_request_times_out_with_plain_text() {
        let router = slow_router(Duration::from_millis(50));
        let request = Request::builder().uri("/slow").body(Body::empty()).unwrap();
        let response = router.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::REQUEST_TIMEOUT);
        let bytes = response.into_body().collect().await.expect("body").to_bytes();
        assert!(serde_json::from_slice::<serde_json::Value>(&bytes).is_err(), "asset-family bodies are plain text");
    }

    #[tokio::test(start_paused = true)]
    async fn a_fast_request_is_untouched_by_the_deadline() {
        async fn fast() -> &'static str {
            "ok"
        }
        let router = Router::new().route("/api/v1/fast", get(fast)).layer(axum::middleware::from_fn(
            move |request: Request, next: Next| {
                let path = request.uri().path().to_owned();
                enforce_deadline(Duration::from_secs(30), path, request, next)
            },
        ));
        let request = Request::builder().uri("/api/v1/fast").body(Body::empty()).unwrap();
        let response = router.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn an_exhausted_semaphore_sheds_with_503_retry_after_and_the_family_shape() {
        async fn handler() -> &'static str {
            "served"
        }
        let capacity = Arc::new(Semaphore::new(0));
        let router = Router::new()
            .route("/api/v1/ping", get(handler))
            .route("/pub/api/packages/{name}", get(handler))
            .route("/healthz", get(handler))
            .route("/api/v1/mutate", post(handler))
            .layer(axum::middleware::from_fn(move |request: Request, next: Next| {
                let capacity = Arc::clone(&capacity);
                concurrency_shed(capacity, request, next)
            }));

        let api =
            router.clone().oneshot(Request::builder().uri("/api/v1/ping").body(Body::empty()).unwrap()).await.unwrap();
        assert_eq!(api.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(api.headers()[header::RETRY_AFTER], "1");
        let json = body_json(api).await;
        assert_eq!(json["status"], "error");
        assert_eq!(json["error"]["code"], "overloaded");

        let pub_shed = router
            .clone()
            .oneshot(Request::builder().uri("/pub/api/packages/foo").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(pub_shed.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(pub_shed.headers()[header::CONTENT_TYPE], PUB_V2_MEDIA_TYPE);
        assert_eq!(body_json(pub_shed).await["error"]["code"], "overloaded");

        // Liveness answers while everything else sheds (S-24 health-check exemption).
        let health =
            router.clone().oneshot(Request::builder().uri("/healthz").body(Body::empty()).unwrap()).await.unwrap();
        assert_eq!(health.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn a_bare_413_is_reshaped_into_the_family_body_and_json_ones_are_left_alone() {
        // What axum's length-limit rejection looks like: 413, plain text, no JSON anywhere.
        async fn bare() -> Response {
            (StatusCode::PAYLOAD_TOO_LARGE, "length limit exceeded").into_response()
        }
        // A 413 a handler shaped itself must pass through untouched.
        async fn shaped() -> Response {
            (StatusCode::PAYLOAD_TOO_LARGE, Json(serde_json::json!({ "custom": true }))).into_response()
        }
        let router = Router::new()
            .route("/api/v1/big", post(bare))
            .route("/pub/api/packages/versions/newUpload", post(bare))
            .route("/assets/big", post(bare))
            .route("/api/v1/custom", post(shaped))
            .layer(axum::middleware::from_fn(reshape_body_limit));

        let api = router
            .clone()
            .oneshot(Request::builder().method("POST").uri("/api/v1/big").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(api.status(), StatusCode::PAYLOAD_TOO_LARGE);
        let json = body_json(api).await;
        assert_eq!(json["status"], "error", "the app API answers the envelope: {json}");
        assert_eq!(json["error"]["code"], "payload_too_large");

        let pub_413 = router
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/pub/api/packages/versions/newUpload")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(pub_413.status(), StatusCode::PAYLOAD_TOO_LARGE);
        assert_eq!(pub_413.headers()[header::CONTENT_TYPE], PUB_V2_MEDIA_TYPE);
        let json = body_json(pub_413).await;
        assert_eq!(json["error"]["code"], "payload_too_large", "spec shape: {json}");
        assert!(json.get("status").is_none(), "the envelope leaked onto a pub route: {json}");

        let asset = router
            .clone()
            .oneshot(Request::builder().method("POST").uri("/assets/big").body(Body::empty()).unwrap())
            .await
            .unwrap();
        let bytes = asset.into_body().collect().await.expect("body").to_bytes();
        assert_eq!(&bytes[..], b"length limit exceeded", "asset-family 413s stay as axum made them");

        let custom = router
            .clone()
            .oneshot(Request::builder().method("POST").uri("/api/v1/custom").body(Body::empty()).unwrap())
            .await
            .unwrap();
        let json = body_json(custom).await;
        assert_eq!(json["custom"], true, "an already-JSON 413 must not be double-wrapped: {json}");
    }

    #[tokio::test]
    async fn a_released_permit_is_a_fresh_slot() {
        async fn handler() -> &'static str {
            "served"
        }
        let capacity = Arc::new(Semaphore::new(1));
        let router = Router::new().route("/api/v1/ping", get(handler)).layer(axum::middleware::from_fn(
            move |request: Request, next: Next| {
                let capacity = Arc::clone(&capacity);
                concurrency_shed(capacity, request, next)
            },
        ));
        for _ in 0..3 {
            let response = router
                .clone()
                .oneshot(Request::builder().uri("/api/v1/ping").body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK, "each completed request must return its slot");
        }
    }
}
