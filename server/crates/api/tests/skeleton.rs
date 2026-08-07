//! Integration tests for the API skeleton: full router over in-memory backends
//! (docs/rules/rust.md — no containers locally).

mod common;

use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use http_body_util::BodyExt;
use tower::ServiceExt;

async fn test_router() -> Router {
    common::TestApp::new().await.router
}

async fn get(path: &str) -> (StatusCode, axum::http::HeaderMap, Vec<u8>) {
    let response =
        test_router().await.oneshot(Request::builder().uri(path).body(Body::empty()).unwrap()).await.unwrap();
    let (parts, body) = response.into_parts();
    let bytes = body.collect().await.unwrap().to_bytes().to_vec();
    (parts.status, parts.headers, bytes)
}

fn json(bytes: &[u8]) -> serde_json::Value {
    serde_json::from_slice(bytes).expect("response body must be valid JSON")
}

#[tokio::test]
async fn healthz_reports_status_version_and_backend_kinds() {
    let (status, headers, body) = get("/healthz").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(headers[header::CONTENT_TYPE], "application/json");

    let body = json(&body);
    assert_eq!(body["status"], "ok");
    // The surfaced version is the single shared constant (decision 18): the release
    // version when `PUB_VERSION` was injected at build time, the crate version + `+dev`
    // otherwise — never the bare crate version of the api crate.
    assert_eq!(body["version"], pub_core::version::VERSION);
    assert_eq!(body["backends"]["database"], "sqlite");
    assert_eq!(body["backends"]["blob"], "memory");
    assert_eq!(body["backends"]["kv"], "memory");
    // Live pings, not config echoes: the database check hits the migrated :memory: db.
    assert_eq!(body["checks"]["database"], true);
    assert_eq!(body["checks"]["blob"], true);
    assert_eq!(body["checks"]["kv"], true);
}

#[tokio::test]
async fn ping_uses_the_app_envelope() {
    let (status, _headers, body) = get("/api/v1/ping").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json(&body), serde_json::json!({"status": "ok", "data": "pong"}));
}

#[tokio::test]
async fn index_html_is_served_at_root() {
    let (status, headers, body) = get("/").await;
    assert_eq!(status, StatusCode::OK);
    let content_type = headers[header::CONTENT_TYPE].to_str().unwrap();
    assert!(content_type.starts_with("text/html"), "unexpected content-type: {content_type}");
    let html = String::from_utf8(body).unwrap();
    assert!(html.contains("<title>Pub</title>"), "placeholder index.html must be served");
}

/// Every client-routed path under `/app` must reach the **app shell** — the document that
/// mounts the SolidJS island — and not the landing page. Astro emits the shell as
/// `app/index.html`, so a resolver that only tries the literal request path answers a
/// marketing page for every deep link and reload, and the app never boots.
#[tokio::test]
async fn client_routed_app_paths_serve_the_app_shell() {
    for path in
        ["/app", "/app/", "/app/orgs/acme/packages", "/app/packages/foo/versions/1.0.0", "/app/auth/callback/google"]
    {
        let (status, headers, body) = get(path).await;
        assert_eq!(status, StatusCode::OK, "{path}");
        assert!(headers[header::CONTENT_TYPE].to_str().unwrap().starts_with("text/html"), "{path}");
        let html = String::from_utf8(body).unwrap();
        assert!(html.contains("app shell"), "{path} did not resolve to app/index.html:\n{html}");
    }
}

/// The build is directory-style (`/app/search` → `app/search/index.html`); the resolver has to
/// try the directory index before it gives up, or every prerendered route below the root is a
/// miss.
#[tokio::test]
async fn a_directory_path_resolves_to_its_index_html() {
    // In the placeholder tree `app/` is the only directory, which is exactly the shape this
    // rule has to handle: the trailing slash must not defeat the lookup.
    let (status, _headers, body) = get("/app/").await;
    assert_eq!(status, StatusCode::OK);
    assert!(String::from_utf8(body).unwrap().contains("app shell"));
}

/// A typo outside the app is not the landing page. Serving `index.html` with 200 tells
/// crawlers, link checkers, and the service worker that a nonexistent path is a real page.
#[tokio::test]
async fn unknown_non_app_path_answers_404_with_the_static_page() {
    let (status, headers, body) = get("/no-such-page").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert!(headers[header::CONTENT_TYPE].to_str().unwrap().starts_with("text/html"));
    assert!(String::from_utf8(body).unwrap().contains("<title>404 — Pub</title>"));
}

/// rust-embed refuses to escape its folder on its own; the resolver refuses to *ask*, so a
/// traversal attempt is a plain 404 rather than a lookup with a hopeful outcome.
#[tokio::test]
async fn traversal_segments_never_resolve() {
    for path in ["/../Cargo.toml", "/app/../../Cargo.toml", "/./index.html"] {
        let (status, _headers, _body) = get(path).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{path}");
    }
}

#[tokio::test]
async fn unknown_api_route_returns_the_error_envelope() {
    let (status, headers, body) = get("/api/v1/does-not-exist").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(headers[header::CONTENT_TYPE], "application/json");

    let body = json(&body);
    assert_eq!(body["status"], "error");
    assert_eq!(body["error"]["code"], "not_found");
    assert!(body["error"]["message"].is_string());
}

#[tokio::test]
async fn security_headers_are_present_on_every_response() {
    for path in ["/", "/healthz", "/api/v1/ping", "/api/v1/does-not-exist"] {
        let (_status, headers, _body) = get(path).await;
        assert_eq!(headers[header::X_CONTENT_TYPE_OPTIONS], "nosniff", "missing nosniff on {path}");
        assert_eq!(
            headers[header::CONTENT_SECURITY_POLICY],
            "frame-ancestors 'none'",
            "missing frame-ancestors on {path}"
        );
        assert_eq!(headers[header::X_FRAME_OPTIONS], "DENY", "missing x-frame-options on {path}");
        assert!(headers.contains_key("x-request-id"), "missing x-request-id on {path}");
    }
}

#[tokio::test]
async fn openapi_json_documents_the_registered_routes() {
    let (status, headers, body) = get("/api/openapi.json").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(headers[header::CONTENT_TYPE], "application/json");

    let doc = json(&body);
    assert_eq!(doc["info"]["title"], "Pub API");
    assert!(doc["paths"]["/healthz"]["get"].is_object(), "healthz missing from OpenAPI");
    assert!(doc["paths"]["/api/v1/ping"]["get"].is_object(), "ping missing from OpenAPI");
}
