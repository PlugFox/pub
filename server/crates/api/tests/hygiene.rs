//! Integration tests for the D8+D13 HTTP hygiene stack: S-28 transport headers, the two-tier
//! CSP (S-11), explicit CORS (S-12), the request deadline and its SSE exemption, load
//! shedding, the global body cap, and the cache/ETag tiers.
//!
//! Full router over in-memory backends (docs/rules/rust.md — no containers locally).

mod common;

use std::io::Write as _;
use std::time::Duration;

use axum::body::Body;
use axum::http::{Method, Request, StatusCode, header};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use common::{DEFAULT_IP, INSTANCE_ORIGIN, RawResponse, TestApp, TestOptions, package_archive};
use sha2::{Digest as _, Sha256};

/// Bare GET without app-API headers — the way a browser fetches a document.
async fn raw_get(app: &TestApp, path: &str) -> RawResponse {
    let request = Request::builder()
        .method(Method::GET)
        .uri(path)
        .header("x-forwarded-for", DEFAULT_IP)
        .body(Body::empty())
        .expect("build request");
    app.send_raw(request).await
}

// ----------------------------------------------------------------- S-28 transport headers

#[tokio::test]
async fn s28_transport_headers_are_present_on_every_family() {
    let app = TestApp::new().await;
    // A document, the health check, an app-API route, and a pub-protocol route: one path per
    // response family, because a header enforced by a scoped layer would pass three of them.
    for path in ["/", "/healthz", "/api/v1/ping", "/pub/api/packages/no_such_package"] {
        let response = raw_get(&app, path).await;
        let headers = &response.headers;
        assert_eq!(headers[header::X_CONTENT_TYPE_OPTIONS], "nosniff", "{path}");
        assert_eq!(headers[header::X_FRAME_OPTIONS], "DENY", "{path}");
        assert_eq!(headers[header::REFERRER_POLICY], "no-referrer", "{path}");
        assert_eq!(
            headers["permissions-policy"], "camera=(), microphone=(), geolocation=(), payment=(), usb=()",
            "{path}"
        );
        // The default test instance is https, so HSTS must be on (two years, subdomains).
        assert_eq!(headers[header::STRICT_TRANSPORT_SECURITY], "max-age=63072000; includeSubDomains", "{path}");
    }
}

#[tokio::test]
async fn s28_hsts_is_absent_when_the_public_url_is_plain_http() {
    // No knob: HSTS derives from the public URL's scheme. Browsers ignore the header over
    // plain http anyway, so sending it there would only be noise.
    let app =
        TestApp::with_options(TestOptions { public_url: "http://pub.corp.test".to_owned(), ..Default::default() })
            .await;
    for path in ["/", "/healthz", "/api/v1/ping"] {
        let response = raw_get(&app, path).await;
        assert!(
            !response.headers.contains_key(header::STRICT_TRANSPORT_SECURITY),
            "HSTS over http is dead weight on {path}"
        );
    }
}

// ------------------------------------------------------------------- S-11 two-tier CSP

#[tokio::test]
async fn s11_html_documents_carry_the_hashed_document_csp() {
    let app = TestApp::new().await;
    let response = raw_get(&app, "/").await;
    assert_eq!(response.status, StatusCode::OK);
    let csp = response.headers[header::CONTENT_SECURITY_POLICY].to_str().unwrap().to_owned();
    let html = String::from_utf8(response.body).unwrap();

    assert!(csp.starts_with("default-src 'self'; "), "documents are not the API policy: {csp}");
    assert!(!csp.contains("unsafe-inline"), "unsafe-inline would void S-11: {csp}");
    assert!(csp.contains("frame-ancestors 'none'"), "{csp}");
    assert!(csp.contains("object-src 'none'"), "{csp}");
    assert!(csp.contains("base-uri 'none'"), "{csp}");

    // The policy must whitelist the *served* inline blocks by hash — extracted from the very
    // body the server answered, so the assertion self-adapts to the embedded build exactly
    // like the startup scanner does (decision 14: Astro emits framework inline bootstraps).
    let script = html.split("<script>").nth(1).and_then(|rest| rest.split("</script>").next()).expect("inline script");
    let style = html.split("<style>").nth(1).and_then(|rest| rest.split("</style>").next()).expect("inline style");
    for (what, source) in [("script", script), ("style", style)] {
        let hash = format!("'sha256-{}'", B64.encode(Sha256::digest(source.as_bytes())));
        assert!(csp.contains(&hash), "served inline {what} is not hashed into the policy: {csp}");
    }
}

#[tokio::test]
async fn s11_the_service_worker_csp_permits_same_origin_fetch() {
    // A service worker's CSP comes from ITS OWN response headers (CSP3), not from the page
    // that registered it — so if /sw.js inherited the API family's `default-src 'none'`, the
    // install-time `cache.addAll(…)` and every runtime `fetch(request)` would be blocked and
    // the worker would never install, silently voiding decision 14's offline promise.
    let app = TestApp::new().await;
    let response = raw_get(&app, "/sw.js").await;
    assert_eq!(response.status, StatusCode::OK);
    let csp = response.headers[header::CONTENT_SECURITY_POLICY].to_str().unwrap();
    assert!(csp.contains("connect-src 'self'"), "the worker cannot populate its cache without it: {csp}");
    assert_ne!(csp, "default-src 'none'; frame-ancestors 'none'", "the API policy leaked onto the worker");
}

#[tokio::test]
async fn s11_api_and_pub_responses_carry_the_locked_down_csp() {
    let app = TestApp::new().await;
    for path in ["/api/v1/ping", "/api/openapi.json", "/pub/api/packages/no_such_package", "/healthz"] {
        let response = raw_get(&app, path).await;
        assert_eq!(
            response.headers[header::CONTENT_SECURITY_POLICY],
            "default-src 'none'; frame-ancestors 'none'",
            "API responses are data, not documents: {path}"
        );
    }
}

// --------------------------------------------------------------------- S-12 explicit CORS

/// A CORS preflight as the browser sends it.
fn preflight(origin: &str) -> Request<Body> {
    Request::builder()
        .method(Method::OPTIONS)
        .uri("/api/v1/tokens")
        .header(header::ORIGIN, origin)
        .header("access-control-request-method", "POST")
        .header("access-control-request-headers", "authorization,content-type,x-pub-request")
        .header("x-forwarded-for", DEFAULT_IP)
        .body(Body::empty())
        .expect("build request")
}

#[tokio::test]
async fn s12_preflight_from_the_instance_origin_is_allowed_without_credentials() {
    let app = TestApp::new().await;
    let response = app.send_raw(preflight(INSTANCE_ORIGIN)).await;
    assert_eq!(response.status, StatusCode::OK);
    let headers = &response.headers;
    assert_eq!(headers["access-control-allow-origin"], INSTANCE_ORIGIN);
    let methods = headers["access-control-allow-methods"].to_str().unwrap();
    for method in ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"] {
        assert!(methods.contains(method), "missing {method} in {methods}");
    }
    let allowed = headers["access-control-allow-headers"].to_str().unwrap().to_ascii_lowercase();
    for name in ["authorization", "content-type", "x-pub-request"] {
        assert!(allowed.contains(name), "missing {name} in {allowed}");
    }
    assert_eq!(headers["access-control-max-age"], "3600");
    // Cookieless API (decision 03): credentials stay off, so a stolen cookie cannot exist and
    // a wildcard-with-credentials misconfiguration cannot either.
    assert!(!headers.contains_key("access-control-allow-credentials"));
}

#[tokio::test]
async fn s12_preflight_from_a_foreign_origin_earns_no_allow_origin() {
    let app = TestApp::new().await;
    for hostile in ["https://evil.example", "http://pub.corp.test", "https://pub.corp.test.evil.example"] {
        let response = app.send_raw(preflight(hostile)).await;
        assert!(!response.headers.contains_key("access-control-allow-origin"), "{hostile} must not be allowed");
    }
}

#[tokio::test]
async fn s12_actual_responses_echo_only_the_instance_origin() {
    let app = TestApp::new().await;
    let same = Request::builder()
        .method(Method::GET)
        .uri("/api/v1/ping")
        .header(header::ORIGIN, INSTANCE_ORIGIN)
        .header("x-forwarded-for", DEFAULT_IP)
        .body(Body::empty())
        .unwrap();
    let response = app.send_raw(same).await;
    assert_eq!(response.headers["access-control-allow-origin"], INSTANCE_ORIGIN);

    let foreign = Request::builder()
        .method(Method::GET)
        .uri("/api/v1/ping")
        .header(header::ORIGIN, "https://evil.example")
        .header("x-forwarded-for", DEFAULT_IP)
        .body(Body::empty())
        .unwrap();
    let response = app.send_raw(foreign).await;
    assert!(!response.headers.contains_key("access-control-allow-origin"));
}

// ------------------------------------------------------- D13 request deadline / SSE carve-out

#[tokio::test]
async fn sse_stream_survives_a_request_timeout_shorter_than_its_life() {
    // Honesty note: today's deadline bounds the *response head* only, and an SSE head
    // resolves in milliseconds — so with the current middleware this test would pass even
    // without the `/api/v1/events` exemption. It is kept as a **canary against a future
    // body-inclusive timeout** (e.g. swapping in a layer that bounds the whole response):
    // the stream below outlives the configured deadline, so such a change would sever it
    // here first. The real exemption guarantee is pinned by the `budget_for` unit test in
    // `src/hygiene.rs`; the stream's actual bound is the token expiry re-checked per
    // heartbeat (S-32).
    //
    // The deadline is 3s, not 1s, so the login flow (which rides the same deadline) has
    // slack on a loaded CI machine; the heartbeats then have to outlive those 3s.
    let app =
        TestApp::with_options(TestOptions { request_timeout_secs: 3, sse_heartbeat_secs: 1, ..Default::default() })
            .await;
    let login = app.login("stream@corp.test").await;
    let access = login["access_token"].as_str().expect("access token");

    let mut stream = app.open_stream(access, None).await;
    assert_eq!(stream.status, StatusCode::OK);
    // Four 1s heartbeats carry the stream past the 3s deadline.
    for n in 1..=4 {
        let frame = stream
            .next_frame(Duration::from_secs(10))
            .await
            .unwrap_or_else(|| panic!("the stream must live past the request deadline (heartbeat {n})"));
        assert!(frame.is_heartbeat(), "unexpected frame: {frame:?}");
    }
}

#[tokio::test]
async fn a_handler_exceeding_the_deadline_answers_408_through_the_real_router() {
    // End-to-end proof that the timeout layer is actually in the stack: without it, this
    // request would simply take ~2s and answer 200/404 — deleting the layer turns this test
    // red. An unclaimed name under a proxying base makes the handler genuinely slow: the
    // scripted upstream delays its listing response past the 1s budget.
    let app =
        TestApp::with_options(TestOptions { request_timeout_secs: 1, upstream: true, ..Default::default() }).await;
    app.mock_upstream().publish("upstream_pkg", &[("1.0.0", b"bytes".as_slice())]);
    app.mock_upstream().set_delay(Duration::from_secs(2));

    let response = app.pub_get("/pub/api/packages/upstream_pkg", None).await;
    assert_eq!(response.status, StatusCode::REQUEST_TIMEOUT, "{:?}", response.json);
    // The middleware answers in the pub family's own dialect (docs/rules/api.md).
    assert_eq!(response.headers[header::CONTENT_TYPE], "application/vnd.pub.v2+json");
    assert_eq!(response.json["error"]["code"], "timeout", "spec shape: {:?}", response.json);
    assert!(response.json.get("status").is_none(), "the envelope must not leak onto pub routes");
}

// ------------------------------------------------------------------------ D8 load shedding

#[tokio::test]
async fn concurrency_shed_answers_503_in_the_family_shape_and_spares_healthz() {
    // A zero-slot semaphore is the deterministic saturation: TestApp builds `Settings`
    // directly (no `validate()`), so the config floor of 16 does not apply here, and no test
    // has to race 1024 parked requests.
    let app = TestApp::with_options(TestOptions { concurrency_limit: 0, ..Default::default() }).await;

    let api = app.get("/api/v1/ping", None).await;
    assert_eq!(api.status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(api.headers[header::RETRY_AFTER], "1");
    assert_eq!(api.json["status"], "error", "app API sheds in the envelope: {:?}", api.json);
    assert_eq!(api.json["error"]["code"], "overloaded");

    let pub_shed = app.pub_get("/pub/api/packages/anything", None).await;
    assert_eq!(pub_shed.status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(pub_shed.headers[header::RETRY_AFTER], "1");
    assert_eq!(pub_shed.headers[header::CONTENT_TYPE], "application/vnd.pub.v2+json");
    assert_eq!(pub_shed.json["error"]["code"], "overloaded", "pub routes shed in the spec shape");
    assert!(pub_shed.json.get("status").is_none(), "the envelope must not leak onto pub routes");

    let asset = raw_get(&app, "/").await;
    assert_eq!(asset.status, StatusCode::SERVICE_UNAVAILABLE);

    // Liveness answers while everything else sheds (S-24 exempts health checks from limits):
    // an orchestrator must be able to tell "shedding" from "dead".
    let health = raw_get(&app, "/healthz").await;
    assert_eq!(health.status, StatusCode::OK);
}

// ---------------------------------------------------------------------- D8 global body cap

#[tokio::test]
async fn a_3mib_app_api_body_is_413_in_the_envelope_while_a_bigger_upload_still_passes() {
    let app = TestApp::new().await;

    // The global 2 MiB cap refuses an oversized app-API body. Axum's own length-limit
    // rejection is plain text; the hygiene response pass reshapes it into the envelope,
    // because every route under /api answers the envelope — middleware-made or not
    // (docs/rules/api.md, same contract as the 408/503 bodies).
    let padded = serde_json::json!({ "email": "big@corp.test", "pad": "x".repeat(3 * 1024 * 1024) });
    let response = app.post("/api/v1/auth/otp/request", None, padded).await;
    assert_eq!(response.status, StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(response.json["status"], "error", "413 must answer the envelope: {:?}", response.json);
    assert_eq!(response.error_code(), "payload_too_large");

    // …while the publish upload rides its own limit (archive cap + multipart envelope): the
    // subrouter's `DefaultBodyLimit` must override the global one, or every real package
    // over 2 MiB would be unpublishable.
    let (access, org) = app.org_owner("uploader@corp.test", "bigco").await;
    let token = app.mint_token(&access, org, &["read", "publish"]).await;
    let archive = incompressible_archive("big_pkg", "1.0.0", 3 * 1024 * 1024);
    assert!(archive.len() > 2 * 1024 * 1024, "fixture must exceed the global cap ({})", archive.len());

    let ticket = app.pub_get("/o/bigco/pub/api/packages/versions/new", Some(&token)).await;
    assert_eq!(ticket.status, StatusCode::OK, "ticket failed: {:?}", ticket.json);
    let url = ticket.json["url"].as_str().expect("upload url").to_owned();
    let upload = app.pub_upload(&app.proxied(&url), Some(&token), &archive).await;
    assert_eq!(
        upload.status,
        StatusCode::NO_CONTENT,
        "a >2MiB archive must pass the upload subrouter: {:?}",
        String::from_utf8_lossy(&upload.body)
    );
}

/// A valid `.tar.gz` package archive padded past `payload_bytes` with data gzip cannot shrink.
fn incompressible_archive(name: &str, version: &str, payload_bytes: usize) -> Vec<u8> {
    let pubspec = format!("name: {name}\nversion: {version}\ndescription: Oversized fixture.\n");
    let mut builder = tar::Builder::new(Vec::new());
    let mut append = |path: &str, content: &[u8]| {
        let mut header = tar::Header::new_gnu();
        header.set_size(content.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        builder.append_data(&mut header, path, content).expect("append");
    };
    append("pubspec.yaml", pubspec.as_bytes());
    append("README.md", b"# big\n");
    append("assets/noise.bin", &noise(payload_bytes));
    let tar = builder.into_inner().expect("finish tar");
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    encoder.write_all(&tar).expect("gzip");
    encoder.finish().expect("finish gzip")
}

/// Deterministic xorshift noise — statistically incompressible, no `rand` needed.
fn noise(len: usize) -> Vec<u8> {
    let mut state = 0x9e37_79b9_7f4a_7c15_u64;
    let mut out = Vec::with_capacity(len + 8);
    while out.len() < len {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        out.extend_from_slice(&state.to_le_bytes());
    }
    out.truncate(len);
    out
}

// ------------------------------------------------------------------- D8 cache tiers & ETags

#[tokio::test]
async fn html_documents_revalidate_with_strong_etags() {
    let app = TestApp::new().await;
    let first = raw_get(&app, "/").await;
    assert_eq!(first.status, StatusCode::OK);
    assert_eq!(first.headers[header::CACHE_CONTROL], "no-cache");
    let etag = first.headers[header::ETAG].to_str().unwrap().to_owned();
    assert!(etag.starts_with('"') && etag.ends_with('"'), "strong quoted ETag, got {etag}");
    let document_csp = first.headers[header::CONTENT_SECURITY_POLICY].to_str().unwrap().to_owned();

    // A matching validator is a 304 that keeps ETag + Cache-Control (the client refreshes
    // its cache entry's metadata from them) and carries no body. It must also keep the
    // document CSP (S-11): RFC 9111 §4.3.4 makes the 304's headers *replace* the stored
    // ones, so a 304 without the CSP would let the outer API-family layer stamp
    // `default-src 'none'` onto the cached document — a blank page on every revalidated
    // navigation, i.e. from the second visit on.
    for validator in [etag.clone(), format!("W/{etag}"), format!("\"unrelated\", {etag}")] {
        let request = Request::builder()
            .method(Method::GET)
            .uri("/")
            .header(header::IF_NONE_MATCH, &validator)
            .header("x-forwarded-for", DEFAULT_IP)
            .body(Body::empty())
            .unwrap();
        let revalidated = app.send_raw(request).await;
        assert_eq!(revalidated.status, StatusCode::NOT_MODIFIED, "validator {validator}");
        assert!(revalidated.body.is_empty());
        assert_eq!(revalidated.headers[header::ETAG].to_str().unwrap(), etag);
        assert_eq!(revalidated.headers[header::CACHE_CONTROL], "no-cache");
        let revalidated_csp = revalidated.headers[header::CONTENT_SECURITY_POLICY].to_str().unwrap();
        assert_eq!(revalidated_csp, document_csp, "the 304 must carry the same CSP as the 200 (S-11)");
        assert!(revalidated_csp.starts_with("default-src 'self'"), "API policy on a document 304: {revalidated_csp}");
    }

    // A stale validator is a fresh 200.
    let request = Request::builder()
        .method(Method::GET)
        .uri("/")
        .header(header::IF_NONE_MATCH, "\"stale\"")
        .header("x-forwarded-for", DEFAULT_IP)
        .body(Body::empty())
        .unwrap();
    let miss = app.send_raw(request).await;
    assert_eq!(miss.status, StatusCode::OK);
    assert!(!miss.body.is_empty());
}

#[tokio::test]
async fn hashed_assets_are_served_immutable() {
    let app = TestApp::new().await;
    let response = raw_get(&app, "/_astro/placeholder.css").await;
    assert_eq!(response.status, StatusCode::OK);
    assert_eq!(response.headers[header::CACHE_CONTROL], "public, max-age=31536000, immutable");
    assert!(response.headers.contains_key(header::ETAG));
    assert!(response.headers[header::CONTENT_TYPE].to_str().unwrap().starts_with("text/css"));
}

#[tokio::test]
async fn api_and_pub_json_are_never_stored() {
    let app = TestApp::new().await;
    for path in ["/api/v1/ping", "/healthz", "/api/openapi.json", "/pub/api/packages/no_such_package"] {
        let response = raw_get(&app, path).await;
        assert_eq!(response.headers[header::CACHE_CONTROL], "no-store", "{path} may carry per-principal data");
    }
}

#[tokio::test]
async fn s18_archive_downloads_are_immutable_with_the_content_hash_etag() {
    let app = TestApp::new().await;
    let (access, org) = app.org_owner("owner@corp.test", "acme").await;
    let token = app.mint_token(&access, org, &["read", "publish"]).await;
    let published = app.publish("/o/acme/pub", &token, &package_archive("acme_core", "1.0.0")).await;
    assert_eq!(published.status, StatusCode::OK, "publish failed: {:?}", published.json);

    let listing = app.pub_get("/o/acme/pub/api/packages/acme_core", Some(&token)).await;
    assert_eq!(listing.status, StatusCode::OK);
    let sha256 = listing.json["latest"]["archive_sha256"].as_str().expect("sha256").to_owned();
    let url = listing.json["latest"]["archive_url"].as_str().expect("archive url").to_owned();

    let archive = app.pub_get_raw(&app.proxied(&url), Some(&token)).await;
    assert_eq!(archive.status, StatusCode::OK);
    // Content addressing (S-18): the bytes behind a name+version can never change, so the
    // archive is cacheable forever — but `private`, because this org's registry is.
    assert_eq!(archive.headers[header::CACHE_CONTROL], "private, max-age=31536000, immutable");
    assert_eq!(archive.headers[header::ETAG].to_str().unwrap(), format!("\"{sha256}\""));
}
