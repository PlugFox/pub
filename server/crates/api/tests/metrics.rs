//! What the exposition actually contains — [decision 28](../../../../docs/decisions.md#28).
//!
//! These assertions are against the **rendered Prometheus text**, not against the call sites,
//! because every interesting way to get this wrong is invisible at the call site: a `route`
//! label that silently degrades to a constant, a histogram that renders as a summary so
//! `histogram_quantile` finds nothing, a metric emitted under a name no dashboard queries.
//!
//! One global recorder per test binary (that is the API `metrics` offers), so these tests
//! share it and assert on *presence* rather than on exact counts.

mod common;

use std::sync::LazyLock;

use axum::http::StatusCode;
use common::TestApp;
use metrics_exporter_prometheus::{PrometheusBuilder, PrometheusHandle};

/// The one recorder this binary installs, with the same bucket configuration `pubd` uses.
static RECORDER: LazyLock<PrometheusHandle> = LazyLock::new(|| {
    PrometheusBuilder::new()
        .set_buckets(pub_telemetry::LATENCY_BUCKETS)
        .expect("buckets")
        .install_recorder()
        .expect("install the test recorder")
});

fn rendered() -> String {
    RECORDER.render()
}

/// **Decision 28.** The `route` label must be the router's *matched path*, not a constant.
///
/// This is the assertion that catches the axum trap: `MatchedPath` is inserted during routing,
/// so a middleware added with `Router::layer` — which wraps the whole router and therefore runs
/// *before* routing — never sees it, and every request silently collapses onto the family
/// fallback. The metric would still exist, still be bounded, and be useless: three buckets for
/// the whole surface, and a p95-by-route panel with nothing to group by.
#[tokio::test]
async fn the_route_label_is_the_matched_path_not_a_family_constant() {
    LazyLock::force(&RECORDER);
    let app = TestApp::new().await;

    let response = app.get("/api/v1/packages/some-package", None).await;
    // 404 is fine — the label is about which route matched, not what it answered.
    assert!(response.status.is_client_error() || response.status.is_success());

    let body = rendered();
    assert!(
        body.contains(r#"route="/api/v1/packages/{name}""#),
        "the matched route template must reach the label; got:\n{}",
        http_lines(&body)
    );
}

/// **Decision 28.** A request that matches no route still counts, under a **bounded** constant —
/// never `uri().path()`, which any anonymous caller could use to mint unbounded label values.
#[tokio::test]
async fn an_unrouted_path_counts_under_a_bounded_constant() {
    LazyLock::force(&RECORDER);
    let app = TestApp::new().await;

    let unique = "/api/v1/no-such-route-9f3a7c";
    assert_eq!(app.get(unique, None).await.status, StatusCode::NOT_FOUND);

    let body = rendered();
    assert!(body.contains(r#"route="{api}""#), "unrouted app-API paths need the family label:\n{}", http_lines(&body));
    assert!(!body.contains(unique), "the raw URI must never become a label value:\n{}", http_lines(&body));
}

/// **Decision 28.** The latency instrument must render as a real histogram.
///
/// Without explicit buckets this exporter renders distributions as **summaries**: the series
/// becomes `…{quantile="0.99"}`, `_bucket` never exists, and `histogram_quantile` — which every
/// dashboard and alert in `docs/ops/monitoring.md` uses — returns nothing at all. The catalogue
/// would call it a histogram and the exposition would disagree.
#[tokio::test]
async fn the_latency_instrument_renders_as_a_histogram_with_buckets() {
    LazyLock::force(&RECORDER);
    let app = TestApp::new().await;
    app.get("/api/v1/ping", None).await;

    let body = rendered();
    assert!(body.contains("# TYPE http_request_duration_seconds histogram"), "not a histogram:\n{}", http_lines(&body));
    assert!(
        body.contains("http_request_duration_seconds_bucket{"),
        "histogram_quantile needs _bucket series:\n{}",
        http_lines(&body)
    );
    assert!(body.contains(r#"le="+Inf""#), "a histogram needs its +Inf bucket:\n{}", http_lines(&body));
}

/// **Decision 28.** Shed and timeout responses are counted, because the dashboard exists for the
/// moments they happen. A metrics layer applied inside the shedder would omit exactly those.
#[tokio::test]
async fn a_shed_request_is_counted_rather_than_missing() {
    LazyLock::force(&RECORDER);
    // `concurrency_limit = 0` saturates the shedder deterministically (see hygiene's suite).
    let app =
        TestApp::with_options(common::TestOptions { concurrency_limit: 0, ..common::TestOptions::default() }).await;

    assert_eq!(app.get("/api/v1/ping", None).await.status, StatusCode::SERVICE_UNAVAILABLE);
    let body = rendered();
    assert!(body.contains(r#"status="503""#), "a shed request must be counted:\n{}", http_lines(&body));
}

/// **S-04.d.** `Server-Timing` is off unless the operator asks, and the authentication family
/// never carries it even then. Asserted on the wire rather than from the config, because the
/// header is the thing that leaks.
#[tokio::test]
async fn s04_d_server_timing_is_absent_by_default() {
    let app = TestApp::new().await;
    let response = app.get("/api/v1/ping", None).await;
    assert!(!response.headers.contains_key("server-timing"), "the timing header is opt-in (S-04.d)");
}

/// Only the HTTP metric lines, so a failure message is readable.
fn http_lines(body: &str) -> String {
    body.lines().filter(|line| line.contains("http_request")).take(40).collect::<Vec<_>>().join("\n")
}
