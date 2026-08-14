//! Tracing initialization and the observability plane (decisions 23 and 28).
//!
//! `tracing` instrumentation and `/healthz` are always on; exports are opt-in and off by
//! default. When `telemetry.prometheus` is set this crate installs the recorder, describes
//! every instrument (so the exposition carries `# HELP` and `# TYPE`), spawns the recorder's
//! upkeep task, and serves the exposition on a **separate listener** — never a route on the
//! application router, for the three reasons decision 28 records.
//!
//! The [`INSTRUMENTS`] catalogue is the single source of truth for what this product exports.
//! Two tests keep it honest: one renders `docs/ops/metrics.md` from it and byte-compares, the
//! other scans every `metrics::*!` call site in the workspace and fails on a name that is not
//! catalogued. A metric that exists only in code is a metric nobody can find.

use std::net::SocketAddr;

use axum::Router;
use axum::http::{StatusCode, header};
use axum::response::IntoResponse;
use axum::routing::get;
use metrics_exporter_prometheus::{PrometheusBuilder, PrometheusHandle};
use pub_config::{LogFormat, TelemetryConfig};
use tracing_subscriber::EnvFilter;

mod catalogue;
pub use catalogue::{INSTRUMENTS, Instrument, InstrumentKind};

/// Handles to the initialized telemetry stack.
pub struct Telemetry {
    /// Render handle for the Prometheus exposition text; `None` when the exporter is
    /// disabled by config or a recorder was already installed (tests).
    pub prometheus: Option<PrometheusHandle>,
}

/// Initializes tracing and the config-gated exporters. Safe to call more than once — later
/// calls keep the first subscriber/recorder (relevant for tests).
///
/// Must be called from inside a Tokio runtime when `prometheus` is enabled: the recorder's
/// upkeep task is spawned here rather than left to the caller. `install_recorder` spawns
/// nothing of its own, and an un-upkept recorder leaks histogram buckets for the life of the
/// process — harmless while every instrument is a counter or a gauge, and no longer true since
/// [`catalogue`] added `http_request_duration_seconds`.
pub fn init(cfg: &TelemetryConfig) -> Telemetry {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let builder = tracing_subscriber::fmt().with_env_filter(filter);
    let subscriber_result = match cfg.log_format {
        LogFormat::Pretty => builder.pretty().try_init(),
        LogFormat::Json => builder.json().try_init(),
    };
    if subscriber_result.is_err() {
        tracing::debug!("tracing subscriber already initialized; keeping the existing one");
    }

    let prometheus = if cfg.prometheus {
        let builder = PrometheusBuilder::new()
            .set_buckets(LATENCY_BUCKETS)
            .expect("LATENCY_BUCKETS is a non-empty ascending ladder");
        match builder.install_recorder() {
            Ok(handle) => {
                catalogue::describe_all();
                spawn_upkeep(handle.clone());
                Some(handle)
            }
            Err(err) => {
                tracing::warn!(error = %err, "failed to install prometheus recorder; metrics export disabled");
                None
            }
        }
    } else {
        None
    };

    Telemetry { prometheus }
}

/// Bucket ladder for `http_request_duration_seconds`, in seconds.
///
/// **Explicit buckets are not a tuning choice, they decide the metric's type.** With none
/// configured this exporter renders every distribution as a *summary* — pre-computed quantiles,
/// no `_bucket` series — so `histogram_quantile` finds nothing, and every latency panel and
/// alert in `docs/ops/monitoring.md` returns empty while the catalogue calls it a histogram.
/// Summaries also cannot be aggregated across instances, which is the whole point of a p95 on a
/// multi-replica deployment.
///
/// The ladder is a web ladder: dense from a millisecond to a second (where the read model and
/// the protocol's resolve endpoint live), then coarse out to a minute for uploads and proxied
/// cold-cache fetches. Public because the api crate's tests assert against the *rendered*
/// exposition and must configure the recorder exactly as `pubd` does.
pub const LATENCY_BUCKETS: &[f64] = &[0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0, 60.0];

/// Interval between recorder upkeep passes — the exporter's own recommended cadence.
const UPKEEP_INTERVAL: std::time::Duration = std::time::Duration::from_secs(5);

/// Runs the recorder's upkeep on an interval, for the life of the process.
fn spawn_upkeep(handle: PrometheusHandle) {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(UPKEEP_INTERVAL);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            ticker.tick().await;
            handle.run_upkeep();
        }
    });
}

/// The exposition router: `GET /metrics` and nothing else.
///
/// Separate from the application router on purpose (decision 28), which is also why it needs
/// none of that router's middleware: no load shedding (a scrape must answer while the instance
/// is saturated — that is when it matters), and its own `no-store`, because a cached scrape is
/// a lie about a moment that has passed.
pub fn metrics_router(handle: PrometheusHandle) -> Router {
    Router::new().route(
        "/metrics",
        get(move || {
            let body = handle.render();
            std::future::ready(
                (
                    StatusCode::OK,
                    [
                        (header::CONTENT_TYPE, "text/plain; version=0.0.4; charset=utf-8"),
                        (header::CACHE_CONTROL, "no-store"),
                    ],
                    body,
                )
                    .into_response(),
            )
        }),
    )
}

/// Binds the metrics listener.
///
/// Separate from [`serve_metrics`] so the caller can fail *startup* on a bad address: an
/// address already in use means the operator asked for an export they are not getting, and
/// discovering that from a detached task's log line — or from the first scrape — is worse than
/// refusing to start.
pub async fn bind_metrics(addr: SocketAddr) -> std::io::Result<tokio::net::TcpListener> {
    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!(%addr, "prometheus exposition listening on /metrics");
    Ok(listener)
}

/// Serves the exposition on an already-bound listener until `shutdown` resolves.
pub async fn serve_metrics(
    listener: tokio::net::TcpListener,
    handle: PrometheusHandle,
    shutdown: impl Future<Output = ()> + Send + 'static,
) -> std::io::Result<()> {
    axum::serve(listener, metrics_router(handle)).with_graceful_shutdown(shutdown).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn init_is_idempotent_and_prometheus_is_config_gated() {
        // Disabled by default.
        let off = init(&TelemetryConfig::default());
        assert!(off.prometheus.is_none());

        // Enabled by config: the first install wins and returns a handle.
        let on = init(&TelemetryConfig { prometheus: true, ..TelemetryConfig::default() });
        assert!(on.prometheus.is_some());

        // A second install attempt must degrade gracefully, not panic.
        let again =
            init(&TelemetryConfig { prometheus: true, log_format: LogFormat::Json, ..TelemetryConfig::default() });
        assert!(again.prometheus.is_none());
    }

    /// The exposition must be self-describing: a scrape with no `# HELP`/`# TYPE` is what the
    /// missing `describe_*!` calls produced, and it is what makes a dashboard guesswork.
    #[tokio::test]
    async fn the_exposition_carries_help_and_type_for_a_described_instrument() {
        // A *local* recorder, so the assertion never depends on which test in this binary
        // installed the global one first.
        let recorder = PrometheusBuilder::new().build_recorder();
        let handle = recorder.handle();
        metrics::with_local_recorder(&recorder, || {
            catalogue::describe_all();
            metrics::counter!("queue_jobs_total", "kind" => "mail", "outcome" => "delivered").increment(1);
        });
        let body = handle.render();
        assert!(body.contains("# HELP queue_jobs_total"), "the exposition must carry HELP:\n{body}");
        assert!(body.contains("# TYPE queue_jobs_total counter"), "and TYPE:\n{body}");
    }

    /// A scrape is a snapshot of a moment that has already passed; a cache of one is a lie.
    #[tokio::test]
    async fn the_metrics_route_answers_plain_text_and_forbids_caching() {
        use tower::ServiceExt as _;

        let recorder = PrometheusBuilder::new().build_recorder();
        let response = metrics_router(recorder.handle())
            .oneshot(axum::http::Request::builder().uri("/metrics").body(axum::body::Body::empty()).unwrap())
            .await
            .expect("the metrics router answers");
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
        assert!(response.headers()[header::CONTENT_TYPE].to_str().unwrap().starts_with("text/plain"));
    }
}
