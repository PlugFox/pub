//! Tracing initialization and observability exports (decision 23).
//!
//! `tracing` instrumentation and `/healthz` are always on; exports are opt-in and off by
//! default. The Prometheus recorder is installed only when `telemetry.prometheus = true`;
//! the rendered handle is exposed so the api crate can mount `/metrics` in a later roadmap
//! step. OTLP export is a declared flag with a TODO — wiring arrives with the observability
//! roadmap step.

use metrics_exporter_prometheus::{PrometheusBuilder, PrometheusHandle};
use pub_config::TelemetryConfig;
use tracing_subscriber::EnvFilter;

/// Log output format.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum LogFormat {
    /// Human-readable multi-line output for development.
    #[default]
    Pretty,
    /// One JSON object per line for log shipping.
    Json,
}

/// Handles to the initialized telemetry stack.
pub struct Telemetry {
    /// Render handle for the Prometheus exposition text; `None` when the exporter is
    /// disabled by config or a recorder was already installed (tests).
    pub prometheus: Option<PrometheusHandle>,
}

/// Initializes tracing and the config-gated exporters. Safe to call more than once — later
/// calls keep the first subscriber/recorder (relevant for tests).
pub fn init(format: LogFormat, cfg: &TelemetryConfig) -> Telemetry {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let builder = tracing_subscriber::fmt().with_env_filter(filter);
    let subscriber_result = match format {
        LogFormat::Pretty => builder.pretty().try_init(),
        LogFormat::Json => builder.json().try_init(),
    };
    if subscriber_result.is_err() {
        tracing::debug!("tracing subscriber already initialized; keeping the existing one");
    }

    let prometheus = if cfg.prometheus {
        match PrometheusBuilder::new().install_recorder() {
            Ok(handle) => Some(handle),
            Err(err) => {
                tracing::warn!(error = %err, "failed to install prometheus recorder; metrics export disabled");
                None
            }
        }
    } else {
        None
    };

    if cfg.otlp {
        // TODO(roadmap/observability): wire OTLP trace export; the flag is honored as a
        // declared intent so configs stay forward-compatible.
        tracing::warn!("telemetry.otlp = true, but OTLP export is not implemented in the skeleton yet");
    }

    Telemetry { prometheus }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn init_is_idempotent_and_prometheus_is_config_gated() {
        // Disabled by default.
        let off = init(LogFormat::Pretty, &TelemetryConfig::default());
        assert!(off.prometheus.is_none());

        // Enabled by config: the first install wins and returns a handle.
        let on = init(LogFormat::Json, &TelemetryConfig { prometheus: true, otlp: false });
        assert!(on.prometheus.is_some());

        // A second install attempt must degrade gracefully, not panic.
        let again = init(LogFormat::Pretty, &TelemetryConfig { prometheus: true, otlp: true });
        assert!(again.prometheus.is_none());
    }
}
