//! The catalogue of every instrument this product exports (decision 28).
//!
//! One list, three consumers: [`describe_all`] turns it into the `# HELP`/`# TYPE` lines of the
//! exposition, `tests/reference.rs` renders `docs/ops/metrics.md` from it and byte-compares,
//! and `tests/drift.rs` scans every `metrics::*!` call site in the workspace and fails on a
//! name that is not here. Before this list existed, `architecture.md` documented 11 names
//! against 21 emitted and nothing noticed.
//!
//! **Adding an instrument**: emit it, add it here, run
//! `UPDATE_METRICS_REFERENCE=1 cargo test -p pub-telemetry`. The drift test fails until the
//! catalogue names it, which is the point — an instrument nobody can find is not observability.

/// What an instrument is, in Prometheus terms.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InstrumentKind {
    /// Monotonic count of things that happened.
    Counter,
    /// A value that goes up and down; the current state of something.
    Gauge,
    /// A distribution of observations.
    Histogram,
}

impl InstrumentKind {
    /// The word Prometheus uses, and the one `docs/ops/metrics.md` prints.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Counter => "counter",
            Self::Gauge => "gauge",
            Self::Histogram => "histogram",
        }
    }
}

/// One exported instrument.
#[derive(Debug, Clone, Copy)]
pub struct Instrument {
    /// Metric name, exactly as the `metrics::*!` call site spells it.
    pub name: &'static str,
    /// Counter, gauge or histogram.
    pub kind: InstrumentKind,
    /// Label keys the emitter attaches, in the order it attaches them.
    pub labels: &'static [&'static str],
    /// The `# HELP` text — written for whoever is reading a dashboard at 3am, not for whoever
    /// wrote the emitter.
    pub help: &'static str,
}

/// Every instrument, grouped by subsystem and sorted by name inside each group.
///
/// The order is the order `docs/ops/metrics.md` prints, so it is chosen for a reader.
pub const INSTRUMENTS: &[Instrument] = &[
    // --- HTTP (decision 28: the RED metrics that did not exist) ---
    Instrument {
        name: "http_requests_total",
        kind: InstrumentKind::Counter,
        labels: &["route", "method", "status"],
        help: "HTTP requests answered, by matched route, method and status code. `route` is the \
               router's matched path or one of the bounded fallbacks `{api}`, `{pub}`, `{asset}` \
               — never the raw URI, which an anonymous caller could otherwise choose.",
    },
    Instrument {
        name: "http_request_duration_seconds",
        kind: InstrumentKind::Histogram,
        labels: &["route", "method", "status"],
        help: "Time to the response head, in seconds. Excludes streaming bodies: an archive \
               download's head is written long before its last byte.",
    },
    // --- abuse limits (S-24) ---
    Instrument {
        name: "rate_limit_trips_total",
        kind: InstrumentKind::Counter,
        labels: &["limit"],
        help: "Requests refused by a rate limit, by bucket family — credential buckets \
               (otp_email, otp_ip, login_ip, token_auth_ip), read buckets (read_per_ip, \
               read_per_token, read_per_user), write buckets (write_per_ip, write_per_token, \
               write_per_user), the per-org publish budget, the audit-export budget, and the \
               two invitation caps. This is the volume signal, and it is the only one: the \
               audit log records at most one row per bucket per window everywhere, so row \
               count measures windows entered rather than requests refused.",
    },
    Instrument {
        name: "rate_limit_fallback_total",
        kind: InstrumentKind::Counter,
        labels: &["bucket"],
        help: "Auth-abuse limit decisions taken by this instance's in-process fallback because \
               the KV was unreachable (S-24.e). Non-zero means the shared limiter is down and \
               the effective budget is per instance — up to N x the limit across N replicas.",
    },
    // --- registry ---
    Instrument {
        name: "latest_window_exhausted_total",
        kind: InstrumentKind::Counter,
        labels: &[],
        help: "Times the `latest` rule ran out of its 1 000-version window before finding a live \
               stable release, so the answer came from the newest versions alone (decision 32). \
               A counter rather than a log line because the scan runs on the anonymous package \
               page, where a read loop would otherwise choose the log volume.",
    },
    Instrument {
        name: "publishes_total",
        kind: InstrumentKind::Counter,
        labels: &["format"],
        help: "Versions successfully published, by artifact format (decision 21).",
    },
    Instrument {
        name: "downloads_total",
        kind: InstrumentKind::Counter,
        labels: &[],
        help: "Archive downloads folded into the durable counters by the rollup job.",
    },
    Instrument {
        name: "storage_quota_refusals_total",
        kind: InstrumentKind::Counter,
        labels: &["stage"],
        help: "Publishes refused because the organization is at its storage quota (S-20.b), by \
               which of the two checkpoints refused. `stage=\"upload\"` means the archive never \
               reached the staging area; `stage=\"finalize\"` means it did and the bytes were \
               then discarded — a sustained gap between the two is a client that keeps \
               finalizing uploads it started before the wall.",
    },
    Instrument {
        name: "search_reindex_documents_total",
        kind: InstrumentKind::Counter,
        labels: &[],
        help: "Search documents written by the reindex job.",
    },
    Instrument {
        name: "search_reindex_removed_total",
        kind: InstrumentKind::Counter,
        labels: &[],
        help: "Search documents removed by the reindex job.",
    },
    // --- supply chain (the signals decision 07 and S-21 exist to produce) ---
    Instrument {
        name: "quarantine_total",
        kind: InstrumentKind::Counter,
        labels: &[],
        help: "Upstream archives quarantined because their bytes did not hash to the digest the \
               upstream advertised. Any non-zero value is worth a look: it is either a broken \
               mirror or an attempted substitution.",
    },
    Instrument {
        name: "upstream_drift_total",
        kind: InstrumentKind::Counter,
        labels: &[],
        help: "Upstream versions whose bytes changed after we had cached them. The cached copy \
               is kept and the alarm is raised; a published version's bytes are immutable, so \
               drift is always a fact about the upstream, never about us.",
    },
    Instrument {
        name: "shadowing_alarms_total",
        kind: InstrumentKind::Counter,
        labels: &[],
        help: "Local package names that also exist upstream. Not an error — an operator decision \
               about dependency confusion, which is why it is a signal and not a refusal.",
    },
    Instrument {
        name: "upstream_versions_rejected_total",
        kind: InstrumentKind::Counter,
        labels: &[],
        help: "Upstream version entries dropped during ingest as unusable or malformed.",
    },
    Instrument {
        name: "upstream_fetch_total",
        kind: InstrumentKind::Counter,
        labels: &["kind", "outcome"],
        help: "Upstream fetches by what was fetched and how it ended.",
    },
    Instrument {
        name: "upstream_failure_total",
        kind: InstrumentKind::Counter,
        labels: &[],
        help: "Upstream requests that failed, feeding the circuit breaker.",
    },
    Instrument {
        name: "upstream_circuit_opened_total",
        kind: InstrumentKind::Counter,
        labels: &[],
        help: "Times the upstream circuit breaker opened, stopping further fetches.",
    },
    Instrument {
        name: "upstream_stale_served_total",
        kind: InstrumentKind::Counter,
        labels: &[],
        help: "Responses served from an expired upstream cache entry because the upstream could \
               not be reached — the graceful-degradation path, not an error.",
    },
    Instrument {
        name: "cache_hit_ratio",
        kind: InstrumentKind::Gauge,
        labels: &[],
        help: "Upstream cache hit ratio since start, 0..1.",
    },
    Instrument {
        name: "upstream_sync_lag_seconds",
        kind: InstrumentKind::Gauge,
        labels: &[],
        help: "Age of the last completed mirror sweep, in seconds. The number to alert on for a \
               mirror-mode deployment: it grows without bound when the sweep stops.",
    },
    // --- blob lifecycle ---
    Instrument {
        name: "blob_gc_scanned_total",
        kind: InstrumentKind::Counter,
        labels: &[],
        help: "Blob keys examined by the garbage collector.",
    },
    Instrument {
        name: "blob_gc_deleted_total",
        kind: InstrumentKind::Counter,
        labels: &[],
        help: "Blobs deleted by the garbage collector.",
    },
    Instrument {
        name: "blob_gc_bytes_total",
        kind: InstrumentKind::Counter,
        labels: &[],
        help: "Bytes reclaimed by the garbage collector.",
    },
    Instrument {
        name: "blob_gc_shards_total",
        kind: InstrumentKind::Counter,
        labels: &[],
        help: "Archive shards swept to the end. A sweep walks the key space one shard at a time \
               from a durable cursor, so this is the rate at which coverage rotates.",
    },
    Instrument {
        name: "blob_gc_sweep_converged",
        kind: InstrumentKind::Gauge,
        labels: &[],
        help: "1 when the last collector pass reached the end of the key space, 0 when it spent \
               its budget first. Sustained 0 means passes never finish: raise \
               `jobs.blob_gc.budget_secs` or lower the interval.",
    },
    Instrument {
        name: "staging_sweep_scanned_total",
        kind: InstrumentKind::Counter,
        labels: &[],
        help: "Staged-upload keys examined by the abandoned-upload sweep.",
    },
    Instrument {
        name: "staging_sweep_deleted_total",
        kind: InstrumentKind::Counter,
        labels: &[],
        help: "Abandoned staged uploads deleted. Steady state is roughly the rate of publishes \
               that are started and never finished.",
    },
    Instrument {
        name: "staging_sweep_bytes_total",
        kind: InstrumentKind::Counter,
        labels: &[],
        help: "Bytes reclaimed from abandoned staged uploads.",
    },
    // --- the job queue and the mail plane it carries (decision 26) ---
    Instrument {
        name: "queue_jobs_total",
        kind: InstrumentKind::Counter,
        labels: &["kind", "outcome"],
        help: "Queue items that reached a terminal state, by job kind and outcome. \
               `outcome=\"dead\"` is work that will never be retried again.",
    },
    Instrument {
        name: "queue_retention_deleted_total",
        kind: InstrumentKind::Counter,
        labels: &["state"],
        help: "Queue rows deleted by retention, by the terminal state they were in.",
    },
    // --- S-23 retention: the one job that deletes rows (decision 30) ---
    Instrument {
        name: "retention_deleted_total",
        kind: InstrumentKind::Counter,
        labels: &["table"],
        help: "Rows deleted by the S-23 retention pass, by table. \
               `table=\"job_queue\"` overlaps `queue_retention_deleted_total`, which breaks the \
               same rows down by terminal state instead.",
    },
    Instrument {
        name: "retention_refused_tables",
        kind: InstrumentKind::Gauge,
        labels: &[],
        help: "Tables the database refused to let the retention pass delete from, as of the last \
               pass. Non-zero means a table is growing without a bound and nothing else will say \
               so: the expected cause is a Postgres provisioned per the hardened S-22 template \
               without `GRANT EXECUTE ON FUNCTION pub_audit_prune(TIMESTAMPTZ, INT)`. Alert on \
               this — the pass keeps sweeping every other table, so no other signal changes.",
    },
    Instrument {
        name: "retention_backlog_tables",
        kind: InstrumentKind::Gauge,
        labels: &[],
        help: "Tables whose backlog outlived the last pass's wall-clock budget. Transient after a \
               window is lowered or a backup is restored — the next pass continues. Persistently \
               non-zero means `jobs.lifecycle` cannot keep up with the row rate.",
    },
    Instrument {
        name: "retention_skipped_tables",
        kind: InstrumentKind::Gauge,
        labels: &[],
        help: "Tables the last retention pass never reached, because its wall-clock budget was \
               already spent by the tables ahead of them. Distinct from \
               `retention_backlog_tables`: a table counted here is getting no retention at all \
               rather than draining slowly. Persistently non-zero means `jobs.lifecycle.budget_secs` \
               is too small for the instance's row rate.",
    },
    Instrument {
        name: "queue_depth",
        kind: InstrumentKind::Gauge,
        labels: &["kind", "state"],
        help: "Queue rows per kind and state, sampled each drain tick. A growing `pending` depth \
               means the drain is slower than the enqueue rate.",
    },
    Instrument {
        name: "mail_transport_unusable",
        kind: InstrumentKind::Gauge,
        labels: &[],
        help: "1 when outbound mail cannot be delivered — the SMTP section will not build, or a \
               send failed and none has succeeded since. Alert on this rather than on dead \
               letters: with the shipped retry ladder a message needs ~21 minutes to die, and an \
               OTP code expires in 10 (decision 29). Zero when no SMTP is configured at all, \
               because delivering nothing to the in-memory sink is a success, not an outage.",
    },
    Instrument {
        name: "notification_enqueue_failed_total",
        kind: InstrumentKind::Counter,
        labels: &["event"],
        help: "Domain events whose fan-out job could not be enqueued. Every one is a set of \
               notifications nobody will ever receive.",
    },
    Instrument {
        name: "notification_mail_enqueue_failed_total",
        kind: InstrumentKind::Counter,
        labels: &["event"],
        help: "Notification emails that could not be filed on the queue during fan-out.",
    },
];

/// Registers every instrument's help text and type with the installed recorder.
///
/// Called once, right after the recorder is installed. Describing after the first emission
/// would still work, but a scrape landing in between would carry a bare number.
pub fn describe_all() {
    for instrument in INSTRUMENTS {
        match instrument.kind {
            InstrumentKind::Counter => metrics::describe_counter!(instrument.name, instrument.help),
            InstrumentKind::Gauge => metrics::describe_gauge!(instrument.name, instrument.help),
            InstrumentKind::Histogram => metrics::describe_histogram!(instrument.name, instrument.help),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_are_unique_and_prometheus_shaped() {
        let mut seen = std::collections::BTreeSet::new();
        for instrument in INSTRUMENTS {
            assert!(seen.insert(instrument.name), "duplicate instrument {}", instrument.name);
            assert!(
                instrument.name.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_'),
                "{} is not a valid Prometheus metric name",
                instrument.name
            );
            assert!(!instrument.help.is_empty(), "{} has no help text", instrument.name);
            // A counter that does not end in `_total` reads as a gauge on every dashboard.
            if instrument.kind == InstrumentKind::Counter {
                assert!(instrument.name.ends_with("_total"), "counter {} must end in _total", instrument.name);
            }
        }
    }
}
