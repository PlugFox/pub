# Operator guide

Pub ships as **one binary, `pubd`**, with the web UI embedded ([decision 04](../decisions.md#04--single-binary-now-optional-split-later)) and every backend compiled in — SQLite or PostgreSQL, filesystem or S3 or in-memory blobs, in-process or Redis KV — selected by configuration at startup, never by build flags ([decision 09](../decisions.md#09--always-compiled-backends-runtime-config-selection)). The production minimum is a single container with SQLite and filesystem blobs on one volume; the same binary scales to Postgres + S3 + Redis by changing config. In production mode the server refuses to boot until real secret material is configured and names every missing key ([S-25](../security.md#6-secrets--configuration)); `/healthz` is always on and reports version, configured backends, and live connectivity. These pages are written against the code, including its known gaps — where a promise is not yet kept, the page says so and cites the [roadmap debt register](../roadmap.md#part-ii--tech-debt).

| Page | Contents |
|------|----------|
| [install.md](install.md) | Docker run quickstart, compose profiles, building from source, dev vs production mode, data layout, first-admin bootstrap, the hardened Postgres role, connecting `dart pub` |
| [configuration.md](configuration.md) | Reference of every configuration key — **generated from the config structs**, do not edit by hand |
| [reverse-proxy.md](reverse-proxy.md) | nginx / Caddy / Traefik examples: TLS, `public_url` correctness, `trust_proxy_headers`, SSE, upload sizes and timeouts |
| [backup-restore.md](backup-restore.md) | What to back up and in which order, per database and blob backend; restore and post-restore verification |
| [upgrade.md](upgrade.md) | Upgrade procedure, automatic forward-only migrations, the one-time grant repair a hardened role needs, version verification, why rollback means restore |
| [security-runbook.md](security-runbook.md) | `require_auth_for_read` guidance (S-04.c), proxy-header trust (S-24.b), the key-rotation runbook (S-27), break-glass — including the mail-plane lockout and `pubd reset-smtp` — and responding to shadowing and quarantine alarms |
| [monitoring.md](monitoring.md) | Turning the Prometheus exposition on, its separate listener, alert rules, a starting dashboard, and **how a dead mail plane surfaces** |
| [metrics.md](metrics.md) | Every exported instrument — **generated from the exporter's catalogue**, do not edit by hand |
| [token-scanning.md](token-scanning.md) | The published CLI-token format, regex, and offline checksum verification for secret scanners (S-15) |

Not covered here because it does not exist yet (honesty over aspiration; each item is tracked):
a **two-replica deployment** is not documented or tested yet (Phase 3 item 3) — leader election is a database lease as of [decision 36](../decisions.md#36--leader-election-leaves-the-process-a-lease-table-a-lock-that-outlives-a-pool-connection-and-a-topology-gate-that-replaces-a-kv-check) and the validator now refuses `replicas > 1` without Postgres and Redis, but no compose file runs two app containers behind a proxy; see [install.md](install.md#more-than-one-replica);
trace export is not implemented — this build exports metrics and logs, and the `telemetry.otlp` flag that promised otherwise was removed rather than left in place ([decision 23](../decisions.md#23--monitoring-is-optional)).
