# Monitoring

Metrics are **off by default** ([decision 23](../decisions.md#23--monitoring-is-optional)) and nothing about running Pub requires a monitoring stack. This page is for the deployment that wants one: how to turn the exposition on, what to alert on, and — the part that matters most on a self-hosted instance — **how a broken mail plane surfaces**, because since delivery moved off the request path it is the one failure that can lock an operator out of their own registry.

Every instrument is listed in [metrics.md](metrics.md), which is generated from the exporter's own catalogue and fails the build if it drifts.

## Turning it on

```toml
[telemetry]
prometheus     = true
metrics_listen = "127.0.0.1:9090"   # default
log_format     = "json"             # optional: one JSON object per line, for a shipper
```

`/metrics` is served on **its own listener** and is never a route on the application port ([decision 28](../decisions.md#28--the-observability-plane-its-own-listener-bounded-labels-and-timing-that-stays-opt-in)). Three reasons, and each one is enough on its own:

- the application listener sheds load under saturation, so a scrape mounted there goes dark exactly when you are trying to find out why the instance is saturated;
- the exposition would inherit the application's cache and error-shape middleware, none of which is right for it;
- it would be published on the instance's public origin, which is not a default anybody should inherit.

**The exposition is unauthenticated.** The default binds loopback, which is correct for a Prometheus running on the same host or a sidecar in the same pod. Publishing it (`0.0.0.0:9090`) is a deliberate act — put it on an internal network, or in front of your proxy's allowlist. The config validator refuses a `metrics_listen` that shares a port with `server.listen`.

### Docker and compose

The image keeps its single `EXPOSE`; map the second port yourself when you need it from outside the container:

```yaml
services:
  pub:
    environment:
      PUB_TELEMETRY__PROMETHEUS: "true"
      PUB_TELEMETRY__METRICS_LISTEN: "0.0.0.0:9090"   # required in a container: loopback is
                                                      # the container's own loopback
    ports:
      - "127.0.0.1:9090:9090"                         # bind the host side to loopback
```

### Scrape config

```yaml
scrape_configs:
  - job_name: pub
    static_configs:
      - targets: ["pub-host:9090"]
```

## `Server-Timing`

Off by default and **never emitted on `/api/v1/auth/*`, whatever the flag says** ([S-04.d](../security.md#1-authentication)). Enabling it (`telemetry.server_timing = true`) publishes exact server-side durations on the read model and the pub protocol, both of which answer 404 for "not yours" as well as "does not exist" — the header hands a prober the timing differential that the network would otherwise hide. It is a debugging aid for an instance you control, not a production default.

## Alert rules

Ship these; they are the signals that mean something on this product specifically.

```yaml
groups:
  - name: pub
    rules:
      # --- the mail plane (roadmap D43, decision 29) --------------------------------------
      # THE important one on an OTP-only instance. Outbound mail is asynchronous, so a broken
      # relay costs nothing at request time and would otherwise surface ~21 minutes later as a
      # dead letter — on the admin API, which needs a session, which arrives by mail. This
      # gauge fires on the FIRST failure and needs no session to read.
      - alert: PubMailTransportUnusable
        expr: mail_transport_unusable == 1
        for: 2m
        labels: { severity: critical }
        annotations:
          summary: "Pub cannot deliver outbound mail"
          description: >-
            Sign-in codes, invitations and notifications are not being delivered. A code expires
            in 10 minutes and the retry ladder takes ~21 to dead-letter, so codes are being lost
            now. If nobody can sign in to fix it, see the mail-plane break-glass entry in the
            security runbook.

      - alert: PubDeadLetters
        expr: increase(queue_jobs_total{outcome="dead"}[1h]) > 0
        labels: { severity: warning }
        annotations:
          summary: "Pub gave up on {{ $value }} queued job(s) in the last hour"
          description: "Dead letters are kept for 30 days; there is no requeue endpoint — fix the cause and have the action retried."

      - alert: PubQueueBacklog
        expr: sum(queue_depth{state="pending"}) > 1000
        for: 15m
        labels: { severity: warning }
        annotations:
          summary: "Pub's job queue is growing faster than it drains"

      # --- retention (roadmap D12/D46, decision 30) ---------------------------------------
      # The expected cause is a Postgres provisioned per the hardened S-22 template without the
      # EXECUTE grant on pub_audit_prune. Nothing else changes when this happens: the pass keeps
      # sweeping every other table and reports success for them, so without this alert an audit
      # log that grows forever looks exactly like one that does not.
      - alert: PubRetentionRefused
        expr: retention_refused_tables > 0
        for: 30m
        labels: { severity: warning }
        annotations:
          summary: "Pub cannot delete from {{ $value }} table(s) it is configured to trim"
          description: >-
            S-23 retention was refused by the database. On PostgreSQL the app role deliberately
            holds no DELETE on audit_log and prunes through a SECURITY DEFINER function; if the
            EXECUTE grant is missing, run:
            GRANT EXECUTE ON FUNCTION pub_audit_prune(TIMESTAMPTZ, INT) TO <app_role>;
            The affected table is named in the instance log and in the lifecycle job's last error.

      - alert: PubRetentionBacklog
        expr: retention_backlog_tables > 0
        for: 6h
        labels: { severity: warning }
        annotations:
          summary: "Pub's retention pass has not caught up in 6 hours"
          description: >-
            Transient after a window is lowered or a backup is restored — the next pass continues
            where this one stopped. Persistent means the row rate is above what
            jobs.lifecycle.batch and jobs.lifecycle.budget_secs can clear in 15 minutes.

      # --- supply chain (decision 07, S-21) -----------------------------------------------
      # Any of these is worth a human look. They are not errors; they are the signals the
      # upstream proxy exists to produce. What each one *means* is in the register behind it:
      # the admin surface's "Supply chain" tab (`/app/admin/supply-chain`) pages the full
      # quarantine and shadowing registers, which the dashboard only samples twenty rows of.
      - alert: PubUpstreamQuarantine
        expr: increase(quarantine_total[15m]) > 0
        labels: { severity: critical }
        annotations:
          summary: "Upstream archive bytes did not match the advertised digest"
          description: "Either a broken mirror or an attempted substitution. The archive was quarantined, not served."

      - alert: PubUpstreamDrift
        expr: increase(upstream_drift_total[15m]) > 0
        labels: { severity: critical }
        annotations:
          summary: "An upstream version's bytes changed after Pub cached them"
          description: "The cached copy was kept. A published version's bytes are immutable, so this is always a fact about the upstream."

      - alert: PubShadowingAlarm
        expr: increase(shadowing_alarms_total[1h]) > 0
        labels: { severity: warning }
        annotations:
          summary: "A local package name also exists upstream"
          description: "Dependency-confusion signal. Local always wins; decide whether that is what you want for this name."

      - alert: PubMirrorSyncLag
        expr: upstream_sync_lag_seconds > 86400
        for: 30m
        labels: { severity: warning }
        annotations:
          summary: "Pub's mirror sweep has not completed for over a day"

      # --- abuse limits (S-24) ------------------------------------------------------------
      - alert: PubRateLimitFallback
        expr: increase(rate_limit_fallback_total[5m]) > 0
        labels: { severity: warning }
        annotations:
          summary: "Pub's shared rate-limit store is unreachable"
          description: >-
            Auth-abuse limits are being enforced per instance instead of across the cluster
            (S-24.e), so the effective budget is up to N x the limit on N replicas. Sign-in keeps
            working; fix the KV.

      # --- presigned downloads (decision 34) ----------------------------------------------
      - alert: PubPresignFailing
        expr: >-
          sum(rate(archive_presign_total{outcome="failed"}[10m]))
            / sum(rate(archive_presign_total[10m])) > 0.01
        for: 10m
        labels: { severity: warning }
        annotations:
          summary: "Pub cannot presign archive URLs and is streaming them instead"
          description: >-
            `blob.presign` is on, but the object store's credential path is failing to sign, so
            every archive is being proxied through the app process. Downloads still work — this
            is latency and egress, not an outage — and without this alert it presents only as S3
            egress disappearing while the app tier gets busy.

      # --- the basics ---------------------------------------------------------------------
      - alert: PubHighErrorRate
        expr: >-
          sum(rate(http_requests_total{status=~"5.."}[5m]))
            / sum(rate(http_requests_total[5m])) > 0.05
        for: 10m
        labels: { severity: critical }
        annotations:
          summary: "Over 5% of Pub's responses are 5xx"

      - alert: PubShedding
        expr: sum(rate(http_requests_total{status="503"}[5m])) > 0
        for: 10m
        labels: { severity: warning }
        annotations:
          summary: "Pub is shedding load"
          description: "The instance is at its `http.concurrency_limit`. Raise it, or add capacity."
```

## A starting dashboard

There is no dashboard JSON to import — one would be a large generated artifact that rots faster than this page. Six panels cover the instance:

| Panel | Query |
|---|---|
| Request rate by status | `sum by (status) (rate(http_requests_total[5m]))` |
| p95 latency by route | `histogram_quantile(0.95, sum by (le, route) (rate(http_request_duration_seconds_bucket[5m])))` |
| Publishes | `sum(rate(publishes_total[1h]))` |
| Queue depth | `sum by (kind, state) (queue_depth)` |
| Mail plane | `mail_transport_unusable` (stat, red on 1) |
| Upstream cache hit ratio | `cache_hit_ratio` |

The `route` label is the router's matched path (`/api/v1/packages/{name}`), or one of `{api}`, `{pub}`, `{asset}` for requests that matched no route — bounded on purpose, so an anonymous caller cannot mint label values.

## When the mail plane is down

Outbound mail is asynchronous ([decision 26](../decisions.md#26--durable-job-queue-async-fan-out-and-outbound-mail-off-the-request-path)), which changed the failure mode of every message the instance sends. A broken relay used to fail the request loudly; now the request succeeds, a row is filed, and the outcome arrives later.

**Where it shows.** In order of how soon you learn:

1. `mail_transport_unusable == 1` — on the first failure, and at startup if the SMTP section will not build at all.
2. An audit row: `mail.delivery_failed` on the edge, `mail.delivery_recovered` when it comes back. One row per transition, not per attempt.
3. The instance log — the same transition, at `error`.
4. `GET /api/v1/admin/stats` → the queue drain's `phase`, e.g. `drain (3 dead)`, also rendered in the **State** column of the admin jobs table.
5. `queue_jobs_total{kind="mail",outcome="dead"}` — the slowest signal, ~21 minutes after the first attempt.

**What it costs.** With the shipped defaults (`max_attempts = 8`, `backoff_base_secs = 10`) the seven waits sum to about 21 minutes before a message can reach `dead`. A sign-in code expires after **10** minutes, so a code that needs two retries expires before it is delivered even if delivery eventually succeeds. Dead letters are kept for 30 days and there is **no requeue endpoint** — the honest instruction is: fix the relay, then have the user request a new code.

**One restore-specific trap.** Queued mail bodies are sealed under `auth.kek`, and a body the KEK cannot open **dead-letters on the first attempt**, not after eight. Restoring a database under a different KEK therefore discards every in-flight message silently. See [backup-restore.md](backup-restore.md).

**If nobody can sign in and mail is the reason**, the recovery is in the [security runbook](security-runbook.md#break-glass): `pubd reset-smtp`.

## What deletes bytes

Two jobs delete objects from the blob store, and they ship with **opposite defaults** ([decision 31](../decisions.md#31--blob-lifecycle-staged-uploads-swept-by-default-and-an-archive-gc-that-streams-batches-and-resumes)). The split is the point: one of them removes bytes somebody may have pinned in a `pubspec.lock`, the other removes bytes nobody can reach.

| Job | Default | What it removes | Grace |
|---|---|---|---|
| `staging-sweep` | **on**, deletes for real, hourly | Abandoned staged uploads under `uploads/<format>/<session>.tar.gz` — publishes that were started and never finished | `jobs.staging.min_age_secs`, default 2 h |
| `blob-gc` | **off**, and dry-run when first enabled, every 6 h | Content-addressed archives that no live version and no cached upstream version references | `jobs.blob_gc.min_age_secs`, default 24 h |

**Why the staged sweep can be on.** A staged upload's session record lives in the KV for one hour. After it expires, `newUploadFinish` answers "this upload has expired or was already finalized" — there is no second door, and no database row ever referenced the object. So age alone decides it, and the two-hour default grace is the one-hour TTL plus room for clock skew. Before this job existed the same sweep rode `blob-gc`, which ships disabled, so a default install kept every abandoned upload forever, bounded only by the S-24 publish budget times the archive cap.

**Why the archive collector cannot.** Content addressing means one object can back a local publish *and* a proxied upstream archive that never met each other, so a key is collectable only when both registers agree — and a mistake is the one failure this system cannot repair ([S-18](../security.md#4-supply-chain--registry-integrity)). Turn it on, read a dry-run pass, then clear `jobs.blob_gc.dry_run`.

**Reading a `blob-gc` pass.** It walks the key space one shard at a time from a durable cursor and stops when `jobs.blob_gc.budget_secs` is spent, so `phase` reads either `swept` (or `dry-run`) when the pass reached the end, or `swept, resumes at pub:3f` when it did not. That is normal on a large bucket — coverage rotates across passes — but it should not be *every* pass: `blob_gc_sweep_converged` sitting at 0 means no rotation ever completes, and the fix is a larger budget or a shorter interval. `staging-sweep` has no cursor because everything it collects leaves the namespace, so each pass makes the next one smaller.

**One safety property worth knowing about**, because it explains a non-zero `contested` count in a report: both jobs re-read an object's age immediately before deleting it. `put` on a content-addressed key is an idempotent overwrite, so republishing byte-identical content refreshes an object that a listing already called old and unreferenced; the re-read sees that and skips. A steady trickle of `contested` is a busy registry, not a fault.

## Who serves the archive bytes

By default, this process does: an archive download is read from the blob store and streamed to the client. With `blob.presign = true` on the `s3` backend the same request answers **`307` to a presigned URL** and the bytes never enter the app tier ([decision 34](../decisions.md#34--presigned-downloads-the-redirect-branch-becomes-reachable-off-by-default-and-honest-about-the-address-a-client-can-dial), [S-18.a](../security.md#4-supply-chain--registry-integrity)). Three things change for whoever is watching the instance, and none of them is visible in an error rate:

- **`http_request_duration_seconds` on the archive route collapses**, because the route stopped doing the work. Egress moves to the object store's own bill and its own dashboard. A latency graph that improves the day this is turned on is the feature, not an anomaly.
- **`downloads_total` counts redirects issued, not bytes delivered.** It was always an upper bound — a streamed download can be aborted mid-body — and it becomes a slightly looser one, because we no longer see whether the client followed the URL.
- **`archive_presign_total{outcome="failed"}` is the one signal that needs an alert** (rule above). Signing runs offline against the store's credentials; when it fails the request falls back to streaming, so nothing 5xxs and nothing 404s. The instance simply, silently, starts doing the work again.

**What a signed URL is.** A bearer capability for `blob.presign_ttl_secs` (default 30 minutes): whoever holds it reads that archive with no token and no session. The authorization decision is made once, when the redirect is issued, which is why the redirect carries `Cache-Control: no-store` and why the S-24.f read bucket is spent at the redirect rather than at the bytes. **During an incident this is the sentence that matters**: revoking a token or a session does not reach a URL already handed out, so the containment step for leaked archive bytes is the object store's own — rotate `blob.access_key`, or turn `blob.presign` off and restart, which makes every outstanding URL useless at once. An instance that cannot accept the second property leaves the flag off, which is the default.

**If downloads break the moment you turn it on**, the address is almost always the cause: `blob.endpoint` is what *this process* dials, and behind a container network or a private link it is not what a client can reach. Set `blob.public_endpoint` to the client-facing address — boot refuses the combination rather than letting you find out from a support ticket, and it refuses two more: a signing origin equal to `server.public_url` (the client keeps its `Authorization` across a same-origin redirect and S3 answers 400 to a request carrying two credentials), and a TTL outside `1500..=604800`.

## What deletes rows, and what it needs

One job deletes rows in this instance: `lifecycle-purge` ([decision 30](../decisions.md#30--retention-one-window-per-table-a-delete-that-stays-bounded-and-a-privilege-that-survives-the-feature), [S-23](../security.md#5-audit--abuse)). It is **on by default** — a default install whose tables only grow is not a default — and it runs every 15 minutes.

**What it removes**, per `[jobs.lifecycle]`; every window is a number of days and `0` means keep forever:

| Table | Default | Aged from |
|---|---|---|
| `audit_log` | 730 d (≈24 months) | `created_at` — one window for every action, [S-23.a](../security.md#5-audit--abuse) |
| `sessions` | 30 d | `last_seen_at`, so a purged row could no longer authenticate |
| `invitations` | 30 d | whenever it settled — accepted, revoked, or expired |
| `notifications` | 180 d | `created_at`; read state is not part of it |
| `download_stats` | **keep forever** | `date`, when enabled |
| `job_queue` | its own three windows in `[jobs.queue]` | `updated_at`, per terminal state |

There is **no on/off switch for the job itself** — each window is one, and `0` means keep forever. That is deliberate: a job-level flag would also stop the `job_queue` windows you configured in `[jobs.queue]`, including the one-hour `suppressed` window that holds addresses typed at the login form by unauthenticated callers.

Version tombstones are never deleted, deliberately: a tombstone is what keeps a hard-deleted version number unpublishable ([S-18](../security.md#4-supply-chain--registry-integrity)).

**On PostgreSQL it needs one grant.** The app role deliberately holds **no `DELETE` on `audit_log`** — that is [S-22](../security.md#5-audit--abuse), and decision 30 refused to trade it away for this feature. Retention calls `pub_audit_prune(cutoff, batch)` instead: a `SECURITY DEFINER` function created by migration 0012, owned by the migration role, which refuses any cutoff that is not comfortably in the past. Migration 0012 **revokes `EXECUTE` from `PUBLIC`** — otherwise every role that can reach the database could prune this instance's audit log — so unless your application connects as the database owner, grant it explicitly:

```sql
GRANT EXECUTE ON FUNCTION pub_audit_prune(TIMESTAMPTZ, INT) TO pub_app;
```

Without it, audit retention is refused, `retention_refused_tables` goes to 1, the instance logs the grant above by name, and **every other table is still swept** — one missing grant does not stop sessions from being purged. This is the one deployment step retention adds, and it is deliberately a step rather than a default: relying on Postgres' `PUBLIC` execute default would have meant no action for you and the same capability for every other role on a shared cluster.

**Reading a pass.** `GET /api/v1/admin/stats` carries the job's `phase`: `drained` when every table is clear, `backlog: notifications, audit_log` when a released backlog outlived the pass's budget. `POST /api/v1/admin/jobs/lifecycle-purge/run` runs one on demand; its report is a line per table, including the ones set to keep forever, so a table that is missing from it is a bug rather than a table with nothing to delete.

**Why a backlog is normal, briefly.** Every delete is bounded to `jobs.lifecycle.batch` rows per statement and the pass stops at `jobs.lifecycle.budget_secs`. On SQLite that bound is load-bearing: one unbounded `DELETE` holds the single writer for its whole duration, and a hold past the busy timeout turns a concurrent publish or sign-in into an error instead of a wait. So lowering a window, restoring a backup, or correcting the clock forward releases a backlog that drains over several passes rather than in one statement.
