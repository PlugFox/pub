# Architecture

Companion to [decisions.md](decisions.md) (the "why"); this is the "how". Backend is Rust (axum + sqlx + object_store), frontend is Bun/Astro/SolidJS, delivered as a single binary with embedded static assets ([decision 04](decisions.md#04--single-binary-now-optional-split-later)).

## System overview

```
                        ┌────────────────────────────────────────────┐
 dart pub CLI ──bearer──►  axum API                                  │
 browser ─JWT/localStorage►  ├─ protocol routes (/o/{org}/pub/api/…) │
 admin UI ──JWT──────────►  ├─ app REST API + SSE (/api/v1/…)        │
                        │   ├─ embedded static assets (Astro build)  │
                        │   └─ /healthz /metrics /openapi.json       │
                        │  core traits ─┬─ db: sqlite | postgres     │
                        │               ├─ blob: fs | s3 | memory    │
                        │               ├─ kv: memory | redis        │
                        │               └─ search: fts5 | tsvector   │
                        │  jobs: leader-locked interval scheduler    │
                        └────────────────────────────────────────────┘
```

All backends are always compiled; config selects implementations at startup ([decision 09](decisions.md#09--always-compiled-backends-runtime-config-selection)). The app tier is stateless: every piece of shared state lives in the DB, the blob store, or the KV layer. Multi-instance operation requires the Redis KV backend (store + pub/sub broker); the config validator rejects `instances > 1` with the in-memory backend.

## Cargo workspace

```
server/
├── Cargo.toml                  # workspace; [workspace.dependencies] pins everything
├── crates/
│   ├── core/                   # domain types, error enums (decision 16), trait definitions:
│   │                           #   PackageRepo UpstreamRepo UserRepo OrgRepo TokenRepo
│   │                           #   SessionRepo AuditRepo SettingsRepo JobRepo
│   │                           #   BlobStore Kv (store+broker) PackageSearch Mailer JobLock
│   │                           # zero infrastructure dependencies
│   ├── config/                 # layered load: defaults → TOML → env → CLI; validation;
│   │                           #   effective-config startup summary (secrets masked)
│   ├── db-postgres/            # sqlx 0.9 impls + migrations/ (tsvector, pg_trgm,
│   │                           #   advisory locks, partial indexes, TIMESTAMPTZ/INET)
│   ├── db-sqlite/              # sqlx 0.9 impls + migrations/ (FTS5, single-writer locks)
│   ├── blob/                   # object_store: LocalFileSystem | AmazonS3(+MinIO) | InMemory
│   │                           #   DownloadPlan::Redirect(presigned) | Stream(bytes)
│   ├── kv/                     # Kv impls: in-process (moka) | redis (deadpool-redis);
│   │                           #   blocklists, rate counters, locks, settings pub/sub
│   ├── auth/                   # OIDC (openidconnect), email OTP, TOTP (totp-rs),
│   │                           #   JWT Ed25519 keyring (kid rotation), token hashing
│   ├── registry/               # domain services: publish pipeline, resolution policy,
│   │                           #   proxy ingest (upstream.rs + upstream/http.rs: the
│   │                           #   UpstreamClient seam over reqwest+rustls), retraction,
│   │                           #   claims, readme rendering
│   ├── mail/                   # lettre + askama templates (text+HTML multipart)
│   ├── jobs/                   # interval scheduler + JobLock leader election;
│   │                           #   mirror.rs (decision 07 sync worker driving
│   │                           #   UpstreamService), gc.rs (unreferenced-blob GC);
│   │                           #   later: session/OTP purge, reindex, webhook delivery
│   ├── api/                    # axum routers (utoipa OpenApiRouter), extractors, DTOs;
│   │                           #   one protocol module per format (pub now; npm/cargo
│   │                           #   later — decision 21) + app REST + SSE;
│   │                           #   tower layers: auth, rate limit, CSP/security headers,
│   │                           #   request-id, tracing, embedded-assets service
│   ├── telemetry/              # tracing init, optional OTLP, prometheus metrics
└── └── bin/pubd/               # clap entrypoint: load config → build Arc<dyn Trait>
                                #   AppState → migrate → spawn jobs → serve
```

Wiring is plain runtime polymorphism: `AppState` holds `Arc<dyn PackageRepo>`, `Arc<dyn BlobStore>`, etc., constructed once in `main` from config. Integration tests assemble the full stack with SQLite `:memory:` + `InMemory` blob + in-process KV — no containers; CI adds the Postgres/MinIO/Redis matrix via testcontainers.

## Data model (core entities)

- `users` — profile, status; `credentials` polymorphic over type (`oidc_google` keyed by `(iss,sub)`, `email_otp`, `totp` seed encrypted with env KEK, `recovery_code`, future `webauthn`).
- `orgs (…, upstream_policy)` — per-org proxy policy `allow` (default) | `block` ([decision 01](decisions.md#01--per-org-virtual-registry-urls)); `org_members (org_id, user_id, role_level)` — cumulative role levels **Read(50) / Write(100) / Admin(200) / Owner(250)** with gaps for future roles, mirrored into JWT claims, all checks through one `authorize()` chokepoint ([decision 19](decisions.md#19--rbac-cumulative-role-levels-with-a-single-authorize-chokepoint)); ≥1 Owner invariant; `invitations` (hashed single-use token, 7-day expiry, bound to email, default role Read).
- `packages (format, name, org_id, visibility, discontinued, replaced_by, unlisted)` — unique per `(format, name)` per instance ([decision 21](decisions.md#21--multi-format-artifact-space-pub-first-npm-cargo--later): pub in v1, npm/cargo later share these entities); `name_claims` — `(format, name)` → org, written at first publish, consulted by resolution and shadowing alerts.
- `versions (package_id, semver columns, pubspec JSONB/TEXT, archive_sha256, readme_html, changelog_html, retracted_at, tombstone)` — immutable; archive bytes content-addressed in blob store by sha256.
- `upstream_packages / upstream_versions` — proxy cache metadata (listing snapshots incl. the raw document, sha256, size, `cached`, `fetched_at`, upstream flags verbatim) behind `UpstreamRepo`. Deliberately **not** part of `PackageRepo`: an upstream row has no org, no claim, no publisher, and no lifecycle of its own, and "local always wins" (S-16) is only meaningful while the two sets stay distinguishable. Snapshots upsert and never delete; a `cached` version's hash and size are frozen (S-19 byte-drift). `fetched_at` is also the mirror worker's work queue (oldest snapshot first).
- `upstream_quarantine (format, name, version, both hashes, occurrences, first/last_seen_at)` and `shadowing_alarms (format, name, org_id, upstream, upstream_version, observations, first/last_seen_at, acknowledged_at)` — the two supply-chain registers behind `UpstreamRepo` ([S-19](security.md#4-supply-chain--registry-integrity), [S-17.a](security.md#4-supply-chain--registry-integrity)). One row per incident with a counter, never one per sighting: both feed an admin surface, and an alarm channel that repeats stops being read. Neither is enforcement — the refusal and the resolution order already happened.
- `jobs (name, cursor, phase, last_run_at, last_success_at, last_error, runs, processed, failures)` — durable background-job state behind `JobRepo`, keyed by the same name the `JobLock` uses. The cursor is opaque to the repository (interpreting it would put job logic in the schema) and counters are added to rather than written, so a run that dies between checkpoints leaves its partial progress recorded. This is what makes a full mirror sweep resume across restarts and leader changes.
- `sessions` (refresh-token hash, device metadata, revoked_at) and `tokens` (SHA-256 hash, display hint, scopes, org binding, package patterns, expiry, last_used throttled).
- `audit_log` — append-only (INSERT-only DB role), ULID ids, dot-namespaced actions, actor/IP/UA/org/target/metadata.
- `notifications (user_id, category, payload, read_at)` — the notification center's persisted feed (unread counts, per-category preferences); fed by the same domain events as the SSE stream, email for high-importance categories.
- `webhooks (org_id | null for instance-wide, url, secret_enc, event_filters, active)` and `webhook_deliveries (webhook_id, event_id, status, attempts, last_error)` — outbound integrations ([decision 22](decisions.md#22--domain-event-bus-webhooks-and-integrations-on-top), S-33), delivered by the jobs crate.
- `download_stats (package_id, version_id, date, count)` — daily rollups aggregated from fire-and-forget download events (HEAD/GET dedup as in foxic: pub clients HEAD before GET, only GET counts); powers package/org/instance statistics.
- `settings` — runtime-changeable key→JSON with version; cached via `ArcSwap`, invalidated cross-instance through the KV broker, plus a 30–60 s version-poll as reconciliation fallback for broker messages missed across reconnects.

## Request planes

Two strictly separated credential planes:

1. **Web session plane** (browser → app API): JWT access token (localStorage, 10–15 min TTL, Ed25519 `kid`-rotated) with `sub`/`sid`/org-role-level claims; refresh via server-side session with rotation; revoked-`sid` set (TTL = access TTL) in KV checked on every request; permission change ⇒ revoke all user sessions. Never accepted on pub protocol routes.
2. **CLI token plane** (`dart pub` → pub routes, CI → REST): opaque `<prefix>_…` bearer tokens, SHA-256 lookup, scope + org checks per request, no server-side caching beyond 60 s. Never accepted on the app session endpoints.

## Pub protocol & resolution

Endpoints per virtual registry base `B = /o/{org}/pub` (plus the public root `B = /pub`); the `/pub` segment is the format discriminator — future formats mount as siblings (`/o/{org}/npm`, …; [decision 21](decisions.md#21--multi-format-artifact-space-pub-first-npm-cargo--later)):

- `GET B/api/packages/{name}` — version listing (hot path; includes `archive_sha256`, `retracted`, `isDiscontinued`, `replacedBy`, later `advisoriesUpdated`).
- `GET B/api/packages/versions/new` → `POST` multipart upload → `GET` finalize — 3-step publish, all under `B` so bearer auth flows automatically; validation happens at finalize (400 + `{"error":…}`).
- `GET B/api/archives/{name}-{version}.tar.gz` — `DownloadPlan`: 307 to presigned URL (S3) or streamed bytes (fs/memory). Legacy routes `B/api/packages/{name}/versions/{v}` and `B/packages/{name}/versions/{v}.tar.gz` kept for old clients.

Both bases are served by **one** handler set (`api/src/protocol/pub_v2.rs`) mounted twice; the base arrives as a typed extractor that yields the resolution scope and the URL prefix, so no handler can be correct on one mount and wrong on the other. Resolution itself is `PackageRepo::resolve_in_base` — a provided trait method, so the ordering exists once, above both SQL dialects, and runs through `authorize()`.

Resolution order inside `B/o/{org}`: org-owned → instance-public → upstream proxy iff name unclaimed locally (local always wins; per-org upstream policy: `allow` default, `delay`/`allowlist` later). Anonymous access follows [decision 05](decisions.md#05--anonymous-read-configurable-default-allowed): private/unknown → 404; 401 (with `WWW-Authenticate: Bearer realm="pub", message="…"`) only for genuinely missing/invalid credentials. See [protocol.md](protocol.md) for client sharp edges.

**Publish pipeline**: step 1 (`versions/new`) verifies only that the token has `publish` scope — the request carries no package name; org binding, token package patterns, and name-claim checks are enforced at finalize (pub.dev does the same). Finalize: per-name lock (`JobLock`) → tar.gz safety validation (size cap, path traversal, symlink escapes) → pubspec parse + name/version/claim/quota checks → sha256 → content-addressed blob write → README/CHANGELOG render (comrak + ammonia + syntect) → DB row + audit event → search index update. Uploaded bytes are stored verbatim and served forever (lockfile hashes depend on it).

**Proxy ingest** (`registry/src/upstream.rs`, shared by read-through and the future mirror worker): fetch upstream listing → validate every version's pubspec with the *publish* validator (S-20) → snapshot metadata, preserving flags verbatim → on an archive miss, fetch, **verify `archive_sha256` before storing** (S-19), store byte-identical and content-addressed. Proxied listings are **re-emitted with `archive_url` rewritten under the requesting virtual base `B`** — never upstream's CDN URL, otherwise clients download straight from pub.dev and caching, per-org policy, and stale-serving are silently bypassed. Flags (`retracted`, `isDiscontinued`, `replacedBy`), pubspec JSON, and `archive_sha256` are preserved verbatim; `advisoriesUpdated` is stored but not advertised until the advisories endpoint exists ([protocol.md sharp edge 11](protocol.md#sharp-edges-violate--break-clients)).

A cached listing is served without asking upstream for `upstream.listing_ttl_secs` (default 300); archives are immutable and cached forever. Degradation is uniform and never 5xx: an unreachable upstream or an open circuit serves the cached snapshot with a staleness marker in tracing/metrics, and anything never cached is a 404. Guards: a per-instance in-process circuit breaker (half-open admits one probe), a per-upstream concurrency semaphore, and a single-flight lock so N simultaneous misses of one package cause one upstream fetch. The breaker counts **reachability** failures only — timeouts, connection errors, the transient status family — on the listing *and* archive paths; a 404, a listing the ingest validator refuses, and one past the size cap are facts about a single package and must not degrade the instance ([S-19.a](security.md#4-supply-chain--registry-integrity)). The network itself sits behind the `UpstreamClient` trait (`upstream/http.rs`: reqwest + rustls, retries with exponential backoff on transient failures only, SSRF-guarded destinations, plus the `/api/package-names` enumeration the mirror sweeps), so the whole pipeline is testable without a socket. Mirror mode is the jobs-crate worker warming this same pipeline through `UpstreamService::refresh` — see "Background jobs" below.

## Realtime events (SSE)

`GET /api/v1/events` streams Server-Sent Events to the web app ([decision 20](decisions.md#20--realtime-sse-event-stream--notification-center)): package publishes/retractions, membership/invitation events, shadowing alarms, notifications, admin-facing settings changes. SSE is one consumer of the **internal domain event bus** — the same bus feeds the notification center, the audit log, and outbound webhooks ([decision 22](decisions.md#22--domain-event-bus-webhooks-and-integrations-on-top)). Domain services emit events into an in-process broadcast; with the Redis KV backend every instance republishes to a broker topic and subscribes to peers, so any instance can serve any client's stream. The browser uses fetch-streaming (not `EventSource` — it cannot set `Authorization`); heartbeats double as revocation re-checks (S-32); `Last-Event-ID` replays best-effort from a short per-user ring buffer. The stream is a hint channel — clients reconcile through the REST API, so lost events are never correctness bugs.

## Background jobs

Interval scheduler in `jobs/` guarded by `JobLock` leader election (PG advisory lock / Redis lock / trivial single-node): mirror sync, unreferenced-blob GC, expired session/OTP/invitation purge, audit retention, search reindex, token-expiry notification emails. Job state (last-run, cursors) in DB; every job idempotent and safe to rerun.

Two jobs exist today, both **off by default** and each skipped entirely when disabled — a job that is not registered cannot tick, which is a stronger guarantee than one whose body returns early:

- **Mirror sync** (`mirror.rs`, decision 07 second half). `off` | `recent` | `full`. `recent` re-polls the packages this instance already caches, oldest snapshot first; `full` first enumerates upstream's `/api/package-names`, chunked and resumable from a durable cursor, then behaves like `recent` until `resweep_after` starts the next enumeration. Both drive `UpstreamService::refresh` — the read-through pipeline with the read TTL replaced by a caller-supplied freshness floor — so there is no second ingest path. A name claimed locally is observed as an [S-17](security.md#4-supply-chain--registry-integrity) alarm and never mirrored; an open circuit skips the whole tick rather than spending the half-open probe on the first name of a chunk.
- **Unreferenced-blob GC** (`gc.rs`). Collects content-addressed archives no live version and no cached upstream version references, plus staged uploads past the grace period. Dry-run by default; `min_age` (≥ the 1-hour staged-upload TTL) protects the window in which a blob is legitimately unreferenced, since publish writes bytes before the version row.

Domain counters both jobs feed (decision 23, exporter off by default): `upstream_fetch_total{kind,outcome}`, `cache_hit_ratio`, `upstream_sync_lag_seconds`, `quarantine_total`, `shadowing_alarms_total`, `blob_gc_{scanned,deleted,bytes}_total`.

## Frontend workspace

```
web/
├── package.json                # bun workspaces: apps/*, packages/*
├── apps/site/                  # Astro 7 (SSG default)
│   ├── src/pages/…             # landing + docs, per-locale routes (10 locales)
│   ├── src/pages/app/[...rest].astro   # static shell → <App client:only="solid-js"/>
│   ├── src/app/                # Solid SPA: solid-router 1.0, createAsync/query/action,
│   │                           #   feature folders (auth, orgs, packages, tokens, admin)
│   └── public/manifest.webmanifest, sw.js (hand-rolled)
├── packages/tokens/            # OKLCH design tokens, @theme, data-theme + anti-FOUC
├── packages/ui/                # Kobalte-based components + ui-kit showcase page
├── packages/i18n/              # YAML messages (mandatory desc per key) + Bun codegen
└── packages/api/               # openapi-typescript types from utoipa 3.1 spec +
                                #   interceptor fetch client (mutex refresh, denial latch,
                                #   network-vs-denial discrimination) — ported from foxic
```

Service worker policy: precache app shell + hashed assets; SWR for metadata/search API; cache-first for immutable per-version artifacts (rendered READMEs, docs); network-only for auth; never cache mutations. README/markdown is rendered and sanitized on the backend — the client injects HTML into a styled container under strict CSP.

## Configuration & secrets

Boot-time only (env/CLI/mounted files, never DB): DB URL, blob credentials, Redis URL, JWT signing keys, OTP/HMAC pepper, KEK, OIDC client secret, upstream auth token, public base URL, instance role flags. Runtime-changeable via admin UI (DB `settings` + KV invalidation): SMTP (password encrypted with KEK), rate-limit numbers, proxy/org policies, registration mode, banners. Rotation: Ed25519 keyring with `kid` overlap; envelope encryption (KEK wraps DEKs) for TOTP seeds/SMTP.

## Observability

`tracing` + JSON logs, request-id propagation, Server-Timing on hot paths. Exports are opt-in and off by default ([decision 23](decisions.md#23--monitoring-is-optional)): Prometheus `/metrics` (HTTP RED + domain counters: downloads_total, publishes_total, upstream_sync_lag, cache_hit_ratio; optionally on its own listen address) and OTLP trace export, both isolated in `telemetry/`. `/healthz` is always on and reports configured backends and migration status.

## Testing strategy

- **Unit**: domain logic, token/JWT/OTP corner cases (expiry grace, malformed input, replay), cursor pagination, resolution policy table-tests.
- **Integration**: full axum stack over SQLite `:memory:` + InMemory blob + memory KV — protocol conformance suite (every spec status code and header, incl. 401-vs-403-vs-404 ladder), RBAC matrix (role × action × visibility), publish pipeline (dup version, oversized, path-traversal tar, retract/unretract), proxy behavior against a scripted upstream (cold miss, cache hit, sha256-mismatch quarantine, byte-drift, stale-serve, circuit breaker, single-flight, per-org policy, shadowing).
- **Jobs** (`crates/jobs/tests/`): the real worker over a real migrated database and blob store, with only the network scripted — two replicas under one leader lock never running a tick concurrently, `recent` picking up a new upstream version and skipping fresh snapshots, a chunked `full` sweep resuming across a simulated restart and re-enumerating after its window, an S-17 alarm raised once and never mirrored, and a GC that keeps bytes a live version or a cached upstream version still shares.
- **Backend matrix in CI**: same integration suite against Postgres (+ MinIO, Redis) via services/testcontainers; SQLite path runs on every PR, full matrix on merge + nightly.
- **E2E**: a CI job running the real `dart pub` client (Dart docker image) against a live server: token add, get, publish, retraction visibility, proxy fetch.
- **Frontend**: bun test for pure logic (i18n, interceptors, stores); vitest browser mode for ui-kit components; Playwright smoke for auth + publish-token flows; Lighthouse/bundle budgets per roadmap step 8.
