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
│   │                           #   PackageRepo UserRepo OrgRepo TokenRepo SessionRepo
│   │                           #   AuditRepo SettingsRepo ClaimRepo UpstreamRepo
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
│   │                           #   proxy ingest, retraction, claims, readme rendering
│   ├── mail/                   # lettre + askama templates (text+HTML multipart)
│   ├── jobs/                   # interval scheduler + JobLock leader election;
│   │                           #   mirror sync, blob GC, session/OTP purge, reindex,
│   │                           #   webhook delivery (retries, dead-letter)
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
- `orgs`, `org_members (org_id, user_id, role_level)` — cumulative role levels **Read(50) / Write(100) / Admin(200) / Owner(250)** with gaps for future roles, mirrored into JWT claims, all checks through one `authorize()` chokepoint ([decision 19](decisions.md#19--rbac-cumulative-role-levels-with-a-single-authorize-chokepoint)); ≥1 Owner invariant; `invitations` (hashed single-use token, 7-day expiry, bound to email, default role Read).
- `packages (format, name, org_id, visibility, discontinued, replaced_by, unlisted)` — unique per `(format, name)` per instance ([decision 21](decisions.md#21--multi-format-artifact-space-pub-first-npm-cargo--later): pub in v1, npm/cargo later share these entities); `name_claims` — `(format, name)` → org, written at first publish, consulted by resolution and shadowing alerts.
- `versions (package_id, semver columns, pubspec JSONB/TEXT, archive_sha256, readme_html, changelog_html, retracted_at, tombstone)` — immutable; archive bytes content-addressed in blob store by sha256.
- `upstream_packages / upstream_versions` — proxy cache metadata (listing snapshots, sha256, fetched_at, upstream flags verbatim).
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

**Proxy ingest** (shared by read-through and mirror worker): fetch upstream listing → verify/record `archive_sha256` → store bytes content-addressed → snapshot metadata → serve stale on upstream outage (circuit breaker). Proxied listings are **re-emitted with `archive_url` rewritten under the requesting virtual base `B`** — never upstream's CDN URL, otherwise clients download straight from pub.dev and caching, per-org policy, and stale-serving are silently bypassed. Flags (`retracted`, `isDiscontinued`, `replacedBy`, `advisoriesUpdated`), pubspec JSON, and `archive_sha256` are preserved verbatim. Mirror mode = jobs-crate worker warming the same pipeline: initial sweep + drift repair via `/api/package-names`, fast path via recent-changes polling.

## Realtime events (SSE)

`GET /api/v1/events` streams Server-Sent Events to the web app ([decision 20](decisions.md#20--realtime-sse-event-stream--notification-center)): package publishes/retractions, membership/invitation events, shadowing alarms, notifications, admin-facing settings changes. SSE is one consumer of the **internal domain event bus** — the same bus feeds the notification center, the audit log, and outbound webhooks ([decision 22](decisions.md#22--domain-event-bus-webhooks-and-integrations-on-top)). Domain services emit events into an in-process broadcast; with the Redis KV backend every instance republishes to a broker topic and subscribes to peers, so any instance can serve any client's stream. The browser uses fetch-streaming (not `EventSource` — it cannot set `Authorization`); heartbeats double as revocation re-checks (S-32); `Last-Event-ID` replays best-effort from a short per-user ring buffer. The stream is a hint channel — clients reconcile through the REST API, so lost events are never correctness bugs.

## Background jobs

Interval scheduler in `jobs/` guarded by `JobLock` leader election (PG advisory lock / Redis lock / trivial single-node): mirror sync, unreferenced-blob GC, expired session/OTP/invitation purge, audit retention, search reindex, token-expiry notification emails. Job state (last-run, cursors) in DB; every job idempotent and safe to rerun.

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

Boot-time only (env/CLI/mounted files, never DB): DB URL, blob credentials, Redis URL, JWT signing keys, OTP/HMAC pepper, KEK, OIDC client secret, public base URL, instance role flags. Runtime-changeable via admin UI (DB `settings` + KV invalidation): SMTP (password encrypted with KEK), rate-limit numbers, proxy/org policies, registration mode, banners. Rotation: Ed25519 keyring with `kid` overlap; envelope encryption (KEK wraps DEKs) for TOTP seeds/SMTP.

## Observability

`tracing` + JSON logs, request-id propagation, Server-Timing on hot paths. Exports are opt-in and off by default ([decision 23](decisions.md#23--monitoring-is-optional)): Prometheus `/metrics` (HTTP RED + domain counters: downloads_total, publishes_total, upstream_sync_lag, cache_hit_ratio; optionally on its own listen address) and OTLP trace export, both isolated in `telemetry/`. `/healthz` is always on and reports configured backends and migration status.

## Testing strategy

- **Unit**: domain logic, token/JWT/OTP corner cases (expiry grace, malformed input, replay), cursor pagination, resolution policy table-tests.
- **Integration**: full axum stack over SQLite `:memory:` + InMemory blob + memory KV — protocol conformance suite (every spec status code and header, incl. 401-vs-403-vs-404 ladder), RBAC matrix (role × action × visibility), publish pipeline (dup version, oversized, path-traversal tar, retract/unretract), proxy behavior (shadowing, stale-serve, sha256 mismatch quarantine).
- **Backend matrix in CI**: same integration suite against Postgres (+ MinIO, Redis) via services/testcontainers; SQLite path runs on every PR, full matrix on merge + nightly.
- **E2E**: a CI job running the real `dart pub` client (Dart docker image) against a live server: token add, get, publish, retraction visibility, proxy fetch.
- **Frontend**: bun test for pure logic (i18n, interceptors, stores); vitest browser mode for ui-kit components; Playwright smoke for auth + publish-token flows; Lighthouse/bundle budgets per roadmap step 8.
