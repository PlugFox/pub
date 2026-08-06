# Changelog

All notable changes to this project. Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versioning: SemVer per component — server crate and web package are versioned independently. Entries are tagged `(server)`, `(web)`, `(infra)`, `(docs)`.

## 2026-08-06 — Postgres identity backend

### Added

- (server) Complete PostgreSQL implementations of all seven identity & access repositories ([db-postgres/src/repo/](server/crates/db-postgres/src/repo/)), replacing the live-ping stubs: native `UUID`/`TIMESTAMPTZ` binds, `INET`/`JSONB` round-tripped as text casts, and `SELECT … FOR UPDATE` row locks serializing the ≥1-Owner invariant, single-use invitation acceptance, and refresh rotation under Postgres' concurrent writers (SQLite's single writer needs none).
- (server) The shared repository contract suite now runs against Postgres ([db-tests/tests/postgres.rs](server/crates/db-tests/tests/postgres.rs)): gated at runtime by `PUB_TEST_POSTGRES_URL` (skip note on stderr when unset, no ignore attributes), one throwaway migrated database per test.
- (infra) `server-ci.yml` test job carries a health-checked `postgres:17-alpine` service container and exports `PUB_TEST_POSTGRES_URL`, so the Postgres contract suite runs on every server CI build.

## 2026-08-06 — design system & UI kit

### Added

- (web) Visual source of truth [web/DESIGN.md](web/DESIGN.md): product-SaaS mood, OKLCH token tables for light/dark, type scale (Inter + JetBrains Mono), 4px rhythm, radii/elevation rules, component specs, Do/Don't catalog, agent pre-commit checklist.
- (web) Finalized design tokens: refined neutral ramp + indigo/violet accent, status colors (success/warning/danger), radius and font-family tokens; [contrast-check script](web/packages/tokens/scripts/contrast-check.ts) asserting WCAG AA 4.5:1 for 44 ink/surface pairs in both themes, wired into `bun run check`.
- (web) Self-hosted fonts via fontsource: Inter Variable + JetBrains Mono (latin/latin-ext/cyrillic/cyrillic-ext woff2 subsets, critical subset preloaded, zero external requests in dist).
- (web) UI kit first tranche in [packages/ui](web/packages/ui/): Button, Input, Label, Card, Badge, Skeleton, Separator, Kobalte-based Dialog and Tooltip, restyled ThemeToggle; `/ui-kit` showcase page (robots-disallowed).
- (web) SaaS landing: gradient hero with CTA, 4-card feature grid, footer — fully i18n'd (new `landing` namespace with `desc` per key, real Russian translations; landing critical path ~82 KB gzip).

### Fixed

- (web) Contrast checker silently validated the light palette twice (selector lookup matched a header comment); the dark theme is now genuinely checked.

## 2026-08-06 — identity & access data layer

### Added

- (server) Identity & access data layer: full repository trait sets in `core` ([UserRepo, CredentialRepo, OrgRepo, SessionRepo, TokenRepo, AuditRepo, SettingsRepo](server/crates/core/src/traits.rs)) with domain types for users, polymorphic credentials (`oidc|email|totp|recovery|webauthn`), orgs/memberships/invitations, rotating refresh sessions with reuse detection (S-08), scoped CLI tokens (S-13), ULID-keyed append-only audit events (S-22), and versioned settings; the single [`authorize()` chokepoint](server/crates/core/src/authorize.rs) with role-ladder boundary tests (decision 19).
- (server) Migration `0002_identity` in both backends ([sqlite](server/crates/db-sqlite/migrations/0002_identity.sql), [postgres](server/crates/db-postgres/migrations/0002_identity.sql)): users, credentials, orgs, org_members, invitations, sessions, tokens, audit_log, settings — case-insensitive unique emails/slugs, partial indexes for active-token/active-session lookups, Postgres INSERT-only audit role template.
- (server) Complete SQLite implementations of all seven repositories ([db-sqlite/src/repo/](server/crates/db-sqlite/src/repo/)); Postgres ships live-ping stubs until its query implementations land.
- (server) Shared repository contract suite ([db-tests](server/crates/db-tests/)) run against SQLite `:memory:` — last-Owner invariant, invitation expiry/double-accept, refresh-reuse detection, cursor-pagination stability, and more.

### Changed

- (server) `/healthz` now live-pings the database (plus blob and KV) and reports per-backend `checks` instead of echoing only configured kinds; `AppState` carries the repository bundle.

## 2026-08-06 — design phase

### Added

- (docs) Design documentation: product vision and feature triage ([docs/product.md](docs/product.md)), architecture ([docs/architecture.md](docs/architecture.md)), decision log with 23 decisions ([docs/decisions.md](docs/decisions.md)), normative security requirements S-01…S-33 ([docs/security.md](docs/security.md)), pub protocol sharp edges ([docs/protocol.md](docs/protocol.md)).
- (docs) Contributor/agent governance: [CLAUDE.md](CLAUDE.md), [AGENTS.md](AGENTS.md), code conventions in [docs/rules/](docs/rules/).
- (infra) Repository scaffolding: `.gitignore`, `.editorconfig`, `.dockerignore`.
- (server) Cargo workspace skeleton — 13 crates per [docs/architecture.md](docs/architecture.md): `core` (domain types, `RoleLevel` 0/50/100/200/250, 12 backend traits), `config` (layered `defaults → TOML → PUB_* env → CLI` with validation incl. the replicas>1-requires-Redis rule), `db-sqlite`/`db-postgres` (pools + initial migrations), `blob` (object_store fs/memory/S3), `kv` (moka + broadcast broker; deadpool-redis skeleton), `telemetry` (tracing; config-gated Prometheus recorder), `jobs` (leader-locked interval scheduler), `api` (axum + utoipa: `/healthz`, `/api/v1/ping`, `/api/openapi.json`, embedded static with SPA fallback, security headers), `bin/pubd` (backend selection, migrations, graceful shutdown, build-info). 81 tests green; fmt/clippy clean.
- (web) Bun workspaces skeleton — `apps/site` (Astro 7.2 + Solid 1.9 island under `/app`, 10-locale i18n routing, anti-FOUC theme script, manifest + service worker), `packages/tokens` (OKLCH light/dark `@theme`), `packages/i18n` (YAML + `desc`, Bun codegen, dependency-free runtime with `Intl.PluralRules`), `packages/ui` (`cn()`, Button, ThemeToggle), `packages/api` (interceptor-chain client, `ApiError`/`NetworkError`). TypeScript 7.0.2 native; 19 tests green; Biome clean. Note: `astro check` waits for TS 7.1 API.
- (infra) CI: path-filtered `server-ci.yml` (fmt/clippy/test, rust-cache) and `web-ci.yml` (check/build/test, setup-bun) with minimal permissions and concurrency-cancel. Docker: 4-stage single-image build (web dist embedded into the Rust binary per decision 04), compose profiles `pg`/`s3`/`redis`/`full` with zero-config defaults.
