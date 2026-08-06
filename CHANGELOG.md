# Changelog

All notable changes to this project. Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versioning: SemVer per component — server crate and web package are versioned independently. Entries are tagged `(server)`, `(web)`, `(infra)`, `(docs)`.

## 2026-08-06 — design phase

### Added

- (docs) Design documentation: product vision and feature triage ([docs/product.md](docs/product.md)), architecture ([docs/architecture.md](docs/architecture.md)), decision log with 23 decisions ([docs/decisions.md](docs/decisions.md)), normative security requirements S-01…S-33 ([docs/security.md](docs/security.md)), pub protocol sharp edges ([docs/protocol.md](docs/protocol.md)).
- (docs) Contributor/agent governance: [CLAUDE.md](CLAUDE.md), [AGENTS.md](AGENTS.md), code conventions in [docs/rules/](docs/rules/).
- (infra) Repository scaffolding: `.gitignore`, `.editorconfig`, `.dockerignore`.
- (server) Cargo workspace skeleton — 13 crates per [docs/architecture.md](docs/architecture.md): `core` (domain types, `RoleLevel` 0/50/100/200/250, 12 backend traits), `config` (layered `defaults → TOML → PUB_* env → CLI` with validation incl. the replicas>1-requires-Redis rule), `db-sqlite`/`db-postgres` (pools + initial migrations), `blob` (object_store fs/memory/S3), `kv` (moka + broadcast broker; deadpool-redis skeleton), `telemetry` (tracing; config-gated Prometheus recorder), `jobs` (leader-locked interval scheduler), `api` (axum + utoipa: `/healthz`, `/api/v1/ping`, `/api/openapi.json`, embedded static with SPA fallback, security headers), `bin/pubd` (backend selection, migrations, graceful shutdown, build-info). 81 tests green; fmt/clippy clean.
- (web) Bun workspaces skeleton — `apps/site` (Astro 7.2 + Solid 1.9 island under `/app`, 10-locale i18n routing, anti-FOUC theme script, manifest + service worker), `packages/tokens` (OKLCH light/dark `@theme`), `packages/i18n` (YAML + `desc`, Bun codegen, dependency-free runtime with `Intl.PluralRules`), `packages/ui` (`cn()`, Button, ThemeToggle), `packages/api` (interceptor-chain client, `ApiError`/`NetworkError`). TypeScript 7.0.2 native; 19 tests green; Biome clean. Note: `astro check` waits for TS 7.1 API.
- (infra) CI: path-filtered `server-ci.yml` (fmt/clippy/test, rust-cache) and `web-ci.yml` (check/build/test, setup-bun) with minimal permissions and concurrency-cancel. Docker: 4-stage single-image build (web dist embedded into the Rust binary per decision 04), compose profiles `pg`/`s3`/`redis`/`full` with zero-config defaults.
