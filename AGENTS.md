# Agent Guide

Tool-agnostic deep guide for AI agents and new contributors. The short router lives in `CLAUDE.md`; this file explains the system. Design docs in `docs/` are the source of truth — when this summary and a design doc disagree, the design doc wins.

## What this is

**Pub** — a self-hosted, open-source package registry for Dart/Flutter (Hosted Pub Repository Spec v2) with corporate-grade security, designed as a multi-format artifact space (npm/cargo later). One binary for a laptop, replicated cluster for an enterprise. Default product name "Pub", white-label per instance.

## Architecture digest

- **Backend** (`server/`): Rust workspace — axum API, config-driven pluggable backends behind `core` traits, all compiled in, selected at runtime: SQLite **or** PostgreSQL (sqlx 0.9, per-backend crates + migrations), filesystem **or** S3 **or** in-memory blobs (`object_store`), in-memory **or** Redis KV. **Redis (store + pub/sub broker) is mandatory for >1 instance** — config refuses `replicas > 1` with the memory KV. Stateless app tier; background jobs behind a leader lock.
- **Two credential planes, never mixed**: web sessions = short-lived Ed25519 JWT (localStorage; claims `sub`/`sid`/org role levels) + rotating refresh session in DB + revoked-`sid` KV fast path; CLI/API = opaque `pub_…` tokens, SHA-256 at rest, scoped. Cookies are never API credentials.
- **Virtual registry URLs**: `PUB_HOSTED_URL = /o/{org}/pub` (format segment reserved: `/npm`, `/cargo` later); public root `/pub`. Resolution: org-owned → instance-public → upstream proxy iff name unclaimed (local always wins). Status ladder: unreadable → 404, missing/invalid creds → 401 + `WWW-Authenticate`, insufficient-but-visible → 403.
- **Proxy**: read-through cache + mirror-mode sync worker share one ingest pipeline; archives byte-stable forever, `archive_url` rewritten to our host, sha256 verified at ingest.
- **Events**: one domain event bus fans out to SSE (`/api/v1/events`), notification center, audit log, outbound webhooks.
- **Frontend** (`web/`): Bun workspaces — Astro 7 SSG (landing/docs, 10 locales, light/dark OKLCH tokens) + one `client:only` SolidJS island under `/app` (solid-router); Kobalte + Tailwind 4; homegrown YAML+codegen i18n; hand-rolled service worker; API types generated from utoipa OpenAPI. Frontend embeds into the server binary (`server/crates/api/embedded/`).

## Domain concepts

- **Org roles** are cumulative levels: 0 none, 50 Read, 100 Write, 200 Admin, 250 Owner (gaps for future roles); checks are `level >= required` through one `authorize()` chokepoint; names on the wire, numbers in storage.
- **Token scopes** (`read`/`publish`/`retract`/`admin`) are the fine-grained plane, org-bound, optional package patterns.
- **Formats**: core entities carry a `format` discriminator; packages unique per `(format, name)`; v1 ships `pub` only.
- **Immutability**: versions are immutable, numbers never reused; retract ≠ delete; hard delete is admin-only + step-up + tombstone.

## Documentation map

| File                   | Contents                                                        |
| ---------------------- | --------------------------------------------------------------- |
| `docs/decisions.md`    | 26 numbered decisions with rationale — normative                |
| `docs/product.md`      | Vision, feature triage v1/v1.1/later, screens list              |
| `docs/architecture.md` | Crate/workspace layout, data model, pipelines, testing strategy |
| `docs/security.md`     | S-01…S-33 normative security requirements                       |
| `docs/protocol.md`     | Pub spec v2 sharp edges + endpoint table                        |
| `docs/rules/*.md`      | Code conventions per area (read before writing)                 |
| `CHANGELOG.md`         | Keep-a-Changelog, entries tagged `(server)`/`(web)`/`(infra)`   |

## Tooling

`just` is the canonical task runner (`just --list`); `.mise.toml` pins Bun; git hooks come from `lefthook.yml` (`just hooks` once per clone). Use the wired tool, not an ad-hoc equivalent:

| Tool | Wired where | Use for |
| --- | --- | --- |
| `just server-check` / `web-check` / `check` | justfile → documented pipelines | validation before "done" |
| `cargo nextest` (`just server-test`) | justfile | fast test iteration (no doctests) |
| `bacon` | run manually in `server/` | live clippy/check loop while editing Rust |
| `gitleaks` | pre-commit hook + `just secrets-scan` + `security-ci.yml` | secret scanning with the custom `pub_` token rule in `.gitleaks.toml` (S-15) |
| `typos` (config `_typos.toml`) | pre-commit hook + `just spell` | spell-check; extend the config, don't ignore findings |
| `taplo` | pre-commit hook + `just fmt` | Cargo.toml formatting/lint |
| `actionlint` (+shellcheck) | pre-commit hook + `just lint-ci` | workflow linting after any `.github/` edit |
| `cargo audit` / `cargo deny` / `cargo machete` | `just audit` | dependency and supply-chain hygiene |
| `oha` (`just bench [url]`) | justfile | HTTP load smoke; Phase 2 latency exit criteria |
| `dive` (`just image-dive`) | justfile | image layer/size analysis when touching docker/ |
| `hyperfine` | manual | benchmark claims instead of asserting them |
| `sqlx-cli` 0.9 | manual | migration ops against a live DB (rare; migrations apply at startup) |
| vitest browser mode | `packages/ui` `test:browser` | component tests in real Chromium (naming: `*.vitest.tsx`, never `*.test.*`) |

## Mandatory rules

1. Design change → record in `docs/decisions.md` (discuss first).
2. API change → utoipa annotations stay in sync (OpenAPI is generated, never hand-edited).
3. Schema change → both `db-postgres` and `db-sqlite` migrations in the same PR + integration tests on both.
4. Pub-protocol change → re-check every sharp edge in `docs/protocol.md`; conformance tests are the arbiter.
5. Security-relevant change → find the S-xx requirement; if none fits, add one (discuss first).
6. User-visible change → `CHANGELOG.md` entry with component tag and file links.
7. New user-facing string → i18n message with `desc`, never a hardcoded literal.
8. No marketing language in docs; mechanism over adjectives.
