---
name: rust-testing
description: Write Rust tests for the pub server — unit tests, dual-backend repository contract tests (db-tests), HTTP integration over the full router, protocol conformance, and S-xx security tests. Use when adding tests, fixtures, or when the user asks to "test X" or "add a test for Y".
---

# Rust Testing (pub server)

**Source:** adapted from [affaan-m/everything-claude-code — rust-testing](https://skills.sh/affaan-m/everything-claude-code/rust-testing), ported from foxic and rebuilt around this repo's taxonomy. Normative: [docs/architecture.md](../../../../docs/architecture.md) § "Testing strategy" and [docs/rules/rust.md](../../../../docs/rules/rust.md) § "Tests". Corner cases are first-class (CLAUDE.md) — expired/garbage tokens, malformed cursors, boundary sizes, clock skew ship with the feature, not later.

## Taxonomy — pick the right layer

| Layer | Where | Runs |
|-------|-------|------|
| Unit | `#[cfg(test)] mod tests` inline in the crate | always |
| Repository contract | `server/crates/db-tests/src/contract.rs` + runners | SQLite always; Postgres when `PUB_TEST_POSTGRES_URL` is set |
| HTTP integration | `server/crates/api/tests/*.rs` (full router) | always, in-memory backends |
| Protocol conformance | `server/crates/api/tests/protocol.rs` | always |
| Security (S-xx) | `attack.rs`, `pub_attack.rs`, and S-xx-named tests everywhere | always |
| Jobs | `server/crates/jobs/tests/` — real worker over a real migrated DB + blob store, only the network scripted | always |

## No `#[sqlx::test]` — and why

Pub deliberately uses **runtime** sqlx queries, not the `query!` macro family (rationale in the module docs of `server/crates/db-sqlite/src/lib.rs`; revisit once the sqlx 0.9 CLI workflow settles). There is no macro metadata, no `.sqlx/` cache, no `cargo sqlx prepare`, no per-test auto-database attribute, and no SQL fixture directories. Correctness is carried by the contract suite against real migrated databases. Fresh databases are built by hand:

- **SQLite**: connect `:memory:`, `run_migrations()`, `repositories()` — see `fresh_repos()` in `server/crates/db-tests/tests/sqlite.rs`. One fresh DB per test; scenarios can never bleed.
- **Postgres**: `TestDb` in `server/crates/db-tests/tests/postgres.rs` creates a throwaway `pub_contract_<uuid>` database, migrates via `pub_db_postgres::MIGRATOR`, drops it on success; on failure the DB is left behind for inspection. Gated **at runtime** by `PUB_TEST_POSTGRES_URL` — no `#[ignore]`; when unset each test prints a skip note and returns.

Seed data through repository calls (`seed_user`, `seed_org` helpers in `contract.rs`), never raw SQL fixtures.

## Repository contract tests

Every DB backend must pass the same suite through the plain `Repositories` trait bundle — the contract code never sees sqlx or backend types. When you add or change a repo trait method:

1. Extend the matching contract fn in `db-tests/src/contract.rs` (or add a new one). It takes `&Repositories`, uses only `core` types, and panics on violation.
2. Register a wrapper test with the **same name** in BOTH `tests/sqlite.rs` and `tests/postgres.rs`.
3. Deterministic time: build timestamps from the `t0()` base instant plus `days()`/`hours()` — never `Utc::now()`.
4. Name pins the requirement: `session_repo_contract_s08_s09_s10`, `resolve_in_base_scope_contract_decision01`.

## HTTP integration harness

`server/crates/api/tests/common/mod.rs` builds the full app the way `pubd` wires it, over SQLite `:memory:` + in-memory blob/KV/mailer — no containers, no mocked router:

- `TestApp::new()` / `TestApp::with_options(TestOptions { .. })` — policy knobs (rate limits, registration, proxy, SSE caps, `require_auth_for_read`, …).
- `app.get / post / post_empty / delete` return `ApiResponse { status, headers, json }`; `send_raw` keeps bytes (archives are not JSON). `request()` adds the S-12 `x-pub-request` header and `x-forwarded-for`.
- **Time**: `app.advance(Duration)` moves the injected clock. Never sleep to make domain time pass.
- **Races**: `app.send_concurrent(requests)` fires on the shared router via `JoinSet` (see `s08_concurrent_refresh_has_exactly_one_winner`).
- **Restarts**: `app.restart()` rebuilds the app over the same durable backends — DB rows, blobs, KV survive; caches and routers don't. Use it to prove cross-restart guarantees (archive byte-stability does).
- **Failure injection**: `FailingKv` proves S-09/S-24 fail-closed clauses; `MockUpstream` scripts the read-through proxy; `InMemoryMailer` is the outbox OTP codes are read from.

## Protocol conformance

`protocol.rs` **is** [docs/protocol.md](../../../../docs/protocol.md) in executable form: every test is named after the sharp edge it pins, and the module docs keep a sharp-edge → test map — extend the map when you add one. Drive the router the way `dart pub` does (bearer, `Accept: application/vnd.pub.v2+json`, no app-API headers) and follow the URLs the server hands back instead of hardcoding them.

## Security tests

Behavior mandated by [docs/security.md](../../../../docs/security.md) gets a test whose name **starts with the S-xx id**: `s03_parallel_wrong_codes_each_spend_an_attempt`, `s24_spoofed_forwarded_header_cannot_mint_fresh_buckets`. Adversarial suites live in `attack.rs` (auth plane) and `pub_attack.rs` (pub protocol plane); contract and integration tests append `_sNN` / `_decisionNN` suffixes when they pin a clause. If a clause has no failing path in normal wiring, inject one (that is what `FailingKv` exists for) — a fail-closed rule proven by dead code is not proven.

## Mocking policy

- **Never mock repositories or sqlx.** Anything DB-shaped runs against a real migrated database via the contract suite or the integration harness.
- Doubles are real implementations of `core` traits, injected as `Arc<dyn Trait>`: `MemoryKv` / `FailingKv`, `InMemoryMailer`, `ObjectStoreBlob::memory()`, `MockUpstream` (implements `UpstreamClient`), `InMemoryJobLock`. No mocking crates.
- **Time**: injected clock in the harness; `#[tokio::test(start_paused = true)]` + tokio `test-util` for timing loops (scheduler tests are the model).

## Assertions & style

- `expect("context")` in setup, plain `assert!`/`assert_eq!` for the invariant under test — don't bury the failing assertion under an `unwrap()` chain.
- Sort before comparing collections unless order is the contract (cursor pagination order **is** the contract — test it as such).
- Test names state behavior, not method names: `finalize_rejects_duplicate_version_with_400_not_500`.

## Running

- `cd server && cargo test --workspace` — everything local (Postgres leg silently skipped when ungated); `/server-check` runs the full gate (fmt + clippy + test).
- Filter: `cargo test -p pub-api s24`, `cargo test -p pub-db-tests --test sqlite`.
- Postgres leg: `/db-up` (or `docker compose -f docker/docker-compose.yml --profile pg up -d`), then `PUB_TEST_POSTGRES_URL=postgres://pub:pub_dev_password@localhost:5432/pub cargo test -p pub-db-tests --test postgres`.
- CI runs the SQLite path on every PR and the full Postgres/MinIO/Redis matrix on merge + nightly; the real-`dart pub` E2E job is the final arbiter for protocol behavior.

## Related

- Async test idioms, paused time, cancel-safety: [rust-async-tokio](../rust-async-tokio/SKILL.md)
- Normative test rules: [docs/rules/rust.md](../../../../docs/rules/rust.md) · taxonomy: [docs/architecture.md](../../../../docs/architecture.md)
- Requirements referenced from test names: [docs/security.md](../../../../docs/security.md) · [docs/protocol.md](../../../../docs/protocol.md) · [docs/decisions.md](../../../../docs/decisions.md)
- Migrations discipline behind every fresh test DB: [docs/rules/migrations.md](../../../../docs/rules/migrations.md)
