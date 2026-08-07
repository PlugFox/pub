# Rust Conventions (`server/`)

Edition 2024, stable toolchain. `rustfmt` (max_width 120) + `clippy --all-targets -- -D warnings` are gates, not suggestions.

## Boundaries

- `core` defines domain types and traits; it depends on **no** infrastructure crates (no sqlx, object_store, redis, axum).
- `api` (and every other consumer) sees **only** `core` traits and domain structs — never sqlx rows, object_store types, or redis connections. Conversions live in the implementation crates.
- Backend selection is runtime config (`AppState` holds `Arc<dyn Trait>`), never cargo features.
- Every authorization check goes through the single `authorize(actor, action, resource)` chokepoint (decision 19). No scattered `level >= X` comparisons in handlers.

## Errors

- `thiserror` enums per domain module; a top-level `core::Error` with `code()` (machine-readable, stable) and HTTP mapping in `api` via `IntoResponse`.
- Never match on error message strings. Never `anyhow` in library crates (`bin/pubd` may use it at the very top).
- App API envelope: `{"status":"ok","data":…}` / `{"status":"error","error":{"code","message"}}`. Pub protocol routes use the spec error shape instead (`docs/protocol.md`).
- Permanent failures are 4xx; 5xx is reserved for genuine server faults (the pub client retries 5xx up to 7 attempts).

## Dependencies

- All versions pinned in `[workspace.dependencies]`; member crates use `workspace = true`.
- `default-features = false` trims carry an inline comment with the reason (security advisory, size). `cargo audit` ignores require a written justification in `.cargo/config.toml`.

## Async & blocking

- tokio everywhere; no blocking calls in handlers. CPU-heavy work (tar extraction, markdown render, hashing large buffers) goes through `spawn_blocking` or a worker.
- Background loops: `tokio::time::interval` + `MissedTickBehavior::Skip`, guarded by `JobLock` when the job must be single-instance.

## Data

- Ids: UUID v7 for entities; ULID for audit events. Timestamps UTC (`TIMESTAMPTZ` / RFC3339).
- Runtime `sqlx::query`/`query_as` with `TryFrom<Row>` mapping — **not** compile-time macros (decision 02 amendment: `COLS` dedup, sqlx-free `core`, and dialect idioms outweigh macro checking; the dual-backend contract suite carries correctness). Keep column lists in per-table `COLS` consts.
- Cursor pagination only (`{items, cursor, has_more}`); no offset pagination.

## Tests

- Unit tests inline (`#[cfg(test)]`), corner cases first-class: expired/garbage tokens, malformed cursors, boundary sizes, clock skew.
- Integration tests in `crates/api/tests/` run the full stack on SQLite `:memory:` + in-memory blob + in-memory KV — no containers. The Postgres/MinIO/Redis matrix runs in CI.
- Security-behavior tests name the requirement: `s14_forbidden_keeps_token_403()`.
- Protocol conformance suite encodes `docs/protocol.md`; the real-`dart pub` E2E job is the final arbiter.
