---
name: rust-error-handling
description: Apply Pub's Rust error conventions — the single core::Error with stable codes, thiserror, ? propagation, ApiError/ProtocolError HTTP mapping, no anyhow in libraries. Use when writing or refactoring error types, Result chains, error variants, or error mapping for HTTP responses.
---

# Rust Error Handling (Pub server)

Source: ported from foxic `.claude/skills/server/rust-error-handling`, rewritten around this repo's real error types.

**Read first**: [docs/rules/rust.md](../../../../docs/rules/rust.md) — the canonical rules. This skill is a reminder, not a replacement.

## The three pieces

- **`pub_core::Error`** (`server/crates/core/src/error.rs`) — the one top-level `thiserror` enum, `#[non_exhaustive]`, shared across the workspace (decision 16). Every variant has a stable machine-readable `code()` string; **codes are public contract — existing values never change** (asserted by `codes_are_stable`).
- **`ApiError`** (`server/crates/api/src/error.rs`) — newtype over `Error` with `From<Error>` + `IntoResponse` for the app API envelope. Handlers return `Result<Json<…>, ApiError>` and use `?` freely; that pair is the whole mapping.
- **`ProtocolError`** (`server/crates/api/src/protocol/error.rs`) — the pub-protocol family: spec shape `{"error":{"code","message"}}`, `WWW-Authenticate` challenge on 401/403, and **permanent failures never map to 5xx** (the pub client retries 5xx 7 times and deletes its token on 401). Never shared with the envelope.

## Core rules

- **Map at the boundary**: infrastructure crates (`db-*`, `blob`, `kv`, …) convert native errors (sqlx, object_store, redis) into `Error::Database/Blob/Kv { message }` where they occur. `core` depends on no infra crates, so there are no `#[from] sqlx::Error` impls — the conversion is explicit in the implementation crate, and consumers only ever see domain errors.
- **Never match on error message strings** — match variants, or compare `code()`.
- **No `anyhow` in library crates**; `bin/pubd` may use it at the very top. No `Result<_, Box<dyn Error>>` on public functions.
- **No `unwrap()`/`expect()`** in request-handling paths; tolerated in tests, startup (with a descriptive message), and values proven infallible.
- **`?` over match** for propagation; `From<Error> for ApiError` already makes `?` work in handlers.
- Permanent (caller-caused) failures are 4xx; **5xx is reserved for genuine server faults**.

## Status mapping (lives in `api`, not `core`)

From `ApiError::status()`: `Invalid`→400 · `NotFound`→404 · `Conflict`/`LastOwner`→409 · `Forbidden`/`StepUpRequired`→403 · `Unauthorized`/`InvalidCode`/`RefreshReused`→401 · `RateLimited`→429 + `Retry-After` (S-24) · `Expired`→410 · `Kv`→503 (auth fast paths fail closed, S-09) · `Unimplemented`→501 · `Config`/`Database`/`Blob`/`Internal`→500.

Distinct codes exist only where the client must react differently: `step_up_required` prompts for a fresh factor (S-06), `refresh_reused` drops the whole session (S-08), while `invalid_code` deliberately collapses every OTP failure (S-03/S-04). Reuse an existing variant before adding one.

## Adding a variant

1. Add it to `Error` with a `#[error(…)]` message and a new `code()` string; extend the `codes_are_stable`/`codes_are_unique` tests in `core/src/error.rs`.
2. Map its status in `ApiError::status()` — `Error` is `#[non_exhaustive]`, so an unmapped variant silently falls to 500 — and extend `statuses_follow_the_contract` in `api/src/error.rs`.
3. If reachable from pub-protocol routes, check `ProtocolError`'s mapping and its `permanent_failures_never_map_to_5xx` test.

## Logging

- `tracing::error!` fires exactly where the error becomes a 5xx (inside `ApiError::into_response`); the wire gets a generic message — **5xx details never leak to the client**. Below the boundary, propagate silently.
- Correlation comes from `TraceLayer` + request-id middleware, not from error messages.
- Never log tokens, OTP codes, or `Authorization` headers; hand-write `Debug` for credential-bearing types (S-25).

## Common mistakes

- Returning a raw `StatusCode` instead of constructing a `pub_core::Error` — logging and body shape drift.
- Changing an existing `code()` string — that breaks the public contract and the generated frontend client.
- `Forbidden` where decision 05 demands `NotFound` — resolve visibility first so invisible resources don't confirm their existence.
- Swallowing errors with `let _ = …` — handle or propagate explicitly.
- Using `ApiError`/the envelope on pub-protocol routes (or `ProtocolError` on `/api/v1/…`) — the families never mix.

## Related

- [add-api-route](../add-api-route/SKILL.md) — where the mapped errors surface, route by route.
- [docs/rules/rust.md](../../../../docs/rules/rust.md) · [docs/rules/api.md](../../../../docs/rules/api.md) · [docs/security.md](../../../../docs/security.md) · [docs/decisions.md](../../../../docs/decisions.md)
