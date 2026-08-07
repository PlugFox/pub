---
name: add-api-route
description: Add a new HTTP route to the Pub server — pick the right API family, register through utoipa, authorize via the chokepoint, update the route-inventory test, and regenerate frontend types. Use when the user asks to add an endpoint, add a route, expose a new API, or extend an existing handler.
---

# Add API Route (Pub server)

Source: ported from foxic `.claude/skills/server/add-api-route`, re-grounded in this repo's API layer.

**Read first**:

- [docs/rules/api.md](../../../../docs/rules/api.md) — the two API families, envelope, middleware order, utoipa rule.
- [docs/rules/rust.md](../../../../docs/rules/rust.md) — crate boundaries, `authorize()` chokepoint, error rules.
- [docs/protocol.md](../../../../docs/protocol.md) — ONLY if the route lives under `/pub/api/…` or `/o/{org}/pub/api/…`; sharp edges there break real `dart pub` clients, and the conformance tests are the gate.

## Two families — never mix them

- **App API** (`/api/v1/…`): envelope `{"status":"ok","data":…}` / `{"status":"error","error":{"code","message"}}`, cursor pagination only. Handlers in `server/crates/api/src/routes/<area>.rs`.
- **Pub protocol**: spec shapes from `docs/protocol.md`, no envelope, own error type (`ProtocolError`). Handlers in `server/crates/api/src/protocol/`. This skill covers the app API; for protocol work the spec + conformance suite lead.

## File layout

- Handler in the matching `server/crates/api/src/routes/<area>.rs`; new file only for a genuinely new area (then add it to `routes/mod.rs`).
- DTOs in `server/crates/api/src/dto.rs` — separate from domain types, `From` conversions, ids travel as strings, `ToSchema` derive. Hand-write `Debug` for credential-bearing bodies (S-25 — see `OtpVerifyBody`).
- Register in `router()` in `server/crates/api/src/lib.rs` via `.routes(routes!(…))`. Handlers sharing one path (e.g. GET + DELETE) must share one `routes!` group.

## Checklist

- **`#[utoipa::path]` on every handler**: method, path, `tag`, `security(("bearer_auth" = []))` when authed, `request_body`, `responses` with `OkEnvelope<T>` / `ErrorEnvelope` bodies. OpenAPI is generated, never hand-edited.
- **Extractors**: `State(state)`, `AuthContext` (typed `FromRequestParts` — never raw extensions), `RequestMeta` when the action is audited, `QueryParams<T>` (not axum's `Query` — its rejection would escape the envelope), `Path`, `Json` body last.
- **Authentication ≠ authorization**: `AuthContext` only proves identity. Every permission check goes through the single `authorize(actor, action, resource)` chokepoint (decision 19) — no `level >= X` comparisons in handlers. Resolve visibility *first* so unreadable resources are 404, not a 403 that confirms existence (decision 05, S-04) — see `manageable()` in `routes/manage.rs`. Dangerous actions get `require_step_up` / `StepUp` (S-06).
- **Return type**: `Result<Json<OkEnvelope<T>>, ApiError>`; propagate `pub_core::Error` with `?`. Lists use `ListDto<T>` (`{items, cursor, has_more}`) — cursor pagination only.
- **No sqlx in `api`**: the crate sees only `core` traits and domain structs; data access goes through the repository traits on `AppState`.
- Mutations are already covered by `guard::mutation_guard` (S-12: custom header + JSON-only) and auth rate limits (S-24) — the middleware order in `lib.rs` is fixed; never add per-route bypasses.

## After writing

1. Add the `(method, path, authed)` row to `SURFACE` in `server/crates/api/tests/surface.rs` — the OpenAPI-matches-inventory test fails otherwise, by design.
2. Integration test in `server/crates/api/tests/` via `common::TestApp` (SQLite `:memory:` + in-memory blob/KV — no containers). Security-behavior tests name the requirement: `s14_forbidden_keeps_token_403()`.
3. Run `/server-check` (`cd server && cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test --workspace`).
4. **Regenerate frontend types**: refresh the committed document (`cargo run -p pubd`, then `curl -o web/packages/api/openapi.json http://127.0.0.1:8080/api/openapi.json`), run `cd web && bun run gen:api`, commit both `openapi.json` and the generated `openapi.ts`, then `/web-check`. Screens import aliases from `packages/api` `src/types.ts`, never the generated file.
5. Breaking API change → decision-log entry ([docs/decisions.md](../../../../docs/decisions.md)); user-visible change → `CHANGELOG.md`.

## Security pitfalls

- **Status ladder** 404→401→403 (decision 05): foreign or invisible ids are 404 (see token revoke), not 403.
- Never log tokens, OTP codes, or `Authorization` headers; 429 responses carry `Retry-After` (use `Error::RateLimited`).
- Pub-protocol routes only: a 401 makes the client delete its stored token, and 5xx is retried 7 times — permanent failures must be 4xx (`protocol/error.rs` documents both).

## Related

- [rust-error-handling](../rust-error-handling/SKILL.md) — `core::Error`, codes, `ApiError` / `ProtocolError` mapping.
- [docs/rules/api.md](../../../../docs/rules/api.md) · [docs/rules/rust.md](../../../../docs/rules/rust.md) · [docs/security.md](../../../../docs/security.md) · [docs/protocol.md](../../../../docs/protocol.md) · [docs/decisions.md](../../../../docs/decisions.md)
