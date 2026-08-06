# HTTP API Rules

Two API families with different contracts — never mix them:

## Pub protocol (`/o/{org}/pub/api/…`, `/pub/api/…`)

- Wire shapes come from `docs/protocol.md` **exactly** (spec error shape, `WWW-Authenticate` on 401/403, status ladder 404→401→403 per decision 05). No envelope.
- Conformance tests are the gate for any change here.

## App API (`/api/v1/…`)

- Envelope: `{"status":"ok","data":…}` / `{"status":"error","error":{"code","message"}}`; codes are stable machine-readable strings from `core::Error::code()`.
- Cursor pagination only: `{items, cursor, has_more}`.
- SSE stream at `/api/v1/events` (S-32): heartbeats re-check revocation; auth via `Authorization` header (fetch-streaming client).
- State-changing endpoints require JSON content type and the custom header (S-12); CORS is locked to the instance origin.

## Both

- Every route registered through utoipa (`OpenApiRouter` + `routes!`) with `#[utoipa::path]` and DTO `ToSchema` — routes and OpenAPI can never drift; the `bearer_auth` SecurityScheme is registered in components. OpenAPI JSON at `/api/openapi.json`; never hand-edited.
- Middleware order: request-id → tracing → security headers → rate limit → auth. Auth context arrives via typed extractors (`FromRequestParts`), not raw extensions.
- Never log tokens, OTP codes, or `Authorization` headers. Rate-limited responses use 429 + `Retry-After`.
- DTOs are separate from domain types (`From` conversions); breaking API changes require a decision-log entry.
