---
name: review-pr
description: Review a pull request or uncommitted diff against Pub's normative docs — rule docs, S-01…S-33 security requirements, decisions.md, and the pub-protocol sharp edges. Use when the user asks to review a PR, review changes, or "what do you think of this diff".
---

# PR Review (Pub)

Source: ported from foxic's `review-pr` skill, remapped to pub's normative docs and monorepo layout.

## Scope

Correctness and convention adherence, not style nits (Biome and `cargo fmt` handle formatting). The normative docs win over any reviewer preference — cite them by section, never restate them from memory.

## Gather the diff

- Current branch vs `master`: `git diff master...HEAD` and `git log master..HEAD --oneline`.
- Specific PR: `gh pr view <n> --json title,body,files` + `gh pr diff <n>`.

## Read the rules that apply to the changed files

| Changed files | Read first |
|---|---|
| `server/**/*.rs` | [docs/rules/rust.md](../../../docs/rules/rust.md) — crate boundaries (`core` has no infra deps; consumers see only `core` traits), the single `authorize()` chokepoint, error envelope, no blocking in handlers |
| `server/crates/db-*/migrations/**` | [docs/rules/migrations.md](../../../docs/rules/migrations.md) — forward-only, paired per dialect, same `NNNN`, dialect-idiomatic SQL, no seed data |
| `server/crates/api/**` (routes, DTOs) | [docs/rules/api.md](../../../docs/rules/api.md) — two API families never mixed (pub protocol vs `/api/v1` envelope), utoipa registration on every route, cursor pagination only, S-12 header on mutations |
| Pub-protocol endpoints (`/pub`, `/o/{org}/pub`) | [docs/protocol.md](../../../docs/protocol.md) — **all 12 sharp edges**; violating one breaks or damages real `dart pub` clients; conformance tests are the arbiter |
| Anything security-relevant (auth, tokens, sessions, limits, visibility, uploads) | [docs/security.md](../../../docs/security.md) — find the governing S-xx; if none fits, that is itself a finding (a new requirement must be discussed and recorded) |
| `web/**` | [docs/rules/web.md](../../../docs/rules/web.md) + [web/DESIGN.md](../../../web/DESIGN.md) |
| Any design-shaped change | [docs/decisions.md](../../../docs/decisions.md) — 23 numbered decisions, normative; an implementation that contradicts one must stop and discuss, never silently deviate |

## Checklist

- **Commits** follow Conventional Commits with repo scopes (`server`/`web`/`infra`/`docs`).
- **Schema changes**: migrations in **both** `db-sqlite` and `db-postgres` with the same number, plus contract tests in `db-tests` exercising both dialects (Postgres leg gated on `PUB_TEST_POSTGRES_URL`).
- **Routes**: every new/changed route registered through utoipa (`#[utoipa::path]`, DTO `ToSchema`); OpenAPI is generated, never hand-edited. Frontend consuming new shapes refreshes `packages/api/openapi.json` + runs `gen:api`.
- **sqlx**: runtime queries only — flag any introduction of `query!` compile-time macros, `.sqlx/`, or `SQLX_OFFLINE` (documented deviation, see `docs/roadmap.md`).
- **Security tests name their requirement** (e.g. `s14_forbidden_keeps_token_403`); a security-relevant change without an S-xx-referencing test is a gap.
- **Authorization** goes through `authorize(actor, action, resource)` — flag scattered `level >= X` comparisons.
- **Errors**: app API answers the `{"status":"error","error":{"code","message"}}` envelope; pub-protocol routes answer the spec error shape; permanent failures are 4xx (the client retries 5xx up to 7 times).
- **SolidJS/web**: `splitProps` (no prop destructuring), `createAsync`/`query` (no `createResource` in new code), no `any`, no TS enums, kebab-case filenames, named exports.
- **i18n**: no hardcoded user-facing strings; every new key has `en` + `desc`; regenerated modules committed.
- **New `packages/ui` component** has a showcase entry in `web/apps/site/src/ui-kit/ui-kit-page.tsx`.
- **Styling**: tokens only from `packages/tokens/theme.css`; no arbitrary values, no `!important`, no hex in components.
- **No secrets** in diff (`password`, `token`, `sk_`, `AKIA`, `.env`); no token/OTP/`Authorization` logging.
- **CHANGELOG.md** entry with component tag for any user-visible change.
- **Tests for corner cases** included — expired/garbage tokens, malformed cursors, boundary sizes are first-class here.

## Output format

1. **Summary** (1–2 sentences): what the PR does and overall verdict.
2. **Must fix**: blocking issues with file:line refs and the doc/S-xx they violate.
3. **Should fix**: non-blocking improvements.
4. **Nits**: optional polish.

Be direct. Call out bad ideas. Silence on a flaw is worse than bluntness.

## Related

- [verify-changes](../verify-changes/SKILL.md) — run the pipelines on the reviewed branch
- [commit-message](../commit-message/SKILL.md) · [release-notes](../release-notes/SKILL.md)
- [docs/decisions.md](../../../docs/decisions.md) · [docs/security.md](../../../docs/security.md) · [docs/protocol.md](../../../docs/protocol.md)
