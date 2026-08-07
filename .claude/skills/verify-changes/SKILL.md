---
name: verify-changes
description: Run the correct validation pipeline (server and/or web) before declaring work done. Use before reporting task completion, when the user asks to "check", "validate", "make sure it builds", or when preparing a commit.
---

# Verify Changes (Pub)

Source: ported from foxic's `verify-changes` skill, adapted to pub's pipelines and generated artifacts.

CLAUDE.md is explicit: **done means green.** This skill picks the right checks based on what changed.

## Regenerate before you check

Stale generated artifacts fail the pipeline or, worse, pass it while lying. If the diff touches a generator input, run the generator first and include its output in the same commit (generated files are committed, Biome-excluded, never hand-edited):

| Changed input | Regenerate with |
|---|---|
| `web/packages/i18n/messages/*.yaml` (en + mandatory `desc` per key) | `cd web && bun run i18n:gen` |
| `web/packages/api/openapi.json` | `cd web && bun run gen:api` |

`openapi.json` itself is fetched from a running `pubd` (`/api/openapi.json`), never hand-edited — if server route/DTO annotations changed and the frontend needs the new shapes, refresh the committed document first, then `gen:api`.

## Decide what to run

Check `git status` and `git diff --name-only` (or the list of files just edited):

| Touched paths | Run |
|---|---|
| `server/**` (Rust, SQL, config) | `/server-check` |
| `web/**` (TS/TSX, CSS, YAML messages, tokens) | `/web-check` |
| Both areas | both commands, server first |
| `server/crates/db-*/migrations/**` | `/server-check`, and confirm **both** dialect directories changed with the same `NNNN` — plus contract tests in `db-tests` covering the change |
| `docker/**`, `.github/**`, root-level docs only | skip — no validation pipeline |
| UI behavior changed (not just visuals) | `/web-check` **plus** a browser walkthrough via claude-in-chrome (below) |

## Procedure

1. Invoke the matching slash command(s) — they hold the canonical sequences (`cargo fmt --check` + `clippy --all-targets -- -D warnings` + `cargo test --workspace`; `bun run check` + `bun run build` + `bun test`). Do not run ad-hoc subsets.
2. If a check fails, **stop**. Show the failing output (tail only), identify the root cause, propose a fix.
3. Do not mark the task complete until every check is green.
4. For schema/repository changes: without `PUB_TEST_POSTGRES_URL` the suite runs SQLite-only and **skips Postgres silently**. Run `/db-up` and set the variable so the contract-test leg covers both dialects; say in the summary which legs ran.
5. For UI-visible changes, after `/web-check` is green, exercise the golden path plus one edge case in a real browser via the `claude-in-chrome` skill (`mcp__claude-in-chrome__*` tools): no uncaught console errors, expected DOM state confirmed. `@playwright/test` is a dev dependency but there is no test suite yet — do not claim an automated walkthrough exists.

## Common footguns

- `cargo test` alone is not sufficient — fmt and clippy (`-D warnings`) are gates, not suggestions.
- This repo uses **runtime sqlx queries** — there is no `.sqlx/` cache, no `cargo sqlx prepare`, no `SQLX_OFFLINE`. Do not introduce them (documented deviation, exit condition in `docs/roadmap.md`).
- Migrations apply at startup via `sqlx::migrate!` — there is no manual apply step; running the tests *is* the verification.
- `bun run check` passing does not mean the UI works — always exercise the flow for behavior changes.
- The contrast gate inside `bun run check` fails on token-palette changes that break WCAG AA — fix the tokens, never bypass the gate.

## Related

- [/server-check](../../commands/server-check.md) · [/web-check](../../commands/web-check.md) · [/db-up](../../commands/db-up.md) · [/new-migration](../../commands/new-migration.md)
- [commit-message](../commit-message/SKILL.md) — after checks are green
- [docs/rules/rust.md](../../../docs/rules/rust.md) · [docs/rules/web.md](../../../docs/rules/web.md) · [docs/rules/migrations.md](../../../docs/rules/migrations.md)
