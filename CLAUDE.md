# Pub — self-hosted package registry

Monorepo: Rust backend (`server/`), Bun/Astro/SolidJS frontend (`web/`), design docs (`docs/`), docker (`docker/`). Deeper agent guide: `AGENTS.md`.

## Read before working

| When | Read |
|------|------|
| Any design/architecture question | `docs/decisions.md` (normative, 23 decisions), `docs/architecture.md` |
| Touching pub protocol endpoints | `docs/protocol.md` — violating a sharp edge breaks `dart pub` clients |
| Auth, tokens, sessions, limits, webhooks | `docs/security.md` — normative S-01…S-33, referenced from tests |
| Writing Rust | `docs/rules/rust.md` |
| Writing frontend code | `docs/rules/web.md` |
| DB schema / migrations | `docs/rules/migrations.md` |
| HTTP API surface | `docs/rules/api.md` |

## Commands

- Server (from `server/`): `cargo fmt --check` · `cargo clippy --all-targets -- -D warnings` · `cargo test --workspace`
- Web (from `web/`): `bun install` · `bun run check` · `bun run build` · `bun test`
- Dev infra (optional — default dev loop needs NO containers: SQLite + fs blob + in-memory KV):
  `docker compose -f docker/docker-compose.yml --profile pg up -d` (profiles: `pg`, `s3`, `redis`, `full`)

## Critical rules

- Russian with the user; English in code, comments, docs, and commits.
- Conventional commits: `feat(server): …`, `fix(web): …`, `chore(infra): …`. Update `CHANGELOG.md` for any user-visible change.
- `docs/decisions.md` is normative. If an implementation needs to contradict a decision — stop and discuss; never silently deviate. New agreements get recorded there.
- Before writing code: challenge the approach, surface unknowns and edge cases, wait for confirmation on genuinely open choices.
- After writing code: run the validation pipeline for the touched side (commands above); done means green.
- Everything testable gets tests; corner cases are first-class. Tests for security behavior reference the S-xx id in their names.
- Never read or edit `.env*` files with real secrets; `.env.example` is the template.
