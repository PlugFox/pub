---
description: Run server pre-commit checks (fmt, clippy, test)
allowed-tools: Bash
---

Run the full server validation pipeline and report results.

Execute in order, stop on first failure:

1. `cd server && cargo fmt --check` — if this fails, run `cargo fmt` and commit the diff separately.
2. `cd server && cargo clippy --all-targets -- -D warnings`
3. `cd server && cargo test --workspace`

If any step fails: show the failing output (tail only, not the full log), identify the root cause, and propose a fix. Do not auto-fix without confirmation unless it's a pure formatting issue.

If all pass: report `server-check: OK` with a one-line summary (test count, warnings count).

Note: the Postgres contract leg only runs when `PUB_TEST_POSTGRES_URL` is set (`docker compose -f docker/docker-compose.yml --profile pg up -d` first). Without it the suite runs on SQLite `:memory:` and skips Postgres silently — say so in the summary.
