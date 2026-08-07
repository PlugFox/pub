---
description: Create a paired DB migration (SQLite + Postgres) following the migration rules
allowed-tools: Bash, Read, Write
---

Create a new schema migration. Read `docs/rules/migrations.md` first — it is normative.

Hard rules from that document:

- Two migration sets, same logical sequence: `server/crates/db-sqlite/migrations/` and `server/crates/db-postgres/migrations/` — **every schema change lands in both backends in the same PR**.
- Naming: `NNNN_short_description.sql`, zero-padded, identical numbering across both backends. Determine `NNNN` by listing both directories and taking max+1 (they must agree).
- Forward-only: no down migrations; never edit an applied migration — fix forward.
- Dialect-idiomatic SQL: Postgres — `TIMESTAMPTZ`/`INET`/`JSONB`, partial and composite indexes, triggers for DB-level invariants; SQLite — `STRICT` tables where practical, `TEXT` RFC3339 timestamps, `FTS5` with sync triggers.
- No seed/test data in migrations — fixtures belong to tests.

Steps:

1. List both migration directories, verify numbering is in sync, compute the next `NNNN`.
2. Write both files with dialect-appropriate SQL for the requested change.
3. Migrations apply at startup via `sqlx::migrate!` — there is no manual apply step; verification is running the tests: `cd server && cargo test --workspace` (add `PUB_TEST_POSTGRES_URL` for the Postgres leg — `/db-up` first).
4. Remind: repository contract tests exercising the new schema must cover both dialects.
