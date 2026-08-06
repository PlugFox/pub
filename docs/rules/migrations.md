# Migration Rules

Two migration sets — `server/crates/db-postgres/migrations/` and `server/crates/db-sqlite/migrations/` — same logical sequence, dialect-idiomatic SQL. Run at startup via `sqlx::migrate!`.

- **Forward-only.** No down migrations. Never edit a migration that may have been applied anywhere; fix forward.
- Naming: `NNNN_short_description.sql`, zero-padded, identical logical numbering across both backends.
- **Every schema change lands in both backends in the same PR**, plus integration tests exercising the change on both.
- Postgres idioms: `TIMESTAMPTZ`, `INET`, `JSONB`, partial indexes matching soft-delete/status predicates, composite indexes for keyset pagination, triggers for DB-level invariants the app also checks (defense in depth).
- SQLite idioms: `STRICT` tables where practical, `TEXT` RFC3339 timestamps, `FTS5` virtual tables with sync triggers, single-writer assumptions documented.
- Audit table gets an INSERT-only role/grant on Postgres (S-22); SQLite enforces append-only in the repository implementation.
- Seed/test data never lives in migrations — fixtures belong to tests.
