# Migration Rules

Two migration sets — `server/crates/db-postgres/migrations/` and `server/crates/db-sqlite/migrations/` — same logical sequence, dialect-idiomatic SQL. Run at startup via `sqlx::migrate!`.

- **Forward-only.** No down migrations. Never edit a migration that may have been applied anywhere; fix forward.
- Naming: `NNNN_short_description.sql`, zero-padded, identical logical numbering across both backends.
- **Every schema change lands in both backends in the same PR**, plus integration tests exercising the change on both.
- Postgres idioms: `TIMESTAMPTZ`, `INET`, `JSONB`, partial indexes matching soft-delete/status predicates, composite indexes for keyset pagination, triggers for DB-level invariants the app also checks (defense in depth).
- SQLite idioms: `STRICT` tables where practical, `TEXT` RFC3339 timestamps, `FTS5` virtual tables with sync triggers, single-writer assumptions documented.
- Audit table gets an INSERT-only role/grant on Postgres (S-22); SQLite enforces append-only in the repository implementation.
- **That grant survives S-23 retention, and the mechanism is a function rather than a widened grant.** `audit_log` is the one table the app role must delete from and may not: migration 0012 adds `pub_audit_prune(cutoff, batch)` as `SECURITY DEFINER` with a pinned `search_path`, owned by the migration role, and the app role holds only `EXECUTE`. The function refuses a cutoff newer than thirty days and a non-positive batch (in Postgres `LIMIT -1` is *unbounded*). If a future feature needs a privileged write on a table the app role is deliberately restricted from, this is the shape to copy — not `GRANT`, which would hand a code regression exactly the recent rows the restriction exists to protect ([S-22.a](../security.md#5-audit--abuse), [decision 30](../decisions.md#30--retention-one-window-per-table-a-delete-that-stays-bounded-and-a-privilege-that-survives-the-feature)).
- **Every retention delete is bounded and converges.** `DELETE … WHERE id IN (SELECT id … LIMIT :batch)` in both dialects, looped by the caller until a pass comes back short — never a bare `DELETE … WHERE <age>`. On SQLite an unbounded delete holds the process's single writer for its whole duration, and a hold past the busy timeout turns a concurrent publish-finalize or sign-in into `SQLITE_BUSY` instead of a wait. `DELETE … LIMIT` is not available: it needs a non-default SQLite build option.
- Seed/test data never lives in migrations — fixtures belong to tests.
