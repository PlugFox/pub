---
name: add-migration
description: Create a paired forward-only DB migration (SQLite + Postgres, same NNNN) for the pub registry schema. Use when asked to add a migration, change the schema, create a table, alter columns, or add an index.
---

# Add Migration (pub server)

Source: ported from foxic's `server/add-migration` skill; rewritten for pub's dual-dialect, forward-only model (foxic's timestamped `.up/.down` pairs, `sqlx migrate run`, and `.sqlx` refresh do not exist here).

**Read first**: [docs/rules/migrations.md](../../../../docs/rules/migrations.md) — normative. The `/new-migration` command ([.claude/commands/new-migration.md](../../../commands/new-migration.md)) walks these same steps.

## Model

- Two migration sets, same logical sequence: `server/crates/db-sqlite/migrations/` and `server/crates/db-postgres/migrations/`. **Every schema change lands in both backends in the same PR.**
- **Forward-only.** No `.down.sql` files exist anywhere. Never edit a migration that may have been applied — add a new one that fixes forward.
- Applied at startup via `sqlx::migrate!` (the `MIGRATOR` static in each db crate's `lib.rs`). There is no manual apply step and no migration CLI.
- Seed/test data never lives in migrations — fixtures belong to tests.

## Naming

`NNNN_short_description.sql`, zero-padded, identical number and description in both directories. Compute `NNNN` by listing both directories, verifying they agree, and taking max+1.

## Dialect idioms — write each side natively

The `0004_registry.sql` pair is the model example; `0007_search_and_stats.sql` shows the search split.

| Concept | Postgres | SQLite |
|---|---|---|
| Ids (UUID v7) | `UUID` | `TEXT` lowercase hyphenated |
| Timestamps | `TIMESTAMPTZ` | `TEXT` RFC3339 UTC, fixed-width `%.6fZ` (string order == time order) |
| Booleans | `BOOLEAN` | `INTEGER` + `CHECK (x IN (0, 1))` |
| JSON documents | `JSONB` | `TEXT` |
| Sizes / counters | `BIGINT` | `INTEGER` |
| Table hygiene | plain | `STRICT` where practical |
| Full-text search | generated `tsvector` + `pg_trgm` GIN | `FTS5` external-content table + sync triggers |
| Semver order key | `TEXT COLLATE "C"` (bytewise) | `TEXT` (default BINARY — never `NOCASE`) |
| IP addresses | `INET` | `TEXT` |
| Soft-delete partial index | `WHERE NOT tombstone` | `WHERE tombstone = 0` |

- Partial indexes must match the exact soft-delete/status predicates the queries use.
- Composite indexes for keyset-pagination hot paths, e.g. `(org_id, name, id)`.
- Postgres: triggers for DB-level invariants the app also checks (defense in depth). SQLite: document single-writer assumptions in a comment.
- Audit table stays INSERT-only: role/grant on Postgres (S-22); SQLite enforces append-only in the repository.
- Comment the WHY in the SQL — existing migrations cite decision numbers and S-xx ids; keep that up.

## Checklist

- [ ] Both files written; numbering identical and in sync.
- [ ] `migrator_contains_the_expected_migrations` test updated in **both** `server/crates/db-{sqlite,postgres}/src/lib.rs` — each asserts the exact version list.
- [ ] Repository code + contract tests in `server/crates/db-tests` exercise the new schema on both dialects.
- [ ] Verify: `cd server && cargo test --workspace` — the SQLite leg always runs; export `PUB_TEST_POSTGRES_URL` for the Postgres leg (`/db-up` first).
- [ ] No seed data; no edits to already-landed migrations.

## Common mistakes

- Copying Postgres SQL into the SQLite file — `STRICT` tables reject `TIMESTAMPTZ`, `BOOLEAN`, `JSONB`.
- Adding `COLLATE NOCASE` (SQLite) or losing `COLLATE "C"` (Postgres) on a `version_sort`-style key — semver precedence needs bytewise comparison; a folding collation silently reorders pre-releases.
- Forgetting the twin file or the `MIGRATOR` version-list tests → `cargo test` fails.
- Adding a `NOT NULL` column without a `DEFAULT` to a populated table.
- Writing a down migration — there is no such thing here.

## Related

- [sqlx-query](../sqlx-query/SKILL.md) — runtime query style, repository boundary, contract tests
- [postgres-optimization](../postgres-optimization/SKILL.md) — indexes, EXPLAIN, dual-dialect caveats
- [docs/rules/migrations.md](../../../../docs/rules/migrations.md) · [docs/decisions.md](../../../../docs/decisions.md) · [docs/security.md](../../../../docs/security.md)
