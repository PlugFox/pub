---
name: postgres-optimization
description: Tune Postgres queries and indexes in the pub server — EXPLAIN (ANALYZE, BUFFERS), the right (partial) indexes, N+1, keyset pagination, locks — without breaking the SQLite twin or the contract suite. Use when a query is slow or a migration touches indexes.
---

# Postgres Optimization (pub server)

Source: ported from foxic's `server/postgres-optimization` skill, itself adapted from [github/awesome-copilot — postgresql-optimization](https://skills.sh/github/awesome-copilot/postgresql-optimization) and the [Postgres performance tips](https://www.postgresql.org/docs/current/performance-tips.html); dual-dialect caveats added for pub. Dev target is Postgres 17 (`docker/docker-compose.yml`).

## The dual-dialect rule (read this first)

Every repository query has a SQLite twin, and both run the shared contract suite in `server/crates/db-tests`. An optimization is only done when:

- the Postgres SQL stays behind the same `core` trait with unchanged semantics,
- the SQLite implementation still returns the same domain results (its own idiomatic SQL — it does not need the same plan, only the same answers),
- `cargo test --workspace` is green, including the Postgres leg (`/db-up`, export `PUB_TEST_POSTGRES_URL`).

Postgres-only features (`pg_trgm`, generated tsvector, `FOR UPDATE`, partial-index tricks) are fine **inside** `db-postgres` — that is the point of decision 02 — but never let them leak into trait signatures or change observable behavior.

## Investigate before optimizing

- Start with `EXPLAIN (ANALYZE, BUFFERS)` on a realistic dataset. "It's slow" is not a diagnosis.
  ```bash
  docker compose -f docker/docker-compose.yml exec pg psql -U pub -d pub \
    -c "EXPLAIN (ANALYZE, BUFFERS) SELECT ...;"
  ```
- Read top-down. Large `Seq Scan` on a filtered table, large `Rows Removed by Filter`, or a `Nested Loop` with a high outer row count → index-missing smell.
- `Buffers: shared read=N` is cold-cache disk; `shared hit=N` is memory. Re-run to see warm-cache cost.
- `actual rows` vs `estimated rows` off by >10× → stale stats (`ANALYZE <table>`) or a hard-to-estimate predicate (extended statistics).

## Indexing

- Match the WHERE / JOIN / ORDER BY columns, in that column order. `(package_id, version_sort, id)` serves the version-listing hot path exactly like `versions_listing_idx` does.
- **Partial indexes must match the soft-delete/status predicate the query uses** ([docs/rules/migrations.md](../../../../docs/rules/migrations.md)): `WHERE NOT tombstone`, `WHERE visibility = 'public' AND NOT unlisted`. The SQLite twin spells the same predicate as `tombstone = 0`. And know the exceptions: `versions_package_version_key` is deliberately NOT partial — burned version numbers must stay unique across tombstones (decision 06, S-18).
- Expression / generated data: pub prefers a generated column (the 0007 tsvector) over expression indexes — no drift, one write path.
- Covering (`INCLUDE`) to avoid heap lookups when a hot query always reads the same few extra columns.
- Ordering keys that must sort bytewise carry `COLLATE "C"` in the schema (`version_sort`); an "optimized" ORDER BY that drops it returns wrong resolution order, not an error.
- Avoid over-indexing: every index costs writes, WAL, vacuum. Drop candidates show `pg_stat_user_indexes.idx_scan = 0`.

## Common bad patterns

- **N+1**: `for id in ids { SELECT … WHERE id = $1 }`. Fix: `WHERE id = ANY($1::uuid[])` or a JOIN. (SQLite twin: `QueryBuilder` + `IN (…)` with pushed binds.)
- **`SELECT *`** — the repos use const `COLS` lists for a reason; name columns, keep covering indexes effective.
- **OFFSET pagination** — banned repo-wide anyway ([docs/rules/rust.md](../../../../docs/rules/rust.md)): keyset only, `WHERE id < $cursor ORDER BY id DESC LIMIT n+1`, `Page { items, cursor, has_more }` (see `repo/audit.rs::list`).
- **`COUNT(*)` on big tables** for UI badges — use `pg_class.reltuples` estimates or skip the count.
- **`LIKE '%foo%'`** can't use a btree. Pub's search already answers this: `pg_trgm` GIN + `similarity()` for fuzzy name match, tsvector for full text (decision 11, migration 0007). Don't bolt a second mechanism next to it.
- **`NOT IN (subquery)`** with nullable columns — use `NOT EXISTS`.
- **Functions on indexed columns**: `WHERE date(created_at) = $1` → rewrite as a range.

## Writes / locks

- Batch inserts: multi-row `VALUES` or `UNNEST($1::uuid[], …)` — one round trip. The SQLite twin batches with `QueryBuilder::push_values`.
- Upserts: `ON CONFLICT … DO UPDATE` — atomic, no double round trip.
- Row locks: follow the existing pattern — `SELECT … FOR UPDATE` only on the **serialization anchor** (org row, invitation row, session row; `db-postgres/src/repo/mod.rs` docs), short transactions, no I/O between lock and commit. `FOR UPDATE SKIP LOCKED` for queue-shaped work.
- Bulk updates: `UPDATE … WHERE id = ANY($1::uuid[])`, not a loop.

## Index/DDL changes are migrations

Any new index lands as a **paired** migration (both dialects, same NNNN — see [add-migration](../add-migration/SKILL.md)). Migrations run at startup inside `sqlx::migrate!` transactions; `CREATE INDEX CONCURRENTLY` cannot run in a transaction — it needs its own migration file starting with sqlx's `-- no-transaction` marker, and matters only for already-large deployed tables.

## Related

- [sqlx-query](../sqlx-query/SKILL.md) — runtime query idioms, repository boundary, contract tests
- [add-migration](../add-migration/SKILL.md) — paired dialect migrations
- [docs/rules/migrations.md](../../../../docs/rules/migrations.md) · [docs/rules/rust.md](../../../../docs/rules/rust.md) · [docs/decisions.md](../../../../docs/decisions.md)
