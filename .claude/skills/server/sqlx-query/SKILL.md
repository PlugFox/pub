---
name: sqlx-query
description: Write a DB query or repository method in the pub server — runtime sqlx (no query! macros, no .sqlx cache), dual-dialect SQLite + Postgres behind core traits, contract-tested in db-tests. Use when adding or changing a query, repository method, or row mapping.
---

# SQLx Queries & Repositories (pub server)

Source: ported from foxic's `server/sqlx-query` skill — and inverted: foxic mandates compile-time `query!` macros with a committed `.sqlx/` cache; pub deliberately does not use either.

## Runtime queries — deliberate, documented deviation

Pub uses runtime `sqlx::query` / `sqlx::query_as` with explicit `#[derive(sqlx::FromRow)]` row structs. **No `query!` macro family, no `.sqlx/` offline cache, no `cargo sqlx prepare`.** The dual-backend prepare ceremony (per-crate `sqlx.toml`, per-backend regeneration, version-coupled metadata) outweighs the benefit until the sqlx 0.9 CLI workflow settles; dynamic filter queries couldn't use macros anyway. Full rationale: crate docs at the top of `server/crates/db-sqlite/src/lib.rs` (this consciously deviates from the "macros where possible" line in [docs/rules/rust.md](../../../../docs/rules/rust.md) and decision 02). Correctness is carried by the shared contract suite instead. Do not reintroduce macros or a `.sqlx` cache.

## The boundary (decision 02)

Repository traits live in `pub_core::traits`; implementations in `server/crates/db-sqlite/src/repo/` and `db-postgres/src/repo/`. **The API layer sees only core traits and domain structs — never sqlx rows or types.** `AppState` carries `Arc<dyn Trait>` bundles (`Repositories`); backend selection is runtime config, never cargo features.

Adding a repository method touches four places in one PR:

1. trait method in `core`,
2. SQLite implementation,
3. Postgres implementation,
4. contract coverage in `db-tests`.

## Query idioms — mirror an existing file (e.g. `repo/tokens.rs` in both crates)

- Const column list + the crate-local `q!` macro (`AssertSqlSafe(format!(…))`): **const fragments only** (column lists, table names) enter the SQL text; every dynamic value travels through `.bind()`. User input never enters the SQL string.
- Placeholders: `?` on SQLite, `$1, $2, …` on Postgres.
- Row mapping: `#[derive(sqlx::FromRow)] struct XRow` + `TryFrom<XRow> for DomainType`. Rows that fail to parse are corruption → `Error::Database`, never `Error::Invalid`.
- Error helpers in `repo/mod.rs`: `db_err` for reads; `write_err(err, conflict_msg, fk_what)` maps unique violations → `Conflict` and FK violations → `NotFound`.
- `fetch_optional` for "may not exist"; `RETURNING {COLS}` on INSERT instead of a follow-up SELECT; `rows_affected()` to detect no-op updates (then distinguish idempotent vs `NotFound`, see `TokenRepo::revoke`).
- Dynamic filters: `sqlx::QueryBuilder` — `.push()` const SQL, `.push_bind()` values (see `repo/audit.rs::list`).
- Pagination is keyset-only (no OFFSET, [docs/rules/rust.md](../../../../docs/rules/rust.md)): `AND id < $cursor ORDER BY id DESC LIMIT n+1`, fetch limit+1 to compute `has_more`, return `Page { items, cursor, has_more }`. Malformed cursor → `Error::Invalid`.
- Transactions for atomic multi-step writes; the executor slot takes `&mut *tx`.

## Keep each dialect idiomatic

SQLite side:

- Ids as `TEXT` (`id.to_string()`); timestamps through `ts(now)` / `parse_ts` — fixed-width RFC3339 UTC so SQL string comparison equals time comparison.
- Single writer: transactions + unique indexes backstop read-then-write sections; no row locks.

Postgres side:

- Ids bound natively as `Uuid` (`*id.as_uuid()`); timestamps bound/read as `DateTime<Utc>`.
- `JSONB`: write `$n::jsonb` binding TEXT, read `col::text AS col` — keeps serde encodings byte-identical across backends without extra sqlx type features.
- `INET`: write `$n::inet`, read `host(col)` — a bare `::text` cast appends `/32`/`/128`. Classic contract-suite trap.
- Concurrent writers: read-then-write sections take `SELECT … FOR UPDATE` on their serialization anchor (org row, invitation row, session row — see `db-postgres/src/repo/mod.rs` docs).
- `version_sort` ordering relies on the schema's `COLLATE "C"` — bytewise comparison is what makes lexicographic order equal semver precedence.

## Contract tests (db-tests)

`server/crates/db-tests/src/contract.rs` holds 26 shared contract functions driven through the plain `Repositories` bundle — the suite never sees sqlx or backend types. `tests/sqlite.rs` runs every function on a fresh `:memory:` DB (every local `cargo test`); `tests/postgres.rs` runs the same on a throwaway per-test database, gated at runtime on `PUB_TEST_POSTGRES_URL` (no `#[ignore]` — CI enables it by exporting the variable).

- **Every new repository method gets contract coverage.** Corner cases are first-class: expired/garbage input, malformed cursors, boundary sizes, idempotency.
- Security-relevant behavior names the S-xx id in the test name (`token_repo_contract_s13`).
- A new contract function needs its `#[tokio::test]` wrapper in **both** `tests/sqlite.rs` and `tests/postgres.rs`.
- Cross-dialect traps the suite exists to catch: INET netmask formatting, C-collation semver ordering, RFC3339 fixed-width round-trips, boolean `0/1` vs `TRUE`.

Verify: `/server-check` (`cd server && cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test --workspace`). Postgres leg: `/db-up`, then export `PUB_TEST_POSTGRES_URL`.

## Related

- [add-migration](../add-migration/SKILL.md) — paired dialect migrations for new tables/columns
- [postgres-optimization](../postgres-optimization/SKILL.md) — EXPLAIN, indexes, N+1
- [docs/decisions.md](../../../../docs/decisions.md) (decision 02) · [docs/rules/rust.md](../../../../docs/rules/rust.md) · [docs/rules/migrations.md](../../../../docs/rules/migrations.md)
