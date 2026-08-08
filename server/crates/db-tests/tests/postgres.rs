//! Runs the shared repository contract suite against PostgreSQL — the CI backend matrix leg
//! (docs/architecture.md). Gated **at runtime** by the `PUB_TEST_POSTGRES_URL` environment
//! variable: when it is unset every test returns early after a skip note on stderr. No
//! `#[ignore]` attributes — CI enables the suite purely by exporting the variable.
//!
//! Each test creates a throwaway, uniquely named database on the target server, migrates it,
//! runs one contract function, and drops the database again. On a failed assertion the
//! `pub_contract_*` database is left behind for inspection — free in CI (the service
//! container is ephemeral); locally drop leftovers manually.

use std::str::FromStr as _;

use pub_core::traits::Repositories;
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use sqlx::{AssertSqlSafe, Connection as _, PgConnection, PgPool};

/// Environment variable carrying the admin connection URL of the test server.
const URL_ENV: &str = "PUB_TEST_POSTGRES_URL";

/// One throwaway database on the configured server.
struct TestDb {
    admin_url: String,
    name: String,
    pool: PgPool,
}

impl TestDb {
    /// Creates and migrates a fresh uniquely named database; `None` (after a skip note on
    /// stderr) when [`URL_ENV`] is not set.
    async fn create(test: &str) -> Option<Self> {
        let Ok(admin_url) = std::env::var(URL_ENV) else {
            eprintln!("skipping {test}: {URL_ENV} is not set (the postgres contract suite runs in CI)");
            return None;
        };
        // Unique and SQL-safe by construction: a dash-stripped UUID v7 is `[0-9a-f]{32}`.
        let name = format!("pub_contract_{}", pub_core::UserId::new().to_string().replace('-', ""));

        let mut admin = PgConnection::connect(&admin_url).await.expect("connect to postgres admin database");
        sqlx::query(AssertSqlSafe(format!("CREATE DATABASE \"{name}\"")))
            .execute(&mut admin)
            .await
            .expect("create throwaway database");
        admin.close().await.expect("close admin connection");

        let options = PgConnectOptions::from_str(&admin_url).expect("parse postgres url").database(&name);
        let pool =
            PgPoolOptions::new().max_connections(5).connect_with(options).await.expect("connect throwaway database");
        pub_db_postgres::MIGRATOR.run(&pool).await.expect("migrate throwaway database");
        Some(Self { admin_url, name, pool })
    }

    /// The repository bundle under test.
    fn repos(&self) -> Repositories {
        pub_db_postgres::repo::repositories(self.pool.clone())
    }

    /// Drops the throwaway database — reached only when the contract assertions passed.
    async fn cleanup(self) {
        self.pool.close().await;
        let mut admin = PgConnection::connect(&self.admin_url).await.expect("connect to postgres admin database");
        sqlx::query(AssertSqlSafe(format!("DROP DATABASE \"{}\" WITH (FORCE)", self.name)))
            .execute(&mut admin)
            .await
            .expect("drop throwaway database");
        admin.close().await.expect("close admin connection");
    }
}

#[tokio::test]
async fn user_repo_contract() {
    let Some(db) = TestDb::create("user_repo_contract").await else { return };
    pub_db_tests::contract::user_repo(&db.repos()).await;
    db.cleanup().await;
}

#[tokio::test]
async fn credential_repo_contract() {
    let Some(db) = TestDb::create("credential_repo_contract").await else { return };
    pub_db_tests::contract::credential_repo(&db.repos()).await;
    db.cleanup().await;
}

#[tokio::test]
async fn second_factor_contract_s05() {
    let Some(db) = TestDb::create("second_factor_contract_s05").await else { return };
    pub_db_tests::contract::second_factor(&db.repos()).await;
    db.cleanup().await;
}

#[tokio::test]
async fn org_repo_contract() {
    let Some(db) = TestDb::create("org_repo_contract").await else { return };
    pub_db_tests::contract::org_repo(&db.repos()).await;
    db.cleanup().await;
}

#[tokio::test]
async fn invitations_contract() {
    let Some(db) = TestDb::create("invitations_contract").await else { return };
    pub_db_tests::contract::invitations(&db.repos()).await;
    db.cleanup().await;
}

#[tokio::test]
async fn session_repo_contract_s08_s09_s10() {
    let Some(db) = TestDb::create("session_repo_contract_s08_s09_s10").await else { return };
    pub_db_tests::contract::session_repo(&db.repos()).await;
    db.cleanup().await;
}

#[tokio::test]
async fn token_repo_contract_s13() {
    let Some(db) = TestDb::create("token_repo_contract_s13").await else { return };
    pub_db_tests::contract::token_repo(&db.repos()).await;
    db.cleanup().await;
}

#[tokio::test]
async fn audit_repo_contract_s22() {
    let Some(db) = TestDb::create("audit_repo_contract_s22").await else { return };
    pub_db_tests::contract::audit_repo(&db.repos()).await;
    db.cleanup().await;
}

#[tokio::test]
async fn settings_repo_contract() {
    let Some(db) = TestDb::create("settings_repo_contract").await else { return };
    pub_db_tests::contract::settings_repo(&db.repos()).await;
    db.cleanup().await;
}

#[tokio::test]
async fn package_repo_contract() {
    let Some(db) = TestDb::create("package_repo_contract").await else { return };
    pub_db_tests::contract::package_repo(&db.repos()).await;
    db.cleanup().await;
}

#[tokio::test]
async fn version_ordering_contract() {
    let Some(db) = TestDb::create("version_ordering_contract").await else { return };
    pub_db_tests::contract::version_ordering(&db.repos()).await;
    db.cleanup().await;
}

#[tokio::test]
async fn publish_invariants_contract_s18() {
    let Some(db) = TestDb::create("publish_invariants_contract_s18").await else { return };
    pub_db_tests::contract::publish_invariants(&db.repos()).await;
    db.cleanup().await;
}

#[tokio::test]
async fn resolve_visibility_contract_s04() {
    let Some(db) = TestDb::create("resolve_visibility_contract_s04").await else { return };
    pub_db_tests::contract::resolve_visibility(&db.repos()).await;
    db.cleanup().await;
}

#[tokio::test]
async fn resolve_in_base_scope_contract_decision01() {
    let Some(db) = TestDb::create("resolve_in_base_scope_contract_decision01").await else { return };
    pub_db_tests::contract::resolve_in_base_scope(&db.repos()).await;
    db.cleanup().await;
}

#[tokio::test]
async fn upstream_repo_contract_s19() {
    let Some(db) = TestDb::create("upstream_repo_contract_s19").await else { return };
    pub_db_tests::contract::upstream_repo(&db.repos()).await;
    db.cleanup().await;
}

#[tokio::test]
async fn upstream_mirror_reads_contract() {
    let Some(db) = TestDb::create("upstream_mirror_reads_contract").await else { return };
    pub_db_tests::contract::upstream_mirror_reads(&db.repos()).await;
    db.cleanup().await;
}

#[tokio::test]
async fn supply_chain_registers_contract_s17_s19() {
    let Some(db) = TestDb::create("supply_chain_registers_contract_s17_s19").await else { return };
    pub_db_tests::contract::supply_chain_registers(&db.repos()).await;
    db.cleanup().await;
}

#[tokio::test]
async fn job_repo_contract() {
    let Some(db) = TestDb::create("job_repo_contract").await else { return };
    pub_db_tests::contract::job_repo(&db.repos()).await;
    db.cleanup().await;
}

#[tokio::test]
async fn package_search_contract_decision11() {
    let Some(db) = TestDb::create("package_search_contract_decision11").await else { return };
    pub_db_tests::contract::package_search(&db.repos()).await;
    db.cleanup().await;
}

#[tokio::test]
async fn search_visibility_contract_s04() {
    let Some(db) = TestDb::create("search_visibility_contract_s04").await else { return };
    pub_db_tests::contract::search_visibility(&db.repos()).await;
    db.cleanup().await;
}

#[tokio::test]
async fn download_stats_contract() {
    let Some(db) = TestDb::create("download_stats_contract").await else { return };
    pub_db_tests::contract::download_stats(&db.repos()).await;
    db.cleanup().await;
}

#[tokio::test]
async fn instance_admins_contract() {
    let Some(db) = TestDb::create("instance_admins_contract").await else { return };
    pub_db_tests::contract::instance_admins(&db.repos()).await;
    db.cleanup().await;
}

#[tokio::test]
async fn org_management_contract() {
    let Some(db) = TestDb::create("org_management_contract").await else { return };
    pub_db_tests::contract::org_management(&db.repos()).await;
    db.cleanup().await;
}

#[tokio::test]
async fn org_deletion_contract_s18() {
    let Some(db) = TestDb::create("org_deletion_contract_s18").await else { return };
    pub_db_tests::contract::org_deletion(&db.repos()).await;
    db.cleanup().await;
}

#[tokio::test]
async fn package_transfer_and_stats_contract() {
    let Some(db) = TestDb::create("package_transfer_and_stats_contract").await else { return };
    pub_db_tests::contract::package_transfer_and_stats(&db.repos()).await;
    db.cleanup().await;
}

#[tokio::test]
async fn notifications_contract_decision20() {
    let Some(db) = TestDb::create("notifications_contract_decision20").await else { return };
    pub_db_tests::contract::notifications(&db.repos()).await;
    db.cleanup().await;
}

#[tokio::test]
async fn job_queue_contract_s04_s31() {
    let Some(db) = TestDb::create("job_queue_contract_s04_s31").await else { return };
    pub_db_tests::contract::job_queue(&db.repos()).await;
    db.cleanup().await;
}

/// The indexes the drain's per-tick statements need exist on this dialect too (SF2).
///
/// The SQLite leg asserts query plans; here the assertion is that the paired migration actually
/// landed the same indexes, which is the failure mode a paired migration has: one dialect gets
/// the fix and the other quietly does not. An `EXPLAIN` against an empty table would prove
/// nothing — Postgres sequentially scans a table of eight rows whatever indexes exist.
#[tokio::test]
async fn the_drains_per_tick_indexes_exist() {
    let Some(db) = TestDb::create("the_drains_per_tick_indexes_exist").await else { return };
    let names: Vec<(String,)> = sqlx::query_as(
        "SELECT indexname::text FROM pg_indexes WHERE tablename IN ('job_queue', 'notifications') ORDER BY indexname",
    )
    .fetch_all(&db.pool)
    .await
    .expect("read pg_indexes");
    let names: Vec<String> = names.into_iter().map(|row| row.0).collect();
    for expected in [
        "job_queue_claim_prio_idx",
        "job_queue_retention_done_idx",
        "job_queue_retention_suppressed_idx",
        "job_queue_retention_dead_idx",
        "job_queue_depth_idx",
        "job_queue_lease_idx",
        "job_queue_dedupe_idx",
        "notifications_event_idx",
    ] {
        assert!(names.iter().any(|name| name == expected), "missing {expected}: {names:?}");
    }
    assert!(
        !names.iter().any(|name| name == "job_queue_claim_idx"),
        "the superseded claim index is still there, costing every enqueue a write for a plan nothing emits: {names:?}"
    );
    db.cleanup().await;
}

/// The claim's seek really uses `run_after`, on a backlog big enough for the planner to care.
///
/// The index name is not the property — the wave shipped a claim that used
/// `job_queue_claim_prio_idx` and still read every pending row of each kind, because `priority`
/// sits between `kind` and `run_after`: with `priority` unconstrained (`ORDER BY priority, id`
/// across both lanes) nothing can bound `run_after`, so it degrades to a filter. That is
/// invisible to `EXPLAIN` on an empty table and invisible to an index-name assertion, so this
/// one loads a backlog that a relay outage backed off into the future — the exact shape the
/// backoff ladder produces — and measures both statements. Numbers from the run this test was
/// written against, 20k pending rows: the lane form is an index-only scan reading 18 buffers;
/// the cross-lane form is a **sequential scan** the planner chose on cost, reading 301 buffers
/// and discarding 19 977 rows, inside a write statement that runs up to 64 times a tick.
#[tokio::test]
async fn the_claim_seeks_on_run_after_instead_of_filtering_the_whole_backlog() {
    let Some(db) = TestDb::create("the_claim_seeks_on_run_after").await else { return };
    // A pending backlog whose every row is backed off into the future, across both kinds and
    // both lanes: nothing here is claimable, which is what the claim has to discover cheaply.
    sqlx::query(
        "INSERT INTO job_queue (id, kind, payload, state, attempts, run_after, locked_until, dedupe_key, \
         last_error, created_at, updated_at, priority) \
         SELECT gen_random_uuid(), CASE WHEN i % 4 = 0 THEN 'notification.fanout' ELSE 'mail.send' END, \
         '{}'::jsonb, 'pending', 0, now() + make_interval(secs => (i % 3600) + 1), NULL, NULL, NULL, now(), now(), \
         CASE WHEN i % 3 = 0 THEN 0 ELSE 100 END FROM generate_series(1, 20000) AS i",
    )
    .execute(&db.pool)
    .await
    .expect("load the backlog");
    sqlx::query("ANALYZE job_queue").execute(&db.pool).await.expect("analyze");

    let explain = async |sql: &str| -> String {
        let rows: Vec<(String,)> = sqlx::query_as(AssertSqlSafe(format!("EXPLAIN (ANALYZE, BUFFERS) {sql}")))
            .fetch_all(&db.pool)
            .await
            .expect("explain");
        rows.into_iter().map(|row| row.0).collect::<Vec<_>>().join("\n")
    };
    // Total buffers touched, off the top node's own accounting.
    let buffers = |plan: &str| -> u64 {
        plan.lines()
            .find_map(|line| line.trim().strip_prefix("Buffers: shared hit="))
            .and_then(|rest| rest.split(|c: char| !c.is_ascii_digit()).next())
            .and_then(|digits| digits.parse().ok())
            .unwrap_or_else(|| panic!("no buffer accounting in the plan:\n{plan}"))
    };

    // What the repository emits: one lane at a time, ordered by the rest of the index.
    let lane = explain(
        "SELECT id FROM job_queue WHERE state = 'pending' AND priority = 0 AND run_after <= now() \
         AND kind = ANY(ARRAY['notification.fanout', 'mail.send']) ORDER BY run_after, id LIMIT 8",
    )
    .await;
    assert!(lane.contains("job_queue_claim_prio_idx"), "the claim does not use the claim index:\n{lane}");
    let cond = lane
        .lines()
        .find(|line| line.trim_start().starts_with("Index Cond:"))
        .unwrap_or_else(|| panic!("the claim is not an index scan at all:\n{lane}"));
    for column in ["kind", "priority", "run_after"] {
        assert!(
            cond.contains(column),
            "{column} is not part of the index condition, so the seek is not bounded by it: {cond}"
        );
    }

    // The shape it replaced, as the control: same index, same data, no equality on the lane.
    let cross = explain(
        "SELECT id FROM job_queue WHERE state = 'pending' AND run_after <= now() \
         AND kind = ANY(ARRAY['notification.fanout', 'mail.send']) ORDER BY priority, id LIMIT 8",
    )
    .await;
    assert!(
        buffers(&lane) * 5 < buffers(&cross),
        "the claim reads {} buffers against the unbounded form's {} — the seek is not paying for itself:\n{lane}\n{cross}",
        buffers(&lane),
        buffers(&cross)
    );
    db.cleanup().await;
}
