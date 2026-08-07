//! Runs the shared repository contract suite against SQLite `:memory:` — the everyday local
//! backend (docs/rules/rust.md: no containers locally). Each test gets a fresh migrated
//! database, so scenarios can never bleed into one another.

use pub_config::{DatabaseConfig, DatabaseKind};
use pub_core::traits::Repositories;
use pub_db_sqlite::SqliteDb;

async fn fresh_repos() -> Repositories {
    let cfg =
        DatabaseConfig { kind: DatabaseKind::Sqlite, url: None, path: ":memory:".to_owned(), ..Default::default() };
    let db = SqliteDb::connect(&cfg).await.expect("connect :memory:");
    db.run_migrations().await.expect("migrate");
    db.repositories()
}

#[tokio::test]
async fn user_repo_contract() {
    pub_db_tests::contract::user_repo(&fresh_repos().await).await;
}

#[tokio::test]
async fn credential_repo_contract() {
    pub_db_tests::contract::credential_repo(&fresh_repos().await).await;
}

#[tokio::test]
async fn second_factor_contract_s05() {
    pub_db_tests::contract::second_factor(&fresh_repos().await).await;
}

#[tokio::test]
async fn org_repo_contract() {
    pub_db_tests::contract::org_repo(&fresh_repos().await).await;
}

#[tokio::test]
async fn invitations_contract() {
    pub_db_tests::contract::invitations(&fresh_repos().await).await;
}

#[tokio::test]
async fn session_repo_contract_s08_s09_s10() {
    pub_db_tests::contract::session_repo(&fresh_repos().await).await;
}

#[tokio::test]
async fn token_repo_contract_s13() {
    pub_db_tests::contract::token_repo(&fresh_repos().await).await;
}

#[tokio::test]
async fn audit_repo_contract_s22() {
    pub_db_tests::contract::audit_repo(&fresh_repos().await).await;
}

#[tokio::test]
async fn settings_repo_contract() {
    pub_db_tests::contract::settings_repo(&fresh_repos().await).await;
}

#[tokio::test]
async fn package_repo_contract() {
    pub_db_tests::contract::package_repo(&fresh_repos().await).await;
}

#[tokio::test]
async fn version_ordering_contract() {
    pub_db_tests::contract::version_ordering(&fresh_repos().await).await;
}

#[tokio::test]
async fn publish_invariants_contract_s18() {
    pub_db_tests::contract::publish_invariants(&fresh_repos().await).await;
}

#[tokio::test]
async fn resolve_visibility_contract_s04() {
    pub_db_tests::contract::resolve_visibility(&fresh_repos().await).await;
}

#[tokio::test]
async fn resolve_in_base_scope_contract_decision01() {
    pub_db_tests::contract::resolve_in_base_scope(&fresh_repos().await).await;
}

#[tokio::test]
async fn upstream_repo_contract_s19() {
    pub_db_tests::contract::upstream_repo(&fresh_repos().await).await;
}

#[tokio::test]
async fn upstream_mirror_reads_contract() {
    pub_db_tests::contract::upstream_mirror_reads(&fresh_repos().await).await;
}

#[tokio::test]
async fn supply_chain_registers_contract_s17_s19() {
    pub_db_tests::contract::supply_chain_registers(&fresh_repos().await).await;
}

#[tokio::test]
async fn job_repo_contract() {
    pub_db_tests::contract::job_repo(&fresh_repos().await).await;
}

#[tokio::test]
async fn package_search_contract_decision11() {
    pub_db_tests::contract::package_search(&fresh_repos().await).await;
}

#[tokio::test]
async fn search_visibility_contract_s04() {
    pub_db_tests::contract::search_visibility(&fresh_repos().await).await;
}

#[tokio::test]
async fn download_stats_contract() {
    pub_db_tests::contract::download_stats(&fresh_repos().await).await;
}

#[tokio::test]
async fn instance_admins_contract() {
    pub_db_tests::contract::instance_admins(&fresh_repos().await).await;
}

#[tokio::test]
async fn org_management_contract() {
    pub_db_tests::contract::org_management(&fresh_repos().await).await;
}

#[tokio::test]
async fn org_deletion_contract_s18() {
    pub_db_tests::contract::org_deletion(&fresh_repos().await).await;
}

#[tokio::test]
async fn package_transfer_and_stats_contract() {
    pub_db_tests::contract::package_transfer_and_stats(&fresh_repos().await).await;
}

#[tokio::test]
async fn notifications_contract_decision20() {
    pub_db_tests::contract::notifications(&fresh_repos().await).await;
}

#[tokio::test]
async fn job_queue_contract_s04_s31() {
    pub_db_tests::contract::job_queue(&fresh_repos().await).await;
}

/// Every statement the drain emits on **every tick** must be an index lookup (SF2).
///
/// Migration 0010 said it carried "partial indexes matching the predicates the repository
/// emits" and carried them for two of the four: retention and the depth gauges had none, and
/// both run every five seconds against a table that only grows — on SQLite the retention
/// `DELETE` is a write statement, so its scan holds the single write lock against every
/// concurrent publish and sign-in for as long as it takes. A query plan is the only thing that
/// can assert this: a missing index is green forever otherwise.
#[tokio::test]
async fn the_drains_per_tick_statements_are_index_lookups() {
    let cfg =
        DatabaseConfig { kind: DatabaseKind::Sqlite, url: None, path: ":memory:".to_owned(), ..Default::default() };
    let db = SqliteDb::connect(&cfg).await.expect("connect :memory:");
    db.run_migrations().await.expect("migrate");

    // `AssertSqlSafe` because the statement is composed here from literals in this file; there
    // is no value from anywhere else in it.
    let plan = async |sql: &str| -> String {
        let rows: Vec<(i64, i64, i64, String)> =
            sqlx::query_as(sqlx::AssertSqlSafe(format!("EXPLAIN QUERY PLAN {sql}")))
                .fetch_all(db.pool())
                .await
                .expect("explain");
        rows.into_iter().map(|row| row.3).collect::<Vec<_>>().join(" | ")
    };

    // Retention, once per state, per tick. The state is a literal in the repository precisely so
    // these partial indexes can be inferred; a bound parameter would plan as a full scan.
    for state in ["done", "suppressed", "dead"] {
        let retention =
            plan(&format!("DELETE FROM job_queue WHERE state = '{state}' AND updated_at < '2026-08-07T00:00:00Z'"))
                .await;
        assert!(
            retention.contains(&format!("job_queue_retention_{state}_idx")),
            "retention full-scans the table for {state} rows: {retention}"
        );
        assert!(!retention.contains("SCAN job_queue"), "{retention}");
    }

    // The depth gauges, once per tick.
    let depth =
        plan("SELECT kind, state, COUNT(*) AS count FROM job_queue GROUP BY kind, state ORDER BY kind, state").await;
    assert!(depth.contains("job_queue_depth_idx"), "the depth aggregate reads the whole table: {depth}");

    // The claim, which now orders by priority before the id.
    let claim = plan(
        "SELECT id FROM job_queue WHERE state = 'pending' AND run_after <= '2026-08-07T00:00:00Z' \
         AND kind IN ('mail.send') ORDER BY priority, id LIMIT 50",
    )
    .await;
    assert!(claim.contains("job_queue_claim_prio_idx"), "the claim full-scans the backlog: {claim}");

    // The lease reaper, once per tick.
    let reap = plan(
        "UPDATE job_queue SET state = 'pending' WHERE state = 'running' AND locked_until <= '2026-08-07T00:00:00Z'",
    )
    .await;
    assert!(reap.contains("job_queue_lease_idx"), "the reaper full-scans the table: {reap}");

    // And the constraint that makes the fan-out exactly once has to be an index, not a scan.
    let dedupe = plan(
        "SELECT id FROM notifications WHERE user_id = '01890000-0000-7000-8000-000000000000' \
         AND event_id = '01K0000000000000000000000A'",
    )
    .await;
    assert!(dedupe.contains("notifications_event_idx"), "the exactly-once conflict check is a scan: {dedupe}");
}
