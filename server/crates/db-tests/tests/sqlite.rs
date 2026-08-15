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
async fn supply_chain_register_pages_contract_s17b_s19b_s23b() {
    pub_db_tests::contract::supply_chain_register_pages(&fresh_repos().await).await;
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
async fn storage_quota_contract_s20_b() {
    pub_db_tests::contract::storage_quota(&fresh_repos().await).await;
}

#[tokio::test]
async fn notifications_contract_decision20() {
    pub_db_tests::contract::notifications(&fresh_repos().await).await;
}

#[tokio::test]
async fn job_queue_contract_s04_s31() {
    pub_db_tests::contract::job_queue(&fresh_repos().await).await;
}

#[tokio::test]
async fn retention_contract_s23_s22a() {
    pub_db_tests::contract::retention(&fresh_repos().await).await;
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

    // Retention, once per state, per pass of the lifecycle job. Two things about the shape below
    // are load-bearing and both changed in the wave that added decision 30:
    //
    //   * the delete is now bounded — `id IN (SELECT … LIMIT ?)` — so the statement whose plan
    //     matters is the inner SELECT, and a test still EXPLAINing the old bare DELETE would be
    //     asserting an index for a statement production no longer emits (D52's exact shape);
    //   * the timestamp is a **bind** now, not a literal. The state stays a literal precisely so
    //     these partial indexes can be inferred, and that distinction is the thing worth pinning:
    //     with the state bound too, SQLite cannot infer the partial index and this plans as a scan.
    for state in ["done", "suppressed", "dead"] {
        let retention = plan(&format!(
            "DELETE FROM job_queue WHERE id IN \
             (SELECT id FROM job_queue WHERE state = '{state}' AND updated_at < ? LIMIT ?)"
        ))
        .await;
        assert!(
            retention.contains(&format!("job_queue_retention_{state}_idx")),
            "retention full-scans the table for {state} rows: {retention}"
        );
        assert!(!retention.contains("SCAN job_queue"), "{retention}");
    }

    // The other five retention statements, which had no plan test at all. Each is a write, so an
    // unindexed one holds SQLite's single writer for the length of its scan — the failure class the
    // whole batching design exists to avoid, and one that is green forever without a plan.
    for (label, sql, index) in [
        (
            "sessions",
            "DELETE FROM sessions WHERE id IN (SELECT id FROM sessions WHERE last_seen_at < ? ORDER BY last_seen_at \
             LIMIT ?)",
            "sessions_last_seen_idx",
        ),
        (
            "invitations",
            "DELETE FROM invitations WHERE id IN (SELECT id FROM invitations \
             WHERE COALESCE(accepted_at, revoked_at, expires_at) < ? \
             ORDER BY COALESCE(accepted_at, revoked_at, expires_at) LIMIT ?)",
            "invitations_settled_idx",
        ),
        (
            "notifications",
            "DELETE FROM notifications WHERE id IN (SELECT id FROM notifications WHERE created_at < ? \
             ORDER BY created_at LIMIT ?)",
            "notifications_created_idx",
        ),
        (
            "audit_log",
            "DELETE FROM audit_log WHERE id IN (SELECT id FROM audit_log WHERE created_at < ? ORDER BY created_at \
             LIMIT ?)",
            "audit_created_idx",
        ),
        (
            "download_stats",
            "DELETE FROM download_stats WHERE (package_id, version_id, date) IN \
             (SELECT package_id, version_id, date FROM download_stats WHERE date < ? ORDER BY date LIMIT ?)",
            "download_stats_date_idx",
        ),
    ] {
        let purge = plan(sql).await;
        assert!(purge.contains(index), "{label} retention does not seek {index}: {purge}");
    }

    // The depth gauges, once per tick.
    let depth =
        plan("SELECT kind, state, COUNT(*) AS count FROM job_queue GROUP BY kind, state ORDER BY kind, state").await;
    assert!(depth.contains("job_queue_depth_idx"), "the depth aggregate reads the whole table: {depth}");

    // The claim, once per lane per pass. The index name is *not* the assertion — the wave
    // shipped a claim that used this very index and still read every pending row of each kind,
    // because `priority` sits between `kind` and `run_after`: with `priority` unconstrained
    // (`ORDER BY priority, id` over both lanes at once) the seek stops at the `kind` prefix and
    // `run_after` becomes a post-filter, measured at 6.3 ms against 0.007 ms on a 200k-row
    // backlog a relay outage had backed off into the future — per claim, inside a write
    // statement, up to 64 times a tick. What the equality on `priority` buys is the *columns
    // the seek can use*, so that is what this asserts.
    let claim = plan(
        "SELECT id FROM job_queue WHERE state = 'pending' AND priority = 0 \
         AND run_after <= '2026-08-07T00:00:00Z' AND kind IN ('notification.fanout', 'mail.send') \
         ORDER BY run_after, id LIMIT 8",
    )
    .await;
    assert!(claim.contains("job_queue_claim_prio_idx"), "the claim full-scans the backlog: {claim}");
    for column in ["kind=?", "priority=?", "run_after<"] {
        assert!(
            claim.contains(column),
            "the claim seek does not bound {column}, so it reads the whole pending partition: {claim}"
        );
    }

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

/// **S-20.b.** The quota's usage read seeks two covering indexes instead of reading version rows.
///
/// This runs on the publish path — twice per publish, per decision 32's two checkpoints — so an
/// org with a large version history must not pay a scan of `versions` for it. What makes that
/// affordable is `versions_org_bytes_idx (package_id, archive_size) WHERE tombstone = 0` from
/// migration 0014: `archive_size` is in the index because it is the column being summed, so the
/// aggregate never touches a table row.
///
/// Two things about the shape of this test are deliberate, both from [D52](../../../../docs/roadmap.md):
///
///   * the SQL is **read from the repository** (`SqlitePackageRepo::ORG_STORAGE_BYTES_SQL`), not
///     copied into this file, so the text under test cannot drift from the text production emits;
///   * the assertion is on the **seek's usable columns**, not on an index name. A name-only
///     assertion passes while the statement scans — that is exactly how the job-queue claim
///     shipped green while reading every pending row.
#[tokio::test]
async fn s20_b_the_org_storage_sum_seeks_instead_of_scanning_versions() {
    let cfg =
        DatabaseConfig { kind: DatabaseKind::Sqlite, url: None, path: ":memory:".to_owned(), ..Default::default() };
    let db = SqliteDb::connect(&cfg).await.expect("connect :memory:");
    db.run_migrations().await.expect("migrate");

    // `AssertSqlSafe`: the statement comes from the repository crate and carries no value from
    // anywhere else; the org id below still travels as a bind, exactly as in production.
    let rows: Vec<(i64, i64, i64, String)> = sqlx::query_as(sqlx::AssertSqlSafe(format!(
        "EXPLAIN QUERY PLAN {}",
        pub_db_sqlite::repo::SqlitePackageRepo::ORG_STORAGE_BYTES_SQL
    )))
    .bind("01890000-0000-7000-8000-000000000000")
    .fetch_all(db.pool())
    .await
    .expect("explain");
    let plan = rows.into_iter().map(|row| row.3).collect::<Vec<_>>().join(" | ");

    // Neither side reads a table row.
    assert!(!plan.contains("SCAN versions"), "the quota sum scans every version on the instance: {plan}");
    assert!(!plan.contains("SCAN packages"), "the quota sum scans every package on the instance: {plan}");
    assert!(plan.contains("packages_org_idx (org_id=?)"), "the org's package list is not a seek: {plan}");
    // The load-bearing assertion, and all three parts of it are separate claims: the seek is into
    // the 0014 index, it is **bounded by `package_id`** (which is why the index leads with it),
    // and it is **covering** (which is why `archive_size` is in it at all).
    //
    // The last part is the one a weaker test would miss, and it was demonstrated rather than
    // assumed: with 0014's index dropped this plans as
    // `SEARCH v USING INDEX versions_listing_idx (package_id=?)` — still a seek, still no "SCAN",
    // so both assertions above stay green while every live version row of the org is fetched off
    // disk to read one integer out of it.
    assert!(
        plan.contains("COVERING INDEX versions_org_bytes_idx (package_id=?)"),
        "the sum is not an index-only seek bounded by package_id — it is reading version rows: {plan}"
    );

    // The per-**package** sum the transfer guard reads (S-20.b) needs **no index of its own**:
    // `versions_org_bytes_idx` already leads on `package_id` and already carries `archive_size`,
    // so it is the same covering seek with the `packages` half of the join removed. Asserted
    // rather than reasoned about, because "the index we have happens to serve it" is exactly the
    // claim that stops being true when somebody reorders the index columns.
    let rows: Vec<(i64, i64, i64, String)> = sqlx::query_as(sqlx::AssertSqlSafe(format!(
        "EXPLAIN QUERY PLAN {}",
        pub_db_sqlite::repo::SqlitePackageRepo::PACKAGE_STORAGE_BYTES_SQL
    )))
    .bind("01890000-0000-7000-8000-000000000001")
    .fetch_all(db.pool())
    .await
    .expect("explain");
    let plan = rows.into_iter().map(|row| row.3).collect::<Vec<_>>().join(" | ");
    assert!(!plan.contains("SCAN versions"), "the per-package sum scans every version on the instance: {plan}");
    assert!(
        plan.contains("COVERING INDEX versions_org_bytes_idx (package_id=?)"),
        "the per-package sum needs no new index, but it does need this one to cover it: {plan}"
    );
}

/// The blob collector's reference check must be an index seek on **both** registers
/// ([decision 31](../../../../docs/decisions.md)).
///
/// This is the query that decides whether bytes may be deleted, asked once per batch of
/// candidate keys, and each half runs against a table that only grows: `versions` on a busy
/// registry, `upstream_versions` on a mirror (pub.dev is ~60 000 packages). The batching from
/// decision 31 removed two round trips *per object*; a sequential scan inside each batch would
/// have put the cost straight back, one layer down and invisible to every test that only checks
/// the answer.
///
/// Both indexes are partial, and the literal in the statement is what lets SQLite infer them —
/// exactly the bind-versus-literal distinction the drain's plan test pins above. The repository
/// writes `tombstone = 0` and `cached = 1` as literals for this reason.
#[tokio::test]
async fn the_blob_collectors_reference_check_is_an_index_lookup() {
    let cfg =
        DatabaseConfig { kind: DatabaseKind::Sqlite, url: None, path: ":memory:".to_owned(), ..Default::default() };
    let db = SqliteDb::connect(&cfg).await.expect("connect :memory:");
    db.run_migrations().await.expect("migrate");

    // `AssertSqlSafe`: composed here from literals in this file, no value from anywhere else.
    let plan = async |sql: &str| -> String {
        let rows: Vec<(i64, i64, i64, String)> =
            sqlx::query_as(sqlx::AssertSqlSafe(format!("EXPLAIN QUERY PLAN {sql}")))
                .fetch_all(db.pool())
                .await
                .expect("explain");
        rows.into_iter().map(|row| row.3).collect::<Vec<_>>().join(" | ")
    };

    let live =
        plan("SELECT DISTINCT archive_sha256 FROM versions WHERE tombstone = 0 AND archive_sha256 IN (?, ?)").await;
    assert!(live.contains("versions_sha256_idx"), "the live-reference check scans `versions`: {live}");
    assert!(!live.contains("SCAN versions"), "{live}");

    let cached =
        plan("SELECT DISTINCT archive_sha256 FROM upstream_versions WHERE cached = 1 AND archive_sha256 IN (?, ?)")
            .await;
    assert!(
        cached.contains("upstream_versions_sha256_idx"),
        "the proxy-cache reference check scans `upstream_versions`: {cached}"
    );
    assert!(!cached.contains("SCAN upstream_versions"), "{cached}");
}

/// **S-17.b / S-19.b / S-23.b.** The registers' page walks and their two retention deletes seek.
///
/// The registers are anonymous-unreachable — every statement here is behind an instance-admin
/// route or the retention job — so this is not about a hot path. It is about the shape a keyset
/// walk needs to *be correct*: the whole primary key in the ORDER BY, in one direction, over an
/// index that carries it. A walk whose tie-break columns are a post-filter still returns the
/// right rows on a small table and starts skipping them exactly when the register fills up.
///
/// The SQL is read from the repository (`quarantine_page_sql` / `shadowing_page_sql`), never
/// copied here, and the assertions name the **seek's usable columns** rather than an index —
/// both per [D52](../../../../docs/roadmap.md) and the working agreement above it.
#[tokio::test]
async fn s17b_s19b_the_register_pages_and_purges_seek() {
    let cfg =
        DatabaseConfig { kind: DatabaseKind::Sqlite, url: None, path: ":memory:".to_owned(), ..Default::default() };
    let db = SqliteDb::connect(&cfg).await.expect("connect :memory:");
    db.run_migrations().await.expect("migrate");

    // `AssertSqlSafe`: every statement below comes from the repository crate or from literals in
    // this file, and the cursor components still travel as binds exactly as in production.
    let plan = async |sql: &str| -> String {
        let rows: Vec<(i64, i64, i64, String)> =
            sqlx::query_as(sqlx::AssertSqlSafe(format!("EXPLAIN QUERY PLAN {sql}")))
                .fetch_all(db.pool())
                .await
                .expect("explain");
        rows.into_iter().map(|row| row.3).collect::<Vec<_>>().join(" | ")
    };

    // The first page of each register: no predicate at all, so the only thing an index can buy
    // is the ordering — and that is the whole point, because without it every page sorts the
    // table.
    let first = plan(pub_db_sqlite::repo::quarantine_page_sql(false)).await;
    assert!(first.contains("upstream_quarantine_page_idx"), "the first quarantine page sorts the table: {first}");
    assert!(!first.contains("TEMP B-TREE"), "the newest-first order must come from the index, not a sort: {first}");

    // The continuation: the row-value comparison has to become a seek, not a filter over a scan.
    let next = plan(pub_db_sqlite::repo::quarantine_page_sql(true)).await;
    assert!(next.contains("upstream_quarantine_page_idx"), "the quarantine walk scans: {next}");
    // The seek's usable columns, spelled the way SQLite renders a row-value seek: all four
    // inside the parentheses. A plan that sought on `last_seen_at` alone and post-filtered the
    // rest would still be an index search and still be wrong — that is the whole reason the
    // assertion is on the columns and not on the index name.
    assert!(
        next.contains("(last_seen_at,format,name,version)<"),
        "the keyset is a post-filter, so the walk re-reads the tied rows on every page: {next}"
    );
    assert!(!next.contains("TEMP B-TREE"), "{next}");

    // All three shadowing slices, paged. The active one must reach the *partial* index — that is
    // what keeps "what is asking for attention" proportional to the open alarms rather than to
    // every alarm ever raised.
    for (active, index) in [
        (None, "shadowing_alarms_page_idx"),
        (Some(true), "shadowing_alarms_active_idx"),
        (Some(false), "shadowing_alarms_page_idx"),
    ] {
        let page = plan(pub_db_sqlite::repo::shadowing_page_sql(active, true)).await;
        assert!(page.contains(index), "the {active:?} shadowing slice does not seek {index}: {page}");
        assert!(
            page.contains("(last_seen_at,format,name)<"),
            "the {active:?} keyset is a post-filter over the tie-break columns: {page}"
        );
        assert!(!page.contains("TEMP B-TREE"), "the {active:?} slice sorts: {page}");
    }

    // The two retention deletes. Each is a write, so an unindexed one holds SQLite's single
    // writer for its whole scan — the failure class every bounded delete in this product exists
    // to avoid.
    let quarantine_purge = plan(
        "DELETE FROM upstream_quarantine WHERE (format, name, version) IN \
         (SELECT format, name, version FROM upstream_quarantine WHERE last_seen_at < ? ORDER BY last_seen_at LIMIT ?)",
    )
    .await;
    assert!(
        quarantine_purge.contains("upstream_quarantine_page_idx"),
        "quarantine retention full-scans the register: {quarantine_purge}"
    );

    // The shadowing purge must seek the **partial** index, because its `IS NOT NULL` half is what
    // makes an active alarm undeletable. A plan that reached the unfiltered index here would be a
    // plan for a statement that had dropped that half.
    let shadowing_purge = plan(
        "DELETE FROM shadowing_alarms WHERE (format, name) IN \
         (SELECT format, name FROM shadowing_alarms \
          WHERE acknowledged_at IS NOT NULL AND acknowledged_at < ? ORDER BY acknowledged_at LIMIT ?)",
    )
    .await;
    assert!(
        shadowing_purge.contains("shadowing_alarms_ack_idx"),
        "shadowing retention does not seek the acknowledged-only index: {shadowing_purge}"
    );
}
