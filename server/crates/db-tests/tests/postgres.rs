//! Runs the shared repository contract suite against PostgreSQL — one leg of the backend
//! matrix ([decision 35](../../../../docs/decisions.md#35--backend-legs-that-fail-when-the-backend-is-absent-and-a-harness-that-admits-a-race)).
//!
//! Gated **at runtime** by `PUB_TEST_POSTGRES_URL`, and the gate fails closed: with neither
//! that variable nor `PUB_TEST_NO_POSTGRES` set, every test here panics naming both. Before
//! decision 35 the unset case returned early and reported `ok`, so a dead database and a
//! passing suite printed the same thing — 31 tests, 0.00 s, port 5432 closed. No `#[ignore]`
//! attributes: CI enables the suite purely by exporting the URL, and sets no opt-out.
//!
//! Each test creates a throwaway, uniquely named database on the target server, migrates it,
//! runs one contract function, and drops the database again. On a failed assertion the
//! `pub_contract_*` database is left behind for inspection — free in CI (the service
//! container is ephemeral); locally drop leftovers manually.

use std::str::FromStr as _;

use pub_core::traits::Repositories;
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use sqlx::{AssertSqlSafe, Connection as _, PgConnection, PgPool};

/// One throwaway database on the configured server.
struct TestDb {
    admin_url: String,
    name: String,
    pool: PgPool,
}

impl TestDb {
    /// Creates and migrates a fresh uniquely named database; `None` only when the operator
    /// explicitly opted out of the Postgres leg.
    ///
    /// # Panics
    ///
    /// When neither `PUB_TEST_POSTGRES_URL` nor `PUB_TEST_NO_POSTGRES` is set — see
    /// [`pub_test_support::OptionalBackend::gate`].
    async fn create(test: &str) -> Option<Self> {
        let admin_url = match pub_test_support::POSTGRES.gate(test) {
            pub_test_support::Gate::Run(url) => url,
            pub_test_support::Gate::Skipped => return None,
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

/// **S-08 under real concurrency.** The throwaway database's pool holds five connections, so
/// this leg races for real — and it is the leg that answers what the *production* backend
/// does, which the SQLite one cannot: the two dialects fail a lost race in different ways.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn session_rotation_is_single_winner_s08() {
    let Some(db) = TestDb::create("session_rotation_is_single_winner_s08").await else { return };
    pub_db_tests::contract::session_rotation_is_single_winner(&db.repos()).await;
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
async fn supply_chain_register_pages_contract_s17b_s19b_s23b() {
    let Some(db) = TestDb::create("supply_chain_register_pages").await else { return };
    pub_db_tests::contract::supply_chain_register_pages(&db.repos()).await;
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
async fn storage_quota_contract_s20_b() {
    let Some(db) = TestDb::create("storage_quota_contract_s20_b").await else { return };
    pub_db_tests::contract::storage_quota(&db.repos()).await;
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

#[tokio::test]
async fn queue_completion_is_fenced_by_its_claim_d45() {
    let Some(db) = TestDb::create("queue_completion_is_fenced_by_its_claim_d45").await else { return };
    pub_db_tests::contract::queue_completion_is_fenced_by_its_claim(&db.repos()).await;
    db.cleanup().await;
}

#[tokio::test]
async fn job_lock_contract_decision36() {
    let Some(db) = TestDb::create("job_lock_contract_decision36").await else { return };
    pub_db_tests::contract::job_lock(&db.repos()).await;
    db.cleanup().await;
}

/// **The claim D1 rests on, against the server that will actually arbitrate it.** Two
/// acquisitions of one name in flight on a real pool: exactly one may win, and the loser must be
/// told it lost rather than handed the same lease.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn job_lock_is_single_winner_decision36() {
    let Some(db) = TestDb::create("job_lock_is_single_winner_decision36").await else { return };
    pub_db_tests::contract::job_lock_is_single_winner(&db.repos()).await;
    db.cleanup().await;
}

/// S-23 retention, and the one contract function that exercises a **stored procedure**.
///
/// On this dialect the audit prune goes through `pub_audit_prune` (migration 0012) rather than
/// through a `DELETE` the app role is allowed to issue, so the floor, the batch bound and the
/// return count are all properties of SQL that only ever runs here (S-22.a).
#[tokio::test]
async fn retention_contract_s23_s22a() {
    let Some(db) = TestDb::create("retention_contract_s23_s22a").await else { return };
    pub_db_tests::contract::retention(&db.repos()).await;
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
        "SELECT indexname::text FROM pg_indexes \
         WHERE tablename IN ('job_queue', 'notifications', 'sessions', 'invitations', 'download_stats') \
         ORDER BY indexname",
    )
    .fetch_all(&db.pool)
    .await
    .expect("read pg_indexes");
    let names: Vec<String> = names.into_iter().map(|row| row.0).collect();
    for expected in [
        // Migration 0012's three. `invitations_settled_idx` is the fragile one: an *expression*
        // index, so a predicate that drifted away from `COALESCE(accepted_at, revoked_at,
        // expires_at)` silently stops matching it and the sweep becomes a seq scan inside a write
        // statement — green forever without this.
        "sessions_last_seen_idx",
        "invitations_settled_idx",
        "notifications_created_idx",
        "download_stats_date_idx",
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

/// **S-22.a / D46.** The hardened app role prunes audit rows without ever holding `DELETE`.
///
/// This is the test the debt was actually about. Every other Postgres test in this file — and the
/// compose file, and the CI service — connects as the **database owner**, which can delete from any
/// table. So a retention job that quietly needed `DELETE ON audit_log` would pass all of them and
/// fail only on the deployments that followed the documented S-22 hardening: the compliance-motivated
/// ones the feature exists for.
///
/// So this provisions a role the way `0002_identity.sql`'s template says to — including its last
/// line, `REVOKE UPDATE, DELETE, TRUNCATE ON audit_log` — connects as that role, and asserts both
/// halves of decision 30's answer: a direct delete is still refused, and the prune still works.
#[tokio::test]
async fn s22_a_the_hardened_app_role_prunes_audit_without_holding_delete() {
    let Some(db) = TestDb::create("s22_a_hardened_app_role").await else { return };

    // The 0002 template, executed for real for the first time anywhere in this repository.
    let role = format!("pub_app_{}", pub_core::UserId::new().to_string().replace('-', ""));
    for statement in [
        format!("CREATE ROLE \"{role}\" LOGIN PASSWORD 'hardened_test_password'"),
        format!("GRANT USAGE ON SCHEMA public TO \"{role}\""),
        format!("GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO \"{role}\""),
        format!("GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO \"{role}\""),
        // The line that makes audit_log append-only, and the reason this test exists.
        format!("REVOKE UPDATE, DELETE, TRUNCATE ON audit_log FROM \"{role}\""),
    ] {
        sqlx::query(AssertSqlSafe(statement)).execute(&db.pool).await.expect("provision the hardened role");
    }

    // Seed as the owner: the hardened role may INSERT, but the rows have to be old and the
    // fixture's clock is not the point here.
    let user = db
        .repos()
        .users
        .create(
            pub_core::user::NewUser {
                email: Some("root@corp.com".into()),
                email_verified: true,
                display_name: "Root".into(),
            },
            chrono::Utc::now(),
        )
        .await
        .expect("user");
    for index in 0..3 {
        db.repos()
            .audit
            .append(
                pub_core::audit::NewAuditEvent {
                    actor: pub_core::audit::AuditActor::User(user.id),
                    ip: None,
                    user_agent: None,
                    org_id: None,
                    action: format!("test.event.{index}"),
                    target: None,
                    result: pub_core::audit::AuditResult::Success,
                    metadata: None,
                },
                chrono::Utc::now() - chrono::Duration::days(400),
            )
            .await
            .expect("audit row");
    }

    // Now connect as the hardened role.
    let options = PgConnectOptions::from_str(&db.admin_url)
        .expect("parse postgres url")
        .database(&db.name)
        .username(&role)
        .password("hardened_test_password");
    let app_pool =
        PgPoolOptions::new().max_connections(2).connect_with(options).await.expect("connect as the hardened role");

    // Half one: the REVOKE is real. A direct delete is refused at the database, which is the
    // property S-22 buys and decision 30 refused to trade away.
    let direct = sqlx::query("DELETE FROM audit_log").execute(&app_pool).await;
    let err = direct.expect_err("the hardened role must not be able to delete audit rows directly");
    let message = err.to_string();
    assert!(message.contains("permission denied"), "expected a privilege error, got: {message}");

    // Half two: **without the documented grant, retention is refused** — and that is the state a
    // hardened deployment starts in, because migration 0012 revokes EXECUTE from PUBLIC rather than
    // relying on Postgres' default. Asserted rather than assumed: it is the exact error the
    // lifecycle job renders as a refusal, and the reason that path exists at all.
    let app_repos = pub_db_postgres::repo::repositories(app_pool.clone());
    let now = chrono::Utc::now();
    let refused = app_repos
        .audit
        .prune_before(now - chrono::Duration::days(31), now, 2)
        .await
        .expect_err("without the grant the prune must be refused, not silently skipped");
    assert!(
        refused.to_string().contains("permission denied"),
        "the refusal must name the privilege so the operator can act on it, got: {refused}"
    );

    // Half three: the one documented deployment step makes it work, and nothing else does.
    sqlx::query(AssertSqlSafe(format!("GRANT EXECUTE ON FUNCTION pub_audit_prune(TIMESTAMPTZ, INT) TO \"{role}\"")))
        .execute(&db.pool)
        .await
        .expect("grant execute");
    assert_eq!(
        app_repos.audit.prune_before(now - chrono::Duration::days(31), now, 2).await.expect("prune"),
        2,
        "the hardened role must be able to spend S-23 retention through the function"
    );
    assert_eq!(app_repos.audit.prune_before(now - chrono::Duration::days(31), now, 2).await.expect("prune"), 1);

    // And the floor holds below the application: even calling the function directly, with the Rust
    // guard bypassed entirely, a recent cutoff is refused. That is what keeps the reachable
    // capability "delete audit rows older than a month" rather than "delete audit rows".
    let recent: Result<(i64,), _> =
        sqlx::query_as("SELECT pub_audit_prune(now() - interval '1 day', 100)").fetch_one(&app_pool).await;
    let err = recent.expect_err("the function must refuse a cutoff inside the floor");
    assert!(err.to_string().contains("refusing a cutoff"), "expected the floor's own message, got: {err}");

    // A negative batch is refused too: in Postgres `LIMIT -1` is *unbounded*, so this guard is the
    // difference between one bounded statement and a full-table delete holding a lock.
    let unbounded: Result<(i64,), _> =
        sqlx::query_as("SELECT pub_audit_prune(now() - interval '400 days', -1)").fetch_one(&app_pool).await;
    let err = unbounded.expect_err("a negative batch must be refused, because LIMIT -1 is unbounded");
    assert!(
        err.to_string().contains("batch must be positive"),
        "matching any error would pass on a renamed or dropped function; got: {err}"
    );

    // **Migration 0014 needs no change to this template, asserted rather than reasoned about.**
    // The template's grants are table-level, and a table-level privilege in Postgres covers every
    // column the table has or later gains — so a column added after the role was provisioned is
    // readable and writable without a re-grant. That is a property of the *grant*, not of the
    // migration, and the way it would break is silent on every other test in this file: they all
    // connect as the database owner, which can do anything. The one deployment shape that would
    // fail is the hardened one this test exists for.
    let quota_org = db
        .repos()
        .orgs
        .create(pub_core::org::NewOrg::new("Quota", "quota"), user.id, chrono::Utc::now())
        .await
        .expect("seed an org as the owner");
    let quota = app_repos
        .orgs
        .set_storage_quota(quota_org.id, Some(4096), chrono::Utc::now())
        .await
        .expect("the hardened role must be able to write a column added after it was provisioned");
    assert_eq!(quota.storage_quota_bytes, Some(4096));
    assert_eq!(
        app_repos.orgs.get(quota_org.id).await.expect("read back").expect("org").storage_quota_bytes,
        Some(4096),
        "the hardened role must be able to read the new column too"
    );

    app_pool.close().await;
    sqlx::query(AssertSqlSafe(format!("DROP OWNED BY \"{role}\""))).execute(&db.pool).await.expect("drop owned");
    let admin_pool = db.pool.clone();
    db.cleanup().await;
    let _ = admin_pool;
    let mut admin = PgConnection::connect(&std::env::var(pub_test_support::POSTGRES.url_env).expect("url"))
        .await
        .expect("connect to postgres admin");
    sqlx::query(AssertSqlSafe(format!("DROP ROLE IF EXISTS \"{role}\"")))
        .execute(&mut admin)
        .await
        .expect("drop the test role");
    admin.close().await.expect("close admin connection");
}

/// **S-20.b.** The quota's usage read is an index-only scan bounded by `package_id`, not a walk
/// of the org's version rows.
///
/// The SQLite sibling asserts the same property against the same statement; this leg is the one
/// that can answer whether the *Postgres* SQL is right, which the SQLite-only run cannot
/// ([D16](../../../../docs/roadmap.md)). Two shapes of this test are deliberate, both from
/// [D52](../../../../docs/roadmap.md): the SQL is read from `PgPackageRepo::ORG_STORAGE_BYTES_SQL`
/// rather than copied here, and the assertion is on the **seek's usable columns** plus the
/// absence of heap fetches — never on an index name alone.
///
/// It needs a *realistically shaped* loaded table to mean anything, and the first shape tried
/// here was wrong in an instructive way. Postgres sequentially scans a handful of rows whatever
/// indexes exist, so the fixture is loaded — but with the 20 000 versions split evenly between
/// two orgs, the planner hash-joined a **sequential scan** of `versions` and was *right* to: at
/// 50 % selectivity a seek per package is more expensive than one pass. That is not the shape a
/// quota check runs in. An instance with one org is an instance with no quota problem; the case
/// worth keeping fast is one org among many, whose slice is a small fraction of the whole. So
/// the fixture below is 202 packages over two orgs where the measured org holds **1 %** of the
/// versions, `VACUUM ANALYZE`d so the visibility map is set and an index-only scan can be one.
#[tokio::test]
async fn s20_b_the_org_storage_sum_is_an_index_only_scan() {
    let Some(db) = TestDb::create("s20_b_the_org_storage_sum").await else { return };
    let repos = db.repos();
    let now = chrono::Utc::now();
    let alice = repos
        .users
        .create(
            pub_core::user::NewUser {
                email: Some("alice@corp.com".into()),
                email_verified: true,
                display_name: "Alice".into(),
            },
            now,
        )
        .await
        .expect("seed the publisher");
    let measured = repos.orgs.create(pub_core::org::NewOrg::new("Measured", "measured"), alice.id, now).await;
    let measured = measured.expect("seed the measured org").id;
    let other = repos.orgs.create(pub_core::org::NewOrg::new("Other", "other"), alice.id, now).await;
    let other = other.expect("seed the second org").id;

    // 2 packages for the org under measurement, 200 for the rest of the instance — 100 versions
    // each, one in fifty tombstoned so the partial predicate has something to exclude.
    for (org, packages) in [(measured, 2), (other, 200)] {
        sqlx::query(
            "WITH claimed AS ( \
               INSERT INTO name_claims (format, name, org_id, claimed_at) \
               SELECT 'pub', 'pkg_' || $2 || '_' || i, $1, now() FROM generate_series(1, $4) AS i RETURNING name \
             ), pkgs AS ( \
               INSERT INTO packages (id, format, name, org_id, visibility, discontinued, replaced_by, unlisted, \
                                     created_at, updated_at) \
               SELECT gen_random_uuid(), 'pub', name, $1, 'private', FALSE, NULL, FALSE, now(), now() \
               FROM claimed RETURNING id \
             ) \
             INSERT INTO versions (id, package_id, version, version_sort, pubspec, archive_sha256, archive_size, \
                                   published_by, published_by_token, published_at, retracted_at, tombstone, \
                                   readme_html, changelog_html) \
             SELECT gen_random_uuid(), p.id, '1.0.' || v, '1.0.' || lpad(v::text, 10, '0'), '{}'::jsonb, \
                    encode(sha256((p.id::text || v)::bytea), 'hex'), 1024, $3, NULL, now(), NULL, v % 50 = 0, \
                    NULL, NULL \
             FROM pkgs p, generate_series(1, 100) AS v",
        )
        .bind(*org.as_uuid())
        .bind(org.to_string())
        .bind(*alice.id.as_uuid())
        .bind(packages)
        .execute(&db.pool)
        .await
        .expect("load the version history");
    }
    // `VACUUM` and not just `ANALYZE`: an index-only scan still visits the heap for every row
    // whose page is not marked all-visible, and a freshly bulk-inserted table has none marked.
    // Without this the plan is the right one and the `Heap Fetches` assertion below fails on a
    // property of the fixture rather than of the schema.
    sqlx::query("VACUUM ANALYZE versions").execute(&db.pool).await.expect("vacuum analyze versions");
    sqlx::query("VACUUM ANALYZE packages").execute(&db.pool).await.expect("vacuum analyze packages");

    let rows: Vec<(String,)> = sqlx::query_as(AssertSqlSafe(format!(
        "EXPLAIN (ANALYZE, BUFFERS) {}",
        pub_db_postgres::repo::PgPackageRepo::ORG_STORAGE_BYTES_SQL
    )))
    .bind(*measured.as_uuid())
    .fetch_all(&db.pool)
    .await
    .expect("explain");
    let plan = rows.into_iter().map(|row| row.0).collect::<Vec<_>>().join("\n");

    // The seek, and what bounds it. `package_id` is the leading column of
    // `versions_org_bytes_idx` precisely so this condition exists; without it the aggregate
    // reads every live version on the instance and filters.
    let cond = plan
        .lines()
        .filter(|line| line.trim_start().starts_with("Index Cond:"))
        .find(|line| line.contains("package_id"))
        .unwrap_or_else(|| panic!("the sum does not seek `versions` on package_id at all:\n{plan}"));
    assert!(cond.contains("package_id"), "{cond}");
    assert!(!plan.contains("Seq Scan on versions"), "the quota sum sequentially scans `versions`:\n{plan}");

    // Index **only**: `archive_size` is in the index so the sum never visits the heap. This is
    // the assertion that carries the test, and it was demonstrated rather than assumed — with
    // 0014's index dropped the planner still produces a nested loop with an `Index Cond` on
    // `package_id`, so the two assertions above stay green, but the inner side becomes a
    // `Bitmap Heap Scan on versions` over `versions_package_version_key` with a heap recheck and
    // `Filter: (NOT tombstone)`: 13 shared buffers against 8, on a fixture where the org owns 1 %
    // of the instance's versions. The gap is proportional to the org's history, and this runs
    // twice per publish.
    assert!(
        plan.contains("Index Only Scan using versions_org_bytes_idx"),
        "the sum reads version rows to sum one column of them:\n{plan}"
    );
    // The node type alone is not the property: an index-only scan that finds an unset visibility
    // map fetches every row from the heap anyway and is an ordinary index scan wearing a hat.
    assert!(
        plan.contains("Heap Fetches: 0"),
        "the index-only scan is still visiting the heap, so it is not paying for itself:\n{plan}"
    );

    // The per-**package** sum the transfer guard reads (S-20.b) needs **no index of its own**:
    // `versions_org_bytes_idx` leads on `package_id` and carries `archive_size`, so it is the
    // same index-only scan with the `packages` half of the join removed. Asserted rather than
    // reasoned about, because "the index we have happens to serve it" stops being true the day
    // somebody reorders its columns.
    let package = sqlx::query_scalar::<_, sqlx::types::Uuid>("SELECT id FROM packages WHERE org_id = $1 LIMIT 1")
        .bind(*measured.as_uuid())
        .fetch_one(&db.pool)
        .await
        .expect("a package of the measured org");
    let rows: Vec<(String,)> = sqlx::query_as(AssertSqlSafe(format!(
        "EXPLAIN (ANALYZE, BUFFERS) {}",
        pub_db_postgres::repo::PgPackageRepo::PACKAGE_STORAGE_BYTES_SQL
    )))
    .bind(package)
    .fetch_all(&db.pool)
    .await
    .expect("explain");
    let plan = rows.into_iter().map(|row| row.0).collect::<Vec<_>>().join("\n");
    assert!(!plan.contains("Seq Scan on versions"), "the per-package sum sequentially scans `versions`:\n{plan}");
    assert!(
        plan.contains("Index Only Scan using versions_org_bytes_idx"),
        "the per-package sum needs no new index, but it does need this one to cover it:\n{plan}"
    );
    assert!(plan.contains("Heap Fetches: 0"), "the per-package sum is visiting the heap:\n{plan}");
}

/// **Decision 31.** The blob collector's reference check seeks both registers instead of
/// scanning them.
///
/// This is the query that decides whether bytes may be deleted, asked once per batch of
/// candidate keys, and its second half runs against `upstream_versions` — the largest table in
/// the schema on a mirror-mode instance, and the one that had no index on `archive_sha256` at
/// all, because until decision 31 it was asked one hash at a time by a job that shipped
/// disabled. Batching removed two round trips per object; a sequential scan inside each batch
/// would have put the whole cost back one layer down, where no test that only checks the
/// *answer* would ever notice.
///
/// Both indexes are partial, so the assertion is on the plan rather than on the index existing:
/// a predicate that drifted away from `WHERE cached` / `WHERE NOT tombstone` leaves the index in
/// `pg_indexes` and stops matching the query.
#[tokio::test]
async fn the_blob_collectors_reference_check_seeks_both_registers() {
    let Some(db) = TestDb::create("the_blob_collectors_reference_check").await else { return };
    // Enough rows, with enough distinct hashes, that the planner has a reason to care.
    sqlx::query(
        "INSERT INTO upstream_packages (id, format, name, upstream, discontinued, replaced_by, \
         advisories_updated, listing, fetched_at) \
         VALUES (gen_random_uuid(), 'pub', 'http', 'https://pub.dev', FALSE, NULL, NULL, NULL, now())",
    )
    .execute(&db.pool)
    .await
    .expect("seed the upstream package");
    sqlx::query(
        "INSERT INTO upstream_versions (id, upstream_package_id, version, version_sort, pubspec, archive_sha256, \
         archive_size, retracted, cached, published_at, fetched_at) \
         SELECT gen_random_uuid(), p.id, '1.0.' || i, '1.0.' || lpad(i::text, 10, '0'), '{}'::jsonb, \
         encode(sha256(i::text::bytea), 'hex'), 1024, FALSE, i % 2 = 0, now(), now() \
         FROM upstream_packages p, generate_series(1, 20000) AS i",
    )
    .execute(&db.pool)
    .await
    .expect("load the proxy cache");
    sqlx::query("ANALYZE upstream_versions").execute(&db.pool).await.expect("analyze");

    let explain = async |sql: &str| -> String {
        let rows: Vec<(String,)> = sqlx::query_as(AssertSqlSafe(format!("EXPLAIN (ANALYZE, BUFFERS) {sql}")))
            .fetch_all(&db.pool)
            .await
            .expect("explain");
        rows.into_iter().map(|row| row.0).collect::<Vec<_>>().join("\n")
    };

    // The proxy-cache half, exactly as `cached_sha256s` emits it.
    let cached = explain(
        "SELECT DISTINCT archive_sha256 FROM upstream_versions WHERE cached \
         AND archive_sha256 = ANY(ARRAY[encode(sha256('7'::text::bytea), 'hex'), \
         encode(sha256('8'::text::bytea), 'hex')])",
    )
    .await;
    assert!(cached.contains("upstream_versions_sha256_idx"), "the proxy-cache check is a scan:\n{cached}");
    assert!(!cached.contains("Seq Scan on upstream_versions"), "{cached}");

    // The local half, which has had `versions_sha256_idx` since 0004 — asserted here so the pair
    // is checked together rather than one of them being assumed.
    let live = explain(
        "SELECT DISTINCT archive_sha256 FROM versions WHERE NOT tombstone \
         AND archive_sha256 = ANY(ARRAY[repeat('a', 64), repeat('b', 64)])",
    )
    .await;
    assert!(live.contains("versions_sha256_idx"), "the live-reference check is a scan:\n{live}");
    db.cleanup().await;
}

/// **S-17.b / S-19.b.** The register page walks seek on the whole key, on a register big enough
/// for the planner to have a choice.
///
/// Loaded with rows that all share one `last_seen_at`, because that is the shape the registers
/// actually produce — one fetch loop refusing a package's versions, one sweep raising a block of
/// alarms — and the shape that separates a seek on the whole key from a seek on the timestamp
/// with the tie-breaks post-filtered. On an empty table every plan looks fine, which is why this
/// one loads a backlog and runs `ANALYZE` first.
///
/// The SQL comes from the repository, never from a copy in this file ([D52](../../../../docs/roadmap.md)).
#[tokio::test]
async fn s17b_s19b_the_register_pages_seek_on_the_whole_key() {
    let Some(db) = TestDb::create("s17b_s19b_register_pages").await else { return };
    sqlx::query(
        "INSERT INTO upstream_quarantine (format, name, version, upstream, expected_sha256, actual_sha256, \
         occurrences, first_seen_at, last_seen_at) \
         SELECT 'pub', 'pkg_' || (i / 100), '1.0.' || i, 'https://pub.dev', repeat('a', 64), repeat('b', 64), 1, \
         now(), now() FROM generate_series(1, 20000) AS i",
    )
    .execute(&db.pool)
    .await
    .expect("load the register");
    sqlx::query("ANALYZE upstream_quarantine").execute(&db.pool).await.expect("analyze");

    let rows: Vec<(String,)> = sqlx::query_as(AssertSqlSafe(format!(
        "EXPLAIN (ANALYZE, BUFFERS) {}",
        pub_db_postgres::repo::quarantine_page_sql(true)
    )))
    .bind(chrono::Utc::now())
    .bind("pub")
    .bind("pkg_50")
    .bind("1.0.5000")
    .bind(20_i64)
    .fetch_all(&db.pool)
    .await
    .expect("explain");
    let plan = rows.into_iter().map(|row| row.0).collect::<Vec<_>>().join("\n");

    assert!(plan.contains("upstream_quarantine_page_idx"), "the register page does not use its index:\n{plan}");
    assert!(!plan.contains("Seq Scan"), "the register page reads every row:\n{plan}");
    // No sort node: the newest-first order has to come from the index's own direction, or every
    // page of a large register sorts it. This is what the all-DESC index in 0015 buys.
    assert!(!plan.contains("Sort Method"), "the page sorts instead of walking the index:\n{plan}");
    // And the seek is bounded by the whole key, not by the timestamp with the rest filtered out.
    let cond = plan
        .lines()
        .find(|line| line.trim_start().starts_with("Index Cond:"))
        .unwrap_or_else(|| panic!("the page is not an index scan at all:\n{plan}"));
    for column in ["last_seen_at", "format", "name", "version"] {
        assert!(cond.contains(column), "{column} is not in the index condition, so the walk can skip rows: {cond}");
    }

    db.cleanup().await;
}
