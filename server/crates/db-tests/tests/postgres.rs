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
