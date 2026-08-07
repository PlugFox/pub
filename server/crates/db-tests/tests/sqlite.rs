//! Runs the shared repository contract suite against SQLite `:memory:` — the everyday local
//! backend (docs/rules/rust.md: no containers locally). Each test gets a fresh migrated
//! database, so scenarios can never bleed into one another.

use pub_config::{DatabaseConfig, DatabaseKind};
use pub_core::traits::Repositories;
use pub_db_sqlite::SqliteDb;

async fn fresh_repos() -> Repositories {
    let cfg = DatabaseConfig { kind: DatabaseKind::Sqlite, url: None, path: ":memory:".to_owned() };
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
