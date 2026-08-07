//! Search-index rebuild over a real migrated database.
//!
//! The job exists because incremental index maintenance is deliberately best-effort: an index
//! write that fails must not fail a publish whose bytes and rows are already committed. So the
//! tests here are about the repair contract, not about search itself:
//!
//! | Rule | Test |
//! |------|------|
//! | A sweep reconstructs what the publish path would have written | [`a_sweep_rebuilds_documents_the_publish_path_never_wrote`] |
//! | Chunks resume from the durable cursor across a restart | [`a_chunked_sweep_resumes_across_a_restart`] |
//! | A finished sweep waits out its window | [`a_completed_sweep_waits_for_the_resweep_window`] |
//! | Packages with nothing live are dropped, not indexed empty | [`packages_with_no_live_version_are_removed_from_the_index`] |
//! | Rebuilding is idempotent | [`a_second_sweep_changes_nothing`] |

use chrono::{DateTime, Duration, TimeZone as _, Utc};
use pub_core::org::NewOrg;
use pub_core::package::{NewPackage, NewVersion, Publisher, Visibility};
use pub_core::search::{SearchQuery, SearchSort, SearchView};
use pub_core::traits::Repositories;
use pub_core::user::NewUser;
use pub_core::{Format, OrgId, SemVer, UserId};
use pub_db_sqlite::SqliteDb;
use pub_jobs::{REINDEX_JOB, ReindexPolicy, Reindexer};

fn t0() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 8, 7, 12, 0, 0).unwrap()
}

struct Harness {
    repos: Repositories,
    org: OrgId,
    user: UserId,
}

impl Harness {
    async fn new() -> Self {
        let cfg = pub_config::DatabaseConfig {
            kind: pub_config::DatabaseKind::Sqlite,
            url: None,
            path: ":memory:".to_owned(),
        };
        let db = SqliteDb::connect(&cfg).await.expect("connect :memory:");
        db.run_migrations().await.expect("migrate");
        let repos = db.repositories();
        let user = repos
            .users
            .create(
                NewUser {
                    email: Some("alice@corp.com".to_owned()),
                    email_verified: true,
                    display_name: "Alice".to_owned(),
                },
                t0(),
            )
            .await
            .expect("user")
            .id;
        let org = repos.orgs.create(NewOrg::new("Acme", "acme"), user, t0()).await.expect("org").id;
        Self { repos, org, user }
    }

    /// Publishes a version **through the repository**, i.e. without the index maintenance the
    /// real publish pipeline performs. That is exactly the state the job has to repair: rows
    /// exist, documents do not.
    async fn publish(&self, name: &str, version: &str) -> pub_core::package::PublishedVersion {
        self.repos
            .packages
            .create_version(
                NewVersion {
                    format: Format::Pub,
                    package_name: name.to_owned(),
                    org_id: self.org,
                    visibility: Visibility::Public,
                    version: SemVer::parse(version).expect("version"),
                    pubspec: serde_json::json!({
                        "name": name,
                        "version": version,
                        "description": format!("The {name} package"),
                        "dependencies": { "meta": "^1.0.0" },
                    }),
                    archive_sha256: format!("{:0>64}", format!("{name}{version}").replace('.', "")),
                    archive_size: 1024,
                    published_by: Publisher { user_id: self.user, token_id: None },
                    readme_html: Some(format!("<p>Docs for {name}</p>")),
                    changelog_html: None,
                },
                t0(),
            )
            .await
            .unwrap_or_else(|err| panic!("publish {name}@{version}: {err}"))
    }

    /// Indexed names, ascending.
    async fn indexed(&self) -> Vec<String> {
        let query = SearchQuery::browse(SearchSort::Name);
        let page = self.repos.search.search(&query, &SearchView::anonymous(), None, 100).await.expect("listing");
        page.items.into_iter().map(|hit| hit.name).collect()
    }
}

fn policy(chunk: u32) -> ReindexPolicy {
    ReindexPolicy { enabled: true, chunk, resweep_after: Duration::hours(24), ..ReindexPolicy::default() }
}

#[tokio::test]
async fn a_sweep_rebuilds_documents_the_publish_path_never_wrote() {
    let harness = Harness::new().await;
    harness.publish("acme_core", "1.0.0").await;
    harness.publish("acme_core", "1.1.0").await;
    harness.publish("acme_ui", "0.1.0").await;
    assert!(harness.indexed().await.is_empty(), "the repository path writes no documents");

    let job = Reindexer::new(harness.repos.clone(), policy(50));
    let report = job.run_once(t0()).await.expect("sweep");
    assert_eq!(report.indexed, 2);
    assert_eq!(report.removed, 0);
    assert!(report.completed);
    assert_eq!(harness.indexed().await, vec!["acme_core".to_owned(), "acme_ui".to_owned()]);

    // The rebuilt document is the full projection, not a stub: description, README text, the
    // dependency graph, and the version count all come back.
    let hits = harness
        .repos
        .search
        .search(&pub_core::search::parse_query("dependency:meta", SearchSort::Name), &SearchView::anonymous(), None, 10)
        .await
        .expect("dependency filter");
    assert_eq!(hits.items.len(), 2, "the reverse dependency graph is rebuilt too");
    let core = hits.items.iter().find(|hit| hit.name == "acme_core").expect("acme_core");
    assert_eq!(core.latest_version, "1.1.0");
    assert_eq!(core.versions_count, 2);
    assert_eq!(core.description, "The acme_core package");
    // The README's rendered HTML is projected to text and searchable.
    let readme = harness
        .repos
        .search
        .search(&pub_core::search::parse_query("docs", SearchSort::Name), &SearchView::anonymous(), None, 10)
        .await
        .expect("readme search");
    assert_eq!(readme.items.len(), 2);

    // Durable state records the pass for the admin surface.
    let state = job.status(t0()).await.expect("status");
    assert_eq!(state.name, REINDEX_JOB);
    assert_eq!(state.runs, 1);
    assert!(state.last_success_at.is_some());
}

#[tokio::test]
async fn a_chunked_sweep_resumes_across_a_restart() {
    let harness = Harness::new().await;
    for name in ["acme_a", "acme_b", "acme_c", "acme_d", "acme_e"] {
        harness.publish(name, "1.0.0").await;
    }

    // One package per tick: the chunk is the tick's cost bound, and the cursor is what makes
    // the sweep survive a restart or a leader change.
    let job = Reindexer::new(harness.repos.clone(), policy(1));
    let first = job.run_once(t0()).await.expect("chunk 1");
    assert_eq!(first.indexed, 1);
    assert!(!first.completed);
    assert_eq!(harness.indexed().await, vec!["acme_a".to_owned()]);

    // A brand-new worker over the same database — the process died and came back.
    let restarted = Reindexer::new(harness.repos.clone(), policy(1));
    let mut ticks = 1;
    loop {
        let report = restarted.run_once(t0() + Duration::minutes(ticks)).await.expect("chunk");
        ticks += 1;
        if report.completed {
            break;
        }
        assert!(ticks < 20, "the sweep is not converging");
    }
    assert_eq!(
        harness.indexed().await,
        vec!["acme_a".to_owned(), "acme_b".to_owned(), "acme_c".to_owned(), "acme_d".to_owned(), "acme_e".to_owned()],
        "resuming from the cursor must cover every package exactly once"
    );
    // Five packages at one per tick: the over-fetch that detects `has_more` also detects the
    // end, so the last chunk completes the sweep rather than costing an extra empty tick.
    assert_eq!(ticks, 5);
}

#[tokio::test]
async fn a_completed_sweep_waits_for_the_resweep_window() {
    let harness = Harness::new().await;
    harness.publish("acme_core", "1.0.0").await;
    let job = Reindexer::new(harness.repos.clone(), policy(50));
    assert!(job.run_once(t0()).await.expect("first").completed);

    // Inside the window the tick is a no-op: a completed index does not need re-walking every
    // interval, and the decision lives with the durable state so a restart cannot reset it.
    let skipped = job.run_once(t0() + Duration::hours(1)).await.expect("inside the window");
    assert!(skipped.skipped);
    assert_eq!(skipped.indexed, 0);

    let after = job.run_once(t0() + Duration::hours(25)).await.expect("after the window");
    assert!(!after.skipped);
    assert_eq!(after.indexed, 1);
}

#[tokio::test]
async fn packages_with_no_live_version_are_removed_from_the_index() {
    let harness = Harness::new().await;
    let published = harness.publish("acme_core", "1.0.0").await;
    // A name reservation: a package row with nothing published.
    harness
        .repos
        .packages
        .create_package(
            NewPackage {
                format: Format::Pub,
                name: "acme_reserved".to_owned(),
                org_id: harness.org,
                visibility: Visibility::Public,
            },
            t0(),
        )
        .await
        .expect("reserve");

    let job = Reindexer::new(harness.repos.clone(), policy(50));
    let report = job.run_once(t0()).await.expect("sweep");
    assert_eq!(report.indexed, 1);
    assert_eq!(report.removed, 1, "a reserved name has nothing to show and must not be a result");
    assert_eq!(harness.indexed().await, vec!["acme_core".to_owned()]);

    // Hard-deleting the only version takes the package out of the index on the next sweep.
    harness.repos.packages.hard_delete_version(published.version.id).await.expect("hard delete");
    let report = job.run_once(t0() + Duration::hours(25)).await.expect("second sweep");
    assert_eq!(report.indexed, 0);
    assert_eq!(report.removed, 2);
    assert!(harness.indexed().await.is_empty());
}

#[tokio::test]
async fn a_second_sweep_changes_nothing() {
    let harness = Harness::new().await;
    harness.publish("acme_core", "1.0.0").await;
    harness.publish("acme_ui", "1.0.0").await;
    let job = Reindexer::new(harness.repos.clone(), policy(50));

    job.run_once(t0()).await.expect("first");
    let before = harness.indexed().await;
    let counters = harness.repos.search.counters(&SearchView::anonymous()).await.expect("counters");

    // Rebuilding is idempotent by contract — the projection is deterministic, so a repair pass
    // over a healthy index is a no-op rather than a duplicate.
    let second = job.run_once(t0() + Duration::hours(25)).await.expect("second");
    assert_eq!(second.indexed, 2);
    assert_eq!(harness.indexed().await, before);
    assert_eq!(harness.repos.search.counters(&SearchView::anonymous()).await.expect("counters"), counters);
}
