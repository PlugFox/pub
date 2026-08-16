//! Publish-pipeline integration tests: the real service over a real migrated SQLite database,
//! an in-memory blob store, the real in-process [`JobLock`], and a recording event sink.
//!
//! These cover the promises the pipeline makes that no unit test can: the publish is
//! transactional, the stored bytes are byte-identical to the upload, a duplicate version is a
//! distinct conflict, a hard-deleted number stays burned, and every step emits its audit and
//! domain event.

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use bytes::Bytes;
use chrono::{DateTime, Duration, TimeZone as _, Utc};
use futures::StreamExt as _;
use pub_config::{DatabaseConfig, DatabaseKind};
use pub_core::audit::{AuditActor, AuditFilter, AuditResult};
use pub_core::event::{DomainEvent, EventSink};
use pub_core::org::NewOrg;
use pub_core::package::{
    NameClaim, NewPackage, NewVersion, Package, PackageOptions, PublishedVersion, Publisher, RegistryStats, Version,
    Visibility,
};
use pub_core::traits::{BlobStore, DownloadMethod, DownloadPlan, PackageRepo, Repositories};
use pub_core::user::NewUser;
use pub_core::{Error, Format, OrgId, PackageId, Page, Result, SemVer, UserId, VersionId};
use pub_db_sqlite::SqliteDb;
use pub_jobs::{InMemoryJobLock, JobLock};
use pub_registry::index::{LATEST_WINDOW, build_document};
use pub_registry::publish::{HardDeleteRequest, RegistryService, RetractRequest, TransferRequest};
use pub_registry::{ActorMeta, ArchiveLimits, PublishRequest, RegistryPolicy, hex_sha256};

// --------------------------------------------------------------------------------- doubles

/// In-memory [`BlobStore`] that records every write, so tests can assert byte stability and
/// that a rejected publish never reached storage.
#[derive(Default)]
struct MemoryBlob {
    objects: Mutex<HashMap<String, Bytes>>,
}

impl MemoryBlob {
    fn keys(&self) -> Vec<String> {
        let mut keys: Vec<String> = self.objects.lock().expect("blob mutex").keys().cloned().collect();
        keys.sort();
        keys
    }
}

#[async_trait]
impl BlobStore for MemoryBlob {
    async fn ping(&self) -> Result<()> {
        Ok(())
    }

    async fn put(&self, key: &str, bytes: Bytes) -> Result<()> {
        self.objects.lock().expect("blob mutex").insert(key.to_owned(), bytes);
        Ok(())
    }

    async fn download(&self, key: &str, _method: DownloadMethod) -> Result<DownloadPlan> {
        let bytes = self
            .objects
            .lock()
            .expect("blob mutex")
            .get(key)
            .cloned()
            .ok_or_else(|| Error::NotFound { what: format!("blob {key}") })?;
        Ok(DownloadPlan::Stream(futures::stream::once(async move { Ok(bytes) }).boxed()))
    }

    async fn delete(&self, key: &str) -> Result<()> {
        self.objects.lock().expect("blob mutex").remove(key);
        Ok(())
    }
}

/// A [`PackageRepo`] that delegates everything and counts the three reads the indexer's cost
/// depends on.
///
/// It exists because "the indexer stopped walking the version list" is a statement about
/// *queries*, and no assertion on the produced document can see one: a walk and a bounded scan
/// build the same [`pub_core::search::SearchDocument`]. Counting is therefore the only way to
/// make [D23](../../../../docs/roadmap.md)'s exit fail if the walk ever comes back.
#[derive(Default)]
struct RepoCallCounts {
    list_versions: AtomicUsize,
    list_versions_desc: AtomicUsize,
    count_versions: AtomicUsize,
}

struct CountingPackages {
    inner: Arc<dyn PackageRepo>,
    counts: Arc<RepoCallCounts>,
}

#[async_trait]
impl PackageRepo for CountingPackages {
    async fn ping(&self) -> Result<()> {
        self.inner.ping().await
    }

    async fn create_package(&self, new: NewPackage, now: DateTime<Utc>) -> Result<Package> {
        self.inner.create_package(new, now).await
    }

    async fn get_package(&self, id: PackageId) -> Result<Option<Package>> {
        self.inner.get_package(id).await
    }

    async fn get_by_name(&self, format: Format, name: &str) -> Result<Option<Package>> {
        self.inner.get_by_name(format, name).await
    }

    async fn list_for_org(&self, org: OrgId, cursor: Option<&str>, limit: u32) -> Result<Page<Package>> {
        self.inner.list_for_org(org, cursor, limit).await
    }

    async fn list_all(&self, cursor: Option<&str>, limit: u32) -> Result<Page<Package>> {
        self.inner.list_all(cursor, limit).await
    }

    async fn set_options(&self, id: PackageId, options: &PackageOptions, now: DateTime<Utc>) -> Result<Package> {
        self.inner.set_options(id, options, now).await
    }

    async fn transfer(&self, id: PackageId, to_org: OrgId, now: DateTime<Utc>) -> Result<Package> {
        self.inner.transfer(id, to_org, now).await
    }

    async fn count_for_org(&self, org: OrgId) -> Result<i64> {
        self.inner.count_for_org(org).await
    }

    async fn stats(&self) -> Result<RegistryStats> {
        self.inner.stats().await
    }

    async fn org_storage_bytes(&self, org: OrgId) -> Result<i64> {
        self.inner.org_storage_bytes(org).await
    }

    async fn package_storage_bytes(&self, package: PackageId) -> Result<i64> {
        self.inner.package_storage_bytes(package).await
    }

    async fn create_version(&self, new: NewVersion, now: DateTime<Utc>) -> Result<PublishedVersion> {
        self.inner.create_version(new, now).await
    }

    async fn get_version(&self, package: PackageId, version: &SemVer) -> Result<Option<Version>> {
        self.inner.get_version(package, version).await
    }

    async fn count_versions(&self, package: PackageId) -> Result<i64> {
        self.counts.count_versions.fetch_add(1, Ordering::Relaxed);
        self.inner.count_versions(package).await
    }

    async fn list_versions(&self, package: PackageId, cursor: Option<&str>, limit: u32) -> Result<Page<Version>> {
        self.counts.list_versions.fetch_add(1, Ordering::Relaxed);
        self.inner.list_versions(package, cursor, limit).await
    }

    async fn list_versions_desc(&self, package: PackageId, cursor: Option<&str>, limit: u32) -> Result<Page<Version>> {
        self.counts.list_versions_desc.fetch_add(1, Ordering::Relaxed);
        self.inner.list_versions_desc(package, cursor, limit).await
    }

    async fn set_retracted(&self, id: VersionId, retracted: bool, now: DateTime<Utc>) -> Result<Version> {
        self.inner.set_retracted(id, retracted, now).await
    }

    async fn hard_delete_version(&self, id: VersionId) -> Result<Version> {
        self.inner.hard_delete_version(id).await
    }

    async fn count_versions_with_sha256(&self, sha256: &str) -> Result<u64> {
        self.inner.count_versions_with_sha256(sha256).await
    }

    async fn live_sha256s(&self, hashes: &[String]) -> Result<HashSet<String>> {
        self.inner.live_sha256s(hashes).await
    }

    async fn claim_name(&self, format: Format, name: &str, org: OrgId, now: DateTime<Utc>) -> Result<NameClaim> {
        self.inner.claim_name(format, name, org, now).await
    }

    async fn lookup_claim(&self, format: Format, name: &str) -> Result<Option<NameClaim>> {
        self.inner.lookup_claim(format, name).await
    }
}

/// Event sink that keeps what it was given (the SSE bus does not exist yet — decision 22).
#[derive(Default)]
struct RecordingEvents {
    events: Mutex<Vec<DomainEvent>>,
}

impl RecordingEvents {
    fn names(&self) -> Vec<String> {
        self.events.lock().expect("events mutex").iter().map(|event| event.name().to_owned()).collect()
    }

    fn last(&self) -> DomainEvent {
        self.events.lock().expect("events mutex").last().cloned().expect("at least one event")
    }
}

#[async_trait]
impl EventSink for RecordingEvents {
    async fn emit(&self, event: DomainEvent) {
        self.events.lock().expect("events mutex").push(event);
    }
}

// --------------------------------------------------------------------------------- harness

/// Deterministic base instant (no wall clock in tests).
fn t0() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 8, 7, 12, 0, 0).unwrap()
}

struct Harness {
    service: RegistryService,
    repos: Repositories,
    blob: Arc<MemoryBlob>,
    events: Arc<RecordingEvents>,
    lock: Arc<InMemoryJobLock>,
    org: OrgId,
    user: UserId,
}

impl Harness {
    async fn new() -> Self {
        Self::with_policy(RegistryPolicy::default()).await
    }

    async fn with_policy(policy: RegistryPolicy) -> Self {
        let cfg =
            DatabaseConfig { kind: DatabaseKind::Sqlite, url: None, path: ":memory:".to_owned(), ..Default::default() };
        let db = SqliteDb::connect(&cfg).await.expect("connect :memory:");
        db.run_migrations().await.expect("migrate");
        let repos = db.repositories();

        let user = repos
            .users
            .create(
                NewUser {
                    email: Some("dev@corp.test".to_owned()),
                    email_verified: true,
                    display_name: "Dev".to_owned(),
                },
                t0(),
            )
            .await
            .expect("seed user");
        let org = repos.orgs.create(NewOrg::new("Acme", "acme"), user.id, t0()).await.expect("seed org");

        let blob = Arc::new(MemoryBlob::default());
        let events = Arc::new(RecordingEvents::default());
        let lock = Arc::new(InMemoryJobLock::new());
        let service = RegistryService::new(
            repos.clone(),
            Arc::clone(&blob) as Arc<dyn BlobStore>,
            Arc::clone(&lock) as Arc<dyn JobLock>,
            Arc::clone(&events) as Arc<dyn EventSink>,
            policy,
        );
        Self { service, repos, blob, events, lock, org: org.id, user: user.id }
    }

    fn request(&self, archive: Vec<u8>) -> PublishRequest {
        PublishRequest {
            format: Format::Pub,
            org_id: self.org,
            visibility: Visibility::Private,
            actor: ActorMeta {
                user_id: self.user,
                token_id: None,
                ip: Some("203.0.113.7".to_owned()),
                user_agent: Some("Dart pub 3.9.0".to_owned()),
            },
            archive: Bytes::from(archive),
            expected_name: None,
            package_patterns: Vec::new(),
            // Unlimited by default, which is what a default install is (S-20.b): the quota
            // scenarios below set their own.
            storage_quota_bytes: None,
        }
    }

    /// The same request under an effective quota of `bytes`.
    fn request_under_quota(&self, archive: Vec<u8>, bytes: u64) -> PublishRequest {
        PublishRequest { storage_quota_bytes: Some(bytes), ..self.request(archive) }
    }

    /// A transfer of `name` out of this harness's org into `to`, under the **receiving** org's
    /// effective quota (`None` = unlimited).
    fn transfer_request(&self, name: &str, to: OrgId, quota: Option<u64>) -> TransferRequest {
        TransferRequest {
            format: Format::Pub,
            from_org: self.org,
            to_org: to,
            name: name.to_owned(),
            actor: ActorMeta {
                user_id: self.user,
                token_id: None,
                ip: Some("203.0.113.7".to_owned()),
                user_agent: Some("Mozilla/5.0".to_owned()),
            },
            storage_quota_bytes: quota,
        }
    }

    /// Creates a second org owned by a second user.
    async fn other_org(&self) -> OrgId {
        let user = self
            .repos
            .users
            .create(
                NewUser {
                    email: Some("other@corp.test".to_owned()),
                    email_verified: true,
                    display_name: "Other".to_owned(),
                },
                t0(),
            )
            .await
            .expect("second user");
        self.repos.orgs.create(NewOrg::new("Other", "other"), user.id, t0()).await.expect("second org").id
    }

    async fn audit_actions(&self) -> Vec<(String, AuditResult)> {
        let page = self.repos.audit.list(&AuditFilter::default(), None, 100).await.expect("audit list");
        page.items.into_iter().map(|event| (event.action, event.result)).collect()
    }

    /// Adds live versions straight through the repository.
    ///
    /// The publish pipeline is the right way to create one version and the wrong way to create
    /// a thousand: each would gzip, hash, untar and render an archive to prove something these
    /// tests are not about. The rows are what the indexer and the read surfaces consume.
    async fn seed_versions(&self, name: &str, versions: impl IntoIterator<Item = String>) {
        for raw in versions {
            self.repos
                .packages
                .create_version(
                    NewVersion {
                        format: Format::Pub,
                        package_name: name.to_owned(),
                        org_id: self.org,
                        visibility: Visibility::Private,
                        version: semver(&raw),
                        pubspec: serde_json::json!({ "name": name, "version": raw }),
                        archive_sha256: "c".repeat(64),
                        archive_size: 512,
                        published_by: Publisher { user_id: self.user, token_id: None },
                        readme_html: None,
                        changelog_html: None,
                    },
                    t0(),
                )
                .await
                .expect("seed version");
        }
    }

    /// Adds one live version of an exact `archive_size`.
    ///
    /// The quota scenarios need a baseline byte total they choose to the byte; a real archive's
    /// gzip size is whatever flate2 decides that day, which would make "just below 80 %" a
    /// coin toss rather than an assertion.
    async fn seed_sized_version(&self, name: &str, version: &str, size: i64) {
        self.repos
            .packages
            .create_version(
                NewVersion {
                    format: Format::Pub,
                    package_name: name.to_owned(),
                    org_id: self.org,
                    visibility: Visibility::Private,
                    version: semver(version),
                    pubspec: serde_json::json!({ "name": name, "version": version }),
                    archive_sha256: hex_sha256(format!("{name}@{version}").as_bytes()),
                    archive_size: size,
                    published_by: Publisher { user_id: self.user, token_id: None },
                    readme_html: None,
                    changelog_html: None,
                },
                t0(),
            )
            .await
            .expect("seed sized version");
    }

    /// The org's live byte total, as the quota guard reads it.
    async fn storage_bytes(&self) -> i64 {
        self.repos.packages.org_storage_bytes(self.org).await.expect("org storage bytes")
    }

    /// The same repositories with a counting [`PackageRepo`] in front of the real one.
    fn counting(&self) -> (Repositories, Arc<RepoCallCounts>) {
        let counts = Arc::new(RepoCallCounts::default());
        let mut repos = self.repos.clone();
        repos.packages =
            Arc::new(CountingPackages { inner: Arc::clone(&self.repos.packages), counts: Arc::clone(&counts) });
        (repos, counts)
    }

    async fn blob_bytes(&self, key: &str) -> Vec<u8> {
        match self.blob.download(key, DownloadMethod::Get).await.expect("download") {
            DownloadPlan::Stream(stream) => {
                let chunks: Vec<Bytes> = stream.map(|chunk| chunk.expect("chunk")).collect().await;
                chunks.concat()
            }
            DownloadPlan::Redirect(url) => panic!("unexpected redirect to {url}"),
        }
    }
}

// -------------------------------------------------------------------------------- fixtures

/// Builds a `.tar.gz` package archive.
fn package(name: &str, version: &str, extra: &[(&str, &str)]) -> Vec<u8> {
    use std::io::Write as _;

    let pubspec = format!("name: {name}\nversion: {version}\ndescription: Test package.\n");
    let mut builder = tar::Builder::new(Vec::new());
    let mut append = |path: &str, content: &str| {
        let mut header = tar::Header::new_gnu();
        header.set_size(content.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        builder.append_data(&mut header, path, content.as_bytes()).expect("append");
    };
    append("pubspec.yaml", &pubspec);
    for (path, content) in extra {
        append(path, content);
    }
    let tar = builder.into_inner().expect("finish tar");

    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(&tar).expect("gzip");
    encoder.finish().expect("gzip finish")
}

fn semver(raw: &str) -> SemVer {
    SemVer::parse(raw).expect("valid version")
}

// ----------------------------------------------------------------------------------- tests

#[tokio::test]
async fn publish_creates_claim_package_version_blob_and_events() {
    let h = Harness::new().await;
    let archive =
        package("acme_core", "1.0.0", &[("README.md", "# acme_core\n\nHello."), ("CHANGELOG.md", "## 1.0.0")]);
    let expected_sha = hex_sha256(&archive);

    let outcome = h.service.publish(h.request(archive.clone()), t0()).await.expect("publish");

    assert!(outcome.package_created, "the first publish creates the package");
    assert_eq!(outcome.package.name, "acme_core");
    assert_eq!(outcome.package.org_id, h.org);
    assert_eq!(outcome.package.visibility, Visibility::Private);
    assert_eq!(outcome.version.version.to_string(), "1.0.0");
    assert_eq!(outcome.version.archive_sha256, expected_sha);
    assert_eq!(outcome.version.archive_size, archive.len() as i64);
    assert_eq!(outcome.version.published_by, Publisher { user_id: h.user, token_id: None });
    assert!(!outcome.version.is_retracted());
    assert!(!outcome.version.tombstone);
    assert_eq!(outcome.version.pubspec["description"], "Test package.");

    // The name claim exists and belongs to the publishing org (decision 01).
    let claim = h.repos.packages.lookup_claim(Format::Pub, "acme_core").await.expect("claim").expect("claimed");
    assert_eq!(claim.org_id, h.org);

    // Blob: content-addressed key, exact bytes.
    assert_eq!(outcome.blob_key, format!("pub/{}/{}.tar.gz", &expected_sha[..2], expected_sha));
    assert_eq!(h.blob.keys(), vec![outcome.blob_key.clone()]);
    let stored = h.blob_bytes(&outcome.blob_key).await;
    assert_eq!(stored, archive, "the exact uploaded bytes must be stored (protocol sharp edge 3)");
    assert_eq!(hex_sha256(&stored), expected_sha);

    // Audit + domain event.
    assert_eq!(h.audit_actions().await, vec![("package.publish".to_owned(), AuditResult::Success)]);
    assert_eq!(h.events.names(), vec!["package.publish"]);
    match h.events.last() {
        DomainEvent::PackagePublished { name, version, package_created, org_id, .. } => {
            assert_eq!((name.as_str(), version.as_str(), package_created, org_id), ("acme_core", "1.0.0", true, h.org));
        }
        other => panic!("expected a publish event, got {other:?}"),
    }
}

#[tokio::test]
async fn readme_and_changelog_are_rendered_sanitized_and_stored_on_the_version() {
    let h = Harness::new().await;
    let readme = "# Title\n\n<script>alert(1)</script>\n\n[link](https://example.com) ![x](/relative.png)\n";
    let archive = package("acme_core", "1.0.0", &[("README.md", readme), ("CHANGELOG.md", "## 1.0.0\n- first")]);

    let outcome = h.service.publish(h.request(archive), t0()).await.expect("publish");

    let html = outcome.version.readme_html.expect("readme html");
    assert!(html.contains("<h1>Title</h1>"), "{html}");
    assert!(!html.contains("<script"), "S-11: raw HTML must not survive: {html}");
    assert!(html.contains("nofollow"), "S-11: links carry rel tokens: {html}");
    assert!(!html.contains("/relative.png"), "S-11: relative image sources are dropped: {html}");
    assert!(outcome.version.changelog_html.expect("changelog html").contains("<li>first</li>"));

    // No README/CHANGELOG in the archive means NULL, not an empty string.
    let bare = h
        .service
        .publish(h.request(package("acme_core", "1.1.0", &[])), t0() + Duration::minutes(1))
        .await
        .expect("publish");
    assert_eq!(bare.version.readme_html, None);
    assert_eq!(bare.version.changelog_html, None);
}

#[tokio::test]
async fn republishing_a_version_is_a_distinct_conflict() {
    let h = Harness::new().await;
    h.service.publish(h.request(package("acme_core", "1.0.0", &[])), t0()).await.expect("first publish");

    // Same bytes.
    let err = h
        .service
        .publish(h.request(package("acme_core", "1.0.0", &[])), t0() + Duration::minutes(1))
        .await
        .expect_err("duplicate version");
    assert_eq!(err.code(), "conflict");

    // Different bytes, same version: still a conflict — versions are immutable (S-18).
    let err = h
        .service
        .publish(h.request(package("acme_core", "1.0.0", &[("lib/a.dart", "// changed")])), t0())
        .await
        .expect_err("duplicate version with different content");
    assert_eq!(err.code(), "conflict");

    // Both failures are audited, and only one version exists.
    let audit = h.audit_actions().await;
    assert_eq!(audit.iter().filter(|(_, result)| *result == AuditResult::Failure).count(), 2);
    // S-22: and the audit trail names *what* was refused. The pub protocol pins no name
    // (publish step 1 carries none), so without the pipeline reporting the parsed name back,
    // every rejected publish would land in the log as an anonymous failure.
    let failures = h
        .repos
        .audit
        .list(&AuditFilter::default(), None, 100)
        .await
        .expect("audit list")
        .items
        .into_iter()
        .filter(|event| event.result == AuditResult::Failure)
        .collect::<Vec<_>>();
    for event in &failures {
        assert_eq!(event.target.as_deref(), Some("acme_core@1.0.0"), "a rejected publish must name its package");
    }
    let package = h.repos.packages.get_by_name(Format::Pub, "acme_core").await.expect("get").expect("package");
    let versions = h.repos.packages.list_versions(package.id, None, 50).await.expect("list");
    assert_eq!(versions.items.len(), 1);
}

#[tokio::test]
async fn a_name_claimed_by_another_org_cannot_be_published_to() {
    let h = Harness::new().await;
    h.service.publish(h.request(package("acme_core", "1.0.0", &[])), t0()).await.expect("first publish");

    let intruder = h.other_org().await;
    let mut request = h.request(package("acme_core", "2.0.0", &[]));
    request.org_id = intruder;
    let err = h.service.publish(request, t0() + Duration::minutes(1)).await.expect_err("foreign claim");
    assert_eq!(err.code(), "forbidden");
    // The message may name the package (the caller supplied it) but never its owner.
    assert!(!err.to_string().contains(&h.org.to_string()), "the message must not identify the holder: {err}");

    // S-04: a *version that already exists* must not answer differently from one that does
    // not. "Version 1.0.0 already exists" in response to a foreign name is a version-existence
    // oracle for somebody else's private package, spendable one publish attempt at a time.
    let mut collide = h.request(package("acme_core", "1.0.0", &[]));
    collide.org_id = intruder;
    let same = h.service.publish(collide, t0() + Duration::minutes(2)).await.expect_err("foreign claim");
    assert_eq!(same.code(), "forbidden");
    assert_eq!(same.to_string(), err.to_string(), "an existing version must be indistinguishable from a new one");
}

#[tokio::test]
async fn the_pubspec_must_match_the_name_the_upload_was_authorized_for() {
    let h = Harness::new().await;
    let mut request = h.request(package("other_pkg", "1.0.0", &[]));
    request.expected_name = Some("acme_core".to_owned());

    let err = h.service.publish(request, t0()).await.expect_err("name mismatch");
    assert_eq!(err.code(), "invalid_argument");
    // Nothing was stored.
    assert!(h.blob.keys().is_empty());
    assert!(h.repos.packages.lookup_claim(Format::Pub, "other_pkg").await.expect("claim").is_none());
}

#[tokio::test]
async fn s13_a_pattern_scoped_token_cannot_claim_a_name_outside_its_patterns() {
    // Publish step 1 carries no package name (docs/protocol.md endpoint 2), so the pattern
    // narrowing has nowhere to be enforced but here — and it has to run before the claim, or
    // a narrowed token would burn a name it may not have.
    let h = Harness::new().await;
    let mut request = h.request(package("other_pkg", "1.0.0", &[]));
    request.package_patterns = vec!["acme_*".to_owned()];

    let err = h.service.publish(request, t0()).await.expect_err("outside the patterns");
    assert_eq!(err.code(), "forbidden");
    assert!(h.blob.keys().is_empty(), "a refused publish must never reach the blob store");
    assert!(h.repos.packages.lookup_claim(Format::Pub, "other_pkg").await.expect("claim").is_none());

    // A name inside the patterns publishes normally.
    let mut allowed = h.request(package("acme_core", "1.0.0", &[]));
    allowed.package_patterns = vec!["acme_*".to_owned()];
    h.service.publish(allowed, t0() + Duration::minutes(1)).await.expect("inside the patterns");
}

#[tokio::test]
async fn an_oversized_upload_is_rejected_before_any_storage_work() {
    let policy = RegistryPolicy {
        archive: ArchiveLimits { max_archive_bytes: 32, ..ArchiveLimits::default() },
        ..RegistryPolicy::default()
    };
    let h = Harness::with_policy(policy).await;

    let err = h.service.publish(h.request(package("acme_core", "1.0.0", &[])), t0()).await.expect_err("too large");
    assert_eq!(err.code(), "invalid_argument");
    assert!(h.blob.keys().is_empty(), "a rejected upload must never reach the blob store");
    assert_eq!(h.audit_actions().await, vec![("package.publish".to_owned(), AuditResult::Failure)]);
}

#[tokio::test]
async fn a_held_publish_lock_makes_a_concurrent_publish_conflict_not_race() {
    let h = Harness::new().await;
    // Simulate another instance mid-publish of the same name.
    let held = h
        .lock
        .try_acquire("publish:pub:acme_core", std::time::Duration::from_secs(60))
        .await
        .expect("acquire")
        .expect("the lock is free");

    let err = h.service.publish(h.request(package("acme_core", "1.0.0", &[])), t0()).await.expect_err("locked");
    // `busy`, not `conflict`: the lock failure is transient, and it must stay structurally
    // distinguishable from the permanent duplicate-version conflict so the API layer can keep
    // a staged upload alive across it.
    assert_eq!(err.code(), "busy");
    assert!(h.blob.keys().is_empty());

    // Once released, the same publish succeeds — and the lock is given back afterwards.
    h.lock.release("publish:pub:acme_core", held).await.expect("release");
    h.service.publish(h.request(package("acme_core", "1.0.0", &[])), t0()).await.expect("publish after release");
    assert!(
        h.lock
            .try_acquire("publish:pub:acme_core", std::time::Duration::from_secs(1))
            .await
            .expect("acquire")
            .is_some(),
        "the service must release its lock"
    );
}

#[tokio::test]
async fn a_publish_of_another_version_reuses_the_package_and_claim() {
    let h = Harness::new().await;
    let first = h.service.publish(h.request(package("acme_core", "1.0.0", &[])), t0()).await.expect("1.0.0");
    let second = h
        .service
        .publish(h.request(package("acme_core", "1.1.0", &[])), t0() + Duration::hours(1))
        .await
        .expect("1.1.0");

    assert!(!second.package_created);
    assert_eq!(second.package.id, first.package.id);
    let versions = h.repos.packages.list_versions(first.package.id, None, 50).await.expect("list");
    let listed: Vec<String> = versions.items.iter().map(|v| v.version.to_string()).collect();
    assert_eq!(listed, vec!["1.0.0", "1.1.0"]);
}

#[tokio::test]
async fn retract_then_restore_inside_the_window_then_conflict_outside_it() {
    let h = Harness::new().await;
    h.service.publish(h.request(package("acme_core", "1.0.0", &[])), t0()).await.expect("publish");

    let retract = |retracted: bool| RetractRequest {
        format: Format::Pub,
        org_id: h.org,
        name: "acme_core".to_owned(),
        version: semver("1.0.0"),
        retracted,
        actor: ActorMeta::user(h.user),
    };

    let retracted = h.service.set_retracted(retract(true), t0() + Duration::hours(1)).await.expect("retract");
    assert_eq!(retracted.retracted_at, Some(t0() + Duration::hours(1)));

    // Restoring inside the 7-day window is allowed…
    let restored = h.service.set_retracted(retract(false), t0() + Duration::days(6)).await.expect("restore");
    assert!(!restored.is_retracted());

    // …and outside it is not.
    h.service.set_retracted(retract(true), t0() + Duration::days(7)).await.expect("retract again");
    let err = h
        .service
        .set_retracted(retract(false), t0() + Duration::days(7) + Duration::days(8))
        .await
        .expect_err("restore window has passed");
    assert_eq!(err.code(), "conflict");

    // Restoring a version that was never retracted is a conflict too.
    h.service
        .publish(h.request(package("acme_core", "2.0.0", &[])), t0() + Duration::days(1))
        .await
        .expect("publish 2.0.0");
    let err = h
        .service
        .set_retracted(
            RetractRequest { version: semver("2.0.0"), ..retract(false) },
            t0() + Duration::days(1) + Duration::hours(1),
        )
        .await
        .expect_err("not retracted");
    assert_eq!(err.code(), "conflict");

    let names = h.events.names();
    assert_eq!(names.iter().filter(|name| *name == "package.retract").count(), 3);
}

#[tokio::test]
async fn retraction_targets_only_packages_the_org_owns() {
    let h = Harness::new().await;
    h.service.publish(h.request(package("acme_core", "1.0.0", &[])), t0()).await.expect("publish");
    let intruder = h.other_org().await;

    let err = h
        .service
        .set_retracted(
            RetractRequest {
                format: Format::Pub,
                org_id: intruder,
                name: "acme_core".to_owned(),
                version: semver("1.0.0"),
                retracted: true,
                actor: ActorMeta::user(h.user),
            },
            t0(),
        )
        .await
        .expect_err("foreign package");
    // S-04: another org's package is indistinguishable from a name that does not exist.
    assert_eq!(err.code(), "not_found");
}

#[tokio::test]
async fn hard_delete_burns_the_number_and_removes_the_bytes() {
    let h = Harness::new().await;
    let published = h
        .service
        .publish(h.request(package("acme_core", "1.0.0", &[("README.md", "secret")])), t0())
        .await
        .expect("publish");

    let outcome = h
        .service
        .hard_delete(
            HardDeleteRequest {
                format: Format::Pub,
                reason: Some("leaked credential".to_owned()),
                org_id: h.org,
                name: "acme_core".to_owned(),
                version: semver("1.0.0"),
                actor: ActorMeta::user(h.user),
            },
            t0() + Duration::hours(1),
        )
        .await
        .expect("hard delete");

    assert!(outcome.blob_removed);
    assert!(outcome.version.tombstone);
    // The leaked-secret remedy actually removes the content.
    assert_eq!(outcome.version.pubspec, serde_json::json!({}));
    assert_eq!(outcome.version.readme_html, None);
    assert!(h.blob.keys().is_empty(), "the archive bytes must be gone");

    // The version disappears from listings but the number stays burned (S-18).
    let versions = h.repos.packages.list_versions(published.package.id, None, 50).await.expect("list");
    assert!(versions.items.is_empty());
    let err = h
        .service
        .publish(h.request(package("acme_core", "1.0.0", &[])), t0() + Duration::days(1))
        .await
        .expect_err("republishing a burned number");
    assert_eq!(err.code(), "conflict");

    assert_eq!(h.events.names().last().map(String::as_str), Some("package.hard_delete"));
    assert!(h.audit_actions().await.iter().any(|(action, _)| action == "package.hard_delete"));
}

#[tokio::test]
async fn hard_delete_keeps_bytes_another_live_version_still_references() {
    let h = Harness::new().await;
    let published = h.service.publish(h.request(package("acme_core", "1.0.0", &[])), t0()).await.expect("publish");
    let sha = published.version.archive_sha256.clone();

    // A second package pointing at the same content hash — possible via the proxy cache and
    // via byte-identical uploads; either way the blob is shared.
    h.repos
        .packages
        .create_version(
            NewVersion {
                format: Format::Pub,
                package_name: "acme_mirror".to_owned(),
                org_id: h.org,
                visibility: Visibility::Private,
                version: semver("1.0.0"),
                pubspec: serde_json::json!({"name": "acme_mirror", "version": "1.0.0"}),
                archive_sha256: sha.clone(),
                archive_size: published.version.archive_size,
                published_by: Publisher { user_id: h.user, token_id: None },
                readme_html: None,
                changelog_html: None,
            },
            t0(),
        )
        .await
        .expect("second version sharing the blob");

    let outcome = h
        .service
        .hard_delete(
            HardDeleteRequest {
                format: Format::Pub,
                reason: Some("leaked credential".to_owned()),
                org_id: h.org,
                name: "acme_core".to_owned(),
                version: semver("1.0.0"),
                actor: ActorMeta::user(h.user),
            },
            t0() + Duration::hours(1),
        )
        .await
        .expect("hard delete");

    assert!(!outcome.blob_removed, "shared bytes must survive: another version still serves this hash");
    assert_eq!(h.blob.keys(), vec![RegistryService::blob_key(Format::Pub, &sha)]);
}

#[tokio::test]
async fn hard_deleting_twice_is_a_conflict_and_unknown_versions_are_not_found() {
    let h = Harness::new().await;
    h.service.publish(h.request(package("acme_core", "1.0.0", &[])), t0()).await.expect("publish");
    let request = |version: &str| HardDeleteRequest {
        format: Format::Pub,
        reason: Some("leaked credential".to_owned()),
        org_id: h.org,
        name: "acme_core".to_owned(),
        version: semver(version),
        actor: ActorMeta::user(h.user),
    };

    h.service.hard_delete(request("1.0.0"), t0()).await.expect("first delete");
    assert_eq!(h.service.hard_delete(request("1.0.0"), t0()).await.expect_err("twice").code(), "conflict");
    assert_eq!(h.service.hard_delete(request("9.9.9"), t0()).await.expect_err("unknown").code(), "not_found");
}

#[tokio::test]
async fn the_publish_audit_event_carries_provenance_and_archive_facts() {
    let h = Harness::new().await;
    let archive = package("acme_core", "1.0.0", &[("lib/a.dart", "void main() {}")]);
    let sha = hex_sha256(&archive);
    h.service.publish(h.request(archive.clone()), t0()).await.expect("publish");

    let page = h.repos.audit.list(&AuditFilter::default(), None, 10).await.expect("audit");
    let event = page.items.first().expect("audit event");
    assert_eq!(event.action, "package.publish");
    assert_eq!(event.actor, AuditActor::User(h.user));
    assert_eq!(event.org_id, Some(h.org));
    assert_eq!(event.target.as_deref(), Some("acme_core@1.0.0"));
    assert_eq!(event.ip.as_deref(), Some("203.0.113.7"));
    let metadata = event.metadata.as_ref().expect("metadata");
    assert_eq!(metadata["sha256"], sha);
    assert_eq!(metadata["package"], "acme_core");
    assert_eq!(metadata["entries"], 2);
    assert_eq!(metadata["package_created"], true);
}

// ------------------------------------------------- the per-org storage quota (S-20.b, D21)

/// **S-20.b.** The authoritative refusal runs *before* the blob write, so a publish an org has
/// no room for costs the store nothing.
///
/// Shaped like [`an_oversized_upload_is_rejected_before_any_storage_work`], and for the same
/// reason: "refused" and "refused before it cost anything" are different claims, and only the
/// second one bounds storage. A check placed after `blob.put` would pass every assertion about
/// the error and still let an org past its quota one unreferenced archive at a time.
#[tokio::test]
async fn s20_b_a_publish_past_the_quota_is_refused_before_any_blob_write() {
    let h = Harness::new().await;
    let archive = package("acme_core", "1.0.0", &[]);

    let err = h
        .service
        .publish(h.request_under_quota(archive.clone(), 10), t0())
        .await
        .expect_err("an archive larger than the whole quota");

    // Permanent 4xx class, never `rate_limited`: the pub client retries a 429 seven times and
    // no amount of waiting frees storage (docs/protocol.md sharp edge 2).
    assert_eq!(err.code(), "invalid_argument");
    assert!(err.to_string().contains("quota"), "the publisher must be told what happened: {err}");
    assert!(h.blob.keys().is_empty(), "a quota refusal must never reach the blob store");
    // Nothing else happened either: no claim burned, no version row, one audited failure.
    assert!(h.repos.packages.lookup_claim(Format::Pub, "acme_core").await.expect("claim").is_none());
    assert_eq!(h.audit_actions().await, vec![("package.publish".to_owned(), AuditResult::Failure)]);
    assert!(h.events.names().is_empty(), "a refused publish announces nothing");
    assert_eq!(h.storage_bytes().await, 0);
}

/// **S-20.b.** The boundary: a publish that lands exactly on the quota is inside it, and the
/// byte after that is not. The quota is what an org may *hold*, not the last byte before it.
#[tokio::test]
async fn s20_b_a_publish_lands_exactly_on_the_quota_and_the_next_one_does_not_fit() {
    let h = Harness::new().await;
    let first = package("acme_core", "1.0.0", &[]);
    let second = package("acme_core", "1.1.0", &[("lib/a.dart", "void main() {}")]);
    let (n1, n2) = (first.len() as u64, second.len() as u64);

    // Exactly the archive's own size: allowed, and it fills the quota to the last byte.
    h.service.publish(h.request_under_quota(first, n1), t0()).await.expect("a publish may fill the quota exactly");
    assert_eq!(h.storage_bytes().await, n1 as i64);

    // One byte short of the pair: refused.
    let err = h
        .service
        .publish(h.request_under_quota(second.clone(), n1 + n2 - 1), t0() + Duration::minutes(1))
        .await
        .expect_err("one byte short");
    assert_eq!(err.code(), "invalid_argument");
    assert_eq!(h.blob.keys().len(), 1, "only the first publish's bytes are stored");

    // Exactly the pair: allowed.
    h.service
        .publish(h.request_under_quota(second, n1 + n2), t0() + Duration::minutes(2))
        .await
        .expect("landing exactly on the quota");
    assert_eq!(h.storage_bytes().await, (n1 + n2) as i64);
}

/// **S-20.b.** Retracted versions still count; tombstoned ones do not.
///
/// The two halves are one rule — "what is still stored" — and they are the difference between a
/// quota an org can free and one it cannot. A retracted version is still downloadable (sharp
/// edge 9), so its bytes are still on disk; a hard delete is the operation that actually
/// reclaims them, and is therefore the only way an org gets room back.
#[tokio::test]
async fn s20_b_a_retracted_version_still_counts_and_a_tombstoned_one_does_not() {
    let h = Harness::new().await;
    let first = package("acme_core", "1.0.0", &[]);
    let second = package("acme_core", "2.0.0", &[("lib/a.dart", "// two")]);
    let (n1, n2) = (first.len() as u64, second.len() as u64);

    h.service.publish(h.request_under_quota(first, n1), t0()).await.expect("publish 1.0.0");
    h.service
        .set_retracted(
            RetractRequest {
                format: Format::Pub,
                org_id: h.org,
                name: "acme_core".to_owned(),
                version: semver("1.0.0"),
                retracted: true,
                actor: ActorMeta::user(h.user),
            },
            t0() + Duration::minutes(1),
        )
        .await
        .expect("retract");

    // Still charged: retraction is a resolution signal, not a delete.
    assert_eq!(h.storage_bytes().await, n1 as i64, "a retracted version's bytes are still stored");
    let err = h
        .service
        .publish(h.request_under_quota(second.clone(), n1 + n2 - 1), t0() + Duration::minutes(2))
        .await
        .expect_err("the retracted version still occupies the quota");
    assert_eq!(err.code(), "invalid_argument");

    // A hard delete is how an org frees space — and the same publish then fits.
    h.service
        .hard_delete(
            HardDeleteRequest {
                format: Format::Pub,
                org_id: h.org,
                name: "acme_core".to_owned(),
                version: semver("1.0.0"),
                reason: Some("freeing space".to_owned()),
                actor: ActorMeta::user(h.user),
            },
            t0() + Duration::minutes(3),
        )
        .await
        .expect("hard delete");
    assert_eq!(h.storage_bytes().await, 0, "a tombstone's bytes are collectable and stop counting");
    h.service
        .publish(h.request_under_quota(second, n2), t0() + Duration::minutes(4))
        .await
        .expect("the freed space is usable");
}

/// **S-20.b.** Two versions sharing one `archive_sha256` are **both** charged.
///
/// Deliberate over-counting, following `RegistryStats::archive_bytes`. Crediting the dedupe
/// would make one org's quota depend on another org's behaviour — a stranger publishing
/// identical bytes would silently give this org room back, and taking their version down would
/// silently take it away again. That is not a quota.
#[tokio::test]
async fn s20_b_two_versions_sharing_one_archive_sha256_are_both_charged() {
    let h = Harness::new().await;
    let archive = package("acme_core", "1.0.0", &[]);
    let size = archive.len() as i64;
    let published = h.service.publish(h.request(archive), t0()).await.expect("publish");

    // A second package pointing at the same content hash — byte-identical uploads and the proxy
    // cache both produce this, and the blob store holds exactly one object for the pair.
    h.repos
        .packages
        .create_version(
            NewVersion {
                format: Format::Pub,
                package_name: "acme_mirror".to_owned(),
                org_id: h.org,
                visibility: Visibility::Private,
                version: semver("1.0.0"),
                pubspec: serde_json::json!({ "name": "acme_mirror", "version": "1.0.0" }),
                archive_sha256: published.version.archive_sha256.clone(),
                archive_size: size,
                published_by: Publisher { user_id: h.user, token_id: None },
                readme_html: None,
                changelog_html: None,
            },
            t0(),
        )
        .await
        .expect("second version sharing the blob");

    assert_eq!(h.blob.keys().len(), 1, "one object backs both versions");
    assert_eq!(h.storage_bytes().await, 2 * size, "and both versions are charged for it");

    // The discriminator: under a quota that is exactly the over-counted total there is no room
    // left, while a dedupe-crediting implementation would still see half of it free.
    let third = package("acme_other", "1.0.0", &[]);
    let third_size = third.len() as u64;
    let err = h
        .service
        .publish(h.request_under_quota(third.clone(), (2 * size) as u64), t0() + Duration::minutes(1))
        .await
        .expect_err("the shared bytes are counted twice");
    assert_eq!(err.code(), "invalid_argument");
    h.service
        .publish(h.request_under_quota(third, (2 * size) as u64 + third_size), t0() + Duration::minutes(2))
        .await
        .expect("room for the third archive");
}

/// **S-20.b.** The 80 % warning is edge-triggered: one event on the publish that crosses the
/// line, nothing from the publishes above it, and nothing at all when the quota is unlimited.
///
/// Level-triggering here would be a notification per publish for an org that is simply full,
/// which is decision 29's rule the other way round — and the org near its wall is exactly the
/// org that publishes most often.
#[tokio::test]
async fn s20_b_the_eighty_percent_warning_fires_once_on_the_crossing_and_not_above_it() {
    const QUOTA: u64 = 100_000;
    const THRESHOLD: i64 = 80_000;

    let h = Harness::new().await;
    // The crossing lands **exactly on** the threshold, which is the only landing that pins
    // "at or above" as both normative documents word it. A baseline of `THRESHOLD - 1` plus an
    // archive whose size the test does not control lands somewhere well past the line, where a
    // mutant that loosened *either* comparison by one — `after > threshold`, or
    // `before > threshold` on the publish above — survives. The archive is measured first and
    // the baseline is chosen to complete it.
    let crossing = package("acme_core", "1.0.0", &[]);
    let baseline = THRESHOLD - crossing.len() as i64;
    h.seed_sized_version("acme_seed", "1.0.0", baseline).await;
    assert_eq!(h.storage_bytes().await, baseline);

    let crossed_at = THRESHOLD;
    h.service.publish(h.request_under_quota(crossing, QUOTA), t0()).await.expect("the crossing publish");
    assert_eq!(h.storage_bytes().await, THRESHOLD, "the crossing publish lands on the line, not past it");

    let warnings: Vec<DomainEvent> = h
        .events
        .events
        .lock()
        .expect("events mutex")
        .iter()
        .filter(|event| event.name() == "org.storage_quota")
        .cloned()
        .collect();
    assert_eq!(warnings.len(), 1, "exactly one warning on the crossing");
    match &warnings[0] {
        DomainEvent::OrgStorageQuotaWarning { org_id, used_bytes, quota_bytes, at } => {
            assert_eq!(*org_id, h.org);
            assert_eq!(*used_bytes, crossed_at, "the warning reports usage after the publish that crossed");
            assert_eq!(*quota_bytes, QUOTA);
            // D49: the stamp is the publish's own instant, not a wall clock — a variant that
            // omitted it would file an unclaimable fan-out row behind a pinned test clock.
            assert_eq!(*at, t0());
        }
        other => panic!("expected a quota warning, got {other:?}"),
    }

    // Already **exactly at** the line: the next publish says nothing. Sitting on the threshold
    // rather than above it is what makes this kill the `before > threshold` mutant, which would
    // read "at the line" as "still below it" and warn a second time.
    h.service
        .publish(h.request_under_quota(package("acme_core", "1.1.0", &[]), QUOTA), t0() + Duration::minutes(1))
        .await
        .expect("a second publish under the same quota");
    assert_eq!(
        h.events.names().iter().filter(|name| *name == "org.storage_quota").count(),
        1,
        "the state is not the signal; the crossing is"
    );

    // And an unlimited org never warns, however full it gets: there is no line.
    let unlimited = Harness::new().await;
    unlimited.seed_sized_version("acme_seed", "1.0.0", 10_000_000).await;
    unlimited
        .service
        .publish(unlimited.request(package("acme_core", "1.0.0", &[])), t0())
        .await
        .expect("unlimited publish");
    assert!(
        !unlimited.events.names().iter().any(|name| name == "org.storage_quota"),
        "0 / NULL is unlimited, and unlimited has no 80 %"
    );
}

/// **S-20.b.** The quota is per org: one org filling its quota does not touch another's.
#[tokio::test]
async fn s20_b_the_quota_is_charged_to_the_publishing_org_alone() {
    let h = Harness::new().await;
    let archive = package("acme_core", "1.0.0", &[]);
    let size = archive.len() as u64;
    h.service.publish(h.request_under_quota(archive, size), t0()).await.expect("acme fills its quota");

    let other = h.other_org().await;
    let neighbour = package("other_pkg", "1.0.0", &[]);
    let neighbour_size = neighbour.len() as u64;
    let mut request = h.request_under_quota(neighbour, neighbour_size);
    request.org_id = other;
    h.service.publish(request, t0() + Duration::minutes(1)).await.expect("the second org has its own room");
    assert_eq!(h.repos.packages.org_storage_bytes(other).await.expect("bytes"), neighbour_size as i64);
    // …and acme's own full quota is unchanged by the neighbour's publish.
    assert_eq!(h.storage_bytes().await, size as i64);
}

// --------------------------------------------- the quota and package transfer (S-20.b, D21)

/// **S-20.b.** A transfer spends the **receiving** org's storage quota, and one that does not
/// fit is refused with the publish path's permanent 400.
///
/// This is the quota's one unbounded bypass if it is left unchecked, and it is trivially
/// reachable by design: `owned_package` needs Owner in both orgs, which one person routinely is.
/// `org_storage_bytes` attributes by the current `packages.org_id`, so every live version
/// re-attributes the instant the row updates — publish into a fresh org, transfer into the
/// walled one, repeat, at rest and for ever. Decision 32 promises a bound that is "exact at rest
/// and loose by at most one round of in-flight publishes"; a transfer is neither.
#[tokio::test]
async fn s20_b_a_transfer_into_a_full_org_is_refused_and_moves_nothing() {
    let h = Harness::new().await;
    let receiver = h.other_org().await;

    // The receiver is at its wall: one archive stored, quota exactly that size.
    let sitting = package("other_pkg", "1.0.0", &[]);
    let wall = sitting.len() as u64;
    let mut seed = h.request_under_quota(sitting, wall);
    seed.org_id = receiver;
    h.service.publish(seed, t0()).await.expect("the receiver fills its own quota");

    // The sender publishes a package of its own, under no quota at all.
    let moving = package("acme_core", "1.0.0", &[]);
    let moving_size = moving.len() as i64;
    h.service.publish(h.request(moving), t0() + Duration::minutes(1)).await.expect("publish into the sending org");

    let err = h
        .service
        .transfer(h.transfer_request("acme_core", receiver, Some(wall)), t0() + Duration::minutes(2))
        .await
        .expect_err("the receiver has no room");
    // The publish path's class, and for the same reason: no amount of waiting frees storage,
    // and a 429 is a lie the pub client acts on seven times (sharp edge 2).
    assert_eq!(err.code(), "invalid_argument");
    assert!(err.to_string().contains("quota"), "the caller must be told what happened: {err}");

    // Nothing moved: the row, the claim, and both byte totals are where they were.
    let package = h.repos.packages.get_by_name(Format::Pub, "acme_core").await.expect("get").expect("package");
    assert_eq!(package.org_id, h.org, "a refused transfer must not move the row");
    assert_eq!(h.storage_bytes().await, moving_size, "the sender still holds its bytes");
    assert_eq!(h.repos.packages.org_storage_bytes(receiver).await.expect("bytes"), wall as i64);
    assert!(
        !h.events.names().iter().any(|name| name == "package.transfer"),
        "a refused transfer emits no transfer event"
    );
}

/// **S-20.b.** A transfer that fits moves the bytes across: the receiver gains them, the sender
/// loses them, and the sum is conserved.
///
/// The sending half is the assertion that pins *why* the check is on the receiver only: bytes
/// leave the sender in the same instant, so a transfer can never take the sender over anything.
#[tokio::test]
async fn s20_b_a_transfer_that_fits_moves_the_bytes_off_the_sender_and_onto_the_receiver() {
    let h = Harness::new().await;
    let receiver = h.other_org().await;

    let moving = package("acme_core", "1.0.0", &[]);
    let moving_size = moving.len() as i64;
    // A second, tombstoned version of the same package: its bytes are collectable, so they must
    // not be charged to the receiver — the transfer moves *live* bytes, like every other reading
    // of the quota.
    h.service.publish(h.request(moving), t0()).await.expect("publish");
    h.seed_sized_version("acme_core", "0.9.0", 5_000).await;
    let dead = h
        .repos
        .packages
        .get_version(
            h.repos.packages.get_by_name(Format::Pub, "acme_core").await.expect("get").expect("package").id,
            &semver("0.9.0"),
        )
        .await
        .expect("get version")
        .expect("0.9.0");
    h.repos.packages.hard_delete_version(dead.id).await.expect("tombstone");
    assert_eq!(h.storage_bytes().await, moving_size, "the tombstone is not part of what moves");

    // Room for exactly the live bytes and not a byte more.
    h.service
        .transfer(h.transfer_request("acme_core", receiver, Some(moving_size as u64)), t0() + Duration::minutes(1))
        .await
        .expect("a transfer that lands exactly on the receiver's quota");

    assert_eq!(h.storage_bytes().await, 0, "the sending org's usage drops by what left");
    assert_eq!(
        h.repos.packages.org_storage_bytes(receiver).await.expect("bytes"),
        moving_size,
        "and the receiving org's rises by the same amount"
    );

    // The crossing warning fires for the **receiver**, deliberately: a transfer is the largest
    // jump an org's usage can make, and because the signal is edge-triggered an org that landed
    // above the line here would otherwise never be warned at all — the next publish would see
    // itself already above 80 % and stay silent.
    let warnings: Vec<DomainEvent> = h
        .events
        .events
        .lock()
        .expect("events mutex")
        .iter()
        .filter(|event| event.name() == "org.storage_quota")
        .cloned()
        .collect();
    assert_eq!(warnings.len(), 1, "one warning, for the org that crossed");
    match &warnings[0] {
        DomainEvent::OrgStorageQuotaWarning { org_id, used_bytes, quota_bytes, at } => {
            assert_eq!(*org_id, receiver, "the receiver crossed; the sender only ever goes down");
            assert_eq!(*used_bytes, moving_size);
            assert_eq!(*quota_bytes, moving_size as u64);
            assert_eq!(*at, t0() + Duration::minutes(1), "D49: the operation's own instant, not a wall clock");
        }
        other => panic!("expected a quota warning, got {other:?}"),
    }
}

/// **S-20.b.** An unlimited receiver accepts anything, and costs nothing to establish.
///
/// `0` and `NULL` both resolve to `None` before the service ever sees them
/// (`effective_storage_quota`), so "unlimited" here is one missing number rather than a very
/// large one — and a default install is exactly this case.
#[tokio::test]
async fn s20_b_an_unlimited_receiver_accepts_a_transfer_of_any_size() {
    let h = Harness::new().await;
    let receiver = h.other_org().await;

    h.service.publish(h.request(package("acme_core", "1.0.0", &[])), t0()).await.expect("publish");
    h.seed_sized_version("acme_core", "2.0.0", 10_000_000).await;
    let total = h.storage_bytes().await;

    h.service
        .transfer(h.transfer_request("acme_core", receiver, None), t0() + Duration::minutes(1))
        .await
        .expect("an unlimited receiver has room for anything");

    assert_eq!(h.repos.packages.org_storage_bytes(receiver).await.expect("bytes"), total);
    assert_eq!(h.storage_bytes().await, 0);
    // No line, so no crossing to report however full the receiver gets.
    assert!(!h.events.names().iter().any(|name| name == "org.storage_quota"), "unlimited has no 80 %");
}

// ------------------------------------------------------- the indexer's cost (D23, decision 32)

#[tokio::test]
async fn d23_building_a_document_does_not_walk_the_version_list() {
    // The publish path calls `build_document` inside the publisher's HTTP request, on every
    // publish, retraction, option change, hard delete and transfer. It used to page through
    // *every* live version at 200 a page — materializing whole rows (pubspec JSON, rendered
    // README HTML) — to use exactly two of them plus a length.
    let h = Harness::new().await;
    h.service.publish(h.request(package("acme_core", "9.0.0", &[("README.md", "# acme")])), t0()).await.expect("seed");
    // Comfortably more than one page of the newest-first scan, so a walk and a bounded scan
    // are distinguishable by query count rather than by luck.
    h.seed_versions("acme_core", (1..=350).map(|i| format!("1.{i}.0"))).await;
    let package = h.repos.packages.get_by_name(Format::Pub, "acme_core").await.expect("get").expect("package");

    let (repos, counts) = h.counting();
    let document = build_document(&repos, &package).await.expect("build").expect("indexable");

    // The length is an aggregate, not a walk — and it is still right.
    assert_eq!(document.versions_count, 351);
    assert_eq!(counts.count_versions.load(Ordering::Relaxed), 1, "the count must be one aggregate query");
    // Newest first, and the newest version here is a live stable, so the rule settles on the
    // first row of the first page.
    assert_eq!(counts.list_versions_desc.load(Ordering::Relaxed), 1, "the scan must stop at the first live stable");
    assert_eq!(counts.list_versions.load(Ordering::Relaxed), 0, "the ascending walk is what D23 removed");
    assert_eq!(document.latest_version, "9.0.0");
}

#[tokio::test]
async fn d23_the_indexer_scan_stays_bounded_when_nothing_recent_is_installable() {
    // The pathological package the window exists for: no live stable among the newest
    // LATEST_WINDOW versions. The scan cannot settle early, so this is the case where an
    // unbounded walk would be most expensive — and it must still stop at the window.
    let h = Harness::new().await;
    h.service.publish(h.request(package("acme_core", "1.0.0", &[])), t0()).await.expect("seed");
    h.seed_versions("acme_core", (1..=LATEST_WINDOW + 50).map(|i| format!("1.{i}.0-beta"))).await;
    let package = h.repos.packages.get_by_name(Format::Pub, "acme_core").await.expect("get").expect("package");

    let (repos, counts) = h.counting();
    let document = build_document(&repos, &package).await.expect("build").expect("indexable");

    // `versions_count` is the whole history even though the scan saw a window of it.
    assert_eq!(document.versions_count, (LATEST_WINDOW + 51) as i64);
    // The scan's cost is bounded by the window and not by the package: ten pages of a hundred
    // over 1 051 versions. Asserted exactly rather than as "bounded", because an unbounded walk
    // over this package is also "bounded"; if the scan's page size changes, this is the number
    // that has to change with it.
    assert_eq!(
        counts.list_versions_desc.load(Ordering::Relaxed),
        LATEST_WINDOW / 100,
        "the scan must stop at LATEST_WINDOW rows, at 100 rows a page"
    );
    assert_eq!(counts.list_versions.load(Ordering::Relaxed), 0, "the ascending walk is what D23 removed");
    // And the answer is the newest pre-release inside the window, not the stable below it —
    // the divergence decision 32 records, here at the surface that used to walk far enough to
    // see that stable release.
    assert_eq!(document.latest_version, format!("1.{}.0-beta", LATEST_WINDOW + 50));
    assert!(!document.latest_retracted);
}
