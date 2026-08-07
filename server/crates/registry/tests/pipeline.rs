//! Publish-pipeline integration tests: the real service over a real migrated SQLite database,
//! an in-memory blob store, the real in-process [`JobLock`], and a recording event sink.
//!
//! These cover the promises the pipeline makes that no unit test can: the publish is
//! transactional, the stored bytes are byte-identical to the upload, a duplicate version is a
//! distinct conflict, a hard-deleted number stays burned, and every step emits its audit and
//! domain event.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use bytes::Bytes;
use chrono::{DateTime, Duration, TimeZone as _, Utc};
use futures::StreamExt as _;
use pub_config::{DatabaseConfig, DatabaseKind};
use pub_core::audit::{AuditActor, AuditFilter, AuditResult};
use pub_core::event::{DomainEvent, EventSink};
use pub_core::org::NewOrg;
use pub_core::package::{NewVersion, Publisher, Visibility};
use pub_core::traits::{BlobStore, DownloadPlan, Repositories};
use pub_core::user::NewUser;
use pub_core::{Error, Format, OrgId, Result, SemVer, UserId};
use pub_db_sqlite::SqliteDb;
use pub_jobs::{InMemoryJobLock, JobLock};
use pub_registry::publish::{HardDeleteRequest, RegistryService, RetractRequest};
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

    async fn download(&self, key: &str) -> Result<DownloadPlan> {
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
        let cfg = DatabaseConfig { kind: DatabaseKind::Sqlite, url: None, path: ":memory:".to_owned() };
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

    async fn blob_bytes(&self, key: &str) -> Vec<u8> {
        match self.blob.download(key).await.expect("download") {
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
    assert!(h.lock.try_acquire("publish:pub:acme_core", std::time::Duration::from_secs(60)).await.expect("acquire"));

    let err = h.service.publish(h.request(package("acme_core", "1.0.0", &[])), t0()).await.expect_err("locked");
    assert_eq!(err.code(), "conflict");
    assert!(h.blob.keys().is_empty());

    // Once released, the same publish succeeds — and the lock is given back afterwards.
    h.lock.release("publish:pub:acme_core").await.expect("release");
    h.service.publish(h.request(package("acme_core", "1.0.0", &[])), t0()).await.expect("publish after release");
    assert!(
        h.lock.try_acquire("publish:pub:acme_core", std::time::Duration::from_secs(1)).await.expect("acquire"),
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
