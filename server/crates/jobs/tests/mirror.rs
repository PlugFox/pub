//! Mirror sync worker (decision 07 second half, S-17).
//!
//! Drives the real [`MirrorWorker`] over a real migrated SQLite database, a real blob store, and
//! the real [`UpstreamService`] — only the network is scripted, for the same reason the proxy
//! suite scripts it: every behaviour worth asserting here is defined by *when* upstream is
//! asked, and a suite that needs a real pub.dev to prove "it did not ask twice" does not run.
//!
//! | Rule | Test |
//! |------|------|
//! | One instance per tick; no double fetch | [`the_leader_lock_stops_a_second_instance_from_double_fetching`] |
//! | Recent mode picks up a new upstream version | [`recent_mode_picks_up_a_new_upstream_version`] |
//! | Recent mode does not re-ask inside the freshness floor | [`recent_mode_leaves_fresh_snapshots_alone`] |
//! | A full sweep resumes from its cursor after a restart | [`full_mode_resumes_its_sweep_after_a_restart`] |
//! | A claimed name alarms (S-17) and is never mirrored (S-16) | [`a_shadowed_name_alarms_once_and_is_never_mirrored`] |
//! | A dead upstream skips the tick instead of hammering | [`an_open_circuit_skips_the_tick`] |

use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration as StdDuration;

use bytes::Bytes;
use chrono::{DateTime, Duration, TimeZone as _, Utc};
use futures::StreamExt as _;
use pub_blob::ObjectStoreBlob;
use pub_core::Format;
use pub_core::audit::AuditFilter;
use pub_core::event::{DomainEvent, EventSink, NoopEventSink};
use pub_core::traits::{BlobStore, JobLock, Repositories};
use pub_db_sqlite::SqliteDb;
use pub_jobs::{InMemoryJobLock, JobLockTtls, MIRROR_JOB, MirrorMode, MirrorPolicy, MirrorWorker, Scheduler};
use pub_registry::upstream::{UpstreamArchive, UpstreamClient, UpstreamError, UpstreamListing, UpstreamNamePage};
use pub_registry::{UpstreamService, UpstreamServicePolicy};
use serde_json::json;

// ---------------------------------------------------------------------------- scripted upstream

/// A scripted upstream that also serves a package-name index and reports the **peak number of
/// simultaneous listing fetches** — which is how "two instances did not both run the job" is
/// proved rather than asserted.
#[derive(Default)]
struct MockUpstream {
    listings: Mutex<HashMap<String, serde_json::Value>>,
    archives: Mutex<HashMap<String, Bytes>>,
    names: Mutex<Vec<String>>,
    listing_calls: AtomicUsize,
    name_calls: AtomicUsize,
    in_flight: AtomicUsize,
    peak_in_flight: AtomicUsize,
    unavailable: Mutex<bool>,
    delay: Mutex<Option<StdDuration>>,
}

impl MockUpstream {
    fn publish(&self, name: &str, versions: &[(&str, &[u8])]) {
        let entries: Vec<serde_json::Value> = versions
            .iter()
            .map(|(version, bytes)| {
                let url = format!("https://cdn.upstream.test/{name}-{version}.tar.gz");
                self.archives.lock().expect("mock").insert(url.clone(), Bytes::copy_from_slice(bytes));
                json!({
                    "version": version,
                    "archive_url": url,
                    "archive_sha256": pub_registry::hex_sha256(bytes),
                    "pubspec": { "name": name, "version": version, "description": "upstream fixture" },
                })
            })
            .collect();
        self.listings.lock().expect("mock").insert(name.to_owned(), json!({ "name": name, "versions": entries }));
        let mut names = self.names.lock().expect("mock");
        if !names.iter().any(|known| known == name) {
            names.push(name.to_owned());
        }
    }

    /// Adds a name to the index without publishing anything under it (the shadowing case: the
    /// index carries a name whose listing we must never end up storing).
    fn index_only(&self, name: &str) {
        let mut names = self.names.lock().expect("mock");
        if !names.iter().any(|known| known == name) {
            names.push(name.to_owned());
        }
    }

    fn set_unavailable(&self, down: bool) {
        *self.unavailable.lock().expect("mock") = down;
    }

    fn set_delay(&self, delay: StdDuration) {
        *self.delay.lock().expect("mock") = Some(delay);
    }

    fn listing_calls(&self) -> usize {
        self.listing_calls.load(Ordering::SeqCst)
    }

    fn name_calls(&self) -> usize {
        self.name_calls.load(Ordering::SeqCst)
    }

    fn peak_in_flight(&self) -> usize {
        self.peak_in_flight.load(Ordering::SeqCst)
    }

    fn enter(&self) {
        let now = self.in_flight.fetch_add(1, Ordering::SeqCst) + 1;
        self.peak_in_flight.fetch_max(now, Ordering::SeqCst);
    }

    fn leave(&self) {
        self.in_flight.fetch_sub(1, Ordering::SeqCst);
    }
}

#[async_trait::async_trait]
impl UpstreamClient for MockUpstream {
    fn base_url(&self) -> &str {
        "https://upstream.test"
    }

    async fn fetch_listing(&self, name: &str) -> Result<UpstreamListing, UpstreamError> {
        self.listing_calls.fetch_add(1, Ordering::SeqCst);
        self.enter();
        let delay = *self.delay.lock().expect("mock");
        if let Some(delay) = delay {
            tokio::time::sleep(delay).await;
        }
        let result = if *self.unavailable.lock().expect("mock") {
            Err(UpstreamError::Unavailable { message: "scripted outage".to_owned() })
        } else {
            match self.listings.lock().expect("mock").get(name).cloned() {
                Some(document) => UpstreamListing::parse(name, document),
                None => Err(UpstreamError::NotFound),
            }
        };
        self.leave();
        result
    }

    async fn fetch_archive(&self, url: &str) -> Result<UpstreamArchive, UpstreamError> {
        if *self.unavailable.lock().expect("mock") {
            return Err(UpstreamError::Unavailable { message: "scripted outage".to_owned() });
        }
        let bytes = self.archives.lock().expect("mock").get(url).cloned().ok_or(UpstreamError::NotFound)?;
        let len = bytes.len() as u64;
        Ok(UpstreamArchive { content_length: Some(len), body: futures::stream::iter(vec![Ok(bytes)]).boxed() })
    }

    async fn fetch_package_names(&self, cursor: Option<&str>) -> Result<UpstreamNamePage, UpstreamError> {
        self.name_calls.fetch_add(1, Ordering::SeqCst);
        if *self.unavailable.lock().expect("mock") {
            return Err(UpstreamError::Unavailable { message: "scripted outage".to_owned() });
        }
        assert_eq!(cursor, None, "this fixture serves a single page");
        Ok(UpstreamNamePage { names: self.names.lock().expect("mock").clone(), next: None })
    }
}

/// Records emitted domain events (the SSE bus does not exist yet — decision 22).
#[derive(Default)]
struct RecordingEvents {
    events: Mutex<Vec<DomainEvent>>,
}

impl RecordingEvents {
    fn names(&self) -> Vec<&'static str> {
        self.events.lock().expect("events").iter().map(DomainEvent::name).collect()
    }
}

#[async_trait::async_trait]
impl EventSink for RecordingEvents {
    async fn emit(&self, event: DomainEvent) {
        self.events.lock().expect("events").push(event);
    }
}

// ------------------------------------------------------------------------------------ harness

fn t0() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 8, 7, 12, 0, 0).unwrap()
}

struct Harness {
    repos: Repositories,
    blob: Arc<dyn BlobStore>,
    client: Arc<MockUpstream>,
    events: Arc<RecordingEvents>,
    service: Arc<UpstreamService>,
}

impl Harness {
    async fn new() -> Self {
        let cfg = pub_config::DatabaseConfig {
            kind: pub_config::DatabaseKind::Sqlite,
            url: None,
            path: ":memory:".to_owned(),
            ..Default::default()
        };
        let db = SqliteDb::connect(&cfg).await.expect("connect :memory:");
        db.run_migrations().await.expect("migrate");
        let repos = db.repositories();
        let blob: Arc<dyn BlobStore> = Arc::new(ObjectStoreBlob::memory());
        let client = Arc::new(MockUpstream::default());
        let events = Arc::new(RecordingEvents::default());
        let service = Arc::new(UpstreamService::new(
            repos.clone(),
            Arc::clone(&blob),
            Arc::clone(&client) as Arc<dyn UpstreamClient>,
            Arc::clone(&events) as Arc<dyn EventSink>,
            UpstreamServicePolicy::default(),
        ));
        Self { repos, blob, client, events, service }
    }

    /// A second `UpstreamService` over the *same* backends — what a second replica is.
    fn peer_service(&self) -> Arc<UpstreamService> {
        Arc::new(UpstreamService::new(
            self.repos.clone(),
            Arc::clone(&self.blob),
            Arc::clone(&self.client) as Arc<dyn UpstreamClient>,
            Arc::new(NoopEventSink) as Arc<dyn EventSink>,
            UpstreamServicePolicy::default(),
        ))
    }

    fn worker(&self, policy: MirrorPolicy) -> MirrorWorker {
        MirrorWorker::new(self.repos.clone(), Arc::clone(&self.service), Format::Pub, policy)
    }

    /// A worker as a freshly started process would build it: same durable state, no in-process
    /// page cache, no breaker history.
    fn restarted_worker(&self, policy: MirrorPolicy) -> MirrorWorker {
        MirrorWorker::new(self.repos.clone(), self.peer_service(), Format::Pub, policy)
    }

    async fn cached_versions(&self, name: &str) -> Vec<String> {
        match self.repos.upstream.get_package(Format::Pub, name).await.expect("get") {
            Some(package) => self
                .repos
                .upstream
                .list_versions(package.id)
                .await
                .expect("versions")
                .into_iter()
                .map(|version| version.version.to_string())
                .collect(),
            None => Vec::new(),
        }
    }

    async fn audit_actions(&self) -> Vec<String> {
        self.repos
            .audit
            .list(&AuditFilter::default(), None, 50)
            .await
            .expect("audit")
            .items
            .into_iter()
            .map(|event| event.action)
            .collect()
    }
}

fn recent_policy() -> MirrorPolicy {
    MirrorPolicy { mode: MirrorMode::Recent, refresh_after: Duration::hours(1), chunk: 10, ..MirrorPolicy::default() }
}

fn sweep_policy(chunk: usize) -> MirrorPolicy {
    MirrorPolicy { mode: MirrorMode::Full, refresh_after: Duration::hours(1), chunk, ..MirrorPolicy::default() }
}

// -------------------------------------------------------------------------------- leader lock

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_leader_lock_stops_a_second_instance_from_double_fetching() {
    // Two replicas, one lock, one job name. The proof is the *peak* number of simultaneous
    // upstream listing fetches: if both instances ran the tick, the scripted delay would put
    // two fetches in flight at once.
    //
    // Real time rather than a paused clock: the harness opens a database pool, and a paused
    // clock fires the pool's acquire timeout the instant the runtime goes idle.
    let harness = Harness::new().await;
    harness.client.publish("http", &[("1.0.0", b"http bytes")]);
    harness.client.set_delay(StdDuration::from_millis(60));
    // Seed the cache so the `recent` pass has something stale to refresh on every tick.
    harness.service.listing(Format::Pub, "http", t0()).await.expect("seed");
    assert_eq!(harness.client.listing_calls(), 1);

    let lock: Arc<dyn JobLock> = Arc::new(InMemoryJobLock::new());
    let mut handles = Vec::new();
    for _ in 0..2 {
        // Each replica gets its own worker and its own service, exactly as two processes would.
        let worker = Arc::new(MirrorWorker::new(
            harness.repos.clone(),
            harness.peer_service(),
            Format::Pub,
            MirrorPolicy { refresh_after: Duration::seconds(1), ..recent_policy() },
        ));
        let mut scheduler = Scheduler::new(Arc::clone(&lock), JobLockTtls::with_default(StdDuration::from_secs(30)));
        scheduler.add(MIRROR_JOB, StdDuration::from_millis(40), move || {
            let worker = Arc::clone(&worker);
            async move {
                worker.run_once(Utc::now()).await?;
                Ok(())
            }
        });
        handles.push(scheduler.spawn());
    }

    tokio::time::sleep(StdDuration::from_millis(500)).await;
    for handle in &handles {
        handle.shutdown();
    }

    assert_eq!(harness.client.peak_in_flight(), 1, "two instances ran the mirror job at the same time");
    let state = harness.repos.jobs.get(MIRROR_JOB).await.expect("state").expect("the job ran");
    assert!(state.runs >= 2, "the schedule kept ticking, it just never doubled up: {state:?}");
    assert!(state.last_success_at.is_some());
}

// ------------------------------------------------------------------------------- recent mode

#[tokio::test]
async fn recent_mode_picks_up_a_new_upstream_version() {
    let harness = Harness::new().await;
    harness.client.publish("http", &[("1.0.0", b"one")]);
    harness.service.listing(Format::Pub, "http", t0()).await.expect("seed the cache");
    assert_eq!(harness.cached_versions("http").await, ["1.0.0"]);

    // Upstream publishes while nobody is asking — the whole point of a mirror.
    harness.client.publish("http", &[("1.0.0", b"one"), ("1.1.0", b"two")]);

    let worker = harness.worker(recent_policy());
    let report = worker.run_once(t0() + Duration::hours(2)).await.expect("tick");
    assert_eq!(report.phase, "recent");
    assert_eq!(report.refreshed, 1);
    assert_eq!(report.skipped, 0);
    assert_eq!(harness.cached_versions("http").await, ["1.0.0", "1.1.0"], "the new version is cached ahead of demand");

    let state = worker.status(t0() + Duration::hours(2)).await.expect("status");
    assert_eq!(state.runs, 1);
    assert_eq!(state.processed, 1);
    assert_eq!(state.phase, "recent");
    assert_eq!(state.last_success_at, Some(t0() + Duration::hours(2)));
    assert_eq!(state.lag_seconds(t0() + Duration::hours(3)), Some(3600));
}

#[tokio::test]
async fn recent_mode_leaves_fresh_snapshots_alone() {
    // The freshness floor is the mirror's throttle: a package the read path just fetched must
    // not be fetched again by the worker one second later.
    let harness = Harness::new().await;
    harness.client.publish("http", &[("1.0.0", b"one")]);
    harness.service.listing(Format::Pub, "http", t0()).await.expect("seed");
    let after_seed = harness.client.listing_calls();

    let worker = harness.worker(recent_policy());
    let report = worker.run_once(t0() + Duration::minutes(5)).await.expect("tick");
    assert_eq!(report.refreshed, 0, "nothing is stale yet");
    assert_eq!(harness.client.listing_calls(), after_seed, "upstream was not asked at all");

    // Past the floor it is refreshed exactly once, and the next tick finds it fresh again.
    assert_eq!(worker.run_once(t0() + Duration::hours(2)).await.expect("tick").refreshed, 1);
    assert_eq!(harness.client.listing_calls(), after_seed + 1);
    let repeat = worker.run_once(t0() + Duration::hours(2)).await.expect("tick");
    assert_eq!(repeat.refreshed, 0);
    assert_eq!(harness.client.listing_calls(), after_seed + 1, "a re-run inside the floor is free");
}

#[tokio::test]
async fn recent_mode_can_warm_archive_bytes() {
    // The air-gap knob: metadata is not enough if nobody may reach upstream at install time.
    let harness = Harness::new().await;
    harness.client.publish("http", &[("1.0.0", b"one"), ("1.1.0", b"two")]);
    harness.service.listing(Format::Pub, "http", t0()).await.expect("seed");
    harness.client.publish("http", &[("1.0.0", b"one"), ("1.1.0", b"two"), ("1.2.0", b"three")]);

    let worker = harness.worker(MirrorPolicy { archives: true, archive_versions: 2, ..recent_policy() });
    let report = worker.run_once(t0() + Duration::hours(2)).await.expect("tick");
    assert_eq!(report.refreshed, 1);
    assert_eq!(report.archives_cached, 2, "the two newest versions' bytes are pulled");

    for (version, bytes) in [("1.2.0", b"three".as_slice()), ("1.1.0", b"two".as_slice())] {
        let key = pub_registry::RegistryService::blob_key(Format::Pub, &pub_registry::hex_sha256(bytes));
        assert_eq!(harness.blob.get(&key).await.expect("cached archive").as_ref(), bytes, "{version} not mirrored");
    }
    // The oldest version is left to the read-through path; `archive_versions` is a bound.
    let cold = pub_registry::RegistryService::blob_key(Format::Pub, &pub_registry::hex_sha256(b"one"));
    assert!(harness.blob.get(&cold).await.is_err());
}

// --------------------------------------------------------------------------------- full mode

#[tokio::test]
async fn full_mode_resumes_its_sweep_after_a_restart() {
    let harness = Harness::new().await;
    for name in ["alpha_pkg", "beta_pkg", "gamma_pkg", "delta_pkg", "epsilon_pkg"] {
        harness.client.publish(name, &[("1.0.0", name.as_bytes())]);
    }

    // Tick 1 on instance A: two of five.
    let first = harness.worker(sweep_policy(2));
    let report = first.run_once(t0()).await.expect("tick 1");
    assert_eq!(report.phase, "sweep");
    assert_eq!(report.refreshed, 2);
    assert!(!report.sweep_complete);
    let cursor = harness.repos.jobs.get(MIRROR_JOB).await.expect("state").expect("row").cursor;
    assert!(cursor.is_some(), "an interrupted sweep must leave a resume point");

    // The process dies here. A new instance shares only the database — no page cache, no
    // in-memory position.
    drop(first);
    let restarted = harness.restarted_worker(sweep_policy(2));
    let report = restarted.run_once(t0() + Duration::minutes(1)).await.expect("tick 2");
    assert_eq!(report.refreshed, 2, "the sweep continued rather than restarting");
    assert_eq!(report.skipped, 0, "restarting would have re-visited the first two as 'fresh'");

    let report = restarted.run_once(t0() + Duration::minutes(2)).await.expect("tick 3");
    assert_eq!(report.refreshed, 1, "the last package");
    assert!(report.sweep_complete);

    // Every package was fetched exactly once across the restart.
    assert_eq!(harness.client.listing_calls(), 5);
    for name in ["alpha_pkg", "beta_pkg", "gamma_pkg", "delta_pkg", "epsilon_pkg"] {
        assert_eq!(harness.cached_versions(name).await, ["1.0.0"], "{name} was not mirrored");
    }

    // Once the enumeration is done the job settles into the steady-state phase…
    let state = harness.repos.jobs.get(MIRROR_JOB).await.expect("state").expect("row");
    assert_eq!(state.phase, "recent");
    assert_eq!(state.processed, 5);
    let enumerations = harness.client.name_calls();
    let steady = restarted.run_once(t0() + Duration::hours(4)).await.expect("tick 4");
    assert_eq!(steady.phase, "recent");
    assert_eq!(harness.client.name_calls(), enumerations, "the steady phase refreshes, it does not re-enumerate");

    // …until the enumeration ages out, because a sweep is also drift repair and the only way a
    // *newly* appearing upstream namesake of a claimed package can ever be noticed (S-17).
    let resweep = restarted.run_once(t0() + Duration::hours(30)).await.expect("tick 5");
    assert_eq!(resweep.phase, "sweep");
    assert_eq!(resweep.refreshed + resweep.skipped, 2, "a fresh enumeration starts at the first page");
}

#[tokio::test]
async fn a_missing_name_index_degrades_to_a_recent_pass() {
    // An upstream without pub.dev's enumeration convention is not broken — it just cannot be
    // full-swept, and the packages we already hold still deserve refreshing.
    let harness = Harness::new().await;
    harness.client.publish("http", &[("1.0.0", b"one")]);
    harness.service.listing(Format::Pub, "http", t0()).await.expect("seed");
    harness.client.set_unavailable(true);
    harness.client.set_unavailable(false);
    // Empty the index without emptying the listings: `fetch_package_names` answers a page with
    // no names, so the sweep completes immediately and the tick still refreshes what we hold.
    harness.client.names.lock().expect("mock").clear();

    let worker = harness.worker(sweep_policy(10));
    let report = worker.run_once(t0() + Duration::hours(2)).await.expect("tick");
    assert!(report.sweep_complete, "an empty index is a finished sweep, not a stuck one");
    assert_eq!(harness.repos.jobs.get(MIRROR_JOB).await.expect("state").expect("row").phase, "recent");
}

// ------------------------------------------------------------------------------ S-17 alarms

#[tokio::test]
async fn a_shadowed_name_alarms_once_and_is_never_mirrored() {
    let harness = Harness::new().await;
    let alice = harness
        .repos
        .users
        .create(
            pub_core::user::NewUser {
                email: Some("owner@corp.com".to_owned()),
                email_verified: true,
                display_name: "Owner".to_owned(),
            },
            t0(),
        )
        .await
        .expect("user");
    let org = harness.repos.orgs.create(pub_core::org::NewOrg::new("Acme", "acme"), alice.id, t0()).await.expect("org");
    harness.repos.packages.claim_name(Format::Pub, "acme_core", org.id, t0()).await.expect("claim");

    // Upstream carries the name too — the dependency-confusion precondition.
    harness.client.publish("acme_core", &[("9.9.9", b"squatted")]);
    harness.client.publish("http", &[("1.0.0", b"honest")]);
    harness.client.index_only("ghost_pkg");

    let worker = harness.worker(sweep_policy(10));
    let report = worker.run_once(t0()).await.expect("sweep");
    assert_eq!(report.shadowed, 1);
    assert_eq!(report.alarms_raised, 1);
    assert_eq!(report.refreshed, 1, "the honest package is mirrored");

    // Never mirrored: caching a claimed name would store bytes resolution can never serve.
    assert!(harness.repos.upstream.get_package(Format::Pub, "acme_core").await.expect("get").is_none());
    assert!(harness.repos.upstream.get_package(Format::Pub, "http").await.expect("get").is_some());

    // Audited, alarmed, and listable by the admin surface.
    assert!(harness.audit_actions().await.contains(&"upstream.shadowing".to_owned()));
    assert!(harness.events.names().contains(&"upstream.shadowing"));
    let alarms = harness.repos.upstream.list_shadowing(Some(true), None, 10).await.expect("alarms").items;
    assert_eq!(alarms.len(), 1);
    assert_eq!(alarms[0].name, "acme_core");
    assert_eq!(alarms[0].org_id, org.id, "the claim holder is the audience");
    assert_eq!(alarms[0].upstream_version, None, "the sweep sees the name, not the version");
    assert!(alarms[0].is_active());

    // A later sweep (the resweep the drift-repair window schedules) re-observes the same
    // condition and must not re-page anybody.
    let restarted = harness.restarted_worker(sweep_policy(10));
    let again = restarted.run_once(t0() + Duration::hours(30)).await.expect("sweep again");
    assert_eq!(again.shadowed, 1);
    assert_eq!(again.alarms_raised, 0, "an ongoing condition is a counter, not a new page");
    assert_eq!(
        harness.repos.upstream.list_shadowing(Some(true), None, 10).await.expect("alarms").items[0].observations,
        2
    );
    assert_eq!(
        harness.audit_actions().await.iter().filter(|action| *action == "upstream.shadowing").count(),
        1,
        "one audit event per incident"
    );
}

// ------------------------------------------------------------------------------- degradation

#[tokio::test]
async fn an_open_circuit_skips_the_tick() {
    // Feeding a chunk into an open circuit would spend the single half-open probe on the first
    // name and answer "unavailable" for the rest — a breaker turned into a slow retry loop.
    let harness = Harness::new().await;
    harness.client.publish("http", &[("1.0.0", b"one")]);
    harness.service.listing(Format::Pub, "http", t0()).await.expect("seed");
    harness.client.set_unavailable(true);

    let worker = harness.worker(recent_policy());
    // Trip the breaker: the default threshold is five consecutive failures.
    for _ in 0..5 {
        let _ = harness.service.listing(Format::Pub, "other_pkg", t0() + Duration::hours(2)).await;
    }
    let calls_before = harness.client.listing_calls();

    let report = worker.run_once(t0() + Duration::hours(2)).await.expect("tick");
    assert_eq!(report.refreshed, 0);
    assert_eq!(harness.client.listing_calls(), calls_before, "an open circuit must not be probed by the worker");
    let state = harness.repos.jobs.get(MIRROR_JOB).await.expect("state").expect("row");
    assert_eq!(state.last_error.as_deref(), Some("upstream circuit open"));
    assert_eq!(state.last_success_at, None, "a skipped tick is not a successful sync");

    // Once upstream recovers and the window elapses, the mirror resumes on its own.
    harness.client.set_unavailable(false);
    harness.client.publish("http", &[("1.0.0", b"one"), ("1.1.0", b"two")]);
    let report = worker.run_once(t0() + Duration::hours(3)).await.expect("tick");
    assert_eq!(report.refreshed, 1);
    assert_eq!(harness.cached_versions("http").await, ["1.0.0", "1.1.0"]);
}

#[tokio::test]
async fn an_off_worker_does_nothing_at_all() {
    // `mode = off` is not "a job that returns early": nothing is scheduled, and the job row is
    // never even created, so an operator can tell a disabled mirror from a broken one.
    let harness = Harness::new().await;
    harness.client.publish("http", &[("1.0.0", b"one")]);
    let worker = harness.worker(MirrorPolicy::default());
    let report = worker.run_once(t0()).await.expect("tick");
    assert_eq!(report, pub_jobs::MirrorReport::default());
    assert!(harness.repos.jobs.get(MIRROR_JOB).await.expect("state").is_none());
    assert_eq!(harness.client.listing_calls(), 0);
    assert_eq!(harness.client.name_calls(), 0);
}
