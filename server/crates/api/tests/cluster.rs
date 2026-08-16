//! Two application instances over one database — the shape roadmap item 1 is about, at the
//! level where an operator meets it ([decision 36](../../../../docs/decisions.md#36--leader-election-leaves-the-process-a-lease-table-a-lock-that-outlives-a-pool-connection-and-a-topology-gate-that-replaces-a-kv-check),
//! closing [D1](../../../../docs/roadmap.md)).
//!
//! Every test here boots on [`TestDatabase::Postgres`], because Postgres is the only backend two
//! instances of this harness can share — and because that is exactly the deployment the config
//! validator now requires before it will accept `cluster.replicas > 1`. The repository contract
//! suite proves the lease's properties against the same server; what these prove is the wiring:
//! that two *applications* take their locks out of one table, so a name being published on one
//! instance is a name the other instance knows is busy.
//!
//! The gate is decision 35's: with neither `PUB_TEST_POSTGRES_URL` nor `PUB_TEST_NO_POSTGRES`
//! set, `try_with_options` panics naming both rather than skipping quietly.

mod common;

use std::time::Duration as StdDuration;

use axum::http::{StatusCode, header};
use common::{TestApp, TestDatabase, TestOptions, package_archive};

/// A publisher on both instances: the org and the token live in the shared database, so the
/// token minted through one instance authenticates against the other with nothing propagated.
struct Publisher {
    token: String,
    base: String,
}

async fn publisher(app: &TestApp, email: &str, slug: &str) -> Publisher {
    let (access, org) = app.org_owner(email, slug).await;
    let token = app.mint_token(&access, org, &["read", "publish"]).await;
    Publisher { token, base: format!("/o/{slug}/pub") }
}

fn postgres_options() -> TestOptions {
    TestOptions { database: TestDatabase::Postgres, ..TestOptions::default() }
}

/// Leader election leaves the process: two instances contend for one name.
///
/// Before this wave both applications would have held a private `InMemoryJobLock`, so this test
/// could not fail — which is what made the config validator's approval of `replicas > 1` a
/// promise rather than a fact.
#[tokio::test]
async fn two_instances_contend_for_one_job_lock_d1() {
    let Some(first) = TestApp::try_with_options(postgres_options()).await else { return };
    let second = first.replica(postgres_options()).await;

    let ttl = StdDuration::from_secs(60);
    let held = first.lock.try_acquire("blob-gc", ttl).await.expect("acquire").expect("a free name");
    assert!(
        second.lock.try_acquire("blob-gc", ttl).await.expect("acquire").is_none(),
        "the second instance must see the first one's lease"
    );
    assert!(
        second.lock.try_acquire("reindex", ttl).await.expect("acquire").is_some(),
        "and it must still be able to run every other job"
    );

    first.lock.release("blob-gc", held).await.expect("release");
    let taken = second.lock.try_acquire("blob-gc", ttl).await.expect("acquire").expect("released");
    assert!(
        first.lock.try_acquire("blob-gc", ttl).await.expect("acquire").is_none(),
        "and the instance that released it is now the one waiting"
    );
    second.lock.release("blob-gc", taken).await.expect("release");
}

/// A crashed instance's lease expires; its late release does not free its successor's lock.
///
/// The property `LockToken` was added for, now across two processes rather than inside one — a
/// stale release that freed the successor's lock would put a *third* worker beside the one still
/// running, which for the queue drain is two drains reaping each other's leases.
#[tokio::test]
async fn a_stale_holder_cannot_free_its_successors_lock_d1() {
    let Some(first) = TestApp::try_with_options(postgres_options()).await else { return };
    let second = first.replica(postgres_options()).await;

    let overrunning =
        first.lock.try_acquire("job-queue", StdDuration::from_millis(50)).await.expect("acquire").expect("free");
    tokio::time::sleep(StdDuration::from_millis(120)).await;
    let successor =
        second.lock.try_acquire("job-queue", StdDuration::from_secs(60)).await.expect("acquire").expect("expired");
    assert_ne!(overrunning, successor);

    first.lock.release("job-queue", overrunning).await.expect("stale release");
    assert!(
        first.lock.try_acquire("job-queue", StdDuration::from_secs(60)).await.expect("acquire").is_none(),
        "the stale holder's release must not hand the lock to a third instance"
    );
    second.lock.release("job-queue", successor).await.expect("release");
}

/// **D1's named damage, at the wire.** A publish in flight on one instance is a `busy` on the
/// other — not a race through to the database's unique index.
///
/// With a per-process lock the second instance would take its own free lock, walk the whole
/// read-then-write of a publish, and meet the unique index at the bottom: the clean, retryable
/// 400 `busy` this asserts would have been a raw constraint violation instead. The staged upload
/// surviving the conflict is the same guarantee `protocol.rs` pins for one instance — a client's
/// retry of a timed-out finalize must not cost it the uploaded archive.
#[tokio::test]
async fn a_publish_in_flight_on_one_instance_is_busy_on_the_other_d1() {
    let Some(first) = TestApp::try_with_options(postgres_options()).await else { return };
    let second = first.replica(postgres_options()).await;
    let acme = publisher(&first, "dev@acme.test", "acme").await;

    // A publish is staged on the second instance, ready to finalize.
    let ticket = second.pub_get(&format!("{}/api/packages/versions/new", acme.base), Some(&acme.token)).await;
    assert_eq!(
        ticket.status,
        StatusCode::OK,
        "the token minted on the first instance must work here: {:?}",
        ticket.json
    );
    let upload = second
        .pub_upload(
            &second.proxied(ticket.json["url"].as_str().expect("upload url")),
            Some(&acme.token),
            &package_archive("acme_core", "1.0.0"),
        )
        .await;
    assert_eq!(upload.status, StatusCode::NO_CONTENT);
    let finalize = second.proxied(upload.headers[header::LOCATION].to_str().expect("location"));

    // Meanwhile the *first* instance is publishing that name.
    let held = first
        .lock
        .try_acquire("publish:pub:acme_core", StdDuration::from_secs(60))
        .await
        .expect("acquire")
        .expect("free");

    let busy = second.pub_get(&finalize, Some(&acme.token)).await;
    assert_eq!(busy.status, StatusCode::BAD_REQUEST, "finalize stays inside 200-or-400: {:?}", busy.json);
    assert_eq!(busy.json["error"]["code"], "busy", "the other instance's publish is transient, not a conflict");

    first.lock.release("publish:pub:acme_core", held).await.expect("release");
    let done = second.pub_get(&finalize, Some(&acme.token)).await;
    assert_eq!(
        done.status,
        StatusCode::OK,
        "the staged upload must survive the cross-instance conflict: {:?}",
        done.json
    );

    // And the version is one registry, not two: the instance that never published it serves it.
    let listing = first.pub_get(&format!("{}/api/packages/acme_core", acme.base), Some(&acme.token)).await;
    assert_eq!(listing.status, StatusCode::OK);
    assert_eq!(listing.json["latest"]["version"], "1.0.0");
}

/// Work filed by one instance is delivered by the other.
///
/// The queue is the one plane where "two replicas" is not a lock question: the row is shared, the
/// claim is exclusive, and either drain may take it. A sign-in code filed on an instance that
/// then goes away must still reach its recipient — which is the whole argument for the mail plane
/// being durable rather than in-process (decision 26).
#[tokio::test]
async fn a_sign_in_filed_on_one_instance_is_delivered_by_the_other() {
    let Some(first) = TestApp::try_with_options(postgres_options()).await else { return };
    let second = first.replica(postgres_options()).await;

    let response =
        first.post("/api/v1/auth/otp/request", None, serde_json::json!({ "email": "traveller@corp.com" })).await;
    assert_eq!(response.status, StatusCode::OK, "otp request failed: {:?}", response.json);

    // The instance that never saw the request drains it, and it is that instance's transport the
    // message goes out on.
    let report = second.drain_jobs().await;
    assert_eq!(report.delivered, 1, "the second instance claimed and delivered the queued mail: {report:?}");
    assert_eq!(report.lost, 0, "and nothing was completed against a claim it did not hold");
    assert_eq!(second.mailer.sent().len(), 1, "the mail left through the draining instance");
    assert!(first.mailer.sent().is_empty(), "not through the one that filed it");

    // The item is settled, so the first instance's drain has nothing left to do — the claim is
    // exclusive, not merely ordered.
    let second_pass = first.drain_jobs().await;
    assert_eq!(second_pass.claimed, 0, "a delivered item is nobody's work: {second_pass:?}");
    assert_eq!(first.mailer.sent().len(), 0, "and it is certainly not sent twice");
}
