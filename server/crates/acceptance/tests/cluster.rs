//! Roadmap Phase 3 item 3, at the wire: two containers, one proxy, four claims
//! ([decision 38](../../../../docs/decisions.md#38--two-replicas-behind-one-proxy-an-acceptance-stand-that-fails-closed-four-claims-proven-at-the-wire-and-a-measurement-that-is-a-number)).
//!
//! What separates this file from `api/tests/cluster.rs` is not the assertions — it is what they
//! are asserted against. That suite runs two `TestApp`s in one process over one Postgres, which
//! can answer questions about a lock and cannot answer questions about a *deployment*: it shares
//! no Redis, so revocation and the event bridge are invisible to it; it has no proxy, so
//! `public_url` and stickiness are untested; and its "mail was sent" is a vector in memory
//! rather than a message in a mailbox.
//!
//! The gate is [decision 35](../../../../docs/decisions.md#35--backend-legs-that-fail-when-the-backend-is-absent-and-a-harness-that-admits-a-race)'s,
//! one level up: with neither `PUB_TEST_CLUSTER_URL` nor `PUB_TEST_NO_CLUSTER` set, every test
//! here panics naming both. Start the stand with `just cluster-up`, run them with
//! `just cluster-check`.
//!
//! **Seen red against a named revert.** Replica B was restarted onto a different Redis logical
//! database (`redis://redis:6379/1`, everything else untouched) and three of the five went red at
//! once: revocation (the blocklist is not shared), the event bridge (the broker topic is not
//! shared), and — the one nobody predicted — the concurrent publishes, which failed with *"this
//! upload has expired or was already finalized"* because a staged upload's session record lives
//! in the KV too. The exactly-once claim stayed green, correctly: the queue is in Postgres. That
//! is the whole argument for this file existing, in one experiment.
//!
//! **Every test takes its own client address.** The replicas trust `X-Forwarded-For` (S-24.b,
//! and the stand sets `trust_proxy_headers` because that is what a proxied deployment must do),
//! so a direct-dialled request is taken at its word. Sharing one address would make the
//! per-IP budgets — `otp_per_ip_hour` is 20 — a hidden coupling between tests and a hidden
//! expiry on how often the run may be repeated.

use std::time::Duration;

use pub_acceptance::{Cluster, unique};

/// **Claim 1 — session revocation propagates (S-09).**
///
/// The revocation writes the session id to the KV blocklist, and the blocklist is the shared
/// Redis rather than either instance's memory. So a token revoked through A must be refused by
/// B, which has never seen the request that revoked it and holds no state about the session
/// beyond what it can read.
///
/// Before this stand existed nothing tested this at all: the in-process cluster suite gives its
/// two applications a *private* KV each, precisely because it has no Redis to share.
#[tokio::test]
async fn a_revoked_session_is_refused_by_the_other_replica_s09() {
    let Some(cluster) = Cluster::gate("a_revoked_session_is_refused_by_the_other_replica_s09") else { return };
    let cluster = cluster.as_client("198.51.100.11");
    let email = format!("{}@corp.test", unique("revoke-"));

    let login = cluster.login(cluster.a(), &email).await;
    let access = login["access_token"].as_str().expect("access token").to_owned();

    // The token works on both instances to begin with — otherwise the assertion below would
    // pass for the wrong reason, and "B refuses it" would mean "B never accepted it".
    let on_b = cluster.get(cluster.b(), "/api/v1/sessions", Some(&access)).await;
    assert_eq!(on_b.status, 200, "the session minted on A must be usable on B: {:?}", on_b.json);
    let sid = on_b.data()["items"]
        .as_array()
        .and_then(|items| items.iter().find(|item| item["current"] == true))
        .and_then(|item| item["id"].as_str())
        .expect("the current session")
        .to_owned();

    let revoked = cluster.delete(cluster.a(), &format!("/api/v1/sessions/{sid}"), Some(&access)).await;
    assert_eq!(revoked.status, 200, "revoke on A failed: {:?}", revoked.json);

    // No sleep: the blocklist write is synchronous with the response, so a retry loop here
    // would be hiding a propagation delay rather than measuring one.
    let after = cluster.get(cluster.b(), "/api/v1/sessions", Some(&access)).await;
    assert_eq!(after.status, 401, "B must refuse a session A revoked: {:?}", after.json);

    // And through the front door, wherever it lands.
    let through_proxy = cluster.get(&cluster.proxy, "/api/v1/sessions", Some(&access)).await;
    assert_eq!(through_proxy.status, 401, "and so must the proxy: {:?}", through_proxy.json);
}

/// **Claim 2 — queued work runs exactly once, with two live drains** ([decision 26](../../../../docs/decisions.md#26--durable-job-queue-async-fan-out-and-outbound-mail-off-the-request-path)).
///
/// Four sign-in requests, four addresses, two instances both ticking their drains. The
/// observable is the mailbox, which is the only place a duplicate delivery is visible to a
/// human — and the place where the lease, the exclusive claim and the fenced completion all
/// have to hold at once for the number to come out right.
///
/// The count is taken **after a grace period** rather than at the first sighting: the failure
/// this guards against is a second delivery, and a check that stopped as soon as it saw four
/// could never see the fifth.
#[tokio::test]
async fn queued_mail_is_delivered_exactly_once_with_two_drains_d26() {
    let Some(cluster) = Cluster::gate("queued_mail_is_delivered_exactly_once_with_two_drains_d26") else { return };
    let cluster = cluster.as_client("198.51.100.12");
    let run = unique("once-");

    // Filed alternately on both instances, so neither drain owns "its own" work.
    let addresses: Vec<String> = (0..4).map(|index| format!("{run}-{index}@corp.test")).collect();
    for (index, address) in addresses.iter().enumerate() {
        let base = if index % 2 == 0 { cluster.a() } else { cluster.b() };
        let requested =
            cluster.post(base, "/api/v1/auth/otp/request", None, serde_json::json!({ "email": address })).await;
        assert_eq!(requested.status, 200, "otp request failed for {address}: {:?}", requested.json);
    }

    for address in &addresses {
        let delivered = cluster.await_mail_count(address, 1, Duration::from_secs(45), Duration::from_secs(8)).await;
        assert_eq!(delivered, 1, "{address} must receive exactly one code, not {delivered}");
    }
}

/// **Claim 3 — publishes of one name serialize across replicas** ([D1](../../../../docs/roadmap.md)).
///
/// Six finalizes of six versions of **one** package name, three through each instance, all in
/// flight together. The publish lock is keyed on the package name, so the losers must get the
/// clean, retryable `400 busy` of [sharp edge 2](../../../../docs/protocol.md#sharp-edges-violate--break-clients)
/// — not a 500, and not the database's unique index surfacing as a constraint violation.
///
/// The two assertions that matter are that **every** answer is one of those two shapes, and
/// that the listing afterwards holds exactly as many versions as there were successes. A lock
/// that silently let two writers through would show up as the second number disagreeing with
/// the first.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_publishes_of_one_name_serialize_across_replicas_d1() {
    let Some(cluster) = Cluster::gate("concurrent_publishes_of_one_name_serialize_across_replicas_d1") else {
        return;
    };
    let cluster = cluster.as_client("198.51.100.13");
    let slug = unique("acc-serialize-");
    let email = format!("{}@corp.test", unique("serialize-"));
    let package = unique("acc_serialize_");

    let (access, org) = cluster.org_owner(cluster.a(), &email, &slug).await;
    let token = cluster.mint_token(cluster.a(), &access, &org, &["read", "publish"]).await;

    let versions: Vec<String> = (1..=6).map(|version| format!("{version}.0.0")).collect();
    let attempts = versions.iter().enumerate().map(|(index, version)| {
        let base = if index % 2 == 0 { cluster.a() } else { cluster.b() };
        cluster.publish(base, &slug, &token, &package, version)
    });
    let answers = futures::future::join_all(attempts).await;

    let mut published = 0;
    let mut busy = 0;
    for answer in &answers {
        match answer.status {
            200 => published += 1,
            400 if answer.json["error"]["code"] == "busy" => busy += 1,
            _ => panic!("a concurrent publish answered neither 200 nor 400 busy: {answer:?}"),
        }
    }
    assert!(published >= 1, "at least one publish must succeed");
    assert!(busy >= 1, "with six concurrent finalizes of one name, at least one must be refused as busy");

    let listing =
        cluster.pub_get(&format!("{}/o/{slug}/pub/api/packages/{package}", cluster.proxy), Some(&token)).await;
    assert_eq!(listing.status, 200, "the package must be listed: {:?}", listing.json);
    let listed = listing.json["versions"].as_array().map_or(0, Vec::len);
    assert_eq!(listed, published, "the registry must hold exactly the versions that were accepted");

    // **The stand's own correctness, asserted where it is cheapest.** Every absolute URL the
    // protocol returns is built from `server.public_url`; a replica that answered with its own
    // address would hand `dart pub` a URL that works by accident on this host and never behind
    // a real proxy. That misconfiguration would leave all four claims green.
    let archive = listing.json["latest"]["archive_url"].as_str().expect("archive_url");
    assert!(
        archive.starts_with(&cluster.proxy),
        "archive_url must name the proxy ({}), not the replica that served it: {archive}",
        cluster.proxy
    );
}

/// **Claim 4 — an event emitted on one replica reaches a stream held by the other**
/// ([decision 20](../../../../docs/decisions.md#20--realtime-sse-event-stream--notification-center)).
///
/// The stream is opened on B and the publish happens on A, so the only path between them is the
/// KV broker topic the event bus fans out to. Nothing in this repository could test that before:
/// a peer bridge with one instance is a bridge to nowhere.
///
/// The stream is opened *before* the event is caused — the ordering is the test. Reading it
/// afterwards would be exercising the replay ring, which is a different promise.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_event_emitted_on_one_replica_reaches_a_stream_on_the_other_d20() {
    let Some(cluster) = Cluster::gate("an_event_emitted_on_one_replica_reaches_a_stream_on_the_other_d20") else {
        return;
    };
    let cluster = cluster.as_client("198.51.100.14");
    let slug = unique("acc-stream-");
    let email = format!("{}@corp.test", unique("stream-"));
    let package = unique("acc_stream_");

    let (access, org) = cluster.org_owner(cluster.b(), &email, &slug).await;
    let token = cluster.mint_token(cluster.b(), &access, &org, &["read", "publish"]).await;

    let listening = cluster.await_event(cluster.b(), &access, "package.publish", Duration::from_secs(30));
    let publishing = async {
        // The stream has to be established first; a publish that beat it would be testing
        // replay rather than delivery.
        tokio::time::sleep(Duration::from_secs(2)).await;
        cluster.publish(cluster.a(), &slug, &token, &package, "1.0.0").await
    };
    let (event, published) = tokio::join!(listening, publishing);

    assert_eq!(published.status, 200, "the publish on A must succeed: {:?}", published.json);
    let event = event.expect("the publish on A must reach the stream held by B");
    assert_eq!(event["package"].as_str(), Some(package.as_str()), "the event names the package: {event}");
    assert_eq!(event["version"].as_str(), Some("1.0.0"), "and the version: {event}");
}

/// **The stand itself: the front door is not sticky.**
///
/// Kept because it is a precondition of the other four rather than a claim about the product.
/// A balancer with a session affinity would keep every request of a test on one instance, and
/// four green claims would then say nothing at all about two.
#[tokio::test]
async fn the_front_door_spreads_requests_across_both_replicas() {
    let Some(cluster) = Cluster::gate("the_front_door_spreads_requests_across_both_replicas") else { return };
    let cluster = cluster.as_client("198.51.100.15");

    let mut upstreams = std::collections::BTreeSet::new();
    for _ in 0..12 {
        if let Some(upstream) = cluster.upstream_of("/healthz").await {
            upstreams.insert(upstream);
        }
    }
    assert!(
        upstreams.len() >= 2,
        "twelve requests through the proxy reached {} upstream(s): {upstreams:?} — a sticky front door \
         would make every other claim in this file a claim about one instance",
        upstreams.len()
    );
}
