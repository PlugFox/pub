//! Upstream read-through proxy conformance (decision 07, S-16/S-19/S-20).
//!
//! Drives the whole router — resolution, policy, ingest, storage, re-emission — against a
//! scripted upstream that never touches the network, so every behaviour the proxy exists for
//! can be produced on demand rather than waited for.
//!
//! | Rule | Where | Test |
//! |------|-------|------|
//! | Cold miss caches and re-emits under **our** base | sharp edge 3 | [`a_cold_miss_caches_the_package_and_serves_our_own_archive_url`] |
//! | A warm cache does not touch upstream | decision 07 | [`a_warm_cache_serves_without_touching_upstream`], [`the_cache_is_refreshed_after_the_listing_ttl`] |
//! | Hash-before-store; a mismatch is quarantined | S-19 | [`s19_a_sha256_mismatch_is_refused_and_quarantined`] |
//! | Byte-drift keeps the cached bytes | S-19 | [`s19_byte_drift_keeps_the_cached_bytes_and_alarms`] |
//! | Degraded upstream serves stale; unknown stays 404 | sharp edge 2 | [`an_upstream_outage_serves_stale_and_never_5xx`] |
//! | Local always wins; a claimed name is never proxied | S-16 | [`s16_a_locally_claimed_name_never_falls_through_to_upstream`], [`s16_a_claim_without_a_package_is_not_a_proxy_candidate`] |
//! | Claiming a proxied name alarms, and local still wins | S-17 | [`s17_claiming_a_proxied_name_alarms_and_the_local_package_still_wins`], [`s17_a_name_nobody_has_seen_upstream_raises_no_alarm`] |
//! | Per-org `block` policy | decision 01 | [`a_blocked_org_answers_404_for_upstream_names`] |
//! | One upstream fetch per burst of misses | decision 07 | [`single_flight_collapses_concurrent_cache_misses`] |
//! | Ingest limits apply to upstream too | S-20 | [`an_oversized_upstream_archive_is_refused`], [`s20_a_hostile_upstream_pubspec_is_refused_by_the_publish_validator`] |
//! | Upstream flags are re-emitted verbatim | decision 07 | [`upstream_flags_are_re_emitted_verbatim`] |
//! | Proxied listings gzip; HEAD matches GET | sharp edge 7 | [`a_proxied_response_negotiates_gzip_and_answers_head_like_get`] |
//! | Upstream owns values, never the field set | sharp edge 10 | [`an_upstream_cannot_inject_fields_into_our_listing`] |

mod common;

use std::sync::Arc;
use std::time::Duration as StdDuration;

use axum::http::{Method, StatusCode, header};
use chrono::Duration;
use common::upstream::{MockUpstream, Mode};
use common::{PUB_MEDIA_TYPE, TestApp, TestOptions};
use pub_core::audit::AuditFilter;
use pub_core::org::UpstreamPolicy;
use pub_core::token::TokenScope;
use pub_core::{Format, OrgId};
use serde_json::json;

/// The public root base.
const ROOT: &str = "/pub";

/// An org registry base for `slug`.
fn base(slug: &str) -> String {
    format!("/o/{slug}/pub")
}

/// An app with the proxy on and everything else at its defaults.
async fn proxying_app() -> TestApp {
    TestApp::with_options(TestOptions { upstream: true, ..TestOptions::default() }).await
}

/// Bytes that stand in for an upstream archive. The proxy stores and serves them verbatim; it
/// deliberately does not re-validate their tar structure (see docs/security.md S-19.a).
fn upstream_archive(seed: &str) -> Vec<u8> {
    format!("upstream archive bytes: {seed}").into_bytes()
}

/// The audit actions recorded so far.
async fn audit_actions(app: &TestApp) -> Vec<String> {
    app.repos
        .audit
        .list(&AuditFilter::default(), None, 50)
        .await
        .expect("audit list")
        .items
        .into_iter()
        .map(|event| event.action)
        .collect()
}

/// Seeds an org with an owner and a publish-capable token, returning `(slug, org, token)`.
async fn org_with_token(app: &TestApp, email: &str, slug: &str) -> (String, OrgId, String) {
    let (access, org) = app.org_owner(email, slug).await;
    let token = app.mint_token(&access, org, &["read", "publish"]).await;
    (slug.to_owned(), org, token)
}

// ------------------------------------------------------------------------------ cold misses

#[tokio::test]
async fn a_cold_miss_caches_the_package_and_serves_our_own_archive_url() {
    let app = proxying_app().await;
    let bytes = upstream_archive("http-1.0.0");
    app.mock_upstream().publish("http", &[("1.0.0", &bytes)]);

    let listing = app.pub_get(&format!("{ROOT}/api/packages/http"), None).await;
    assert_eq!(listing.status, StatusCode::OK, "{:?}", listing.json);
    assert_eq!(listing.headers[header::CONTENT_TYPE], PUB_MEDIA_TYPE);
    assert_eq!(listing.json["name"], "http");
    assert_eq!(listing.json["versions"].as_array().expect("versions").len(), 1);

    // docs/protocol.md sharp edge 3: the client must never see upstream's CDN URL, or the
    // download bypasses the cache, the per-org policy, and stale-serving in one step.
    let archive_url = listing.json["versions"][0]["archive_url"].as_str().expect("archive_url").to_owned();
    assert_eq!(archive_url, format!("{}{ROOT}/api/archives/http-1.0.0.tar.gz", common::INSTANCE_ORIGIN));
    assert!(!archive_url.contains("upstream.test"), "an upstream url leaked into a listing: {archive_url}");
    assert_eq!(listing.json["versions"][0]["archive_sha256"], pub_registry::hex_sha256(&bytes));
    // The pubspec is upstream's document, verbatim.
    assert_eq!(listing.json["versions"][0]["pubspec"]["description"], "An upstream package.");
    assert_eq!(listing.json["latest"]["version"], "1.0.0");

    // Following the advertised URL serves upstream's exact bytes from our own store.
    let archive = app.pub_get_raw(&app.proxied(&archive_url), None).await;
    assert_eq!(archive.status, StatusCode::OK);
    assert_eq!(archive.body, bytes, "proxied archives are byte-identical to upstream");
    assert_eq!(archive.headers[header::CONTENT_LENGTH], bytes.len().to_string());

    // The snapshot is durable, and the bytes are content-addressed exactly like a local publish.
    let cached = app.repos.upstream.get_package(Format::Pub, "http").await.unwrap().expect("snapshot");
    assert_eq!(cached.upstream, common::upstream::UPSTREAM_BASE);
    let key = pub_registry::RegistryService::blob_key(Format::Pub, &pub_registry::hex_sha256(&bytes));
    assert_eq!(app.state.blob.get(&key).await.unwrap().as_ref(), bytes.as_slice());
}

#[tokio::test]
async fn a_warm_cache_serves_without_touching_upstream() {
    let app = proxying_app().await;
    let bytes = upstream_archive("http-1.0.0");
    app.mock_upstream().publish("http", &[("1.0.0", &bytes)]);

    for _ in 0..3 {
        let listing = app.pub_get(&format!("{ROOT}/api/packages/http"), None).await;
        assert_eq!(listing.status, StatusCode::OK);
        let url = listing.json["versions"][0]["archive_url"].as_str().expect("archive_url").to_owned();
        let archive = app.pub_get_raw(&app.proxied(&url), None).await;
        assert_eq!(archive.status, StatusCode::OK);
        assert_eq!(archive.body, bytes);
    }
    assert_eq!(app.mock_upstream().listing_calls(), 1, "a fresh snapshot must not re-ask upstream");
    assert_eq!(app.mock_upstream().archive_calls(), 1, "cached bytes must not be re-fetched");
}

#[tokio::test]
async fn the_cache_is_refreshed_after_the_listing_ttl() {
    let app =
        TestApp::with_options(TestOptions { upstream: true, upstream_listing_ttl_secs: 300, ..TestOptions::default() })
            .await;
    app.mock_upstream().publish("http", &[("1.0.0", &upstream_archive("a"))]);
    assert_eq!(app.pub_get(&format!("{ROOT}/api/packages/http"), None).await.status, StatusCode::OK);

    // Upstream publishes a new version; inside the TTL we still serve the old snapshot.
    app.mock_upstream().publish("http", &[("1.0.0", &upstream_archive("a")), ("1.1.0", &upstream_archive("b"))]);
    app.advance(Duration::seconds(60));
    let inside = app.pub_get(&format!("{ROOT}/api/packages/http"), None).await;
    assert_eq!(inside.json["versions"].as_array().unwrap().len(), 1);
    assert_eq!(app.mock_upstream().listing_calls(), 1);

    app.advance(Duration::seconds(300));
    let outside = app.pub_get(&format!("{ROOT}/api/packages/http"), None).await;
    assert_eq!(outside.json["versions"].as_array().unwrap().len(), 2, "past the TTL upstream is re-asked");
    assert_eq!(outside.json["latest"]["version"], "1.1.0");
    assert_eq!(app.mock_upstream().listing_calls(), 2);
}

#[tokio::test]
async fn an_unknown_upstream_package_is_404_with_the_spec_error_shape() {
    let app = proxying_app().await;
    let response = app.pub_get(&format!("{ROOT}/api/packages/nope_pkg"), None).await;
    assert_eq!(response.status, StatusCode::NOT_FOUND);
    assert_eq!(response.headers[header::CONTENT_TYPE], PUB_MEDIA_TYPE);
    assert_eq!(response.json["error"]["code"], "not_found");
    // S-04: a 404 never carries a challenge — hinting that a credential would help is the leak
    // the 404 exists to prevent.
    assert!(!response.headers.contains_key(header::WWW_AUTHENTICATE));
}

#[tokio::test]
async fn a_disabled_proxy_answers_404_for_every_unclaimed_name() {
    // `[upstream].enabled = false` leaves no upstream branch in the resolution path at all —
    // which is what an air-gapped operator is buying.
    let app = TestApp::with_options(TestOptions { upstream: false, ..TestOptions::default() }).await;
    assert_eq!(app.pub_get(&format!("{ROOT}/api/packages/http"), None).await.status, StatusCode::NOT_FOUND);
    assert_eq!(
        app.pub_get_raw(&format!("{ROOT}/api/archives/http-1.0.0.tar.gz"), None).await.status,
        StatusCode::NOT_FOUND
    );
}

// -------------------------------------------------------------------------- proxy integrity

#[tokio::test]
async fn s19_a_sha256_mismatch_is_refused_and_quarantined() {
    let app = proxying_app().await;
    let honest = upstream_archive("honest");
    app.mock_upstream().publish("http", &[("1.0.0", &honest)]);
    assert_eq!(app.pub_get(&format!("{ROOT}/api/packages/http"), None).await.status, StatusCode::OK);

    // Upstream now serves different bytes under the hash it advertised.
    app.mock_upstream().corrupt_archive("http", "1.0.0", b"tampered bytes");

    let archive = app.pub_get_raw(&format!("{ROOT}/api/archives/http-1.0.0.tar.gz"), None).await;
    assert_eq!(archive.status, StatusCode::NOT_FOUND, "never served");
    assert!(archive.status.is_client_error(), "a permanent refusal must not look retryable");

    // Never stored, either — under the advertised hash or the actual one.
    for sha in [pub_registry::hex_sha256(&honest), pub_registry::hex_sha256(b"tampered bytes")] {
        let key = pub_registry::RegistryService::blob_key(Format::Pub, &sha);
        assert!(app.state.blob.get(&key).await.is_err(), "quarantined bytes reached storage under {sha}");
    }
    assert!(audit_actions(&app).await.contains(&"upstream.quarantine".to_owned()), "S-19 requires an audit trail");

    // And the version stays fetchable later, once upstream is honest again.
    app.mock_upstream().corrupt_archive("http", "1.0.0", &honest);
    let retry = app.pub_get_raw(&format!("{ROOT}/api/archives/http-1.0.0.tar.gz"), None).await;
    assert_eq!(retry.status, StatusCode::OK);
    assert_eq!(retry.body, honest);
}

#[tokio::test]
async fn s19_byte_drift_keeps_the_cached_bytes_and_alarms() {
    let app = proxying_app().await;
    let original = upstream_archive("original");
    app.mock_upstream().publish("http", &[("1.0.0", &original)]);
    let first = app.pub_get(&format!("{ROOT}/api/packages/http"), None).await;
    let pinned = first.json["versions"][0]["archive_sha256"].as_str().expect("sha").to_owned();
    assert_eq!(app.pub_get_raw(&format!("{ROOT}/api/archives/http-1.0.0.tar.gz"), None).await.body, original);

    // Upstream now advertises a *different* hash for a version whose bytes we already hold —
    // exactly the shape of a compromised or re-signed upstream artifact.
    let replacement = upstream_archive("replacement");
    app.mock_upstream().publish("http", &[("1.0.0", &replacement)]);
    app.advance(Duration::hours(1));

    let refreshed = app.pub_get(&format!("{ROOT}/api/packages/http"), None).await;
    assert_eq!(refreshed.json["versions"][0]["archive_sha256"], pinned, "the hash a lockfile pinned must not move");
    assert_ne!(pinned, pub_registry::hex_sha256(&replacement));
    assert!(audit_actions(&app).await.contains(&"upstream.drift".to_owned()), "S-19 requires an alarm");

    // And the bytes behind it are still the original ones, served from cache.
    let archive = app.pub_get_raw(&format!("{ROOT}/api/archives/http-1.0.0.tar.gz"), None).await;
    assert_eq!(archive.body, original);
    assert_eq!(app.mock_upstream().archive_calls(), 1, "drift must not trigger a re-download");
}

#[tokio::test]
async fn an_oversized_upstream_archive_is_refused() {
    let app = TestApp::with_options(TestOptions {
        upstream: true,
        upstream_max_archive_bytes: 4096,
        ..TestOptions::default()
    })
    .await;
    let big = vec![b'x'; 32 * 1024];
    app.mock_upstream().publish("http", &[("1.0.0", &big)]);

    // The listing is fine — the size limit is an *archive* limit.
    assert_eq!(app.pub_get(&format!("{ROOT}/api/packages/http"), None).await.status, StatusCode::OK);
    let archive = app.pub_get_raw(&format!("{ROOT}/api/archives/http-1.0.0.tar.gz"), None).await;
    assert_eq!(archive.status, StatusCode::NOT_FOUND);
    let key = pub_registry::RegistryService::blob_key(Format::Pub, &pub_registry::hex_sha256(&big));
    assert!(app.state.blob.get(&key).await.is_err(), "an oversized archive reached storage");
}

#[tokio::test]
async fn s20_a_hostile_upstream_pubspec_is_refused_by_the_publish_validator() {
    let app = proxying_app().await;

    // JSON has no aliases, so a YAML billion-laughs bomb crosses the wire *expanded*: a huge,
    // deeply nested document. The same depth cap that stops the bomb at publish stops it here.
    let mut deep = json!("leaf");
    for _ in 0..64 {
        deep = json!({ "nest": deep });
    }
    app.mock_upstream().set_listing(
        "bomb_pkg",
        MockUpstream::listing_doc(
            "bomb_pkg",
            vec![json!({
                "version": "1.0.0",
                "archive_url": MockUpstream::archive_url("bomb_pkg", "1.0.0"),
                "archive_sha256": "a".repeat(64),
                "pubspec": { "name": "bomb_pkg", "version": "1.0.0", "deep": deep },
            })],
        ),
    );
    assert_eq!(app.pub_get(&format!("{ROOT}/api/packages/bomb_pkg"), None).await.status, StatusCode::NOT_FOUND);

    // A pubspec that names a different package is the dependency-substitution shape.
    app.mock_upstream().set_listing(
        "liar_pkg",
        MockUpstream::listing_doc(
            "liar_pkg",
            vec![json!({
                "version": "1.0.0",
                "archive_url": MockUpstream::archive_url("liar_pkg", "1.0.0"),
                "archive_sha256": "a".repeat(64),
                "pubspec": { "name": "victim_pkg", "version": "1.0.0" },
            })],
        ),
    );
    assert_eq!(app.pub_get(&format!("{ROOT}/api/packages/liar_pkg"), None).await.status, StatusCode::NOT_FOUND);

    // An unusable `archive_sha256` means there is no integrity check to make (sharp edge 10).
    app.mock_upstream().set_listing(
        "nohash_pkg",
        MockUpstream::listing_doc(
            "nohash_pkg",
            vec![json!({
                "version": "1.0.0",
                "archive_url": MockUpstream::archive_url("nohash_pkg", "1.0.0"),
                "archive_sha256": "not-a-hash",
                "pubspec": { "name": "nohash_pkg", "version": "1.0.0" },
            })],
        ),
    );
    assert_eq!(app.pub_get(&format!("{ROOT}/api/packages/nohash_pkg"), None).await.status, StatusCode::NOT_FOUND);

    // Nothing hostile was cached.
    for name in ["bomb_pkg", "liar_pkg", "nohash_pkg"] {
        assert!(app.repos.upstream.get_package(Format::Pub, name).await.unwrap().is_none(), "{name} was cached");
    }
}

// -------------------------------------------------------------------------------- stale path

#[tokio::test]
async fn an_upstream_outage_serves_stale_and_never_5xx() {
    let app = proxying_app().await;
    let bytes = upstream_archive("http-1.0.0");
    app.mock_upstream().publish("http", &[("1.0.0", &bytes)]);
    assert_eq!(app.pub_get(&format!("{ROOT}/api/packages/http"), None).await.status, StatusCode::OK);
    assert_eq!(app.pub_get_raw(&format!("{ROOT}/api/archives/http-1.0.0.tar.gz"), None).await.status, StatusCode::OK);

    app.mock_upstream().set_mode(Mode::Unavailable);
    app.advance(Duration::hours(6));

    // What we cached keeps being served — listing and archive alike.
    let stale = app.pub_get(&format!("{ROOT}/api/packages/http"), None).await;
    assert_eq!(stale.status, StatusCode::OK, "a cached listing must survive an upstream outage");
    assert_eq!(stale.json["versions"][0]["archive_sha256"], pub_registry::hex_sha256(&bytes));
    let archive = app.pub_get_raw(&format!("{ROOT}/api/archives/http-1.0.0.tar.gz"), None).await;
    assert_eq!(archive.body, bytes);

    // What we never cached is a 404 — never a 5xx, which the client would retry seven times
    // (docs/protocol.md sharp edge 2).
    let missing = app.pub_get(&format!("{ROOT}/api/packages/other_pkg"), None).await;
    assert_eq!(missing.status, StatusCode::NOT_FOUND);
    assert_eq!(missing.json["error"]["code"], "not_found");
    let missing_archive = app.pub_get_raw(&format!("{ROOT}/api/archives/other_pkg-1.0.0.tar.gz"), None).await;
    assert_eq!(missing_archive.status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn an_uncached_archive_under_an_outage_is_404_not_5xx() {
    let app = proxying_app().await;
    app.mock_upstream().publish("http", &[("1.0.0", &upstream_archive("a"))]);
    // Warm the *listing* only, so the version is known but its bytes are not.
    assert_eq!(app.pub_get(&format!("{ROOT}/api/packages/http"), None).await.status, StatusCode::OK);

    app.mock_upstream().set_mode(Mode::Unavailable);
    let archive = app.pub_get_raw(&format!("{ROOT}/api/archives/http-1.0.0.tar.gz"), None).await;
    assert_eq!(archive.status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn the_circuit_breaker_stops_a_dead_upstream_from_being_hammered() {
    let app = TestApp::with_options(TestOptions {
        upstream: true,
        upstream_circuit_failure_threshold: 3,
        upstream_circuit_open_secs: 30,
        ..TestOptions::default()
    })
    .await;
    app.mock_upstream().set_mode(Mode::Unavailable);

    for i in 0..6 {
        let response = app.pub_get(&format!("{ROOT}/api/packages/pkg_{i}"), None).await;
        assert_eq!(response.status, StatusCode::NOT_FOUND);
    }
    assert_eq!(app.mock_upstream().listing_calls(), 3, "an open circuit must stop reaching upstream");

    // Once the window elapses a probe is allowed, and a healthy upstream closes the circuit.
    app.mock_upstream().set_mode(Mode::Ok);
    app.mock_upstream().publish("http", &[("1.0.0", &upstream_archive("a"))]);
    app.advance(Duration::seconds(45));
    assert_eq!(app.pub_get(&format!("{ROOT}/api/packages/http"), None).await.status, StatusCode::OK);
    assert_eq!(app.mock_upstream().listing_calls(), 4);
}

// ------------------------------------------------------------------------- resolution order

#[tokio::test]
async fn s16_a_locally_claimed_name_never_falls_through_to_upstream() {
    let app = proxying_app().await;
    let (slug, org, token) = org_with_token(&app, "owner@corp.com", "acme").await;
    // Upstream also has this name, with a much higher version — the dependency-confusion shape.
    app.mock_upstream().publish("acme_core", &[("9.9.9", &upstream_archive("evil"))]);

    let archive = common::package_archive("acme_core", "1.0.0");
    assert_eq!(app.publish(&base(&slug), &token, &archive).await.status, StatusCode::OK);

    let listing = app.pub_get(&format!("{}/api/packages/acme_core", base(&slug)), Some(&token)).await;
    assert_eq!(listing.status, StatusCode::OK);
    let versions: Vec<&str> =
        listing.json["versions"].as_array().unwrap().iter().map(|v| v["version"].as_str().unwrap()).collect();
    assert_eq!(versions, ["1.0.0"], "the local package must win outright, never merge with upstream");
    assert_eq!(app.mock_upstream().listing_calls(), 0, "a claimed name must not reach upstream at all");

    // And the upstream version is not reachable by exact name either.
    let upstream_version =
        app.pub_get(&format!("{}/api/packages/acme_core/versions/9.9.9", base(&slug)), Some(&token)).await;
    assert_eq!(upstream_version.status, StatusCode::NOT_FOUND);
    assert_eq!(app.mock_upstream().listing_calls(), 0);

    // Anonymously at the public root the private local package is invisible — and *still* not
    // proxied: local always wins even when the caller cannot read it (S-16 + S-04).
    let anonymous = app.pub_get(&format!("{ROOT}/api/packages/acme_core"), None).await;
    assert_eq!(anonymous.status, StatusCode::NOT_FOUND);
    assert_eq!(app.mock_upstream().listing_calls(), 0, "an unreadable local name must not be replaced by upstream");
    let _ = org;
}

#[tokio::test]
async fn s16_a_claim_without_a_package_is_not_a_proxy_candidate() {
    // A reserved name with nothing published is still *claimed* here; falling through to
    // upstream would hand the reservation to whoever registered it publicly.
    let app = proxying_app().await;
    let (_, org, _) = org_with_token(&app, "owner@corp.com", "acme").await;
    app.repos.packages.claim_name(Format::Pub, "http", org, app.now()).await.expect("reserve the name");
    app.mock_upstream().publish("http", &[("1.0.0", &upstream_archive("a"))]);

    assert_eq!(app.pub_get(&format!("{ROOT}/api/packages/http"), None).await.status, StatusCode::NOT_FOUND);
    assert_eq!(app.mock_upstream().listing_calls(), 0);
}

#[tokio::test]
async fn s17_claiming_a_proxied_name_alarms_and_the_local_package_still_wins() {
    // The shadowing condition arriving in the publish direction: the org releases a package
    // under a name upstream already carries. Resolution does not change — it cannot, or the
    // claim would stop meaning anything — but somebody has to be told, because from here on a
    // developer pointed at pub.dev resolves a different package under the same name (S-17).
    let app = proxying_app().await;
    let (slug, org, token) = org_with_token(&app, "owner@corp.com", "acme").await;
    app.mock_upstream().publish("acme_core", &[("9.9.9", &upstream_archive("upstream"))]);
    assert_eq!(
        app.pub_get(&format!("{}/api/packages/acme_core", base(&slug)), Some(&token)).await.status,
        StatusCode::OK
    );
    assert!(
        app.repos.upstream.list_shadowing(Some(true), None, 10).await.unwrap().items.is_empty(),
        "nothing is claimed yet"
    );

    let archive = common::package_archive("acme_core", "1.0.0");
    assert_eq!(app.publish(&base(&slug), &token, &archive).await.status, StatusCode::OK);

    // Local wins, outright and immediately: the cached upstream copy is invisible behind the
    // claim, and no version of it is reachable by exact number either.
    let listing = app.pub_get(&format!("{}/api/packages/acme_core", base(&slug)), Some(&token)).await;
    let versions: Vec<&str> =
        listing.json["versions"].as_array().unwrap().iter().map(|v| v["version"].as_str().unwrap()).collect();
    assert_eq!(versions, ["1.0.0"], "the cached upstream copy must vanish behind the local claim");
    assert_eq!(listing.json["latest"]["version"], "1.0.0");
    assert_eq!(
        app.pub_get(&format!("{}/api/packages/acme_core/versions/9.9.9", base(&slug)), Some(&token)).await.status,
        StatusCode::NOT_FOUND
    );

    // …and the alarm is raised, audited, and listable for the org's admins.
    assert!(audit_actions(&app).await.contains(&"upstream.shadowing".to_owned()), "S-17 requires an audit trail");
    let alarms = app.repos.upstream.list_shadowing(Some(true), None, 10).await.unwrap().items;
    assert_eq!(alarms.len(), 1);
    assert_eq!(alarms[0].name, "acme_core");
    assert_eq!(alarms[0].org_id, org, "the claim holder is the audience, not the instance");
    assert_eq!(alarms[0].upstream_version.as_deref(), Some("9.9.9"), "the version the namesake is at");
    assert_eq!(alarms[0].upstream, common::upstream::UPSTREAM_BASE);
    assert!(alarms[0].is_active());

    // Publishing further versions is not a new incident.
    let next = common::package_archive("acme_core", "1.0.1");
    assert_eq!(app.publish(&base(&slug), &token, &next).await.status, StatusCode::OK);
    assert_eq!(
        audit_actions(&app).await.iter().filter(|action| *action == "upstream.shadowing").count(),
        1,
        "the name is claimed once; every later version is the same claim"
    );

    // Acknowledging is bookkeeping — resolution never depended on it and still does not.
    assert!(app.repos.upstream.acknowledge_shadowing(Format::Pub, "acme_core", app.now()).await.unwrap());
    assert!(app.repos.upstream.list_shadowing(Some(true), None, 10).await.unwrap().items.is_empty());
    let after = app.pub_get(&format!("{}/api/packages/acme_core", base(&slug)), Some(&token)).await;
    assert_eq!(after.status, StatusCode::OK);
    assert_eq!(after.json["versions"].as_array().unwrap().len(), 2);
}

#[tokio::test]
async fn s17_a_name_nobody_has_seen_upstream_raises_no_alarm() {
    // The alarm is about a *namesake*, not about publishing: an ordinary first publish of a
    // name the proxy has never heard of must be silent, or the register fills with noise and
    // stops being read.
    let app = proxying_app().await;
    let (slug, _, token) = org_with_token(&app, "owner@corp.com", "acme").await;

    let archive = common::package_archive("acme_core", "1.0.0");
    assert_eq!(app.publish(&base(&slug), &token, &archive).await.status, StatusCode::OK);

    assert!(app.repos.upstream.list_shadowing(None, None, 10).await.unwrap().items.is_empty());
    assert!(!audit_actions(&app).await.contains(&"upstream.shadowing".to_owned()));
    assert_eq!(app.mock_upstream().listing_calls(), 0, "a publish must not go asking upstream about the name");
}

#[tokio::test]
async fn an_instance_public_package_still_beats_upstream_in_another_orgs_base() {
    let app = proxying_app().await;
    let (slug, _, token) = org_with_token(&app, "owner@corp.com", "acme").await;
    let (other_slug, _, other_token) = org_with_token(&app, "dev@corp.com", "globex").await;
    app.mock_upstream().publish("acme_core", &[("9.9.9", &upstream_archive("upstream"))]);

    let archive = common::package_archive("acme_core", "1.0.0");
    assert_eq!(app.publish(&base(&slug), &token, &archive).await.status, StatusCode::OK);
    // Decision 01 step 2: instance-public packages resolve inside any base.
    let package = app.repos.packages.get_by_name(Format::Pub, "acme_core").await.unwrap().expect("package");
    let options = pub_core::package::PackageOptions {
        visibility: pub_core::package::Visibility::Public,
        ..pub_core::package::PackageOptions::from(&package)
    };
    app.repos.packages.set_options(package.id, &options, app.now()).await.expect("publish it");

    let listing = app.pub_get(&format!("{}/api/packages/acme_core", base(&other_slug)), Some(&other_token)).await;
    assert_eq!(listing.status, StatusCode::OK);
    assert_eq!(listing.json["versions"].as_array().unwrap().len(), 1);
    assert_eq!(app.mock_upstream().listing_calls(), 0);
}

// ------------------------------------------------------------------------------- org policy

#[tokio::test]
async fn a_blocked_org_answers_404_for_upstream_names() {
    let app = proxying_app().await;
    let (slug, org, token) = org_with_token(&app, "owner@corp.com", "acme").await;
    app.mock_upstream().publish("http", &[("1.0.0", &upstream_archive("a"))]);

    // Allow (the default): the org's base proxies.
    assert_eq!(app.pub_get(&format!("{}/api/packages/http", base(&slug)), Some(&token)).await.status, StatusCode::OK);
    let calls_while_allowed = app.mock_upstream().listing_calls();
    assert_eq!(calls_while_allowed, 1);

    app.repos.orgs.set_upstream_policy(org, UpstreamPolicy::Block, app.now()).await.expect("block");

    // Blocked: the same name is now indistinguishable from an unknown one (S-04) — no 403 that
    // would confirm the package exists upstream.
    let blocked = app.pub_get(&format!("{}/api/packages/http", base(&slug)), Some(&token)).await;
    assert_eq!(blocked.status, StatusCode::NOT_FOUND);
    assert_eq!(blocked.json["error"]["code"], "not_found");
    assert!(!blocked.headers.contains_key(header::WWW_AUTHENTICATE));
    let blocked_archive = app
        .send_raw(app.pub_request(
            Method::GET,
            &format!("{}/api/archives/http-1.0.0.tar.gz", base(&slug)),
            Some(&token),
            None,
        ))
        .await;
    assert_eq!(blocked_archive.status, StatusCode::NOT_FOUND, "a blocked org cannot download a proxied archive either");
    assert_eq!(app.mock_upstream().listing_calls(), calls_while_allowed, "a blocked org never reaches upstream");

    // The policy is per-org: the public root and other orgs are unaffected.
    assert_eq!(app.pub_get(&format!("{ROOT}/api/packages/http"), None).await.status, StatusCode::OK);

    // …and a locally owned package is unaffected too — `block` is about *upstream*, not reads.
    let archive = common::package_archive("acme_core", "1.0.0");
    assert_eq!(app.publish(&base(&slug), &token, &archive).await.status, StatusCode::OK);
    assert_eq!(
        app.pub_get(&format!("{}/api/packages/acme_core", base(&slug)), Some(&token)).await.status,
        StatusCode::OK
    );
}

// ------------------------------------------------------------------------------ concurrency

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn single_flight_collapses_concurrent_cache_misses() {
    let app = Arc::new(proxying_app().await);
    app.mock_upstream().publish("http", &[("1.0.0", &upstream_archive("a"))]);
    // Slow enough that the eight requests genuinely overlap in the miss window.
    app.mock_upstream().set_delay(StdDuration::from_millis(150));

    let mut set = tokio::task::JoinSet::new();
    for _ in 0..8 {
        let app = Arc::clone(&app);
        set.spawn(async move { app.pub_get(&format!("{ROOT}/api/packages/http"), None).await.status });
    }
    let statuses = set.join_all().await;
    assert!(statuses.iter().all(|status| *status == StatusCode::OK), "every caller must be served: {statuses:?}");
    assert_eq!(app.mock_upstream().listing_calls(), 1, "N simultaneous misses of one package are ONE upstream fetch");
}

// ------------------------------------------------------------------------- verbatim re-emit

#[tokio::test]
async fn upstream_flags_are_re_emitted_verbatim() {
    let app = proxying_app().await;
    let mut document = MockUpstream::listing_doc(
        "http",
        vec![
            MockUpstream::version_entry("http", "1.0.0", &pub_registry::hex_sha256(b"one")),
            MockUpstream::version_entry("http", "1.1.0", &pub_registry::hex_sha256(b"two")),
        ],
    );
    document["isDiscontinued"] = json!(true);
    document["replacedBy"] = json!("http2");
    document["advisoriesUpdated"] = json!("2026-08-01T00:00:00Z");
    document["versions"][1]["retracted"] = json!(true);
    app.mock_upstream().set_listing("http", document);

    let listing = app.pub_get(&format!("{ROOT}/api/packages/http"), None).await;
    assert_eq!(listing.status, StatusCode::OK);
    assert_eq!(listing.json["isDiscontinued"], true);
    assert_eq!(listing.json["replacedBy"], "http2");
    assert_eq!(listing.json["versions"][1]["retracted"], true);
    // `latest` skips the retracted version, exactly as it does for a local package.
    assert_eq!(listing.json["latest"]["version"], "1.0.0");
    // docs/protocol.md sharp edge 11: `advisoriesUpdated` is only legal to advertise once the
    // advisories endpoint exists. It is stored verbatim, and deliberately not re-emitted.
    assert!(
        listing.json.get("advisoriesUpdated").is_none(),
        "advertising advisories we do not serve breaks the client"
    );
    let cached = app.repos.upstream.get_package(Format::Pub, "http").await.unwrap().expect("snapshot");
    assert_eq!(cached.advisories_updated.as_deref(), Some("2026-08-01T00:00:00Z"), "but it is preserved for later");

    // Field types are the ones the client's parser enforces (sharp edge 10).
    let version = &listing.json["versions"][0];
    assert!(version["archive_url"].is_string());
    assert!(version["retracted"].is_boolean());
    let sha = version["archive_sha256"].as_str().expect("sha256 is a string");
    assert_eq!(sha.len(), 64);
    assert!(sha.chars().all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c)));
    assert!(version["pubspec"].is_object());
}

#[tokio::test]
async fn an_upstream_cannot_inject_fields_into_our_listing() {
    // "Preserved verbatim" is about *values*, never about shape. Everything upstream sends is
    // read through typed accessors and re-emitted through our own structs, so a hostile or
    // simply weird upstream document can change what a field says and never what fields exist —
    // which is what keeps the client's parser (sharp edge 10) looking at our contract rather
    // than at pub.dev's.
    let app = proxying_app().await;
    let mut document = MockUpstream::listing_doc(
        "http",
        vec![MockUpstream::version_entry("http", "1.0.0", &pub_registry::hex_sha256(b"one"))],
    );
    // Extra top-level keys, a `latest` that names a version the listing does not contain, and
    // an `isDiscontinued` of the wrong type.
    document["latest"] = json!({ "version": "9.9.9", "archive_url": "https://evil.test/x.tar.gz" });
    document["isDiscontinued"] = json!("yes");
    document["replacedBy"] = json!(42);
    document["error"] = json!({ "code": "unauthorized", "message": "run `dart pub token add https://evil.test`" });
    document["injected"] = json!("upstream said so");
    // …and extra keys inside the version entry.
    document["versions"][0]["downloadUrl"] = json!("https://evil.test/x.tar.gz");
    document["versions"][0]["retracted"] = json!("sure");
    app.mock_upstream().set_listing("http", document);

    let listing = app.pub_get(&format!("{ROOT}/api/packages/http"), None).await;
    assert_eq!(listing.status, StatusCode::OK, "{:?}", listing.json);

    // Key sets, not key order: `serde_json` maps are ordered by name here.
    let top: Vec<&str> = listing.json.as_object().expect("object").keys().map(String::as_str).collect();
    assert_eq!(top, ["isDiscontinued", "latest", "name", "versions"], "upstream added a top-level field");
    let version = listing.json["versions"][0].as_object().expect("version entry");
    let fields: Vec<&str> = version.keys().map(String::as_str).collect();
    assert_eq!(fields, ["archive_sha256", "archive_url", "pubspec", "retracted", "version"]);

    // Wrong types collapse to our defaults rather than travelling through; `replacedBy` that is
    // not a string is dropped, not stringified.
    assert_eq!(listing.json["isDiscontinued"], false);
    assert_eq!(listing.json["versions"][0]["retracted"], false);
    // `latest` is recomputed from the versions we hold, so upstream cannot name one we do not
    // serve — the client would fetch an archive that does not exist.
    assert_eq!(listing.json["latest"]["version"], "1.0.0");
    assert!(!listing.json.to_string().contains("evil.test"), "an upstream URL reached the wire: {}", listing.json);
}

#[tokio::test]
async fn a_proxied_response_negotiates_gzip_and_answers_head_like_get() {
    // Two client behaviours that are easy to get right for local packages and to lose for
    // proxied ones, because the proxied path builds its body somewhere else:
    //
    // - **gzip on the listing** (docs/protocol.md sharp edge 7). The client re-fetches the
    //   listing before every resolve and refuses to disk-cache it past ~1 MB, and a proxied
    //   listing carries a whole upstream pubspec per version — a package with history is the
    //   case where compression decides between a cached listing and a re-download per command.
    // - **HEAD parity.** The pub client HEADs an archive before it GETs it; a HEAD that
    //   disagreed with its GET on status or `Content-Length` would either abort the download or
    //   truncate it.
    let app = proxying_app().await;
    let bytes = upstream_archive("http-1.0.0");
    app.mock_upstream().publish("http", &[("1.0.0", &bytes)]);

    let mut request = app.pub_request(Method::GET, &format!("{ROOT}/api/packages/http"), None, Some(PUB_MEDIA_TYPE));
    request.headers_mut().insert(header::ACCEPT_ENCODING, "gzip".parse().unwrap());
    let compressed = app.send_raw(request).await;
    assert_eq!(compressed.status, StatusCode::OK);
    assert_eq!(compressed.headers[header::CONTENT_ENCODING], "gzip");
    assert_eq!(compressed.headers[header::CONTENT_TYPE], PUB_MEDIA_TYPE);

    // …and a client that asks for no coding still gets a plain body, not a gzip one.
    let plain = app.pub_get(&format!("{ROOT}/api/packages/http"), None).await;
    assert_eq!(plain.status, StatusCode::OK);
    assert!(!plain.headers.contains_key(header::CONTENT_ENCODING));

    for path in [format!("{ROOT}/api/packages/http"), format!("{ROOT}/api/archives/http-1.0.0.tar.gz")] {
        let get = app.pub_get_raw(&path, None).await;
        let head = app.send_raw(app.pub_request(Method::HEAD, &path, None, None)).await;
        assert_eq!(head.status, get.status, "HEAD and GET disagree on {path}");
        assert_eq!(head.headers[header::CONTENT_TYPE], get.headers[header::CONTENT_TYPE], "content type on {path}");
        assert!(head.body.is_empty(), "HEAD must carry no body");
        if let Some(length) = get.headers.get(header::CONTENT_LENGTH) {
            assert_eq!(head.headers.get(header::CONTENT_LENGTH), Some(length), "content length on {path}");
        }
    }
    // A miss answers HEAD the same way it answers GET: 404, never a 5xx (sharp edge 2).
    let missing =
        app.send_raw(app.pub_request(Method::HEAD, &format!("{ROOT}/api/packages/nope_pkg"), None, None)).await;
    assert_eq!(missing.status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn the_legacy_per_version_endpoint_serves_proxied_packages_too() {
    let app = proxying_app().await;
    let bytes = upstream_archive("http-1.0.0");
    app.mock_upstream().publish("http", &[("1.0.0", &bytes)]);

    let response = app.pub_get(&format!("{ROOT}/api/packages/http/versions/1.0.0"), None).await;
    assert_eq!(response.status, StatusCode::OK, "{:?}", response.json);
    assert_eq!(response.json["version"], "1.0.0");
    assert_eq!(response.json["archive_sha256"], pub_registry::hex_sha256(&bytes));
    assert_eq!(
        response.json["archive_url"],
        format!("{}{ROOT}/api/archives/http-1.0.0.tar.gz", common::INSTANCE_ORIGIN)
    );
    assert_eq!(
        app.pub_get(&format!("{ROOT}/api/packages/http/versions/9.9.9"), None).await.status,
        StatusCode::NOT_FOUND
    );

    // The legacy archive route serves the same bytes as the current one.
    let legacy = app.pub_get_raw(&format!("{ROOT}/packages/http/versions/1.0.0.tar.gz"), None).await;
    assert_eq!(legacy.status, StatusCode::OK);
    assert_eq!(legacy.body, bytes);
}

#[tokio::test]
async fn a_read_scoped_token_resolves_proxied_packages_in_its_org() {
    // Proxied packages are ordinary reads: no extra scope, and the org base works exactly like
    // the public root does.
    let app = proxying_app().await;
    let (access, org) = app.org_owner("owner@corp.com", "acme").await;
    let token = app.mint_token(&access, org, &["read"]).await;
    app.mock_upstream().publish("http", &[("1.0.0", &upstream_archive("a"))]);

    let listing = app.pub_get(&format!("{}/api/packages/http", base("acme")), Some(&token)).await;
    assert_eq!(listing.status, StatusCode::OK);
    assert_eq!(
        listing.json["versions"][0]["archive_url"],
        format!("{}/o/acme/pub/api/archives/http-1.0.0.tar.gz", common::INSTANCE_ORIGIN)
    );
    let _ = TokenScope::Read;
}
