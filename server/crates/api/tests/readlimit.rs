//! Read-path rate limiting on both planes — [S-24.f](../../../../docs/security.md#5-audit--abuse)
//! and [S-13.b](../../../../docs/security.md#3-cliapi-tokens), decision 27.
//!
//! | Test | Requirement |
//! |---|---|
//! | `s24_f_an_anonymous_read_burst_is_refused_with_retry_after` | reads are bucketed at all |
//! | `s24_f_the_pub_protocol_plane_is_bucketed_too` | `dart pub get` volume is inside the limit |
//! | `s13_b_two_tokens_do_not_share_a_budget` | a token is a rate-limit identity of its own |
//! | `s24_f_a_signed_in_account_does_not_spend_the_anonymous_ip_bucket` | identity beats IP |
//! | `s24_f_health_and_the_event_stream_are_exempt` | the two documented exemptions |
//! | `s24_f_a_trip_is_audited_once_per_window_not_once_per_request` | audit is not amplifiable |
//! | `s24_f_an_unverifiable_credential_falls_back_to_the_ip_bucket` | no free bucket by forgery |

mod common;

use axum::http::StatusCode;
use common::{TestApp, TestOptions};

/// A tiny anonymous budget; everything identified stays wide open so a test that means to
/// exercise one bucket cannot accidentally trip the other.
fn anon_budget(read_per_ip_minute: u32) -> TestOptions {
    TestOptions { read_per_ip_minute, read_per_identity_minute: 100_000, ..TestOptions::default() }
}

/// **S-24.f.** An unauthenticated read burst is refused, with the header that says when to
/// come back — the bucket that did not exist at all before this wave.
#[tokio::test]
async fn s24_f_an_anonymous_read_burst_is_refused_with_retry_after() {
    let app = TestApp::with_options(anon_budget(3)).await;

    for i in 0..3 {
        let response = app.get("/api/v1/packages?q=anything", None).await;
        assert_ne!(response.status, StatusCode::TOO_MANY_REQUESTS, "read {i} is inside the budget");
    }
    let refused = app.get("/api/v1/packages?q=anything", None).await;
    assert_eq!(refused.status, StatusCode::TOO_MANY_REQUESTS);
    let retry_after: u64 =
        refused.headers.get("retry-after").expect("Retry-After").to_str().unwrap().parse().expect("seconds");
    assert!((1..=60).contains(&retry_after), "the window is a minute, got {retry_after}");
}

/// **S-24.f.** The pub protocol plane is bucketed too. A limit the plane carrying every
/// `dart pub get` does not have is not a limit — it is a limit on the web UI.
#[tokio::test]
async fn s24_f_the_pub_protocol_plane_is_bucketed_too() {
    let app = TestApp::with_options(anon_budget(2)).await;

    for i in 0..2 {
        let response = app.pub_get("/pub/api/packages/anything", None).await;
        assert_ne!(response.status, StatusCode::TOO_MANY_REQUESTS, "resolve {i} is inside the budget");
    }
    let refused = app.pub_get("/pub/api/packages/anything", None).await;
    assert_eq!(refused.status, StatusCode::TOO_MANY_REQUESTS);
    assert!(refused.headers.contains_key("retry-after"), "429 must say when to retry");
    // The refusal must speak the *plane's* dialect. Asserting the body shape proves nothing
    // here — the app envelope and the pub spec error share a JSON structure — so this asserts
    // the media type, which is what `dart pub` decides by (docs/rules/api.md; sharp edge 2).
    assert_eq!(
        refused.headers.get("content-type").and_then(|value| value.to_str().ok()),
        Some(common::PUB_MEDIA_TYPE),
        "a middleware refusal on the registry plane must carry the pub v2 media type"
    );
    assert!(refused.json["error"]["message"].is_string(), "spec error shape, got {:?}", refused.json);
}

/// **S-13.b.** Two CLI tokens are two identities. Before this, "per-token rate limits" in S-13
/// described nothing that existed — every bucket on the token plane was keyed on the IP, so one
/// noisy CI runner throttled every other client behind the same NAT.
#[tokio::test]
async fn s13_b_two_tokens_do_not_share_a_budget() {
    let app = TestApp::with_options(TestOptions {
        // Small identity budget, generous IP budget: this test is about the identity split.
        read_per_identity_minute: 2,
        read_per_ip_minute: 100_000,
        ..TestOptions::default()
    })
    .await;
    let (access, org) = app.org_owner("owner@corp.com", "acme").await;
    let first = app.mint_token(&access, org, &["read"]).await;
    let second = app.mint_token(&access, org, &["read"]).await;

    for i in 0..2 {
        let response = app.pub_get("/pub/api/packages/anything", Some(&first)).await;
        assert_ne!(response.status, StatusCode::TOO_MANY_REQUESTS, "first token, read {i}");
    }
    assert_eq!(
        app.pub_get("/pub/api/packages/anything", Some(&first)).await.status,
        StatusCode::TOO_MANY_REQUESTS,
        "the first token has spent its own budget"
    );
    // Same IP, same instance, same second. A per-IP bucket would refuse this one too.
    assert_ne!(
        app.pub_get("/pub/api/packages/anything", Some(&second)).await.status,
        StatusCode::TOO_MANY_REQUESTS,
        "a second token must carry a budget of its own (S-13.b)"
    );
}

/// **S-24.f.** A signed-in account rides the identity budget, not the anonymous per-IP one.
/// That separation is the whole reason there are two numbers.
#[tokio::test]
async fn s24_f_a_signed_in_account_does_not_spend_the_anonymous_ip_bucket() {
    let app = TestApp::with_options(TestOptions {
        read_per_ip_minute: 1,
        read_per_identity_minute: 100_000,
        ..TestOptions::default()
    })
    .await;
    let session = app.login("member@corp.com").await;
    let access = session["access_token"].as_str().expect("access token").to_owned();

    // Spend the anonymous budget from this IP entirely.
    app.get("/api/v1/packages?q=x", None).await;
    assert_eq!(app.get("/api/v1/packages?q=x", None).await.status, StatusCode::TOO_MANY_REQUESTS);

    // The signed-in caller is unaffected: same IP, different identity.
    for i in 0..5 {
        let response = app.get("/api/v1/packages?q=x", Some(&access)).await;
        assert_ne!(response.status, StatusCode::TOO_MANY_REQUESTS, "authenticated read {i} must pass");
    }
}

/// **S-24.f.** The two documented exemptions, asserted rather than assumed: an orchestrator's
/// liveness probe must not be throttled (S-24 exempts health checks), and the SSE stream is one
/// request per session rather than a rate.
#[tokio::test]
async fn s24_f_health_and_the_event_stream_are_exempt() {
    let app = TestApp::with_options(anon_budget(1)).await;

    // Well past the budget of one.
    for i in 0..10 {
        assert_eq!(app.get("/healthz", None).await.status, StatusCode::OK, "health probe {i} must answer");
    }
    // ...and the budget is genuinely spent, so the exemption is what let those through.
    assert_eq!(app.get("/api/v1/packages?q=x", None).await.status, StatusCode::OK, "the first read is free");
    assert_eq!(app.get("/api/v1/packages?q=x", None).await.status, StatusCode::TOO_MANY_REQUESTS);

    // The stream refuses for its own reason (no credential), never with a 429.
    let stream = app.open_stream_expecting_error(None).await;
    assert_eq!(stream.status, StatusCode::UNAUTHORIZED, "the SSE stream is exempt from the read bucket");
}

/// **S-24.f / S-22.** A throttled bucket writes **one** audit row per window, not one per
/// refused request. Otherwise the limiter is a cheaper way to fill `audit_log` — a table with
/// no retention yet — than the traffic it refuses.
#[tokio::test]
async fn s24_f_a_trip_is_audited_once_per_window_not_once_per_request() {
    let app = TestApp::with_options(anon_budget(1)).await;

    app.get("/api/v1/packages?q=x", None).await;
    for _ in 0..8 {
        assert_eq!(app.get("/api/v1/packages?q=x", None).await.status, StatusCode::TOO_MANY_REQUESTS);
    }

    let actions = app.audit_actions().await;
    let throttles = actions.iter().filter(|action| *action == "read.throttled").count();
    assert_eq!(throttles, 1, "eight refusals in one window are one audit row, not eight");
    // ...and a read trip must not land under the credential-abuse action, or an operator
    // filtering for sign-in abuse reads a scraper's traffic as an attack on their auth plane.
    assert!(!actions.iter().any(|action| action == "auth.throttled"), "a read trip is not an auth trip");
}

/// **S-24.f.** A credential that verifies as neither a CLI token nor a session falls back to
/// the per-IP bucket. Otherwise every forged string would be a fresh budget, and the read limit
/// would be bypassable by anyone who can type `Authorization:`.
#[tokio::test]
async fn s24_f_an_unverifiable_credential_falls_back_to_the_ip_bucket() {
    let app = TestApp::with_options(anon_budget(2)).await;

    // Two different garbage bearers: distinct strings, and they must share one bucket.
    app.get("/api/v1/packages?q=x", Some("not-a-real-token")).await;
    app.get("/api/v1/packages?q=x", Some("another-fake-token")).await;
    let refused = app.get("/api/v1/packages?q=x", Some("a-third-one")).await;
    assert_eq!(
        refused.status,
        StatusCode::TOO_MANY_REQUESTS,
        "an unverifiable credential must not mint a fresh read budget"
    );
}
