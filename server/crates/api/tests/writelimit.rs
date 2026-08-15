//! Write-path rate limiting on the app API — [S-24.g](../../../../docs/security.md#5-audit--abuse)
//! and decision 32 — plus the "one identity per request" property that pays for it (D58).
//!
//! | Test | Requirement |
//! |---|---|
//! | `s24_g_a_write_burst_is_refused_with_retry_after` | mutations are bucketed at all (D57) |
//! | `s24_g_a_cli_token_is_not_a_write_identity_on_the_app_plane` | decision 27's re-check clause, pulled |
//! | `s24_g_a_signed_in_account_does_not_spend_the_anonymous_ip_bucket` | identity beats IP, as on the read path |
//! | `s24_g_the_pub_plane_is_not_write_bucketed` | a publish spends its own budget and only that |
//! | `s24_g_the_credential_endpoints_are_not_double_charged` | the six exempt endpoints |
//! | `s24_g_a_request_the_s12_guard_refuses_spends_nothing` | the mounting order, stated as a behaviour |
//! | `s24_g_a_trip_is_audited_once_per_window_under_write_throttled` | a third action name, deduped per window |
//! | `s24_g_both_write_numbers_take_effect_without_a_restart` | runtime-changeable, per decision 09 |
//! | `d58_a_request_verifies_its_access_token_once` | one identity per request, counted not claimed |
//!
//! **Every test here is red until the router line exists.** The middleware is mounted by
//! `api/src/lib.rs` with
//! `.layer(axum::middleware::from_fn_with_state(state.clone(), guard::write_rate_limit))`
//! placed **last** in the `ServiceBuilder`, i.e. inside `guard::mutation_guard`.
//!
//! No test in this file is a concurrency test. [D51](../../../../docs/roadmap.md) records that
//! the `:memory:` harness pins SQLite to one connection and staggers every burst, so a
//! wire-level race claim here would be green by construction; the atomicity of the counter
//! these buckets spend is proven where it can fail, in
//! `pub_auth::ratelimit::tests::hit_is_atomic_under_concurrency`.

mod common;

use axum::body::Body;
use axum::http::{Method, Request, StatusCode, header};
use chrono::{DateTime, Utc};
use common::{DEFAULT_IP, TestApp, TestOptions};

/// The rate-limit key a bucket lives under at `now` — `{prefix}:{floor(now / 60)}`, the layout
/// `pub_auth::ratelimit` writes.
///
/// Spelled out rather than derived from the limiter, because "the pub plane spends no write
/// bucket" is an assertion about a key that must *not* exist, and a helper that shared the
/// production code's mistake would agree with it.
fn window_key(prefix: &str, now: DateTime<Utc>) -> String {
    format!("{prefix}:{}", now.timestamp().div_euclid(60))
}

/// A mutation from the default IP that deliberately omits the S-12 custom header.
fn without_custom_header(path: &str) -> Request<Body> {
    Request::builder()
        .method(Method::POST)
        .uri(path)
        .header("x-forwarded-for", DEFAULT_IP)
        .header(header::USER_AGENT, "pub-tests/1.0")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(r#"{"name":"acme","slug":"acme"}"#))
        .expect("build request")
}

/// A body that creates a distinct org per index — org creation is the mutation used throughout,
/// because it is authenticated, cheap, and reachable by any signed-in account.
fn new_org(index: usize) -> serde_json::Value {
    serde_json::json!({ "name": format!("acme{index}"), "slug": format!("acme{index}") })
}

/// **S-24.g.** An authenticated write burst is refused, with the header that says when to come
/// back. Before this bucket the only bound on mutations was the D8 concurrency shed, which caps
/// concurrency and not rate — an account could write as fast as the instance answered (D57).
#[tokio::test]
async fn s24_g_a_write_burst_is_refused_with_retry_after() {
    let app = TestApp::with_options(TestOptions {
        write_per_identity_minute: 3,
        write_per_ip_minute: 100_000,
        ..TestOptions::default()
    })
    .await;
    let access = app.login("owner@corp.com").await["access_token"].as_str().expect("access token").to_owned();

    for index in 0..3 {
        let response = app.post("/api/v1/orgs", Some(&access), new_org(index)).await;
        assert_eq!(response.status, StatusCode::OK, "write {index} is inside the budget: {:?}", response.json);
    }
    let refused = app.post("/api/v1/orgs", Some(&access), new_org(3)).await;
    assert_eq!(refused.status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(refused.error_code(), "rate_limited");
    let retry_after: u64 =
        refused.headers.get("retry-after").expect("Retry-After").to_str().unwrap().parse().expect("seconds");
    assert!((1..=60).contains(&retry_after), "the window is a minute, got {retry_after}");
}

/// **S-24.g / S-13.b.** Two CLI tokens are two write identities, exactly as they are two read
/// identities. A CLI token never authenticates on the app API — the extractor refuses it — but
/// the *bucket* runs first, and keying it on the IP would let one noisy client throttle every
/// other client behind the same NAT.
#[tokio::test]
async fn s24_g_a_cli_token_is_not_a_write_identity_on_the_app_plane() {
    let app = TestApp::with_options(TestOptions {
        // The mirror image of the pub-plane test in `readlimit.rs`: a tiny **IP** budget and a
        // wide identity one, so only a token landing in the per-IP bucket can refuse anything.
        write_per_ip_minute: 2,
        write_per_identity_minute: 100_000,
        ..TestOptions::default()
    })
    .await;
    let (_access, org) = app.org_owner("owner@corp.com", "acme").await;
    let owner = app.user_of("owner@corp.com").await;
    // Inserted through the repository, not minted over HTTP: a mint is itself a write and would
    // spend the owner's budget rather than the one under test.
    let first = app.insert_token(owner, org, &[pub_core::token::TokenScope::Admin], &[], None).await;
    let second = app.insert_token(owner, org, &[pub_core::token::TokenScope::Admin], &[], None).await;

    for index in 0..2 {
        let response = app.post("/api/v1/orgs", Some(&first), new_org(index)).await;
        assert_eq!(response.status, StatusCode::UNAUTHORIZED, "a CLI token never authenticates here, write {index}");
    }
    // A *different* token, same IP, same second. Under the rule this test replaces each token
    // carried its own `write_per_identity_minute` bucket, so this request was admitted and the
    // per-IP write cap was unenforceable against anyone willing to send a fresh fake token per
    // request — `pub_auth::token::validate` is prefix, length, charset and CRC32, all offline.
    // Decision 27 accepted that trade on the pub plane, where a bad token spends
    // `token_auth_fail_per_ip_minute`, and named this exact re-check: a plane that accepts CLI
    // tokens without spending the failure budget. The app API is that plane, so here a
    // token-shaped credential is an anonymous caller and shares the address's bucket.
    assert_eq!(
        app.post("/api/v1/orgs", Some(&second), new_org(2)).await.status,
        StatusCode::TOO_MANY_REQUESTS,
        "two CLI tokens from one address share the per-IP write bucket"
    );
}

/// **S-24.g.** A signed-in account rides the identity budget, not the anonymous per-IP one —
/// the reason there are two numbers rather than one, mirroring S-24.f.
#[tokio::test]
async fn s24_g_a_signed_in_account_does_not_spend_the_anonymous_ip_bucket() {
    let app = TestApp::with_options(TestOptions {
        write_per_ip_minute: 1,
        write_per_identity_minute: 100_000,
        ..TestOptions::default()
    })
    .await;
    let access = app.login("member@corp.com").await["access_token"].as_str().expect("access token").to_owned();

    // Spend the anonymous budget from this IP. The request is refused for its own reason (no
    // credential), and it still costs a unit — a bucket that only charged successful writes
    // would be trivially bypassable.
    let first = app.post("/api/v1/orgs", None, new_org(0)).await;
    assert_eq!(first.status, StatusCode::UNAUTHORIZED, "anonymous writes fail for their own reason");
    assert_eq!(app.post("/api/v1/orgs", None, new_org(1)).await.status, StatusCode::TOO_MANY_REQUESTS);

    // The signed-in caller is unaffected: same IP, different identity.
    for index in 2..5 {
        let response = app.post("/api/v1/orgs", Some(&access), new_org(index)).await;
        assert_eq!(response.status, StatusCode::OK, "authenticated write {index}: {:?}", response.json);
    }
}

/// **S-24.g.** The pub protocol plane is **not** write-bucketed: its one write already spends
/// S-24.c's per-org publish budget, and charging it twice would answer 429 for two unrelated
/// reasons with two different `Retry-After` values on one `dart pub publish`.
///
/// Asserted on the keyspace rather than on a status, because the honest claim is "no write
/// bucket was spent", not "the publish happened to succeed". The app-API mutation in the same
/// test is the positive control: without it, a missing key would prove only that the assertion
/// was looking in the wrong place.
#[tokio::test]
async fn s24_g_the_pub_plane_is_not_write_bucketed() {
    let app = TestApp::new().await;
    let (access, org) = app.org_owner("owner@corp.com", "acme").await;
    let user = app.user_of("owner@corp.com").await;
    let token = app.mint_token(&access, org, &["read", "publish"]).await;

    let published = app.publish("/o/acme/pub", &token, &common::package_archive("acme_core", "1.0.0")).await;
    assert_eq!(published.status, StatusCode::OK, "publish failed: {:?}", published.json);

    let now = app.now();
    let token_hash = pub_auth::token::sha256_hex(&token);
    assert_eq!(
        app.kv_get(&window_key(&format!("rl:write:tok:{}", &token_hash[..16]), now)).await,
        None,
        "a publish must not spend a write bucket (S-24.g)"
    );
    assert_eq!(
        app.kv_get(&window_key(&format!("rl:write:ip:{DEFAULT_IP}"), now)).await,
        None,
        "...and not the anonymous one either"
    );
    // It did spend the budget it is supposed to spend (S-24.c), keyed on the org.
    assert!(
        app.kv_get(&format!("rl:publish:org:{org}:{}", now.timestamp().div_euclid(3600))).await.is_some(),
        "the publish budget is the one a publish spends"
    );
    // Positive control: an app-API mutation by the same account *does* create a write bucket,
    // so the absences above are about the plane and not about the key layout.
    assert_eq!(app.post("/api/v1/orgs", Some(&access), new_org(1)).await.status, StatusCode::OK);
    assert!(
        app.kv_get(&window_key(&format!("rl:write:usr:{user}"), now)).await.is_some(),
        "an app-API mutation spends a write bucket"
    );
}

/// **S-24.g.** The six credential endpoints are **excluded**, not charged twice. They spend
/// their own buckets, which fail *closed* onto S-24.e's in-process table; an open bucket beside
/// a closed one on the same request only makes the closed one harder to reason about.
#[tokio::test]
async fn s24_g_the_credential_endpoints_are_not_double_charged() {
    let app = TestApp::with_options(TestOptions {
        // One anonymous write per minute: if the credential endpoints were charged, the second
        // sign-in attempt of the minute would answer 429 and the instance would be unusable.
        write_per_ip_minute: 1,
        write_per_identity_minute: 1,
        ..TestOptions::default()
    })
    .await;

    // A distinct address per request: the S-03 resend policy (≥60 s per email) would otherwise
    // be what refuses the second one, and this test would pass for the wrong reason.
    for index in 0..5 {
        let body = serde_json::json!({ "email": format!("user{index}@corp.com") });
        let response = app.post("/api/v1/auth/otp/request", None, body).await;
        assert_eq!(response.status, StatusCode::OK, "otp request {index} must not spend a write bucket");
    }
    // A full sign-in — request *and* redemption — still completes on a spent write budget.
    let login = app.login("signin@corp.com").await;
    assert!(login["access_token"].is_string(), "the redemption endpoints are exempt too");

    assert_eq!(
        app.kv_get(&window_key(&format!("rl:write:ip:{DEFAULT_IP}"), app.now())).await,
        None,
        "no write bucket may exist for a request that spends a credential bucket"
    );
    // ...and the credential bucket they *do* spend is there.
    assert!(
        app.kv_get(&format!("rl:otp:ip:{DEFAULT_IP}:{}", app.now().timestamp().div_euclid(3600))).await.is_some(),
        "the OTP bucket is the one an OTP request spends"
    );
}

/// **S-24.g / S-12.** A request the S-12 mutation guard refuses spends **nothing**. The bucket
/// is mounted inside the guard for exactly this: with the other order, a page a user merely
/// visits could fire header-less mutations and drain that user's own `ip:` write budget.
#[tokio::test]
async fn s24_g_a_request_the_s12_guard_refuses_spends_nothing() {
    let app = TestApp::with_options(TestOptions {
        write_per_ip_minute: 1,
        write_per_identity_minute: 100_000,
        ..TestOptions::default()
    })
    .await;

    for index in 0..5 {
        let refused = app.send(without_custom_header("/api/v1/orgs")).await;
        assert_eq!(refused.status, StatusCode::FORBIDDEN, "S-12 refusal {index}");
    }
    assert_eq!(
        app.kv_get(&window_key(&format!("rl:write:ip:{DEFAULT_IP}"), app.now())).await,
        None,
        "a request the S-12 guard refused must not have reached the bucket at all"
    );
    // And the budget is genuinely intact: the whole single unit is still there to spend.
    assert_eq!(app.post("/api/v1/orgs", None, new_org(0)).await.status, StatusCode::UNAUTHORIZED);
    assert_eq!(app.post("/api/v1/orgs", None, new_org(1)).await.status, StatusCode::TOO_MANY_REQUESTS);
}

/// **S-24.g / S-22.** A write trip writes **one** audit row per bucket per window, under
/// `write.throttled` — a third action name, because an operator filtering the log for refused
/// credentials must not have to read past refused writes.
#[tokio::test]
async fn s24_g_a_trip_is_audited_once_per_window_under_write_throttled() {
    let app = TestApp::with_options(TestOptions {
        write_per_identity_minute: 1,
        write_per_ip_minute: 100_000,
        ..TestOptions::default()
    })
    .await;
    let access = app.login("owner@corp.com").await["access_token"].as_str().expect("access token").to_owned();

    assert_eq!(app.post("/api/v1/orgs", Some(&access), new_org(0)).await.status, StatusCode::OK);
    for index in 1..8 {
        assert_eq!(
            app.post("/api/v1/orgs", Some(&access), new_org(index)).await.status,
            StatusCode::TOO_MANY_REQUESTS,
            "write {index}"
        );
    }

    let actions = app.audit_actions().await;
    assert_eq!(
        actions.iter().filter(|action| *action == "write.throttled").count(),
        1,
        "seven refusals in one window are one audit row, not seven"
    );
    assert!(!actions.iter().any(|action| action == "auth.throttled"), "a write trip is not a credential trip");
    assert!(!actions.iter().any(|action| action == "read.throttled"), "a write trip is not a read trip");
    let trip = app.audit_event("write.throttled").await.expect("the trip is audited");
    assert_eq!(trip.metadata.expect("metadata")["limit"], "write_per_user", "the label is a bucket family");
}

/// **S-24.g / decision 09.** Both numbers are runtime settings: an instance being spammed
/// lowers them from the admin surface and the next request obeys, with no restart.
#[tokio::test]
async fn s24_g_both_write_numbers_take_effect_without_a_restart() {
    let app = TestApp::with_options(TestOptions {
        instance_admins: vec!["root@corp.com".to_owned()],
        ..TestOptions::default()
    })
    .await;
    let access = app.login("root@corp.com").await["access_token"].as_str().expect("access token").to_owned();

    // Read the section back and hand it in with two fields changed, so this test carries no
    // copy of the field list — a new limit added to the section cannot silently break it.
    let current = app.get("/api/v1/admin/settings", Some(&access)).await;
    assert_eq!(current.status, StatusCode::OK, "{:?}", current.json);
    let mut limits = current.json["data"]["rate_limits"].clone();
    limits["write_per_identity_minute"] = serde_json::json!(1);
    limits["write_per_ip_minute"] = serde_json::json!(1);
    let patched =
        app.patch("/api/v1/admin/settings", Some(&access), serde_json::json!({ "rate_limits": limits })).await;
    assert_eq!(patched.status, StatusCode::OK, "{:?}", patched.json);

    // The identity number: this account has already spent more than one write in this window
    // (the PATCH itself), so the next one is over the new limit.
    assert_eq!(
        app.post("/api/v1/orgs", Some(&access), new_org(0)).await.status,
        StatusCode::TOO_MANY_REQUESTS,
        "the lowered identity number took effect on the next request"
    );
    // The anonymous number, from a bucket that is still untouched: one through, then refused.
    assert_eq!(app.post("/api/v1/orgs", None, new_org(1)).await.status, StatusCode::UNAUTHORIZED);
    assert_eq!(
        app.post("/api/v1/orgs", None, new_org(2)).await.status,
        StatusCode::TOO_MANY_REQUESTS,
        "the lowered per-IP number took effect too"
    );
}

/// **D58 / S-24.g.** One identity per request: a write verifies its access token **once**, not
/// twice and not three times.
///
/// Counted rather than asserted in a comment. `AuthService::access_verifications` exists for
/// this: the identity layer verifies the signature and stashes the claims, and the auth
/// extractor reuses them — so the number of Ed25519 verifications a request costs is the only
/// thing that can tell "resolved once" from "resolved wherever it was needed".
#[tokio::test]
async fn d58_a_request_verifies_its_access_token_once() {
    let app = TestApp::new().await;
    let access = app.login("owner@corp.com").await["access_token"].as_str().expect("access token").to_owned();
    let verifications = || app.state.auth.access_verifications();

    // A write: the bucket layer resolves the identity, the extractor consumes that resolution.
    let before = verifications();
    let created = app.post("/api/v1/orgs", Some(&access), new_org(0)).await;
    assert_eq!(created.status, StatusCode::OK, "{:?}", created.json);
    assert_eq!(verifications() - before, 1, "a write must verify its access token exactly once");

    // A read: the same, through the S-24.f bucket instead — this is the half D58 named.
    let before = verifications();
    let listed = app.get("/api/v1/sessions", Some(&access)).await;
    assert_eq!(listed.status, StatusCode::OK, "{:?}", listed.json);
    assert_eq!(verifications() - before, 1, "an authenticated read must verify its access token exactly once");

    // A step-up-gated write walks two more extractors over the same claims and still costs one.
    let before = verifications();
    let minted = app
        .post(
            "/api/v1/tokens",
            Some(&access),
            serde_json::json!({
                "org_id": created.json["data"]["id"], "scopes": ["publish"], "label": "one", "expires_days": 90,
            }),
        )
        .await;
    assert_eq!(minted.status, StatusCode::OK, "{:?}", minted.json);
    assert_eq!(verifications() - before, 1, "a step-up gated write verifies once as well");

    // An anonymous request verifies nothing at all: there is no credential to check.
    let before = verifications();
    app.get("/api/v1/packages?q=x", None).await;
    assert_eq!(verifications(), before, "an anonymous request costs no verification");
}
