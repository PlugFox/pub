//! The CLI/API token plane at the wire — [S-13](../../../../docs/security.md#3-cliapi-tokens)
//! and the two clauses [decision 33](../../../../docs/decisions.md#33) made reachable
//! ([S-13.c](../../../../docs/security.md#3-cliapi-tokens),
//! [S-06.d](../../../../docs/security.md#1-authentication); closes roadmap D19).
//!
//! | Test | Requirement |
//! |---|---|
//! | `s13_c_a_minted_pattern_narrows_a_real_publish` | patterns reach the enforcement that already existed |
//! | `s13_c_the_mint_refuses_a_pattern_the_matcher_could_never_satisfy` | the grammar is checked where it is stored |
//! | `s13_c_patterns_are_readable_after_the_mint` | a narrowing nobody can see is a narrowing nobody trusts |
//! | `s13_c_a_non_expiring_read_token_is_mintable_and_outlives_every_finite_window` | "never" exists and works |
//! | `s13_c_a_non_expiring_token_may_not_carry_a_write_scope` | the S-13 clause, finally enforced |
//! | `s13_c_zero_days_is_refused_rather_than_read_as_never` | the old client that computes 0 |
//! | `s06_d_a_non_expiring_mint_needs_a_fresh_factor_at_every_scope` | the lifetime is the gate, not the scope |
//! | `s06_d_the_wire_change_is_loud_for_a_client_that_omits_the_field` | decision 33's accepted cost, pinned |
//!
//! The publish narrowing is asserted end to end rather than at the service, because the whole
//! debt was that the two halves — a mint that could express a pattern and an enforcement that
//! reads one — had never met.

mod common;

use axum::http::StatusCode;
use chrono::Duration;
use common::{TestApp, package_archive, token_body};

const EMAIL: &str = "owner@corp.com";

/// The org's own registry base — publishing through the public root is refused by design.
const ORG_BASE: &str = "/o/acme/pub";

/// Signs in, creates an org, returns `(access_token, refresh_token, org_id_string)`.
async fn owner(app: &TestApp) -> (String, String, String) {
    let login = app.login(EMAIL).await;
    let access = login["access_token"].as_str().expect("access token").to_owned();
    let refresh = login["refresh_token"].as_str().expect("refresh token").to_owned();
    let org = app.post("/api/v1/orgs", Some(&access), serde_json::json!({ "name": "Acme", "slug": "acme" })).await;
    assert_eq!(org.status, StatusCode::OK, "{:?}", org.json);
    (access, refresh, org.json["data"]["id"].as_str().expect("org id").to_owned())
}

/// Moves past the step-up window and trades `refresh` for a live access token.
///
/// Both halves are needed: the access JWT dies at 15 minutes (S-07) while step-up freshness
/// dies at `auth.step_up_minutes`, so a test that only advanced the clock would be asserting
/// against a 401 and calling it a step-up gate.
async fn stale_but_signed_in(app: &TestApp, refresh: &str) -> String {
    app.advance(Duration::minutes(16));
    let rotated = app.post("/api/v1/auth/refresh", None, serde_json::json!({ "refresh_token": refresh })).await;
    assert_eq!(rotated.status, StatusCode::OK, "{:?}", rotated.json);
    rotated.json["data"]["access_token"].as_str().expect("access token").to_owned()
}

#[tokio::test]
async fn s13_c_a_minted_pattern_narrows_a_real_publish() {
    let app = TestApp::new().await;
    let (access, _refresh, org_id) = owner(&app).await;

    let created = app
        .post(
            "/api/v1/tokens",
            Some(&access),
            serde_json::json!({
                "org_id": org_id,
                "scopes": ["read", "publish"],
                "expires_days": 90,
                "package_patterns": ["acme_*"],
            }),
        )
        .await;
    assert_eq!(created.status, StatusCode::OK, "{:?}", created.json);
    let secret = created.json["data"]["secret"].as_str().expect("secret").to_owned();

    // Inside the pattern: an ordinary publish.
    let inside = app.publish(ORG_BASE, &secret, &package_archive("acme_core", "1.0.0")).await;
    assert_eq!(inside.status, StatusCode::OK, "a name inside the pattern must publish: {:?}", inside.json);

    // Outside it: refused by the enforcement that has been there all along, now reachable.
    let outside = app.publish(ORG_BASE, &secret, &package_archive("other_pkg", "1.0.0")).await;
    assert_eq!(outside.status, StatusCode::FORBIDDEN, "{:?}", outside.json);
}

#[tokio::test]
async fn s13_c_the_mint_refuses_a_pattern_the_matcher_could_never_satisfy() {
    let app = TestApp::new().await;
    let (access, _refresh, org_id) = owner(&app).await;

    // A dash is legal in no package name, `*acme` is not the one wildcard shape, and a bare
    // `*` is a second spelling of "no narrowing". Each would otherwise mint a token whose
    // owner discovers at the first CI publish that it authorizes nothing.
    for pattern in ["acme-*", "*acme", "*", "", "Acme_*", "ac*me"] {
        let refused = app
            .post(
                "/api/v1/tokens",
                Some(&access),
                serde_json::json!({
                    "org_id": org_id,
                    "scopes": ["read"],
                    "expires_days": 90,
                    "package_patterns": [pattern],
                }),
            )
            .await;
        assert_eq!(refused.status, StatusCode::BAD_REQUEST, "pattern {pattern:?} was accepted");
        assert_eq!(refused.error_code(), "invalid_argument");
    }
}

#[tokio::test]
async fn s13_c_patterns_are_readable_after_the_mint() {
    let app = TestApp::new().await;
    let (access, _refresh, org_id) = owner(&app).await;

    let created = app
        .post(
            "/api/v1/tokens",
            Some(&access),
            serde_json::json!({
                "org_id": org_id,
                "scopes": ["read"],
                "expires_days": 90,
                // Duplicated on purpose: the mint deduplicates and keeps the caller's order, so
                // the list shows what is enforced rather than what was typed.
                "package_patterns": ["acme_*", "shared_utils", "acme_*"],
            }),
        )
        .await;
    assert_eq!(created.status, StatusCode::OK, "{:?}", created.json);
    assert_eq!(created.json["data"]["token"]["package_patterns"], serde_json::json!(["acme_*", "shared_utils"]));

    let listed = app.get("/api/v1/tokens", Some(&access)).await;
    assert_eq!(listed.status, StatusCode::OK);
    assert_eq!(listed.json["data"]["items"][0]["package_patterns"], serde_json::json!(["acme_*", "shared_utils"]));

    // An unnarrowed token reports an empty list, never a missing field — the UI renders the
    // difference between "every package" and "unknown".
    let plain = app.post("/api/v1/tokens", Some(&access), token_body(&org_id, &["read"])).await;
    assert_eq!(plain.json["data"]["token"]["package_patterns"], serde_json::json!([]));
}

#[tokio::test]
async fn s13_c_a_non_expiring_read_token_is_mintable_and_outlives_every_finite_window() {
    let app = TestApp::new().await;
    let (access, _refresh, org_id) = owner(&app).await;

    // The session is step-up-fresh (it was just created), which S-06.d requires.
    let created = app
        .post(
            "/api/v1/tokens",
            Some(&access),
            serde_json::json!({ "org_id": org_id, "scopes": ["read"], "expires_days": serde_json::Value::Null }),
        )
        .await;
    assert_eq!(created.status, StatusCode::OK, "{:?}", created.json);
    assert!(created.json["data"]["token"]["expires_at"].is_null(), "a non-expiring token has no expiry");
    let secret = created.json["data"]["secret"].as_str().expect("secret").to_owned();

    // Past the longest lifetime the mint would have granted, the credential still authenticates.
    // The probe is a *publish ticket* rather than a read, because reads are anonymous here by
    // default: a read-scoped token that authenticates is refused for its scope (403), while an
    // expired one is refused for its credential (401, S-14) — so only this pair discriminates.
    app.advance(Duration::days(3651));
    let ticket = app.pub_get(&format!("{ORG_BASE}/api/packages/versions/new"), Some(&secret)).await;
    assert_eq!(ticket.status, StatusCode::FORBIDDEN, "a non-expiring token must still authenticate: {:?}", ticket.json);
}

#[tokio::test]
async fn s13_c_a_non_expiring_token_may_not_carry_a_write_scope() {
    let app = TestApp::new().await;
    let (access, _refresh, org_id) = owner(&app).await;

    for scopes in [
        serde_json::json!(["publish"]),
        serde_json::json!(["retract"]),
        serde_json::json!(["admin"]),
        // Smuggled next to a permitted scope: the rule is about the token, not about one entry.
        serde_json::json!(["read", "publish"]),
    ] {
        let refused = app
            .post(
                "/api/v1/tokens",
                Some(&access),
                serde_json::json!({ "org_id": org_id, "scopes": scopes, "expires_days": serde_json::Value::Null }),
            )
            .await;
        assert_eq!(refused.status, StatusCode::BAD_REQUEST, "{scopes:?} minted without an expiry: {:?}", refused.json);
        assert_eq!(refused.error_code(), "invalid_argument");
    }
}

#[tokio::test]
async fn s13_c_zero_days_is_refused_rather_than_read_as_never() {
    let app = TestApp::new().await;
    let (access, _refresh, org_id) = owner(&app).await;

    // A client computing `max(0, days_left)` must not stumble into an eternal credential, and
    // 3651 days must not silently clamp to the cap.
    for days in [0, -1, 3651] {
        let refused = app
            .post(
                "/api/v1/tokens",
                Some(&access),
                serde_json::json!({ "org_id": org_id, "scopes": ["read"], "expires_days": days }),
            )
            .await;
        assert_eq!(refused.status, StatusCode::BAD_REQUEST, "expires_days = {days} was accepted");
        assert_eq!(refused.error_code(), "invalid_argument");
    }
}

#[tokio::test]
async fn s06_d_a_non_expiring_mint_needs_a_fresh_factor_at_every_scope() {
    // A long window would let the login's own freshness cover the whole test; 100 logins per
    // IP because this test signs in twice from one address.
    let app = TestApp::new().await;
    let (_fresh_access, refresh, org_id) = owner(&app).await;
    let access = stale_but_signed_in(&app, &refresh).await;

    // An expiring read mint stays ungated — S-06.b's rule is unchanged.
    let expiring = app.post("/api/v1/tokens", Some(&access), token_body(&org_id, &["read"])).await;
    assert_eq!(expiring.status, StatusCode::OK, "an expiring read mint must not be gated: {:?}", expiring.json);

    // The same scope, with no expiry, is gated — the lifetime is what S-06.d weighs.
    let forever = app
        .post(
            "/api/v1/tokens",
            Some(&access),
            serde_json::json!({ "org_id": org_id, "scopes": ["read"], "expires_days": serde_json::Value::Null }),
        )
        .await;
    assert_eq!(forever.status, StatusCode::FORBIDDEN, "{:?}", forever.json);
    assert_eq!(forever.error_code(), "step_up_required", "the UI must be able to prompt rather than dead-end");
}

#[tokio::test]
async fn s06_d_the_wire_change_is_loud_for_a_client_that_omits_the_field() {
    let app = TestApp::new().await;
    let (fresh_access, refresh, org_id) = owner(&app).await;

    // A write scope with an omitted expiry is refused on the body alone, and the refusal is
    // independent of the org: a caller probing an org it cannot see gets the same
    // `invalid_argument`, so this validation is not an existence oracle (S-04). Asserted from a
    // step-up-FRESH session, because a stale one is refused by the gate before the body is
    // judged and would prove nothing about the ordering.
    for org in [org_id.as_str(), "00000000-0000-7000-8000-000000000000"] {
        let refused = app
            .post("/api/v1/tokens", Some(&fresh_access), serde_json::json!({ "org_id": org, "scopes": ["admin"] }))
            .await;
        assert_eq!(refused.status, StatusCode::BAD_REQUEST, "{:?}", refused.json);
        assert_eq!(refused.error_code(), "invalid_argument", "the body is judged before the org, for every caller");
    }

    // From a stale session, the request an old client sends when it expects the 90-day default
    // meets the S-06.d gate instead of receiving an eternal credential. Absent and explicit
    // `null` must be indistinguishable, or the guard has a hole shaped like a serde default.
    let access = stale_but_signed_in(&app, &refresh).await;
    for body in [
        serde_json::json!({ "org_id": org_id, "scopes": ["read"] }),
        serde_json::json!({ "org_id": org_id, "scopes": ["read"], "expires_days": serde_json::Value::Null }),
    ] {
        let refused = app.post("/api/v1/tokens", Some(&access), body).await;
        assert_eq!(refused.error_code(), "step_up_required", "an omitted expiry must never be granted silently");
    }
}
