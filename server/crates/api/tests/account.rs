//! The account surface at the wire — [S-29](../../../../docs/security.md#7-platform),
//! [S-03.b](../../../../docs/security.md#1-authentication) and
//! [decision 39](../../../../docs/decisions.md#39--the-account-surface-one-me-the-client-can-trust-an-email-change-that-proves-both-addresses-an-export-that-streams-and-a-deletion-that-keeps-the-attribution-and-nothing-else).
//!
//! | Test | Requirement |
//! |---|---|
//! | `me_reports_the_second_factor_the_token_cannot_carry` | the read that ends the session-local guess |
//! | `a_rename_changes_the_name_and_nothing_else` | profile edit, narrow by construction |
//! | `s03_b_an_email_change_proves_the_new_address_before_it_moves` | the whole flow, end to end |
//! | `s03_b_a_code_is_bound_to_the_account_that_asked_for_it` | a phished code is not enough |
//! | `s03_b_an_address_another_account_holds_is_refused` | decision 39's recorded oracle |
//! | `s06_a_stale_session_may_not_change_an_address_or_delete_an_account` | the gates, on the wire |
//! | `s29_a_deletion_erases_the_identity_and_keeps_the_attribution` | what a tombstone is |
//! | `s29_a_a_deleted_account_frees_its_address_for_a_new_one` | deletion does not reserve an address |
//! | `s29_a_the_last_owner_of_an_org_is_refused` | the owner's chosen answer, named |
//! | `s29_b_the_export_streams_the_callers_own_rows_and_terminates` | the export contract |
//! | `s29_b_the_export_carries_no_credential_material` | the exclusion, asserted negatively |
//! | `d40_a_write_member_can_leave_an_org` | the route Read and Write members never had |
//! | `s29_c_security_txt_is_absent_until_a_contact_is_configured` | 404 by default, RFC 9116 when set |
//!
//! The deletion tests assert through the **repositories** as well as the wire, because the whole
//! point of an anonymizing delete is what the row looks like afterwards, and a 200 says nothing
//! about that.

mod common;

use axum::http::{Method, StatusCode};
use chrono::Duration;
use common::{TestApp, TestOptions};
use pub_auth::totp;
use pub_core::user::UserStatus;

const EMAIL: &str = "owner@corp.com";

/// Registers the instance's first account, which the bootstrap promotes to instance admin
/// (decision 09).
///
/// Every deletion scenario needs one that is **not** the account under test: S-29.a refuses to
/// delete the last instance administrator, so a test that deleted the first account would be
/// asserting against that refusal rather than against deletion.
async fn seed_instance_admin(app: &TestApp) {
    signed_in(app, "admin@corp.com").await;
}

/// Signs in and returns `(access, refresh)`.
async fn signed_in(app: &TestApp, email: &str) -> (String, String) {
    let login = app.login(email).await;
    (
        login["access_token"].as_str().expect("access token").to_owned(),
        login["refresh_token"].as_str().expect("refresh token").to_owned(),
    )
}

/// Moves past the step-up window and trades `refresh` for a live — but stale — access token.
///
/// Both halves matter: the access JWT dies at fifteen minutes (S-07) while step-up freshness dies
/// at `auth.step_up_minutes`, so a test that only advanced the clock would be asserting against a
/// 401 and calling it a step-up gate.
async fn stale_but_signed_in(app: &TestApp, refresh: &str) -> String {
    app.advance(Duration::minutes(16));
    let rotated = app.post("/api/v1/auth/refresh", None, serde_json::json!({ "refresh_token": refresh })).await;
    assert_eq!(rotated.status, StatusCode::OK, "{:?}", rotated.json);
    rotated.json["data"]["access_token"].as_str().expect("access token").to_owned()
}

#[tokio::test]
async fn me_reports_the_second_factor_the_token_cannot_carry() {
    let app = TestApp::new().await;
    let (access, _refresh) = signed_in(&app, EMAIL).await;

    let me = app.get("/api/v1/me", Some(&access)).await;
    assert_eq!(me.status, StatusCode::OK, "{:?}", me.json);
    assert_eq!(me.json["data"]["email"], EMAIL);
    assert_eq!(me.json["data"]["email_verified"], true);
    assert_eq!(me.json["data"]["totp_enabled"], false);
    assert_eq!(me.json["data"]["is_instance_admin"], true, "the first account bootstraps as the instance admin");

    // The field is a read of the credential table, not a claim: enrolling on this device and
    // asking again must change the answer without a new token.
    let enroll = app.post_empty("/api/v1/auth/totp/enroll", Some(&access)).await;
    assert_eq!(enroll.status, StatusCode::OK, "{:?}", enroll.json);
    let seed = totp::base32_decode(enroll.json["data"]["secret"].as_str().expect("secret")).expect("base32");
    let code = totp::code_at(&seed, totp::step_at(app.now()));
    let confirmed = app.post("/api/v1/auth/totp/confirm", Some(&access), serde_json::json!({ "code": code })).await;
    assert_eq!(confirmed.status, StatusCode::OK, "{:?}", confirmed.json);

    let me = app.get("/api/v1/me", Some(&access)).await;
    assert_eq!(me.json["data"]["totp_enabled"], true, "the same token now reports an enrolled factor");
}

#[tokio::test]
async fn a_rename_changes_the_name_and_nothing_else() {
    let app = TestApp::new().await;
    let (access, _refresh) = signed_in(&app, EMAIL).await;

    let renamed =
        app.patch("/api/v1/me", Some(&access), serde_json::json!({ "display_name": "  Ada Lovelace  " })).await;
    assert_eq!(renamed.status, StatusCode::OK, "{:?}", renamed.json);
    assert_eq!(renamed.json["data"]["display_name"], "Ada Lovelace", "the name is trimmed, not stored padded");
    assert_eq!(renamed.json["data"]["email"], EMAIL, "a rename does not touch the address");

    for bad in ["", "   ", "a\u{7}b"] {
        let refused = app.patch("/api/v1/me", Some(&access), serde_json::json!({ "display_name": bad })).await;
        assert_eq!(refused.status, StatusCode::BAD_REQUEST, "{bad:?} must be refused: {:?}", refused.json);
    }
    let long = "x".repeat(81);
    let refused = app.patch("/api/v1/me", Some(&access), serde_json::json!({ "display_name": long })).await;
    assert_eq!(refused.status, StatusCode::BAD_REQUEST, "{:?}", refused.json);

    assert!(app.audit_actions().await.iter().any(|action| action == "account.profile"), "the rename is audited");
}

#[tokio::test]
async fn s03_b_an_email_change_proves_the_new_address_before_it_moves() {
    let app = TestApp::new().await;
    let (access, _refresh) = signed_in(&app, EMAIL).await;

    // The request alone changes nothing: the old address is still the account's until the code
    // comes back, which is what makes a typo a dead record rather than a lockout.
    let started = app.post("/api/v1/me/email", Some(&access), serde_json::json!({ "email": "new@corp.com" })).await;
    assert_eq!(started.status, StatusCode::OK, "{:?}", started.json);
    let me = app.get("/api/v1/me", Some(&access)).await;
    assert_eq!(me.json["data"]["email"], EMAIL, "the address must not move before the proof");

    let pending_id = started.json["data"]["pending_id"].as_str().expect("pending id").to_owned();
    app.drain_jobs().await;
    let code = common::extract_code(&app.mailer.sent().last().expect("mail").text);

    // A wrong code is `invalid_code`, the same answer every other guess gets (S-04).
    let wrong = app
        .post(
            "/api/v1/me/email/verify",
            Some(&access),
            serde_json::json!({ "pending_id": pending_id, "code": common::wrong_code(&code) }),
        )
        .await;
    // 401, not 400: `invalid_code` is the uniform auth answer this surface already gives on
    // `totp/confirm` and `step-up`, and the status follows the variant rather than the route.
    assert_eq!(wrong.status, StatusCode::UNAUTHORIZED, "{:?}", wrong.json);
    assert_eq!(wrong.json["error"]["code"], "invalid_code");

    let confirmed = app
        .post("/api/v1/me/email/verify", Some(&access), serde_json::json!({ "pending_id": pending_id, "code": code }))
        .await;
    assert_eq!(confirmed.status, StatusCode::OK, "{:?}", confirmed.json);
    assert_eq!(confirmed.json["data"]["email"], "new@corp.com");
    assert_eq!(confirmed.json["data"]["email_verified"], true);

    // The old address is told, and only after the swap.
    app.drain_jobs().await;
    let notice = app
        .mailer
        .sent()
        .into_iter()
        .find(|mail| mail.to == EMAIL && mail.subject.contains("changed"))
        .expect("the old address is notified");
    assert!(notice.text.contains("new@corp.com"), "the notice names the new address: {}", notice.text);

    // The address really moved: the new one signs in, the old one is now a stranger's to claim.
    assert_eq!(
        app.repos.users.find_by_email("new@corp.com").await.expect("lookup").map(|u| u.id),
        Some(app.user_of("new@corp.com").await)
    );
    assert!(app.repos.users.find_by_email(EMAIL).await.expect("lookup").is_none());
    assert!(app.audit_actions().await.iter().any(|action| action == "account.email.changed"));
}

#[tokio::test]
async fn s03_b_a_code_is_bound_to_the_account_that_asked_for_it() {
    let app = TestApp::new().await;
    let (access, _refresh) = signed_in(&app, EMAIL).await;
    let (other_access, _other_refresh) = signed_in(&app, "other@corp.com").await;

    let started = app.post("/api/v1/me/email", Some(&access), serde_json::json!({ "email": "new@corp.com" })).await;
    assert_eq!(started.status, StatusCode::OK, "{:?}", started.json);
    let pending_id = started.json["data"]["pending_id"].as_str().expect("pending id").to_owned();
    app.drain_jobs().await;
    let code = common::extract_code(&app.mailer.sent().last().expect("mail").text);

    // The whole point of the binding: holding the code is not enough. This is the phished-code
    // case, and it must fail for the *other* account even though the code itself is correct.
    let stolen = app
        .post(
            "/api/v1/me/email/verify",
            Some(&other_access),
            serde_json::json!({ "pending_id": pending_id, "code": code.clone() }),
        )
        .await;
    assert_eq!(stolen.status, StatusCode::UNAUTHORIZED, "{:?}", stolen.json);
    assert_eq!(stolen.json["error"]["code"], "invalid_code");
    let other = app.get("/api/v1/me", Some(&other_access)).await;
    assert_eq!(other.json["data"]["email"], "other@corp.com", "the thief's own address must be untouched");

    // And the rightful owner can still spend it — the refusal above cost the thief an attempt,
    // not the record.
    let mine = app
        .post("/api/v1/me/email/verify", Some(&access), serde_json::json!({ "pending_id": pending_id, "code": code }))
        .await;
    assert_eq!(mine.status, StatusCode::OK, "{:?}", mine.json);
}

#[tokio::test]
async fn s03_b_an_address_another_account_holds_is_refused() {
    let app = TestApp::new().await;
    let (access, _refresh) = signed_in(&app, EMAIL).await;
    signed_in(&app, "taken@corp.com").await;

    let before = app.drain_and_count_mail().await;
    let refused = app.post("/api/v1/me/email", Some(&access), serde_json::json!({ "email": "taken@corp.com" })).await;
    assert_eq!(refused.status, StatusCode::CONFLICT, "{:?}", refused.json);
    assert_eq!(refused.json["error"]["code"], "conflict");
    // The half of the trade that is not the oracle: no code was mailed to somebody else's inbox.
    app.drain_jobs().await;
    assert_eq!(app.mailer.sent().len(), before, "a refused change must not mail a stranger");

    // The current address is refused too, and before any message is queued.
    let same = app.post("/api/v1/me/email", Some(&access), serde_json::json!({ "email": EMAIL })).await;
    assert_eq!(same.status, StatusCode::BAD_REQUEST, "{:?}", same.json);
    app.drain_jobs().await;
    assert_eq!(app.mailer.sent().len(), before);
}

#[tokio::test]
async fn s06_a_stale_session_may_not_change_an_address_or_delete_an_account() {
    let app = TestApp::new().await;
    let (access, refresh) = signed_in(&app, EMAIL).await;
    // Enrolling a second factor is what makes the session *stale* rather than perpetually fresh:
    // without one, S-06.a's clause (a) says a login is the strongest chain the account has.
    let enroll = app.post_empty("/api/v1/auth/totp/enroll", Some(&access)).await;
    let seed = totp::base32_decode(enroll.json["data"]["secret"].as_str().expect("secret")).expect("base32");
    let code = totp::code_at(&seed, totp::step_at(app.now()));
    app.post("/api/v1/auth/totp/confirm", Some(&access), serde_json::json!({ "code": code })).await;

    let stale = stale_but_signed_in(&app, &refresh).await;
    for (path, body) in [
        ("/api/v1/me/email", serde_json::json!({ "email": "new@corp.com" })),
        ("/api/v1/me/email/verify", serde_json::json!({ "pending_id": "x", "code": "00000000" })),
    ] {
        let refused = app.post(path, Some(&stale), body).await;
        assert_eq!(refused.status, StatusCode::FORBIDDEN, "{path} must be step-up gated: {:?}", refused.json);
        assert_eq!(refused.json["error"]["code"], "step_up_required");
    }
    let refused = app.delete_with("/api/v1/me", Some(&stale), serde_json::json!({ "confirm": EMAIL })).await;
    assert_eq!(refused.status, StatusCode::FORBIDDEN, "{:?}", refused.json);
    assert_eq!(refused.json["error"]["code"], "step_up_required");
    let refused = app.get("/api/v1/me/export", Some(&stale)).await;
    assert_eq!(refused.status, StatusCode::FORBIDDEN, "the bulk export is gated (S-06.c): {:?}", refused.json);

    // A rename is deliberately **not** gated: S-06's list is about escalation and bulk.
    let renamed = app.patch("/api/v1/me", Some(&stale), serde_json::json!({ "display_name": "Ada" })).await;
    assert_eq!(renamed.status, StatusCode::OK, "{:?}", renamed.json);
}

#[tokio::test]
async fn s29_a_deletion_erases_the_identity_and_keeps_the_attribution() {
    let app = TestApp::new().await;
    seed_instance_admin(&app).await;
    let (access, _refresh) = signed_in(&app, EMAIL).await;
    let user = app.user_of(EMAIL).await;
    let org = app.post("/api/v1/orgs", Some(&access), serde_json::json!({ "name": "Acme", "slug": "acme" })).await;
    assert_eq!(org.status, StatusCode::OK, "{:?}", org.json);
    let org_id: pub_core::OrgId = org.json["data"]["id"].as_str().expect("org id").parse().expect("org id");
    // A second owner, so the account is not the last one and deletion may proceed.
    let (other_access, _other) = signed_in(&app, "second@corp.com").await;
    let second = app.user_of("second@corp.com").await;
    app.repos.orgs.add_member(org_id, second, pub_core::RoleLevel::OWNER, app.now()).await.expect("second owner");
    let token = app.mint_token(&access, org_id, &["read"]).await;

    // The confirmation is not decoration: a wrong one refuses before anything is touched.
    let wrong = app.delete_with("/api/v1/me", Some(&access), serde_json::json!({ "confirm": "nope@corp.com" })).await;
    assert_eq!(wrong.status, StatusCode::BAD_REQUEST, "{:?}", wrong.json);
    assert!(app.repos.users.get(user).await.expect("get").expect("row").status == UserStatus::Active);

    let deleted = app.delete_with("/api/v1/me", Some(&access), serde_json::json!({ "confirm": EMAIL })).await;
    assert_eq!(deleted.status, StatusCode::OK, "{:?}", deleted.json);
    assert_eq!(deleted.json["data"]["memberships_removed"], 1);
    assert!(deleted.json["data"]["tokens_revoked"].as_u64().expect("count") >= 1);

    // The row survives as the attribution tombstone, with nothing identifying left on it.
    let tombstone = app.repos.users.get(user).await.expect("get").expect("the row must survive");
    assert_eq!(tombstone.status, UserStatus::Deleted);
    assert_eq!(tombstone.email, None);
    assert!(!tombstone.is_instance_admin, "a tombstone is not an administrator");

    // The identity plane is gone: no credentials, no sessions, no live tokens.
    assert!(app.repos.credentials.list_for_user(user).await.expect("credentials").is_empty());
    let after = app.get("/api/v1/me", Some(&access)).await;
    assert_eq!(after.status, StatusCode::UNAUTHORIZED, "the access token must stop working: {:?}", after.json);
    let with_token = app.get("/api/v1/orgs", Some(&token)).await;
    assert_ne!(with_token.status, StatusCode::OK, "a revoked CLI token must not authenticate");

    // The org survived, and its remaining owner still runs it.
    let orgs = app.get("/api/v1/orgs", Some(&other_access)).await;
    assert_eq!(orgs.status, StatusCode::OK, "{:?}", orgs.json);
    assert_eq!(orgs.json["data"]["items"].as_array().expect("items").len(), 1);
    assert!(app.audit_actions().await.iter().any(|action| action == "account.deleted"));
}

#[tokio::test]
async fn s29_a_a_deleted_account_frees_its_address_for_a_new_one() {
    let app = TestApp::new().await;
    seed_instance_admin(&app).await;
    let (access, _refresh) = signed_in(&app, EMAIL).await;
    let first = app.user_of(EMAIL).await;
    let deleted = app.delete_with("/api/v1/me", Some(&access), serde_json::json!({ "confirm": EMAIL })).await;
    assert_eq!(deleted.status, StatusCode::OK, "{:?}", deleted.json);

    // Signing up again with the same address works and produces a **new** account with no
    // history — deletion releases an address rather than reserving it forever (S-29.a).
    let (fresh_access, _fresh_refresh) = signed_in(&app, EMAIL).await;
    let me = app.get("/api/v1/me", Some(&fresh_access)).await;
    assert_eq!(me.status, StatusCode::OK, "{:?}", me.json);
    assert_ne!(me.json["data"]["id"].as_str().expect("id"), first.to_string(), "a new account, not the tombstone");
}

#[tokio::test]
async fn s29_a_the_last_owner_of_an_org_is_refused() {
    let app = TestApp::new().await;
    seed_instance_admin(&app).await;
    let (access, _refresh) = signed_in(&app, EMAIL).await;
    let org = app.post("/api/v1/orgs", Some(&access), serde_json::json!({ "name": "Acme", "slug": "acme" })).await;
    assert_eq!(org.status, StatusCode::OK, "{:?}", org.json);

    let refused = app.delete_with("/api/v1/me", Some(&access), serde_json::json!({ "confirm": EMAIL })).await;
    assert_eq!(refused.status, StatusCode::CONFLICT, "{:?}", refused.json);
    assert_eq!(refused.json["error"]["code"], "conflict");
    let message = refused.json["error"]["message"].as_str().expect("message");
    assert!(message.contains("acme"), "the refusal names what is in the way: {message}");

    // Nothing was touched — the refusal happens before the first destructive step.
    let me = app.get("/api/v1/me", Some(&access)).await;
    assert_eq!(me.status, StatusCode::OK, "the account must still work after a refused deletion");
}

/// **S-29.a.** The instance's last administrator may not delete themselves.
///
/// Sharper than the org rule it mirrors, and found by this wave's own review rather than by a
/// test: anonymization drops the instance-admin flag, and `claim_first_admin` hands that flag to
/// the next account that registers — so on an open-registration instance, an administrator
/// deleting their own account would arm a takeover for whoever signs up next.
#[tokio::test]
async fn s29_a_the_last_instance_admin_is_refused() {
    let app = TestApp::new().await;
    let (access, _refresh) = signed_in(&app, EMAIL).await;
    let admin = app.user_of(EMAIL).await;
    assert!(app.repos.users.get(admin).await.expect("get").expect("row").is_instance_admin);

    let refused = app.delete_with("/api/v1/me", Some(&access), serde_json::json!({ "confirm": EMAIL })).await;
    assert_eq!(refused.status, StatusCode::CONFLICT, "{:?}", refused.json);
    let message = refused.json["error"]["message"].as_str().expect("message");
    assert!(message.contains("administrator"), "the refusal says what is in the way: {message}");
    assert_eq!(app.repos.users.get(admin).await.expect("get").expect("row").status, UserStatus::Active);

    // With a second administrator the same request goes through: the rule is about the *last*
    // one, not about administrators.
    signed_in(&app, "second@corp.com").await;
    app.make_instance_admin("second@corp.com").await;
    let deleted = app.delete_with("/api/v1/me", Some(&access), serde_json::json!({ "confirm": EMAIL })).await;
    assert_eq!(deleted.status, StatusCode::OK, "{:?}", deleted.json);
}

#[tokio::test]
async fn s29_b_the_export_streams_the_callers_own_rows_and_terminates() {
    let app = TestApp::new().await;
    let (access, _refresh) = signed_in(&app, EMAIL).await;
    // A neighbour with rows of their own — the control for "the caller's own" in every section.
    let (other_access, _other) = signed_in(&app, "other@corp.com").await;
    let other_org =
        app.post("/api/v1/orgs", Some(&other_access), serde_json::json!({ "name": "Theirs", "slug": "theirs" })).await;
    assert_eq!(other_org.status, StatusCode::OK, "{:?}", other_org.json);
    let org = app.post("/api/v1/orgs", Some(&access), serde_json::json!({ "name": "Acme", "slug": "acme" })).await;
    let org_id: pub_core::OrgId = org.json["data"]["id"].as_str().expect("org id").parse().expect("org id");
    app.mint_token(&access, org_id, &["read"]).await;

    let export =
        app.send_raw(app.request(Method::GET, "/api/v1/me/export", Some(&access), None, common::DEFAULT_IP)).await;
    assert_eq!(export.status, StatusCode::OK);
    assert_eq!(export.headers["content-type"], "application/x-ndjson");
    let body = String::from_utf8(export.body.clone()).expect("utf-8");
    let lines: Vec<serde_json::Value> =
        body.lines().filter(|line| !line.is_empty()).map(|line| serde_json::from_str(line).expect("ndjson")).collect();

    // The terminator is the contract: its absence is how a caller learns the file is partial.
    assert_eq!(lines.last().expect("a line"), &serde_json::json!({ "done": true }));
    let sections: Vec<&str> = lines
        .iter()
        .filter_map(|line| line["section"].as_str())
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect();
    for expected in ["meta", "profile", "organizations", "sessions", "tokens"] {
        assert!(sections.contains(&expected), "the {expected} section is missing: {sections:?}");
    }
    let orgs: Vec<&str> = lines
        .iter()
        .filter(|line| line["section"] == "organizations")
        .filter_map(|line| line["record"]["org"]["slug"].as_str())
        .collect();
    assert_eq!(orgs, ["acme"], "the export carries the caller's own memberships and nobody else's");
}

#[tokio::test]
async fn s29_b_the_export_carries_no_credential_material() {
    let app = TestApp::new().await;
    let (access, _refresh) = signed_in(&app, EMAIL).await;
    let org = app.post("/api/v1/orgs", Some(&access), serde_json::json!({ "name": "Acme", "slug": "acme" })).await;
    let org_id: pub_core::OrgId = org.json["data"]["id"].as_str().expect("org id").parse().expect("org id");
    let secret = app.mint_token(&access, org_id, &["read"]).await;
    // A second factor, so the export runs on an account that actually has credential material to
    // leak — without one this assertion would pass against an implementation that exports seeds.
    let enroll = app.post_empty("/api/v1/auth/totp/enroll", Some(&access)).await;
    let totp_secret = enroll.json["data"]["secret"].as_str().expect("secret").to_owned();
    let seed = totp::base32_decode(&totp_secret).expect("base32");
    let code = totp::code_at(&seed, totp::step_at(app.now()));
    app.post("/api/v1/auth/totp/confirm", Some(&access), serde_json::json!({ "code": code })).await;

    let export =
        app.send_raw(app.request(Method::GET, "/api/v1/me/export", Some(&access), None, common::DEFAULT_IP)).await;
    assert_eq!(export.status, StatusCode::OK);
    let body = String::from_utf8(export.body.clone()).expect("utf-8");
    assert!(!body.contains(&secret), "the export must not carry a CLI token's secret");
    assert!(!body.contains(&totp_secret), "the export must not carry the TOTP seed");
    for needle in ["\"secret\"", "token_hash", "refresh_token", "secret_enc", "$argon2"] {
        assert!(!body.contains(needle), "the export carries a credential-shaped field {needle}");
    }
}

#[tokio::test]
async fn d40_a_write_member_can_leave_an_org() {
    let app = TestApp::new().await;
    let (owner_access, _owner_refresh) = signed_in(&app, EMAIL).await;
    let org =
        app.post("/api/v1/orgs", Some(&owner_access), serde_json::json!({ "name": "Acme", "slug": "acme" })).await;
    let org_id: pub_core::OrgId = org.json["data"]["id"].as_str().expect("org id").parse().expect("org id");
    signed_in(&app, "writer@corp.com").await;
    let member = app.user_of("writer@corp.com").await;
    app.repos.orgs.add_member(org_id, member, pub_core::RoleLevel::WRITE, app.now()).await.expect("add member");
    // Signed in *again* after the grant: org levels are frozen into the access token when it is
    // minted (S-07), so a membership added afterwards is invisible until the pair rotates.
    let (member_access, _member_refresh) = signed_in(&app, "writer@corp.com").await;

    // The surface a Write member never had: they cannot reach the member-management routes at
    // all, which is exactly why D40 existed.
    let refused = app.delete(&format!("/api/v1/orgs/acme/members/{member}"), Some(&member_access)).await;
    assert_eq!(refused.status, StatusCode::FORBIDDEN, "{:?}", refused.json);

    let left = app.delete("/api/v1/orgs/acme/membership", Some(&member_access)).await;
    assert_eq!(left.status, StatusCode::OK, "{:?}", left.json);
    assert!(app.repos.orgs.get_member(org_id, member).await.expect("member").is_none());

    // The sole Owner is still refused by the invariant the repository owns. Their token predates
    // the org they created, so it too has to be rotated first — decision 38's recorded snapshot
    // rule, met here rather than worked around.
    let (owner_access, _rotated) = signed_in(&app, EMAIL).await;
    let owner_leaving = app.delete("/api/v1/orgs/acme/membership", Some(&owner_access)).await;
    assert_eq!(owner_leaving.status, StatusCode::CONFLICT, "{:?}", owner_leaving.json);
    assert_eq!(owner_leaving.json["error"]["code"], "last_owner");
}

#[tokio::test]
async fn s29_c_security_txt_is_absent_until_a_contact_is_configured() {
    let app = TestApp::new().await;
    let absent =
        app.send_raw(app.request(Method::GET, "/.well-known/security.txt", None, None, common::DEFAULT_IP)).await;
    assert_eq!(absent.status, StatusCode::NOT_FOUND, "the default install advertises no contact");

    let configured = TestApp::with_options(TestOptions {
        disclosure_contact: Some("mailto:security@corp.com".to_owned()),
        disclosure_policy_url: Some("https://corp.com/security".to_owned()),
        ..TestOptions::default()
    })
    .await;
    let file = configured
        .send_raw(configured.request(Method::GET, "/.well-known/security.txt", None, None, common::DEFAULT_IP))
        .await;
    assert_eq!(file.status, StatusCode::OK);
    assert!(file.headers["content-type"].to_str().expect("ascii").starts_with("text/plain"));
    let body = String::from_utf8(file.body.clone()).expect("utf-8");
    assert!(body.contains("Contact: mailto:security@corp.com"), "{body}");
    assert!(body.contains("Policy: https://corp.com/security"), "{body}");
    // RFC 9116 requires Expires, and it must be in the future — the failure of every
    // hand-maintained security.txt is that it silently is not.
    let expires =
        body.lines().find_map(|line| line.strip_prefix("Expires: ")).expect("Expires is mandatory (RFC 9116)");
    let expires: chrono::DateTime<chrono::Utc> = chrono::DateTime::parse_from_rfc3339(expires).expect("rfc3339").into();
    assert!(expires > configured.now(), "the published file must not be expired: {expires}");
}
