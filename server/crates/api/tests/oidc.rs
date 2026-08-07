//! OIDC vertical-slice integration tests (S-01, S-02, S-31): the full relying-party path
//! against an in-process mock issuer — discovery, PKCE, token exchange, id_token
//! validation, account resolution and linking. Security tests carry their S-xx id.

mod common;

use std::collections::HashMap;

use axum::http::StatusCode;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
use common::oidc::{DEFAULT_KID, MockIssuer, sign_rs256};
use common::{ApiResponse, INSTANCE_ORIGIN, TestApp, TestOptions};

const PROVIDER: &str = "mock";
const CLIENT_ID: &str = "pub-client-id";
const CLIENT_SECRET: &str = "pub-client-secret";

async fn issuer() -> MockIssuer {
    MockIssuer::spawn(CLIENT_ID, CLIENT_SECRET).await
}

async fn app_with(issuer: &MockIssuer, options: TestOptions) -> TestApp {
    TestApp::with_options(TestOptions { oidc_providers: vec![issuer.provider_config(PROVIDER)], ..options }).await
}

/// A started flow, with the authorize-URL parameters the IdP would receive.
struct Flow {
    flow_id: String,
    authorize_url: String,
    params: HashMap<String, String>,
}

impl Flow {
    fn param(&self, name: &str) -> &str {
        self.params.get(name).unwrap_or_else(|| panic!("authorize_url misses {name}: {}", self.authorize_url))
    }
}

async fn start_flow(app: &TestApp) -> Flow {
    let response = app.post(&format!("/api/v1/auth/oidc/{PROVIDER}/start"), None, serde_json::json!({})).await;
    assert_eq!(response.status, StatusCode::OK, "start failed: {:?}", response.json);
    let flow_id = response.json["data"]["flow_id"].as_str().expect("flow_id").to_owned();
    let authorize_url = response.json["data"]["authorize_url"].as_str().expect("authorize_url").to_owned();
    let parsed = url::Url::parse(&authorize_url).expect("authorize_url parses");
    let params = parsed.query_pairs().into_owned().collect();
    Flow { flow_id, authorize_url, params }
}

async fn callback(app: &TestApp, flow_id: &str, state: &str, code: &str) -> ApiResponse {
    app.post(
        &format!("/api/v1/auth/oidc/{PROVIDER}/callback"),
        None,
        serde_json::json!({ "flow_id": flow_id, "code": code, "state": state }),
    )
    .await
}

/// Full happy-path dance for `sub`/`email`; returns the callback response.
async fn oidc_login(app: &TestApp, issuer: &MockIssuer, sub: &str, email: Option<&str>, verified: bool) -> ApiResponse {
    let flow = start_flow(app).await;
    let claims = issuer.claims(sub, email, verified, flow.param("nonce"), app.now());
    let code = issuer.issue_code(claims, flow.param("code_challenge"));
    callback(app, &flow.flow_id, flow.param("state"), &code).await
}

// --- provider listing & 404s ---

#[tokio::test]
async fn providers_listing_and_unknown_provider_404() {
    let issuer = issuer().await;
    let app = app_with(&issuer, TestOptions::default()).await;

    let listing = app.get("/api/v1/auth/providers", None).await;
    assert_eq!(listing.status, StatusCode::OK);
    let providers = listing.json["data"]["providers"].as_array().unwrap();
    assert_eq!(providers.len(), 1);
    assert_eq!(providers[0]["id"], PROVIDER);
    assert_eq!(providers[0]["display_name"], "Mock mock");
    assert!(!listing.json.to_string().contains(CLIENT_SECRET), "secret leaked into the listing");

    // Unknown provider: start and callback are both uniform 404s.
    let start = app.post("/api/v1/auth/oidc/github/start", None, serde_json::json!({})).await;
    assert_eq!(start.status, StatusCode::NOT_FOUND);
    let cb = app
        .post(
            "/api/v1/auth/oidc/github/callback",
            None,
            serde_json::json!({ "flow_id": "x", "code": "y", "state": "z" }),
        )
        .await;
    assert_eq!(cb.status, StatusCode::NOT_FOUND);

    // Zero providers configured: the listing is empty (email OTP only).
    let bare = TestApp::new().await;
    let listing = bare.get("/api/v1/auth/providers", None).await;
    assert_eq!(listing.status, StatusCode::OK);
    assert_eq!(listing.json["data"]["providers"].as_array().unwrap().len(), 0);
}

// --- S-01: the happy path and the flow contract ---

#[tokio::test]
async fn s01_happy_path_creates_user_and_flow_carries_pkce_state_nonce() {
    let issuer = issuer().await;
    let app = app_with(&issuer, TestOptions::default()).await;

    let flow = start_flow(&app).await;
    assert!(flow.authorize_url.starts_with(&format!("{}/authorize?", issuer.issuer)));
    assert_eq!(flow.param("response_type"), "code");
    assert_eq!(flow.param("client_id"), CLIENT_ID);
    assert_eq!(flow.param("redirect_uri"), format!("{INSTANCE_ORIGIN}/auth/callback/{PROVIDER}"));
    assert_eq!(flow.param("code_challenge_method"), "S256");
    assert_eq!(flow.param("state").len(), 64, "state is 256-bit hex (S-01: ≥128-bit)");
    assert_eq!(flow.param("nonce").len(), 64);
    assert_eq!(flow.param("code_challenge").len(), 43, "S256 challenge is 32 b64url bytes");
    assert!(flow.param("scope").split(' ').any(|s| s == "openid"));

    let claims = issuer.claims("subject-1", Some("newcomer@corp.com"), true, flow.param("nonce"), app.now());
    let code = issuer.issue_code(claims, flow.param("code_challenge"));
    let response = callback(&app, &flow.flow_id, flow.param("state"), &code).await;
    assert_eq!(response.status, StatusCode::OK, "{:?}", response.json);
    let data = &response.json["data"];
    assert_eq!(data["mfa_required"], false);
    assert_eq!(data["user"]["email"], "newcomer@corp.com");
    assert_eq!(data["user"]["email_verified"], true);
    let access = data["access_token"].as_str().unwrap();
    assert_eq!(app.get("/api/v1/sessions", Some(access)).await.status, StatusCode::OK);
    let first_user = data["user"]["id"].as_str().unwrap().to_owned();

    // Same (issuer, subject) signs in to the same account — even with a changed email:
    // the identity key is (iss, sub), never the address (S-01).
    let again = oidc_login(&app, &issuer, "subject-1", Some("changed@corp.com"), true).await;
    assert_eq!(again.status, StatusCode::OK);
    assert_eq!(again.json["data"]["user"]["id"].as_str().unwrap(), first_user);
}

#[tokio::test]
async fn s01_state_replay_and_mismatch_rejected() {
    let issuer = issuer().await;
    let app = app_with(&issuer, TestOptions::default()).await;

    // A completed flow cannot be redeemed twice (single-use state).
    let flow = start_flow(&app).await;
    let claims = issuer.claims("replay-sub", Some("replay@corp.com"), true, flow.param("nonce"), app.now());
    let code = issuer.issue_code(claims.clone(), flow.param("code_challenge"));
    assert_eq!(callback(&app, &flow.flow_id, flow.param("state"), &code).await.status, StatusCode::OK);
    let replay_code = issuer.issue_code(claims, flow.param("code_challenge"));
    let replay = callback(&app, &flow.flow_id, flow.param("state"), &replay_code).await;
    assert_eq!(replay.status, StatusCode::UNAUTHORIZED, "flow replay must fail");

    // A wrong state value on a live flow is rejected — and burns the flow (single-use
    // regardless of outcome).
    let flow = start_flow(&app).await;
    let claims = issuer.claims("tamper-sub", Some("tamper@corp.com"), true, flow.param("nonce"), app.now());
    let code = issuer.issue_code(claims, flow.param("code_challenge"));
    let forged_state = "f".repeat(64);
    assert_eq!(callback(&app, &flow.flow_id, &forged_state, &code).await.status, StatusCode::UNAUTHORIZED);
    let after = callback(&app, &flow.flow_id, flow.param("state"), &code).await;
    assert_eq!(after.status, StatusCode::UNAUTHORIZED, "one bad presentation kills the flow");

    // Unknown flow id.
    let ghost = callback(&app, &"a".repeat(32), &forged_state, "any-code").await;
    assert_eq!(ghost.status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn s01_nonce_mismatch_rejected() {
    let issuer = issuer().await;
    let app = app_with(&issuer, TestOptions::default()).await;

    let flow = start_flow(&app).await;
    // The IdP echoes a *different* nonce than the one this flow minted.
    let claims = issuer.claims("nonce-sub", Some("nonce@corp.com"), true, &"e".repeat(64), app.now());
    let code = issuer.issue_code(claims, flow.param("code_challenge"));
    let response = callback(&app, &flow.flow_id, flow.param("state"), &code).await;
    assert_eq!(response.status, StatusCode::UNAUTHORIZED, "nonce mismatch must fail");

    // And a token with *no* nonce at all fails too.
    let flow = start_flow(&app).await;
    let mut claims = issuer.claims("nonce-sub", Some("nonce@corp.com"), true, "ignored", app.now());
    claims.as_object_mut().unwrap().remove("nonce");
    let code = issuer.issue_code(claims, flow.param("code_challenge"));
    assert_eq!(callback(&app, &flow.flow_id, flow.param("state"), &code).await.status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn s01_forged_alg_none_and_hs256_id_tokens_rejected() {
    use hmac::{KeyInit as _, Mac as _};

    let issuer = issuer().await;
    let app = app_with(&issuer, TestOptions::default()).await;

    let run_with_override = |token: String| {
        let issuer = &issuer;
        let app = &app;
        async move {
            let flow = start_flow(app).await;
            issuer.override_id_token(Some(token));
            let claims = issuer.claims("forged-sub", Some("forged@corp.com"), true, flow.param("nonce"), app.now());
            let code = issuer.issue_code(claims, flow.param("code_challenge"));
            let response = callback(app, &flow.flow_id, flow.param("state"), &code).await;
            issuer.override_id_token(None);
            response
        }
    };

    // alg:none with a perfectly valid payload — with and without a trailing signature.
    let claims = issuer.claims("forged-sub", Some("forged@corp.com"), true, &"0".repeat(64), app.now());
    let header = B64URL.encode(format!(r#"{{"alg":"none","typ":"JWT","kid":"{DEFAULT_KID}"}}"#));
    let body = B64URL.encode(serde_json::to_vec(&claims).unwrap());
    for forged in [format!("{header}.{body}."), format!("{header}.{body}.{}", B64URL.encode([0u8; 256]))] {
        let response = run_with_override(forged).await;
        assert_eq!(response.status, StatusCode::UNAUTHORIZED, "alg:none must never verify");
    }

    // HS256 "signed" with public material (the classic key-confusion forgery).
    let hs_header = B64URL.encode(format!(r#"{{"alg":"HS256","typ":"JWT","kid":"{DEFAULT_KID}"}}"#));
    let signing_input = format!("{hs_header}.{body}");
    let mut mac = hmac::Hmac::<sha2::Sha256>::new_from_slice(CLIENT_SECRET.as_bytes()).unwrap();
    mac.update(signing_input.as_bytes());
    let forged = format!("{signing_input}.{}", B64URL.encode(mac.finalize().into_bytes()));
    let response = run_with_override(forged).await;
    assert_eq!(response.status, StatusCode::UNAUTHORIZED, "HS256 must never verify");

    // Sanity: the same dance with an honest RS256 token succeeds (the harness is not
    // rejecting everything).
    let honest = oidc_login(&app, &issuer, "honest-sub", Some("honest@corp.com"), true).await;
    assert_eq!(honest.status, StatusCode::OK, "{:?}", honest.json);
}

#[tokio::test]
async fn s01_expired_and_future_id_tokens_rejected() {
    let issuer = issuer().await;
    let app = app_with(&issuer, TestOptions::default()).await;

    // Expired beyond skew.
    let flow = start_flow(&app).await;
    let mut claims = issuer.claims("time-sub", Some("time@corp.com"), true, flow.param("nonce"), app.now());
    claims["exp"] = (app.now().timestamp() - 600).into();
    let code = issuer.issue_code(claims, flow.param("code_challenge"));
    assert_eq!(callback(&app, &flow.flow_id, flow.param("state"), &code).await.status, StatusCode::UNAUTHORIZED);

    // iat in the future beyond skew.
    let flow = start_flow(&app).await;
    let mut claims = issuer.claims("time-sub", Some("time@corp.com"), true, flow.param("nonce"), app.now());
    claims["iat"] = (app.now().timestamp() + 600).into();
    let code = issuer.issue_code(claims, flow.param("code_challenge"));
    assert_eq!(callback(&app, &flow.flow_id, flow.param("state"), &code).await.status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn s01_aud_mismatch_rejected() {
    let issuer = issuer().await;
    let app = app_with(&issuer, TestOptions::default()).await;

    let flow = start_flow(&app).await;
    let mut claims = issuer.claims("aud-sub", Some("aud@corp.com"), true, flow.param("nonce"), app.now());
    claims["aud"] = "some-other-client".into();
    let code = issuer.issue_code(claims, flow.param("code_challenge"));
    assert_eq!(callback(&app, &flow.flow_id, flow.param("state"), &code).await.status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn s01_unknown_kid_refetches_jwks_once_then_rejects_and_rotation_works() {
    let issuer = issuer().await;
    let app = app_with(&issuer, TestOptions::default()).await;

    // Prime the metadata cache with one successful login: exactly one JWKS fetch.
    let primed = oidc_login(&app, &issuer, "kid-sub", Some("kid@corp.com"), true).await;
    assert_eq!(primed.status, StatusCode::OK);
    assert_eq!(issuer.jwks_hits(), 1);

    // A kid the JWKS does not list: one refetch, then rejection — never trial verification.
    issuer.set_signing_kid("ghost-kid");
    let ghost = oidc_login(&app, &issuer, "kid-sub", Some("kid@corp.com"), true).await;
    assert_eq!(ghost.status, StatusCode::UNAUTHORIZED, "unknown kid must reject");
    assert_eq!(issuer.jwks_hits(), 2, "exactly one refetch on an unknown kid");

    // Genuine key rotation: the new kid appears in the JWKS — the refetch picks it up.
    issuer.set_jwks_kids(&[DEFAULT_KID, "gen2"]);
    issuer.set_signing_kid("gen2");
    let rotated = oidc_login(&app, &issuer, "kid-sub", Some("kid@corp.com"), true).await;
    assert_eq!(rotated.status, StatusCode::OK, "rotation via refetch must work: {:?}", rotated.json);
    assert_eq!(issuer.jwks_hits(), 3);
}

// --- S-02: account linking ---

#[tokio::test]
async fn s02_links_to_existing_account_only_when_both_sides_verified() {
    let issuer = issuer().await;
    let app = app_with(&issuer, TestOptions::default()).await;

    // A local, email-verified account exists (created through the OTP path).
    let otp_login = app.login("linked@corp.com").await;
    let local_user = otp_login["user"]["id"].as_str().unwrap().to_owned();
    let mails_before = app.mailer.sent().len();

    // OIDC identity with the same, IdP-verified address: auto-link (S-02).
    let response = oidc_login(&app, &issuer, "link-sub", Some("linked@corp.com"), true).await;
    assert_eq!(response.status, StatusCode::OK, "{:?}", response.json);
    assert_eq!(response.json["data"]["user"]["id"].as_str().unwrap(), local_user, "must be the same account");

    // The link is recorded as a credential and the user was notified by email (S-02).
    let user_id: pub_core::UserId = local_user.parse().unwrap();
    let credentials = app.repos.credentials.list_for_user(user_id).await.unwrap();
    assert!(
        credentials.iter().any(|c| c.credential_type == pub_core::credential::CredentialType::Oidc
            && c.issuer.as_deref() == Some(issuer.issuer.as_str())
            && c.subject.as_deref() == Some("link-sub")),
        "oidc credential missing: {credentials:?}"
    );
    let mails = app.mailer.sent();
    assert_eq!(mails.len(), mails_before + 1, "linking must notify the user");
    assert_eq!(mails.last().unwrap().to, "linked@corp.com");
    assert!(
        mails.last().unwrap().subject.contains("linked"),
        "notification subject: {}",
        mails.last().unwrap().subject
    );
}

#[tokio::test]
async fn s02_refuses_link_when_oidc_email_unverified() {
    let issuer = issuer().await;
    let app = app_with(&issuer, TestOptions::default()).await;

    let otp_login = app.login("victim@corp.com").await;
    let local_user: pub_core::UserId = otp_login["user"]["id"].as_str().unwrap().parse().unwrap();

    // The IdP does not vouch for the address: no link, no account, uniform failure.
    let response = oidc_login(&app, &issuer, "phisher-sub", Some("victim@corp.com"), false).await;
    assert_eq!(response.status, StatusCode::UNAUTHORIZED);
    assert_eq!(response.error_code(), "unauthorized");
    let credentials = app.repos.credentials.list_for_user(local_user).await.unwrap();
    assert!(
        credentials.iter().all(|c| c.credential_type != pub_core::credential::CredentialType::Oidc),
        "an unverified identity must never claim an account (S-02): {credentials:?}"
    );

    // No email claim at all is refused the same way.
    let response = oidc_login(&app, &issuer, "emailless-sub", None, false).await;
    assert_eq!(response.status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn s02_refuses_link_when_local_email_unverified() {
    let issuer = issuer().await;
    let app = app_with(&issuer, TestOptions::default()).await;

    // A local account *claims* the address but never verified it.
    let squatter = app
        .repos
        .users
        .create(
            pub_core::user::NewUser {
                email: Some("contested@corp.com".to_owned()),
                email_verified: false,
                display_name: "Squatter".to_owned(),
            },
            common::t0(),
        )
        .await
        .unwrap();

    // Verified OIDC email for the same address: must NOT link to the unverified holder,
    // and must not silently create a duplicate either — uniform refusal.
    let response = oidc_login(&app, &issuer, "contest-sub", Some("contested@corp.com"), true).await;
    assert_eq!(response.status, StatusCode::UNAUTHORIZED);
    let credentials = app.repos.credentials.list_for_user(squatter.id).await.unwrap();
    assert!(credentials.is_empty(), "the unverified holder must gain nothing: {credentials:?}");
}

// --- S-31: domain policy ---

#[tokio::test]
async fn s31_domain_allowlist_applies_to_oidc_sign_in() {
    let issuer = issuer().await;
    let app =
        app_with(&issuer, TestOptions { allowed_email_domains: vec!["corp.com".to_owned()], ..TestOptions::default() })
            .await;

    // A verified email outside the allowlist cannot register.
    let blocked = oidc_login(&app, &issuer, "outsider-sub", Some("outsider@evil.com"), true).await;
    assert_eq!(blocked.status, StatusCode::UNAUTHORIZED, "S-31 must gate OIDC registration");
    assert!(app.repos.users.find_by_email("outsider@evil.com").await.unwrap().is_none());

    // The allowed domain sails through.
    let allowed = oidc_login(&app, &issuer, "insider-sub", Some("insider@corp.com"), true).await;
    assert_eq!(allowed.status, StatusCode::OK, "{:?}", allowed.json);

    // And S-31 is a *sign-in* gate: a pre-existing account+identity on a de-listed domain
    // stops authenticating even though its credential is valid.
    let legacy = app
        .repos
        .users
        .create(
            pub_core::user::NewUser {
                email: Some("legacy@evil.com".to_owned()),
                email_verified: true,
                display_name: "Legacy".to_owned(),
            },
            common::t0(),
        )
        .await
        .unwrap();
    app.repos.credentials.upsert_oidc(legacy.id, &issuer.issuer, "legacy-sub", common::t0()).await.unwrap();
    let denied = oidc_login(&app, &issuer, "legacy-sub", Some("legacy@evil.com"), true).await;
    assert_eq!(denied.status, StatusCode::UNAUTHORIZED, "de-listed domains must not sign in (S-31)");
    assert!(app.repos.sessions.list_for_user(legacy.id).await.unwrap().is_empty(), "no session may exist");
}

// --- registration policy ---

#[tokio::test]
async fn oidc_respects_closed_registration() {
    let issuer = issuer().await;
    let app = app_with(&issuer, TestOptions { allow_registration: false, ..TestOptions::default() }).await;

    let response = oidc_login(&app, &issuer, "reg-sub", Some("stranger@corp.com"), true).await;
    assert_eq!(response.status, StatusCode::UNAUTHORIZED, "closed registration must refuse new OIDC users");
    assert!(app.repos.users.find_by_email("stranger@corp.com").await.unwrap().is_none());
}

// --- forged RS256 from a rogue key is rejected (signature actually checked) ---

#[tokio::test]
async fn s01_signature_of_the_real_key_is_required() {
    let issuer = issuer().await;
    let app = app_with(&issuer, TestOptions::default()).await;

    // Take honest claims but flip one payload byte after signing: signature mismatch.
    let flow = start_flow(&app).await;
    let claims = issuer.claims("sig-sub", Some("sig@corp.com"), true, flow.param("nonce"), app.now());
    let honest = sign_rs256(DEFAULT_KID, &claims);
    let mut parts: Vec<String> = honest.split('.').map(str::to_owned).collect();
    let mut tampered: serde_json::Value = claims.clone();
    tampered["sub"] = "attacker-sub".into();
    parts[1] = B64URL.encode(serde_json::to_vec(&tampered).unwrap());
    issuer.override_id_token(Some(parts.join(".")));
    let code = issuer.issue_code(claims, flow.param("code_challenge"));
    let response = callback(&app, &flow.flow_id, flow.param("state"), &code).await;
    issuer.override_id_token(None);
    assert_eq!(response.status, StatusCode::UNAUTHORIZED, "payload swap must break the signature");
}
