//! TOTP second-factor + step-up integration tests (S-05, S-06): enrollment, the login-time
//! MFA step, replay/skew handling, recovery codes, backoff, and the sudo-mode gates.

mod common;

use axum::http::{StatusCode, header};
use chrono::Duration;
use common::{TestApp, TestOptions};
use pub_auth::totp;

const EMAIL: &str = "dev@corp.com";

/// A TOTP code guaranteed wrong at (and around) `now` for this seed.
fn wrong_totp(seed: &[u8], app: &TestApp) -> String {
    let current = totp::step_at(app.now());
    let live: Vec<String> = (current - 2..=current + 2).map(|step| totp::code_at(seed, step)).collect();
    for candidate in ["000000", "111111", "222222", "333333", "444444", "555555"] {
        if !live.iter().any(|code| code == candidate) {
            return candidate.to_owned();
        }
    }
    unreachable!("six candidates cannot all be live");
}

/// Enrolls + confirms TOTP for the holder of `access`; returns (seed, recovery codes).
async fn enroll(app: &TestApp, access: &str) -> (Vec<u8>, Vec<String>) {
    let started = app.post("/api/v1/auth/totp/enroll", Some(access), serde_json::json!({})).await;
    assert_eq!(started.status, StatusCode::OK, "enroll failed: {:?}", started.json);
    let secret_b32 = started.json["data"]["secret"].as_str().expect("secret").to_owned();
    let otpauth = started.json["data"]["otpauth_url"].as_str().expect("otpauth_url");
    assert!(otpauth.starts_with("otpauth://totp/"), "bad otpauth url: {otpauth}");
    assert!(otpauth.contains(&format!("secret={secret_b32}")));
    let seed = totp::base32_decode(&secret_b32).expect("secret is base32");
    assert_eq!(seed.len(), 20, "S-05: 160-bit seed");

    let code = totp::code_at(&seed, totp::step_at(app.now()));
    let confirmed = app.post("/api/v1/auth/totp/confirm", Some(access), serde_json::json!({ "code": code })).await;
    assert_eq!(confirmed.status, StatusCode::OK, "confirm failed: {:?}", confirmed.json);
    let codes: Vec<String> = confirmed.json["data"]["recovery_codes"]
        .as_array()
        .expect("recovery codes")
        .iter()
        .map(|value| value.as_str().unwrap().to_owned())
        .collect();
    assert_eq!(codes.len(), 10, "S-05: ten recovery codes");
    for code in &codes {
        assert_eq!(code.len(), 11, "XXXXX-XXXXX shape: {code}");
        assert_eq!(code.as_bytes()[5], b'-');
    }
    (seed, codes)
}

/// Runs the OTP first factor and returns the pending-MFA token (asserts no session leaked).
async fn first_factor(app: &TestApp, email: &str) -> String {
    let (pending_id, code) = app.request_otp(email).await;
    let response = app
        .post(
            "/api/v1/auth/otp/verify",
            None,
            serde_json::json!({ "pending_id": pending_id, "email": email, "code": code }),
        )
        .await;
    assert_eq!(response.status, StatusCode::OK, "{:?}", response.json);
    let data = &response.json["data"];
    assert_eq!(data["mfa_required"], true, "TOTP-enrolled account must not get tokens yet: {data}");
    assert!(data["access_token"].is_null(), "no access token before the second factor");
    assert!(data["refresh_token"].is_null(), "no refresh token before the second factor");
    data["mfa_token"].as_str().expect("mfa_token").to_owned()
}

/// Full MFA login with a fresh TOTP code; returns the login payload.
async fn mfa_login(app: &TestApp, email: &str, seed: &[u8]) -> serde_json::Value {
    let mfa_token = first_factor(app, email).await;
    let code = totp::code_at(seed, totp::step_at(app.now()));
    let response =
        app.post("/api/v1/auth/totp/verify", None, serde_json::json!({ "mfa_token": mfa_token, "code": code })).await;
    assert_eq!(response.status, StatusCode::OK, "mfa verify failed: {:?}", response.json);
    response.json["data"].clone()
}

// --- S-05: enrollment & login ---

#[tokio::test]
async fn s05_enroll_confirm_login_happy_path_and_secret_encrypted_at_rest() {
    let app = TestApp::new().await;
    let login = app.login(EMAIL).await;
    let access = login["access_token"].as_str().unwrap().to_owned();
    let user_id: pub_core::UserId = login["user"]["id"].as_str().unwrap().parse().unwrap();

    // A wrong confirmation code activates nothing.
    let started = app.post("/api/v1/auth/totp/enroll", Some(&access), serde_json::json!({})).await;
    assert_eq!(started.status, StatusCode::OK);
    let seed = totp::base32_decode(started.json["data"]["secret"].as_str().unwrap()).unwrap();
    let bad = app
        .post("/api/v1/auth/totp/confirm", Some(&access), serde_json::json!({ "code": wrong_totp(&seed, &app) }))
        .await;
    assert_eq!(bad.status, StatusCode::UNAUTHORIZED);
    assert_eq!(bad.error_code(), "invalid_code");
    assert!(app.repos.credentials.find_totp(user_id).await.unwrap().is_none(), "nothing active yet");

    // Re-enrolling replaces the pending seed; confirm with the fresh one.
    let (seed, _codes) = enroll(&app, &access).await;

    // S-05: the stored bytes are NOT the seed — they are the KEK-sealed form.
    let stored = app.repos.credentials.find_totp(user_id).await.unwrap().expect("enrolled");
    assert_ne!(stored.secret_enc, seed, "seed stored in plaintext");
    assert!(!stored.secret_enc.windows(seed.len()).any(|w| w == seed), "seed embedded in stored bytes");
    assert_eq!(totp::open(&common::TEST_KEK, &stored.secret_enc).unwrap(), seed, "sealed under the boot KEK");

    // Double enrollment while active conflicts.
    let again = app.post("/api/v1/auth/totp/enroll", Some(&access), serde_json::json!({})).await;
    assert_eq!(again.status, StatusCode::CONFLICT);

    // Login now demands the second factor and completes with a fresh code.
    app.advance(Duration::seconds(61));
    let data = mfa_login(&app, EMAIL, &seed).await;
    let mfa_access = data["access_token"].as_str().unwrap();
    assert_eq!(app.get("/api/v1/sessions", Some(mfa_access)).await.status, StatusCode::OK);
}

#[tokio::test]
async fn s05_wrong_and_out_of_window_codes_rejected_then_valid_one_passes() {
    let app = TestApp::new().await;
    let login = app.login(EMAIL).await;
    let (seed, _codes) = enroll(&app, login["access_token"].as_str().unwrap()).await;

    app.advance(Duration::seconds(61));
    let mfa_token = first_factor(&app, EMAIL).await;
    let current = totp::step_at(app.now());

    // ±2 steps is outside the accepted window (S-05: ±1).
    for step in [current - 2, current + 2] {
        let response = app
            .post(
                "/api/v1/auth/totp/verify",
                None,
                serde_json::json!({ "mfa_token": mfa_token, "code": totp::code_at(&seed, step) }),
            )
            .await;
        assert_eq!(response.status, StatusCode::UNAUTHORIZED, "step {step} must be outside the window");
        assert_eq!(response.error_code(), "invalid_code");
    }

    // −1 step (previous code, clock skew) is accepted.
    let response = app
        .post(
            "/api/v1/auth/totp/verify",
            None,
            serde_json::json!({ "mfa_token": mfa_token, "code": totp::code_at(&seed, current - 1) }),
        )
        .await;
    assert_eq!(response.status, StatusCode::OK, "−1 skew must be accepted: {:?}", response.json);
}

#[tokio::test]
async fn s05_replayed_step_rejected_and_plus_one_skew_accepted() {
    let app = TestApp::new().await;
    let login = app.login(EMAIL).await;
    let access = login["access_token"].as_str().unwrap().to_owned();
    let (seed, _codes) = enroll(&app, &access).await;

    // Step-up is the cleanest surface for replay semantics: same session, same clock.
    app.advance(Duration::seconds(30));
    let current = totp::step_at(app.now());
    let code = totp::code_at(&seed, current);
    let first = app.post("/api/v1/auth/step-up", Some(&access), serde_json::json!({ "code": code })).await;
    assert_eq!(first.status, StatusCode::OK, "{:?}", first.json);

    // The exact same code at the exact same time: the last-accepted-step floor kills it.
    let replay = app.post("/api/v1/auth/step-up", Some(&access), serde_json::json!({ "code": code })).await;
    assert_eq!(replay.status, StatusCode::UNAUTHORIZED, "replay of an accepted step must fail (S-05)");
    assert_eq!(replay.error_code(), "invalid_code");

    // +1 step (client clock ahead) is within skew and above the floor: accepted.
    let ahead = totp::code_at(&seed, current + 1);
    let plus_one = app.post("/api/v1/auth/step-up", Some(&access), serde_json::json!({ "code": ahead })).await;
    assert_eq!(plus_one.status, StatusCode::OK, "+1 skew must be accepted: {:?}", plus_one.json);
}

#[tokio::test]
async fn s05_recovery_codes_are_single_use() {
    let app = TestApp::new().await;
    let login = app.login(EMAIL).await;
    let (_seed, codes) = enroll(&app, login["access_token"].as_str().unwrap()).await;

    // Sign in with a recovery code instead of TOTP.
    app.advance(Duration::seconds(61));
    let mfa_token = first_factor(&app, EMAIL).await;
    let response = app
        .post(
            "/api/v1/auth/totp/verify",
            None,
            serde_json::json!({ "mfa_token": mfa_token, "recovery_code": codes[0] }),
        )
        .await;
    assert_eq!(response.status, StatusCode::OK, "recovery login failed: {:?}", response.json);

    // The spent code is dead; an unspent one still works (S-05 single-use).
    app.advance(Duration::seconds(61));
    let mfa_token = first_factor(&app, EMAIL).await;
    let reused = app
        .post(
            "/api/v1/auth/totp/verify",
            None,
            serde_json::json!({ "mfa_token": mfa_token, "recovery_code": codes[0] }),
        )
        .await;
    assert_eq!(reused.status, StatusCode::UNAUTHORIZED, "a recovery code is single-use");
    let fresh = app
        .post(
            "/api/v1/auth/totp/verify",
            None,
            serde_json::json!({ "mfa_token": mfa_token, "recovery_code": codes[1] }),
        )
        .await;
    assert_eq!(fresh.status, StatusCode::OK, "{:?}", fresh.json);

    // Entry is forgiving: case and separators do not matter (the code, not the format,
    // is the secret).
    app.advance(Duration::seconds(61));
    let mfa_token = first_factor(&app, EMAIL).await;
    let sloppy = codes[2].to_ascii_lowercase().replace('-', " ");
    let forgiving = app
        .post("/api/v1/auth/totp/verify", None, serde_json::json!({ "mfa_token": mfa_token, "recovery_code": sloppy }))
        .await;
    assert_eq!(forgiving.status, StatusCode::OK, "{:?}", forgiving.json);
}

#[tokio::test]
async fn s05_sixth_failure_hits_exponential_backoff() {
    // A generous IP bucket isolates the *MFA* backoff from the S-24 login limit.
    let app = TestApp::with_options(TestOptions { login_per_ip_minute: 100, ..TestOptions::default() }).await;
    let login = app.login(EMAIL).await;
    let (seed, _codes) = enroll(&app, login["access_token"].as_str().unwrap()).await;

    app.advance(Duration::seconds(61));
    let mfa_token = first_factor(&app, EMAIL).await;
    let bad = wrong_totp(&seed, &app);

    // Five failures spend the budget (each an ordinary uniform 401)…
    for attempt in 1..=5 {
        let response = app
            .post("/api/v1/auth/totp/verify", None, serde_json::json!({ "mfa_token": mfa_token, "code": bad }))
            .await;
        assert_eq!(response.status, StatusCode::UNAUTHORIZED, "attempt {attempt}");
        assert_eq!(response.error_code(), "invalid_code", "attempt {attempt}");
    }

    // …the sixth attempt is refused *before* verification: 429 + Retry-After (S-05 backoff).
    let throttled =
        app.post("/api/v1/auth/totp/verify", None, serde_json::json!({ "mfa_token": mfa_token, "code": bad })).await;
    assert_eq!(throttled.status, StatusCode::TOO_MANY_REQUESTS);
    let retry_after: u64 = throttled.headers[header::RETRY_AFTER].to_str().unwrap().parse().unwrap();
    assert!(retry_after >= 1, "backoff must be at least a second");

    // After the backoff a (failing) attempt processes again — and doubles the delay.
    app.advance(Duration::seconds(retry_after as i64 + 1));
    let processed =
        app.post("/api/v1/auth/totp/verify", None, serde_json::json!({ "mfa_token": mfa_token, "code": bad })).await;
    assert_eq!(processed.status, StatusCode::UNAUTHORIZED);
    let throttled =
        app.post("/api/v1/auth/totp/verify", None, serde_json::json!({ "mfa_token": mfa_token, "code": bad })).await;
    assert_eq!(throttled.status, StatusCode::TOO_MANY_REQUESTS);
    let longer: u64 = throttled.headers[header::RETRY_AFTER].to_str().unwrap().parse().unwrap();
    assert!(longer > retry_after, "backoff must grow: {longer} vs {retry_after}");

    // The correct code still works once the wait is honoured — the *account* never locks.
    app.advance(Duration::seconds(longer as i64 + 1));
    let code = totp::code_at(&seed, totp::step_at(app.now()));
    let recovered =
        app.post("/api/v1/auth/totp/verify", None, serde_json::json!({ "mfa_token": mfa_token, "code": code })).await;
    assert_eq!(recovered.status, StatusCode::OK, "{:?}", recovered.json);
}

#[tokio::test]
async fn s05_mfa_pending_handle_expires_and_garbage_is_uniform() {
    let app = TestApp::new().await;
    let login = app.login(EMAIL).await;
    let (seed, _codes) = enroll(&app, login["access_token"].as_str().unwrap()).await;

    // Garbage handle → uniform invalid_code.
    let garbage = app
        .post("/api/v1/auth/totp/verify", None, serde_json::json!({ "mfa_token": "f".repeat(32), "code": "123456" }))
        .await;
    assert_eq!(garbage.status, StatusCode::UNAUTHORIZED);
    assert_eq!(garbage.error_code(), "invalid_code");

    // A pending login dies after its TTL even with a perfect code.
    app.advance(Duration::seconds(61));
    let mfa_token = first_factor(&app, EMAIL).await;
    app.advance(Duration::minutes(6));
    let code = totp::code_at(&seed, totp::step_at(app.now()));
    let expired =
        app.post("/api/v1/auth/totp/verify", None, serde_json::json!({ "mfa_token": mfa_token, "code": code })).await;
    assert_eq!(expired.status, StatusCode::UNAUTHORIZED, "expired pending-MFA handle must fail");

    // Sending both code and recovery_code is a shape error, not an auth probe.
    app.advance(Duration::seconds(61));
    let mfa_token = first_factor(&app, EMAIL).await;
    let both = app
        .post(
            "/api/v1/auth/totp/verify",
            None,
            serde_json::json!({ "mfa_token": mfa_token, "code": "123456", "recovery_code": "AAAAA-AAAAA" }),
        )
        .await;
    assert_eq!(both.status, StatusCode::BAD_REQUEST);
}

// --- S-06: step-up gates ---

#[tokio::test]
async fn s06_publish_token_mint_requires_step_up_and_totp_satisfies_it() {
    let app = TestApp::with_options(TestOptions { login_per_ip_minute: 100, ..TestOptions::default() }).await;
    let login = app.login(EMAIL).await;
    let access0 = login["access_token"].as_str().unwrap().to_owned();
    let org = app.post("/api/v1/orgs", Some(&access0), serde_json::json!({ "name": "Acme", "slug": "acme" })).await;
    let org_id = org.json["data"]["id"].as_str().unwrap().to_owned();
    let (seed, _codes) = enroll(&app, &access0).await;

    // Fresh MFA login: the login itself is the strongest factor chain — step-up-fresh.
    app.advance(Duration::seconds(61));
    let data = mfa_login(&app, EMAIL, &seed).await;
    let access = data["access_token"].as_str().unwrap().to_owned();
    let refresh = data["refresh_token"].as_str().unwrap().to_owned();
    let fresh_mint =
        app.post("/api/v1/tokens", Some(&access), serde_json::json!({ "org_id": org_id, "scopes": ["publish"] })).await;
    assert_eq!(fresh_mint.status, StatusCode::OK, "a fresh login satisfies S-06: {:?}", fresh_mint.json);

    // 16 minutes later the session is stale: publish/admin mints demand step-up.
    app.advance(Duration::minutes(16));
    let rotated = app.post("/api/v1/auth/refresh", None, serde_json::json!({ "refresh_token": refresh })).await;
    assert_eq!(rotated.status, StatusCode::OK);
    let access = rotated.json["data"]["access_token"].as_str().unwrap().to_owned();
    let refresh = rotated.json["data"]["refresh_token"].as_str().unwrap().to_owned();

    let stale_mint =
        app.post("/api/v1/tokens", Some(&access), serde_json::json!({ "org_id": org_id, "scopes": ["publish"] })).await;
    assert_eq!(stale_mint.status, StatusCode::FORBIDDEN);
    assert_eq!(stale_mint.error_code(), "step_up_required", "distinct code so the UI can prompt (S-06)");
    let admin_mint =
        app.post("/api/v1/tokens", Some(&access), serde_json::json!({ "org_id": org_id, "scopes": ["admin"] })).await;
    assert_eq!(admin_mint.error_code(), "step_up_required");

    // Read-scoped mints stay ungated.
    let read_mint =
        app.post("/api/v1/tokens", Some(&access), serde_json::json!({ "org_id": org_id, "scopes": ["read"] })).await;
    assert_eq!(read_mint.status, StatusCode::OK, "{:?}", read_mint.json);

    // Step up with a live code; the gate opens for the window.
    let code = totp::code_at(&seed, totp::step_at(app.now()));
    let stepped = app.post("/api/v1/auth/step-up", Some(&access), serde_json::json!({ "code": code })).await;
    assert_eq!(stepped.status, StatusCode::OK, "{:?}", stepped.json);
    assert!(stepped.json["data"]["valid_until"].is_string());
    let gated_mint =
        app.post("/api/v1/tokens", Some(&access), serde_json::json!({ "org_id": org_id, "scopes": ["publish"] })).await;
    assert_eq!(gated_mint.status, StatusCode::OK, "step-up must open the gate: {:?}", gated_mint.json);

    // The mark expires with the window (S-06): 16 minutes later the gate is closed again.
    app.advance(Duration::minutes(16));
    let rotated = app.post("/api/v1/auth/refresh", None, serde_json::json!({ "refresh_token": refresh })).await;
    let access = rotated.json["data"]["access_token"].as_str().unwrap().to_owned();
    let expired_mint =
        app.post("/api/v1/tokens", Some(&access), serde_json::json!({ "org_id": org_id, "scopes": ["publish"] })).await;
    assert_eq!(expired_mint.error_code(), "step_up_required", "step-up freshness must expire");
}

#[tokio::test]
async fn s06_totp_disable_requires_step_up() {
    let app = TestApp::with_options(TestOptions { login_per_ip_minute: 100, ..TestOptions::default() }).await;
    let login = app.login(EMAIL).await;
    let user_id: pub_core::UserId = login["user"]["id"].as_str().unwrap().parse().unwrap();
    let (seed, _codes) = enroll(&app, login["access_token"].as_str().unwrap()).await;

    app.advance(Duration::seconds(61));
    let data = mfa_login(&app, EMAIL, &seed).await;
    let refresh = data["refresh_token"].as_str().unwrap().to_owned();

    // Stale session: disabling 2FA is exactly what a session thief would do first (S-06).
    app.advance(Duration::minutes(16));
    let rotated = app.post("/api/v1/auth/refresh", None, serde_json::json!({ "refresh_token": refresh })).await;
    let access = rotated.json["data"]["access_token"].as_str().unwrap().to_owned();
    let denied = app.delete("/api/v1/auth/totp", Some(&access)).await;
    assert_eq!(denied.status, StatusCode::FORBIDDEN);
    assert_eq!(denied.error_code(), "step_up_required");
    assert!(app.repos.credentials.find_totp(user_id).await.unwrap().is_some(), "second factor must survive");

    // Step up, then disable.
    let code = totp::code_at(&seed, totp::step_at(app.now()));
    assert_eq!(
        app.post("/api/v1/auth/step-up", Some(&access), serde_json::json!({ "code": code })).await.status,
        StatusCode::OK
    );
    let disabled = app.delete("/api/v1/auth/totp", Some(&access)).await;
    assert_eq!(disabled.status, StatusCode::OK, "{:?}", disabled.json);
    assert!(app.repos.credentials.find_totp(user_id).await.unwrap().is_none());
    assert!(app.repos.credentials.list_recovery_codes(user_id).await.unwrap().is_empty(), "codes removed too");

    // With MFA gone, the next login is single-factor again.
    app.advance(Duration::seconds(61));
    let plain = app.login(EMAIL).await;
    assert_eq!(plain["mfa_required"], false);
}

#[tokio::test]
async fn s06_revoke_all_requires_step_up_but_fresh_login_counts() {
    let app = TestApp::with_options(TestOptions { login_per_ip_minute: 100, ..TestOptions::default() }).await;
    // No TOTP on this account: re-auth (a fresh login) is the only step-up path.
    let login = app.login(EMAIL).await;
    let refresh = login["refresh_token"].as_str().unwrap().to_owned();

    app.advance(Duration::minutes(16));
    let rotated = app.post("/api/v1/auth/refresh", None, serde_json::json!({ "refresh_token": refresh })).await;
    let stale_access = rotated.json["data"]["access_token"].as_str().unwrap().to_owned();
    let denied = app.post_empty("/api/v1/sessions/revoke-all", Some(&stale_access)).await;
    assert_eq!(denied.status, StatusCode::FORBIDDEN);
    assert_eq!(denied.error_code(), "step_up_required");

    // Without a second factor the step-up endpoint refuses — re-auth is the answer.
    let no_factor =
        app.post("/api/v1/auth/step-up", Some(&stale_access), serde_json::json!({ "code": "123456" })).await;
    assert_eq!(no_factor.status, StatusCode::BAD_REQUEST);

    // A fresh login (fresh session) satisfies the gate.
    let fresh = app.login(EMAIL).await;
    let fresh_access = fresh["access_token"].as_str().unwrap();
    let revoked = app.post_empty("/api/v1/sessions/revoke-all", Some(fresh_access)).await;
    assert_eq!(revoked.status, StatusCode::OK, "{:?}", revoked.json);
    assert!(revoked.json["data"]["revoked"].as_u64().unwrap() >= 2);
}

#[tokio::test]
async fn s06_step_up_accepts_recovery_codes_too() {
    let app = TestApp::with_options(TestOptions { login_per_ip_minute: 100, ..TestOptions::default() }).await;
    let login = app.login(EMAIL).await;
    let (seed, codes) = enroll(&app, login["access_token"].as_str().unwrap()).await;

    app.advance(Duration::seconds(61));
    let data = mfa_login(&app, EMAIL, &seed).await;
    let refresh = data["refresh_token"].as_str().unwrap().to_owned();

    app.advance(Duration::minutes(16));
    let rotated = app.post("/api/v1/auth/refresh", None, serde_json::json!({ "refresh_token": refresh })).await;
    let access = rotated.json["data"]["access_token"].as_str().unwrap().to_owned();

    // Lost the phone, still holding a recovery code: step-up works (and burns the code).
    let stepped =
        app.post("/api/v1/auth/step-up", Some(&access), serde_json::json!({ "recovery_code": codes[0] })).await;
    assert_eq!(stepped.status, StatusCode::OK, "{:?}", stepped.json);
    let again = app.post("/api/v1/auth/step-up", Some(&access), serde_json::json!({ "recovery_code": codes[0] })).await;
    assert_eq!(again.status, StatusCode::UNAUTHORIZED, "the spent recovery code must be gone");
}
