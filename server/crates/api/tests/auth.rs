//! Auth vertical-slice integration tests: email OTP, sessions/JWT, CLI tokens — full
//! in-memory stack with a deterministic clock. Security tests carry their S-xx id
//! (docs/rules/rust.md).

mod common;

use axum::http::{Method, StatusCode, header};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
use chrono::Duration;
use common::{DEFAULT_IP, TestApp, TestOptions, wrong_code};
use pub_auth::jwt::{Claims, Keyring};
use pub_auth::token as cli_token;

const EMAIL: &str = "dev@corp.com";

// --- S-03: OTP lifecycle ---

#[tokio::test]
async fn s03_otp_happy_path_and_single_use() {
    let app = TestApp::new().await;
    let (pending_id, code) = app.request_otp(EMAIL).await;
    assert_eq!(pending_id.len(), 32, "pending id is an opaque 128-bit hex id");
    assert_eq!(code.len(), 8);

    // The mail renders the code, the requester IP, and the expiry window.
    let mail = app.mailer.sent().pop().unwrap();
    assert_eq!(mail.to, EMAIL);
    assert!(mail.text.contains(DEFAULT_IP), "requester IP missing:\n{}", mail.text);
    assert!(mail.text.contains("10 minutes"), "expiry missing:\n{}", mail.text);
    assert!(mail.html.is_some(), "multipart mail must carry the HTML alternative");

    let verify = serde_json::json!({ "pending_id": pending_id, "email": EMAIL, "code": code });
    let response = app.post("/api/v1/auth/otp/verify", None, verify.clone()).await;
    assert_eq!(response.status, StatusCode::OK);
    let data = &response.json["data"];
    assert!(data["access_token"].is_string());
    assert!(data["refresh_token"].is_string());
    assert_eq!(data["user"]["email"], EMAIL);
    assert_eq!(data["user"]["email_verified"], true);

    // The access token authenticates.
    let access = data["access_token"].as_str().unwrap();
    assert_eq!(app.get("/api/v1/sessions", Some(access)).await.status, StatusCode::OK);

    // Single-use: the exact same correct verification fails now.
    let replay = app.post("/api/v1/auth/otp/verify", None, verify).await;
    assert_eq!(replay.status, StatusCode::UNAUTHORIZED);
    assert_eq!(replay.error_code(), "invalid_code");
}

#[tokio::test]
async fn s03_five_wrong_attempts_kill_code() {
    let app = TestApp::new().await;
    let (pending_id, code) = app.request_otp(EMAIL).await;
    let bad = wrong_code(&code);

    for attempt in 1..=5 {
        let response = app
            .post(
                "/api/v1/auth/otp/verify",
                None,
                serde_json::json!({ "pending_id": pending_id, "email": EMAIL, "code": bad }),
            )
            .await;
        assert_eq!(response.status, StatusCode::UNAUTHORIZED, "attempt {attempt}");
        assert_eq!(response.error_code(), "invalid_code", "attempt {attempt}");
    }

    // The correct code is dead too — the record died with attempt 5, never the account.
    let response = app
        .post(
            "/api/v1/auth/otp/verify",
            None,
            serde_json::json!({ "pending_id": pending_id, "email": EMAIL, "code": code }),
        )
        .await;
    assert_eq!(response.status, StatusCode::UNAUTHORIZED);
    assert_eq!(response.error_code(), "invalid_code");
}

#[tokio::test]
async fn s03_resend_invalidates_previous_and_throttles() {
    let app = TestApp::new().await;
    let (first_pending, first_code) = app.request_otp(EMAIL).await;

    // An immediate resend is throttled (< 60 s) with Retry-After.
    let early = app.post("/api/v1/auth/otp/request", None, serde_json::json!({ "email": EMAIL })).await;
    assert_eq!(early.status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(early.error_code(), "rate_limited");
    let retry_after: u64 = early.headers[header::RETRY_AFTER].to_str().unwrap().parse().unwrap();
    assert!(retry_after > 0 && retry_after <= 60, "retry-after {retry_after} out of the resend window");

    // Past the 60 s spacing the resend goes out — and kills the previous record.
    app.advance(Duration::seconds(61));
    let (second_pending, second_code) = app.request_otp(EMAIL).await;
    assert_ne!(second_pending, first_pending);

    let stale = app
        .post(
            "/api/v1/auth/otp/verify",
            None,
            serde_json::json!({ "pending_id": first_pending, "email": EMAIL, "code": first_code }),
        )
        .await;
    assert_eq!(stale.status, StatusCode::UNAUTHORIZED, "replaced record must be dead");
    assert_eq!(stale.error_code(), "invalid_code");

    let fresh = app
        .post(
            "/api/v1/auth/otp/verify",
            None,
            serde_json::json!({ "pending_id": second_pending, "email": EMAIL, "code": second_code }),
        )
        .await;
    assert_eq!(fresh.status, StatusCode::OK, "the replacement code must work: {:?}", fresh.json);
}

// --- S-04 / S-31: anti-enumeration ---

#[tokio::test]
async fn s04_unknown_email_uniform_response() {
    // Registration closed: unknown emails cannot get mail — but must be indistinguishable.
    let app = TestApp::with_options(TestOptions { allow_registration: false, ..TestOptions::default() }).await;
    app.repos
        .users
        .create(
            pub_core::user::NewUser {
                email: Some("known@corp.com".to_owned()),
                email_verified: true,
                display_name: "Known".to_owned(),
            },
            common::t0(),
        )
        .await
        .expect("seed known user");

    let known = app.post("/api/v1/auth/otp/request", None, serde_json::json!({ "email": "known@corp.com" })).await;
    assert_eq!(known.status, StatusCode::OK);
    // Delivery is off the request path now (decision 26), so the drain is where "was a mail
    // sent" becomes observable — and the negative half below stays a real assertion because of
    // it, rather than passing merely because nothing has been drained yet.
    app.drain_jobs().await;
    assert_eq!(app.mailer.sent().len(), 1, "known account receives mail");

    // S-03's 60 s resend floor is per address, so the second request needs no clock step.
    let unknown = app.post("/api/v1/auth/otp/request", None, serde_json::json!({ "email": "nobody@corp.com" })).await;
    assert_eq!(unknown.status, StatusCode::OK, "unknown email must not differ in status");
    app.drain_jobs().await;
    assert_eq!(app.mailer.sent().len(), 1, "unknown email must not receive mail");

    // Shape equality: same envelope, same data keys, a well-formed pending id either way.
    let shape = |json: &serde_json::Value| {
        (
            json["status"].as_str().map(str::to_owned),
            json["data"].as_object().map(|obj| obj.keys().cloned().collect::<Vec<_>>()),
            json["data"]["pending_id"].as_str().map(str::len),
        )
    };
    assert_eq!(shape(&known.json), shape(&unknown.json), "response shapes must be indistinguishable");
}

#[tokio::test]
async fn s31_domain_allowlist_blocks_and_stays_uniform() {
    let app = TestApp::with_options(TestOptions {
        allowed_email_domains: vec!["corp.com".to_owned()],
        ..TestOptions::default()
    })
    .await;

    // Blocked domain: uniform 200 + pending id, no mail.
    let blocked = app.post("/api/v1/auth/otp/request", None, serde_json::json!({ "email": "spy@evil.com" })).await;
    assert_eq!(blocked.status, StatusCode::OK, "rejection must stay uniform (S-04)");
    let blocked_pending = blocked.json["data"]["pending_id"].as_str().unwrap().to_owned();
    assert_eq!(blocked_pending.len(), 32);
    // The row the blocked address filed is `suppressed`: the drain runs, claims nothing of it,
    // and the outbox stays empty. That is S-31 surviving the move off the request path.
    app.drain_jobs().await;
    assert!(app.mailer.sent().is_empty(), "blocked domain must never receive mail");

    // No code exists that redeems the blocked pending record.
    let verify = app
        .post(
            "/api/v1/auth/otp/verify",
            None,
            serde_json::json!({ "pending_id": blocked_pending, "email": "spy@evil.com", "code": "12345678" }),
        )
        .await;
    assert_eq!(verify.status, StatusCode::UNAUTHORIZED);
    assert_eq!(verify.error_code(), "invalid_code");

    // The allowed domain sails through end to end.
    let login = app.login(EMAIL).await;
    assert_eq!(login["user"]["email"], EMAIL);
}

// --- S-08: refresh rotation ---

#[tokio::test]
async fn s08_refresh_rotation_and_reuse_revokes_family() {
    let app = TestApp::new().await;
    let login = app.login(EMAIL).await;
    let first_refresh = login["refresh_token"].as_str().unwrap().to_owned();

    // Rotation: a fresh pair arrives, tokens actually differ.
    let rotated = app.post("/api/v1/auth/refresh", None, serde_json::json!({ "refresh_token": first_refresh })).await;
    assert_eq!(rotated.status, StatusCode::OK);
    let second_access = rotated.json["data"]["access_token"].as_str().unwrap().to_owned();
    let second_refresh = rotated.json["data"]["refresh_token"].as_str().unwrap().to_owned();
    assert_ne!(second_refresh, first_refresh);
    assert_eq!(app.get("/api/v1/sessions", Some(&second_access)).await.status, StatusCode::OK);

    // Reuse of the rotated-out token: distinct code, family revoked (S-08).
    let reuse = app.post("/api/v1/auth/refresh", None, serde_json::json!({ "refresh_token": first_refresh })).await;
    assert_eq!(reuse.status, StatusCode::UNAUTHORIZED);
    assert_eq!(reuse.error_code(), "refresh_reused");

    // The *current* refresh token of the family is dead too…
    let after = app.post("/api/v1/auth/refresh", None, serde_json::json!({ "refresh_token": second_refresh })).await;
    assert_eq!(after.status, StatusCode::UNAUTHORIZED);
    assert_eq!(after.error_code(), "unauthorized");

    // …and the still-unexpired access token is blocklisted immediately (S-09 fast path).
    let denied = app.get("/api/v1/sessions", Some(&second_access)).await;
    assert_eq!(denied.status, StatusCode::UNAUTHORIZED);
}

// --- S-09: logout ---

#[tokio::test]
async fn s09_logout_blocklists_sid_immediately() {
    let app = TestApp::new().await;
    let login = app.login(EMAIL).await;
    let access = login["access_token"].as_str().unwrap().to_owned();
    assert_eq!(app.get("/api/v1/sessions", Some(&access)).await.status, StatusCode::OK);

    let logout = app.post_empty("/api/v1/auth/logout", Some(&access)).await;
    assert_eq!(logout.status, StatusCode::OK, "{:?}", logout.json);

    // The unexpired JWT is rejected on the very next request — no TTL grace (S-09).
    let denied = app.get("/api/v1/sessions", Some(&access)).await;
    assert_eq!(denied.status, StatusCode::UNAUTHORIZED);
    assert_eq!(denied.error_code(), "unauthorized");

    // And the refresh token is dead in the DB (durable truth).
    let refresh = login["refresh_token"].as_str().unwrap();
    let after = app.post("/api/v1/auth/refresh", None, serde_json::json!({ "refresh_token": refresh })).await;
    assert_eq!(after.status, StatusCode::UNAUTHORIZED);
}

// --- S-07: JWT hardening ---

#[tokio::test]
async fn s07_jwt_tampered_alg_and_unknown_kid_rejected() {
    let app = TestApp::new().await;
    let login = app.login(EMAIL).await;
    let access = login["access_token"].as_str().unwrap().to_owned();
    assert_eq!(app.get("/api/v1/sessions", Some(&access)).await.status, StatusCode::OK);

    let parts: Vec<&str> = access.split('.').collect();

    // alg:none with the genuine payload — with and without a signature.
    let none_header = B64URL.encode(format!(r#"{{"alg":"none","typ":"JWT","kid":"{}"}}"#, common::TEST_KID));
    for forged in [format!("{none_header}.{}.", parts[1]), format!("{none_header}.{}.{}", parts[1], parts[2])] {
        let denied = app.get("/api/v1/sessions", Some(&forged)).await;
        assert_eq!(denied.status, StatusCode::UNAUTHORIZED, "alg:none must never verify");
    }

    // A rogue key under an unknown kid, correctly signed — rejected by strict kid resolution.
    let claims: Claims = serde_json::from_slice(&B64URL.decode(parts[1]).unwrap()).unwrap();
    let rogue = Keyring::new("rogue-kid", [9u8; 32], &[]).unwrap();
    let rogue_token = rogue.sign(&claims).unwrap();
    let denied = app.get("/api/v1/sessions", Some(&rogue_token)).await;
    assert_eq!(denied.status, StatusCode::UNAUTHORIZED, "unknown kid must never verify");

    // A rogue key impersonating the real kid — signature mismatch.
    let impostor = Keyring::new(common::TEST_KID, [9u8; 32], &[]).unwrap();
    let impostor_token = impostor.sign(&claims).unwrap();
    let denied = app.get("/api/v1/sessions", Some(&impostor_token)).await;
    assert_eq!(denied.status, StatusCode::UNAUTHORIZED, "foreign signature must never verify");

    // Bit-flipped signature on the genuine token.
    let mut sig = B64URL.decode(parts[2]).unwrap();
    sig[0] ^= 0x01;
    let flipped = format!("{}.{}.{}", parts[0], parts[1], B64URL.encode(sig));
    let denied = app.get("/api/v1/sessions", Some(&flipped)).await;
    assert_eq!(denied.status, StatusCode::UNAUTHORIZED);

    // Garbage and absence.
    assert_eq!(app.get("/api/v1/sessions", Some("garbage")).await.status, StatusCode::UNAUTHORIZED);
    let anonymous = app.get("/api/v1/sessions", None).await;
    assert_eq!(anonymous.status, StatusCode::UNAUTHORIZED);
    assert_eq!(anonymous.error_code(), "unauthorized");
}

// --- S-12: CSRF-class guard ---

#[tokio::test]
async fn s12_missing_custom_header_rejected_on_mutations() {
    let app = TestApp::new().await;

    // Missing X-Pub-Request on a mutation → 403, before any handler logic.
    let request = axum::http::Request::builder()
        .method(Method::POST)
        .uri("/api/v1/auth/otp/request")
        .header(header::CONTENT_TYPE, "application/json")
        .body(axum::body::Body::from(serde_json::json!({ "email": EMAIL }).to_string()))
        .unwrap();
    let denied = app.send(request).await;
    assert_eq!(denied.status, StatusCode::FORBIDDEN);
    assert_eq!(denied.error_code(), "forbidden");
    assert!(app.mailer.sent().is_empty(), "guard must run before the flow");

    // Header present but a non-JSON content type → 415.
    let request = axum::http::Request::builder()
        .method(Method::POST)
        .uri("/api/v1/auth/otp/request")
        .header("x-pub-request", "1")
        .header(header::CONTENT_TYPE, "text/plain")
        .body(axum::body::Body::from("email=dev@corp.com"))
        .unwrap();
    let denied = app.send(request).await;
    assert_eq!(denied.status, StatusCode::UNSUPPORTED_MEDIA_TYPE);
    assert_eq!(denied.error_code(), "unsupported_media_type");

    // GET requests need neither.
    let request =
        axum::http::Request::builder().method(Method::GET).uri("/healthz").body(axum::body::Body::empty()).unwrap();
    assert_eq!(app.send(request).await.status, StatusCode::OK);
}

// --- S-13: CLI tokens ---

/// Logs in, creates an org, returns `(access_token, org_id)`.
async fn login_with_org(app: &TestApp) -> (String, String) {
    let login = app.login(EMAIL).await;
    let access = login["access_token"].as_str().unwrap().to_owned();
    let org = app.post("/api/v1/orgs", Some(&access), serde_json::json!({ "name": "Acme", "slug": "acme" })).await;
    assert_eq!(org.status, StatusCode::OK, "{:?}", org.json);
    let org_id = org.json["data"]["id"].as_str().unwrap().to_owned();
    (access, org_id)
}

#[tokio::test]
async fn s13_token_show_once_sha256_at_rest_crc_offline_validation() {
    let app = TestApp::new().await;
    let (access, org_id) = login_with_org(&app).await;

    let created = app
        .post(
            "/api/v1/tokens",
            Some(&access),
            serde_json::json!({ "label": "ci", "org_id": org_id, "scopes": ["read", "publish"] }),
        )
        .await;
    assert_eq!(created.status, StatusCode::OK, "{:?}", created.json);
    let secret = created.json["data"]["secret"].as_str().unwrap().to_owned();
    let hint = created.json["data"]["token"]["display_hint"].as_str().unwrap().to_owned();

    // Format: pub_ + 30 base62 + 6-char CRC32; the hint is the first 8 chars.
    assert!(secret.starts_with("pub_"));
    assert_eq!(secret.len(), 40);
    assert_eq!(hint, secret[..8], "display hint is the first 8 chars");
    cli_token::validate(&secret, "pub_").expect("fresh secret must validate offline");

    // Offline CRC validation rejects tampering — no DB, no oracle.
    let mut tampered = secret.clone().into_bytes();
    let last = tampered.last_mut().unwrap();
    *last = if *last == b'0' { b'1' } else { b'0' };
    assert!(cli_token::validate(&String::from_utf8(tampered).unwrap(), "pub_").is_err());

    // At rest: SHA-256 only — the repo finds the token by hash and stores no plaintext.
    let stored = app
        .repos
        .tokens
        .find_active_by_hash(&cli_token::sha256_hex(&secret), app.now())
        .await
        .expect("lookup")
        .expect("token stored under its sha256");
    assert_eq!(stored.name, "ci");
    assert_eq!(stored.display_hint, hint);
    let expires_at = stored.expires_at.expect("default expiry applies");
    assert_eq!(expires_at, app.now() + Duration::days(90), "S-13 default expiry is 90 days");

    // Show-once: the listing never carries the secret again.
    let listing = app.get("/api/v1/tokens", Some(&access)).await;
    assert_eq!(listing.status, StatusCode::OK);
    assert_eq!(listing.json["data"]["items"].as_array().unwrap().len(), 1);
    assert_eq!(listing.json["data"]["items"][0]["display_hint"], hint);
    assert!(!listing.json.to_string().contains(&secret), "secret leaked into the token list");
}

#[tokio::test]
async fn s13_revoked_token_gone() {
    let app = TestApp::new().await;
    let (access, org_id) = login_with_org(&app).await;

    let created =
        app.post("/api/v1/tokens", Some(&access), serde_json::json!({ "org_id": org_id, "scopes": ["read"] })).await;
    let secret = created.json["data"]["secret"].as_str().unwrap().to_owned();
    let token_id = created.json["data"]["token"]["id"].as_str().unwrap().to_owned();

    let revoked = app.delete(&format!("/api/v1/tokens/{token_id}"), Some(&access)).await;
    assert_eq!(revoked.status, StatusCode::OK, "{:?}", revoked.json);

    // Auth by hash fails immediately; the listing no longer shows it.
    let lookup = app.repos.tokens.find_active_by_hash(&cli_token::sha256_hex(&secret), app.now()).await.unwrap();
    assert!(lookup.is_none(), "revoked token must vanish from the active lookup");
    let listing = app.get("/api/v1/tokens", Some(&access)).await;
    assert_eq!(listing.json["data"]["items"].as_array().unwrap().len(), 0);

    // Revoking it again (or any unknown id) is a uniform 404.
    let again = app.delete(&format!("/api/v1/tokens/{token_id}"), Some(&access)).await;
    assert_eq!(again.status, StatusCode::NOT_FOUND);
}

// --- S-24: rate limits ---

#[tokio::test]
async fn s24_otp_request_rate_limit_429_retry_after() {
    let app = TestApp::new().await;

    // Per-email: 5/h. Space the requests past the resend throttle to isolate the hourly cap.
    for i in 1..=5 {
        let response = app.post("/api/v1/auth/otp/request", None, serde_json::json!({ "email": EMAIL })).await;
        assert_eq!(response.status, StatusCode::OK, "request {i} within the cap");
        app.advance(Duration::seconds(61));
    }
    let sixth = app.post("/api/v1/auth/otp/request", None, serde_json::json!({ "email": EMAIL })).await;
    assert_eq!(sixth.status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(sixth.error_code(), "rate_limited");
    let retry_after: u64 = sixth.headers[header::RETRY_AFTER].to_str().unwrap().parse().unwrap();
    assert!(retry_after > 0 && retry_after <= 3600, "retry-after {retry_after} outside the hourly window");

    // Per-IP: 20/h across different emails from one fresh address (the per-email loop above
    // ran from DEFAULT_IP and does not count here).
    let ip = "198.51.100.9";
    for i in 0..20 {
        let body = serde_json::json!({ "email": format!("user{i}@corp.com") });
        let request = app.request(Method::POST, "/api/v1/auth/otp/request", None, Some(body), ip);
        let response = app.send(request).await;
        assert_eq!(response.status, StatusCode::OK, "ip request {i} within the cap");
    }
    let body = serde_json::json!({ "email": "straw@corp.com" });
    let over = app.send(app.request(Method::POST, "/api/v1/auth/otp/request", None, Some(body), ip)).await;
    assert_eq!(over.status, StatusCode::TOO_MANY_REQUESTS, "21st request from one IP must trip S-24");
    assert!(over.headers.contains_key(header::RETRY_AFTER));
}

// --- session management + orgs happy paths ---

#[tokio::test]
async fn sessions_list_current_flag_revoke_one_and_revoke_all() {
    let app = TestApp::new().await;
    let first = app.login(EMAIL).await;
    let first_access = first["access_token"].as_str().unwrap().to_owned();
    let first_sid = first["session_id"].as_str().unwrap().to_owned();

    app.advance(Duration::seconds(61)); // past the resend throttle
    let second = app.login(EMAIL).await;
    let second_access = second["access_token"].as_str().unwrap().to_owned();
    let second_sid = second["session_id"].as_str().unwrap().to_owned();

    // List through the second session: both rows, current flag exactly on the caller.
    let listing = app.get("/api/v1/sessions", Some(&second_access)).await;
    assert_eq!(listing.status, StatusCode::OK);
    let items = listing.json["data"]["items"].as_array().unwrap().clone();
    assert_eq!(items.len(), 2);
    let current: Vec<&str> = items.iter().filter(|s| s["current"] == true).map(|s| s["id"].as_str().unwrap()).collect();
    assert_eq!(current, vec![second_sid.as_str()], "exactly the calling session is current");
    assert!(items.iter().any(|s| s["id"] == first_sid.as_str()));
    assert!(items.iter().all(|s| s["ip"].is_string() && s["user_agent"].is_string()), "S-10 metadata present");

    // Foreign/unknown sid → uniform 404.
    let bogus = app.delete(&format!("/api/v1/sessions/{}", pub_core::SessionId::new()), Some(&second_access)).await;
    assert_eq!(bogus.status, StatusCode::NOT_FOUND);

    // Revoke the first session from the second one; the first access token dies instantly.
    let revoked = app.delete(&format!("/api/v1/sessions/{first_sid}"), Some(&second_access)).await;
    assert_eq!(revoked.status, StatusCode::OK);
    assert_eq!(app.get("/api/v1/sessions", Some(&first_access)).await.status, StatusCode::UNAUTHORIZED);

    // Revoke-all kills the caller too.
    let all = app.post_empty("/api/v1/sessions/revoke-all", Some(&second_access)).await;
    assert_eq!(all.status, StatusCode::OK);
    assert_eq!(all.json["data"]["revoked"], 1, "one live session remained");
    assert_eq!(app.get("/api/v1/sessions", Some(&second_access)).await.status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn orgs_create_and_list_happy_path() {
    let app = TestApp::new().await;
    let login = app.login(EMAIL).await;
    let access = login["access_token"].as_str().unwrap().to_owned();

    let created = app.post("/api/v1/orgs", Some(&access), serde_json::json!({ "name": "Acme", "slug": "Acme" })).await;
    assert_eq!(created.status, StatusCode::OK, "{:?}", created.json);
    assert_eq!(created.json["data"]["slug"], "acme", "slug is normalized to lowercase");

    // Duplicate slug conflicts.
    let dup = app.post("/api/v1/orgs", Some(&access), serde_json::json!({ "name": "Other", "slug": "acme" })).await;
    assert_eq!(dup.status, StatusCode::CONFLICT);
    assert_eq!(dup.error_code(), "conflict");

    // Bad slug is invalid.
    let bad = app.post("/api/v1/orgs", Some(&access), serde_json::json!({ "name": "X", "slug": "-x-" })).await;
    assert_eq!(bad.status, StatusCode::BAD_REQUEST);

    // The creator shows up as owner (decision 19: names on the wire).
    let listing = app.get("/api/v1/orgs", Some(&access)).await;
    assert_eq!(listing.status, StatusCode::OK);
    let items = listing.json["data"]["items"].as_array().unwrap();
    assert_eq!(items.len(), 1);
    assert_eq!(items[0]["org"]["slug"], "acme");
    assert_eq!(items[0]["role"], "owner");

    // Anonymous listing is rejected.
    assert_eq!(app.get("/api/v1/orgs", None).await.status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn token_scopes_are_gated_by_org_role() {
    // A Read member cannot mint a publish token (decision 19 chokepoint behind S-13).
    let app = TestApp::new().await;
    let (owner_access, org_id) = login_with_org(&app).await;

    // Second user joins with Read via direct repo access.
    app.advance(Duration::seconds(61));
    let member_login = app.login("reader@corp.com").await;
    let member_access = member_login["access_token"].as_str().unwrap().to_owned();
    let member_id: pub_core::UserId = member_login["user"]["id"].as_str().unwrap().parse().unwrap();
    let org: pub_core::OrgId = org_id.parse().unwrap();
    app.repos.orgs.add_member(org, member_id, pub_core::RoleLevel::READ, app.now()).await.expect("add member");

    let denied = app
        .post("/api/v1/tokens", Some(&member_access), serde_json::json!({ "org_id": org_id, "scopes": ["publish"] }))
        .await;
    assert_eq!(denied.status, StatusCode::FORBIDDEN, "read member must not mint publish tokens");

    let allowed = app
        .post("/api/v1/tokens", Some(&member_access), serde_json::json!({ "org_id": org_id, "scopes": ["read"] }))
        .await;
    assert_eq!(allowed.status, StatusCode::OK, "{:?}", allowed.json);

    // A non-member cannot even see the org: uniform 404 (S-04).
    app.advance(Duration::seconds(61));
    let outsider_login = app.login("outsider@corp.com").await;
    let outsider_access = outsider_login["access_token"].as_str().unwrap().to_owned();
    let invisible = app
        .post("/api/v1/tokens", Some(&outsider_access), serde_json::json!({ "org_id": org_id, "scopes": ["read"] }))
        .await;
    assert_eq!(invisible.status, StatusCode::NOT_FOUND);
    let _ = owner_access;
}

// --- D20 / S-04.a: the SMTP oracle after delivery moved onto the queue (decision 26) ---

/// **D20.** With the relay down, an accepted address used to answer **500** while a
/// policy-blocked one answered 200 instantly — an existence oracle you could trigger by taking
/// the mail server off the network, no timing needed. Delivery is not part of the response any
/// more, so there is nothing left for SMTP to fail.
#[tokio::test]
async fn d20_otp_request_answers_200_when_the_mailer_is_down() {
    let app =
        TestApp::with_options(TestOptions { smtp_host: Some("smtp.corp.test".to_owned()), ..TestOptions::default() })
            .await;
    // Every transport this instance builds from now on refuses everything, the way a dead relay
    // or a wrong credential does.
    app.smtp_builds.fail_deliveries(true);

    let response = app.post("/api/v1/auth/otp/request", None, serde_json::json!({ "email": EMAIL })).await;
    assert_eq!(response.status, StatusCode::OK, "an SMTP outage must not fail a sign-in: {:?}", response.json);
    assert_eq!(response.json["data"]["pending_id"].as_str().expect("pending_id").len(), 32);

    // The message is filed rather than lost: the drain tries, fails, and re-arms it.
    let report = app.drain_jobs().await;
    assert_eq!(report.retried, 1, "a refused delivery is transient and stays in the queue");
    assert_eq!(report.dead, 0);
    assert!(app.mailer.sent().is_empty(), "nothing was delivered — but the caller never learned that");
}

/// **S-04.a.** Both branches file exactly one row, of the same kind, differing only in state:
/// `pending` for an address that may receive a code, `suppressed` for one that may not.
#[tokio::test]
async fn s04a_accepted_and_rejected_addresses_do_identical_work() {
    let app = TestApp::with_options(TestOptions {
        allowed_email_domains: vec!["corp.com".to_owned()],
        ..TestOptions::default()
    })
    .await;

    let accepted = app.post("/api/v1/auth/otp/request", None, serde_json::json!({ "email": EMAIL })).await;
    let rejected = app.post("/api/v1/auth/otp/request", None, serde_json::json!({ "email": "spy@evil.com" })).await;
    assert_eq!(accepted.status, StatusCode::OK);
    assert_eq!(rejected.status, StatusCode::OK);
    let shape = |json: &serde_json::Value| {
        (
            json["status"].as_str().map(str::to_owned),
            json["data"].as_object().map(|obj| obj.keys().cloned().collect::<Vec<_>>()),
            json["data"]["pending_id"].as_str().map(str::len),
        )
    };
    assert_eq!(shape(&accepted.json), shape(&rejected.json), "response shapes must be indistinguishable");

    let mut depth = app.repos.queue.depth().await.expect("queue depth");
    depth.sort();
    assert_eq!(
        depth,
        vec![
            (pub_core::queue::JobKind::MailSend, pub_core::queue::QueueState::Pending, 1),
            (pub_core::queue::JobKind::MailSend, pub_core::queue::QueueState::Suppressed, 1),
        ],
        "one row each, same kind, differing only in state — nothing else about the two requests differs"
    );
}

/// **S-31.** A suppressed row is a dead end: the drain never claims it, so a blocked address
/// cannot be talked into a redeemable code by anything the worker does later — and it does not
/// live forever either (decision 26). This endpoint is unauthenticated and every row it files carries
/// the address somebody typed at a login form, so "kept until the operator notices" is the
/// wrong answer: nothing reads one after the request that filed it, and decision 26 promises
/// the queue does not become the next unbounded table.
#[tokio::test]
async fn s31_a_blocked_address_row_is_never_claimed_and_does_not_live_forever() {
    let app = TestApp::with_options(TestOptions {
        allowed_email_domains: vec!["corp.com".to_owned()],
        ..TestOptions::default()
    })
    .await;
    app.post("/api/v1/auth/otp/request", None, serde_json::json!({ "email": "spy@evil.com" })).await;

    let report = app.drain_jobs().await;
    assert_eq!(report.claimed, 0, "a suppressed row must never be handed to a worker");
    assert!(app.mailer.sent().is_empty(), "and therefore must never produce a message");

    // Inside its retention window it is still exactly where it was, and still unclaimable.
    app.advance(Duration::minutes(30));
    assert_eq!(app.drain_jobs().await.claimed, 0);
    assert_eq!(
        app.repos.queue.depth().await.expect("queue depth"),
        vec![(pub_core::queue::JobKind::MailSend, pub_core::queue::QueueState::Suppressed, 1)]
    );

    // Past it, retention takes it: the only thing it ever had to do — make a rejected request
    // cost what an accepted one costs — was done the moment the request returned.
    app.advance(Duration::hours(2));
    let report = app.drain_jobs().await;
    assert_eq!(report.claimed, 0, "it is not claimed on the way out either");
    assert_eq!(report.purged, 1);
    assert!(app.repos.queue.depth().await.expect("queue depth").is_empty());
    assert!(app.mailer.sent().is_empty());
}

/// **S-03.** The queue's latency cannot extend a code's life: the KV pending-auth record's own
/// `created_at` is the authority on expiry, and single use is decided at redemption.
#[tokio::test]
async fn s03_a_queued_code_is_still_single_use_and_still_expires() {
    let app = TestApp::new().await;
    let (pending_id, code) = app.request_otp(EMAIL).await;
    let verify = serde_json::json!({ "pending_id": pending_id, "email": EMAIL, "code": code });
    assert_eq!(app.post("/api/v1/auth/otp/verify", None, verify.clone()).await.status, StatusCode::OK);
    let replay = app.post("/api/v1/auth/otp/verify", None, verify).await;
    assert_eq!(replay.status, StatusCode::UNAUTHORIZED, "a delivered code is still single use");
    assert_eq!(replay.error_code(), "invalid_code");

    // A message that sits in the queue past the code's life is delivered late and is already
    // dead on arrival — the clock never restarted.
    app.advance(Duration::seconds(61));
    let late = "late@corp.com";
    let response = app.post("/api/v1/auth/otp/request", None, serde_json::json!({ "email": late })).await;
    let late_pending = response.json["data"]["pending_id"].as_str().expect("pending_id").to_owned();
    app.advance(Duration::minutes(11));
    app.drain_jobs().await;
    let late_code = common::extract_code(&app.mailer.sent().pop().expect("the late message").text);
    let expired = app
        .post(
            "/api/v1/auth/otp/verify",
            None,
            serde_json::json!({ "pending_id": late_pending, "email": late, "code": late_code }),
        )
        .await;
    assert_eq!(expired.status, StatusCode::UNAUTHORIZED, "queue latency must not extend a code's life");
    assert_eq!(expired.error_code(), "invalid_code");
}
