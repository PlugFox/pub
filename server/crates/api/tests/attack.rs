//! Adversarial suite: each test is an attack against the auth slice, named for the S-xx
//! clause it tries to break (docs/rules/rust.md). These are deliberately written from the
//! attacker's side — "can I get in / can I get more budget / can I make the server tell me
//! something it shouldn't" — rather than as happy-path assertions.

mod common;

use std::sync::Arc;
use std::time::Duration as StdDuration;

use axum::body::Body;
use axum::http::{Method, Request, StatusCode, header};
use chrono::Duration;
use common::{ApiResponse, DEFAULT_IP, FailingKv, INSTANCE_ORIGIN, TestApp, TestOptions, wrong_code};
use pub_auth::jwt::{Claims, Keyring};
use pub_auth::otp;
use pub_auth::token as cli_token;
use pub_core::traits::Kv as _;

const EMAIL: &str = "dev@corp.com";

// --- S-03: the wrong-attempt budget cannot be stretched ---

/// Two parallel wrong codes must cost two attempts. Under a get-modify-set counter both
/// requests read the same value and write the same increment, so a burst of guesses costs one
/// attempt and the ≤5 budget stops bounding anything.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn s03_parallel_wrong_codes_each_spend_an_attempt() {
    let app = TestApp::with_options(TestOptions { login_per_ip_minute: 100, ..TestOptions::default() }).await;
    let (pending_id, code) = app.request_otp(EMAIL).await;
    let bad = wrong_code(&code);

    let burst: Vec<Request<Body>> = (0..2)
        .map(|_| {
            let body = serde_json::json!({ "pending_id": pending_id, "email": EMAIL, "code": bad });
            app.request(Method::POST, "/api/v1/auth/otp/verify", None, Some(body), DEFAULT_IP)
        })
        .collect();
    for response in app.send_concurrent(burst).await {
        assert_eq!(response.status, StatusCode::UNAUTHORIZED);
    }

    let spent = app.kv_get(&otp::attempt_key(&pending_id)).await.expect("attempt counter exists");
    assert_eq!(spent, "2", "two parallel wrong codes must cost two attempts, not one");
}

/// The same in bulk: 5 concurrent guesses exhaust the budget outright, so the genuine code is
/// dead afterwards — the attacker bought nothing by parallelising.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn s03_concurrent_burst_exhausts_the_budget_and_kills_the_code() {
    let app = TestApp::with_options(TestOptions { login_per_ip_minute: 100, ..TestOptions::default() }).await;
    let (pending_id, code) = app.request_otp(EMAIL).await;
    let bad = wrong_code(&code);

    let burst: Vec<Request<Body>> = (0..otp::MAX_ATTEMPTS)
        .map(|_| {
            let body = serde_json::json!({ "pending_id": pending_id, "email": EMAIL, "code": bad });
            app.request(Method::POST, "/api/v1/auth/otp/verify", None, Some(body), DEFAULT_IP)
        })
        .collect();
    app.send_concurrent(burst).await;

    let real = app
        .post(
            "/api/v1/auth/otp/verify",
            None,
            serde_json::json!({ "pending_id": pending_id, "email": EMAIL, "code": code }),
        )
        .await;
    assert_eq!(real.status, StatusCode::UNAUTHORIZED, "budget spent, the code must be dead");
    assert_eq!(real.error_code(), "invalid_code");
}

/// A resend must not hand the attacker a fresh budget on the *old* pending id: the previous
/// record is destroyed, so the old handle cannot be replayed at all.
#[tokio::test]
async fn s03_resend_cannot_rewind_the_attempt_budget_of_the_old_pending_id() {
    let app = TestApp::new().await;
    let (first_pending, first_code) = app.request_otp(EMAIL).await;
    let bad = wrong_code(&first_code);

    // Burn 4 of the 5 attempts on the first record.
    for _ in 0..4 {
        let body = serde_json::json!({ "pending_id": first_pending, "email": EMAIL, "code": bad });
        assert_eq!(app.post("/api/v1/auth/otp/verify", None, body).await.status, StatusCode::UNAUTHORIZED);
    }

    // Resend, then come back to the OLD handle: it must be gone, not reset.
    app.advance(Duration::seconds(61));
    let (second_pending, _) = app.request_otp(EMAIL).await;
    assert_ne!(second_pending, first_pending);
    assert!(app.kv_get(&otp::pending_key(&first_pending)).await.is_none(), "resend must destroy the prior record");

    let replay = app
        .post(
            "/api/v1/auth/otp/verify",
            None,
            serde_json::json!({ "pending_id": first_pending, "email": EMAIL, "code": first_code }),
        )
        .await;
    assert_eq!(replay.status, StatusCode::UNAUTHORIZED);
    assert_eq!(replay.error_code(), "invalid_code");
}

/// The 10-minute expiry is enforced by the record's own timestamp, not merely by the KV TTL:
/// a KV whose eviction lags must not extend a code's life.
#[tokio::test]
async fn s03_code_expires_after_ten_minutes_even_if_the_kv_entry_survives() {
    let app = TestApp::new().await;
    let (pending_id, code) = app.request_otp(EMAIL).await;

    // Re-write the record with a long TTL: the KV would happily keep serving it.
    let raw = app.kv_get(&otp::pending_key(&pending_id)).await.expect("record present");
    app.kv.set_ttl(&otp::pending_key(&pending_id), &raw, StdDuration::from_secs(86_400)).await.unwrap();

    app.advance(otp::PENDING_TTL);
    let expired = app
        .post(
            "/api/v1/auth/otp/verify",
            None,
            serde_json::json!({ "pending_id": pending_id, "email": EMAIL, "code": code }),
        )
        .await;
    assert_eq!(expired.status, StatusCode::UNAUTHORIZED, "expiry is decided by created_at, not the KV TTL");
    assert_eq!(expired.error_code(), "invalid_code");
}

/// Exhausting a code kills the code, never the account (S-03 anti-lockout, S-24).
#[tokio::test]
async fn s03_exhausted_code_does_not_lock_the_account() {
    let app = TestApp::new().await;
    let (pending_id, code) = app.request_otp(EMAIL).await;
    let bad = wrong_code(&code);
    for _ in 0..otp::MAX_ATTEMPTS {
        let body = serde_json::json!({ "pending_id": pending_id, "email": EMAIL, "code": bad });
        app.post("/api/v1/auth/otp/verify", None, body).await;
    }

    // A fresh code for the same address still works end to end.
    app.advance(Duration::seconds(61));
    let login = app.login(EMAIL).await;
    assert_eq!(login["user"]["email"], EMAIL);
}

/// The code must not be recoverable from anything the server stores or returns: not the
/// pending record, not the failure body, not the success body (S-03/S-22).
#[tokio::test]
async fn s03_code_never_leaks_into_storage_or_responses() {
    let app = TestApp::new().await;
    let (pending_id, code) = app.request_otp(EMAIL).await;

    let record = app.kv_get(&otp::pending_key(&pending_id)).await.expect("record present");
    assert!(!record.contains(&code), "code stored in clear: {record}");

    let failed = app
        .post(
            "/api/v1/auth/otp/verify",
            None,
            serde_json::json!({ "pending_id": pending_id, "email": EMAIL, "code": wrong_code(&code) }),
        )
        .await;
    assert!(!failed.json.to_string().contains(&code), "failure body leaked the code: {}", failed.json);

    let success = app
        .post(
            "/api/v1/auth/otp/verify",
            None,
            serde_json::json!({ "pending_id": pending_id, "email": EMAIL, "code": code }),
        )
        .await;
    assert_eq!(success.status, StatusCode::OK);
    assert!(!success.json.to_string().contains(&code), "success body echoed the code");
}

// --- S-07/S-09: forged and revoked access tokens ---

/// Algorithm confusion at the HTTP boundary: an `HS256` token whose MAC key is the Ed25519
/// public key, plus `alg: none`, plus an unknown `kid`. All three are the same 401.
#[tokio::test]
async fn s07_forged_access_tokens_are_all_rejected_at_the_boundary() {
    use base64::Engine as _;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
    use hmac::{Hmac, Mac as _};
    use sha2::Sha256;

    let app = TestApp::new().await;
    let login = app.login(EMAIL).await;
    let genuine = login["access_token"].as_str().unwrap().to_owned();
    let payload = genuine.split('.').nth(1).unwrap().to_owned();

    let public = Keyring::new(common::TEST_KID, common::TEST_JWT_SEED, &[]).unwrap();
    let public_bytes = ed25519_public_bytes(common::TEST_JWT_SEED);

    // 1. HS256 signed with the verification key material.
    let hs_header = B64URL.encode(format!(r#"{{"alg":"HS256","typ":"JWT","kid":"{}"}}"#, common::TEST_KID));
    let signing_input = format!("{hs_header}.{payload}");
    let mut mac = Hmac::<Sha256>::new_from_slice(&public_bytes).unwrap();
    mac.update(signing_input.as_bytes());
    let hs_token = format!("{signing_input}.{}", B64URL.encode(mac.finalize().into_bytes()));

    // 2. alg:none, unsigned.
    let none_header = B64URL.encode(format!(r#"{{"alg":"none","typ":"JWT","kid":"{}"}}"#, common::TEST_KID));
    let none_token = format!("{none_header}.{payload}.");

    // 3. A correctly signed token under a kid the boot keyring never had.
    let claims: Claims = serde_json::from_slice(&B64URL.decode(&payload).unwrap()).unwrap();
    let stranger = Keyring::new("kid-from-another-instance", [3u8; 32], &[]).unwrap();
    let unknown_kid = stranger.sign(&claims).unwrap();

    for (label, forged) in [("hs256-with-public-key", hs_token), ("alg-none", none_token), ("unknown-kid", unknown_kid)]
    {
        let denied = app.get("/api/v1/sessions", Some(&forged)).await;
        assert_eq!(denied.status, StatusCode::UNAUTHORIZED, "{label} was accepted");
        assert_eq!(denied.error_code(), "unauthorized", "{label} answered with a distinguishable code");
    }

    // Sanity: the genuine token from the same keyring still works, so the suite is not
    // passing because every request happens to fail.
    assert!(public.verify(&genuine, app.now()).is_ok());
    assert_eq!(app.get("/api/v1/sessions", Some(&genuine)).await.status, StatusCode::OK);
}

/// The revoked-`sid` fast path must **fail closed**: when the KV is unreachable the server
/// rejects rather than assuming the session is live (S-09). With the in-memory KV nothing ever
/// fails, so this is the only test that reaches the fallback.
#[tokio::test]
async fn s09_kv_outage_fails_closed_on_the_access_token_path() {
    let app = TestApp::with_options(TestOptions { kv: Some(Arc::new(FailingKv)), ..TestOptions::default() }).await;

    // A perfectly valid token signed by the instance's own keyring.
    let keyring = Keyring::new(common::TEST_KID, common::TEST_JWT_SEED, &[]).unwrap();
    let now = app.now();
    let claims = Claims {
        sub: pub_core::UserId::new(),
        sid: pub_core::SessionId::new(),
        orgs: std::collections::BTreeMap::new(),
        iat: now.timestamp(),
        exp: (now + Duration::minutes(15)).timestamp(),
    };
    let token = keyring.sign(&claims).unwrap();

    let denied = app.get("/api/v1/sessions", Some(&token)).await;
    assert_eq!(denied.status, StatusCode::SERVICE_UNAVAILABLE, "an unverifiable revocation check must not pass");
    assert_eq!(denied.error_code(), "kv_error");
}

/// Auth-abuse rate limiting fails closed too (S-24): a KV outage must not become an open door
/// on the OTP endpoint, and no mail may go out.
#[tokio::test]
async fn s24_kv_outage_fails_closed_on_the_otp_endpoint() {
    let app = TestApp::with_options(TestOptions { kv: Some(Arc::new(FailingKv)), ..TestOptions::default() }).await;
    let denied = app.post("/api/v1/auth/otp/request", None, serde_json::json!({ "email": EMAIL })).await;
    assert_eq!(denied.status, StatusCode::SERVICE_UNAVAILABLE);
    assert!(app.mailer.sent().is_empty(), "a KV outage must not turn into an unmetered mail relay");
}

// --- S-08: refresh rotation under concurrency ---

/// Two concurrent refreshes of the same token: exactly one may win, and the loser must fail
/// loudly. A silent second success would mean two live refresh chains from one theft.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn s08_concurrent_refresh_has_exactly_one_winner() {
    let app = TestApp::with_options(TestOptions { login_per_ip_minute: 100, ..TestOptions::default() }).await;
    let login = app.login(EMAIL).await;
    let refresh_token = login["refresh_token"].as_str().unwrap().to_owned();

    let race: Vec<Request<Body>> = (0..2)
        .map(|_| {
            let body = serde_json::json!({ "refresh_token": refresh_token });
            app.request(Method::POST, "/api/v1/auth/refresh", None, Some(body), DEFAULT_IP)
        })
        .collect();
    let responses = app.send_concurrent(race).await;

    let winners: Vec<&ApiResponse> = responses.iter().filter(|r| r.status == StatusCode::OK).collect();
    assert_eq!(winners.len(), 1, "exactly one rotation may succeed");
    let losers: Vec<&ApiResponse> = responses.iter().filter(|r| r.status != StatusCode::OK).collect();
    assert_eq!(losers.len(), 1);
    assert_eq!(losers[0].status, StatusCode::UNAUTHORIZED, "the loser must be rejected, never silently accepted");
    assert!(
        matches!(losers[0].error_code(), "refresh_reused" | "unauthorized"),
        "unexpected loser code: {}",
        losers[0].error_code()
    );
}

/// Reuse detection must revoke the family in **both** stores: the DB row (durable truth) and
/// the KV blocklist (fast path), so a still-unexpired access token dies immediately rather
/// than at the end of its TTL.
#[tokio::test]
async fn s08_reuse_detection_revokes_in_db_and_kv_immediately() {
    let app = TestApp::new().await;
    let login = app.login(EMAIL).await;
    let first_refresh = login["refresh_token"].as_str().unwrap().to_owned();
    let sid: pub_core::SessionId = login["session_id"].as_str().unwrap().parse().unwrap();
    let user_id: pub_core::UserId = login["user"]["id"].as_str().unwrap().parse().unwrap();

    let rotated = app.post("/api/v1/auth/refresh", None, serde_json::json!({ "refresh_token": first_refresh })).await;
    let live_access = rotated.json["data"]["access_token"].as_str().unwrap().to_owned();
    assert_eq!(app.get("/api/v1/sessions", Some(&live_access)).await.status, StatusCode::OK);

    // Replay the rotated-out token — the theft signal.
    let reuse = app.post("/api/v1/auth/refresh", None, serde_json::json!({ "refresh_token": first_refresh })).await;
    assert_eq!(reuse.error_code(), "refresh_reused");

    // Durable truth: no live session row remains.
    let live = app.repos.sessions.list_for_user(user_id).await.unwrap();
    assert!(live.is_empty(), "the family must be revoked in the database");

    // Fast path: the sid is blocklisted right now, not one access TTL from now.
    assert!(
        app.kv_get(&format!("session:revoked:{sid}")).await.is_some(),
        "the revoked sid must be on the KV blocklist"
    );
    let denied = app.get("/api/v1/sessions", Some(&live_access)).await;
    assert_eq!(denied.status, StatusCode::UNAUTHORIZED, "the unexpired access token must die immediately");
}

/// The refresh plaintext is a bearer credential: it must exist only in the response body.
/// Storage is keyed by its SHA-256, and the domain session carries nothing that reveals it.
#[tokio::test]
async fn s08_refresh_plaintext_is_never_persisted() {
    let app = TestApp::new().await;
    let login = app.login(EMAIL).await;
    let secret = login["refresh_token"].as_str().unwrap().to_owned();
    let user_id: pub_core::UserId = login["user"]["id"].as_str().unwrap().parse().unwrap();
    let limits = pub_core::session::SessionLimits::DEFAULT;

    // ≥128 bits of CSPRNG entropy (32 bytes, base64url) — S-08.
    assert!(secret.len() >= 43, "refresh secret is only {} chars", secret.len());

    // Looking up by the plaintext finds nothing; looking up by its hash finds the session.
    assert!(app.repos.sessions.find_by_refresh_hash(&secret, &limits, app.now()).await.unwrap().is_none());
    let found = app
        .repos
        .sessions
        .find_by_refresh_hash(&cli_token::sha256_hex(&secret), &limits, app.now())
        .await
        .unwrap()
        .expect("session stored under the hash");
    assert_eq!(found.user_id, user_id);

    // Nothing readable back out of the session list carries it either.
    let listing = app.get("/api/v1/sessions", Some(login["access_token"].as_str().unwrap())).await;
    assert!(!listing.json.to_string().contains(&secret), "refresh token surfaced in the session list");
}

// --- S-13: token scopes cannot outrun the org role ---

/// A Write-level member may mint publish tokens but not an `admin`-scoped one: the scope→role
/// mapping runs through `authorize()` for *every* requested scope, so smuggling `admin` in
/// alongside a permitted scope must fail the whole mint.
#[tokio::test]
async fn s13_admin_scope_requires_admin_role_even_when_bundled() {
    let app = TestApp::new().await;
    let owner = app.login(EMAIL).await;
    let owner_access = owner["access_token"].as_str().unwrap().to_owned();
    let org =
        app.post("/api/v1/orgs", Some(&owner_access), serde_json::json!({ "name": "Acme", "slug": "acme" })).await;
    let org_id = org.json["data"]["id"].as_str().unwrap().to_owned();

    app.advance(Duration::seconds(61));
    let writer = app.login("writer@corp.com").await;
    let writer_access = writer["access_token"].as_str().unwrap().to_owned();
    let writer_id: pub_core::UserId = writer["user"]["id"].as_str().unwrap().parse().unwrap();
    app.repos
        .orgs
        .add_member(org_id.parse().unwrap(), writer_id, pub_core::RoleLevel::WRITE, app.now())
        .await
        .expect("add writer");

    // Permitted on its own…
    let publish = app
        .post("/api/v1/tokens", Some(&writer_access), serde_json::json!({ "org_id": org_id, "scopes": ["publish"] }))
        .await;
    assert_eq!(publish.status, StatusCode::OK, "{:?}", publish.json);

    // …but `admin` demands Admin, alone or smuggled next to a permitted scope.
    for scopes in [serde_json::json!(["admin"]), serde_json::json!(["read", "admin"])] {
        let denied = app
            .post("/api/v1/tokens", Some(&writer_access), serde_json::json!({ "org_id": org_id, "scopes": scopes }))
            .await;
        assert_eq!(denied.status, StatusCode::FORBIDDEN, "write member minted {scopes:?}");
    }

    // And nothing was created behind the denial.
    let listing = app.get("/api/v1/tokens", Some(&writer_access)).await;
    assert_eq!(listing.json["data"]["items"].as_array().unwrap().len(), 1, "a denied mint must not persist a token");
}

// --- S-24: rate-limit identity cannot be forged ---

/// The per-email bucket is keyed on the *normalized* address, so casing variants share one
/// budget instead of each getting a fresh five.
#[tokio::test]
async fn s24_email_bucket_is_case_folded() {
    let app = TestApp::new().await;
    for (index, variant) in
        ["dev@corp.com", "Dev@corp.com", "DEV@CORP.COM", "dEv@CoRp.CoM", "dev@Corp.Com"].into_iter().enumerate()
    {
        let response = app.post("/api/v1/auth/otp/request", None, serde_json::json!({ "email": variant })).await;
        assert_eq!(response.status, StatusCode::OK, "request {index} ({variant}) within the cap");
        app.advance(Duration::seconds(61));
    }
    let sixth = app.post("/api/v1/auth/otp/request", None, serde_json::json!({ "email": "DeV@corp.com" })).await;
    assert_eq!(sixth.status, StatusCode::TOO_MANY_REQUESTS, "case variants must share one per-email bucket");
}

/// `Retry-After` must be the real remainder of the fixed window, not a constant: a client that
/// obeys it retries exactly when the budget is back.
#[tokio::test]
async fn s24_retry_after_matches_the_real_window_remainder() {
    let app = TestApp::new().await;
    // Five requests, 61 s apart: the hourly window is anchored at the first one.
    let mut elapsed = 0;
    for _ in 0..5 {
        assert_eq!(
            app.post("/api/v1/auth/otp/request", None, serde_json::json!({ "email": EMAIL })).await.status,
            StatusCode::OK
        );
        app.advance(Duration::seconds(61));
        elapsed += 61;
    }
    let limited = app.post("/api/v1/auth/otp/request", None, serde_json::json!({ "email": EMAIL })).await;
    assert_eq!(limited.status, StatusCode::TOO_MANY_REQUESTS);
    let retry_after: i64 = limited.headers[header::RETRY_AFTER].to_str().unwrap().parse().unwrap();
    assert_eq!(retry_after, 3600 - elapsed, "Retry-After must be the window remainder");

    // Obeying it works: one second earlier is still limited, exactly then is allowed.
    app.advance(Duration::seconds(retry_after - 1));
    assert_eq!(
        app.post("/api/v1/auth/otp/request", None, serde_json::json!({ "email": EMAIL })).await.status,
        StatusCode::TOO_MANY_REQUESTS
    );
    app.advance(Duration::seconds(1));
    assert_eq!(
        app.post("/api/v1/auth/otp/request", None, serde_json::json!({ "email": EMAIL })).await.status,
        StatusCode::OK
    );
}

/// Credential redemption is throttled per IP (S-24 "login 10/min/IP"). Without it the ≤5
/// attempts per code are no bound at all — the attacker just keeps asking for new codes.
#[tokio::test]
async fn s24_credential_redemption_is_rate_limited_per_ip() {
    let app = TestApp::new().await;
    for attempt in 1..=10 {
        let body = serde_json::json!({ "pending_id": "00".repeat(16), "email": EMAIL, "code": "12345678" });
        let response = app.post("/api/v1/auth/otp/verify", None, body).await;
        assert_eq!(response.status, StatusCode::UNAUTHORIZED, "attempt {attempt} within the cap");
    }
    let body = serde_json::json!({ "pending_id": "00".repeat(16), "email": EMAIL, "code": "12345678" });
    let over = app.post("/api/v1/auth/otp/verify", None, body).await;
    assert_eq!(over.status, StatusCode::TOO_MANY_REQUESTS, "the 11th redemption in a minute must be throttled");
    assert!(over.headers.contains_key(header::RETRY_AFTER));

    // The same bucket covers refresh — both are credential redemptions.
    let refresh = app.post("/api/v1/auth/refresh", None, serde_json::json!({ "refresh_token": "x" })).await;
    assert_eq!(refresh.status, StatusCode::TOO_MANY_REQUESTS);

    // A new minute restores the budget (no account-level lockout — S-24 anti-lockout).
    app.advance(Duration::seconds(61));
    let body = serde_json::json!({ "pending_id": "00".repeat(16), "email": EMAIL, "code": "12345678" });
    assert_eq!(app.post("/api/v1/auth/otp/verify", None, body).await.status, StatusCode::UNAUTHORIZED);
}

/// With the default (untrusted) proxy stance, rotating `X-Forwarded-For` must not mint fresh
/// per-IP buckets — otherwise the S-24 IP caps are decoration.
#[tokio::test]
async fn s24_spoofed_forwarded_header_cannot_mint_fresh_buckets() {
    let app = TestApp::with_options(TestOptions { trust_proxy_headers: false, ..TestOptions::default() }).await;
    for index in 0..20 {
        let body = serde_json::json!({ "email": format!("user{index}@corp.com") });
        // A different claimed source address every single time.
        let request =
            app.request(Method::POST, "/api/v1/auth/otp/request", None, Some(body), &format!("198.51.100.{index}"));
        assert_eq!(app.send(request).await.status, StatusCode::OK, "request {index} within the cap");
    }
    let body = serde_json::json!({ "email": "straw@corp.com" });
    let request = app.request(Method::POST, "/api/v1/auth/otp/request", None, Some(body), "198.51.100.200");
    let over = app.send(request).await;
    assert_eq!(over.status, StatusCode::TOO_MANY_REQUESTS, "a rotating XFF must not buy 20 more requests each time");
}

/// …and it must not let the caller *pose* as somebody else either: an untrusted forwarding
/// header never becomes the recorded client identity.
#[tokio::test]
async fn s24_spoofed_forwarded_header_cannot_poison_another_address() {
    let app = TestApp::with_options(TestOptions { trust_proxy_headers: false, ..TestOptions::default() }).await;
    let victim = "192.0.2.55";
    let request = app.request(
        Method::POST,
        "/api/v1/auth/otp/request",
        None,
        Some(serde_json::json!({ "email": EMAIL })),
        victim,
    );
    assert_eq!(app.send(request).await.status, StatusCode::OK);

    // The OTP mail renders the requester IP; the spoofed value must not appear there, which
    // is the same resolution the rate-limit bucket and the audit trail use.
    let mail = app.mailer.sent().pop().expect("one mail");
    assert!(!mail.text.contains(victim), "spoofed XFF became the recorded client identity:\n{}", mail.text);
    assert!(mail.text.contains("unknown"), "untrusted deployments have no client IP to report:\n{}", mail.text);
}

// --- S-12: cross-site mutations ---

/// The custom-header requirement leans on the browser; the `Origin`/`Sec-Fetch-Site` check is
/// decided server-side and must reject a foreign origin even when the header is present.
#[tokio::test]
async fn s12_cross_site_mutations_are_rejected_server_side() {
    let app = TestApp::new().await;

    let mutation = |email: &str, extra: Vec<(&'static str, &'static str)>| {
        let mut builder = Request::builder()
            .method(Method::POST)
            .uri("/api/v1/auth/otp/request")
            .header("x-pub-request", "1")
            .header(header::CONTENT_TYPE, "application/json");
        for (name, value) in extra {
            builder = builder.header(name, value);
        }
        builder.body(Body::from(serde_json::json!({ "email": email }).to_string())).unwrap()
    };

    for hostile in [
        vec![("origin", "https://evil.example")],
        vec![("origin", "http://pub.corp.test")],
        vec![("origin", "https://pub.corp.test.evil.example")],
        vec![("sec-fetch-site", "cross-site")],
        vec![("origin", INSTANCE_ORIGIN), ("sec-fetch-site", "cross-site")],
    ] {
        let denied = app.send(mutation(EMAIL, hostile.clone())).await;
        assert_eq!(denied.status, StatusCode::FORBIDDEN, "accepted cross-site request {hostile:?}");
        assert_eq!(denied.error_code(), "forbidden");
    }
    assert!(app.mailer.sent().is_empty(), "the guard must run before the flow");

    // The instance's own origin passes…
    let same_origin =
        app.send(mutation(EMAIL, vec![("origin", INSTANCE_ORIGIN), ("sec-fetch-site", "same-origin")])).await;
    assert_eq!(same_origin.status, StatusCode::OK, "{:?}", same_origin.json);
    // …and so does a header-less non-browser client: absence is not evidence of cross-site.
    let cli = app.send(mutation("cli@corp.com", Vec::new())).await;
    assert_eq!(cli.status, StatusCode::OK, "CLI clients send neither header and must keep working: {:?}", cli.json);
}

// --- S-31: domain policy at sign-in, not only at registration ---

/// An account whose domain has since left the allowlist cannot sign in even holding a live,
/// correct code — S-31 is evaluated at sign-in, not merely when the code is requested.
#[tokio::test]
async fn s31_domain_policy_blocks_sign_in_for_pre_existing_accounts() {
    let app = TestApp::with_options(TestOptions {
        allowed_email_domains: vec!["corp.com".to_owned()],
        ..TestOptions::default()
    })
    .await;
    let legacy = "legacy@evil.com";
    app.repos
        .users
        .create(
            pub_core::user::NewUser {
                email: Some(legacy.to_owned()),
                email_verified: true,
                display_name: "Legacy".to_owned(),
            },
            common::t0(),
        )
        .await
        .expect("seed the pre-policy account");

    // Plant a live pending record with a code we know — as if it had been issued before the
    // allowlist tightened. The request path would no longer mail one.
    let code = "13571357";
    let pending_id = "ab".repeat(16);
    let record = otp::PendingAuth {
        email: legacy.to_owned(),
        code_hmac: otp::code_hmac(code, common::TEST_PEPPER),
        created_at: app.now(),
        resend_of: None,
    };
    app.kv
        .set_ttl(&otp::pending_key(&pending_id), &serde_json::to_string(&record).unwrap(), StdDuration::from_secs(600))
        .await
        .unwrap();

    let denied = app
        .post(
            "/api/v1/auth/otp/verify",
            None,
            serde_json::json!({ "pending_id": pending_id, "email": legacy, "code": code }),
        )
        .await;
    assert_eq!(denied.status, StatusCode::UNAUTHORIZED, "a valid code must not beat the domain policy");
    assert_eq!(denied.error_code(), "invalid_code", "the rejection stays anti-enumeration-uniform (S-04)");

    let user = app.repos.users.find_by_email(legacy).await.unwrap().expect("account still exists");
    assert!(app.repos.sessions.list_for_user(user.id).await.unwrap().is_empty(), "no session may have been opened");
}

/// Raw Ed25519 public-key bytes for a seed — the material an attacker would try to reuse as
/// an HMAC secret. (Published JWKS make this public by design; the defence is pinning `alg`,
/// not hiding the key.)
fn ed25519_public_bytes(seed: [u8; 32]) -> Vec<u8> {
    ed25519_dalek::SigningKey::from_bytes(&seed).verifying_key().to_bytes().to_vec()
}
