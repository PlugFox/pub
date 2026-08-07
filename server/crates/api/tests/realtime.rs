//! The realtime layer end to end: the SSE stream (S-32), the notification center, and the
//! event bus that feeds both (decisions 20/22).
//!
//! Everything here drives the **real** router over the real publish and membership paths, so
//! the events under test are the ones the domain services actually emit — a suite that pushed
//! events into the bus directly would pass while nothing on the write path emitted anything.
//!
//! The four properties S-32 names, one test each:
//!
//! - a package publish in org A reaches a member of A and **not** a non-member;
//! - a revoked session's stream dies on the next heartbeat;
//! - the per-user connection cap holds;
//! - `Last-Event-ID` replay works.

mod common;

use std::time::Duration as StdDuration;

use axum::http::{Method, StatusCode};
use common::{TestApp, TestOptions, package_archive};

/// How long a test waits for a frame that should arrive.
const SOON: StdDuration = StdDuration::from_secs(5);

/// How long a test waits to prove a frame does **not** arrive.
const NEVER: StdDuration = StdDuration::from_millis(400);

/// An app whose heartbeat is fast enough to observe inside a test's patience.
async fn app_with_fast_heartbeat() -> TestApp {
    TestApp::with_options(TestOptions { sse_heartbeat_secs: 1, ..TestOptions::default() }).await
}

/// Signs `email` in, creates `slug`, and returns `(access token, publish token, org slug)`.
///
/// The re-login is load-bearing: org role levels live in the JWT (decision 03), and the token
/// minted before the org existed carries no claim for it — so a stream opened with it would
/// filter the org's events out.
async fn owner(app: &TestApp, email: &str, slug: &str) -> (String, String) {
    let (access, org) = app.org_owner(email, slug).await;
    let token = app.mint_token(&access, org, &["read", "publish"]).await;
    let access = app.login(email).await["access_token"].as_str().expect("access token").to_owned();
    (access, token)
}

#[tokio::test]
async fn s32_a_publish_reaches_org_members_and_no_one_else() {
    let app = app_with_fast_heartbeat().await;
    let (owner_access, publish_token) = owner(&app, "owner@corp.com", "acme").await;
    // A perfectly ordinary account with an org of its own — and no membership in acme.
    let (outsider_access, _) = owner(&app, "outsider@corp.com", "other").await;

    let mut member = app.open_stream(&owner_access, None).await;
    let mut outsider = app.open_stream(&outsider_access, None).await;
    assert_eq!(member.status, StatusCode::OK);
    assert_eq!(
        member.headers[axum::http::header::CONTENT_TYPE].to_str().unwrap(),
        "text/event-stream",
        "the stream must announce itself as SSE"
    );

    app.publish("/o/acme/pub", &publish_token, &package_archive("acme_core", "1.0.0")).await;

    let frame = member.next_event(SOON).await.expect("the org's own member must receive the publish");
    assert_eq!(frame.event.as_deref(), Some("package.publish"));
    let data = frame.json();
    assert_eq!(data["type"], "package.publish");
    assert_eq!(data["package"], "acme_core");
    assert_eq!(data["version"], "1.0.0");
    assert!(frame.id.is_some(), "every frame carries a replayable id");
    assert_eq!(data["id"], frame.id.unwrap().as_str(), "the SSE id and the payload id agree");

    // The outsider's stream is open and healthy — it simply never carries acme's events.
    assert_eq!(outsider.next_event(NEVER).await, None, "a non-member must not receive another org's publish");
}

#[tokio::test]
async fn s32_a_revoked_session_stream_dies_on_the_next_heartbeat() {
    let app = app_with_fast_heartbeat().await;
    let (access, _) = owner(&app, "owner@corp.com", "acme").await;
    let mut stream = app.open_stream(&access, None).await;
    assert_eq!(stream.status, StatusCode::OK);

    // Logout revokes the session (S-09): the durable row plus the KV blocklist the stream's
    // heartbeat re-checks.
    let logout = app.post_empty("/api/v1/auth/logout", Some(&access)).await;
    assert_eq!(logout.status, StatusCode::OK);

    let frame = stream.next_event(SOON).await.expect("the stream must announce why it is closing");
    assert_eq!(frame.event.as_deref(), Some("stream.closed"));
    assert_eq!(frame.data, "session_revoked");
    // …and then actually end, rather than sit there sending heartbeats.
    assert_eq!(stream.next_frame(SOON).await, None, "the stream must terminate");
}

#[tokio::test]
async fn s32_the_per_user_connection_cap_holds() {
    let app =
        TestApp::with_options(TestOptions { sse_heartbeat_secs: 1, max_sse_connections: 2, ..TestOptions::default() })
            .await;
    let (access, _) = owner(&app, "owner@corp.com", "acme").await;

    let first = app.open_stream(&access, None).await;
    let second = app.open_stream(&access, None).await;
    assert_eq!(first.status, StatusCode::OK);
    assert_eq!(second.status, StatusCode::OK);

    let refused = app.open_stream_expecting_error(Some(&access)).await;
    assert_eq!(refused.status, StatusCode::TOO_MANY_REQUESTS, "the third stream must be refused");
    assert_eq!(refused.error_code(), "rate_limited");
    assert!(refused.headers.contains_key(axum::http::header::RETRY_AFTER), "S-24: a 429 always carries Retry-After");

    // Another account has its own budget.
    let (other_access, _) = owner(&app, "other@corp.com", "other").await;
    assert_eq!(app.open_stream(&other_access, None).await.status, StatusCode::OK);

    // Dropping a stream returns its slot; the writer notices on its next heartbeat.
    drop(second);
    tokio::time::sleep(StdDuration::from_millis(1500)).await;
    assert_eq!(app.open_stream(&access, None).await.status, StatusCode::OK, "a freed slot must be reusable");
    drop(first);
}

#[tokio::test]
async fn s32_last_event_id_replays_what_the_client_missed() {
    let app = app_with_fast_heartbeat().await;
    let (access, publish_token) = owner(&app, "owner@corp.com", "acme").await;

    let mut stream = app.open_stream(&access, None).await;
    app.publish("/o/acme/pub", &publish_token, &package_archive("acme_core", "1.0.0")).await;
    // A publish produces two frames for a member — the event, and the notification the center
    // files off it — so the client's "last seen" is whatever it read last, not the first frame.
    let mut last_seen = String::new();
    while let Some(frame) = stream.next_event(NEVER).await {
        last_seen = frame.id.expect("every frame carries an id");
    }
    assert!(!last_seen.is_empty(), "the first publish must have produced at least one frame");
    drop(stream);

    // Offline: a second publish happens with nobody listening.
    app.publish("/o/acme/pub", &publish_token, &package_archive("acme_core", "2.0.0")).await;

    let mut resumed = app.open_stream(&access, Some(&last_seen)).await;
    let mut replayed = Vec::new();
    while let Some(frame) = resumed.next_event(SOON).await {
        assert!(frame.id.as_deref() > Some(last_seen.as_str()), "replay is strictly newer than the given id");
        replayed.push(frame);
        if replayed.len() == 2 {
            break;
        }
    }
    let publish = replayed
        .iter()
        .find(|frame| frame.event.as_deref() == Some("package.publish"))
        .expect("the missed publish must be replayed");
    assert_eq!(publish.json()["version"], "2.0.0");

    // A client that is already current gets nothing replayed — not the whole ring again.
    let current = replayed.last().expect("frames").id.clone().expect("id");
    let mut idle = app.open_stream(&access, Some(&current)).await;
    assert_eq!(idle.next_event(NEVER).await, None);
}

#[tokio::test]
async fn the_stream_refuses_anonymous_and_broken_credentials() {
    let app = app_with_fast_heartbeat().await;
    let anonymous = app.open_stream_expecting_error(None).await;
    assert_eq!(anonymous.status, StatusCode::UNAUTHORIZED);
    let garbage = app.open_stream_expecting_error(Some("not-a-jwt")).await;
    assert_eq!(garbage.status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn s32_instance_scoped_events_reach_administrators_only() {
    let app = app_with_fast_heartbeat().await;
    // The *first* account on an instance is promoted to instance administrator by the
    // decision-09 bootstrap, so burn one before making the org Owner: this test is about a
    // principal who holds the top org role and no instance rights.
    app.login("first@corp.com").await;
    // An org Owner is not an instance administrator (decision 19: orthogonal planes).
    let (org_owner, _) = owner(&app, "owner@corp.com", "acme").await;
    app.login("admin@corp.com").await;
    app.make_instance_admin("admin@corp.com").await;
    let admin_access = app.login("admin@corp.com").await["access_token"].as_str().expect("access").to_owned();

    let mut admin_stream = app.open_stream(&admin_access, None).await;
    let mut owner_stream = app.open_stream(&org_owner, None).await;

    let patched = app
        .patch(
            "/api/v1/admin/settings",
            Some(&admin_access),
            serde_json::json!({ "branding": { "name": "Acme Registry", "tagline": "", "logo_url": "", "primary_color": "" } }),
        )
        .await;
    assert_eq!(patched.status, StatusCode::OK, "{:?}", patched.json);

    let frame = admin_stream.next_event(SOON).await.expect("an instance admin must see settings changes");
    assert_eq!(frame.event.as_deref(), Some("admin.settings"));
    assert_eq!(frame.json()["org_id"], serde_json::Value::Null, "instance-scoped events carry no org");
    assert_eq!(owner_stream.next_event(NEVER).await, None, "an org Owner is not an instance administrator");
}

#[tokio::test]
async fn the_notification_center_files_publishes_and_pages_them() {
    let app = app_with_fast_heartbeat().await;
    let (access, publish_token) = owner(&app, "owner@corp.com", "acme").await;

    app.publish("/o/acme/pub", &publish_token, &package_archive("acme_core", "1.0.0")).await;
    app.publish("/o/acme/pub", &publish_token, &package_archive("acme_core", "1.1.0")).await;

    let feed = app.get("/api/v1/notifications", Some(&access)).await;
    assert_eq!(feed.status, StatusCode::OK, "{:?}", feed.json);
    let items = feed.json["data"]["items"].as_array().expect("items");
    assert_eq!(items.len(), 2, "one notification per publish");
    assert_eq!(items[0]["event"], "package.publish", "newest first");
    assert_eq!(items[0]["category"], "package");
    assert_eq!(items[0]["payload"]["version"], "1.1.0", "the event payload travels verbatim");
    assert_eq!(feed.json["data"]["unread"], 2);
    assert_eq!(feed.json["data"]["has_more"], false);

    // Cursor pagination over the feed.
    let page = app.get("/api/v1/notifications?limit=1", Some(&access)).await;
    assert_eq!(page.json["data"]["has_more"], true);
    let cursor = page.json["data"]["cursor"].as_str().expect("cursor").to_owned();
    let second = app.get(&format!("/api/v1/notifications?limit=1&cursor={cursor}"), Some(&access)).await;
    assert_eq!(second.json["data"]["items"][0]["payload"]["version"], "1.0.0");
    assert_eq!(second.json["data"]["has_more"], false);
    // A tampered cursor is a clean 400, never a reset listing.
    let bad = app.get("/api/v1/notifications?cursor=%25%25%25", Some(&access)).await;
    assert_eq!(bad.status, StatusCode::BAD_REQUEST);
    assert_eq!(bad.error_code(), "invalid_argument");
}

#[tokio::test]
async fn marking_notifications_read_moves_the_badge_and_is_scoped_to_the_caller() {
    let app = app_with_fast_heartbeat().await;
    let (access, publish_token) = owner(&app, "owner@corp.com", "acme").await;
    let (other_access, other_token) = owner(&app, "other@corp.com", "other").await;
    app.publish("/o/acme/pub", &publish_token, &package_archive("acme_core", "1.0.0")).await;
    app.publish("/o/acme/pub", &publish_token, &package_archive("acme_ui", "1.0.0")).await;
    app.publish("/o/other/pub", &other_token, &package_archive("other_core", "1.0.0")).await;

    let feed = app.get("/api/v1/notifications", Some(&access)).await;
    let ids: Vec<String> =
        feed.json["data"]["items"].as_array().unwrap().iter().map(|n| n["id"].as_str().unwrap().to_owned()).collect();
    assert_eq!(ids.len(), 2);

    // Another account's notification id is a silent no-op, never an error that would confirm
    // the id exists (S-04).
    let foreign = app.get("/api/v1/notifications", Some(&other_access)).await;
    let foreign_id = foreign.json["data"]["items"][0]["id"].as_str().unwrap().to_owned();
    let marked =
        app.post("/api/v1/notifications/read", Some(&access), serde_json::json!({ "ids": [ids[0], foreign_id] })).await;
    assert_eq!(marked.status, StatusCode::OK);
    assert_eq!(marked.json["data"]["marked"], 1);
    assert_eq!(marked.json["data"]["unread"], 1);
    assert_eq!(
        app.get("/api/v1/notifications", Some(&other_access)).await.json["data"]["unread"],
        1,
        "the other account's badge is untouched"
    );

    // Mark-all clears the rest and is idempotent.
    let all = app.post("/api/v1/notifications/read", Some(&access), serde_json::json!({ "all": true })).await;
    assert_eq!(all.json["data"]["marked"], 1);
    assert_eq!(all.json["data"]["unread"], 0);
    let again = app.post("/api/v1/notifications/read", Some(&access), serde_json::json!({ "all": true })).await;
    assert_eq!(again.json["data"]["marked"], 0);

    // Neither ids nor all is a 400 rather than a silent no-op.
    let empty = app.post("/api/v1/notifications/read", Some(&access), serde_json::json!({})).await;
    assert_eq!(empty.status, StatusCode::BAD_REQUEST);
    assert_eq!(empty.error_code(), "invalid_argument");
}

#[tokio::test]
async fn per_category_preferences_decide_what_is_filed_and_what_is_mailed() {
    let app = app_with_fast_heartbeat().await;
    let (access, publish_token) = owner(&app, "owner@corp.com", "acme").await;

    let defaults = app.get("/api/v1/notifications/preferences", Some(&access)).await;
    assert_eq!(defaults.status, StatusCode::OK);
    let prefs = defaults.json["data"]["preferences"].as_array().expect("preferences");
    assert_eq!(prefs.len(), 3, "every category is present, stored or not");
    let package = prefs.iter().find(|p| p["category"] == "package").expect("package");
    assert_eq!(package["in_app"], true);
    assert_eq!(package["email"], false, "the package firehose does not reach a mailbox by default");
    let security = prefs.iter().find(|p| p["category"] == "security").expect("security");
    assert_eq!(security["email"], true, "high-importance categories do");

    // Muting a category stops the rows, not just the mail.
    let patched = app
        .patch(
            "/api/v1/notifications/preferences",
            Some(&access),
            serde_json::json!({ "preferences": [{ "category": "package", "in_app": false, "email": false }] }),
        )
        .await;
    assert_eq!(patched.status, StatusCode::OK, "{:?}", patched.json);
    app.publish("/o/acme/pub", &publish_token, &package_archive("acme_core", "1.0.0")).await;
    assert_eq!(
        app.get("/api/v1/notifications", Some(&access)).await.json["data"]["items"].as_array().unwrap().len(),
        0,
        "a muted category files nothing"
    );
    // An untouched category kept its default.
    let after = app.get("/api/v1/notifications/preferences", Some(&access)).await;
    let org = after.json["data"]["preferences"].as_array().unwrap().iter().find(|p| p["category"] == "org").cloned();
    assert_eq!(org.expect("org")["email"], true);

    // Junk categories and duplicates are refused rather than half-applied.
    for body in [
        serde_json::json!({ "preferences": [{ "category": "nonsense", "in_app": true, "email": true }] }),
        serde_json::json!({ "preferences": [
            { "category": "org", "in_app": true, "email": true },
            { "category": "org", "in_app": false, "email": false }
        ] }),
        serde_json::json!({ "preferences": [] }),
    ] {
        let refused = app.patch("/api/v1/notifications/preferences", Some(&access), body).await;
        assert_eq!(refused.status, StatusCode::BAD_REQUEST, "{:?}", refused.json);
    }
}

#[tokio::test]
async fn high_importance_categories_reach_a_mailbox() {
    let app = app_with_fast_heartbeat().await;
    let (access, _) = owner(&app, "owner@corp.com", "acme").await;
    // A second account to promote — a role change is an `org`-category event, which is
    // high-importance and therefore mailed by default.
    app.login("teammate@corp.com").await;
    let added = app
        .post(
            "/api/v1/orgs/acme/members",
            Some(&access),
            serde_json::json!({ "email": "teammate@corp.com", "role": "read" }),
        )
        .await;
    assert_eq!(added.status, StatusCode::OK, "{:?}", added.json);

    let before = app.mailer.sent().len();
    let teammate = app.user_of("teammate@corp.com").await;
    let promoted = app
        .patch(&format!("/api/v1/orgs/acme/members/{teammate}"), Some(&access), serde_json::json!({ "role": "read" }))
        .await;
    assert_eq!(promoted.status, StatusCode::OK, "{:?}", promoted.json);

    let sent = app.mailer.sent();
    let fresh: Vec<_> = sent[before..].iter().collect();
    assert!(!fresh.is_empty(), "an org-category notification must reach the mailbox");
    assert!(
        fresh.iter().all(|mail| mail.subject.contains("Pub")),
        "the instance name brands the subject: {:?}",
        fresh.iter().map(|m| m.subject.clone()).collect::<Vec<_>>()
    );

    // Turning email off for the category stops it while keeping the feed row.
    app.patch(
        "/api/v1/notifications/preferences",
        Some(&access),
        serde_json::json!({ "preferences": [{ "category": "org", "in_app": true, "email": false }] }),
    )
    .await;
    let before = app.mailer.sent().len();
    app.patch(&format!("/api/v1/orgs/acme/members/{teammate}"), Some(&access), serde_json::json!({ "role": "read" }))
        .await;
    let owner_mails: Vec<_> =
        app.mailer.sent()[before..].iter().filter(|mail| mail.to == "owner@corp.com").cloned().collect();
    assert!(owner_mails.is_empty(), "a muted category must not mail: {owner_mails:?}");
}

#[tokio::test]
async fn org_creation_is_audited() {
    // S-22 lists org changes among the audited events, and creating one — which mints a name
    // space, an Owner, and a virtual registry base — is the first of them.
    let app = TestApp::new().await;
    app.org_owner("owner@corp.com", "acme").await;
    let event = app.audit_event("org.created").await.expect("org.created must be audited");
    assert_eq!(event.target.as_deref(), Some("acme"));
    assert_eq!(event.ip.as_deref(), Some(common::DEFAULT_IP));
    assert!(event.org_id.is_some(), "the audit row names the org it created");
}

#[tokio::test]
async fn the_notification_surface_rejects_anonymous_callers() {
    let app = TestApp::new().await;
    for (method, path, body) in [
        (Method::GET, "/api/v1/notifications", None),
        (Method::GET, "/api/v1/notifications/preferences", None),
        (Method::POST, "/api/v1/notifications/read", Some(serde_json::json!({ "all": true }))),
        (
            Method::PATCH,
            "/api/v1/notifications/preferences",
            Some(serde_json::json!({ "preferences": [{ "category": "org", "in_app": true, "email": true }] })),
        ),
    ] {
        let response = app.send(app.request(method.clone(), path, None, body, common::DEFAULT_IP)).await;
        assert_eq!(response.status, StatusCode::UNAUTHORIZED, "{method} {path} must demand a credential");
    }
}
