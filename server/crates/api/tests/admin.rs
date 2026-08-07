//! The instance-administration surface end to end: who may reach it, what a settings write
//! actually changes, and the moderation actions.
//!
//! The two properties worth the most attention here:
//!
//! - **The admin plane is orthogonal to the org ladder** (decision 19). An org Owner is not an
//!   instance administrator, and the flag is read from the durable user row on every request
//!   rather than from a JWT claim (S-07), so a demotion is effective immediately.
//! - **A settings write propagates.** It bumps the durable version, the writing instance
//!   observes it at once, a peer's reconciliation poll picks it up, and the behaviour those
//!   settings gate actually changes — registration mode, the S-31 domain allowlist, the S-24
//!   rate limits, branding, the upstream switch, the SMTP transport itself (D10), and the
//!   anonymous-read flag (D31). "The row was written" is not the property under test; "the next
//!   request behaves differently" is.

mod common;

use std::sync::Arc;

use axum::http::{Method, StatusCode, header};
use chrono::Duration;
use common::{TestApp, TestOptions, package_archive};
use pub_core::audit::AuditResult;
use pub_core::package::{PackageOptions, Visibility};
use pub_core::settings::SettingsCache;
use pub_core::traits::{JobLock, JobTrigger, Mailer as _};
use pub_jobs::{InMemoryJobLock, JobRegistry, ReindexPolicy, Reindexer};

/// Signs `email` in and returns their access token.
async fn token(app: &TestApp, email: &str) -> String {
    app.login(email).await["access_token"].as_str().expect("access token").to_owned()
}

/// Signs an instance administrator in (the flag is set straight on the row).
async fn admin_token(app: &TestApp, email: &str) -> String {
    app.login(email).await;
    app.make_instance_admin(email).await;
    token(app, email).await
}

/// An app whose admin surface can trigger the **real** reindex worker, over the app's own
/// repositories — a double would prove nothing about the durable job state the dashboard reads.
async fn app_with_jobs() -> TestApp {
    let factory: common::JobFactory = Box::new(|repos| {
        let lock: Arc<dyn JobLock> = Arc::new(InMemoryJobLock::new());
        let policy = ReindexPolicy { enabled: true, resweep_after: Duration::seconds(0), ..ReindexPolicy::default() };
        Arc::new(JobRegistry::new(lock).with_reindex(Arc::new(Reindexer::new(repos.clone(), policy))))
            as Arc<dyn JobTrigger>
    });
    TestApp::with_options(TestOptions { jobs: Some(factory), ..TestOptions::default() }).await
}

// ------------------------------------------------------------------------------ the gate

/// Nobody but an instance administrator reaches `/api/v1/admin/…` — org Owners included.
#[tokio::test]
async fn the_admin_surface_is_closed_to_every_other_principal() {
    let app = TestApp::new().await;
    // The administrator registers first: on an empty instance the *first* account bootstraps
    // itself (decision 09), and an org Owner who accidentally held that flag would make this
    // whole matrix pass for the wrong reason.
    let admin = admin_token(&app, "root@corp.com").await;
    let (owner_access, _) = app.org_owner("owner@corp.com", "acme").await;
    let plain = token(&app, "nobody@corp.com").await;

    let routes: Vec<(Method, &str, Option<serde_json::Value>)> = vec![
        (Method::GET, "/api/v1/admin/settings", None),
        (
            Method::PATCH,
            "/api/v1/admin/settings",
            Some(
                serde_json::json!({ "branding": { "name": "X", "tagline": "", "logo_url": "", "primary_color": "" } }),
            ),
        ),
        (Method::GET, "/api/v1/admin/users", None),
        (Method::GET, "/api/v1/admin/orgs", None),
        (Method::GET, "/api/v1/admin/audit", None),
        (Method::GET, "/api/v1/admin/stats", None),
        (Method::POST, "/api/v1/admin/jobs/search-reindex/run", Some(serde_json::json!({}))),
        (Method::POST, "/api/v1/admin/settings/smtp/test", None),
    ];

    for (method, path, body) in &routes {
        // Anonymous: 401 — the caller has not been judged yet.
        let anonymous = app.send(app.request(method.clone(), path, None, body.clone(), common::DEFAULT_IP)).await;
        assert_eq!(anonymous.status, StatusCode::UNAUTHORIZED, "{path} must demand a credential");

        // An ordinary account and an org Owner: 403, with the plain forbidden code. Not 404 —
        // the admin API is in the published OpenAPI document, so hiding it buys nothing and
        // costs an operator their only diagnostic.
        for (label, credential) in [("plain user", &plain), ("org owner", &owner_access)] {
            let denied =
                app.send(app.request(method.clone(), path, Some(credential), body.clone(), common::DEFAULT_IP)).await;
            assert_eq!(denied.status, StatusCode::FORBIDDEN, "{label} must not reach {path}");
            assert_eq!(denied.error_code(), "forbidden");
        }
    }

    // The administrator reaches all of them (the job route 404s only because this instance
    // registered no jobs, which is a different answer from "you may not").
    for (method, path, body) in &routes {
        let response =
            app.send(app.request(method.clone(), path, Some(&admin), body.clone(), common::DEFAULT_IP)).await;
        assert!(
            response.status == StatusCode::OK || response.status == StatusCode::NOT_FOUND,
            "{path} answered {} for an administrator: {:?}",
            response.status,
            response.json
        );
    }
}

/// The flag is read from the row per request, so revoking it takes effect immediately — not
/// within one access TTL.
#[tokio::test]
async fn demoting_an_administrator_takes_effect_on_the_next_request() {
    let app = TestApp::new().await;
    let access = admin_token(&app, "root@corp.com").await;
    assert_eq!(app.get("/api/v1/admin/stats", Some(&access)).await.status, StatusCode::OK);

    let id = app.user_of("root@corp.com").await;
    app.repos.users.set_instance_admin(id, false, app.now()).await.expect("demote");
    // Same token, same session, same claims — and no longer an administrator.
    let denied = app.get("/api/v1/admin/stats", Some(&access)).await;
    assert_eq!(denied.status, StatusCode::FORBIDDEN);

    // A suspended administrator is not authenticated at all any more.
    app.repos.users.set_instance_admin(id, true, app.now()).await.expect("re-promote");
    app.repos.users.update_status(id, pub_core::user::UserStatus::Suspended, app.now()).await.expect("suspend");
    assert_eq!(app.get("/api/v1/admin/stats", Some(&access)).await.status, StatusCode::UNAUTHORIZED);
}

/// The bootstrap paths of decision 09: the configured email list, and the first account.
#[tokio::test]
async fn instance_admin_bootstrap_promotes_the_configured_list_and_the_first_account() {
    // First-account bootstrap: nobody is configured, so whoever registers first gets it.
    let app = TestApp::new().await;
    app.login("first@corp.com").await;
    app.login("second@corp.com").await;
    assert!(app.repos.users.find_by_email("first@corp.com").await.unwrap().unwrap().is_instance_admin);
    assert!(!app.repos.users.find_by_email("second@corp.com").await.unwrap().unwrap().is_instance_admin);

    // Configured list: the named address is promoted at registration, and the first-account
    // path does not additionally fire for somebody else.
    let configured = TestApp::with_options(TestOptions {
        instance_admins: vec!["ops@corp.com".to_owned()],
        ..TestOptions::default()
    })
    .await;
    configured.login("someone@corp.com").await;
    configured.login("ops@corp.com").await;
    assert!(configured.repos.users.find_by_email("ops@corp.com").await.unwrap().unwrap().is_instance_admin);
    // `someone` registered first on an empty instance, so they hold the bootstrap flag too —
    // that is the documented behaviour, and it is why the list exists for instances that care.
    let grants = configured.audit_actions().await.iter().filter(|action| *action == "admin.granted").count();
    assert_eq!(grants, 2, "both bootstrap paths are audited");
}

// ------------------------------------------------------------------------------- settings

/// A settings write bumps the version, the writer observes it at once, and a peer's
/// reconciliation poll converges on it (decision 09).
#[tokio::test]
async fn a_settings_write_bumps_the_version_and_every_instance_observes_it() {
    let app = TestApp::new().await;
    let access = admin_token(&app, "root@corp.com").await;

    let before = app.get("/api/v1/admin/settings", Some(&access)).await;
    assert_eq!(before.status, StatusCode::OK, "{:?}", before.json);
    let version_before = before.json["data"]["version"].as_i64().expect("version");
    assert_eq!(before.json["data"]["branding"]["name"], "Pub");
    assert_eq!(before.json["data"]["registration"]["mode"], "open");

    // A second cache over the same database — the peer instance.
    let peer = Arc::new(SettingsCache::new((*app.state.settings).runtime_defaults()));
    peer.reload(app.repos.settings.as_ref()).await.expect("peer initial load");
    assert!(!pub_admin::instance::poll_settings(&peer, &app.repos).await.expect("no change yet"));

    let patched = app
        .patch(
            "/api/v1/admin/settings",
            Some(&access),
            serde_json::json!({
                "branding": { "name": "Acme Registry", "tagline": "internal", "logo_url": "", "primary_color": "" }
            }),
        )
        .await;
    assert_eq!(patched.status, StatusCode::OK, "{:?}", patched.json);
    assert!(patched.json["data"]["version"].as_i64().expect("version") > version_before);
    assert_eq!(patched.json["data"]["branding"]["name"], "Acme Registry");

    // The writing instance serves the new value immediately — including on the public route
    // that renders it.
    let home = app.get("/api/v1/home", None).await;
    assert_eq!(home.json["data"]["instance"]["name"], "Acme Registry");
    assert_eq!(home.json["data"]["instance"]["tagline"], "internal");

    // The peer converges through the version poll alone (no broker message needed).
    assert!(pub_admin::instance::poll_settings(&peer, &app.repos).await.expect("poll"));
    assert_eq!(peer.current().branding.name, "Acme Registry");
    assert_eq!(peer.version(), patched.json["data"]["version"].as_i64().expect("version"));
    // …and converging is idempotent: a second poll with no change does nothing.
    assert!(!pub_admin::instance::poll_settings(&peer, &app.repos).await.expect("second poll"));

    // A write with no sections is refused rather than bumping a version for nothing.
    let empty = app.patch("/api/v1/admin/settings", Some(&access), serde_json::json!({})).await;
    assert_eq!(empty.status, StatusCode::BAD_REQUEST);

    assert!(app.audit_actions().await.contains(&"admin.settings".to_owned()));
}

/// **S-26.** The SMTP password is accepted on a write and never comes back.
#[tokio::test]
async fn s26_the_smtp_password_is_write_only() {
    let app = TestApp::new().await;
    let access = admin_token(&app, "root@corp.com").await;
    let smtp = |password: serde_json::Value| {
        serde_json::json!({ "smtp": {
            "host": "smtp.corp.com", "port": 587, "username": "mailer",
            "from": "Pub <noreply@corp.com>", "security": "starttls", "password": password
        }})
    };

    let written = app.patch("/api/v1/admin/settings", Some(&access), smtp("hunter2".into())).await;
    assert_eq!(written.status, StatusCode::OK, "{:?}", written.json);
    assert_eq!(written.json["data"]["smtp"]["host"], "smtp.corp.com");
    assert_eq!(written.json["data"]["smtp"]["password_set"], true);
    // Not in the response, under any key, in any form.
    let body = serde_json::to_string(&written.json).expect("serialize");
    assert!(!body.contains("hunter2"), "the password must never be returned: {body}");
    assert!(written.json["data"]["smtp"].get("password").is_none());

    // Stored sealed, not in the clear (S-26 envelope encryption under the env KEK).
    let stored = app.repos.settings.get_all().await.expect("settings");
    let raw = serde_json::to_string(&stored).expect("serialize");
    assert!(!raw.contains("hunter2"), "the stored value must be sealed");

    // Omitting the field keeps the stored credential rather than blanking it — which is what
    // makes a read-modify-write round trip of the returned view safe.
    let kept = app.patch("/api/v1/admin/settings", Some(&access), smtp(serde_json::Value::Null)).await;
    assert_eq!(kept.json["data"]["smtp"]["password_set"], true);

    // Clearing it while a login user remains is refused exactly as the boot validator refuses
    // the same pair: the stored half-credential would be dropped silently by the transport and
    // reported as `password_set: false` next to a filled-in username.
    let half = app.patch("/api/v1/admin/settings", Some(&access), smtp("".into())).await;
    assert_eq!(half.status, StatusCode::BAD_REQUEST, "{:?}", half.json);
    assert!(half.json["error"]["message"].as_str().expect("message").contains("smtp.username"));

    // Clearing both is the way to say "send unauthenticated".
    let cleared = app
        .patch(
            "/api/v1/admin/settings",
            Some(&access),
            serde_json::json!({ "smtp": {
                "host": "smtp.corp.com", "port": 587, "username": null,
                "from": "Pub <noreply@corp.com>", "security": "starttls", "password": ""
            }}),
        )
        .await;
    assert_eq!(cleared.status, StatusCode::OK, "{:?}", cleared.json);
    assert_eq!(cleared.json["data"]["smtp"]["password_set"], false);

    // The audit row names the section and nothing else.
    let event = app.audit_event("admin.settings").await.expect("audited");
    let metadata = serde_json::to_string(&event.metadata).expect("metadata");
    assert!(metadata.contains("smtp"));
    assert!(!metadata.contains("hunter2"));
}

/// Builds the SMTP patch body the D10 tests write.
fn smtp_patch(host: &str, port: u16, from: &str, username: serde_json::Value, password: &str) -> serde_json::Value {
    secured_smtp_patch(host, port, from, username, password, "tls")
}

/// The same body with an explicit transport security mode — which is part of the endpoint the
/// boot credential belongs to (decision 09 amendment, S-26.a).
fn secured_smtp_patch(
    host: &str,
    port: u16,
    from: &str,
    username: serde_json::Value,
    password: &str,
    security: &str,
) -> serde_json::Value {
    serde_json::json!({ "smtp": {
        "host": host, "port": port, "username": username,
        "from": from, "security": security, "password": password
    }})
}

/// Puts one message through the real OTP path.
///
/// The clock step is the S-03 resend floor (≥ 60 s per email between unconsumed requests), not
/// incidental: these tests send several times in a row without redeeming any of the codes.
async fn send_one_message(app: &TestApp, email: &str) {
    app.advance(Duration::seconds(61));
    app.request_otp(email).await;
}

/// **D10.** The mailer resolves from the settings cache, so an SMTP write reaches the very next
/// message — and an unchanged section does not cost a transport rebuild.
#[tokio::test]
async fn d10_smtp_settings_take_effect_without_a_restart() {
    let app = TestApp::new().await;
    let access = admin_token(&app, "root@corp.com").await;
    // Nothing is configured at boot, so nothing was ever built: mail lands in the outbox.
    assert!(app.smtp_builds.built().is_empty(), "an unconfigured instance builds no transport");

    let patched = app
        .patch(
            "/api/v1/admin/settings",
            Some(&access),
            smtp_patch("smtp.corp.com", 2525, "Acme <noreply@corp.com>", "mailer".into(), "hunter2"),
        )
        .await;
    assert_eq!(patched.status, StatusCode::OK, "{:?}", patched.json);

    // The next message resolves the new section. No restart, and no call site changed.
    send_one_message(&app, "dev@corp.com").await;
    let built = app.smtp_builds.built();
    assert_eq!(built.len(), 1, "the write took effect on the next send");
    assert_eq!(built[0].host, "smtp.corp.com");
    assert_eq!(built[0].port, 2525);
    assert_eq!(built[0].security, "tls");
    assert_eq!(built[0].from, "Acme <noreply@corp.com>");
    assert_eq!(built[0].username.as_deref(), Some("mailer"));
    // The stored credential was unsealed on its way into the transport — this is the reader
    // that did not exist while D10 was open.
    assert_eq!(built[0].password.as_deref(), Some("hunter2"));

    // The transport is a connection pool: an unchanged section must reuse it.
    send_one_message(&app, "dev@corp.com").await;
    assert_eq!(app.smtp_builds.built().len(), 1, "an unchanged section must not rebuild the pool");

    // A settings write to another section is not an SMTP change either.
    app.patch(
        "/api/v1/admin/settings",
        Some(&access),
        serde_json::json!({ "branding": { "name": "Acme", "tagline": "", "logo_url": "", "primary_color": "" } }),
    )
    .await;
    send_one_message(&app, "dev@corp.com").await;
    assert_eq!(app.smtp_builds.built().len(), 1, "a branding write is not an smtp change");
}

/// The runtime plane refuses every SMTP section the boot validator refuses.
///
/// It matters more here than at boot: a stored section the transport cannot be built from is
/// not *refused* by the mailer, it is **ignored** — the previous transport keeps delivering
/// while the admin surface reports settings that are not in force.
#[tokio::test]
async fn an_smtp_section_the_transport_could_not_be_built_from_is_refused_on_the_write() {
    let app = TestApp::new().await;
    let access = admin_token(&app, "root@corp.com").await;
    let null = serde_json::Value::Null;
    for (label, body) in [
        ("empty from", smtp_patch("smtp.corp.com", 587, "  ", null.clone(), "")),
        ("zero port", smtp_patch("smtp.corp.com", 0, "Acme <noreply@corp.com>", null.clone(), "")),
        (
            "unknown security",
            serde_json::json!({ "smtp": {
                "host": "smtp.corp.com", "port": 587, "username": null,
                "from": "Acme <noreply@corp.com>", "security": "plaintext", "password": ""
            }}),
        ),
        ("username with no password", smtp_patch("smtp.corp.com", 587, "Acme <noreply@corp.com>", "mailer".into(), "")),
        // The one the wave shipped: non-empty, so the old validator took it, and unparsable as a
        // mailbox, so `SmtpMailer::new` fails hours later on a path with no user attached. The
        // write path now runs the transport build itself, which is the only check that cannot
        // drift from what the mailer will actually do.
        ("from that is not a mailbox", smtp_patch("smtp.corp.com", 587, "Acme Pub", null.clone(), "")),
    ] {
        let refused = app.patch("/api/v1/admin/settings", Some(&access), body).await;
        assert_eq!(refused.status, StatusCode::BAD_REQUEST, "{label} was accepted: {:?}", refused.json);
    }
    // Nothing was stored, so the resolver still has nothing to apply.
    assert!(app.smtp_builds.built().is_empty());
}

/// A refused PATCH changes **nothing** — not even the sections validated before the failure.
///
/// The web form always submits all six sections, so an SMTP rule the administrator did not think
/// they were touching used to silently drop the `registry` anonymous-read flag they had just
/// ticked, while the 400 named only SMTP. `registry` was written last, so it was the first thing
/// lost — a security flag dropped by an error message about mail.
#[tokio::test]
async fn a_refused_settings_patch_writes_none_of_its_sections() {
    let app = TestApp::new().await;
    let access = admin_token(&app, "root@corp.com").await;
    let before = app.get("/api/v1/admin/settings", Some(&access)).await;
    assert_eq!(before.json["data"]["registry"]["require_auth_for_read"], false);

    let refused = app
        .patch(
            "/api/v1/admin/settings",
            Some(&access),
            serde_json::json!({
                "registration": { "mode": "closed", "allowed_email_domains": [] },
                "registry": { "require_auth_for_read": true },
                // Refused: a login user the runtime plane has no password for.
                "smtp": { "host": "smtp.corp.com", "port": 587, "username": "mailer",
                          "from": "Acme <noreply@corp.com>", "security": "tls", "password": "" },
            }),
        )
        .await;
    assert_eq!(refused.status, StatusCode::BAD_REQUEST, "{:?}", refused.json);

    let after = app.get("/api/v1/admin/settings", Some(&access)).await;
    assert_eq!(after.json["data"]["registry"]["require_auth_for_read"], false, "a security flag was dropped");
    assert_eq!(after.json["data"]["registration"]["mode"], "open", "an earlier section was written anyway");
    assert_eq!(after.json["data"]["version"], before.json["data"]["version"], "a refusal must not bump the version");
    // The durable rows, not just this instance's cache: a peer polling the version would
    // otherwise converge onto whatever landed.
    let stored = app.repos.settings.get_all().await.expect("settings rows");
    assert!(stored.is_empty(), "a refused patch wrote rows: {stored:?}");
}

/// **D10.** A peer instance picks the write up through the reconciliation poll — and rebuilds on
/// its next send, not on the reload: "the settings version is current" ≠ "the mailer is current".
#[tokio::test]
async fn d10_a_second_instance_picks_up_smtp_through_the_version_poll() {
    let app = TestApp::new().await;
    let access = admin_token(&app, "root@corp.com").await;

    // A second cache over the same database, with its own resolver — the peer instance.
    let peer_cache = Arc::new(SettingsCache::new((*app.state.settings).runtime_defaults()));
    peer_cache.reload(app.repos.settings.as_ref()).await.expect("peer initial load");
    let (peer, peer_builds) = common::peer_mailer(Arc::clone(&peer_cache));
    peer.send("dev@corp.com", "before", "body").await.expect("send");
    assert!(peer_builds.built().is_empty(), "the peer has no smtp configured yet");

    let patched = app
        .patch(
            "/api/v1/admin/settings",
            Some(&access),
            smtp_patch("smtp.corp.com", 587, "Acme <noreply@corp.com>", "mailer".into(), "hunter2"),
        )
        .await;
    assert_eq!(patched.status, StatusCode::OK, "{:?}", patched.json);

    // The peer converges through the poll alone (no broker message needed)…
    assert!(pub_admin::instance::poll_settings(&peer_cache, &app.repos).await.expect("poll"));
    assert!(peer_builds.built().is_empty(), "a reload does not push a transport rebuild");
    // …and applies it on its next send.
    peer.send("dev@corp.com", "after", "body").await.expect("send");
    let built = peer_builds.built();
    assert_eq!(built.len(), 1);
    assert_eq!(built[0].host, "smtp.corp.com");
    assert_eq!(built[0].password.as_deref(), Some("hunter2"), "the peer unsealed the same credential");
}

/// **S-25/S-26.a.** The boot SMTP password belongs to the boot endpoint and follows it nowhere.
///
/// Without this rule an instance administrator points `smtp.host` at a server they control,
/// leaves the password unset, and receives the operator's credential — an instance-admin →
/// operator-credential escalation the write-only design does not otherwise cover, because that
/// design is about *reading back*, not about *redirecting*.
#[tokio::test]
async fn s26_a_the_boot_password_is_only_used_for_the_boot_endpoint() {
    let app = TestApp::with_options(TestOptions {
        smtp_host: Some("smtp.corp.com".to_owned()),
        smtp_port: 587,
        smtp_username: Some("mailer".to_owned()),
        smtp_password: Some("boot-secret-value".to_owned()),
        ..TestOptions::default()
    })
    .await;
    let access = admin_token(&app, "root@corp.com").await;
    // Boot `[smtp]` defaults to starttls, and that is now part of the endpoint being matched.
    let boot_patch = |username: serde_json::Value, password: &str| {
        secured_smtp_patch("smtp.corp.com", 587, "Acme <noreply@corp.com>", username, password, "starttls")
    };
    // Signing in already sent mail through the boot section.
    let built = app.smtp_builds.built();
    assert_eq!(built.len(), 1);
    assert_eq!(built[0].password.as_deref(), Some("boot-secret-value"), "the boot endpoint gets the boot credential");

    // Repointing the host while keeping the login user is refused outright: the runtime plane
    // will not store a login user it has no password for.
    let redirected = app
        .patch(
            "/api/v1/admin/settings",
            Some(&access),
            smtp_patch("smtp.attacker.example", 587, "Acme <noreply@corp.com>", "mailer".into(), ""),
        )
        .await;
    assert_eq!(redirected.status, StatusCode::BAD_REQUEST, "{:?}", redirected.json);

    // **The downgrade**, which the three-field gate accepted: same host, same port, same login
    // user, `security` flipped to `none` and no password supplied. It used to store cleanly and
    // put `AUTH PLAIN base64("\0mailer\0boot-secret-value")` on the wire in the clear on the very
    // next send — which the administrator can trigger on demand with the test-mail button.
    let downgraded = app
        .patch(
            "/api/v1/admin/settings",
            Some(&access),
            secured_smtp_patch("smtp.corp.com", 587, "Acme <noreply@corp.com>", "mailer".into(), "", "none"),
        )
        .await;
    assert_eq!(downgraded.status, StatusCode::BAD_REQUEST, "the downgrade was accepted: {:?}", downgraded.json);
    // An *upgrade* is a different endpoint too — "equal to boot" needs no ordering between modes.
    let upgraded = app
        .patch(
            "/api/v1/admin/settings",
            Some(&access),
            smtp_patch("smtp.corp.com", 587, "Acme <noreply@corp.com>", "mailer".into(), ""),
        )
        .await;
    assert_eq!(upgraded.status, StatusCode::BAD_REQUEST, "{:?}", upgraded.json);
    send_one_message(&app, "dev@corp.com").await;
    assert_eq!(app.smtp_builds.built().len(), 1, "no refused section may reach the transport");

    // Repointing it *without* a login user is a legitimate "send unauthenticated" — and the
    // transport that comes out carries no credential at all.
    let moved = app
        .patch(
            "/api/v1/admin/settings",
            Some(&access),
            smtp_patch("smtp.attacker.example", 587, "Acme <noreply@corp.com>", serde_json::Value::Null, ""),
        )
        .await;
    assert_eq!(moved.status, StatusCode::OK, "{:?}", moved.json);
    send_one_message(&app, "dev@corp.com").await;
    let built = app.smtp_builds.built();
    assert_eq!(built.len(), 2);
    assert_eq!(built[1].host, "smtp.attacker.example");
    assert_eq!(built[1].password, None, "the boot credential must never follow the host");
    assert!(!built[1].credentialed());

    // A plaintext transport with no login user is not a downgrade of anything: there is no
    // credential to expose, so it is stored and built like any other section.
    let plaintext = app
        .patch(
            "/api/v1/admin/settings",
            Some(&access),
            secured_smtp_patch("smtp.corp.com", 25, "Acme <noreply@corp.com>", serde_json::Value::Null, "", "none"),
        )
        .await;
    assert_eq!(plaintext.status, StatusCode::OK, "{:?}", plaintext.json);
    send_one_message(&app, "dev@corp.com").await;
    let built = app.smtp_builds.built();
    assert_eq!(built.len(), 3);
    assert_eq!(built[2].security, "none");
    assert_eq!(built[2].password, None, "an unencrypted transport never carries the operator's credential");

    // Back on the boot endpoint — same host, port, user *and* security — a cleared runtime
    // password falls back to boot again: the symmetry decision 09 gives every other section,
    // minus the redirection.
    let home = app.patch("/api/v1/admin/settings", Some(&access), boot_patch("mailer".into(), "")).await;
    assert_eq!(home.status, StatusCode::OK, "{:?}", home.json);
    assert_eq!(home.json["data"]["smtp"]["password_set"], false, "nothing is stored; the fallback is boot config");
    send_one_message(&app, "dev@corp.com").await;
    let built = app.smtp_builds.built();
    assert_eq!(built.len(), 4);
    assert_eq!(built[3].password.as_deref(), Some("boot-secret-value"));
}

/// **D10.** A stored section the resolver cannot build is an error on the send path — never a
/// silent hand-off to the in-memory sink, and never a green test-mail report.
///
/// Before this fix the sink stood in whenever a build failed with nothing memoized, which is
/// *every* send after a restart: every sign-in code went into an in-process `Vec`, the queue
/// marked each row `done`, `dead_pending` stayed 0, and the test-mail action answered
/// `delivered: true` for a host it never contacted. An instance nobody could sign in to where
/// every observable signal said mail works (decision 09 amendment).
#[tokio::test]
async fn d10_a_section_the_resolver_cannot_build_fails_the_send_instead_of_discarding_it() {
    let app = TestApp::new().await;
    let access = admin_token(&app, "root@corp.com").await;

    // The KEK-rotation / ephemeral-development-KEK case: a sealed password this process cannot
    // open. It is the one unbuildable section the write validator cannot catch — the row was
    // valid when it was written — which is exactly why the send path must not treat it as "no
    // SMTP configured" and quietly accept the message.
    // Composed rather than pasted: a base64 literal in a `password_sealed` field is what the
    // repository's own secret scanner exists to shout about, and it cannot tell this apart.
    let unopenable = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, b"not sealed under this kek");
    let section = serde_json::json!({
        "host": "smtp.corp.com", "port": 587, "username": "mailer",
        "from": "Acme <noreply@corp.com>", "security": "starttls",
        "password_sealed": unopenable
    });
    app.repos
        .settings
        .upsert(pub_core::settings::keys::SMTP, &section, app.now())
        .await
        .expect("store the unopenable section");
    app.runtime.reload(app.repos.settings.as_ref()).await.expect("reload");

    // The test-mail action answers for the transport that ran, not for the row it read.
    let report = app.post_empty("/api/v1/admin/settings/smtp/test", Some(&access)).await;
    assert_eq!(report.status, StatusCode::OK, "a wrong SMTP config is not a 5xx: {:?}", report.json);
    assert_eq!(report.json["data"]["delivered"], false, "a host it never contacted was reported as delivered");
    assert_eq!(report.json["data"]["host"], "smtp.corp.com");
    assert!(
        report.json["data"]["detail"].as_str().is_some_and(|detail| !detail.is_empty()),
        "the operator needs the reason: {:?}",
        report.json["data"]["detail"]
    );
    assert!(app.smtp_builds.built().is_empty(), "no transport could be built at all");
    let audited = app.audit_event("admin.smtp.test").await.expect("the failure is audited");
    assert_eq!(audited.result, AuditResult::Failure);

    // …and a queued sign-in code is retried — and eventually dead-lettered — rather than marked
    // delivered. `retried` is what makes it visible on the admin job surface.
    let sent_before = app.mailer.sent().len();
    let requested = app.post("/api/v1/auth/otp/request", None, serde_json::json!({ "email": "dev@corp.com" })).await;
    assert_eq!(requested.status, StatusCode::OK, "{:?}", requested.json);
    let drain = app.drain_jobs().await;
    assert_eq!(drain.delivered, 0, "an undeliverable message must never be reported delivered");
    assert_eq!(drain.retried, 1, "the row stays in the queue where an operator can see it");
    assert_eq!(app.mailer.sent().len(), sent_before, "a configured host must never fall back to the outbox");
}

/// **S-26.** The stored password is unsealed into the transport and nowhere else.
#[tokio::test]
async fn s26_the_unsealed_password_never_leaves_the_process() {
    let app = TestApp::new().await;
    let access = admin_token(&app, "root@corp.com").await;
    app.patch(
        "/api/v1/admin/settings",
        Some(&access),
        smtp_patch("smtp.corp.com", 587, "Acme <noreply@corp.com>", "mailer".into(), "hunter2"),
    )
    .await;
    send_one_message(&app, "dev@corp.com").await;
    // It *is* used — otherwise this test would pass on the broken D10 code it exists to close.
    assert_eq!(app.smtp_builds.built()[0].password.as_deref(), Some("hunter2"));

    let mail = app.post_empty("/api/v1/admin/settings/smtp/test", Some(&access)).await;
    let settings = app.get("/api/v1/admin/settings", Some(&access)).await;
    for (label, body) in [("test-mail", &mail.json), ("settings", &settings.json)] {
        let rendered = serde_json::to_string(body).expect("serialize");
        assert!(!rendered.contains("hunter2"), "the credential reached the {label} response: {rendered}");
    }
    for action in ["admin.settings", "admin.smtp.test"] {
        let event = app.audit_event(action).await.unwrap_or_else(|| panic!("{action} audited"));
        let metadata = serde_json::to_string(&event.metadata).expect("metadata");
        assert!(!metadata.contains("hunter2"), "the credential reached the {action} audit row: {metadata}");
    }
    // Even the harness's own record redacts it: the only way to read it is an explicit field
    // access, which is the review checkpoint S-25.a asks for.
    let rendered = format!("{:?}", app.smtp_builds.built());
    assert!(!rendered.contains("hunter2"), "the credential reached a Debug line: {rendered}");
    assert!(rendered.contains("<redacted>"));
}

/// The test-mail action diagnoses the configuration instead of hiding behind a 5xx, and audits
/// both outcomes.
#[tokio::test]
async fn the_test_mail_action_reports_the_smtp_error_and_audits_both_outcomes() {
    let app = TestApp::new().await;
    let access = admin_token(&app, "root@corp.com").await;
    app.patch(
        "/api/v1/admin/settings",
        Some(&access),
        smtp_patch("smtp.corp.com", 587, "Acme <noreply@corp.com>", "mailer".into(), "hunter2"),
    )
    .await;

    let sent_before = app.mailer.sent().len();
    let ok = app.post_empty("/api/v1/admin/settings/smtp/test", Some(&access)).await;
    assert_eq!(ok.status, StatusCode::OK, "{:?}", ok.json);
    assert_eq!(ok.json["data"]["delivered"], true);
    assert_eq!(ok.json["data"]["host"], "smtp.corp.com");
    assert_eq!(ok.json["data"]["security"], "tls");
    assert_eq!(ok.json["data"]["credentialed"], true);
    assert!(ok.json["data"]["detail"].is_null());
    // There is no recipient field: it went to the acting administrator's own verified address,
    // which is what removes the mail-bomb vector rather than rate-limiting it.
    let sent = app.mailer.sent();
    assert_eq!(sent.len(), sent_before + 1);
    assert_eq!(sent.last().expect("mail").to, "root@corp.com");

    // A server that refuses the credential is a diagnosis, not a server fault.
    app.smtp_builds.fail_deliveries(true);
    app.patch(
        "/api/v1/admin/settings",
        Some(&access),
        smtp_patch("smtp.corp.com", 2525, "Acme <noreply@corp.com>", "mailer".into(), "hunter2"),
    )
    .await;
    let failed = app.post_empty("/api/v1/admin/settings/smtp/test", Some(&access)).await;
    assert_eq!(failed.status, StatusCode::OK, "a wrong SMTP config is not a 5xx: {:?}", failed.json);
    assert_eq!(failed.json["data"]["delivered"], false);
    assert!(
        failed.json["data"]["detail"].as_str().expect("detail").contains("535"),
        "the operator needs the server's own words: {:?}",
        failed.json["data"]["detail"]
    );

    let actions = app.audit_actions().await;
    assert_eq!(actions.iter().filter(|action| *action == "admin.smtp.test").count(), 2, "both outcomes are audited");
    let newest = app.audit_event("admin.smtp.test").await.expect("audited");
    assert_eq!(newest.result, AuditResult::Failure);
    assert_eq!(newest.target.as_deref(), Some("root@corp.com"));
    let metadata = serde_json::to_string(&newest.metadata).expect("metadata");
    assert!(metadata.contains("smtp.corp.com"));
    assert!(metadata.contains("\"credentialed\":true"));
    assert!(!metadata.contains("hunter2"));
}

/// An instance with no SMTP anywhere says so rather than reporting a delivery nobody will get.
#[tokio::test]
async fn the_test_mail_action_names_an_unconfigured_instance() {
    let app = TestApp::new().await;
    let access = admin_token(&app, "root@corp.com").await;
    let report = app.post_empty("/api/v1/admin/settings/smtp/test", Some(&access)).await;
    assert_eq!(report.status, StatusCode::OK, "{:?}", report.json);
    assert!(report.json["data"]["host"].is_null());
    assert_eq!(report.json["data"]["credentialed"], false);
    assert!(report.json["data"]["detail"].as_str().expect("detail").contains("no smtp host"));
}

/// **D31.** `require_auth_for_read` is a settings section now, so it flips without a restart —
/// and the extractor still judges credentials before the org lookup.
#[tokio::test]
async fn d31_require_auth_for_read_flips_at_runtime() {
    let app = TestApp::new().await;
    let access = admin_token(&app, "root@corp.com").await;
    let (owner_access, org) = app.org_owner("owner@corp.com", "acme").await;
    let cli = app.mint_token(&owner_access, org, &["read", "publish"]).await;
    app.publish("/o/acme/pub", &cli, &package_archive("acme_core", "1.0.0")).await;
    let package = app.repos.packages.get_by_name(pub_core::Format::Pub, "acme_core").await.unwrap().expect("package");
    let options = PackageOptions { visibility: Visibility::Public, ..PackageOptions::from(&package) };
    app.repos.packages.set_options(package.id, &options, app.now()).await.expect("publish it publicly");

    // The boot default: anonymous reads resolve, and an unknown org slug is an anti-enumeration
    // 404 with no challenge.
    assert_eq!(app.pub_get("/o/acme/pub/api/packages/acme_core", None).await.status, StatusCode::OK);
    assert_eq!(app.pub_get("/o/nosuch/pub/api/packages/acme_core", None).await.status, StatusCode::NOT_FOUND);

    let flag = |on: bool| serde_json::json!({ "registry": { "require_auth_for_read": on } });
    let patched = app.patch("/api/v1/admin/settings", Some(&access), flag(true)).await;
    assert_eq!(patched.status, StatusCode::OK, "{:?}", patched.json);
    assert_eq!(patched.json["data"]["registry"]["require_auth_for_read"], true);

    // Same request, no restart: the spec-mandated 401 plus the onboarding message that is our
    // only channel into the CLI.
    let refused = app.pub_get("/o/acme/pub/api/packages/acme_core", None).await;
    assert_eq!(refused.status, StatusCode::UNAUTHORIZED);
    let challenge = refused.headers[header::WWW_AUTHENTICATE].to_str().expect("challenge");
    assert!(challenge.contains("dart pub token add"), "onboarding message missing: {challenge}");
    // The extractor's ordering survives the move: an unknown slug answers 401 too, or org slugs
    // become enumerable by an anonymous caller (decision 05 addendum).
    assert_eq!(app.pub_get("/o/nosuch/pub/api/packages/acme_core", None).await.status, StatusCode::UNAUTHORIZED);
    // A credential still reads.
    assert_eq!(app.pub_get("/o/acme/pub/api/packages/acme_core", Some(&cli)).await.status, StatusCode::OK);

    // And it flips back.
    assert_eq!(app.patch("/api/v1/admin/settings", Some(&access), flag(false)).await.status, StatusCode::OK);
    assert_eq!(app.pub_get("/o/acme/pub/api/packages/acme_core", None).await.status, StatusCode::OK);
}

/// The registration mode is a runtime setting, and all three values behave.
#[tokio::test]
async fn registration_mode_takes_effect_without_a_restart() {
    let app = TestApp::new().await;
    let access = admin_token(&app, "root@corp.com").await;
    // The org that will send the invitation, created while registration is still open — an
    // org owner cannot be conjured under `invite`.
    app.org_owner("owner@corp.com", "acme").await;
    let set_mode = |mode: &str, domains: serde_json::Value| serde_json::json!({ "registration": { "mode": mode, "allowed_email_domains": domains } });

    // Open (the boot default): a new address registers on first sign-in.
    let (pending, code) = app.request_otp("newcomer@corp.com").await;
    let verify = |pending: String, email: &str, code: String| serde_json::json!({ "pending_id": pending, "email": email, "code": code });
    assert_eq!(
        app.post("/api/v1/auth/otp/verify", None, verify(pending, "newcomer@corp.com", code)).await.status,
        StatusCode::OK
    );

    // Closed: an existing account still signs in, a new one cannot register. A rejected
    // address gets the same response shape but never a redeemable code (S-04.a), so the
    // observable is "no mail" plus a uniform failure on any code it might guess.
    assert_eq!(
        app.patch("/api/v1/admin/settings", Some(&access), set_mode("closed", serde_json::json!([]))).await.status,
        StatusCode::OK
    );
    let (pending, code) = app.request_otp_raw("stranger@corp.com").await;
    assert_eq!(code, None, "a closed instance must not mail a redeemable code to a stranger");
    let refused =
        app.post("/api/v1/auth/otp/verify", None, verify(pending, "stranger@corp.com", "00000000".to_owned())).await;
    assert_eq!(refused.status, StatusCode::UNAUTHORIZED);
    assert_eq!(refused.error_code(), "invalid_code", "S-04: the refusal is uniform");
    let (pending, code) = app.request_otp("newcomer@corp.com").await;
    assert_eq!(
        app.post("/api/v1/auth/otp/verify", None, verify(pending, "newcomer@corp.com", code)).await.status,
        StatusCode::OK,
        "an existing account signs in in every mode"
    );

    // Invite-only: registration needs a live invitation for that exact address.
    assert_eq!(
        app.patch("/api/v1/admin/settings", Some(&access), set_mode("invite", serde_json::json!([]))).await.status,
        StatusCode::OK
    );
    // Re-login: the role claim for a just-created org is not in the token that created it.
    let owner_access = token(&app, "owner@corp.com").await;
    let invited = app
        .post("/api/v1/orgs/acme/invitations", Some(&owner_access), serde_json::json!({ "email": "invitee@corp.com" }))
        .await;
    assert_eq!(invited.status, StatusCode::OK, "{:?}", invited.json);

    let (pending, code) = app.request_otp("invitee@corp.com").await;
    assert_eq!(
        app.post("/api/v1/auth/otp/verify", None, verify(pending, "invitee@corp.com", code)).await.status,
        StatusCode::OK,
        "an invited address may register"
    );
    let (_, uninvited) = app.request_otp_raw("uninvited@corp.com").await;
    assert_eq!(uninvited, None, "an uninvited address may not register, and is never mailed a code");
}

/// **S-31.** The sign-in domain allowlist is a runtime setting, applied at sign-in.
#[tokio::test]
async fn s31_the_domain_allowlist_takes_effect_without_a_restart() {
    let app = TestApp::new().await;
    let access = admin_token(&app, "root@corp.com").await;
    // An account that exists *before* the policy tightens.
    app.login("dev@outside.example").await;

    let patched = app
        .patch(
            "/api/v1/admin/settings",
            Some(&access),
            serde_json::json!({ "registration": { "mode": "open", "allowed_email_domains": [" @CORP.com "] } }),
        )
        .await;
    assert_eq!(patched.status, StatusCode::OK, "{:?}", patched.json);
    // Normalized on the way in, so a stray `@` or casing cannot silently match nothing.
    assert_eq!(patched.json["data"]["registration"]["allowed_email_domains"][0], "corp.com");

    // S-31 is evaluated at every sign-in, not only at registration: the existing account whose
    // domain left the allowlist can no longer authenticate.
    let (pending, code) = app.request_otp_raw("dev@outside.example").await;
    assert_eq!(code, None, "a blocked domain is never mailed a redeemable code");
    let blocked = app
        .post(
            "/api/v1/auth/otp/verify",
            None,
            serde_json::json!({ "pending_id": pending, "email": "dev@outside.example", "code": "00000000" }),
        )
        .await;
    assert_eq!(blocked.status, StatusCode::UNAUTHORIZED);
    assert_eq!(blocked.error_code(), "invalid_code", "S-04: uniform with every other failure");

    // An allowed domain still works.
    let (pending, code) = app.request_otp("dev@corp.com").await;
    assert_eq!(
        app.post(
            "/api/v1/auth/otp/verify",
            None,
            serde_json::json!({ "pending_id": pending, "email": "dev@corp.com", "code": code })
        )
        .await
        .status,
        StatusCode::OK
    );

    // A malformed domain entry is refused rather than stored as a lockout.
    let bad = app
        .patch(
            "/api/v1/admin/settings",
            Some(&access),
            serde_json::json!({ "registration": { "mode": "open", "allowed_email_domains": ["dev@corp.com"] } }),
        )
        .await;
    assert_eq!(bad.status, StatusCode::BAD_REQUEST);
}

/// **S-24.** Rate-limit numbers are runtime settings, and a zero is refused.
#[tokio::test]
async fn s24_rate_limits_take_effect_without_a_restart() {
    let app = TestApp::new().await;
    let access = admin_token(&app, "root@corp.com").await;
    let limits = |login: u32| {
        serde_json::json!({ "rate_limits": {
            "otp_per_email_hour": 5, "otp_per_ip_hour": 20, "login_per_ip_minute": login,
            "token_auth_fail_per_ip_minute": 30, "publish_per_hour_org": 30
        }})
    };

    // A zero would lock the instance out of its own sign-in.
    let zero = app.patch("/api/v1/admin/settings", Some(&access), limits(0)).await;
    assert_eq!(zero.status, StatusCode::BAD_REQUEST);
    assert!(zero.json["error"]["message"].as_str().expect("message").contains("login_per_ip_minute"));

    // Tightening the login bucket to 1 trips the *second* redemption in the window. The window
    // is a fixed minute, so step into a clean one first — the sign-ins above already spent the
    // current one.
    assert_eq!(app.patch("/api/v1/admin/settings", Some(&access), limits(1)).await.status, StatusCode::OK);
    app.advance(Duration::minutes(2));
    let (pending, code) = app.request_otp("dev@corp.com").await;
    let body = serde_json::json!({ "pending_id": pending, "email": "dev@corp.com", "code": code });
    assert_eq!(app.post("/api/v1/auth/otp/verify", None, body.clone()).await.status, StatusCode::OK);
    let throttled = app.post("/api/v1/auth/otp/verify", None, body).await;
    assert_eq!(throttled.status, StatusCode::TOO_MANY_REQUESTS);
    assert!(throttled.headers.contains_key(axum::http::header::RETRY_AFTER));
}

/// The instance-wide upstream switch is a runtime setting: an operator can stop egress without
/// a restart (decision 07).
#[tokio::test]
async fn the_upstream_switch_takes_effect_without_a_restart() {
    let app = TestApp::with_options(TestOptions { upstream: true, ..TestOptions::default() }).await;
    let access = admin_token(&app, "root@corp.com").await;
    app.mock_upstream().publish("http", &[("1.0.0", b"http-archive-bytes")]);

    // With the proxy on, an unclaimed name resolves through it.
    assert_eq!(app.pub_get("/pub/api/packages/http", None).await.status, StatusCode::OK);

    let patched = app
        .patch(
            "/api/v1/admin/settings",
            Some(&access),
            serde_json::json!({ "upstream": { "enabled": false, "default_org_policy": "block" } }),
        )
        .await;
    assert_eq!(patched.status, StatusCode::OK, "{:?}", patched.json);

    // Off: the same name answers the same 404 an unknown one does (S-04), with no new upstream
    // request — the branch is gone, not merely unsuccessful.
    let calls = app.mock_upstream().listing_calls();
    let blocked = app.pub_get("/pub/api/packages/http", None).await;
    assert_eq!(blocked.status, StatusCode::NOT_FOUND);
    assert_eq!(app.mock_upstream().listing_calls(), calls, "a disabled proxy must not be contacted");

    // The new default reaches org creation too.
    let created = app.post("/api/v1/orgs", Some(&access), serde_json::json!({ "name": "New", "slug": "new" })).await;
    assert_eq!(created.status, StatusCode::OK, "{:?}", created.json);
    assert_eq!(created.json["data"]["upstream_policy"], "block");
}

// ----------------------------------------------------------------------------- moderation

/// Suspension blocks sign-in, revokes every live session (S-09), and halts the account's CLI
/// tokens on the pub plane (D37, decision 13 addendum) — all of it reversible: reinstatement
/// restores sign-in and the tokens with no re-mint.
#[tokio::test]
async fn s13_suspension_revokes_sessions_blocks_sign_in_and_gates_cli_tokens() {
    let app = TestApp::new().await;
    let access = admin_token(&app, "root@corp.com").await;
    let (bob_access, org) = app.org_owner("bob@corp.com", "bobs").await;
    let victim = token(&app, "bob@corp.com").await;
    let bob = app.user_of("bob@corp.com").await;
    assert_eq!(app.get("/api/v1/sessions", Some(&victim)).await.status, StatusCode::OK);

    // Bob's CLI credential works on the pub plane: his own private package resolves.
    let cli = app.mint_token(&bob_access, org, &["read", "publish"]).await;
    let published = app.publish("/o/bobs/pub", &cli, &package_archive("bobs_pkg", "1.0.0")).await;
    assert_eq!(published.status, StatusCode::OK, "{:?}", published.json);
    assert_eq!(app.pub_get("/o/bobs/pub/api/packages/bobs_pkg", Some(&cli)).await.status, StatusCode::OK);

    let suspended = app.post_empty(&format!("/api/v1/admin/users/{bob}/suspend"), Some(&access)).await;
    assert_eq!(suspended.status, StatusCode::OK, "{:?}", suspended.json);
    assert_eq!(suspended.json["data"]["status"], "suspended");

    assert_eq!(app.get("/api/v1/sessions", Some(&victim)).await.status, StatusCode::UNAUTHORIZED);
    assert!(app.repos.sessions.list_for_user(bob).await.expect("sessions").is_empty());

    // The CLI token stops authenticating too — uniform 401, indistinguishable from revoked
    // (S-14): the credential plane is gated at the repository, within the S-13 ≤60 s bound.
    let gated = app.pub_get("/o/bobs/pub/api/packages/bobs_pkg", Some(&cli)).await;
    assert_eq!(gated.status, StatusCode::UNAUTHORIZED, "a suspended account's token must not authenticate");

    // Sign-in is refused, uniformly (S-04).
    let (pending, code) = app.request_otp("bob@corp.com").await;
    let denied = app
        .post(
            "/api/v1/auth/otp/verify",
            None,
            serde_json::json!({ "pending_id": pending, "email": "bob@corp.com", "code": code }),
        )
        .await;
    assert_eq!(denied.status, StatusCode::UNAUTHORIZED);
    assert_eq!(denied.error_code(), "invalid_code");

    // Reinstated: sign-in works, and the untouched token row authenticates again — suspension
    // is reversible on the token plane too, no re-mint required.
    let restored = app.post_empty(&format!("/api/v1/admin/users/{bob}/unsuspend"), Some(&access)).await;
    assert_eq!(restored.status, StatusCode::OK);
    assert_eq!(restored.json["data"]["status"], "active");
    app.login("bob@corp.com").await;
    assert_eq!(
        app.pub_get("/o/bobs/pub/api/packages/bobs_pkg", Some(&cli)).await.status,
        StatusCode::OK,
        "unsuspension must restore the CLI token automatically"
    );

    // An administrator cannot lock themselves out.
    let root = app.user_of("root@corp.com").await;
    let selfharm = app.post_empty(&format!("/api/v1/admin/users/{root}/suspend"), Some(&access)).await;
    assert_eq!(selfharm.status, StatusCode::BAD_REQUEST);

    let actions = app.audit_actions().await;
    assert!(actions.contains(&"admin.user.suspend".to_owned()));
    assert!(actions.contains(&"admin.user.unsuspend".to_owned()));
}

/// The read-only admin views: users, orgs, audit, and the dashboard numbers.
#[tokio::test]
async fn the_admin_views_report_what_the_dashboard_renders() {
    let app = TestApp::new().await;
    let access = admin_token(&app, "root@corp.com").await;
    let (_, org) = app.org_owner("owner@corp.com", "acme").await;
    let owner_access = token(&app, "owner@corp.com").await;
    let publish_token = app.mint_token(&owner_access, org, &["publish"]).await;
    app.publish("/o/acme/pub", &publish_token, &package_archive("acme_core", "1.0.0")).await;

    // Users: filters and the keyset cursor.
    let users = app.get("/api/v1/admin/users?limit=1", Some(&access)).await;
    assert_eq!(users.status, StatusCode::OK, "{:?}", users.json);
    assert_eq!(users.json["data"]["items"].as_array().expect("items").len(), 1);
    assert_eq!(users.json["data"]["has_more"], true);
    let cursor = users.json["data"]["cursor"].as_str().expect("cursor").to_owned();
    let next = app.get(&format!("/api/v1/admin/users?limit=10&cursor={cursor}"), Some(&access)).await;
    assert!(!next.json["data"]["items"].as_array().expect("items").is_empty());
    let admins = app.get("/api/v1/admin/users?admins=true", Some(&access)).await;
    assert_eq!(admins.json["data"]["items"].as_array().expect("items").len(), 1);
    assert_eq!(admins.json["data"]["items"][0]["instance_admin"], true);
    // A junk status filter is a clean 400, not an empty page.
    assert_eq!(app.get("/api/v1/admin/users?status=nope", Some(&access)).await.status, StatusCode::BAD_REQUEST);

    // Orgs, with the counts the deletion guard uses.
    let orgs = app.get("/api/v1/admin/orgs", Some(&access)).await;
    assert_eq!(orgs.status, StatusCode::OK);
    assert_eq!(orgs.json["data"]["items"][0]["org"]["slug"], "acme");
    assert_eq!(orgs.json["data"]["items"][0]["members"], 1);
    assert_eq!(orgs.json["data"]["items"][0]["packages"], 1);

    // Audit, with the action-prefix filter.
    let audit = app.get("/api/v1/admin/audit?action=package.", Some(&access)).await;
    assert_eq!(audit.status, StatusCode::OK, "{:?}", audit.json);
    let actions: Vec<&str> =
        audit.json["data"]["items"].as_array().expect("items").iter().map(|e| e["action"].as_str().unwrap()).collect();
    assert!(actions.iter().all(|action| action.starts_with("package.")), "{actions:?}");
    assert!(actions.contains(&"package.publish"));
    assert_eq!(app.get("/api/v1/admin/audit?org=not-a-uuid", Some(&access)).await.status, StatusCode::BAD_REQUEST);

    // Stats.
    let stats = app.get("/api/v1/admin/stats", Some(&access)).await;
    assert_eq!(stats.status, StatusCode::OK, "{:?}", stats.json);
    let data = &stats.json["data"];
    assert_eq!(data["orgs"], 1);
    assert_eq!(data["registry"]["packages"], 1);
    assert_eq!(data["registry"]["versions"], 1);
    assert!(data["registry"]["archive_bytes"].as_i64().expect("bytes") > 0);
    assert_eq!(data["upstream_cache"]["packages"], 0);
    assert_eq!(data["users"]["admins"], 1);
    assert_eq!(data["users"]["active"].as_i64().expect("active"), data["users"]["total"].as_i64().expect("total"));
    assert!(data["quarantine"].as_array().expect("quarantine").is_empty());
    assert!(data["shadowing"].as_array().expect("shadowing").is_empty());
    assert!(data["runnable_jobs"].as_array().expect("jobs").is_empty(), "this instance registered none");
    assert!(data["settings_version"].as_i64().is_some());
}

/// Triggering a job runs it, reports its summary, and audits the operator.
#[tokio::test]
async fn a_manually_triggered_job_runs_and_is_audited() {
    let app = app_with_jobs().await;
    let access = admin_token(&app, "root@corp.com").await;

    let listed = app.get("/api/v1/admin/stats", Some(&access)).await;
    assert_eq!(listed.json["data"]["runnable_jobs"][0], "search-reindex");

    let run = app.post_empty("/api/v1/admin/jobs/search-reindex/run", Some(&access)).await;
    assert_eq!(run.status, StatusCode::OK, "{:?}", run.json);
    assert_eq!(run.json["data"]["job"], "search-reindex");
    assert!(run.json["data"]["summary"]["completed"].as_bool().expect("completed"));

    // A job this instance does not run is a 404, indistinguishable from one that does not
    // exist: the admin UI offers exactly what `runnable_jobs` reports.
    let unknown = app.post_empty("/api/v1/admin/jobs/mirror-sync/run", Some(&access)).await;
    assert_eq!(unknown.status, StatusCode::NOT_FOUND);

    // Both outcomes are audited (S-22): a manual sweep costs upstream traffic or deletes bytes.
    let event = app.audit_event("admin.job.run").await.expect("job run audited");
    assert!(event.target.is_some());
    // The job's durable state advanced, which is what the dashboard reads.
    let jobs = app.get("/api/v1/admin/stats", Some(&access)).await;
    let states = jobs.json["data"]["jobs"].as_array().expect("jobs");
    assert!(states.iter().any(|job| job["name"] == "search-reindex" && job["runs"].as_i64() == Some(1)));
}

/// Every admin route and DTO is in the generated spec — the frontend's types come from it.
#[tokio::test]
async fn openapi_documents_the_admin_surface() {
    let app = TestApp::new().await;
    let spec = app.get("/api/openapi.json", None).await;
    let paths = &spec.json["paths"];
    for (path, method) in [
        ("/api/v1/admin/settings", "get"),
        ("/api/v1/admin/settings", "patch"),
        ("/api/v1/admin/users", "get"),
        ("/api/v1/admin/users/{id}/suspend", "post"),
        ("/api/v1/admin/users/{id}/unsuspend", "post"),
        ("/api/v1/admin/orgs", "get"),
        ("/api/v1/admin/audit", "get"),
        ("/api/v1/admin/stats", "get"),
        ("/api/v1/admin/jobs/{job}/run", "post"),
        ("/api/v1/admin/settings/smtp/test", "post"),
    ] {
        assert!(paths.get(path).is_some(), "missing {path}");
        assert!(paths[path].get(method).is_some(), "{path} has no {method}");
    }
    let schemas = &spec.json["components"]["schemas"];
    for schema in [
        "AdminSettingsDto",
        "AdminSettingsPatchBody",
        "AdminUserDto",
        "AdminOrgDto",
        "AuditEventDto",
        "AdminStatsDto",
        "JobRunDto",
        "SmtpSettingsDto",
        "SmtpTestResultDto",
        "RegistrySettingsDto",
    ] {
        assert!(schemas.get(schema).is_some(), "missing schema {schema}");
    }
    // The write-only credential has no field on the read schema at all (S-26).
    let smtp = &schemas["SmtpSettingsDto"]["properties"];
    assert!(smtp.get("password").is_none());
    assert!(smtp.get("password_set").is_some());
}
