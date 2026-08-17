//! The app API's route inventory, asserted against the generated OpenAPI document.
//!
//! This is the machine-checked twin of the endpoint table in the docs: a route that is not in
//! this list is either missing from the spec (and therefore uncallable by the generated
//! frontend client — docs/rules/api.md) or newly added and undocumented. Either way the test
//! fails, which is the point.

mod common;

use std::collections::BTreeSet;

use axum::http::StatusCode;
use common::TestApp;

/// Every `(method, path)` the app API exposes, plus whether it demands a bearer credential in
/// the spec. `false` means the route is anonymous-reachable by design (decision 05) or is part
/// of the sign-in flow that mints the credential in the first place.
const SURFACE: &[(&str, &str, bool)] = &[
    // system
    ("get", "/healthz", false),
    ("get", "/api/v1/ping", false),
    ("get", "/.well-known/security.txt", false),
    // auth
    ("post", "/api/v1/auth/otp/request", false),
    ("post", "/api/v1/auth/otp/verify", false),
    ("post", "/api/v1/auth/refresh", false),
    ("post", "/api/v1/auth/logout", true),
    ("get", "/api/v1/auth/providers", false),
    ("post", "/api/v1/auth/oidc/{provider}/start", false),
    ("post", "/api/v1/auth/oidc/{provider}/callback", false),
    ("post", "/api/v1/auth/totp/enroll", true),
    ("post", "/api/v1/auth/totp/confirm", true),
    ("delete", "/api/v1/auth/totp", true),
    ("post", "/api/v1/auth/totp/verify", false),
    ("post", "/api/v1/auth/step-up", true),
    // account (decision 39, S-29)
    ("get", "/api/v1/me", true),
    ("patch", "/api/v1/me", true),
    ("delete", "/api/v1/me", true),
    ("post", "/api/v1/me/email", true),
    ("post", "/api/v1/me/email/verify", true),
    ("get", "/api/v1/me/export", true),
    // sessions & tokens
    ("get", "/api/v1/sessions", true),
    ("delete", "/api/v1/sessions/{sid}", true),
    ("post", "/api/v1/sessions/revoke-all", true),
    ("post", "/api/v1/tokens", true),
    ("get", "/api/v1/tokens", true),
    ("delete", "/api/v1/tokens/{id}", true),
    // orgs
    ("post", "/api/v1/orgs", true),
    ("get", "/api/v1/orgs", true),
    ("get", "/api/v1/orgs/{slug}", false),
    ("patch", "/api/v1/orgs/{slug}", true),
    ("delete", "/api/v1/orgs/{slug}", true),
    ("get", "/api/v1/orgs/{slug}/members", true),
    ("post", "/api/v1/orgs/{slug}/members", true),
    ("patch", "/api/v1/orgs/{slug}/members/{user_id}", true),
    ("delete", "/api/v1/orgs/{slug}/members/{user_id}", true),
    ("get", "/api/v1/orgs/{slug}/invitations", true),
    ("post", "/api/v1/orgs/{slug}/invitations", true),
    ("delete", "/api/v1/orgs/{slug}/invitations/{id}", true),
    ("delete", "/api/v1/orgs/{slug}/membership", true),
    ("post", "/api/v1/invitations/accept", true),
    // packages: read model
    ("get", "/api/v1/packages", false),
    ("get", "/api/v1/packages/{name}", false),
    ("get", "/api/v1/packages/{name}/versions", false),
    ("get", "/api/v1/packages/{name}/versions/{version}", false),
    ("get", "/api/v1/packages/{name}/dependents", false),
    ("get", "/api/v1/home", false),
    // packages: management
    ("patch", "/api/v1/packages/{name}/options", true),
    ("post", "/api/v1/packages/{name}/versions/{version}/retract", true),
    ("post", "/api/v1/packages/{name}/versions/{version}/unretract", true),
    ("delete", "/api/v1/packages/{name}/versions/{version}", true),
    ("post", "/api/v1/packages/{name}/transfer", true),
    // realtime
    ("get", "/api/v1/events", true),
    ("get", "/api/v1/notifications", true),
    ("post", "/api/v1/notifications/read", true),
    ("get", "/api/v1/notifications/preferences", true),
    ("patch", "/api/v1/notifications/preferences", true),
    // instance administration
    ("get", "/api/v1/admin/settings", true),
    ("patch", "/api/v1/admin/settings", true),
    ("post", "/api/v1/admin/settings/smtp/test", true),
    ("get", "/api/v1/admin/users", true),
    ("post", "/api/v1/admin/users/{id}/suspend", true),
    ("post", "/api/v1/admin/users/{id}/unsuspend", true),
    ("get", "/api/v1/admin/orgs", true),
    ("patch", "/api/v1/admin/orgs/{id}", true),
    ("get", "/api/v1/admin/audit", true),
    ("get", "/api/v1/admin/audit/export", true),
    ("get", "/api/v1/admin/stats", true),
    ("post", "/api/v1/admin/jobs/{job}/run", true),
    // The two supply-chain registers and the one write they have (decision 33).
    ("get", "/api/v1/admin/quarantine", true),
    ("get", "/api/v1/admin/shadowing", true),
    ("post", "/api/v1/admin/shadowing/{format}/{name}/acknowledge", true),
];

#[tokio::test]
async fn the_openapi_document_matches_the_route_inventory_exactly() {
    let app = TestApp::new().await;
    let response = app.get("/api/openapi.json", None).await;
    assert_eq!(response.status, StatusCode::OK);

    // The frontend's `openapi.json` is a checked-in snapshot the type codegen reads, and the
    // documented way to refresh it was "start the server and curl it" — a manual step, which is
    // how it drifts. `UPDATE_OPENAPI=1 cargo test -p pub-api --test surface` writes it from the
    // router this test already built, the same shape as the config reference and the metric
    // catalogue. Nothing asserts the snapshot yet: making it a drift gate is D36's job, and it
    // needs the codegen to be idempotent first.
    if std::env::var_os("UPDATE_OPENAPI").is_some() {
        let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../web/packages/api/openapi.json");
        // Compact and newline-free, byte-for-byte the shape `curl` produced, so refreshing it is
        // a diff of the contract rather than a diff of the formatting.
        let rendered = serde_json::to_string(&response.json).expect("render the document");
        std::fs::write(&path, rendered).expect("write web/packages/api/openapi.json");
    }

    let paths = response.json["paths"].as_object().expect("paths object");

    // What the spec says, minus the pub protocol (its own contract, its own suite).
    let mut documented: BTreeSet<(String, String)> = BTreeSet::new();
    for (path, item) in paths {
        if path.starts_with("/o/") || path.starts_with("/pub/") {
            continue;
        }
        for method in ["get", "post", "patch", "delete", "put", "head"] {
            if item.get(method).is_some() {
                documented.insert((method.to_owned(), path.clone()));
            }
        }
    }
    let expected: BTreeSet<(String, String)> =
        SURFACE.iter().map(|(method, path, _)| ((*method).to_owned(), (*path).to_owned())).collect();

    let missing: Vec<_> = expected.difference(&documented).collect();
    let extra: Vec<_> = documented.difference(&expected).collect();
    assert!(missing.is_empty(), "routes in the inventory but not in the spec: {missing:?}");
    assert!(extra.is_empty(), "routes in the spec but not in the inventory — add them here: {extra:?}");
}

#[tokio::test]
async fn every_authenticated_route_declares_the_bearer_scheme() {
    let app = TestApp::new().await;
    let response = app.get("/api/openapi.json", None).await;
    let paths = &response.json["paths"];
    assert!(
        response.json["components"]["securitySchemes"]["bearer_auth"].is_object(),
        "the bearer scheme must be registered in components (docs/rules/api.md)"
    );
    for (method, path, needs_auth) in SURFACE {
        let operation = &paths[*path][*method];
        assert!(operation.is_object(), "{method} {path} is missing from the spec");
        let declared = operation.get("security").is_some();
        assert_eq!(
            declared, *needs_auth,
            "{method} {path}: security declaration disagrees with the inventory (declared = {declared})"
        );
    }
}

#[tokio::test]
async fn every_route_answers_the_envelope_on_error() {
    // The one shape a generated client parses. A route that answered a bare string or axum's
    // own plain-text rejection would be the exception that forces a second parser.
    let app = TestApp::new().await;
    for (path, expected) in [
        ("/api/v1/packages?limit=not-a-number", StatusCode::BAD_REQUEST),
        ("/api/v1/packages/does_not_exist", StatusCode::NOT_FOUND),
        ("/api/v1/notifications", StatusCode::UNAUTHORIZED),
        ("/api/v1/admin/stats", StatusCode::UNAUTHORIZED),
        ("/api/v1/orgs/nosuchorg", StatusCode::NOT_FOUND),
    ] {
        let response = app.get(path, None).await;
        assert_eq!(response.status, expected, "{path}: {:?}", response.json);
        assert_eq!(response.json["status"], "error", "{path} must answer the envelope");
        assert!(response.json["error"]["code"].is_string(), "{path} must carry a stable code");
        assert!(response.json["error"]["message"].is_string(), "{path} must carry a message");
    }
}

#[tokio::test]
async fn cursor_tampering_is_a_clean_400_on_every_paginated_route() {
    let app = TestApp::new().await;
    let (_access, _org) = app.org_owner("owner@corp.com", "acme").await;
    app.make_instance_admin("owner@corp.com").await;
    let access = app.login("owner@corp.com").await["access_token"].as_str().expect("access").to_owned();

    for path in [
        "/api/v1/packages?cursor=%25%25%25",
        "/api/v1/orgs/acme?cursor=%25%25%25",
        "/api/v1/notifications?cursor=%25%25%25",
        "/api/v1/admin/users?cursor=%25%25%25",
        "/api/v1/admin/orgs?cursor=%25%25%25",
        "/api/v1/admin/audit?cursor=%25%25%25",
    ] {
        let response = app.get(path, Some(&access)).await;
        assert_eq!(response.status, StatusCode::BAD_REQUEST, "{path}: {:?}", response.json);
        assert_eq!(response.error_code(), "invalid_argument", "{path}");
    }
}

#[tokio::test]
async fn no_response_schema_carries_a_credential_field() {
    // A grep with teeth: every schema in the generated document is scanned for property names
    // that would be a leaked credential. The legitimate ones are enumerated below, so adding
    // another is a deliberate act rather than an accident.
    // Outbound: the four show-once credentials the product deliberately returns exactly once.
    const ALLOWED_OUT: &[(&str, &str)] = &[
        // The minted CLI token (S-13 show-once).
        ("TokenCreatedDto", "secret"),
        // The invitation token, shown once and mailed (S-06).
        ("InvitationCreatedDto", "token"),
        // The TOTP provisioning seed, shown once at enrollment (S-05).
        ("TotpEnrollDto", "secret"),
        // The pair a sign-in mints, and the pending-MFA handle that replaces it mid-flow.
        ("LoginDto", "access_token"),
        ("LoginDto", "refresh_token"),
        ("LoginDto", "mfa_token"),
        // A boolean, not a value: whether an SMTP password is stored (S-26 write-only).
        ("SmtpSettingsDto", "password_set"),
    ];
    // Inbound: request bodies where the *caller* presents a credential they already hold.
    // Deserialize-only types — none of them is ever serialized back.
    const ALLOWED_IN: &[(&str, &str)] = &[
        ("RefreshBody", "refresh_token"),
        ("MfaVerifyBody", "mfa_token"),
        ("InvitationAcceptBody", "token"),
        ("SmtpSettingsPatchDto", "password"),
    ];
    // Names that merely *mention* a credential without carrying one.
    const NOT_A_CREDENTIAL: &[(&str, &str)] = &[
        ("RateLimitSettingsDto", "token_auth_fail_per_ip_minute"),
        ("TokenDto", "display_hint"),
        // A nested `TokenDto` (metadata), not the secret next to it.
        ("TokenCreatedDto", "token"),
        // A count of credentials the D37 sweep revoked, not a credential (decision 13).
        ("MembershipChangedDto", "tokens_revoked"),
        // The same shape one layer up: what an account deletion revoked, as numbers (S-29.a).
        ("AccountDeletedDto", "tokens_revoked"),
    ];

    const SUSPICIOUS: &[&str] = &["secret", "token", "password", "hash", "pepper", "kek", "private_key"];

    let app = TestApp::new().await;
    let response = app.get("/api/openapi.json", None).await;
    let schemas = response.json["components"]["schemas"].as_object().expect("schemas");
    for (name, schema) in schemas {
        let Some(properties) = schema.get("properties").and_then(|p| p.as_object()) else { continue };
        for property in properties.keys() {
            let lowered = property.to_ascii_lowercase();
            let suspicious = SUSPICIOUS.iter().any(|needle| lowered.contains(needle));
            let pair = (name.as_str(), property.as_str());
            let known = ALLOWED_OUT.contains(&pair) || ALLOWED_IN.contains(&pair) || NOT_A_CREDENTIAL.contains(&pair);
            if suspicious && !known {
                panic!("schema {name} exposes a credential-shaped field {property:?}");
            }
        }
    }
}

/// Every mutation on the app API, as `(method, path, body)`.
///
/// Kept next to [`SURFACE`] on purpose: the two lists disagreeing is how a new write endpoint
/// escapes both the anonymous check below and the S-12 guard check under it.
fn mutations() -> Vec<(axum::http::Method, String, Option<serde_json::Value>)> {
    use axum::http::Method;

    let json = |value| Some(value);
    vec![
        (Method::POST, "/api/v1/auth/logout".to_owned(), None),
        (Method::POST, "/api/v1/auth/totp/enroll".to_owned(), None),
        (Method::POST, "/api/v1/auth/totp/confirm".to_owned(), json(serde_json::json!({ "code": "000000" }))),
        (Method::DELETE, "/api/v1/auth/totp".to_owned(), None),
        (Method::POST, "/api/v1/auth/step-up".to_owned(), json(serde_json::json!({ "code": "000000" }))),
        (Method::PATCH, "/api/v1/me".to_owned(), json(serde_json::json!({ "display_name": "X" }))),
        (Method::DELETE, "/api/v1/me".to_owned(), json(serde_json::json!({ "confirm": "x@corp.com" }))),
        (Method::POST, "/api/v1/me/email".to_owned(), json(serde_json::json!({ "email": "x@corp.com" }))),
        (
            Method::POST,
            "/api/v1/me/email/verify".to_owned(),
            json(serde_json::json!({ "pending_id": "x", "code": "00000000" })),
        ),
        (Method::DELETE, "/api/v1/sessions/00000000-0000-7000-8000-000000000000".to_owned(), None),
        (Method::POST, "/api/v1/sessions/revoke-all".to_owned(), None),
        (
            Method::POST,
            "/api/v1/tokens".to_owned(),
            json(serde_json::json!({ "org_id": "00000000-0000-7000-8000-000000000000", "scopes": ["read"] })),
        ),
        (Method::DELETE, "/api/v1/tokens/00000000-0000-7000-8000-000000000000".to_owned(), None),
        (Method::POST, "/api/v1/orgs".to_owned(), json(serde_json::json!({ "name": "X", "slug": "xx" }))),
        (Method::PATCH, "/api/v1/orgs/acme".to_owned(), json(serde_json::json!({ "name": "X" }))),
        (Method::DELETE, "/api/v1/orgs/acme".to_owned(), json(serde_json::json!({ "confirm": "acme" }))),
        (Method::POST, "/api/v1/orgs/acme/members".to_owned(), json(serde_json::json!({ "email": "x@corp.com" }))),
        (
            Method::PATCH,
            "/api/v1/orgs/acme/members/00000000-0000-7000-8000-000000000000".to_owned(),
            json(serde_json::json!({ "role": "read" })),
        ),
        (Method::DELETE, "/api/v1/orgs/acme/members/00000000-0000-7000-8000-000000000000".to_owned(), None),
        (Method::POST, "/api/v1/orgs/acme/invitations".to_owned(), json(serde_json::json!({ "email": "x@corp.com" }))),
        (Method::DELETE, "/api/v1/orgs/acme/invitations/00000000-0000-7000-8000-000000000000".to_owned(), None),
        (Method::DELETE, "/api/v1/orgs/acme/membership".to_owned(), None),
        (Method::POST, "/api/v1/invitations/accept".to_owned(), json(serde_json::json!({ "token": "x" }))),
        (Method::PATCH, "/api/v1/packages/acme_core/options".to_owned(), json(serde_json::json!({ "unlisted": true }))),
        (Method::POST, "/api/v1/packages/acme_core/versions/1.0.0/retract".to_owned(), None),
        (Method::POST, "/api/v1/packages/acme_core/versions/1.0.0/unretract".to_owned(), None),
        (
            Method::DELETE,
            "/api/v1/packages/acme_core/versions/1.0.0".to_owned(),
            json(serde_json::json!({ "confirm": "acme_core@1.0.0", "reason": "why" })),
        ),
        (
            Method::POST,
            "/api/v1/packages/acme_core/transfer".to_owned(),
            json(serde_json::json!({ "target_org": "other", "confirm": "acme_core" })),
        ),
        (Method::POST, "/api/v1/notifications/read".to_owned(), json(serde_json::json!({ "all": true }))),
        (
            Method::PATCH,
            "/api/v1/notifications/preferences".to_owned(),
            json(serde_json::json!({ "preferences": [{ "category": "org", "in_app": true, "email": true }] })),
        ),
        (Method::PATCH, "/api/v1/admin/settings".to_owned(), json(serde_json::json!({}))),
        (Method::POST, "/api/v1/admin/settings/smtp/test".to_owned(), None),
        (
            Method::PATCH,
            "/api/v1/admin/orgs/00000000-0000-7000-8000-000000000000".to_owned(),
            json(serde_json::json!({ "storage_quota_bytes": 1024 })),
        ),
        (Method::POST, "/api/v1/admin/users/00000000-0000-7000-8000-000000000000/suspend".to_owned(), None),
        (Method::POST, "/api/v1/admin/users/00000000-0000-7000-8000-000000000000/unsuspend".to_owned(), None),
        (Method::POST, "/api/v1/admin/jobs/reindex/run".to_owned(), None),
    ]
}

#[tokio::test]
async fn every_mutation_refuses_an_anonymous_caller() {
    // A route registered without an auth extractor would answer 400/404/409 here instead of
    // 401 — the failure this walk exists to catch.
    let app = TestApp::new().await;
    for (method, path, body) in mutations() {
        let response = app.send(app.request(method.clone(), &path, None, body, common::DEFAULT_IP)).await;
        assert_eq!(response.status, StatusCode::UNAUTHORIZED, "{method} {path} answered {:?}", response.json);
        assert_eq!(response.json["error"]["code"], "unauthorized", "{method} {path}");
    }
}

#[tokio::test]
async fn s12_every_mutation_demands_the_custom_header() {
    // The guard is a middleware, so this is really a test that no mutation route escapes the
    // `/api/` prefix it is scoped to — a `/v1/...` typo would silently opt out of CSRF defence.
    use axum::body::Body;
    use axum::http::{Request, header};

    let app = TestApp::new().await;
    for (method, path, body) in mutations() {
        let mut builder = Request::builder().method(method.clone()).uri(&path).header("x-forwarded-for", "203.0.113.7");
        let request = match body {
            Some(json) => builder
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(serde_json::to_vec(&json).unwrap()))
                .unwrap(),
            None => {
                builder = builder.header(header::CONTENT_TYPE, "application/json");
                builder.body(Body::empty()).unwrap()
            }
        };
        let response = app.send(request).await;
        assert_eq!(response.status, StatusCode::FORBIDDEN, "{method} {path} answered {:?}", response.json);
        assert_eq!(response.json["error"]["code"], "forbidden", "{method} {path}");
    }
}

#[tokio::test]
async fn the_event_stream_documents_its_media_type_and_replay_header() {
    // The frontend generates its client from this document; a stream typed `application/json`
    // would produce a client that tries to parse the whole body.
    let app = TestApp::new().await;
    let response = app.get("/api/openapi.json", None).await;
    let operation = &response.json["paths"]["/api/v1/events"]["get"];
    assert!(
        operation["responses"]["200"]["content"]["text/event-stream"].is_object(),
        "the SSE response must be typed text/event-stream: {}",
        serde_json::to_string_pretty(&operation["responses"]).unwrap()
    );
    let params: Vec<&str> =
        operation["parameters"].as_array().expect("params").iter().map(|p| p["name"].as_str().unwrap()).collect();
    assert!(params.contains(&"Last-Event-ID"), "the replay header must be documented: {params:?}");
}
