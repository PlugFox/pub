//! Hosted Pub Repository Spec v2 conformance suite.
//!
//! This file **is** `docs/protocol.md` in executable form: every test is named after the sharp
//! edge it pins, and every sharp edge that the current slice implements has at least one test
//! here. It drives the full router over in-memory backends the way the real `dart pub` client
//! drives a server — bearer in `Authorization`, `Accept: application/vnd.pub.v2+json`, no
//! app-API headers — and follows the URLs the server hands back rather than hardcoding them,
//! so a change to any advertised URL fails here instead of in production.
//!
//! Sharp edge → test map (numbers from docs/protocol.md § "Sharp edges"):
//!
//! | # | Behaviour | Test |
//! |---|-----------|------|
//! | 1 | 401 destroys credentials; 401/403 carry the challenge; unreadable ⇒ 404 | [`unauthenticated_private_package_is_404_not_401`], [`insufficient_scope_gets_403_with_www_authenticate`], [`invalid_token_gets_401_with_www_authenticate`], [`require_auth_for_read_makes_anonymous_reads_401`] |
//! | 2 | Permanent failures are 4xx | [`finalize_rejects_duplicate_version_with_400_not_500`], [`finalize_rejects_a_corrupt_archive_with_400`] |
//! | 3 | Archives are byte-stable, `archive_url` is ours | [`archive_bytes_are_identical_across_restarts_and_backends`], [`listing_archive_urls_point_at_our_own_base`] |
//! | 4 | `archive_url` lives under the credential prefix; presigned URLs need no auth | [`listing_archive_urls_point_at_our_own_base`], [`publish_urls_stay_under_the_base`], [`a_presigned_archive_is_a_307_that_no_cache_may_keep`], [`a_presigned_archive_is_signed_for_the_method_the_client_used`], [`a_presigned_archive_is_still_behind_the_visibility_ladder`] |
//! | 5 | Validate at finalize, not upload | [`upload_accepts_junk_and_finalize_rejects_it`] |
//! | 6 | Absent `Accept` ⇒ v2; 406 only for version mismatch | [`accept_header_absent_defaults_to_v2`], [`unsupported_api_version_gets_406`] |
//! | 7 | Full pubspec per version; a capped listing keeps its newest end | [`listing_field_types_match_the_client_parser`], [`a_listing_at_the_safety_cap_drops_the_oldest_versions_not_the_newest`] |
//! | 8 | Subpath bases work behind a reverse proxy | [`subpath_base_is_honored`] |
//! | 9 | Retracted stays downloadable; discontinued/replacedBy are listing fields | [`retracted_versions_stay_listed_flagged_and_downloadable`], [`discontinued_and_replaced_by_are_package_level_flags`] |
//! | 10 | Listing field types | [`listing_field_types_match_the_client_parser`] |
//! | 11 | Advisories — not implemented in this slice | [`advisories_are_not_advertised_until_they_exist`] |
//! | 12 | The base is the whole registry (local always wins) | [`local_names_never_fall_through_to_upstream`], [`resolution_order_follows_the_base`] |

mod common;

use axum::http::{Method, StatusCode, header};
use chrono::Duration;
use common::{ApiResponse, PUB_ACCEPT, PUB_MEDIA_TYPE, TestApp, TestDatabase, TestOptions, package_archive};
use pub_api::protocol::pub_v2::MAX_LISTED_VERSIONS;
use pub_blob::ObjectStoreBlob;
use pub_core::package::{PackageOptions, Visibility};
use pub_core::token::TokenScope;
use pub_core::{OrgId, RoleLevel, SemVer, UserId};
use std::sync::Arc;

/// An org registry base for `slug`.
fn base(slug: &str) -> String {
    format!("/o/{slug}/pub")
}

/// The public root base.
const ROOT: &str = "/pub";

/// A signed-in owner of a fresh org, plus a publish-capable token.
struct Publisher {
    org: OrgId,
    user: UserId,
    token: String,
    slug: String,
}

impl Publisher {
    fn base(&self) -> String {
        base(&self.slug)
    }
}

/// Seeds `slug` with an owner and a `read`+`publish` token minted through the real API.
async fn publisher(app: &TestApp, email: &str, slug: &str) -> Publisher {
    let (access, org) = app.org_owner(email, slug).await;
    let token = app.mint_token(&access, org, &["read", "publish"]).await;
    let user = app.user_of(email).await;
    Publisher { org, user, token, slug: slug.to_owned() }
}

/// Publishes `name`@`version` into `publisher`'s registry and asserts it succeeded.
async fn publish_ok(app: &TestApp, publisher: &Publisher, name: &str, version: &str) -> Vec<u8> {
    let archive = package_archive(name, version);
    let response = app.publish(&publisher.base(), &publisher.token, &archive).await;
    assert_eq!(response.status, StatusCode::OK, "publish failed: {:?}", response.json);
    archive
}

/// Flips a published package to public visibility (the app-facing settings API lands later).
async fn make_public(app: &TestApp, name: &str) {
    let package = app.repos.packages.get_by_name(pub_core::Format::Pub, name).await.unwrap().expect("package");
    let options = PackageOptions { visibility: Visibility::Public, ..PackageOptions::from(&package) };
    app.repos.packages.set_options(package.id, &options, app.now()).await.expect("set visibility");
}

// ------------------------------------------------------------------ sharp edge 1: the ladder

#[tokio::test]
async fn unauthenticated_private_package_is_404_not_401() {
    // Decision 05 / S-04: visibility comes first. A 401 here would confirm the name exists,
    // which is exactly the enumeration a 403-vs-404 differential enables.
    let app = TestApp::new().await;
    let acme = publisher(&app, "dev@acme.test", "acme").await;
    publish_ok(&app, &acme, "acme_core", "1.0.0").await;

    let anonymous = app.pub_get(&format!("{}/api/packages/acme_core", acme.base()), None).await;
    assert_eq!(anonymous.status, StatusCode::NOT_FOUND);
    assert!(anonymous.headers.get(header::WWW_AUTHENTICATE).is_none(), "a 404 must not hint that a token would help");
    assert_eq!(anonymous.json["error"]["code"], "not_found");
}

#[tokio::test]
async fn another_orgs_private_package_is_404_for_a_valid_token() {
    // The same 404 for an authenticated stranger: "for anonymous and authenticated principals
    // alike" (decision 05).
    let app = TestApp::new().await;
    let acme = publisher(&app, "dev@acme.test", "acme").await;
    let other = publisher(&app, "dev@other.test", "other").await;
    publish_ok(&app, &acme, "acme_core", "1.0.0").await;

    let response = app.pub_get(&format!("{}/api/packages/acme_core", other.base()), Some(&other.token)).await;
    assert_eq!(response.status, StatusCode::NOT_FOUND);
    // And the same shape as a genuinely unknown name — the two must be indistinguishable.
    let unknown = app.pub_get(&format!("{}/api/packages/never_published", other.base()), Some(&other.token)).await;
    assert_eq!(unknown.status, response.status);
    assert_eq!(unknown.json["error"]["code"], response.json["error"]["code"]);
}

#[tokio::test]
async fn insufficient_scope_gets_403_with_www_authenticate() {
    // S-14: a valid token with too little scope keeps working elsewhere, so 403 (not 401) —
    // and the challenge is the only way the CLI can tell the user what to do about it.
    let app = TestApp::new().await;
    let (access, org) = app.org_owner("dev@acme.test", "acme").await;
    let read_only = app.mint_token(&access, org, &["read"]).await;

    let response = app.pub_get(&format!("{}/api/packages/versions/new", base("acme")), Some(&read_only)).await;
    assert_eq!(response.status, StatusCode::FORBIDDEN);
    let challenge = response.headers[header::WWW_AUTHENTICATE].to_str().unwrap();
    assert!(challenge.starts_with("Bearer realm=\"pub\", message=\""), "challenge shape: {challenge}");
    assert!(challenge.contains("'publish' scope"), "the message must name the missing scope: {challenge}");
    assert_eq!(response.json["error"]["code"], "forbidden");
}

#[tokio::test]
async fn insufficient_role_gets_403_even_with_the_publish_scope() {
    // Two independent planes (decision 19 roles × S-13 scopes): a publish-scoped token whose
    // user only holds Read must not publish.
    let app = TestApp::new().await;
    let acme = publisher(&app, "dev@acme.test", "acme").await;
    let reader = app.org_owner("reader@acme.test", "readers").await;
    let reader_user = app.user_of("reader@acme.test").await;
    app.repos.orgs.add_member(acme.org, reader_user, RoleLevel::READ, app.now()).await.expect("add member");
    let token = app.insert_token(reader_user, acme.org, &[TokenScope::Publish], &[], None).await;
    let _ = reader;

    let response = app.pub_get(&format!("{}/api/packages/versions/new", acme.base()), Some(&token)).await;
    assert_eq!(response.status, StatusCode::FORBIDDEN);
    let challenge = response.headers[header::WWW_AUTHENTICATE].to_str().unwrap();
    assert!(challenge.contains("Write role"), "the message must name the missing role: {challenge}");
}

#[tokio::test]
async fn invalid_token_gets_401_with_www_authenticate() {
    // Sharp edge 1: the client deletes its stored token on 401, so the message has to be the
    // recovery instructions.
    let app = TestApp::new().await;
    let acme = publisher(&app, "dev@acme.test", "acme").await;
    publish_ok(&app, &acme, "acme_core", "1.0.0").await;

    for bad in ["pub_notarealtokenatallnotarealtoken", "garbage", ""] {
        let request =
            app.pub_request(Method::GET, &format!("{}/api/packages/acme_core", acme.base()), None, Some(PUB_ACCEPT));
        let (mut parts, body) = request.into_parts();
        parts.headers.insert(header::AUTHORIZATION, format!("Bearer {bad}").parse().unwrap());
        let response = app.send(axum::http::Request::from_parts(parts, body)).await;
        assert_eq!(response.status, StatusCode::UNAUTHORIZED, "token {bad:?} must be rejected");
        let challenge = response.headers[header::WWW_AUTHENTICATE].to_str().unwrap();
        assert!(challenge.starts_with("Bearer realm=\"pub\", message=\""), "challenge shape: {challenge}");
        assert!(challenge.contains("dart pub token add"), "the message must say how to recover: {challenge}");
    }
}

#[tokio::test]
async fn expired_and_revoked_tokens_are_indistinguishable_401s() {
    // S-14: the auth path never says *why* a credential failed.
    let app = TestApp::new().await;
    let acme = publisher(&app, "dev@acme.test", "acme").await;
    publish_ok(&app, &acme, "acme_core", "1.0.0").await;
    let expired =
        app.insert_token(acme.user, acme.org, &[TokenScope::Read], &[], Some(app.now() - Duration::days(1))).await;
    let revoked = app.insert_token(acme.user, acme.org, &[TokenScope::Read], &[], None).await;
    let revoked_id = app.repos.tokens.list_for_user(acme.user).await.unwrap().first().expect("token").id;
    app.repos.tokens.revoke(revoked_id, app.now()).await.expect("revoke");

    let path = format!("{}/api/packages/acme_core", acme.base());
    let a = app.pub_get(&path, Some(&expired)).await;
    let b = app.pub_get(&path, Some(&revoked)).await;
    assert_eq!(a.status, StatusCode::UNAUTHORIZED);
    assert_eq!(b.status, StatusCode::UNAUTHORIZED);
    assert_eq!(a.json, b.json, "expired and revoked must look identical");
}

#[tokio::test]
async fn browser_jwts_are_never_accepted_on_pub_routes() {
    // Decision 03: two credential planes, never mixed. The access JWT is a working credential
    // on `/api/v1/...` and must be worthless here.
    let app = TestApp::new().await;
    let acme = publisher(&app, "dev@acme.test", "acme").await;
    publish_ok(&app, &acme, "acme_core", "1.0.0").await;
    let login = app.login("dev@acme.test").await;
    let jwt = login["access_token"].as_str().expect("access token");

    // It works on the app API...
    let app_api = app.get("/api/v1/orgs", Some(jwt)).await;
    assert_eq!(app_api.status, StatusCode::OK);
    // ...and is rejected on the pub protocol, without ever reaching a database lookup.
    let pub_api = app.pub_get(&format!("{}/api/packages/acme_core", acme.base()), Some(jwt)).await;
    assert_eq!(pub_api.status, StatusCode::UNAUTHORIZED);
    assert!(pub_api.headers.contains_key(header::WWW_AUTHENTICATE));
}

#[tokio::test]
async fn pub_tokens_are_never_accepted_on_the_app_api() {
    // The mirror image of the rule above.
    let app = TestApp::new().await;
    let acme = publisher(&app, "dev@acme.test", "acme").await;
    let response = app.get("/api/v1/orgs", Some(&acme.token)).await;
    assert_eq!(response.status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn require_auth_for_read_makes_anonymous_reads_401() {
    // Decision 05: with nothing anonymous-readable there is nothing to enumerate, so the
    // anti-enumeration 404 gives way to the spec-mandated 401 + onboarding message.
    let app = TestApp::with_options(TestOptions { require_auth_for_read: true, ..TestOptions::default() }).await;
    let acme = publisher(&app, "dev@acme.test", "acme").await;
    publish_ok(&app, &acme, "acme_core", "1.0.0").await;
    make_public(&app, "acme_core").await;

    let anonymous = app.pub_get(&format!("{}/api/packages/acme_core", acme.base()), None).await;
    assert_eq!(anonymous.status, StatusCode::UNAUTHORIZED);
    let challenge = anonymous.headers[header::WWW_AUTHENTICATE].to_str().unwrap();
    assert!(challenge.contains("dart pub token add"), "onboarding message missing: {challenge}");
    // Even an unknown name answers 401 in this mode — nothing is readable, so nothing leaks.
    let unknown = app.pub_get(&format!("{}/api/packages/never_seen", acme.base()), None).await;
    assert_eq!(unknown.status, StatusCode::UNAUTHORIZED);
    // With a token the same package resolves.
    let authed = app.pub_get(&format!("{}/api/packages/acme_core", acme.base()), Some(&acme.token)).await;
    assert_eq!(authed.status, StatusCode::OK);
}

#[tokio::test]
async fn anonymous_read_of_a_public_package_is_allowed_by_default() {
    let app = TestApp::new().await;
    let acme = publisher(&app, "dev@acme.test", "acme").await;
    publish_ok(&app, &acme, "acme_core", "1.0.0").await;
    make_public(&app, "acme_core").await;

    let response = app.pub_get(&format!("{}/api/packages/acme_core", acme.base()), None).await;
    assert_eq!(response.status, StatusCode::OK);
    assert_eq!(response.json["name"], "acme_core");
}

#[tokio::test]
async fn s24_repeated_token_auth_failures_are_throttled_not_answered_forever() {
    // S-24: 30 failed token authentications per IP per minute, then 429 + Retry-After. The
    // 429 also protects a bystander's stored credential: the pub client deletes its token on
    // 401, never on 429.
    let app = TestApp::with_options(TestOptions { token_auth_fail_per_ip_minute: 3, ..TestOptions::default() }).await;
    let acme = publisher(&app, "dev@acme.test", "acme").await;
    publish_ok(&app, &acme, "acme_core", "1.0.0").await;
    let path = format!("{}/api/packages/acme_core", acme.base());

    for attempt in 0..3 {
        let response = app.pub_get(&path, Some("pub_bogus")).await;
        assert_eq!(response.status, StatusCode::UNAUTHORIZED, "attempt {attempt}");
    }
    let throttled = app.pub_get(&path, Some("pub_bogus")).await;
    assert_eq!(throttled.status, StatusCode::TOO_MANY_REQUESTS);
    assert!(throttled.headers.contains_key(header::RETRY_AFTER));
    // A working token is unaffected: the budget counts failures only.
    assert_eq!(app.pub_get(&path, Some(&acme.token)).await.status, StatusCode::OK);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn s24_parallel_token_auth_failures_each_spend_the_budget() {
    // S-24.d: the budget is spent with an atomic increment, so firing the failures in parallel
    // buys nothing. A `get` → decide → `set` counter lets a whole burst share one unit, which
    // hands an attacker unlimited 401s — and every one of those costs a co-located client its
    // stored credential (S-14.a).
    //
    // The pool is file-backed so the burst really overlaps (D51), but this is a wire-shape
    // guard, not the atomicity proof: measured against a reverted read-modify-write limiter it
    // still passes, because the racing window lives inside the KV and is nanoseconds wide.
    // `pub_auth::ratelimit::tests::hit_is_atomic_under_concurrency` is the discriminator — it
    // admits 20 against a budget of 5 the moment `hit` stops being one increment.
    let app = TestApp::with_options(TestOptions {
        token_auth_fail_per_ip_minute: 5,
        database: TestDatabase::FileSqlite,
        ..TestOptions::default()
    })
    .await;
    let acme = publisher(&app, "dev@acme.test", "acme").await;
    publish_ok(&app, &acme, "acme_core", "1.0.0").await;
    let path = format!("{}/api/packages/acme_core", acme.base());

    let burst = (0..30).map(|_| app.pub_request(Method::GET, &path, Some("pub_bogus"), Some(PUB_ACCEPT))).collect();
    let responses = app.send_concurrent(burst).await;

    let unauthorized = responses.iter().filter(|r| r.status == StatusCode::UNAUTHORIZED).count();
    let throttled = responses.iter().filter(|r| r.status == StatusCode::TOO_MANY_REQUESTS).count();
    assert_eq!(unauthorized, 5, "only the budget's worth of failures may be answered with a 401");
    assert_eq!(throttled, 25, "every failure past the budget must be a 429");
    for response in responses.iter().filter(|r| r.status == StatusCode::TOO_MANY_REQUESTS) {
        assert!(response.headers.contains_key(header::RETRY_AFTER));
    }
}

// --------------------------------------------------- sharp edges 3, 7, 10: the listing shape

#[tokio::test]
async fn listing_field_types_match_the_client_parser() {
    // Sharp edge 10: the client enforces these types and hard-fails on a mismatch. Sharp edge
    // 7: the whole pubspec travels per version.
    let app = TestApp::new().await;
    let acme = publisher(&app, "dev@acme.test", "acme").await;
    publish_ok(&app, &acme, "acme_core", "1.0.0").await;
    publish_ok(&app, &acme, "acme_core", "1.1.0").await;

    let response = app.pub_get(&format!("{}/api/packages/acme_core", acme.base()), Some(&acme.token)).await;
    assert_eq!(response.status, StatusCode::OK);
    assert_eq!(response.headers[header::CONTENT_TYPE], PUB_MEDIA_TYPE);

    assert_eq!(response.json["name"], "acme_core");
    assert!(response.json["isDiscontinued"].is_boolean(), "isDiscontinued must be a bool");
    assert_eq!(response.json["isDiscontinued"], false);
    assert!(response.json["replacedBy"].is_null(), "replacedBy is omitted while not discontinued");
    assert_eq!(response.json["latest"]["version"], "1.1.0", "latest must be the newest live stable");

    let versions = response.json["versions"].as_array().expect("versions array");
    assert_eq!(versions.len(), 2);
    // Ascending semver precedence — the order the repository's sort key produces.
    assert_eq!(versions[0]["version"], "1.0.0");
    assert_eq!(versions[1]["version"], "1.1.0");
    for entry in versions {
        assert!(entry["version"].is_string(), "version must be a string");
        assert!(entry["retracted"].is_boolean(), "retracted must be a bool");
        assert!(entry["archive_url"].is_string(), "archive_url must be a string");
        let sha = entry["archive_sha256"].as_str().expect("archive_sha256 must be a string");
        assert_eq!(sha.len(), 64, "archive_sha256 must be exactly 64 chars: {sha}");
        assert!(sha.chars().all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c)), "must be lowercase hex: {sha}");
        // Sharp edge 7: the full pubspec, not a summary.
        assert_eq!(entry["pubspec"]["name"], "acme_core");
        assert_eq!(entry["pubspec"]["description"], "Conformance fixture.");
    }
}

#[tokio::test]
async fn listing_archive_urls_point_at_our_own_base() {
    // Sharp edges 3 and 4: never an upstream CDN, always under the base, so the client keeps
    // attaching its credential.
    let app = TestApp::new().await;
    let acme = publisher(&app, "dev@acme.test", "acme").await;
    publish_ok(&app, &acme, "acme_core", "1.2.3").await;

    let listing = app.pub_get(&format!("{}/api/packages/acme_core", acme.base()), Some(&acme.token)).await;
    let url = listing.json["versions"][0]["archive_url"].as_str().expect("archive_url");
    assert_eq!(url, "https://pub.corp.test/o/acme/pub/api/archives/acme_core-1.2.3.tar.gz");
    let base_url = format!("https://pub.corp.test{}", acme.base());
    assert!(url.to_lowercase().starts_with(&base_url.to_lowercase()), "outside the credential prefix: {url}");
}

#[tokio::test]
async fn advisories_are_not_advertised_until_they_exist() {
    // Sharp edge 11: `advisoriesUpdated` is a *required* RFC3339 string once advertised, and
    // the client caches against it. Advertising it without an advisories endpoint would
    // either break caching or serve stale advisories, so the field must be absent.
    let app = TestApp::new().await;
    let acme = publisher(&app, "dev@acme.test", "acme").await;
    publish_ok(&app, &acme, "acme_core", "1.0.0").await;

    let listing = app.pub_get(&format!("{}/api/packages/acme_core", acme.base()), Some(&acme.token)).await;
    assert!(listing.json["advisoriesUpdated"].is_null(), "advisories must not be advertised in this slice");
    let advisories =
        app.pub_get(&format!("{}/api/packages/acme_core/advisories", acme.base()), Some(&acme.token)).await;
    assert_eq!(advisories.status, StatusCode::NOT_FOUND);
}

// ------------------------------------------------------------ sharp edges 2, 5: the publish

#[tokio::test]
async fn publish_three_step_flow_happy_path() {
    let app = TestApp::new().await;
    let acme = publisher(&app, "dev@acme.test", "acme").await;
    let archive = package_archive("acme_core", "1.0.0");

    // Step 1: `{url, fields}` under the base.
    let ticket = app.pub_get(&format!("{}/api/packages/versions/new", acme.base()), Some(&acme.token)).await;
    assert_eq!(ticket.status, StatusCode::OK);
    assert_eq!(ticket.headers[header::CONTENT_TYPE], PUB_MEDIA_TYPE);
    let upload_url = ticket.json["url"].as_str().expect("url");
    assert!(ticket.json["fields"].is_object(), "fields must be an object the client can iterate");

    // Step 2: multipart POST with field `file` ⇒ 204 + Location.
    let upload = app.pub_upload(&app.proxied(upload_url), Some(&acme.token), &archive).await;
    assert_eq!(upload.status, StatusCode::NO_CONTENT);
    assert!(upload.body.is_empty());
    let finalize_url = upload.headers[header::LOCATION].to_str().expect("location").to_owned();

    // Step 3: GET the finalize URL ⇒ 200 {"success":{"message":…}}.
    let finalize = app.pub_get(&app.proxied(&finalize_url), Some(&acme.token)).await;
    assert_eq!(finalize.status, StatusCode::OK);
    assert!(finalize.json["success"]["message"].is_string(), "spec success shape: {:?}", finalize.json);
    assert!(finalize.json["success"]["message"].as_str().unwrap().contains("acme_core"));

    // And the package is resolvable immediately afterwards.
    let listing = app.pub_get(&format!("{}/api/packages/acme_core", acme.base()), Some(&acme.token)).await;
    assert_eq!(listing.status, StatusCode::OK);
    assert_eq!(listing.json["latest"]["version"], "1.0.0");
}

#[tokio::test]
async fn publish_urls_stay_under_the_base() {
    // Sharp edge 4 / docs/protocol.md "Keep upload and finalize URLs under B": the client
    // attaches `Authorization` to steps 2 and 3 only because of the prefix rule.
    let app = TestApp::new().await;
    let acme = publisher(&app, "dev@acme.test", "acme").await;
    let expected_prefix = format!("https://pub.corp.test{}/", acme.base());

    let ticket = app.pub_get(&format!("{}/api/packages/versions/new", acme.base()), Some(&acme.token)).await;
    let upload_url = ticket.json["url"].as_str().unwrap().to_owned();
    assert!(upload_url.starts_with(&expected_prefix), "upload url outside the base: {upload_url}");

    let upload =
        app.pub_upload(&app.proxied(&upload_url), Some(&acme.token), &package_archive("acme_core", "1.0.0")).await;
    let finalize_url = upload.headers[header::LOCATION].to_str().unwrap().to_owned();
    assert!(finalize_url.starts_with(&expected_prefix), "finalize url outside the base: {finalize_url}");
}

#[tokio::test]
async fn upload_accepts_junk_and_finalize_rejects_it() {
    // Sharp edge 5: step 2 is a byte sink; every content check happens at step 3, where the
    // spec error shape renders in the CLI.
    let app = TestApp::new().await;
    let acme = publisher(&app, "dev@acme.test", "acme").await;

    let ticket = app.pub_get(&format!("{}/api/packages/versions/new", acme.base()), Some(&acme.token)).await;
    let upload =
        app.pub_upload(&app.proxied(ticket.json["url"].as_str().unwrap()), Some(&acme.token), b"not a tarball").await;
    assert_eq!(upload.status, StatusCode::NO_CONTENT, "step 2 must not validate content");

    let finalize =
        app.pub_get(&app.proxied(upload.headers[header::LOCATION].to_str().unwrap()), Some(&acme.token)).await;
    assert_eq!(finalize.status, StatusCode::BAD_REQUEST);
    assert!(finalize.json["error"]["message"].is_string(), "spec error shape: {:?}", finalize.json);
}

#[tokio::test]
async fn finalize_rejects_duplicate_version_with_400_not_500() {
    // Sharp edge 2: the client retries 5xx up to 7 times. "This version already exists" is a
    // permanent outcome and must not be hammered.
    let app = TestApp::new().await;
    let acme = publisher(&app, "dev@acme.test", "acme").await;
    let archive = publish_ok(&app, &acme, "acme_core", "1.0.0").await;

    let again = app.publish(&acme.base(), &acme.token, &archive).await;
    assert_eq!(again.status, StatusCode::BAD_REQUEST, "duplicate publish: {:?}", again.json);
    assert_eq!(again.json["error"]["code"], "conflict");
    assert!(again.json["error"]["message"].as_str().unwrap().contains("1.0.0"));
}

#[tokio::test]
async fn finalize_keeps_the_staged_upload_across_a_publish_lock_conflict() {
    // The per-name publish lock is *transient*: its holder may be this very client's first
    // finalize attempt that timed out (the client retries the same finalize URL up to 7
    // times). Burning the staged 100 MB on that conflict would turn every timeout-and-retry
    // into "publish again from scratch" — so the session must survive it, unlike every
    // permanent 400 (duplicate version, corrupt archive), whose discard behavior is pinned by
    // the surrounding tests.
    use pub_core::traits::JobLock as _;

    let app = TestApp::new().await;
    let acme = publisher(&app, "dev@acme.test", "acme").await;
    let ticket = app.pub_get(&format!("{}/api/packages/versions/new", acme.base()), Some(&acme.token)).await;
    let upload = app
        .pub_upload(
            &app.proxied(ticket.json["url"].as_str().unwrap()),
            Some(&acme.token),
            &package_archive("acme_core", "1.0.0"),
        )
        .await;
    assert_eq!(upload.status, StatusCode::NO_CONTENT);
    let finalize_url = app.proxied(upload.headers[header::LOCATION].to_str().unwrap());

    // Another publish of the same name is mid-flight: the per-name lock is held.
    let held = app
        .lock
        .try_acquire("publish:pub:acme_core", std::time::Duration::from_secs(60))
        .await
        .unwrap()
        .expect("the lock is free");
    let busy = app.pub_get(&finalize_url, Some(&acme.token)).await;
    assert_eq!(busy.status, StatusCode::BAD_REQUEST, "finalize stays inside 200-or-400: {:?}", busy.json);
    assert_eq!(busy.json["error"]["code"], "busy", "transient, distinct from the duplicate-version conflict");

    // Once the lock clears, the very same finalize URL succeeds — the staged upload survived.
    app.lock.release("publish:pub:acme_core", held).await.unwrap();
    let done = app.pub_get(&finalize_url, Some(&acme.token)).await;
    assert_eq!(done.status, StatusCode::OK, "the lock conflict must not burn the session: {:?}", done.json);

    // The successful finalize consumed the session; replaying it is the permanent 400.
    let replay = app.pub_get(&finalize_url, Some(&acme.token)).await;
    assert_eq!(replay.status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn finalize_rejects_a_corrupt_archive_with_400() {
    // Every S-20 ingest rejection is permanent; none may reach 5xx.
    let app = TestApp::new().await;
    let acme = publisher(&app, "dev@acme.test", "acme").await;

    for junk in [b"".to_vec(), b"\x1f\x8b\x08 truncated gzip".to_vec(), vec![0u8; 512]] {
        if junk.is_empty() {
            // An empty `file` field is caught at upload — there are no bytes to stage.
            let ticket = app.pub_get(&format!("{}/api/packages/versions/new", acme.base()), Some(&acme.token)).await;
            let upload =
                app.pub_upload(&app.proxied(ticket.json["url"].as_str().unwrap()), Some(&acme.token), &junk).await;
            assert_eq!(upload.status, StatusCode::BAD_REQUEST);
            continue;
        }
        let response = app.publish(&acme.base(), &acme.token, &junk).await;
        assert!(response.status.is_client_error(), "junk archive answered {}: {:?}", response.status, response.json);
        assert!(response.json["error"]["code"].is_string(), "spec error shape: {:?}", response.json);
    }
}

#[tokio::test]
async fn publish_start_carries_no_package_name_so_it_only_checks_scope() {
    // docs/protocol.md endpoint 2: name-dependent checks are impossible here. A token narrowed
    // to `acme_*` therefore passes step 1 and is stopped at finalize.
    let app = TestApp::new().await;
    let acme = publisher(&app, "dev@acme.test", "acme").await;
    let narrowed = app.insert_token(acme.user, acme.org, &[TokenScope::Publish], &["acme_*"], None).await;

    let ticket = app.pub_get(&format!("{}/api/packages/versions/new", acme.base()), Some(&narrowed)).await;
    assert_eq!(ticket.status, StatusCode::OK, "step 1 has no name to judge: {:?}", ticket.json);

    let allowed = app.publish(&acme.base(), &narrowed, &package_archive("acme_core", "1.0.0")).await;
    assert_eq!(allowed.status, StatusCode::OK, "{:?}", allowed.json);

    let refused = app.publish(&acme.base(), &narrowed, &package_archive("other_pkg", "1.0.0")).await;
    assert_eq!(refused.status, StatusCode::FORBIDDEN, "{:?}", refused.json);
    assert!(refused.headers.contains_key(header::WWW_AUTHENTICATE), "403 must carry the challenge (S-14)");
    // The refused name must not have been claimed on the way out.
    assert!(app.repos.packages.lookup_claim(pub_core::Format::Pub, "other_pkg").await.unwrap().is_none());
}

#[tokio::test]
async fn a_finalize_url_cannot_be_redeemed_by_another_credential() {
    // The finalize URL travels over the wire; provenance (S-21) is only meaningful if the
    // upload cannot be adopted by a different token.
    let app = TestApp::new().await;
    let acme = publisher(&app, "dev@acme.test", "acme").await;
    let second = app.insert_token(acme.user, acme.org, &[TokenScope::Publish], &[], None).await;

    let ticket = app.pub_get(&format!("{}/api/packages/versions/new", acme.base()), Some(&acme.token)).await;
    let upload = app
        .pub_upload(
            &app.proxied(ticket.json["url"].as_str().unwrap()),
            Some(&acme.token),
            &package_archive("acme_core", "1.0.0"),
        )
        .await;
    let finalize_url = app.proxied(upload.headers[header::LOCATION].to_str().unwrap());

    let stolen = app.pub_get(&finalize_url, Some(&second)).await;
    assert_eq!(stolen.status, StatusCode::FORBIDDEN);
    // The rightful owner can still finish.
    assert_eq!(app.pub_get(&finalize_url, Some(&acme.token)).await.status, StatusCode::OK);
}

#[tokio::test]
async fn an_upload_session_is_single_use() {
    let app = TestApp::new().await;
    let acme = publisher(&app, "dev@acme.test", "acme").await;

    let ticket = app.pub_get(&format!("{}/api/packages/versions/new", acme.base()), Some(&acme.token)).await;
    let upload = app
        .pub_upload(
            &app.proxied(ticket.json["url"].as_str().unwrap()),
            Some(&acme.token),
            &package_archive("acme_core", "1.0.0"),
        )
        .await;
    let finalize_url = app.proxied(upload.headers[header::LOCATION].to_str().unwrap());

    assert_eq!(app.pub_get(&finalize_url, Some(&acme.token)).await.status, StatusCode::OK);
    let replay = app.pub_get(&finalize_url, Some(&acme.token)).await;
    assert_eq!(replay.status, StatusCode::BAD_REQUEST, "a spent session must not publish twice");
}

#[tokio::test]
async fn publishing_at_the_public_root_is_403_with_directions() {
    // Decision 01: the public root serves public and proxied packages; publishing belongs to
    // an org's registry, and the challenge is where we say so.
    let app = TestApp::new().await;
    let acme = publisher(&app, "dev@acme.test", "acme").await;

    let response = app.pub_get(&format!("{ROOT}/api/packages/versions/new"), Some(&acme.token)).await;
    assert_eq!(response.status, StatusCode::FORBIDDEN);
    let challenge = response.headers[header::WWW_AUTHENTICATE].to_str().unwrap();
    assert!(challenge.contains("PUB_HOSTED_URL"), "message must point at the org URL: {challenge}");
}

#[tokio::test]
async fn a_token_from_another_org_cannot_publish_here() {
    let app = TestApp::new().await;
    let acme = publisher(&app, "dev@acme.test", "acme").await;
    let other = publisher(&app, "dev@other.test", "other").await;

    let response = app.pub_get(&format!("{}/api/packages/versions/new", acme.base()), Some(&other.token)).await;
    assert_eq!(response.status, StatusCode::FORBIDDEN);
    assert!(response.headers.contains_key(header::WWW_AUTHENTICATE));
    let _ = acme;
}

#[tokio::test]
async fn anonymous_publish_is_401_not_403() {
    let app = TestApp::new().await;
    let acme = publisher(&app, "dev@acme.test", "acme").await;
    let response = app.pub_get(&format!("{}/api/packages/versions/new", acme.base()), None).await;
    assert_eq!(response.status, StatusCode::UNAUTHORIZED);
    assert!(response.headers[header::WWW_AUTHENTICATE].to_str().unwrap().contains("dart pub token add"));
}

// ------------------------------------------------------- sharp edge 3: byte-stable archives

#[tokio::test]
async fn archive_bytes_are_identical_across_restarts_and_backends() {
    // The hash in a user's pubspec.lock is computed over exactly these bytes, and the client
    // hard-fails on a mismatch. Two backends, and a restart on each.
    let fs_dir = tempfile::tempdir().expect("tempdir");
    let fs_blob = Arc::new(
        ObjectStoreBlob::fs(&pub_config::BlobConfig {
            path: fs_dir.path().join("blobs").to_string_lossy().into_owned(),
            ..pub_config::BlobConfig::default()
        })
        .expect("fs blob store"),
    );
    let backends: Vec<Option<Arc<dyn pub_core::traits::BlobStore>>> =
        vec![None, Some(fs_blob as Arc<dyn pub_core::traits::BlobStore>)];

    for blob in backends {
        let app = TestApp::with_options(TestOptions { blob, ..TestOptions::default() }).await;
        let acme = publisher(&app, "dev@acme.test", "acme").await;
        let uploaded = publish_ok(&app, &acme, "acme_core", "1.0.0").await;

        let listing = app.pub_get(&format!("{}/api/packages/acme_core", acme.base()), Some(&acme.token)).await;
        let entry = &listing.json["versions"][0];
        let published_sha = entry["archive_sha256"].as_str().expect("sha").to_owned();
        let archive_url = app.proxied(entry["archive_url"].as_str().expect("url"));

        let downloaded = app.pub_get_raw(&archive_url, Some(&acme.token)).await;
        assert_eq!(downloaded.status, StatusCode::OK);
        assert_eq!(downloaded.body, uploaded, "served bytes differ from the uploaded bytes");
        assert_eq!(
            pub_registry::hex_sha256(&downloaded.body),
            published_sha,
            "served bytes do not match the listed hash"
        );
        assert_eq!(downloaded.headers[header::CONTENT_TYPE], "application/octet-stream");

        // A restart keeps the same database, blob store, and KV — and therefore the same bytes.
        let restarted = app.restart();
        let after = restarted.pub_get_raw(&archive_url, Some(&acme.token)).await;
        assert_eq!(after.status, StatusCode::OK);
        assert_eq!(after.body, uploaded, "bytes changed across a restart");
        let listing_after =
            restarted.pub_get(&format!("{}/api/packages/acme_core", acme.base()), Some(&acme.token)).await;
        assert_eq!(listing_after.json["versions"][0]["archive_sha256"], published_sha);
    }
}

#[tokio::test]
async fn a_private_archive_is_404_without_a_token_and_served_with_one() {
    let app = TestApp::new().await;
    let acme = publisher(&app, "dev@acme.test", "acme").await;
    publish_ok(&app, &acme, "acme_core", "1.0.0").await;
    let path = format!("{}/api/archives/acme_core-1.0.0.tar.gz", acme.base());

    assert_eq!(app.pub_get_raw(&path, None).await.status, StatusCode::NOT_FOUND);
    assert_eq!(app.pub_get_raw(&path, Some(&acme.token)).await.status, StatusCode::OK);
}

// ------------------------- sharp edge 4: presigned downloads (decision 34, S-18.a, roadmap D11)

/// A blob store that plans every download as a redirect, recording the method it was asked to
/// sign for.
///
/// It stands in for the S3 backend deliberately: the signing itself is offline and unit-tested
/// in `pub-blob` (`presigning_signs_the_method_the_caller_will_use` and friends), while what
/// belongs *here* is what the wire does with a `Redirect` plan — the status, the headers a
/// capability URL must and must not carry, and the fact that the visibility ladder still runs
/// in front of it. Its inner store is real, so a test that expects bytes still gets bytes.
#[derive(Debug)]
struct RedirectingBlob {
    inner: ObjectStoreBlob,
    signed_for: std::sync::Mutex<Vec<pub_core::traits::DownloadMethod>>,
}

impl RedirectingBlob {
    /// The URL every plan points at — a distinct origin, as decision 34's validator requires.
    const SIGNED: &'static str = "https://blobs.example.test/pub-blobs/archive?X-Amz-Signature=deadbeef";

    fn new() -> Self {
        Self { inner: ObjectStoreBlob::memory(), signed_for: std::sync::Mutex::new(Vec::new()) }
    }

    fn methods(&self) -> Vec<pub_core::traits::DownloadMethod> {
        self.signed_for.lock().expect("lock").clone()
    }
}

#[async_trait::async_trait]
impl pub_core::traits::BlobStore for RedirectingBlob {
    async fn ping(&self) -> pub_core::Result<()> {
        self.inner.ping().await
    }

    async fn put(&self, key: &str, bytes: bytes::Bytes) -> pub_core::Result<()> {
        self.inner.put(key, bytes).await
    }

    async fn download(
        &self,
        key: &str,
        method: pub_core::traits::DownloadMethod,
    ) -> pub_core::Result<pub_core::traits::DownloadPlan> {
        // A signing backend does not look before it signs (decision 34), but the key must still
        // be the one the caller asked for — otherwise this double would hide a steering bug.
        assert!(key.starts_with("pub/"), "unexpected blob key {key}");
        self.signed_for.lock().expect("lock").push(method);
        Ok(pub_core::traits::DownloadPlan::Redirect(Self::SIGNED.parse().expect("url")))
    }

    async fn get(&self, key: &str) -> pub_core::Result<bytes::Bytes> {
        self.inner.get(key).await
    }

    async fn delete(&self, key: &str) -> pub_core::Result<()> {
        self.inner.delete(key).await
    }

    fn list_stream<'a>(
        &'a self,
        prefix: &'a str,
    ) -> futures::stream::BoxStream<'a, pub_core::Result<pub_core::traits::BlobObject>> {
        self.inner.list_stream(prefix)
    }

    async fn list_prefixes(&self, prefix: &str) -> pub_core::Result<pub_core::traits::PrefixListing> {
        self.inner.list_prefixes(prefix).await
    }

    async fn head(&self, key: &str) -> pub_core::Result<Option<pub_core::traits::BlobObject>> {
        self.inner.head(key).await
    }
}

#[tokio::test]
async fn a_presigned_archive_is_a_307_that_no_cache_may_keep() {
    // S-18.a: the URL is a bearer capability for the length of its TTL, so the one response
    // that carries it must not be storable. The streamed path's `immutable` tier is the exact
    // opposite header, which is why this asserts what is absent as well as what is present.
    //
    // The `no-store` assertion here is the *observable* contract and nothing more: the S-28
    // response pass would supply that header for the whole pub family even if the handler set
    // nothing, so this test stays green against a handler that dropped it. What proves the
    // handler owns the guarantee is the unit test beside `redirect_to`
    // (`a_presigned_redirect_carries_no_store_without_help_from_the_middleware`).
    let blob = Arc::new(RedirectingBlob::new());
    let app = TestApp::with_options(TestOptions {
        blob: Some(Arc::clone(&blob) as Arc<dyn pub_core::traits::BlobStore>),
        ..TestOptions::default()
    })
    .await;
    let acme = publisher(&app, "dev@acme.test", "acme").await;
    publish_ok(&app, &acme, "acme_core", "1.0.0").await;
    let path = format!("{}/api/archives/acme_core-1.0.0.tar.gz", acme.base());

    let response = app.pub_get_raw(&path, Some(&acme.token)).await;
    assert_eq!(response.status, StatusCode::TEMPORARY_REDIRECT);
    assert_eq!(response.headers[header::LOCATION], RedirectingBlob::SIGNED);
    assert_eq!(response.headers[header::CACHE_CONTROL], "no-store");
    assert!(response.body.is_empty(), "the bytes come from the object store, not from us");
    assert!(!response.headers.contains_key(header::ETAG), "an ETag here would describe a body we did not send");
}

#[tokio::test]
async fn a_presigned_archive_is_signed_for_the_method_the_client_used() {
    // The pub client HEADs an archive before it GETs it, and SigV4 covers the method: a
    // GET-signed URL handed to that HEAD is refused by S3. This is the wire half of
    // `DownloadMethod` — that the request's own method reaches the plan.
    let blob = Arc::new(RedirectingBlob::new());
    let app = TestApp::with_options(TestOptions {
        blob: Some(Arc::clone(&blob) as Arc<dyn pub_core::traits::BlobStore>),
        ..TestOptions::default()
    })
    .await;
    let acme = publisher(&app, "dev@acme.test", "acme").await;
    publish_ok(&app, &acme, "acme_core", "1.0.0").await;
    let path = format!("{}/api/archives/acme_core-1.0.0.tar.gz", acme.base());

    let head = app.send_raw(app.pub_request(Method::HEAD, &path, Some(&acme.token), None)).await;
    assert_eq!(head.status, StatusCode::TEMPORARY_REDIRECT, "HEAD must be answered like GET (sharp edge 7)");
    assert_eq!(head.headers[header::LOCATION], RedirectingBlob::SIGNED);
    let get = app.pub_get_raw(&path, Some(&acme.token)).await;
    assert_eq!(get.status, StatusCode::TEMPORARY_REDIRECT);

    use pub_core::traits::DownloadMethod::{Get, Head};
    assert_eq!(blob.methods(), vec![Head, Get], "the plan must be signed for the method that asked for it");
}

#[tokio::test]
async fn a_presigned_archive_is_still_behind_the_visibility_ladder() {
    // A redirect is an authorization decision made once and then handed out, so the check that
    // precedes it is the only one there is. Anonymous and cross-org callers must never reach
    // the plan at all — asserted by the double having been asked nothing.
    let blob = Arc::new(RedirectingBlob::new());
    let app = TestApp::with_options(TestOptions {
        blob: Some(Arc::clone(&blob) as Arc<dyn pub_core::traits::BlobStore>),
        ..TestOptions::default()
    })
    .await;
    let acme = publisher(&app, "dev@acme.test", "acme").await;
    let other = publisher(&app, "dev@other.test", "other").await;
    publish_ok(&app, &acme, "acme_core", "1.0.0").await;
    let path = format!("{}/api/archives/acme_core-1.0.0.tar.gz", acme.base());

    assert_eq!(app.pub_get_raw(&path, None).await.status, StatusCode::NOT_FOUND);
    assert_eq!(app.pub_get_raw(&path, Some(&other.token)).await.status, StatusCode::NOT_FOUND);
    assert!(blob.methods().is_empty(), "no URL may be signed for a caller who cannot read the package");
    assert_eq!(app.pub_get_raw(&path, Some(&acme.token)).await.status, StatusCode::TEMPORARY_REDIRECT);
}

// ------------------------------------------------------------- sharp edge 6: API versioning

#[tokio::test]
async fn accept_header_absent_defaults_to_v2() {
    // Old clients (and every archive download) omit the header; defaulting to anything but v2
    // would break them.
    let app = TestApp::new().await;
    let acme = publisher(&app, "dev@acme.test", "acme").await;
    publish_ok(&app, &acme, "acme_core", "1.0.0").await;
    let path = format!("{}/api/packages/acme_core", acme.base());

    for accept in [None, Some("*/*"), Some("application/json"), Some(PUB_ACCEPT)] {
        let response = app.pub_get_accepting(&path, Some(&acme.token), accept).await;
        assert_eq!(response.status, StatusCode::OK, "Accept {accept:?} must be served");
        assert_eq!(response.headers[header::CONTENT_TYPE], PUB_MEDIA_TYPE);
    }
}

#[tokio::test]
async fn unsupported_api_version_gets_406() {
    // Sharp edge 6: 406 means "client too old / API version unsupported" and nothing else —
    // the CLI turns it into an upgrade prompt.
    let app = TestApp::new().await;
    let acme = publisher(&app, "dev@acme.test", "acme").await;
    publish_ok(&app, &acme, "acme_core", "1.0.0").await;
    let path = format!("{}/api/packages/acme_core", acme.base());

    let response = app.pub_get_accepting(&path, Some(&acme.token), Some("application/vnd.pub.v3+json")).await;
    assert_eq!(response.status, StatusCode::NOT_ACCEPTABLE);
    assert_eq!(response.json["error"]["code"], "unsupported_api_version");
    // A client that also accepts v2 is served rather than told to upgrade.
    let mixed = app
        .pub_get_accepting(&path, Some(&acme.token), Some("application/vnd.pub.v3+json, application/vnd.pub.v2+json"))
        .await;
    assert_eq!(mixed.status, StatusCode::OK);
}

// ------------------------------------------------------------------- sharp edge 8: subpaths

#[tokio::test]
async fn subpath_base_is_honored() {
    // Sharp edge 8: `https://host/registry/o/acme/pub` must work end to end. Every URL we emit
    // carries the prefix, because they are all built from `server.public_url`.
    let app = TestApp::with_options(TestOptions {
        public_url: "https://pub.corp.test/registry".to_owned(),
        ..TestOptions::default()
    })
    .await;
    let acme = publisher(&app, "dev@acme.test", "acme").await;

    // The publish flow follows the advertised URLs, so a lost prefix breaks it immediately.
    let uploaded = publish_ok(&app, &acme, "acme_core", "1.0.0").await;

    let listing = app.pub_get(&format!("{}/api/packages/acme_core", acme.base()), Some(&acme.token)).await;
    let url = listing.json["versions"][0]["archive_url"].as_str().unwrap();
    assert_eq!(url, "https://pub.corp.test/registry/o/acme/pub/api/archives/acme_core-1.0.0.tar.gz");

    // And downloading through the advertised (prefixed) URL returns the bytes. The reverse
    // proxy strips `/registry`, which is exactly what `app.proxied()` simulates here.
    let downloaded = app.pub_get_raw(&app.proxied(url), Some(&acme.token)).await;
    assert_eq!(downloaded.status, StatusCode::OK);
    assert_eq!(downloaded.body, uploaded);
}

// ------------------------------------------------------- sharp edge 9: retraction lifecycle

#[tokio::test]
async fn retracted_versions_stay_listed_flagged_and_downloadable() {
    // Sharp edge 9: retraction excludes a version from *new* resolution but must never break
    // a lockfile-pinned build.
    let app = TestApp::new().await;
    let acme = publisher(&app, "dev@acme.test", "acme").await;
    let uploaded = publish_ok(&app, &acme, "acme_core", "1.0.0").await;
    publish_ok(&app, &acme, "acme_core", "1.1.0").await;

    let package = app.repos.packages.get_by_name(pub_core::Format::Pub, "acme_core").await.unwrap().unwrap();
    let target =
        app.repos.packages.get_version(package.id, &SemVer::parse("1.1.0").unwrap()).await.unwrap().expect("version");
    app.repos.packages.set_retracted(target.id, true, app.now()).await.expect("retract");

    let listing = app.pub_get(&format!("{}/api/packages/acme_core", acme.base()), Some(&acme.token)).await;
    let versions = listing.json["versions"].as_array().unwrap();
    assert_eq!(versions.len(), 2, "a retracted version stays in the listing");
    assert_eq!(versions[1]["version"], "1.1.0");
    assert_eq!(versions[1]["retracted"], true);
    assert_eq!(versions[0]["retracted"], false);
    assert_eq!(listing.json["latest"]["version"], "1.0.0", "latest must skip the retracted version");

    // Still downloadable, byte-for-byte.
    let url = app.proxied(versions[0]["archive_url"].as_str().unwrap());
    let _ = &uploaded;
    assert_eq!(app.pub_get_raw(&url, Some(&acme.token)).await.status, StatusCode::OK);
    let retracted_url = app.proxied(versions[1]["archive_url"].as_str().unwrap());
    assert_eq!(app.pub_get_raw(&retracted_url, Some(&acme.token)).await.status, StatusCode::OK);
}

#[tokio::test]
async fn hard_deleted_versions_disappear_from_listings_and_downloads() {
    // Decision 06: the row survives as a tombstone so the number stays burned, but the
    // metadata and bytes are gone — the protocol surface must not serve either.
    let app = TestApp::new().await;
    let acme = publisher(&app, "dev@acme.test", "acme").await;
    publish_ok(&app, &acme, "acme_core", "1.0.0").await;
    publish_ok(&app, &acme, "acme_core", "1.1.0").await;

    let package = app.repos.packages.get_by_name(pub_core::Format::Pub, "acme_core").await.unwrap().unwrap();
    let doomed =
        app.repos.packages.get_version(package.id, &SemVer::parse("1.1.0").unwrap()).await.unwrap().expect("version");
    app.repos.packages.hard_delete_version(doomed.id).await.expect("hard delete");

    let listing = app.pub_get(&format!("{}/api/packages/acme_core", acme.base()), Some(&acme.token)).await;
    let versions = listing.json["versions"].as_array().unwrap();
    assert_eq!(versions.len(), 1);
    assert_eq!(versions[0]["version"], "1.0.0");

    let gone = format!("{}/api/archives/acme_core-1.1.0.tar.gz", acme.base());
    assert_eq!(app.pub_get_raw(&gone, Some(&acme.token)).await.status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn discontinued_and_replaced_by_are_package_level_flags() {
    let app = TestApp::new().await;
    let acme = publisher(&app, "dev@acme.test", "acme").await;
    publish_ok(&app, &acme, "acme_core", "1.0.0").await;

    let package = app.repos.packages.get_by_name(pub_core::Format::Pub, "acme_core").await.unwrap().unwrap();
    let options = PackageOptions {
        discontinued: true,
        replaced_by: Some("acme_core2".to_owned()),
        ..PackageOptions::from(&package)
    };
    app.repos.packages.set_options(package.id, &options, app.now()).await.expect("set options");

    let listing = app.pub_get(&format!("{}/api/packages/acme_core", acme.base()), Some(&acme.token)).await;
    assert_eq!(listing.json["isDiscontinued"], true);
    assert_eq!(listing.json["replacedBy"], "acme_core2");
}

// --------------------------------------------- sharp edge 12 / decision 01: resolution order

#[tokio::test]
async fn resolution_order_follows_the_base() {
    // Decision 01: org-owned → instance-public → upstream. A *public* package of another org
    // resolves inside an org base; a *private* one never does, even for its own members.
    let app = TestApp::new().await;
    let acme = publisher(&app, "dev@acme.test", "acme").await;
    let other = publisher(&app, "dev@other.test", "other").await;
    publish_ok(&app, &acme, "acme_core", "1.0.0").await;
    publish_ok(&app, &other, "shared_utils", "1.0.0").await;
    make_public(&app, "shared_utils").await;

    // Step 2 of the order: another org's public package resolves in acme's base.
    let shared = app.pub_get(&format!("{}/api/packages/shared_utils", acme.base()), Some(&acme.token)).await;
    assert_eq!(shared.status, StatusCode::OK);
    // ...and its archive_url is rewritten under *this* base, not the owning org's.
    let url = shared.json["versions"][0]["archive_url"].as_str().unwrap();
    assert!(url.contains("/o/acme/pub/"), "archive_url must stay in the requesting base: {url}");
    assert_eq!(app.pub_get_raw(&app.proxied(url), Some(&acme.token)).await.status, StatusCode::OK);

    // A member of *both* orgs still cannot see other's private package through acme's base:
    // the URL is the namespace, not the principal.
    let acme_user = app.user_of("dev@acme.test").await;
    app.repos.orgs.add_member(other.org, acme_user, RoleLevel::READ, app.now()).await.expect("add member");
    let cross = app.pub_get(&format!("{}/api/packages/other_secret", acme.base()), Some(&acme.token)).await;
    assert_eq!(cross.status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn the_public_root_serves_only_public_packages() {
    let app = TestApp::new().await;
    let acme = publisher(&app, "dev@acme.test", "acme").await;
    publish_ok(&app, &acme, "acme_core", "1.0.0").await;
    publish_ok(&app, &acme, "acme_open", "1.0.0").await;
    make_public(&app, "acme_open").await;

    assert_eq!(app.pub_get(&format!("{ROOT}/api/packages/acme_open"), None).await.status, StatusCode::OK);
    // Not even the owner's own token opens a private package at the public root — decision 01
    // does not list private packages in that base's resolution order at all.
    let private = app.pub_get(&format!("{ROOT}/api/packages/acme_core"), Some(&acme.token)).await;
    assert_eq!(private.status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn local_names_never_fall_through_to_upstream() {
    // S-16 / sharp edge 12: a name claimed on this instance is answered by this instance,
    // whatever the caller can or cannot read. Until the proxy slice lands, an *unclaimed*
    // name is the only 404 that a future upstream lookup may ever turn into a hit.
    let app = TestApp::new().await;
    let acme = publisher(&app, "dev@acme.test", "acme").await;
    let other = publisher(&app, "dev@other.test", "other").await;
    // A name that also exists on pub.dev, claimed here by acme and kept private.
    publish_ok(&app, &acme, "http", "1.0.0").await;

    let claimed = app.pub_get(&format!("{}/api/packages/http", other.base()), Some(&other.token)).await;
    let unclaimed = app.pub_get(&format!("{}/api/packages/collection", other.base()), Some(&other.token)).await;
    assert_eq!(claimed.status, StatusCode::NOT_FOUND);
    assert_eq!(unclaimed.status, StatusCode::NOT_FOUND);
    // The claim is what makes the difference structurally, not the response.
    assert!(app.repos.packages.lookup_claim(pub_core::Format::Pub, "http").await.unwrap().is_some());
    assert!(app.repos.packages.lookup_claim(pub_core::Format::Pub, "collection").await.unwrap().is_none());
    // And the holder still gets the local package.
    assert_eq!(
        app.pub_get(&format!("{}/api/packages/http", acme.base()), Some(&acme.token)).await.status,
        StatusCode::OK
    );
}

#[tokio::test]
async fn an_unknown_org_base_is_404() {
    let app = TestApp::new().await;
    let acme = publisher(&app, "dev@acme.test", "acme").await;
    let response = app.pub_get("/o/does-not-exist/pub/api/packages/acme_core", Some(&acme.token)).await;
    assert_eq!(response.status, StatusCode::NOT_FOUND);
    assert!(response.headers.get(header::WWW_AUTHENTICATE).is_none());
}

// ------------------------------------------------------------ sharp edges 6, 7: legacy paths

#[tokio::test]
async fn legacy_endpoints_work() {
    // docs/protocol.md endpoints 6 and 7 — pre-Dart-2.8 clients.
    let app = TestApp::new().await;
    let acme = publisher(&app, "dev@acme.test", "acme").await;
    let uploaded = publish_ok(&app, &acme, "acme_core", "1.0.0").await;

    let version =
        app.pub_get(&format!("{}/api/packages/acme_core/versions/1.0.0", acme.base()), Some(&acme.token)).await;
    assert_eq!(version.status, StatusCode::OK);
    assert_eq!(version.headers[header::CONTENT_TYPE], PUB_MEDIA_TYPE);
    assert_eq!(version.json["version"], "1.0.0");
    assert_eq!(version.json["archive_sha256"].as_str().unwrap().len(), 64);
    assert!(version.json["archive_url"].as_str().unwrap().ends_with("/o/acme/pub/api/archives/acme_core-1.0.0.tar.gz"));
    assert_eq!(version.json["pubspec"]["name"], "acme_core");

    let archive =
        app.pub_get_raw(&format!("{}/packages/acme_core/versions/1.0.0.tar.gz", acme.base()), Some(&acme.token)).await;
    assert_eq!(archive.status, StatusCode::OK);
    assert_eq!(archive.body, uploaded, "the legacy route must serve the same bytes");

    // The legacy routes obey the same ladder.
    assert_eq!(
        app.pub_get(&format!("{}/api/packages/acme_core/versions/1.0.0", acme.base()), None).await.status,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        app.pub_get(&format!("{}/api/packages/acme_core/versions/9.9.9", acme.base()), Some(&acme.token)).await.status,
        StatusCode::NOT_FOUND
    );
}

// -------------------------------------------------------------------------------- guardrails

#[tokio::test]
async fn pub_routes_do_not_inherit_the_app_api_mutation_guard() {
    // S-12's custom header and JSON-only rule exist for browsers; the pub client can send
    // neither, so a pub route that inherited them would be unusable.
    let app = TestApp::new().await;
    let acme = publisher(&app, "dev@acme.test", "acme").await;
    let ticket = app.pub_get(&format!("{}/api/packages/versions/new", acme.base()), Some(&acme.token)).await;
    let upload = app
        .pub_upload(
            &app.proxied(ticket.json["url"].as_str().unwrap()),
            Some(&acme.token),
            &package_archive("acme_core", "1.0.0"),
        )
        .await;
    // No `x-pub-request`, no JSON content type, and still accepted.
    assert_eq!(upload.status, StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn every_pub_error_uses_the_spec_shape_and_never_the_envelope() {
    let app = TestApp::new().await;
    let acme = publisher(&app, "dev@acme.test", "acme").await;
    let cases = [
        app.pub_get(&format!("{}/api/packages/never_published", acme.base()), Some(&acme.token)).await,
        app.pub_get(&format!("{}/api/packages/versions/new", acme.base()), None).await,
        app.pub_get_accepting(
            &format!("{}/api/packages/acme_core", acme.base()),
            Some(&acme.token),
            Some("application/vnd.pub.v9+json"),
        )
        .await,
    ];
    for response in cases {
        assert!(response.status.is_client_error(), "unexpected status {}", response.status);
        assert_eq!(response.headers[header::CONTENT_TYPE], PUB_MEDIA_TYPE);
        assert!(response.json.get("status").is_none(), "the app envelope leaked in: {:?}", response.json);
        assert!(response.json["error"]["code"].is_string(), "spec error shape: {:?}", response.json);
        assert!(response.json["error"]["message"].is_string(), "spec error shape: {:?}", response.json);
    }
}

#[tokio::test]
async fn listings_are_gzipped_and_archives_are_not() {
    // Sharp edge 7: the listing is the hot path, carries a whole pubspec per version, and the
    // client refuses to disk-cache it past ~1 MB. Archives are already gzip, so re-compressing
    // them would burn CPU and drop the Content-Length.
    let app = TestApp::new().await;
    let acme = publisher(&app, "dev@acme.test", "acme").await;
    publish_ok(&app, &acme, "acme_core", "1.0.0").await;

    let with_gzip = |path: &str| {
        let mut request = app.pub_request(Method::GET, path, Some(&acme.token), Some(PUB_ACCEPT));
        request.headers_mut().insert(header::ACCEPT_ENCODING, "gzip".parse().unwrap());
        request
    };

    let listing = app.send_raw(with_gzip(&format!("{}/api/packages/acme_core", acme.base()))).await;
    assert_eq!(listing.status, StatusCode::OK);
    assert_eq!(listing.headers[header::CONTENT_ENCODING], "gzip");

    let archive = app.send_raw(with_gzip(&format!("{}/api/archives/acme_core-1.0.0.tar.gz", acme.base()))).await;
    assert_eq!(archive.status, StatusCode::OK);
    assert!(archive.headers.get(header::CONTENT_ENCODING).is_none(), "an archive must not be double-compressed");
    assert!(archive.headers.contains_key(header::CONTENT_LENGTH));
}

#[tokio::test]
async fn both_virtual_bases_are_documented_in_the_openapi_document() {
    // docs/rules/api.md: routes and OpenAPI can never drift, and *both* mounts are real routes.
    let app = TestApp::new().await;
    let openapi = app.get("/api/openapi.json", None).await;
    assert_eq!(openapi.status, StatusCode::OK);
    let paths = openapi.json["paths"].as_object().expect("paths");
    for path in [
        "/o/{org}/pub/api/packages/{name}",
        "/o/{org}/pub/api/packages/versions/new",
        "/o/{org}/pub/api/packages/versions/newUpload",
        "/o/{org}/pub/api/packages/versions/newUploadFinish/{session}",
        "/o/{org}/pub/api/archives/{file}",
        "/o/{org}/pub/api/packages/{name}/versions/{version}",
        "/o/{org}/pub/packages/{name}/versions/{file}",
        "/pub/api/packages/{name}",
        "/pub/api/archives/{file}",
    ] {
        assert!(paths.contains_key(path), "{path} is served but undocumented");
    }
    // The spec DTOs must reach the components section too, or the generated TypeScript client
    // would type these responses as `unknown`.
    let schemas = openapi.json["components"]["schemas"].as_object().expect("schemas");
    for schema in ["PackageListing", "VersionInfo", "UploadTicket", "PublishSuccess", "SpecError"] {
        assert!(schemas.contains_key(schema), "{schema} is returned but has no schema");
    }
}

#[tokio::test]
async fn a_wrong_method_under_a_registry_base_still_answers_the_spec_shape() {
    // The router answers a known path with an unsupported method itself, before any handler —
    // as a bare 405 with no body. Under a registry base that is the same defect the
    // unimplemented-endpoint fallback exists to prevent: the client parses the body of every
    // failure, so unparseable bytes turn "wrong method" into a decoding error.
    let app = TestApp::new().await;
    let acme = publisher(&app, "dev@acme.test", "acme").await;
    publish_ok(&app, &acme, "acme_core", "1.0.0").await;

    for (method, path) in [
        (Method::POST, format!("{}/api/packages/acme_core", acme.base())),
        (Method::DELETE, format!("{}/api/archives/acme_core-1.0.0.tar.gz", acme.base())),
        (Method::GET, format!("{}/api/packages/versions/newUpload", acme.base())),
    ] {
        let response = app.send(app.pub_request(method.clone(), &path, Some(&acme.token), Some(PUB_ACCEPT))).await;
        assert_eq!(response.status, StatusCode::METHOD_NOT_ALLOWED, "{method} {path}");
        assert_eq!(response.headers[header::CONTENT_TYPE], PUB_MEDIA_TYPE, "{method} {path}");
        assert!(response.json["error"]["message"].is_string(), "{method} {path}: {:?}", response.json);
        assert!(response.status.is_client_error(), "a retryable status would loop the client");
    }
}

#[tokio::test]
async fn the_bearer_scheme_is_matched_case_insensitively() {
    // Auth schemes are case-insensitive (RFC 9110 §11.1). On this plane a rejected credential
    // is a 401 and a 401 makes the client *delete the stored token*, so header casing must
    // never cost a developer their credential.
    let app = TestApp::new().await;
    let acme = publisher(&app, "dev@acme.test", "acme").await;
    publish_ok(&app, &acme, "acme_core", "1.0.0").await;

    for scheme in ["Bearer", "bearer", "BEARER"] {
        let request =
            app.pub_request(Method::GET, &format!("{}/api/packages/acme_core", acme.base()), None, Some(PUB_ACCEPT));
        let (mut parts, body) = request.into_parts();
        parts.headers.insert(header::AUTHORIZATION, format!("{scheme} {}", acme.token).parse().unwrap());
        let response = app.send(axum::http::Request::from_parts(parts, body)).await;
        assert_eq!(response.status, StatusCode::OK, "{scheme} was rejected: {:?}", response.json);
    }
}

#[tokio::test]
async fn a_valid_credential_is_never_answered_with_401() {
    // Sharp edge 1, re-derived across the whole surface: 401 destroys the user's token, so it
    // is reserved for credentials that are absent or genuinely unusable. Every *authorization*
    // outcome — wrong scope, wrong org, wrong role, wrong base, a name held elsewhere, a
    // pattern-narrowed name, an unreadable package — must answer 403 or 404 instead.
    let app = TestApp::new().await;
    let acme = publisher(&app, "dev@acme.test", "acme").await;
    let other = publisher(&app, "dev@other.test", "other").await;
    publish_ok(&app, &acme, "acme_core", "1.0.0").await;
    let read_only = app.insert_token(acme.user, acme.org, &[TokenScope::Read], &[], None).await;
    let narrowed =
        app.insert_token(acme.user, acme.org, &[TokenScope::Read, TokenScope::Publish], &["nothing_*"], None).await;

    let cases: Vec<(&str, ApiResponse)> = vec![
        (
            "read-scoped token publishing",
            app.pub_get(&format!("{}/api/packages/versions/new", acme.base()), Some(&read_only)).await,
        ),
        (
            "token from another org",
            app.pub_get(&format!("{}/api/packages/versions/new", acme.base()), Some(&other.token)).await,
        ),
        (
            "publishing at the public root",
            app.pub_get(&format!("{ROOT}/api/packages/versions/new"), Some(&acme.token)).await,
        ),
        (
            "another org's private package",
            app.pub_get(&format!("{}/api/packages/acme_core", other.base()), Some(&other.token)).await,
        ),
        (
            "a package outside the token's patterns",
            app.pub_get(&format!("{}/api/packages/acme_core", acme.base()), Some(&narrowed)).await,
        ),
        (
            "a name claimed by another org",
            app.publish(&other.base(), &other.token, &package_archive("acme_core", "2.0.0")).await,
        ),
        (
            "a version that does not exist",
            app.pub_get(&format!("{}/api/packages/acme_core/versions/9.9.9", acme.base()), Some(&acme.token)).await,
        ),
    ];
    for (what, response) in cases {
        assert_ne!(response.status, StatusCode::UNAUTHORIZED, "{what} would delete a working token");
        assert!(
            matches!(response.status, StatusCode::FORBIDDEN | StatusCode::NOT_FOUND),
            "{what} answered {}",
            response.status
        );
        // Sharp edge 1 again: 403 must explain itself, 404 must not hint at credentials.
        if response.status == StatusCode::FORBIDDEN {
            assert!(response.headers.contains_key(header::WWW_AUTHENTICATE), "{what}: 403 without a challenge");
        } else {
            assert!(!response.headers.contains_key(header::WWW_AUTHENTICATE), "{what}: 404 with a challenge");
        }
    }
}

#[tokio::test]
async fn response_bodies_carry_exactly_the_documented_fields() {
    // Read the bytes, not the handler: the client parses these documents field by field and
    // hard-fails on a type mismatch (sharp edge 10). An extra *required*-looking field is
    // harmless (unknown fields are ignored), a missing or renamed one is not.
    let app = TestApp::new().await;
    let acme = publisher(&app, "dev@acme.test", "acme").await;
    publish_ok(&app, &acme, "acme_core", "1.0.0").await;

    let listing = app.pub_get_raw(&format!("{}/api/packages/acme_core", acme.base()), Some(&acme.token)).await;
    let parsed: serde_json::Value = serde_json::from_slice(&listing.body).expect("listings are JSON");
    let mut keys: Vec<&str> = parsed.as_object().expect("object").keys().map(String::as_str).collect();
    keys.sort_unstable();
    assert_eq!(keys, ["isDiscontinued", "latest", "name", "versions"], "listing shape changed");
    let mut version_keys: Vec<&str> =
        parsed["versions"][0].as_object().expect("object").keys().map(String::as_str).collect();
    version_keys.sort_unstable();
    assert_eq!(version_keys, ["archive_sha256", "archive_url", "pubspec", "retracted", "version"]);

    let error = app.pub_get_raw(&format!("{}/api/packages/never_published", acme.base()), Some(&acme.token)).await;
    let parsed: serde_json::Value = serde_json::from_slice(&error.body).expect("errors are JSON");
    let keys: Vec<&str> = parsed.as_object().expect("object").keys().map(String::as_str).collect();
    assert_eq!(keys, ["error"], "the spec error body is a single `error` object");
    let mut inner: Vec<&str> = parsed["error"].as_object().expect("object").keys().map(String::as_str).collect();
    inner.sort_unstable();
    assert_eq!(inner, ["code", "message"]);
}

#[tokio::test]
async fn archives_answer_head_with_the_same_metadata_as_get() {
    // The client HEADs an archive before downloading it; a 404 or a missing length there turns
    // into a failed `pub get` even though the bytes are right here.
    let app = TestApp::new().await;
    let acme = publisher(&app, "dev@acme.test", "acme").await;
    let uploaded = publish_ok(&app, &acme, "acme_core", "1.0.0").await;
    let path = format!("{}/api/archives/acme_core-1.0.0.tar.gz", acme.base());

    let head = app.send_raw(app.pub_request(Method::HEAD, &path, Some(&acme.token), None)).await;
    let get = app.pub_get_raw(&path, Some(&acme.token)).await;
    assert_eq!(head.status, StatusCode::OK);
    assert!(head.body.is_empty(), "a HEAD response carries no body");
    assert_eq!(head.headers[header::CONTENT_LENGTH], uploaded.len().to_string());
    assert_eq!(head.headers[header::CONTENT_TYPE], get.headers[header::CONTENT_TYPE]);
    assert_eq!(get.body.len(), uploaded.len());
}

#[tokio::test]
async fn a_token_query_parameter_is_not_a_credential() {
    // docs/protocol.md describes no query-parameter credential, and the client never sends
    // one. Accepting `?token=` would put live credentials into access logs and — via
    // `archive_url` — into users' pubspec.lock files.
    let app = TestApp::new().await;
    let acme = publisher(&app, "dev@acme.test", "acme").await;
    publish_ok(&app, &acme, "acme_core", "1.0.0").await;

    let response = app.pub_get(&format!("{}/api/packages/acme_core?token={}", acme.base(), acme.token), None).await;
    assert_eq!(response.status, StatusCode::NOT_FOUND, "a query token must not authenticate");
}

// --------------------------------------------- sharp edge 7: which end of a huge listing is cut

/// Adds live versions straight through the repository.
///
/// Ten thousand three-step publishes would gzip, hash, untar and render ten thousand archives
/// to prove something this test is not about. The rows are what the listing handler reads.
async fn seed_versions(app: &TestApp, publisher: &Publisher, name: &str, versions: impl IntoIterator<Item = String>) {
    for raw in versions {
        app.repos
            .packages
            .create_version(
                pub_core::package::NewVersion {
                    format: pub_core::Format::Pub,
                    package_name: name.to_owned(),
                    org_id: publisher.org,
                    visibility: Visibility::Private,
                    version: SemVer::parse(&raw).expect("valid version"),
                    pubspec: serde_json::json!({ "name": name, "version": raw }),
                    archive_sha256: "c".repeat(64),
                    archive_size: 512,
                    published_by: pub_core::package::Publisher { user_id: publisher.user, token_id: None },
                    readme_html: None,
                    changelog_html: None,
                },
                app.now(),
            )
            .await
            .expect("seed version");
    }
}

#[tokio::test]
async fn a_listing_at_the_safety_cap_drops_the_oldest_versions_not_the_newest() {
    // The cap has to cut *somewhere*; which end it cuts is the whole question. Reading
    // ascending — how it worked before decision 32 — a package past `MAX_LISTED_VERSIONS`
    // served `dart pub` a listing whose newest entries were simply absent, with `latest`
    // derived from the ~10 000th-oldest release: the package looks frozen at whatever the cap
    // reached, and a resolve cannot see anything published since. Reading descending and
    // reversing drops the oldest instead, which is the end a resolver can afford to lose.
    //
    // Built one version *over* the cap on purpose: asserted on a package that never reaches
    // the cap, every line below would pass against either direction.
    let app = TestApp::new().await;
    let acme = publisher(&app, "dev@acme.test", "acme").await;
    publish_ok(&app, &acme, "acme_core", "1.0.0").await;
    seed_versions(&app, &acme, "acme_core", (1..=MAX_LISTED_VERSIONS).map(|i| format!("1.{i}.0"))).await;
    let newest = format!("1.{MAX_LISTED_VERSIONS}.0");

    let response = app.pub_get(&format!("{}/api/packages/acme_core", acme.base()), Some(&acme.token)).await;
    assert_eq!(response.status, StatusCode::OK, "{:?}", response.json);
    let versions: Vec<&str> = response.json["versions"]
        .as_array()
        .expect("versions")
        .iter()
        .map(|v| v["version"].as_str().unwrap())
        .collect();

    assert_eq!(versions.len(), MAX_LISTED_VERSIONS, "the cap still bounds the listing");
    assert_eq!(versions.last().copied(), Some(newest.as_str()), "the newest version must survive the cap");
    assert_eq!(versions.first().copied(), Some("1.1.0"), "the oldest version is the one that gets dropped");
    assert!(!versions.contains(&"1.0.0"), "1.0.0 is the oldest of 10 001 and is exactly what the cap should drop");

    // Still ascending on the wire — the spec's order, and the order `latest` is derived from.
    // Compared on the registry's own precedence key, because as text `1.10.0` precedes `1.9.0`.
    let keys: Vec<String> = versions.iter().map(|raw| SemVer::parse(raw).expect("semver").sort_key()).collect();
    assert!(keys.windows(2).all(|pair| pair[0] < pair[1]), "the emitted listing must stay ascending by precedence");
    assert_eq!(response.json["latest"]["version"], newest, "`latest` follows the newest end, not the truncated one");
}
