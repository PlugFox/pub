//! The public read model end to end: search, package pages, version lists, the reverse
//! dependency graph, the landing dashboard, org profiles, and download counting.
//!
//! Everything here drives the **real** router over the real publish pipeline — packages arrive
//! through the three-step pub protocol flow, so the search index these tests query is the one
//! the publish path wrote, not a fixture. That is the point: the index is derived data, and a
//! suite that seeded it directly would pass while the maintenance path was broken.
//!
//! Two properties get the most attention, because they are the ones that fail quietly:
//!
//! - **S-04 visibility.** A private package must be absent from search, facets, counters, the
//!   org profile, the dependents graph, and every by-name route — with the same 404 an unknown
//!   name gets. [`s04_private_packages_are_invisible_on_every_read_route`] walks all of them.
//! - **Cursor stability.** A cursor is bound to its ordering and must neither skip nor repeat.

mod common;

use std::sync::Arc;

use axum::http::{Method, StatusCode};
use chrono::Duration;
use common::{TestApp, package_archive, package_archive_with};
use pub_core::package::{PackageOptions, Visibility};
use pub_core::{Format, OrgId};
use pub_jobs::{DownloadRollup, DownloadRollupPolicy};
use pub_registry::ActorMeta;
use pub_registry::index::LATEST_WINDOW;

/// A signed-in org owner whose access token actually carries the org's role claim.
///
/// The re-login is load-bearing: role levels live in the JWT (decision 03), and the token
/// minted before the org existed does not carry a claim for it.
struct Owner {
    access: String,
    token: String,
    org: OrgId,
    slug: String,
    email: String,
}

async fn owner(app: &TestApp, email: &str, slug: &str) -> Owner {
    let (access, org) = app.org_owner(email, slug).await;
    let token = app.mint_token(&access, org, &["read", "publish", "retract"]).await;
    let access = app.login(email).await["access_token"].as_str().expect("access token").to_owned();
    Owner { access, token, org, slug: slug.to_owned(), email: email.to_owned() }
}

impl Owner {
    fn base(&self) -> String {
        format!("/o/{}/pub", self.slug)
    }
}

/// Publishes an archive through the real three-step flow.
async fn publish(app: &TestApp, owner: &Owner, archive: &[u8]) {
    let response = app.publish(&owner.base(), &owner.token, archive).await;
    assert_eq!(response.status, StatusCode::OK, "publish failed: {:?}", response.json);
}

/// Flips a package to public through the registry **service**, so the search index is
/// refreshed the way a future package-settings endpoint will refresh it.
async fn make_public(app: &TestApp, owner: &Owner, name: &str) {
    set_options(app, owner, name, |options| options.visibility = Visibility::Public).await;
}

async fn set_options(app: &TestApp, owner: &Owner, name: &str, mutate: impl FnOnce(&mut PackageOptions)) {
    let package = app.repos.packages.get_by_name(Format::Pub, name).await.unwrap().expect("package");
    let mut options = PackageOptions::from(&package);
    mutate(&mut options);
    let user = app.user_of(&owner.email).await;
    app.state
        .registry
        .set_options(Format::Pub, owner.org, name, &options, &ActorMeta::user(user), app.now())
        .await
        .expect("set options");
}

/// The names in an enveloped search/listing response.
fn names(json: &serde_json::Value) -> Vec<String> {
    item_names(&json["data"])
}

/// The names inside a bare `{items, cursor, has_more}` payload.
fn item_names(list: &serde_json::Value) -> Vec<String> {
    list["items"]
        .as_array()
        .unwrap_or_else(|| panic!("expected an items array, got {list}"))
        .iter()
        .map(|item| item["name"].as_str().expect("name").to_owned())
        .collect()
}

/// A public package with a rich pubspec, published and made public.
async fn seed_public(app: &TestApp, owner: &Owner, name: &str, version: &str, extra: &str, readme: &str) {
    publish(app, owner, &package_archive_with(name, version, extra, readme)).await;
    make_public(app, owner, name).await;
}

// ------------------------------------------------------------------------------------ search

#[tokio::test]
async fn publishing_indexes_the_package_and_search_finds_it() {
    let app = TestApp::new().await;
    let acme = owner(&app, "alice@corp.com", "acme").await;
    seed_public(
        &app,
        &acme,
        "acme_bloc",
        "1.0.0",
        "description: Predictable state management.\ntopics:\n  - state-management\ndependencies:\n  meta: ^1.0.0\n",
        "# acme_bloc\n\nA tiny state container.\n",
    )
    .await;

    // Nothing was seeded into the index by hand: the publish pipeline wrote this document.
    let response = app.get("/api/v1/packages?q=acme_bloc", None).await;
    assert_eq!(response.status, StatusCode::OK, "{:?}", response.json);
    assert_eq!(names(&response.json), vec!["acme_bloc".to_owned()]);

    let hit = &response.json["data"]["items"][0];
    assert_eq!(hit["description"], "Predictable state management.");
    assert_eq!(hit["latest_version"], "1.0.0");
    assert_eq!(hit["versions_count"], 1);
    assert_eq!(hit["org"], "acme");
    assert_eq!(hit["topics"][0], "state-management");
    assert_eq!(response.json["data"]["total"], 1);
    assert_eq!(response.json["data"]["facets"]["orgs"][0]["value"], "acme");
    assert_eq!(response.json["data"]["sort"], "relevance");

    // Description and README text are searchable, not only the name.
    assert_eq!(names(&app.get("/api/v1/packages?q=predictable", None).await.json), vec!["acme_bloc".to_owned()]);
    assert_eq!(names(&app.get("/api/v1/packages?q=container", None).await.json), vec!["acme_bloc".to_owned()]);
    // …and so are the filter dimensions.
    assert_eq!(names(&app.get("/api/v1/packages?q=topic:state-management", None).await.json).len(), 1);
    assert_eq!(names(&app.get("/api/v1/packages?q=dependency:meta", None).await.json).len(), 1);
}

#[tokio::test]
async fn search_rejects_a_cursor_from_another_ordering_and_pages_without_gaps() {
    let app = TestApp::new().await;
    let acme = owner(&app, "alice@corp.com", "acme").await;
    for name in ["acme_a", "acme_b", "acme_c"] {
        seed_public(&app, &acme, name, "1.0.0", "description: Fixture.\n", "# fixture\n").await;
    }

    let mut seen = Vec::new();
    let mut url = "/api/v1/packages?sort=name&limit=1".to_owned();
    loop {
        let page = app.get(&url, None).await;
        assert_eq!(page.status, StatusCode::OK, "{:?}", page.json);
        seen.extend(names(&page.json));
        let Some(cursor) = page.json["data"]["cursor"].as_str() else { break };
        url = format!("/api/v1/packages?sort=name&limit=1&cursor={}", urlencoding(cursor));
    }
    assert_eq!(seen, vec!["acme_a".to_owned(), "acme_b".to_owned(), "acme_c".to_owned()], "no gaps or repeats");

    // A cursor carries the ordering it was produced under; reusing it elsewhere is a clean 400,
    // not a silently reshuffled page.
    let first = app.get("/api/v1/packages?sort=name&limit=1", None).await;
    let cursor = first.json["data"]["cursor"].as_str().expect("cursor").to_owned();
    let wrong =
        app.get(&format!("/api/v1/packages?sort=downloads&limit=1&cursor={}", urlencoding(&cursor)), None).await;
    assert_eq!(wrong.status, StatusCode::BAD_REQUEST);
    assert_eq!(wrong.error_code(), "invalid_argument");

    // So is a malformed one, and an unknown sort — both in the app-API envelope, because a
    // query-string mistake is a client error like any other and the UI parses one shape.
    for path in ["/api/v1/packages?cursor=%%%", "/api/v1/packages?sort=sideways", "/api/v1/packages?limit=x"] {
        let response = app.get(path, None).await;
        assert_eq!(response.status, StatusCode::BAD_REQUEST, "{path}");
        assert_eq!(response.json["status"], "error", "{path} must answer in the envelope: {:?}", response.json);
        assert!(response.json["error"]["code"].is_string(), "{path}: {:?}", response.json);
    }
}

#[tokio::test]
async fn unknown_filters_are_reported_rather_than_silently_searched() {
    let app = TestApp::new().await;
    let acme = owner(&app, "alice@corp.com", "acme").await;
    seed_public(&app, &acme, "acme_core", "1.0.0", "description: Fixture.\n", "# fixture\n").await;

    let response = app.get("/api/v1/packages?q=license:mit%20is:sponsored", None).await;
    assert_eq!(response.status, StatusCode::OK);
    let unknown: Vec<&str> =
        response.json["data"]["unknown_filters"].as_array().unwrap().iter().map(|v| v.as_str().unwrap()).collect();
    assert_eq!(unknown, vec!["license:mit", "is:sponsored"]);
    // The tokens are dropped, not searched as text — the whole (visible) set comes back.
    assert_eq!(names(&response.json), vec!["acme_core".to_owned()]);

    // Injection attempts are terms, never syntax: no error, no full listing, no results.
    for probe in ["'%3B%20DROP%20TABLE%20packages%3B%20--", "%25%25%25", "%22)%20OR%201%3D1%20--"] {
        let response = app.get(&format!("/api/v1/packages?q={probe}"), None).await;
        assert_eq!(response.status, StatusCode::OK, "{probe}: {:?}", response.json);
        assert!(names(&response.json).is_empty(), "{probe} matched something");
    }
}

// -------------------------------------------------------------------------------- visibility

#[tokio::test]
async fn s04_private_packages_are_invisible_on_every_read_route() {
    let app = TestApp::new().await;
    let acme = owner(&app, "alice@corp.com", "acme").await;
    let other = owner(&app, "bob@corp.com", "other").await;

    // `acme_secret` stays private; `acme_open` is published to the instance.
    publish(&app, &acme, &package_archive_with("acme_secret", "1.0.0", "description: Internal.\n", "# secret\n")).await;
    seed_public(&app, &acme, "acme_open", "1.0.0", "description: Internal.\n", "# open\n").await;
    // A dependent of the private package, owned by the outsider — the dependents graph must not
    // become a back door to the private name either.
    seed_public(
        &app,
        &other,
        "other_app",
        "1.0.0",
        "description: Consumer.\ndependencies:\n  acme_secret: ^1.0.0\n",
        "# app\n",
    )
    .await;

    let member = Some(acme.access.as_str());
    let outsider = Some(other.access.as_str());

    // 1. Search: the private name never appears, and asking for it by name or by `is:private`
    // does not conjure it.
    for probe in ["q=acme_secret", "q=internal", "q=is:private", "q=org:acme", ""] {
        for (label, token) in [("anonymous", None), ("outsider", outsider)] {
            let response = app.get(&format!("/api/v1/packages?{probe}"), token).await;
            assert!(
                !names(&response.json).contains(&"acme_secret".to_owned()),
                "{label} saw acme_secret through {probe:?}"
            );
        }
    }
    assert!(names(&app.get("/api/v1/packages?q=is:private", member).await.json).contains(&"acme_secret".to_owned()));

    // 2. Facets and counters agree with the listing, or the count leaks what the listing hides.
    let anonymous_view = app.get("/api/v1/packages", None).await;
    assert_eq!(anonymous_view.json["data"]["total"], 2, "acme_open + other_app");
    assert_eq!(app.get("/api/v1/packages", member).await.json["data"]["total"], 3);
    assert_eq!(app.get("/api/v1/home", None).await.json["data"]["counters"]["packages"], 2);
    assert_eq!(app.get("/api/v1/home", member).await.json["data"]["counters"]["packages"], 3);

    // 3. Every by-name route answers the anti-enumeration 404 — the same one an unknown name
    // gets, down to the message template. (The message quotes the name the *caller* supplied,
    // which they already know; what must not differ is anything derived from our state.)
    let unknown = app.get("/api/v1/packages/acme_unknown", None).await;
    for (label, token) in [("anonymous", None), ("outsider", outsider)] {
        for path in [
            "/api/v1/packages/acme_secret",
            "/api/v1/packages/acme_secret/versions",
            "/api/v1/packages/acme_secret/versions/1.0.0",
            "/api/v1/packages/acme_secret/dependents",
        ] {
            let response = app.get(path, token).await;
            assert_eq!(response.status, StatusCode::NOT_FOUND, "{label} on {path}");
            assert_eq!(response.error_code(), "not_found");
        }
        let response = app.get("/api/v1/packages/acme_secret", token).await;
        let normalized: serde_json::Value =
            serde_json::from_str(&response.json.to_string().replace("acme_secret", "acme_unknown")).unwrap();
        assert_eq!(normalized, unknown.json, "{label}: a private package must answer exactly like an unknown one");
    }
    // The member sees all four.
    for path in [
        "/api/v1/packages/acme_secret",
        "/api/v1/packages/acme_secret/versions",
        "/api/v1/packages/acme_secret/versions/1.0.0",
        "/api/v1/packages/acme_secret/dependents",
    ] {
        assert_eq!(app.get(path, member).await.status, StatusCode::OK, "member on {path}");
    }

    // 4. The dependents graph does not leak the *dependent* either: `other_app` depends on the
    // private package, and only somebody who can read the private package can ask the question.
    let dependents = app.get("/api/v1/packages/acme_secret/dependents", member).await;
    assert_eq!(names(&dependents.json), vec!["other_app".to_owned()]);

    // 5. The org profile is filtered by the same predicate.
    assert_eq!(
        item_names(&app.get("/api/v1/orgs/acme", None).await.json["data"]["packages"]),
        vec!["acme_open".to_owned()]
    );
    let mut visible = item_names(&app.get("/api/v1/orgs/acme", member).await.json["data"]["packages"]);
    visible.sort();
    assert_eq!(visible, vec!["acme_open".to_owned(), "acme_secret".to_owned()]);
}

#[tokio::test]
async fn unlisted_packages_leave_discovery_but_stay_readable_by_name() {
    let app = TestApp::new().await;
    let acme = owner(&app, "alice@corp.com", "acme").await;
    seed_public(&app, &acme, "acme_hidden", "1.0.0", "description: Quiet.\n", "# hidden\n").await;
    set_options(&app, &acme, "acme_hidden", |options| options.unlisted = true).await;

    // Gone from every discovery surface for everybody outside the org…
    assert!(names(&app.get("/api/v1/packages?q=quiet", None).await.json).is_empty());
    assert!(names(&app.get("/api/v1/packages?q=is:unlisted", None).await.json).is_empty());
    assert_eq!(app.get("/api/v1/home", None).await.json["data"]["counters"]["packages"], 0);
    // …but still a real page: `unlisted` is a discovery flag, not an access-control one.
    let detail = app.get("/api/v1/packages/acme_hidden", None).await;
    assert_eq!(detail.status, StatusCode::OK);
    assert_eq!(detail.json["data"]["unlisted"], true);
    // Its own org still manages it.
    assert_eq!(
        names(&app.get("/api/v1/packages?q=is:unlisted", Some(&acme.access)).await.json),
        vec!["acme_hidden".to_owned()]
    );
}

#[tokio::test]
async fn a_rejected_credential_is_401_not_a_silent_downgrade_to_anonymous() {
    let app = TestApp::new().await;
    // Absent credentials are anonymous (decision 05); a *broken* one must not quietly become
    // anonymous, or an expired session would answer 404 for a package the user can read.
    assert_eq!(app.get("/api/v1/packages", None).await.status, StatusCode::OK);
    let response = app.get("/api/v1/packages", Some("not-a-real-token")).await;
    assert_eq!(response.status, StatusCode::UNAUTHORIZED);
    assert_eq!(response.error_code(), "unauthorized");
}

// --------------------------------------------------------------------------- package surface

#[tokio::test]
async fn package_detail_carries_the_whole_page_payload() {
    let app = TestApp::new().await;
    let acme = owner(&app, "alice@corp.com", "acme").await;
    seed_public(
        &app,
        &acme,
        "acme_core",
        "1.0.0",
        "description: Core utilities.\n\
         homepage: https://example.test/acme\n\
         repository: https://example.test/acme.git\n\
         issue_tracker: https://example.test/acme/issues\n\
         documentation: https://example.test/acme/docs\n\
         topics:\n  - utils\n",
        "# acme_core\n\nUseful **things**.\n",
    )
    .await;
    // The page's links come from the version it recommends, so the newer publish carries them.
    publish(
        &app,
        &acme,
        &package_archive_with(
            "acme_core",
            "1.1.0",
            "description: Core utilities.\n\
             homepage: https://example.test/acme\n\
             repository: https://example.test/acme.git\n\
             issue_tracker: https://example.test/acme/issues\n\
             documentation: https://example.test/acme/docs\n\
             topics:\n  - utils\n",
            "# acme_core\n\nUseful **things**.\n",
        ),
    )
    .await;

    let response = app.get("/api/v1/packages/acme_core", None).await;
    assert_eq!(response.status, StatusCode::OK, "{:?}", response.json);
    let data = &response.json["data"];
    assert_eq!(data["name"], "acme_core");
    assert_eq!(data["org"], "acme");
    assert_eq!(data["org_name"], "acme");
    assert_eq!(data["visibility"], "public");
    assert_eq!(data["latest_version"], "1.1.0", "latest follows the newest live stable");
    assert_eq!(data["versions_count"], 2);
    assert_eq!(data["discontinued"], false);
    assert_eq!(data["unlisted"], false);
    assert_eq!(data["downloads"]["total"], 0, "nothing has been downloaded yet");
    assert_eq!(data["links"]["repository"], "https://example.test/acme.git");
    assert_eq!(data["links"]["issue_tracker"], "https://example.test/acme/issues");
    assert_eq!(data["latest"]["version"], "1.1.0");
    assert_eq!(data["latest"]["retracted"], false);
    assert!(data["latest"]["archive_sha256"].as_str().unwrap().len() == 64);
    // S-11: the README is rendered and sanitized at publish, and served as HTML.
    let readme = data["readme_html"].as_str().expect("readme html");
    assert!(readme.contains("<h1>"), "{readme}");
    assert!(!readme.contains("<script"), "{readme}");

    // The publisher account is visible inside the org and withheld outside it.
    assert!(
        app.get("/api/v1/packages/acme_core", Some(&acme.access)).await.json["data"]["latest"]["publisher"].is_object()
    );
    assert!(data["latest"]["publisher"].is_null(), "an anonymous visitor gets the org, not the account");

    // Discontinued/replaced-by are package-level flags the page renders.
    set_options(&app, &acme, "acme_core", |options| {
        options.discontinued = true;
        options.replaced_by = Some("acme_core2".to_owned());
    })
    .await;
    let response = app.get("/api/v1/packages/acme_core", None).await;
    assert_eq!(response.json["data"]["discontinued"], true);
    assert_eq!(response.json["data"]["replaced_by"], "acme_core2");
    // …and the index is refreshed in the same breath, so search agrees with the page.
    assert_eq!(names(&app.get("/api/v1/packages?q=is:discontinued", None).await.json), vec!["acme_core".to_owned()]);
}

#[tokio::test]
async fn version_list_is_newest_first_and_pages_without_gaps() {
    let app = TestApp::new().await;
    let acme = owner(&app, "alice@corp.com", "acme").await;
    let ordered = ["1.0.0", "1.0.1", "1.1.0", "2.0.0-beta.1", "2.0.0"];
    for version in ordered {
        publish(&app, &acme, &package_archive("acme_core", version)).await;
    }
    make_public(&app, &acme, "acme_core").await;

    let mut seen = Vec::new();
    let mut url = "/api/v1/packages/acme_core/versions?limit=2".to_owned();
    loop {
        let page = app.get(&url, None).await;
        assert_eq!(page.status, StatusCode::OK, "{:?}", page.json);
        seen.extend(
            page.json["data"]["items"].as_array().unwrap().iter().map(|v| v["version"].as_str().unwrap().to_owned()),
        );
        let Some(cursor) = page.json["data"]["cursor"].as_str() else { break };
        url = format!("/api/v1/packages/acme_core/versions?limit=2&cursor={}", urlencoding(cursor));
    }
    let mut expected: Vec<String> = ordered.iter().map(|v| (*v).to_owned()).collect();
    expected.reverse();
    assert_eq!(seen, expected, "newest first, semver precedence, no gaps");

    // Retraction shows up as a flag on the row, not as a removal (sharp edge 9).
    app.state
        .registry
        .set_retracted(
            pub_registry::RetractRequest {
                format: Format::Pub,
                org_id: acme.org,
                name: "acme_core".to_owned(),
                version: pub_core::SemVer::parse("2.0.0").unwrap(),
                retracted: true,
                actor: ActorMeta::user(app.user_of(&acme.email).await),
            },
            app.now(),
        )
        .await
        .expect("retract");
    let list = app.get("/api/v1/packages/acme_core/versions?limit=50", None).await;
    let newest = &list.json["data"]["items"][0];
    assert_eq!(newest["version"], "2.0.0");
    assert_eq!(newest["retracted"], true);
    assert!(newest["retracted_at"].is_string());

    // Retraction moves `latest` and flips the search flag, because it reindexed.
    let detail = app.get("/api/v1/packages/acme_core", None).await;
    assert_eq!(detail.json["data"]["latest_version"], "1.1.0", "the newest live stable");
    assert_eq!(detail.json["data"]["latest_retracted"], true, "…but the newest version is retracted");
    assert_eq!(
        names(&app.get("/api/v1/packages?q=is:retracted-latest", None).await.json),
        vec!["acme_core".to_owned()]
    );

    assert_eq!(app.get("/api/v1/packages/acme_core/versions?cursor=%%%", None).await.status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn version_detail_serves_rendered_html_and_the_pubspec() {
    let app = TestApp::new().await;
    let acme = owner(&app, "alice@corp.com", "acme").await;
    seed_public(&app, &acme, "acme_core", "1.2.3", "description: Core.\n", "# acme_core\n\nHello.\n").await;

    let response = app.get("/api/v1/packages/acme_core/versions/1.2.3", None).await;
    assert_eq!(response.status, StatusCode::OK, "{:?}", response.json);
    let data = &response.json["data"];
    assert_eq!(data["name"], "acme_core");
    assert_eq!(data["version"], "1.2.3");
    assert_eq!(data["pubspec"]["name"], "acme_core");
    assert_eq!(data["pubspec"]["description"], "Core.");
    assert!(data["readme_html"].as_str().unwrap().contains("Hello."));
    assert!(data["changelog_html"].as_str().unwrap().contains("Released."));
    // The archive URL is the org's virtual base — the same URL `dart pub` downloads from, so a
    // browser download and a resolve fetch identical bytes through identical policy.
    assert_eq!(
        data["archive_url"],
        format!("{}/o/acme/pub/api/archives/acme_core-1.2.3.tar.gz", common::INSTANCE_ORIGIN)
    );
    let path = app.proxied(data["archive_url"].as_str().unwrap());
    assert_eq!(app.pub_get_raw(&path, None).await.status, StatusCode::OK, "the advertised URL must actually serve");

    // Unknown and unparseable versions are the same 404 (no version-syntax oracle).
    for version in ["9.9.9", "not-a-version", "1.2.3-"] {
        let response = app.get(&format!("/api/v1/packages/acme_core/versions/{version}"), None).await;
        assert_eq!(response.status, StatusCode::NOT_FOUND, "{version}");
    }
}

#[tokio::test]
async fn dependents_are_read_from_the_stored_pubspecs() {
    let app = TestApp::new().await;
    let acme = owner(&app, "alice@corp.com", "acme").await;
    seed_public(&app, &acme, "acme_base", "1.0.0", "description: Base.\n", "# base\n").await;
    seed_public(
        &app,
        &acme,
        "acme_widgets",
        "1.0.0",
        "description: Widgets.\ndependencies:\n  acme_base: ^1.0.0\n",
        "# widgets\n",
    )
    .await;
    seed_public(
        &app,
        &acme,
        "acme_tools",
        "1.0.0",
        "description: Tools.\ndev_dependencies:\n  acme_base: ^1.0.0\n",
        "# tools\n",
    )
    .await;
    seed_public(&app, &acme, "acme_alone", "1.0.0", "description: Alone.\n", "# alone\n").await;

    // Both dependency kinds count as depending on the package.
    let response = app.get("/api/v1/packages/acme_base/dependents", None).await;
    assert_eq!(response.status, StatusCode::OK, "{:?}", response.json);
    assert_eq!(names(&response.json), vec!["acme_tools".to_owned(), "acme_widgets".to_owned()]);
    assert!(
        app.get("/api/v1/packages/acme_alone/dependents", None).await.json["data"]["items"]
            .as_array()
            .unwrap()
            .is_empty()
    );

    // The graph tracks the *newest* pubspec: dropping the dependency drops the edge.
    publish(&app, &acme, &package_archive_with("acme_widgets", "2.0.0", "description: Widgets.\n", "# widgets\n"))
        .await;
    assert_eq!(
        names(&app.get("/api/v1/packages/acme_base/dependents", None).await.json),
        vec!["acme_tools".to_owned()]
    );
}

// ------------------------------------------------------------------------------- home & orgs

#[tokio::test]
async fn home_carries_branding_counters_and_both_rails() {
    let app = TestApp::new().await;
    let acme = owner(&app, "alice@corp.com", "acme").await;
    seed_public(&app, &acme, "acme_one", "1.0.0", "description: One.\n", "# one\n").await;
    app.advance(Duration::hours(1));
    seed_public(&app, &acme, "acme_two", "1.0.0", "description: Two.\n", "# two\n").await;

    let response = app.get("/api/v1/home", None).await;
    assert_eq!(response.status, StatusCode::OK, "{:?}", response.json);
    let data = &response.json["data"];
    assert_eq!(data["instance"]["name"], "Pub", "decision 17 default");
    assert_eq!(data["instance"]["public_url"], common::INSTANCE_ORIGIN);
    assert!(data["instance"]["tagline"].is_null(), "an unset branding field is absent, not empty");
    assert_eq!(data["counters"]["packages"], 2);
    assert_eq!(data["counters"]["versions"], 2);
    assert_eq!(data["counters"]["orgs"], 1);
    assert_eq!(
        data["recently_updated"].as_array().unwrap()[0]["name"],
        "acme_two",
        "the newest publish leads the rail"
    );
    assert_eq!(data["most_downloaded"].as_array().unwrap().len(), 2, "the rail renders even with no statistics");
}

#[tokio::test]
async fn org_profile_is_public_and_carries_the_callers_role() {
    let app = TestApp::new().await;
    let acme = owner(&app, "alice@corp.com", "acme").await;
    let other = owner(&app, "bob@corp.com", "other").await;
    seed_public(&app, &acme, "acme_core", "1.0.0", "description: Core.\n", "# core\n").await;

    let anonymous = app.get("/api/v1/orgs/acme", None).await;
    assert_eq!(anonymous.status, StatusCode::OK, "{:?}", anonymous.json);
    assert_eq!(anonymous.json["data"]["org"]["slug"], "acme");
    assert!(anonymous.json["data"]["role"].is_null());
    assert_eq!(item_names(&anonymous.json["data"]["packages"]), vec!["acme_core".to_owned()]);

    // Decision 19 names on the wire, numbers in storage.
    let member = app.get("/api/v1/orgs/acme", Some(&acme.access)).await;
    assert_eq!(member.json["data"]["role"], "owner");
    // A member of another org holds no role here.
    assert!(app.get("/api/v1/orgs/acme", Some(&other.access)).await.json["data"]["role"].is_null());

    assert_eq!(app.get("/api/v1/orgs/nosuchorg", None).await.status, StatusCode::NOT_FOUND);
}

// ---------------------------------------------------------------------------------- download
// statistics

#[tokio::test]
async fn downloads_are_counted_on_get_and_never_on_head() {
    let app = TestApp::new().await;
    let acme = owner(&app, "alice@corp.com", "acme").await;
    seed_public(&app, &acme, "acme_core", "1.0.0", "description: Core.\n", "# core\n").await;
    let archive = format!("{}/api/archives/acme_core-1.0.0.tar.gz", acme.base());

    // The pub client HEADs an archive before every GET to check its cache. Axum routes HEAD to
    // the GET handler with the body discarded, so without an explicit check every download
    // would be counted twice — and a fully cached `pub get`, which only ever HEADs, would be
    // counted as a download nobody made.
    let head = app.send_raw(app.pub_request(Method::HEAD, &archive, None, None)).await;
    assert_eq!(head.status, StatusCode::OK);
    assert_eq!(app.state.downloads.pending(), 0, "HEAD must not count");

    for _ in 0..3 {
        assert_eq!(app.pub_get_raw(&archive, None).await.status, StatusCode::OK);
    }
    assert_eq!(app.state.downloads.pending(), 1, "three downloads of one version collapse into one bucket");

    // The rollup job is the only thing that moves buffered counts into the database.
    let policy = DownloadRollupPolicy { recent_window: Duration::days(30), ..DownloadRollupPolicy::default() };
    let rollup = DownloadRollup::new(app.repos.clone(), Arc::clone(&app.state.downloads), policy);
    let report = rollup.run_once(app.now()).await.expect("rollup");
    assert_eq!(report.downloads, 3);
    assert_eq!(report.packages, 1);
    assert_eq!(app.state.downloads.pending(), 0);

    // …and the counters surface on the package page and in the search index.
    let detail = app.get("/api/v1/packages/acme_core", None).await;
    assert_eq!(detail.json["data"]["downloads"]["total"], 3);
    assert_eq!(detail.json["data"]["downloads"]["recent"], 3);
    let hit = &app.get("/api/v1/packages?sort=downloads", None).await.json["data"]["items"][0];
    assert_eq!(hit["downloads"]["total"], 3);

    // A second pass with nothing buffered is a clean no-op.
    assert_eq!(rollup.run_once(app.now()).await.expect("empty rollup").downloads, 0);
}

#[tokio::test]
async fn a_proxied_download_is_not_attributed_to_a_local_package() {
    // The proxy's version rows live in `upstream_versions`; `download_stats` is keyed on
    // `versions`. Counting a proxied fetch would attribute somebody else's package to a row
    // that does not exist here — and on Postgres it would be a foreign-key violation.
    let app = TestApp::with_options(common::TestOptions { upstream: true, ..common::TestOptions::default() }).await;
    let acme = owner(&app, "alice@corp.com", "acme").await;
    app.mock_upstream().publish("http", &[("1.0.0", b"upstream-archive-bytes")]);

    let archive = format!("{}/api/archives/http-1.0.0.tar.gz", acme.base());
    assert_eq!(app.pub_get_raw(&archive, None).await.status, StatusCode::OK);
    assert_eq!(app.state.downloads.pending(), 0, "a proxied archive is not a local download");
}

// ------------------------------------------------------------------------------- openapi

/// Everything the frontend renders has to be in the generated spec: the web client's types are
/// produced from it, so a route or DTO that is missing here is a route the UI cannot call
/// (docs/rules/api.md — routes and OpenAPI can never drift).
#[tokio::test]
async fn openapi_documents_every_read_model_route_and_schema() {
    let app = TestApp::new().await;
    let response = app.get("/api/openapi.json", None).await;
    assert_eq!(response.status, StatusCode::OK);
    let paths = &response.json["paths"];
    for path in [
        "/api/v1/packages",
        "/api/v1/packages/{name}",
        "/api/v1/packages/{name}/versions",
        "/api/v1/packages/{name}/versions/{version}",
        "/api/v1/packages/{name}/dependents",
        "/api/v1/home",
        "/api/v1/orgs/{slug}",
    ] {
        assert!(paths.get(path).is_some(), "missing {path}: {}", serde_json::to_string_pretty(paths).unwrap());
        assert!(paths[path].get("get").is_some(), "{path} has no GET");
    }
    let params = paths["/api/v1/packages"]["get"]["parameters"].as_array().expect("params");
    let names: Vec<&str> = params.iter().map(|p| p["name"].as_str().unwrap()).collect();
    assert!(
        names.contains(&"q") && names.contains(&"sort") && names.contains(&"cursor") && names.contains(&"limit"),
        "{names:?}"
    );
    let schemas = &response.json["components"]["schemas"];
    for schema in
        ["SearchResultsDto", "PackageSummaryDto", "PackageDetailDto", "VersionDetailDto", "HomeDto", "OrgProfileDto"]
    {
        assert!(schemas.get(schema).is_some(), "missing schema {schema}");
    }
}

/// Minimal percent-encoding for a cursor placed in a query string.
///
/// Cursors are base64url (`[A-Za-z0-9_-]`), so only the padding-free alphabet shows up; the
/// helper exists so a future codec change fails loudly here rather than producing a silently
/// truncated query.
fn urlencoding(raw: &str) -> String {
    assert!(raw.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'), "cursor is not URL-safe: {raw}");
    raw.to_owned()
}

// ------------------------------------------------- D50: one `latest`, three surfaces, one window

/// Adds live versions straight through the repository.
///
/// The publish pipeline is the right way to create one version and the wrong way to create a
/// thousand: each would gzip, hash, untar and render an archive to prove something this test is
/// not about. The rows are exactly what all three read surfaces consume.
async fn seed_versions(app: &TestApp, owner: &Owner, name: &str, versions: impl IntoIterator<Item = String>) {
    let user = app.user_of(&owner.email).await;
    for raw in versions {
        app.repos
            .packages
            .create_version(
                pub_core::package::NewVersion {
                    format: Format::Pub,
                    package_name: name.to_owned(),
                    org_id: owner.org,
                    visibility: Visibility::Private,
                    version: pub_core::SemVer::parse(&raw).expect("valid version"),
                    pubspec: serde_json::json!({ "name": name, "version": raw, "description": "Wide fixture." }),
                    archive_sha256: "c".repeat(64),
                    archive_size: 512,
                    published_by: pub_core::package::Publisher { user_id: user, token_id: None },
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
async fn d50_latest_is_the_same_version_on_the_listing_the_page_and_the_search_document() {
    // The package D50 is about: larger than the smallest of the three windows, with **no live
    // stable release among the newest `LATEST_WINDOW` versions** and one live stable below
    // them. Before decision 32 the three surfaces bounded their reads differently and answered
    // differently — the pub protocol and the search index reached down to the old stable while
    // the package page stopped at its own 1 000 and reported the newest pre-release.
    let app = TestApp::new().await;
    let acme = owner(&app, "alice@corp.com", "acme").await;
    publish(&app, &acme, &package_archive("acme_wide", "1.0.0")).await;
    seed_versions(&app, &acme, "acme_wide", (1..=LATEST_WINDOW).map(|i| format!("1.{i}.0-beta"))).await;
    // Through the registry service, so the search document is written by the production
    // indexer over the finished 1 001-version package rather than seeded by hand.
    make_public(&app, &acme, "acme_wide").await;

    let expected = format!("1.{LATEST_WINDOW}.0-beta");
    let count = (LATEST_WINDOW + 1) as u64;

    // 1. what `dart pub` is told.
    let listing = app.pub_get(&format!("{}/api/packages/acme_wide", acme.base()), Some(&acme.token)).await;
    assert_eq!(listing.status, StatusCode::OK, "{:?}", listing.json);
    let protocol_latest = listing.json["latest"]["version"].as_str().expect("latest").to_owned();
    assert_eq!(listing.json["versions"].as_array().expect("versions").len(), count as usize);

    // 2. what the package page renders.
    let page = app.get("/api/v1/packages/acme_wide", None).await;
    assert_eq!(page.status, StatusCode::OK, "{:?}", page.json);
    let page_latest = page.json["data"]["latest_version"].as_str().expect("latest_version").to_owned();
    assert_eq!(page.json["data"]["versions_count"], count);

    // 3. what search says.
    let hits = app.get("/api/v1/packages?q=acme_wide", None).await;
    let hit = &hits.json["data"]["items"][0];
    let search_latest = hit["latest_version"].as_str().expect("latest_version").to_owned();
    assert_eq!(hit["versions_count"], count, "the count is an aggregate now, and it still covers every version");

    assert_eq!(protocol_latest, expected, "the protocol listing must not reach below the window");
    assert_eq!(page_latest, expected, "the page must not reach below the window");
    assert_eq!(search_latest, expected, "the search document must not reach below the window");
    assert_eq!(
        (protocol_latest.as_str(), page_latest.as_str()),
        (search_latest.as_str(), search_latest.as_str()),
        "three surfaces of one registry may not name three different `latest` versions"
    );

    // The window is a bound on the *rule*, not on what the surfaces carry: the old stable is
    // still listed, still installable, and still counted.
    let versions: Vec<&str> =
        listing.json["versions"].as_array().unwrap().iter().map(|v| v["version"].as_str().unwrap()).collect();
    assert_eq!(versions.first().copied(), Some("1.0.0"), "the stable below the window stays in the listing");
    assert_eq!(versions.last().copied(), Some(expected.as_str()));
}
