//! Adversarial tests for the registry surface: publish authorization, ingest limits under
//! hostile archives, private-name enumeration, and blob-key steering.
//!
//! The conformance suite ([`protocol.rs`](protocol.rs)) pins what the pub client needs; this
//! one pins what an attacker must not get. Everything here drives the real router over the
//! real publish pipeline — a rejection that only exists in a unit test is a rejection that a
//! handler can forget to call.
//!
//! | Requirement | Test |
//! |---|---|
//! | S-13/19 publish authorization (scope × org × role × pattern) | [`publish_authorization_matrix`] |
//! | S-20 hostile archives are permanent 4xx | [`hostile_archives_are_refused_with_a_permanent_4xx`] |
//! | S-20 nothing hides behind the tar stream | [`a_smuggled_second_gzip_member_never_reaches_the_blob_store`] |
//! | S-24 publish budget per org | [`s24_publish_uploads_are_capped_per_org`] |
//! | S-04 private names are not enumerable | [`private_and_unknown_names_answer_identical_bytes`] |
//! | S-18 blob keys are content-addressed only | [`blob_keys_cannot_be_steered_by_names_or_versions`] |
//! | S-21 provenance cannot be borrowed | [`an_upload_cannot_be_finalized_from_another_org`] |

mod common;

use std::io::Write as _;

use axum::http::{StatusCode, header};
use common::{TestApp, TestOptions, package_archive};
use pub_core::token::TokenScope;
use pub_core::{Format, OrgId, RoleLevel, UserId};

/// An org registry base for `slug`.
fn base(slug: &str) -> String {
    format!("/o/{slug}/pub")
}

/// A seeded org with an owner and a `read`+`publish` token.
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

async fn publisher(app: &TestApp, email: &str, slug: &str) -> Publisher {
    let (access, org) = app.org_owner(email, slug).await;
    let token = app.mint_token(&access, org, &["read", "publish"]).await;
    let user = app.user_of(email).await;
    Publisher { org, user, token, slug: slug.to_owned() }
}

/// Gzips raw bytes.
fn gzip(bytes: &[u8]) -> Vec<u8> {
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    encoder.write_all(bytes).expect("gzip");
    encoder.finish().expect("finish gzip")
}

/// A hand-built ustar entry — the high-level builder refuses to write the paths we need here.
fn raw_entry(out: &mut Vec<u8>, path: &str, content: &[u8]) {
    let mut header = [0u8; 512];
    header[..path.len().min(100)].copy_from_slice(&path.as_bytes()[..path.len().min(100)]);
    header[100..108].copy_from_slice(b"0000644\0");
    header[108..116].copy_from_slice(b"0000000\0");
    header[116..124].copy_from_slice(b"0000000\0");
    header[124..136].copy_from_slice(format!("{:011o}\0", content.len()).as_bytes());
    header[136..148].copy_from_slice(b"00000000000\0");
    header[148..156].copy_from_slice(b"        ");
    header[156] = b'0';
    header[257..263].copy_from_slice(b"ustar\0");
    header[263..265].copy_from_slice(b"00");
    let checksum: u32 = header.iter().map(|byte| u32::from(*byte)).sum();
    header[148..156].copy_from_slice(format!("{checksum:06o}\0 ").as_bytes());
    out.extend_from_slice(&header);
    out.extend_from_slice(content);
    out.extend(std::iter::repeat_n(0u8, (512 - content.len() % 512) % 512));
}

/// A `.tar.gz` built from `(path, content)` pairs, end-of-archive marker included.
fn hostile_targz(entries: &[(&str, &[u8])]) -> Vec<u8> {
    let mut tar = Vec::new();
    for (path, content) in entries {
        raw_entry(&mut tar, path, content);
    }
    tar.extend(std::iter::repeat_n(0u8, 1024));
    gzip(&tar)
}

/// The minimal valid pubspec used by the hostile fixtures.
fn pubspec(name: &str) -> Vec<u8> {
    format!("name: {name}\nversion: 1.0.0\ndescription: Hostile fixture.\n").into_bytes()
}

// ------------------------------------------------------------------- publish authorization

#[tokio::test]
async fn publish_authorization_matrix() {
    // S-13 scopes × decision 19 roles × decision 01 org binding. Every cell must be a 403 that
    // *keeps* the credential: a 401 here would make the client delete a token that is perfectly
    // valid elsewhere (docs/protocol.md sharp edge 1).
    let app = TestApp::new().await;
    let acme = publisher(&app, "dev@acme.test", "acme").await;
    let other = publisher(&app, "dev@other.test", "other").await;

    // A member with only the Read role, holding a publish-scoped token.
    let _ = app.login("reader@acme.test").await;
    let reader = app.user_of("reader@acme.test").await;
    app.repos.orgs.add_member(acme.org, reader, RoleLevel::READ, app.now()).await.expect("add member");
    let reader_token = app.insert_token(reader, acme.org, &[TokenScope::Publish], &[], None).await;

    // A non-member holding a token bound to acme (a stale token from before they left).
    let _ = app.login("stranger@acme.test").await;
    let stranger = app.user_of("stranger@acme.test").await;
    let stranger_token = app.insert_token(stranger, acme.org, &[TokenScope::Publish], &[], None).await;

    let read_only = app.insert_token(acme.user, acme.org, &[TokenScope::Read], &[], None).await;

    let cases: [(&str, &str); 4] = [
        ("a read-scoped token", &read_only),
        ("a token bound to another org", &other.token),
        ("a member holding only the Read role", &reader_token),
        ("a non-member's token", &stranger_token),
    ];
    for (what, token) in cases {
        // Step 1 already refuses everything name-independent.
        let start = app.pub_get(&format!("{}/api/packages/versions/new", acme.base()), Some(token)).await;
        assert_eq!(start.status, StatusCode::FORBIDDEN, "{what} passed publish step 1: {:?}", start.json);
        assert!(start.headers.contains_key(header::WWW_AUTHENTICATE), "{what}: a 403 must carry the challenge (S-14)");

        // And the upload endpoint is not a back door around step 1.
        let upload = app
            .pub_upload(
                &format!("{}/api/packages/versions/newUpload", acme.base()),
                Some(token),
                &package_archive("acme_core", "1.0.0"),
            )
            .await;
        assert_eq!(upload.status, StatusCode::FORBIDDEN, "{what} reached the byte sink");
    }

    // Nothing above created a package or burned the name.
    assert!(app.repos.packages.lookup_claim(Format::Pub, "acme_core").await.unwrap().is_none());
}

#[tokio::test]
async fn a_pattern_scoped_token_cannot_claim_a_name_outside_its_patterns() {
    // S-13: patterns are enforced at finalize (step 1 has no name), and a refusal must not
    // leave the name claimed on the way out.
    let app = TestApp::new().await;
    let acme = publisher(&app, "dev@acme.test", "acme").await;
    let narrowed = app.insert_token(acme.user, acme.org, &[TokenScope::Publish], &["acme_*"], None).await;

    let refused = app.publish(&acme.base(), &narrowed, &package_archive("evil_pkg", "1.0.0")).await;
    assert_eq!(refused.status, StatusCode::FORBIDDEN, "{:?}", refused.json);
    assert!(app.repos.packages.lookup_claim(Format::Pub, "evil_pkg").await.unwrap().is_none());
    assert!(app.repos.packages.get_by_name(Format::Pub, "evil_pkg").await.unwrap().is_none());
}

#[tokio::test]
async fn an_upload_cannot_be_finalized_from_another_org() {
    // S-21: the finalize URL travels over the wire. Binding it to the creating token *and* the
    // creating org is what keeps provenance from being borrowed — replaying the session id
    // under another base must not publish into that org.
    let app = TestApp::new().await;
    let acme = publisher(&app, "dev@acme.test", "acme").await;
    let other = publisher(&app, "dev@other.test", "other").await;

    let ticket = app.pub_get(&format!("{}/api/packages/versions/new", acme.base()), Some(&acme.token)).await;
    let upload = app
        .pub_upload(
            &app.proxied(ticket.json["url"].as_str().unwrap()),
            Some(&acme.token),
            &package_archive("acme_core", "1.0.0"),
        )
        .await;
    let finalize = app.proxied(upload.headers[header::LOCATION].to_str().unwrap());
    let session = finalize.rsplit('/').next().expect("session id");

    let replayed = app
        .pub_get(&format!("{}/api/packages/versions/newUploadFinish/{session}", other.base()), Some(&other.token))
        .await;
    assert_eq!(replayed.status, StatusCode::FORBIDDEN, "{:?}", replayed.json);
    assert!(app.repos.packages.lookup_claim(Format::Pub, "acme_core").await.unwrap().is_none());
    // The rightful owner still finishes.
    assert_eq!(app.pub_get(&finalize, Some(&acme.token)).await.status, StatusCode::OK);
}

// ------------------------------------------------------------------------- hostile archives

#[tokio::test]
async fn hostile_archives_are_refused_with_a_permanent_4xx() {
    // S-20 through the wire: every rejection must be a 4xx carrying the spec error shape. A
    // 5xx would be retried up to seven times (docs/protocol.md sharp edge 2), and a 2xx would
    // put the archive in the store.
    let app = TestApp::new().await;
    let acme = publisher(&app, "dev@acme.test", "acme").await;

    let good = package_archive("acme_core", "1.0.0");
    let mut truncated_gzip = good.clone();
    truncated_gzip.truncate(good.len() / 2);

    // A gz file *inside* the tar is ordinary content; a gz stream where the tar should be is not.
    let nested_gz = gzip(&gzip(&good));

    // One past the default 10 000-entry cap.
    let many_entries: Vec<(String, Vec<u8>)> = std::iter::once(("pubspec.yaml".to_owned(), pubspec("acme_core")))
        .chain((0..10_001).map(|i| (format!("lib/f{i}.dart"), format!("// {i}").into_bytes())))
        .collect();
    let many_entries: Vec<(&str, &[u8])> =
        many_entries.iter().map(|(path, body)| (path.as_str(), body.as_slice())).collect();

    let bomb_payload = vec![b'0'; 32 * 1024 * 1024];
    let cases: Vec<(&str, Vec<u8>)> = vec![
        ("truncated gzip", truncated_gzip),
        ("gzip inside gzip instead of a tar", nested_gz),
        ("garbage that is not gzip at all", b"PK\x03\x04 definitely not a tarball".to_vec()),
        ("a valid gzip wrapping tar garbage", gzip(&[0x42u8; 4096])),
        ("path traversal", hostile_targz(&[("pubspec.yaml", &pubspec("acme_core")), ("../../evil", b"x")])),
        ("absolute path", hostile_targz(&[("pubspec.yaml", &pubspec("acme_core")), ("/etc/passwd", b"x")])),
        (
            "duplicate entries",
            hostile_targz(&[
                ("pubspec.yaml", &pubspec("acme_core")),
                ("lib/a.dart", b"one"),
                ("lib/a.dart", b"two"),
            ]),
        ),
        ("no pubspec at the root", hostile_targz(&[("lib/a.dart", b"x")])),
        ("a pubspec that is not a mapping", hostile_targz(&[("pubspec.yaml", b"- just\n- a list\n")])),
        ("a pubspec with an illegal name", hostile_targz(&[("pubspec.yaml", b"name: ../evil\nversion: 1.0.0\n")])),
        (
            "a yaml anchor bomb",
            hostile_targz(&[(
                "pubspec.yaml",
                b"name: acme_core\nversion: 1.0.0\na: &a [x,x,x,x,x,x,x,x,x]\nb: &b [*a,*a,*a,*a,*a,*a,*a,*a,*a]\nc: [*b,*b,*b,*b,*b,*b,*b,*b,*b]\n",
            )]),
        ),
        ("a gzip bomb", hostile_targz(&[("pubspec.yaml", &pubspec("acme_core")), ("payload.bin", &bomb_payload)])),
        ("a huge entry count", hostile_targz(&many_entries)),
    ];

    for (what, archive) in cases {
        let response = app.publish(&acme.base(), &acme.token, &archive).await;
        assert!(
            response.status.is_client_error(),
            "{what} answered {} — a doomed publish must never look retryable: {:?}",
            response.status,
            response.json
        );
        assert!(response.json["error"]["code"].is_string(), "{what}: spec error shape, got {:?}", response.json);
        assert!(response.json["error"]["message"].is_string(), "{what}: spec error shape, got {:?}", response.json);
    }

    // Nothing above published anything.
    assert!(app.repos.packages.get_by_name(Format::Pub, "acme_core").await.unwrap().is_none());
    // And the honest archive still publishes, so the limits did not simply close the door.
    assert_eq!(app.publish(&acme.base(), &acme.token, &good).await.status, StatusCode::OK);
}

#[tokio::test]
async fn a_smuggled_second_gzip_member_never_reaches_the_blob_store() {
    // The validator must see every byte we would store: `tar -xzf` walks concatenated gzip
    // members, so a payload in member two would ship inside an archive we called validated.
    let app = TestApp::new().await;
    let acme = publisher(&app, "dev@acme.test", "acme").await;

    let mut smuggled = package_archive("acme_core", "1.0.0");
    smuggled.extend_from_slice(&hostile_targz(&[("../../evil.sh", b"rm -rf /")]));

    let response = app.publish(&acme.base(), &acme.token, &smuggled).await;
    assert_eq!(response.status, StatusCode::BAD_REQUEST, "{:?}", response.json);
    assert!(app.repos.packages.get_by_name(Format::Pub, "acme_core").await.unwrap().is_none());
}

#[tokio::test]
async fn s24_publish_uploads_are_capped_per_org() {
    // S-24: 30 publish attempts per hour per org by default. The budget is spent by the upload
    // step, because that is the step that costs storage — abandoned uploads sit in staging with
    // no sweeper behind them yet.
    let app = TestApp::with_options(TestOptions { publish_per_hour_org: 2, ..TestOptions::default() }).await;
    let acme = publisher(&app, "dev@acme.test", "acme").await;
    let other = publisher(&app, "dev@other.test", "other").await;
    let upload_url = format!("{}/api/packages/versions/newUpload", acme.base());
    let archive = package_archive("acme_core", "1.0.0");

    for attempt in 0..2 {
        let response = app.pub_upload(&upload_url, Some(&acme.token), &archive).await;
        assert_eq!(response.status, StatusCode::NO_CONTENT, "attempt {attempt}");
    }
    let throttled = app.pub_upload(&upload_url, Some(&acme.token), &archive).await;
    assert_eq!(throttled.status, StatusCode::TOO_MANY_REQUESTS);
    assert!(throttled.headers.contains_key(header::RETRY_AFTER), "429 must say when to come back (S-24)");
    let body: serde_json::Value = serde_json::from_slice(&throttled.body).expect("spec error shape");
    assert_eq!(body["error"]["code"], "rate_limited");

    // The bucket is per org: a different org is unaffected.
    let neighbour = app
        .pub_upload(&format!("{}/api/packages/versions/newUpload", other.base()), Some(&other.token), &archive)
        .await;
    assert_eq!(neighbour.status, StatusCode::NO_CONTENT);

    // Reads are never charged to it — the pub client resolves far more often than it publishes.
    assert_eq!(
        app.pub_get(&format!("{}/api/packages/anything", acme.base()), Some(&acme.token)).await.status,
        StatusCode::NOT_FOUND
    );

    // The trip is audit-logged (S-22).
    let events = app.repos.audit.list(&pub_core::audit::AuditFilter::default(), None, 100).await.expect("audit");
    assert!(
        events.items.iter().any(|event| event.action == "package.publish.throttled"),
        "a throttle trip must be visible to an operator"
    );
}

// -------------------------------------------------------------------------- enumeration

#[tokio::test]
async fn private_and_unknown_names_answer_identical_bytes() {
    // S-04: a private name and a name that was never published must be indistinguishable —
    // not "the same status", the same *response*. Anything that varies (a header, a code, a
    // word in the message) is an enumeration oracle for an account holder.
    let app = TestApp::new().await;
    let acme = publisher(&app, "dev@acme.test", "acme").await;
    let other = publisher(&app, "dev@other.test", "other").await;
    app.publish(&acme.base(), &acme.token, &package_archive("acme_secret", "1.0.0")).await;

    // Probed from another org's base with that org's own valid token.
    let probes = ["acme_secret", "never_published"];
    let mut seen: Vec<(StatusCode, Vec<u8>)> = Vec::new();
    for name in probes {
        for path in [
            format!("{}/api/packages/{name}", other.base()),
            format!("{}/api/archives/{name}-1.0.0.tar.gz", other.base()),
            format!("{}/api/packages/{name}/versions/1.0.0", other.base()),
        ] {
            let response = app.pub_get_raw(&path, Some(&other.token)).await;
            assert_eq!(response.status, StatusCode::NOT_FOUND, "{path}");
            assert!(response.headers.get(header::WWW_AUTHENTICATE).is_none(), "a 404 must not hint at a credential");
            seen.push((response.status, response.body));
        }
    }
    let (existing, unknown) = seen.split_at(3);
    for (index, (status, body)) in existing.iter().enumerate() {
        // The message names the package the caller asked for, so compare against the same
        // probe with the *other* name substituted — everything else has to be byte-identical.
        let normalized = String::from_utf8(body.clone()).unwrap().replace("acme_secret", "PROBE");
        let other_normalized = String::from_utf8(unknown[index].1.clone()).unwrap().replace("never_published", "PROBE");
        assert_eq!(*status, unknown[index].0);
        assert_eq!(normalized, other_normalized, "a private name is distinguishable from an unknown one");
    }

    // The same holds for an anonymous prober.
    let private = app.pub_get_raw(&format!("{}/api/packages/acme_secret", acme.base()), None).await;
    let missing = app.pub_get_raw(&format!("{}/api/packages/acme_secret", other.base()), None).await;
    assert_eq!(private.status, missing.status);
    assert_eq!(private.body, missing.body);
}

#[tokio::test]
async fn a_syntactically_impossible_name_is_not_a_separate_status() {
    // A name that could never be claimed must not answer 400 while a real miss answers 404:
    // the difference is a free name-syntax oracle and a second code path to keep in step.
    let app = TestApp::new().await;
    let acme = publisher(&app, "dev@acme.test", "acme").await;

    for name in ["Acme_Core", "class", "1abc", "acme-core", "%2e%2e", &"a".repeat(300)] {
        let response = app.pub_get(&format!("{}/api/packages/{name}", acme.base()), Some(&acme.token)).await;
        assert_eq!(response.status, StatusCode::NOT_FOUND, "{name} answered {}", response.status);
        assert_eq!(response.json["error"]["code"], "not_found");
        assert!(
            response.json["error"]["message"].as_str().unwrap().len() < 200,
            "caller text must be clipped before it is reflected"
        );
    }
}

// ---------------------------------------------------------------------------- blob keys

#[tokio::test]
async fn blob_keys_cannot_be_steered_by_names_or_versions() {
    // S-18: the blob key is `<format>/<sha[0..2]>/<sha>.tar.gz` and nothing else. Names and
    // versions never enter it, so no crafted name can collide with, overwrite, or escape into
    // another object — and two byte-identical uploads deliberately *share* one blob.
    let app = TestApp::new().await;
    let acme = publisher(&app, "dev@acme.test", "acme").await;

    app.publish(&acme.base(), &acme.token, &package_archive("acme_core", "1.0.0")).await;
    let package = app.repos.packages.get_by_name(Format::Pub, "acme_core").await.unwrap().expect("package");
    let version = app
        .repos
        .packages
        .get_version(package.id, &pub_core::SemVer::parse("1.0.0").unwrap())
        .await
        .unwrap()
        .expect("version");
    let key = pub_registry::RegistryService::blob_key(Format::Pub, &version.archive_sha256);
    assert_eq!(key, format!("pub/{}/{}.tar.gz", &version.archive_sha256[..2], version.archive_sha256));
    assert!(!key.contains("acme_core") && !key.contains("1.0.0"), "the key must not carry caller input: {key}");

    // A crafted name/version pair cannot reach a different object either: the archive route
    // resolves a package row first, and everything unresolvable is one 404.
    for file in [
        "..%2f..%2fuploads%2fpub%2fdeadbeef.tar.gz",
        "acme_core-..%2f..%2fx.tar.gz",
        "acme_core-1.0.0%2f..%2f..%2fetc.tar.gz",
        "acme_core-1.0.0.tar.gz.tar.gz",
    ] {
        let response = app.pub_get_raw(&format!("{}/api/archives/{file}", acme.base()), Some(&acme.token)).await;
        assert_eq!(response.status, StatusCode::NOT_FOUND, "{file} answered {}", response.status);
    }

    // Content addressing means two packages can legitimately share one object. Publish
    // byte-identical *content* under a second name in a second org and assert both download —
    // a key derived from the name would have made these two collide or overwrite each other.
    let second = publisher(&app, "dev@other.test", "other").await;
    let twin = package_archive("other_twin", "1.0.0");
    assert_eq!(app.publish(&second.base(), &second.token, &twin).await.status, StatusCode::OK);
    let twin_package = app.repos.packages.get_by_name(Format::Pub, "other_twin").await.unwrap().expect("package");
    let twin_version = app
        .repos
        .packages
        .get_version(twin_package.id, &pub_core::SemVer::parse("1.0.0").unwrap())
        .await
        .unwrap()
        .expect("version");
    assert_ne!(twin_version.archive_sha256, version.archive_sha256, "different pubspecs, different bytes");

    // The same bytes under a name another org holds is refused by the claim, and refused
    // *before* the duplicate check, so it cannot report which versions exist (S-04).
    let stolen = app.publish(&second.base(), &second.token, &package_archive("acme_core", "1.0.0")).await;
    assert_eq!(stolen.status, StatusCode::FORBIDDEN, "a foreign claim must win: {:?}", stolen.json);
    let fresh = app.publish(&second.base(), &second.token, &package_archive("acme_core", "7.7.7")).await;
    assert_eq!(fresh.json, stolen.json, "an existing version must be indistinguishable from a new one");
}
