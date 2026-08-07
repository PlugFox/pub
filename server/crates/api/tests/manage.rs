//! Org and package management over the real HTTP surface: the authorization matrix, the S-06
//! step-up gates, the S-09 session revocation, the ≥1-Owner invariant, the decision 06
//! retraction window and hard delete, and package transfer.
//!
//! Everything here drives the actual router, so the assertions cover the whole stack —
//! extractor, `authorize()` chokepoint, service, repository, audit log. Two properties get the
//! most attention because they are the ones that fail silently:
//!
//! - **S-09.** Every role change and every removal must revoke the affected user's sessions,
//!   and a *grant* must not. [`s09_a_role_change_revokes_every_session_of_the_affected_member`]
//!   and its neighbours prove both halves against live tokens.
//! - **S-04 ordering on writes.** A package the caller cannot read answers 404 on a management
//!   route too, before the role is ever consulted — otherwise `PATCH …/options` would be an
//!   existence oracle for another org's private packages.

mod common;

use std::sync::Arc;
use std::time::Duration as StdDuration;

use axum::http::StatusCode;
use chrono::{DateTime, Duration, Utc};
use common::{TestApp, TestOptions, package_archive};
use pub_admin::{ActorMeta, OrgPolicy, OrgService};
use pub_auth::random::OsRandom;
use pub_auth::token::sha256_hex;
use pub_core::event::EventSink;
use pub_core::token::{NewToken, Token, TokenScope};
use pub_core::traits::{JobLock, Mailer, TokenRepo};
use pub_core::{Format, OrgId, RoleLevel, TokenId, UserId};
use pub_jobs::InMemoryJobLock;
use pub_registry::{RegistryPolicy, RegistryService};

/// A signed-in principal with a fresh access token carrying its current org claims.
struct Principal {
    email: String,
    access: String,
}

impl Principal {
    /// Re-authenticates so the access token carries whatever roles the account holds *now*
    /// (claims are minted at login — decision 03).
    async fn relogin(&mut self, app: &TestApp) {
        self.access = app.login(&self.email).await["access_token"].as_str().expect("access token").to_owned();
    }
}

/// Signs `email` in and returns the principal.
async fn sign_in(app: &TestApp, email: &str) -> Principal {
    let access = app.login(email).await["access_token"].as_str().expect("access token").to_owned();
    Principal { email: email.to_owned(), access }
}

/// An owner plus their org.
async fn owner_org(app: &TestApp, email: &str, slug: &str) -> (Principal, String) {
    let (_, _org) = app.org_owner(email, slug).await;
    // The token minted before the org existed carries no claim for it.
    (sign_in(app, email).await, slug.to_owned())
}

/// Adds `email` to `slug` at `role` through the API, as the owner.
async fn add_member(app: &TestApp, owner: &Principal, slug: &str, email: &str, role: &str) {
    let response = app
        .post(
            &format!("/api/v1/orgs/{slug}/members"),
            Some(&owner.access),
            serde_json::json!({ "email": email, "role": role }),
        )
        .await;
    assert_eq!(response.status, StatusCode::OK, "add member failed: {:?}", response.json);
}

/// Publishes a package into `slug` through the real three-step flow.
async fn publish(app: &TestApp, owner: &Principal, slug: &str, name: &str, version: &str) {
    let (_, org) = app.repos.orgs.get_by_slug(slug).await.expect("org").map(|org| ((), org.id)).expect("org exists");
    let token = app.mint_token(&owner.access, org, &["read", "publish", "retract"]).await;
    let response = app.publish(&format!("/o/{slug}/pub"), &token, &package_archive(name, version)).await;
    assert_eq!(response.status, StatusCode::OK, "publish failed: {:?}", response.json);
}

// ------------------------------------------------------------------ org profile & authority

/// The role ladder on `PATCH /api/v1/orgs/{slug}`, walked end to end (decision 19).
#[tokio::test]
async fn org_patch_authorization_matrix() {
    let app = TestApp::new().await;
    let (mut owner, slug) = owner_org(&app, "owner@corp.com", "acme").await;
    for (email, role) in [("reader@corp.com", "read"), ("writer@corp.com", "write"), ("admin@corp.com", "admin")] {
        app.login(email).await;
        add_member(&app, &owner, &slug, email, role).await;
    }
    let outsider = sign_in(&app, "outsider@corp.com").await;

    let body = || serde_json::json!({ "description": "new" });
    let path = format!("/api/v1/orgs/{slug}");

    // Anonymous: no credential at all is 401, not 403 — the caller has not been judged yet.
    assert_eq!(app.patch(&path, None, body()).await.status, StatusCode::UNAUTHORIZED);
    // Below Admin (including a non-member) is 403: org slugs are not secret (S-04.b), and a
    // 404 here would leave a Read member unable to tell "wrong role" from "wrong URL".
    for email in ["reader@corp.com", "writer@corp.com"] {
        let principal = sign_in(&app, email).await;
        let response = app.patch(&path, Some(&principal.access), body()).await;
        assert_eq!(response.status, StatusCode::FORBIDDEN, "{email} must not patch the org");
        assert_eq!(response.error_code(), "forbidden");
    }
    assert_eq!(app.patch(&path, Some(&outsider.access), body()).await.status, StatusCode::FORBIDDEN);

    // Admin and Owner may.
    let admin = sign_in(&app, "admin@corp.com").await;
    assert_eq!(app.patch(&path, Some(&admin.access), body()).await.status, StatusCode::OK);
    owner.relogin(&app).await;
    let updated = app
        .patch(
            &path,
            Some(&owner.access),
            serde_json::json!({ "name": "Acme Inc", "upstream_policy": "block", "description": "  spaced  " }),
        )
        .await;
    assert_eq!(updated.status, StatusCode::OK);
    assert_eq!(updated.json["data"]["name"], "Acme Inc");
    assert_eq!(updated.json["data"]["upstream_policy"], "block");
    assert_eq!(updated.json["data"]["description"], "spaced");
    // The slug is not patchable: it is the virtual registry base (decision 01).
    assert_eq!(updated.json["data"]["slug"], "acme");

    // An unknown org is 404 for everybody, member or not.
    assert_eq!(app.patch("/api/v1/orgs/nosuch", Some(&owner.access), body()).await.status, StatusCode::NOT_FOUND);
    // A junk policy value is a clean 400 rather than a silent default.
    let bad = app.patch(&path, Some(&owner.access), serde_json::json!({ "upstream_policy": "maybe" })).await;
    assert_eq!(bad.status, StatusCode::BAD_REQUEST);
    assert_eq!(bad.error_code(), "invalid_argument");

    assert!(app.audit_actions().await.contains(&"org.updated".to_owned()));
}

/// **S-09.** Changing a member's role revokes every session that member holds — and only
/// theirs.
#[tokio::test]
async fn s09_a_role_change_revokes_every_session_of_the_affected_member() {
    let app = TestApp::new().await;
    let (owner, slug) = owner_org(&app, "owner@corp.com", "acme").await;
    let bob = sign_in(&app, "bob@corp.com").await;
    add_member(&app, &owner, &slug, "bob@corp.com", "read").await;

    // Bob signs in on a second device: two live sessions, both usable.
    let second = app.login("bob@corp.com").await["access_token"].as_str().expect("token").to_owned();
    let bob_id = app.user_of("bob@corp.com").await;
    assert_eq!(app.repos.sessions.list_for_user(bob_id).await.expect("sessions").len(), 2);
    assert_eq!(app.get("/api/v1/sessions", Some(&bob.access)).await.status, StatusCode::OK);

    // The owner demotes… well, re-roles him. Both of Bob's devices are logged out at once.
    let response = app
        .patch(
            &format!("/api/v1/orgs/{slug}/members/{bob_id}"),
            Some(&owner.access),
            serde_json::json!({ "role": "admin" }),
        )
        .await;
    assert_eq!(response.status, StatusCode::OK, "{:?}", response.json);
    assert_eq!(response.json["data"]["role"], "admin");
    assert_eq!(response.json["data"]["sessions_revoked"], 2);

    for token in [&bob.access, &second] {
        let denied = app.get("/api/v1/sessions", Some(token)).await;
        assert_eq!(denied.status, StatusCode::UNAUTHORIZED, "a stale role claim must not outlive the change");
        assert_eq!(denied.error_code(), "unauthorized");
    }
    assert!(app.repos.sessions.list_for_user(bob_id).await.expect("sessions").is_empty());
    // The actor's own session is untouched — S-09 is about the *affected* user.
    assert_eq!(app.get("/api/v1/sessions", Some(&owner.access)).await.status, StatusCode::OK);

    let event = app.audit_event("session.revoked").await.expect("revocation audited");
    assert_eq!(event.metadata.expect("metadata")["reason"], "role_changed");
}

/// **S-09.** A removal withdraws authority and revokes; a pure grant does not.
#[tokio::test]
async fn s09_removal_revokes_sessions_but_a_grant_leaves_them_alone() {
    let app = TestApp::new().await;
    let (owner, slug) = owner_org(&app, "owner@corp.com", "acme").await;
    let bob = sign_in(&app, "bob@corp.com").await;
    let bob_id = app.user_of("bob@corp.com").await;

    // Granting: nothing to withdraw, so Bob stays signed in. A token minted before the grant
    // simply carries no claim for the org and fails closed on anything that needs one.
    add_member(&app, &owner, &slug, "bob@corp.com", "read").await;
    assert_eq!(app.get("/api/v1/sessions", Some(&bob.access)).await.status, StatusCode::OK);
    assert!(!app.repos.sessions.list_for_user(bob_id).await.expect("sessions").is_empty());

    // Removing: revoked.
    let response = app.delete(&format!("/api/v1/orgs/{slug}/members/{bob_id}"), Some(&owner.access)).await;
    assert_eq!(response.status, StatusCode::OK, "{:?}", response.json);
    assert_eq!(response.json["data"]["role"], serde_json::Value::Null);
    assert!(response.json["data"]["sessions_revoked"].as_u64().expect("count") >= 1);
    assert_eq!(app.get("/api/v1/sessions", Some(&bob.access)).await.status, StatusCode::UNAUTHORIZED);
    assert!(app.repos.sessions.list_for_user(bob_id).await.expect("sessions").is_empty());

    let event = app.audit_event("org.member.remove").await.expect("removal audited");
    assert!(event.org_id.is_some(), "a membership change is org-scoped in the audit log");
}

/// Whether a CLI token secret still authenticates (the D37 sweep's observable effect).
async fn token_alive(app: &TestApp, secret: &str) -> bool {
    app.repos.tokens.find_active_by_hash(&sha256_hex(secret), app.now()).await.expect("lookup").is_some()
}

/// **D37 (decision 13 addendum).** A demotion revokes exactly the org tokens whose scopes
/// exceed the new level — the comparison is the token's scopes, not the holder — and the
/// response and audit log both say how many.
#[tokio::test]
async fn s13_a_demotion_revokes_the_org_tokens_the_new_role_could_no_longer_mint() {
    let app = TestApp::new().await;
    let (owner, slug) = owner_org(&app, "owner@corp.com", "acme").await;
    app.login("bob@corp.com").await;
    add_member(&app, &owner, &slug, "bob@corp.com", "admin").await;
    let bob_id = app.user_of("bob@corp.com").await;
    let org_id = app.repos.orgs.get_by_slug(&slug).await.expect("lookup").expect("org").id;

    let admin_tok = app.insert_token(bob_id, org_id, &[TokenScope::Admin], &[], None).await;
    let publish_tok = app.insert_token(bob_id, org_id, &[TokenScope::Publish], &[], None).await;
    let read_tok = app.insert_token(bob_id, org_id, &[TokenScope::Read], &[], None).await;
    for secret in [&admin_tok, &publish_tok, &read_tok] {
        assert!(token_alive(&app, secret).await, "freshly minted tokens authenticate");
    }

    // admin → write: the admin-scoped token dies; publish and read fit the new level and live.
    let demoted = app
        .patch(
            &format!("/api/v1/orgs/{slug}/members/{bob_id}"),
            Some(&owner.access),
            serde_json::json!({ "role": "write" }),
        )
        .await;
    assert_eq!(demoted.status, StatusCode::OK, "{:?}", demoted.json);
    assert_eq!(demoted.json["data"]["tokens_revoked"], 1, "exactly the admin-scoped token: {:?}", demoted.json);
    assert!(demoted.json["data"]["sessions_revoked"].as_u64().expect("count") >= 1, "S-09 rides along");
    assert!(!token_alive(&app, &admin_tok).await, "an admin-scoped token must not outlive the demotion");
    assert!(token_alive(&app, &publish_tok).await, "a publish token fits a write member");
    assert!(token_alive(&app, &read_tok).await, "a read token fits a write member");

    // The sweep audits itself: system actor, the authority-change reason, the count.
    let event = app.audit_event("token.revoked").await.expect("token sweep audited");
    assert_eq!(event.actor, pub_core::audit::AuditActor::System, "the system revokes, not the demoted user");
    let metadata = event.metadata.expect("metadata");
    assert_eq!(metadata["reason"], "role_changed");
    assert_eq!(metadata["count"], 1);

    // write → read: now the publish token is above the level too.
    let owner_fresh = sign_in(&app, "owner@corp.com").await;
    let demoted_again = app
        .patch(
            &format!("/api/v1/orgs/{slug}/members/{bob_id}"),
            Some(&owner_fresh.access),
            serde_json::json!({ "role": "read" }),
        )
        .await;
    assert_eq!(demoted_again.status, StatusCode::OK, "{:?}", demoted_again.json);
    assert_eq!(demoted_again.json["data"]["tokens_revoked"], 1, "{:?}", demoted_again.json);
    assert!(!token_alive(&app, &publish_tok).await, "a publish token must not outlive the demotion to read");
    assert!(token_alive(&app, &read_tok).await, "the read token survives every demotion down to read");
}

/// **D37 (decision 13 addendum).** A raise revokes no tokens (mirroring S-09.a's grant row),
/// and a removal sweeps every token in *that* org while tokens in the user's other orgs keep
/// working.
#[tokio::test]
async fn s13_a_raise_revokes_no_tokens_and_a_removal_sweeps_only_this_orgs_tokens() {
    let app = TestApp::new().await;
    let (owner, slug) = owner_org(&app, "owner@corp.com", "acme").await;
    let (other_owner, other_slug) = owner_org(&app, "other@corp.com", "other").await;
    app.login("bob@corp.com").await;
    add_member(&app, &owner, &slug, "bob@corp.com", "write").await;
    add_member(&app, &other_owner, &other_slug, "bob@corp.com", "write").await;
    let bob_id = app.user_of("bob@corp.com").await;
    let org_id = app.repos.orgs.get_by_slug(&slug).await.expect("lookup").expect("org").id;
    let other_id = app.repos.orgs.get_by_slug(&other_slug).await.expect("lookup").expect("org").id;

    let publish_tok = app.insert_token(bob_id, org_id, &[TokenScope::Publish], &[], None).await;
    let read_tok = app.insert_token(bob_id, org_id, &[TokenScope::Read], &[], None).await;
    let foreign_tok = app.insert_token(bob_id, other_id, &[TokenScope::Publish], &[], None).await;

    // A raise: sessions go (stale claim), tokens stay — nothing stale outranks a grant.
    let raised = app
        .patch(
            &format!("/api/v1/orgs/{slug}/members/{bob_id}"),
            Some(&owner.access),
            serde_json::json!({ "role": "admin" }),
        )
        .await;
    assert_eq!(raised.status, StatusCode::OK, "{:?}", raised.json);
    assert_eq!(raised.json["data"]["tokens_revoked"], 0, "a raise revokes no tokens: {:?}", raised.json);
    assert!(raised.json["data"]["sessions_revoked"].as_u64().expect("count") >= 1);
    for secret in [&publish_tok, &read_tok, &foreign_tok] {
        assert!(token_alive(&app, secret).await, "a raise must leave every token alone");
    }

    // Removal: every token in this org goes, the other org's token is untouched.
    let owner_fresh = sign_in(&app, "owner@corp.com").await;
    let removed = app.delete(&format!("/api/v1/orgs/{slug}/members/{bob_id}"), Some(&owner_fresh.access)).await;
    assert_eq!(removed.status, StatusCode::OK, "{:?}", removed.json);
    assert_eq!(removed.json["data"]["tokens_revoked"], 2, "both acme tokens, read included: {:?}", removed.json);
    assert!(!token_alive(&app, &publish_tok).await, "removal revokes the publish token");
    assert!(!token_alive(&app, &read_tok).await, "removal revokes even a read token");
    assert!(token_alive(&app, &foreign_tok).await, "authority changed in acme only — the other org's token lives");

    let event = app.audit_event("token.revoked").await.expect("token sweep audited");
    let metadata = event.metadata.expect("metadata");
    assert_eq!(metadata["reason"], "membership_removed");
    assert_eq!(metadata["count"], 2);
}

/// A [`TokenRepo`] that fails on command — the D37 sweep-resilience probe. Every `revoke`
/// dies; `fail_list` additionally kills the listing query. Everything else delegates to the
/// real repository.
struct FailingTokens {
    inner: Arc<dyn TokenRepo>,
    fail_list: bool,
}

fn token_plane_down() -> pub_core::Error {
    pub_core::Error::Database { message: "simulated token-plane outage".to_owned() }
}

#[async_trait::async_trait]
impl TokenRepo for FailingTokens {
    async fn ping(&self) -> pub_core::Result<()> {
        self.inner.ping().await
    }

    async fn create(&self, new: NewToken, now: DateTime<Utc>) -> pub_core::Result<Token> {
        self.inner.create(new, now).await
    }

    async fn find_active_by_hash(&self, token_hash: &str, now: DateTime<Utc>) -> pub_core::Result<Option<Token>> {
        self.inner.find_active_by_hash(token_hash, now).await
    }

    async fn touch_last_used(
        &self,
        id: TokenId,
        ip: Option<&str>,
        throttle: StdDuration,
        now: DateTime<Utc>,
    ) -> pub_core::Result<bool> {
        self.inner.touch_last_used(id, ip, throttle, now).await
    }

    async fn revoke(&self, _id: TokenId, _now: DateTime<Utc>) -> pub_core::Result<()> {
        Err(token_plane_down())
    }

    async fn list_for_user(&self, user: UserId) -> pub_core::Result<Vec<Token>> {
        if self.fail_list {
            return Err(token_plane_down());
        }
        self.inner.list_for_user(user).await
    }

    async fn list_for_org(&self, org: OrgId) -> pub_core::Result<Vec<Token>> {
        self.inner.list_for_org(org).await
    }
}

/// The app's own [`OrgService`], rebuilt over the same backends with the token repository
/// swapped out — how the resilience tests inject a token-plane failure into the D37 sweep.
fn org_service_with_tokens(app: &TestApp, tokens: Arc<dyn TokenRepo>) -> OrgService {
    let mut repos = app.repos.clone();
    repos.tokens = tokens;
    let registry = Arc::new(RegistryService::new(
        repos.clone(),
        Arc::clone(&app.state.blob),
        Arc::new(InMemoryJobLock::new()) as Arc<dyn JobLock>,
        Arc::clone(&app.events) as Arc<dyn EventSink>,
        RegistryPolicy::default(),
    ));
    OrgService::new(
        repos,
        Arc::clone(&app.state.auth),
        registry,
        Arc::clone(&app.mailer) as Arc<dyn Mailer>,
        Arc::clone(&app.events) as Arc<dyn EventSink>,
        Arc::new(OsRandom),
        OrgPolicy::default(),
    )
}

/// **S-09 over D37 (adversarial).** The session sweep is the load-bearing control and runs
/// before the best-effort token sweep: with the token plane down mid-demotion, the call still
/// succeeds, every session of the demoted member is revoked, and the reported token count is
/// the honest zero — no audit row claims a revocation that never happened.
#[tokio::test]
async fn s09_a_token_sweep_failure_never_blocks_the_session_sweep() {
    let app = TestApp::new().await;
    let (owner, slug) = owner_org(&app, "owner@corp.com", "acme").await;
    app.login("bob@corp.com").await;
    add_member(&app, &owner, &slug, "bob@corp.com", "admin").await;
    let bob_id = app.user_of("bob@corp.com").await;
    let owner_id = app.user_of("owner@corp.com").await;
    let org = app.repos.orgs.get_by_slug(&slug).await.expect("lookup").expect("org");
    let admin_tok = app.insert_token(bob_id, org.id, &[TokenScope::Admin], &[], None).await;
    assert!(!app.repos.sessions.list_for_user(bob_id).await.expect("sessions").is_empty());

    // Same backends, except every `TokenRepo::revoke` fails — a transient DB error inside the
    // sweep, after the membership row is already committed.
    let failing = FailingTokens { inner: Arc::clone(&app.repos.tokens), fail_list: false };
    let orgs = org_service_with_tokens(&app, Arc::new(failing));
    let (member, revoked) = orgs
        .change_role(&org, bob_id, RoleLevel::WRITE, RoleLevel::OWNER, &ActorMeta::user(owner_id), app.now())
        .await
        .expect("a committed demotion must not fail on a token-plane error");
    assert_eq!(member.role, RoleLevel::WRITE);
    assert!(revoked.sessions >= 1, "S-09 must run before, and despite, the failing token sweep");
    assert_eq!(revoked.tokens, 0, "the count is honest: nothing was actually revoked");
    assert!(app.repos.sessions.list_for_user(bob_id).await.expect("sessions").is_empty(), "zero sessions survive");
    // The credential survived the failed sweep — the authority did not: the role is re-derived
    // per request (decision 13), so the stale token can no longer spend admin.
    assert!(token_alive(&app, &admin_tok).await, "the un-revoked token is still there for a later sweep");
    assert!(app.audit_event("token.revoked").await.is_none(), "no audit row may claim a revocation that failed");

    // Same story when the *listing* dies before any revoke could even be attempted.
    app.login("carol@corp.com").await;
    add_member(&app, &owner, &slug, "carol@corp.com", "admin").await;
    let carol_id = app.user_of("carol@corp.com").await;
    let carol_tok = app.insert_token(carol_id, org.id, &[TokenScope::Admin], &[], None).await;
    let failing = FailingTokens { inner: Arc::clone(&app.repos.tokens), fail_list: true };
    let orgs = org_service_with_tokens(&app, Arc::new(failing));
    let (_, revoked) = orgs
        .change_role(&org, carol_id, RoleLevel::READ, RoleLevel::OWNER, &ActorMeta::user(owner_id), app.now())
        .await
        .expect("a dead token listing must not fail the demotion either");
    assert!(revoked.sessions >= 1, "S-09 still ran");
    assert_eq!(revoked.tokens, 0);
    assert!(app.repos.sessions.list_for_user(carol_id).await.expect("sessions").is_empty());
    assert!(token_alive(&app, &carol_tok).await);
}

/// The ≥1-Owner invariant surfaces as a clean `409 last_owner`, from both directions.
#[tokio::test]
async fn last_owner_protection_is_a_clean_conflict() {
    let app = TestApp::new().await;
    let (owner, slug) = owner_org(&app, "owner@corp.com", "acme").await;
    let owner_id = app.user_of("owner@corp.com").await;

    let demote = app
        .patch(
            &format!("/api/v1/orgs/{slug}/members/{owner_id}"),
            Some(&owner.access),
            serde_json::json!({ "role": "admin" }),
        )
        .await;
    assert_eq!(demote.status, StatusCode::CONFLICT);
    assert_eq!(demote.error_code(), "last_owner");

    let remove = app.delete(&format!("/api/v1/orgs/{slug}/members/{owner_id}"), Some(&owner.access)).await;
    assert_eq!(remove.status, StatusCode::CONFLICT);
    assert_eq!(remove.error_code(), "last_owner");

    // The refusal is not a role problem: with a second Owner in place the same call succeeds,
    // and the sessions of the demoted account are revoked as any role change would.
    app.login("second@corp.com").await;
    add_member(&app, &owner, &slug, "second@corp.com", "owner").await;
    let ok = app
        .patch(
            &format!("/api/v1/orgs/{slug}/members/{owner_id}"),
            Some(&owner.access),
            serde_json::json!({ "role": "admin" }),
        )
        .await;
    assert_eq!(ok.status, StatusCode::OK, "{:?}", ok.json);
}

/// **D39 (decision 19 addendum).** The role-grant ceiling, walked as a matrix: an Admin
/// manages only levels strictly below admin — granting, demoting, removing, and inviting at
/// admin or owner are all a plain `403 forbidden` naming the role — while an Owner does every
/// one of those, appointing a second Owner included. A denial mutates nothing.
#[tokio::test]
async fn d39_an_admin_manages_only_levels_below_admin_while_an_owner_manages_every_level() {
    let app = TestApp::new().await;
    let (mut owner, slug) = owner_org(&app, "owner@corp.com", "acme").await;
    for (email, role) in [
        ("actor@corp.com", "admin"),
        ("peer@corp.com", "admin"),
        ("writer@corp.com", "write"),
        ("reader@corp.com", "read"),
    ] {
        app.login(email).await;
        add_member(&app, &owner, &slug, email, role).await;
    }
    app.login("newbie@corp.com").await;
    let admin = sign_in(&app, "actor@corp.com").await;
    let org_id = app.repos.orgs.get_by_slug(&slug).await.expect("lookup").expect("org").id;
    let actor_id = app.user_of("actor@corp.com").await;
    let peer_id = app.user_of("peer@corp.com").await;
    let writer_id = app.user_of("writer@corp.com").await;
    let reader_id = app.user_of("reader@corp.com").await;
    let owner_id = app.user_of("owner@corp.com").await;
    let members = format!("/api/v1/orgs/{slug}/members");
    let invitations = format!("/api/v1/orgs/{slug}/invitations");

    // Below the ceiling an Admin manages freely: add at write, re-role to read, remove.
    let added = app
        .post(&members, Some(&admin.access), serde_json::json!({ "email": "newbie@corp.com", "role": "write" }))
        .await;
    assert_eq!(added.status, StatusCode::OK, "{:?}", added.json);
    let newbie_id = app.user_of("newbie@corp.com").await;
    let changed =
        app.patch(&format!("{members}/{newbie_id}"), Some(&admin.access), serde_json::json!({ "role": "read" })).await;
    assert_eq!(changed.status, StatusCode::OK, "{:?}", changed.json);
    let removed = app.delete(&format!("{members}/{newbie_id}"), Some(&admin.access)).await;
    assert_eq!(removed.status, StatusCode::OK, "{:?}", removed.json);

    // At or above it: every mutation path answers the same 403 whose message names the role.
    let audit_before = app.audit_actions().await;
    let denials: Vec<(&str, axum::http::Method, String, Option<serde_json::Value>)> = vec![
        (
            "granting admin",
            axum::http::Method::POST,
            members.clone(),
            Some(serde_json::json!({ "email": "newbie@corp.com", "role": "admin" })),
        ),
        (
            "granting owner",
            axum::http::Method::POST,
            members.clone(),
            Some(serde_json::json!({ "email": "newbie@corp.com", "role": "owner" })),
        ),
        (
            "demoting a fellow admin",
            axum::http::Method::PATCH,
            format!("{members}/{peer_id}"),
            Some(serde_json::json!({ "role": "write" })),
        ),
        (
            "demoting the owner",
            axum::http::Method::PATCH,
            format!("{members}/{owner_id}"),
            Some(serde_json::json!({ "role": "write" })),
        ),
        ("removing a fellow admin", axum::http::Method::DELETE, format!("{members}/{peer_id}"), None),
        ("removing the owner", axum::http::Method::DELETE, format!("{members}/{owner_id}"), None),
        (
            "inviting at admin",
            axum::http::Method::POST,
            invitations.clone(),
            Some(serde_json::json!({ "email": "hire@corp.com", "role": "admin" })),
        ),
        (
            "inviting at owner",
            axum::http::Method::POST,
            invitations.clone(),
            Some(serde_json::json!({ "email": "hire@corp.com", "role": "owner" })),
        ),
    ];
    for (label, method, path, body) in denials {
        let response = app.send(app.request(method, &path, Some(&admin.access), body, common::DEFAULT_IP)).await;
        assert_eq!(response.status, StatusCode::FORBIDDEN, "{label} must hit the ceiling: {:?}", response.json);
        assert_eq!(response.error_code(), "forbidden", "{label} is the standard denial, not a new code");
        let message = response.json["error"]["message"].as_str().expect("message");
        assert!(
            message.contains("your role admin manages only roles below admin"),
            "{label}: the denial must name role names, got {message:?}"
        );
    }

    // Nothing moved behind those denials: same roles, same member count, no invitation rows,
    // and not one membership mutation reached the audit log while they were refused.
    for (user, role) in [
        (peer_id, RoleLevel::ADMIN),
        (owner_id, RoleLevel::OWNER),
        (actor_id, RoleLevel::ADMIN),
        (writer_id, RoleLevel::WRITE),
        (reader_id, RoleLevel::READ),
    ] {
        let member = app.repos.orgs.get_member(org_id, user).await.expect("lookup").expect("still a member");
        assert_eq!(member.role, role, "a denied mutation must not move {user}");
    }
    assert!(app.repos.orgs.get_member(org_id, newbie_id).await.expect("lookup").is_none(), "denied grant must not add");
    assert!(app.repos.orgs.list_invitations(org_id).await.expect("invitations").is_empty());
    assert_eq!(app.audit_actions().await, audit_before, "a denied mutation must leave no audit trace of success");

    // The Owner is exempt from the ceiling and does every denied action.
    owner.relogin(&app).await;
    let promote =
        app.patch(&format!("{members}/{writer_id}"), Some(&owner.access), serde_json::json!({ "role": "admin" })).await;
    assert_eq!(promote.status, StatusCode::OK, "an owner grants admin: {:?}", promote.json);
    let demote =
        app.patch(&format!("{members}/{peer_id}"), Some(&owner.access), serde_json::json!({ "role": "write" })).await;
    assert_eq!(demote.status, StatusCode::OK, "an owner demotes an admin: {:?}", demote.json);
    let remove = app.delete(&format!("{members}/{actor_id}"), Some(&owner.access)).await;
    assert_eq!(remove.status, StatusCode::OK, "an owner removes an admin: {:?}", remove.json);
    let invite = app
        .post(
            &invitations,
            Some(&owner.access),
            serde_json::json!({ "email": "future.owner@corp.com", "role": "owner" }),
        )
        .await;
    assert_eq!(invite.status, StatusCode::OK, "an owner invites at owner: {:?}", invite.json);
    // A second Owner — the existing last-owner test covers granting `owner` on the add path.
    let second =
        app.patch(&format!("{members}/{reader_id}"), Some(&owner.access), serde_json::json!({ "role": "owner" })).await;
    assert_eq!(second.status, StatusCode::OK, "an owner appoints another owner: {:?}", second.json);
}

/// **D39 (decision 19 addendum).** Self-directed *reduction* bypasses the ceiling — an Admin
/// demotes themselves or leaves the org, which the peer-blocking matrix above would otherwise
/// forbid — while a self-*raise* stays blocked, and the ≥1-Owner invariant still keeps the
/// last Owner in place.
#[tokio::test]
async fn d39_self_reduction_bypasses_the_ceiling_while_a_self_raise_stays_blocked() {
    let app = TestApp::new().await;
    let (owner, slug) = owner_org(&app, "owner@corp.com", "acme").await;
    for email in ["actor@corp.com", "leaver@corp.com"] {
        app.login(email).await;
        add_member(&app, &owner, &slug, email, "admin").await;
    }
    let org_id = app.repos.orgs.get_by_slug(&slug).await.expect("lookup").expect("org").id;
    let members = format!("/api/v1/orgs/{slug}/members");
    let admin = sign_in(&app, "actor@corp.com").await;
    let actor_id = app.user_of("actor@corp.com").await;

    // Self-raise: exactly the escalation the ceiling exists to stop — the standard denial,
    // and the membership does not move.
    let raise =
        app.patch(&format!("{members}/{actor_id}"), Some(&admin.access), serde_json::json!({ "role": "owner" })).await;
    assert_eq!(raise.status, StatusCode::FORBIDDEN, "an admin must not promote themselves: {:?}", raise.json);
    assert_eq!(raise.error_code(), "forbidden");
    let member = app.repos.orgs.get_member(org_id, actor_id).await.expect("lookup").expect("member");
    assert_eq!(member.role, RoleLevel::ADMIN, "a denied self-raise must not move the role");

    // Self-demotion: admin-touches-admin would hit the ceiling for anyone else; aimed at
    // yourself it is a reduction and goes through — with the S-09 sweep riding along.
    let demote =
        app.patch(&format!("{members}/{actor_id}"), Some(&admin.access), serde_json::json!({ "role": "write" })).await;
    assert_eq!(demote.status, StatusCode::OK, "self-demotion must bypass the ceiling: {:?}", demote.json);
    assert_eq!(demote.json["data"]["role"], "write");
    assert!(demote.json["data"]["sessions_revoked"].as_u64().expect("count") >= 1, "S-09 applies to self-demotion");
    assert_eq!(app.get("/api/v1/sessions", Some(&admin.access)).await.status, StatusCode::UNAUTHORIZED);

    // Self-removal: an Admin leaves the org.
    let leaver = sign_in(&app, "leaver@corp.com").await;
    let leaver_id = app.user_of("leaver@corp.com").await;
    let removed = app.delete(&format!("{members}/{leaver_id}"), Some(&leaver.access)).await;
    assert_eq!(removed.status, StatusCode::OK, "self-removal must bypass the ceiling: {:?}", removed.json);
    assert!(app.repos.orgs.get_member(org_id, leaver_id).await.expect("lookup").is_none(), "the member is gone");

    // The carve-out does not touch the ≥1-Owner invariant: a sole Owner still cannot leave…
    let owner_id = app.user_of("owner@corp.com").await;
    let refused = app.delete(&format!("{members}/{owner_id}"), Some(&owner.access)).await;
    assert_eq!(refused.status, StatusCode::CONFLICT);
    assert_eq!(refused.error_code(), "last_owner");
    // …until another Owner exists, after which self-removal is an ordinary reduction.
    app.login("successor@corp.com").await;
    add_member(&app, &owner, &slug, "successor@corp.com", "owner").await;
    let departed = app.delete(&format!("{members}/{owner_id}"), Some(&owner.access)).await;
    assert_eq!(departed.status, StatusCode::OK, "a non-sole owner removes themselves: {:?}", departed.json);
    assert!(app.repos.orgs.get_member(org_id, owner_id).await.expect("lookup").is_none());
}

/// **S-06.** The step-up list, walked with a session that is authenticated but stale.
///
/// The window is set shorter than the access TTL so the JWT is still valid while the step-up
/// mark has expired — which is exactly the state a stolen session is in.
#[tokio::test]
async fn s06_step_up_gates_write_grants_invitations_and_every_danger_zone_action() {
    let app = TestApp::with_options(TestOptions { step_up_minutes: 1, ..TestOptions::default() }).await;
    let (owner, slug) = owner_org(&app, "owner@corp.com", "acme").await;
    app.login("bob@corp.com").await;
    publish(&app, &owner, &slug, "acme_core", "1.0.0").await;
    let bob_id = app.user_of("bob@corp.com").await;

    // A read-level grant is not on S-06's list, and it works while the session is fresh.
    add_member(&app, &owner, &slug, "bob@corp.com", "read").await;

    // Now let the step-up go stale. The access token (15 min) is still valid.
    app.advance(Duration::minutes(2));
    assert_eq!(app.get("/api/v1/sessions", Some(&owner.access)).await.status, StatusCode::OK, "still authenticated");

    // Ungated: the org profile patch and a Read-level grant.
    assert_eq!(
        app.patch(&format!("/api/v1/orgs/{slug}"), Some(&owner.access), serde_json::json!({ "description": "x" }))
            .await
            .status,
        StatusCode::OK
    );

    // Gated: every action S-06 names.
    let gated: Vec<(&str, axum::http::Method, String, serde_json::Value)> = vec![
        (
            "write grant",
            axum::http::Method::POST,
            format!("/api/v1/orgs/{slug}/members"),
            serde_json::json!({ "email": "carol@corp.com", "role": "write" }),
        ),
        (
            "role change",
            axum::http::Method::PATCH,
            format!("/api/v1/orgs/{slug}/members/{bob_id}"),
            serde_json::json!({ "role": "write" }),
        ),
        (
            "invitation",
            axum::http::Method::POST,
            format!("/api/v1/orgs/{slug}/invitations"),
            serde_json::json!({ "email": "new@corp.com" }),
        ),
        (
            "retract",
            axum::http::Method::POST,
            "/api/v1/packages/acme_core/versions/1.0.0/retract".to_owned(),
            serde_json::json!({}),
        ),
        (
            "hard delete",
            axum::http::Method::DELETE,
            "/api/v1/packages/acme_core/versions/1.0.0".to_owned(),
            serde_json::json!({ "confirm": "acme_core@1.0.0", "reason": "leak" }),
        ),
        (
            "transfer",
            axum::http::Method::POST,
            "/api/v1/packages/acme_core/transfer".to_owned(),
            serde_json::json!({ "target_org": "other", "confirm": "acme_core" }),
        ),
        (
            "org deletion",
            axum::http::Method::DELETE,
            format!("/api/v1/orgs/{slug}"),
            serde_json::json!({ "confirm": slug }),
        ),
    ];
    for (label, method, path, body) in gated {
        let response = app.send(app.request(method, &path, Some(&owner.access), Some(body), common::DEFAULT_IP)).await;
        assert_eq!(response.status, StatusCode::FORBIDDEN, "{label} must be step-up gated");
        assert_eq!(response.error_code(), "step_up_required", "{label} must say why");
    }

    // A fresh login re-satisfies the gate (S-06.a: fresh login ∨ fresh step-up).
    let fresh = app.login("owner@corp.com").await["access_token"].as_str().expect("token").to_owned();
    let retracted =
        app.post("/api/v1/packages/acme_core/versions/1.0.0/retract", Some(&fresh), serde_json::json!({})).await;
    assert_eq!(retracted.status, StatusCode::OK, "{:?}", retracted.json);
}

// ------------------------------------------------------------------------------ invitations

/// The invitation lifecycle end to end, including the two ways it can be refused.
#[tokio::test]
async fn invitation_lifecycle_from_send_to_accept() {
    let app = TestApp::new().await;
    let (owner, slug) = owner_org(&app, "owner@corp.com", "acme").await;

    let created = app
        .post(
            &format!("/api/v1/orgs/{slug}/invitations"),
            Some(&owner.access),
            serde_json::json!({ "email": "New.Hire@corp.com", "role": "write" }),
        )
        .await;
    assert_eq!(created.status, StatusCode::OK, "{:?}", created.json);
    let token = created.json["data"]["token"].as_str().expect("token").to_owned();
    assert_eq!(created.json["data"]["invitation"]["status"], "pending");
    assert_eq!(created.json["data"]["invitation"]["role"], "write");
    // Normalized to lowercase, because that is what acceptance will compare against.
    assert_eq!(created.json["data"]["invitation"]["email"], "new.hire@corp.com");
    // The invitee is also mailed; the token is returned so an SMTP-less instance still works.
    assert!(app.mailer.sent().iter().any(|mail| mail.to == "new.hire@corp.com"));

    let listed = app.get(&format!("/api/v1/orgs/{slug}/invitations"), Some(&owner.access)).await;
    assert_eq!(listed.json["data"]["items"].as_array().expect("items").len(), 1);

    // The invitation is bound to its address in *verified* state: a different account cannot
    // spend it even holding the token.
    let mallory = sign_in(&app, "mallory@evil.com").await;
    let stolen =
        app.post("/api/v1/invitations/accept", Some(&mallory.access), serde_json::json!({ "token": token })).await;
    assert_eq!(stolen.status, StatusCode::FORBIDDEN);

    // The invitee accepts and is a Write member; accepting is a grant, so their session lives.
    let hire = sign_in(&app, "new.hire@corp.com").await;
    let accepted =
        app.post("/api/v1/invitations/accept", Some(&hire.access), serde_json::json!({ "token": token })).await;
    assert_eq!(accepted.status, StatusCode::OK, "{:?}", accepted.json);
    assert_eq!(accepted.json["data"]["slug"], slug);
    assert_eq!(app.get("/api/v1/sessions", Some(&hire.access)).await.status, StatusCode::OK, "S-09.a: a grant");
    let hire_id = app.user_of("new.hire@corp.com").await;
    let member = app.repos.orgs.get_member(app.repos.orgs.get_by_slug(&slug).await.unwrap().unwrap().id, hire_id).await;
    assert_eq!(member.expect("member").expect("row").role, RoleLevel::WRITE);

    // Single use.
    let again = app.post("/api/v1/invitations/accept", Some(&hire.access), serde_json::json!({ "token": token })).await;
    assert_eq!(again.status, StatusCode::CONFLICT);

    // Revocation: a pending invitation can be withdrawn, and a foreign id is a 404.
    let second = app
        .post(
            &format!("/api/v1/orgs/{slug}/invitations"),
            Some(&owner.access),
            serde_json::json!({ "email": "later@corp.com" }),
        )
        .await;
    let id = second.json["data"]["invitation"]["id"].as_str().expect("id").to_owned();
    let revoked = app.delete(&format!("/api/v1/orgs/{slug}/invitations/{id}"), Some(&owner.access)).await;
    assert_eq!(revoked.status, StatusCode::OK);
    assert_eq!(revoked.json["data"]["status"], "revoked");
    assert_eq!(
        app.delete(&format!("/api/v1/orgs/{slug}/invitations/{id}"), Some(&owner.access)).await.status,
        StatusCode::CONFLICT
    );

    let actions = app.audit_actions().await;
    for action in ["org.invitation.create", "org.invitation.accept", "org.invitation.revoke"] {
        assert!(actions.contains(&action.to_owned()), "{action} must be audited");
    }
}

/// **S-24.** The per-org invitation budget is spent and answers 429 with a `Retry-After`.
#[tokio::test]
async fn s24_the_org_invitation_budget_is_bounded_per_day() {
    let app = TestApp::new().await;
    let (owner, slug) = owner_org(&app, "owner@corp.com", "acme").await;
    let path = format!("/api/v1/orgs/{slug}/invitations");

    for index in 0..20 {
        let response =
            app.post(&path, Some(&owner.access), serde_json::json!({ "email": format!("hire{index}@corp.com") })).await;
        assert_eq!(response.status, StatusCode::OK, "invite {index} failed: {:?}", response.json);
    }
    let refused = app.post(&path, Some(&owner.access), serde_json::json!({ "email": "one.too.many@corp.com" })).await;
    assert_eq!(refused.status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(refused.error_code(), "rate_limited");
    assert!(refused.headers.contains_key(axum::http::header::RETRY_AFTER));
    let throttle = app.audit_event("auth.throttled").await.expect("throttle trip audited");
    assert_eq!(throttle.metadata.expect("metadata")["limit"], "invitations_per_day_org");

    // The window is rolling: a day later the budget is back.
    app.advance(Duration::days(1) + Duration::minutes(1));
    let fresh = app.login("owner@corp.com").await["access_token"].as_str().expect("token").to_owned();
    assert_eq!(
        app.post(&path, Some(&fresh), serde_json::json!({ "email": "tomorrow@corp.com" })).await.status,
        StatusCode::OK
    );
}

// -------------------------------------------------------------------------------- deletion

/// An org that owns packages cannot be erased; forcing archives it instead (decision 06/S-18).
#[tokio::test]
async fn org_deletion_refuses_while_packages_exist_and_force_archives_instead() {
    let app = TestApp::new().await;
    let (owner, slug) = owner_org(&app, "owner@corp.com", "acme").await;
    let bob = sign_in(&app, "bob@corp.com").await;
    add_member(&app, &owner, &slug, "bob@corp.com", "admin").await;
    publish(&app, &owner, &slug, "acme_core", "1.0.0").await;
    let bob_id = app.user_of("bob@corp.com").await;
    let path = format!("/api/v1/orgs/{slug}");

    // The confirmation must name the org.
    let mistyped = app.delete_with(&path, Some(&owner.access), serde_json::json!({ "confirm": "wrong" })).await;
    assert_eq!(mistyped.status, StatusCode::BAD_REQUEST);

    // Without force: a conflict that says how many packages are in the way.
    let refused = app.delete_with(&path, Some(&owner.access), serde_json::json!({ "confirm": slug })).await;
    assert_eq!(refused.status, StatusCode::CONFLICT);
    assert_eq!(refused.error_code(), "conflict");
    assert!(refused.json["error"]["message"].as_str().expect("message").contains("1 package"));

    // With force: archived, not erased — the name claim has to survive (S-18).
    let forced =
        app.delete_with(&path, Some(&owner.access), serde_json::json!({ "confirm": slug, "force": true })).await;
    assert_eq!(forced.status, StatusCode::OK, "{:?}", forced.json);
    assert_eq!(forced.json["data"]["archived"], true);
    assert_eq!(forced.json["data"]["packages"], 1);
    assert!(forced.json["data"]["sessions_revoked"].as_u64().expect("count") >= 1);

    let org = app.repos.orgs.get_by_slug(&slug).await.expect("lookup").expect("row still exists");
    assert!(org.is_archived());
    assert!(app.repos.packages.lookup_claim(Format::Pub, "acme_core").await.expect("claim").is_some());
    // Its packages serve nothing: private, unlisted, discontinued.
    let package = app.repos.packages.get_by_name(Format::Pub, "acme_core").await.expect("get").expect("row");
    assert_eq!(package.visibility, pub_core::package::Visibility::Private);
    assert!(package.unlisted && package.discontinued);
    // Every member lost their sessions (S-09) and the profile is gone from the read model.
    assert!(app.repos.sessions.list_for_user(bob_id).await.expect("sessions").is_empty());
    assert_eq!(app.get("/api/v1/sessions", Some(&bob.access)).await.status, StatusCode::UNAUTHORIZED);
    assert_eq!(app.get(&format!("/api/v1/orgs/{slug}"), None).await.status, StatusCode::NOT_FOUND);
    // And it is unmanageable: an archived org answers 404 on every management route.
    let fresh = app.login("owner@corp.com").await["access_token"].as_str().expect("token").to_owned();
    assert_eq!(
        app.patch(&path, Some(&fresh), serde_json::json!({ "description": "x" })).await.status,
        StatusCode::NOT_FOUND
    );

    assert!(app.audit_actions().await.contains(&"org.deleted".to_owned()));
}

/// An org with nothing durable behind it is erased outright, slug and all.
#[tokio::test]
async fn an_empty_org_is_erased_rather_than_archived() {
    let app = TestApp::new().await;
    let (owner, slug) = owner_org(&app, "owner@corp.com", "acme").await;

    let deleted = app
        .delete_with(&format!("/api/v1/orgs/{slug}"), Some(&owner.access), serde_json::json!({ "confirm": slug }))
        .await;
    assert_eq!(deleted.status, StatusCode::OK, "{:?}", deleted.json);
    assert_eq!(deleted.json["data"]["archived"], false);
    assert_eq!(app.repos.orgs.get_by_slug(&slug).await.expect("lookup"), None);
}

// ------------------------------------------------------------------- package administration

/// Package options: the S-04 ordering, the role gate, and the effect on discovery.
#[tokio::test]
async fn s04_package_options_answers_404_before_it_answers_403() {
    let app = TestApp::new().await;
    let (owner, slug) = owner_org(&app, "owner@corp.com", "acme").await;
    publish(&app, &owner, &slug, "acme_secret", "1.0.0").await;
    let outsider = sign_in(&app, "outsider@corp.com").await;
    let path = "/api/v1/packages/acme_secret/options";
    let body = || serde_json::json!({ "visibility": "public" });

    // A principal who cannot *read* the package gets the same 404 an unknown name gets —
    // before the role is consulted, or the route would be an existence oracle.
    let hidden = app.patch(path, Some(&outsider.access), body()).await;
    assert_eq!(hidden.status, StatusCode::NOT_FOUND);
    assert_eq!(hidden.error_code(), "not_found");
    let unknown = app.patch("/api/v1/packages/nosuch_pkg/options", Some(&outsider.access), body()).await;
    assert_eq!(unknown.status, hidden.status);
    assert_eq!(unknown.error_code(), hidden.error_code());

    // A member who can read but not publish gets 403.
    app.login("reader@corp.com").await;
    add_member(&app, &owner, &slug, "reader@corp.com", "read").await;
    let reader = sign_in(&app, "reader@corp.com").await;
    assert_eq!(app.patch(path, Some(&reader.access), body()).await.status, StatusCode::FORBIDDEN);

    // Write may, and the change reaches the search index in the same breath.
    app.login("writer@corp.com").await;
    add_member(&app, &owner, &slug, "writer@corp.com", "write").await;
    let writer = sign_in(&app, "writer@corp.com").await;
    let updated = app
        .patch(
            path,
            Some(&writer.access),
            serde_json::json!({ "visibility": "public", "discontinued": true, "replaced_by": "acme_core2" }),
        )
        .await;
    assert_eq!(updated.status, StatusCode::OK, "{:?}", updated.json);
    assert_eq!(updated.json["data"]["visibility"], "public");
    assert_eq!(updated.json["data"]["replaced_by"], "acme_core2");

    let anonymous = app.get("/api/v1/packages?q=acme_secret", None).await;
    assert_eq!(anonymous.json["data"]["total"], 1, "a public package is discoverable");

    // Unlisting removes it from discovery again while keeping it readable by name.
    let unlisted = app.patch(path, Some(&writer.access), serde_json::json!({ "unlisted": true })).await;
    assert_eq!(unlisted.status, StatusCode::OK);
    assert_eq!(app.get("/api/v1/packages?q=acme_secret", None).await.json["data"]["total"], 0);
    assert_eq!(app.get("/api/v1/packages/acme_secret", None).await.status, StatusCode::OK);

    // A replacement that could never be a package name is refused rather than stored.
    let bad = app.patch(path, Some(&writer.access), serde_json::json!({ "replaced_by": "Not A Name" })).await;
    assert_eq!(bad.status, StatusCode::BAD_REQUEST);

    assert!(app.audit_actions().await.contains(&"package.options".to_owned()));
}

/// Decision 06's restore window, at both boundaries.
#[tokio::test]
async fn the_unretract_window_is_enforced_at_its_boundary() {
    let app = TestApp::new().await;
    let (owner, slug) = owner_org(&app, "owner@corp.com", "acme").await;
    publish(&app, &owner, &slug, "acme_core", "1.0.0").await;
    publish(&app, &owner, &slug, "acme_core", "1.1.0").await;

    let retract =
        app.post("/api/v1/packages/acme_core/versions/1.1.0/retract", Some(&owner.access), serde_json::json!({})).await;
    assert_eq!(retract.status, StatusCode::OK, "{:?}", retract.json);
    assert_eq!(retract.json["data"]["retracted"], true);
    assert!(retract.json["data"]["restorable_until"].is_string());
    // Retraction moves `latest` on the read model in the same breath. The package is private
    // by default, so the read has to be the owner's — an anonymous 404 here would pass for the
    // wrong reason.
    let detail = app.get("/api/v1/packages/acme_core", Some(&owner.access)).await;
    assert_eq!(detail.status, StatusCode::OK, "{:?}", detail.json);
    assert_eq!(detail.json["data"]["latest_version"], "1.0.0");

    // Inside the window (day 6 of 7): restorable.
    app.advance(Duration::days(6));
    let fresh = app.login("owner@corp.com").await["access_token"].as_str().expect("token").to_owned();
    let restored =
        app.post("/api/v1/packages/acme_core/versions/1.1.0/unretract", Some(&fresh), serde_json::json!({})).await;
    assert_eq!(restored.status, StatusCode::OK, "{:?}", restored.json);
    assert_eq!(restored.json["data"]["retracted"], false);
    assert_eq!(app.get("/api/v1/packages/acme_core", Some(&fresh)).await.json["data"]["latest_version"], "1.1.0");

    // Retract again, then step outside the window: refused, and the message names it.
    app.post("/api/v1/packages/acme_core/versions/1.1.0/retract", Some(&fresh), serde_json::json!({})).await;
    app.advance(Duration::days(7) + Duration::minutes(1));
    let late = app.login("owner@corp.com").await["access_token"].as_str().expect("token").to_owned();
    let refused =
        app.post("/api/v1/packages/acme_core/versions/1.1.0/unretract", Some(&late), serde_json::json!({})).await;
    assert_eq!(refused.status, StatusCode::CONFLICT);
    assert_eq!(refused.error_code(), "conflict");
    assert!(refused.json["error"]["message"].as_str().expect("message").contains("7-day window"));

    // Restoring something that was never retracted is also a conflict, not a silent success.
    let never =
        app.post("/api/v1/packages/acme_core/versions/1.0.0/unretract", Some(&late), serde_json::json!({})).await;
    assert_eq!(never.status, StatusCode::CONFLICT);

    assert!(app.audit_actions().await.contains(&"package.retract".to_owned()));
}

/// Hard delete: three gates, a tombstone that survives, and a number that stays burned.
#[tokio::test]
async fn hard_delete_needs_admin_step_up_and_a_confirmation_and_leaves_a_tombstone() {
    let app = TestApp::new().await;
    let (owner, slug) = owner_org(&app, "owner@corp.com", "acme").await;
    publish(&app, &owner, &slug, "acme_core", "1.0.0").await;
    publish(&app, &owner, &slug, "acme_core", "1.1.0").await;
    let path = "/api/v1/packages/acme_core/versions/1.0.0";
    let good = || serde_json::json!({ "confirm": "acme_core@1.0.0", "reason": "leaked credential" });

    // A Write member may publish but may not erase: those are different authorities.
    app.login("writer@corp.com").await;
    add_member(&app, &owner, &slug, "writer@corp.com", "write").await;
    let writer = sign_in(&app, "writer@corp.com").await;
    assert_eq!(app.delete_with(path, Some(&writer.access), good()).await.status, StatusCode::FORBIDDEN);

    // The confirmation must name exactly this version, and a reason is required.
    let wrong = app
        .delete_with(path, Some(&owner.access), serde_json::json!({ "confirm": "acme_core@1.1.0", "reason": "x" }))
        .await;
    assert_eq!(wrong.status, StatusCode::BAD_REQUEST);
    let unreasoned = app
        .delete_with(path, Some(&owner.access), serde_json::json!({ "confirm": "acme_core@1.0.0", "reason": "  " }))
        .await;
    assert_eq!(unreasoned.status, StatusCode::BAD_REQUEST);

    // The real thing.
    let deleted = app.delete_with(path, Some(&owner.access), good()).await;
    assert_eq!(deleted.status, StatusCode::OK, "{:?}", deleted.json);
    assert_eq!(deleted.json["data"]["tombstone"], true);
    assert_eq!(deleted.json["data"]["blob_removed"], true);

    // Burned: invisible to the read model, and the number can never be republished (S-18).
    assert_eq!(app.get(path, None).await.status, StatusCode::NOT_FOUND);
    let org = app.repos.orgs.get_by_slug(&slug).await.unwrap().unwrap().id;
    let fresh = app.login("owner@corp.com").await["access_token"].as_str().expect("token").to_owned();
    let token = app.mint_token(&fresh, org, &["publish"]).await;
    let republished = app.publish(&format!("/o/{slug}/pub"), &token, &package_archive("acme_core", "1.0.0")).await;
    assert_eq!(republished.status, StatusCode::BAD_REQUEST, "a burned number must not come back");

    // A second delete of the same version is a conflict, not a second destruction.
    assert_eq!(app.delete_with(path, Some(&fresh), good()).await.status, StatusCode::CONFLICT);

    // The audit row carries the reason (S-22).
    let event = app.audit_event("package.hard_delete").await.expect("hard delete audited");
    let metadata = event.metadata.expect("metadata");
    assert_eq!(metadata["reason"], "leaked credential");
    assert_eq!(metadata["blob_removed"], true);
}

/// Transfer needs Owner on **both** sides, and moves the claim with the package.
#[tokio::test]
async fn package_transfer_requires_owner_of_both_orgs() {
    let app = TestApp::new().await;
    let (source, source_slug) = owner_org(&app, "owner@corp.com", "acme").await;
    publish(&app, &source, &source_slug, "acme_core", "1.0.0").await;
    // A second org owned by somebody else.
    let (_other, other_slug) = owner_org(&app, "other@corp.com", "other").await;
    let source = sign_in(&app, "owner@corp.com").await;
    let path = "/api/v1/packages/acme_core/transfer";
    let body = || serde_json::json!({ "target_org": other_slug, "confirm": "acme_core" });

    // Owner of the source only: refused on the receiving side.
    let denied = app.post(path, Some(&source.access), body()).await;
    assert_eq!(denied.status, StatusCode::FORBIDDEN);

    // An unknown target is 404; a mistyped confirmation is 400.
    assert_eq!(
        app.post(path, Some(&source.access), serde_json::json!({ "target_org": "nosuch", "confirm": "acme_core" }))
            .await
            .status,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        app.post(path, Some(&source.access), serde_json::json!({ "target_org": other_slug, "confirm": "wrong" }))
            .await
            .status,
        StatusCode::BAD_REQUEST
    );

    // Owner of both: it moves, claim included.
    let other_owner = sign_in(&app, "other@corp.com").await;
    add_member(&app, &other_owner, &other_slug, "owner@corp.com", "owner").await;
    let source = sign_in(&app, "owner@corp.com").await;
    let moved = app.post(path, Some(&source.access), body()).await;
    assert_eq!(moved.status, StatusCode::OK, "{:?}", moved.json);
    assert_eq!(moved.json["data"]["org"], other_slug);

    let target_id = app.repos.orgs.get_by_slug(&other_slug).await.unwrap().unwrap().id;
    assert_eq!(app.repos.packages.get_by_name(Format::Pub, "acme_core").await.unwrap().unwrap().org_id, target_id);
    assert_eq!(app.repos.packages.lookup_claim(Format::Pub, "acme_core").await.unwrap().unwrap().org_id, target_id);
    // The new owner can publish the name; the old one now holds nothing.
    let token = app.mint_token(&source.access, target_id, &["publish"]).await;
    let published = app.publish(&format!("/o/{other_slug}/pub"), &token, &package_archive("acme_core", "2.0.0")).await;
    assert_eq!(published.status, StatusCode::OK, "{:?}", published.json);

    assert!(app.audit_actions().await.contains(&"package.transfer".to_owned()));
}

/// Every management route is in the generated spec — the frontend's types come from it.
#[tokio::test]
async fn openapi_documents_the_management_surface() {
    let app = TestApp::new().await;
    let spec = app.get("/api/openapi.json", None).await;
    assert_eq!(spec.status, StatusCode::OK);
    let paths = &spec.json["paths"];

    for (path, method) in [
        ("/api/v1/orgs/{slug}", "patch"),
        ("/api/v1/orgs/{slug}", "delete"),
        ("/api/v1/orgs/{slug}/members", "get"),
        ("/api/v1/orgs/{slug}/members", "post"),
        ("/api/v1/orgs/{slug}/members/{user_id}", "patch"),
        ("/api/v1/orgs/{slug}/members/{user_id}", "delete"),
        ("/api/v1/orgs/{slug}/invitations", "get"),
        ("/api/v1/orgs/{slug}/invitations", "post"),
        ("/api/v1/orgs/{slug}/invitations/{id}", "delete"),
        ("/api/v1/invitations/accept", "post"),
        ("/api/v1/packages/{name}/options", "patch"),
        ("/api/v1/packages/{name}/versions/{version}/retract", "post"),
        ("/api/v1/packages/{name}/versions/{version}/unretract", "post"),
        ("/api/v1/packages/{name}/versions/{version}", "delete"),
        ("/api/v1/packages/{name}/transfer", "post"),
    ] {
        assert!(paths.get(path).is_some(), "missing {path}");
        assert!(paths[path].get(method).is_some(), "{path} has no {method}");
    }
    // The GET and the DELETE share one path item rather than one overwriting the other.
    assert!(paths["/api/v1/packages/{name}/versions/{version}"].get("get").is_some());

    let schemas = &spec.json["components"]["schemas"];
    for schema in [
        "OrgUpdateBody",
        "OrgDeleteBody",
        "OrgDeletedDto",
        "MemberDto",
        "MemberAddBody",
        "MemberRoleBody",
        "MembershipChangedDto",
        "InvitationDto",
        "InvitationCreatedDto",
        "PackageOptionsBody",
        "VersionRetractedDto",
        "HardDeleteBody",
        "HardDeletedDto",
        "PackageTransferBody",
    ] {
        assert!(schemas.get(schema).is_some(), "missing schema {schema}");
    }
}
