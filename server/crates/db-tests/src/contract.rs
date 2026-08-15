//! The contract functions. Each takes a freshly migrated, empty database and exercises one
//! repository trait end to end, corner cases included. Panics (assert) on violation — the
//! caller wraps each function in its own test.

use std::collections::BTreeMap;
use std::future::Future;
use std::task::Poll;
use std::time::Duration;

use chrono::{DateTime, TimeZone as _, Utc};
use pub_core::audit::{AuditActor, AuditFilter, AuditResult, NewAuditEvent};
use pub_core::authorize::ActorContext;
use pub_core::credential::CredentialType;
use pub_core::event::EventId;
use pub_core::notification::{NewNotification, NotificationCategory, NotificationPreference, NotificationPreferences};
use pub_core::org::{NewInvitation, NewOrg, OrgProfile, UpstreamPolicy};
use pub_core::package::{
    BaseScope, NewPackage, NewUpstreamVersion, NewVersion, PackageOptions, Publisher, Resolution, UpstreamSnapshot,
    Visibility,
};
use pub_core::queue::{JobKind, MailJob, NewQueuedJob, QueueOutcome, QueuePurged, QueueRetention, QueueState};
use pub_core::search::{SearchDocument, SearchHit, SearchSort, SearchView, parse_query};
use pub_core::session::{NewSession, SessionLimits};
use pub_core::stats::{DownloadDelta, DownloadTotals};
use pub_core::token::{NewToken, TokenScope};
use pub_core::traits::Repositories;
use pub_core::user::{NewUser, UserFilter, UserStatus};
use pub_core::{Format, OrgId, PackageId, QueuedJobId, RoleLevel, SemVer, UserId};

/// The recipient cap both dialects enforce on a batched notification write or read.
///
/// Restated here rather than imported: the contract is "past the cap it is a caller error",
/// and a suite that read the backends' own constant could not notice one of them drifting.
const MAX_NOTIFICATION_BATCH: usize = 500;

/// Batch bound used where a retention scenario is about *what* is deleted rather than about the
/// bound itself. Large enough that one call drains the fixture, so the assertion under test stays
/// the predicate; the bound has its own scenarios.
const PURGE_BATCH: u32 = 1_000;

/// Deterministic base instant for every scenario (no wall clock in tests).
fn t0() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 8, 6, 12, 0, 0).unwrap()
}

fn days(n: i64) -> chrono::Duration {
    chrono::Duration::days(n)
}

fn hours(n: i64) -> chrono::Duration {
    chrono::Duration::hours(n)
}

fn minutes(n: i64) -> chrono::Duration {
    chrono::Duration::minutes(n)
}

fn seconds(n: i64) -> chrono::Duration {
    chrono::Duration::seconds(n)
}

/// Creates an active user with a verified email.
async fn seed_user(repos: &Repositories, email: &str, name: &str) -> pub_core::user::User {
    repos
        .users
        .create(NewUser { email: Some(email.to_owned()), email_verified: true, display_name: name.to_owned() }, t0())
        .await
        .expect("seed user")
}

/// Creates an org owned by `owner`.
async fn seed_org(repos: &Repositories, slug: &str, owner: UserId) -> pub_core::org::Org {
    repos.orgs.create(NewOrg::new(slug.to_uppercase(), slug), owner, t0()).await.expect("seed org")
}

/// `UserRepo`: create/get/find_by_email/update_status incl. case-insensitive uniqueness and
/// delete-anonymization.
pub async fn user_repo(repos: &Repositories) {
    repos.users.ping().await.expect("ping");

    let alice = seed_user(repos, "alice@corp.com", "Alice").await;
    assert_eq!(alice.email.as_deref(), Some("alice@corp.com"));
    assert!(alice.email_verified);
    assert_eq!(alice.status, UserStatus::Active);
    assert_eq!(alice.created_at, t0());
    assert_eq!(alice.updated_at, t0());

    // get: hit and miss.
    assert_eq!(repos.users.get(alice.id).await.expect("get"), Some(alice.clone()));
    assert_eq!(repos.users.get(UserId::new()).await.expect("get unknown"), None);

    // find_by_email is case-insensitive and only sees verified emails.
    let found = repos.users.find_by_email("ALICE@Corp.Com").await.expect("find");
    assert_eq!(found, Some(alice.clone()));
    let bob = repos
        .users
        .create(
            NewUser { email: Some("bob@corp.com".to_owned()), email_verified: false, display_name: "Bob".to_owned() },
            t0(),
        )
        .await
        .expect("unverified user");
    assert_eq!(repos.users.find_by_email("bob@corp.com").await.expect("find unverified"), None);

    // Duplicate email differing only by case is a conflict.
    let err = repos
        .users
        .create(
            NewUser { email: Some("Alice@CORP.com".to_owned()), email_verified: false, display_name: "A2".to_owned() },
            t0(),
        )
        .await
        .expect_err("duplicate email must conflict");
    assert_eq!(err.code(), "conflict");

    // Email-less accounts coexist: uniqueness is partial (WHERE email IS NOT NULL), so NULL
    // never collides with NULL.
    repos
        .users
        .create(NewUser { email: None, email_verified: false, display_name: "Ghost 1".to_owned() }, t0())
        .await
        .expect("first email-less user");
    repos
        .users
        .create(NewUser { email: None, email_verified: false, display_name: "Ghost 2".to_owned() }, t0())
        .await
        .expect("second email-less user must not collide on NULL email");

    // `get_many` is the N+1 killer for listings that show a person per row. Order is
    // unspecified and unknown ids are simply absent — a deleted account is a gap, not an error.
    let batch = repos.users.get_many(&[alice.id, bob.id, UserId::new()]).await.expect("batch");
    let mut ids: Vec<UserId> = batch.iter().map(|user| user.id).collect();
    ids.sort_unstable();
    let mut expected = vec![alice.id, bob.id];
    expected.sort_unstable();
    assert_eq!(ids, expected, "known ids come back, unknown ones are absent");
    assert!(repos.users.get_many(&[]).await.expect("empty batch").is_empty());

    // Status updates bump updated_at.
    let suspended = repos.users.update_status(bob.id, UserStatus::Suspended, t0() + hours(1)).await.expect("suspend");
    assert_eq!(suspended.status, UserStatus::Suspended);
    assert_eq!(suspended.updated_at, t0() + hours(1));
    assert_eq!(suspended.created_at, t0());

    // Deletion anonymizes (S-29): profile gone, email slot freed, row remains.
    let deleted = repos.users.update_status(alice.id, UserStatus::Deleted, t0() + hours(2)).await.expect("delete");
    assert_eq!(deleted.status, UserStatus::Deleted);
    assert_eq!(deleted.email, None);
    assert!(!deleted.email_verified);
    assert_ne!(deleted.display_name, "Alice");
    assert_eq!(repos.users.find_by_email("alice@corp.com").await.expect("find deleted"), None);
    assert!(repos.users.get(alice.id).await.expect("tombstone row").is_some());
    // The email is reusable by a new account now.
    seed_user(repos, "alice@corp.com", "Alice II").await;

    // Unknown id is NotFound.
    let err = repos.users.update_status(UserId::new(), UserStatus::Suspended, t0()).await.expect_err("unknown user");
    assert_eq!(err.code(), "not_found");
}

/// `CredentialRepo`: oidc upsert semantics (refresh vs foreign conflict), email identities,
/// listing.
pub async fn credential_repo(repos: &Repositories) {
    repos.credentials.ping().await.expect("ping");

    let alice = seed_user(repos, "alice@corp.com", "Alice").await;
    let bob = seed_user(repos, "bob@corp.com", "Bob").await;
    let issuer = "https://accounts.google.com";

    // First upsert creates.
    let cred = repos.credentials.upsert_oidc(alice.id, issuer, "sub-1", t0()).await.expect("create oidc");
    assert_eq!(cred.credential_type, CredentialType::Oidc);
    assert_eq!(cred.user_id, alice.id);
    assert_eq!(cred.issuer.as_deref(), Some(issuer));
    assert_eq!(cred.subject.as_deref(), Some("sub-1"));
    assert_eq!(cred.email, None);

    // find_oidc: hit and miss.
    assert_eq!(repos.credentials.find_oidc(issuer, "sub-1").await.expect("find"), Some(cred.clone()));
    assert_eq!(repos.credentials.find_oidc(issuer, "sub-2").await.expect("find miss"), None);

    // Second upsert by the same user refreshes the same row.
    let refreshed = repos.credentials.upsert_oidc(alice.id, issuer, "sub-1", t0() + hours(1)).await.expect("refresh");
    assert_eq!(refreshed.id, cred.id);
    assert_eq!(refreshed.updated_at, t0() + hours(1));
    assert_eq!(refreshed.created_at, t0());

    // The same identity for a different user never re-binds silently (S-02).
    let err = repos.credentials.upsert_oidc(bob.id, issuer, "sub-1", t0()).await.expect_err("foreign identity");
    assert_eq!(err.code(), "conflict");

    // The identity key is (issuer, subject) — the same subject under another issuer is a
    // distinct identity, not a conflict (S-01).
    let other_issuer = "https://idp.corp.example";
    let cred2 = repos
        .credentials
        .upsert_oidc(alice.id, other_issuer, "sub-1", t0() + chrono::Duration::minutes(1))
        .await
        .expect("same subject, different issuer");
    assert_ne!(cred2.id, cred.id);
    assert_eq!(repos.credentials.find_oidc(other_issuer, "sub-1").await.expect("find 2nd"), Some(cred2.clone()));

    // Email identity.
    let email_cred =
        repos.credentials.create_email_identity(alice.id, "alice@corp.com", t0() + hours(2)).await.expect("email");
    assert_eq!(email_cred.credential_type, CredentialType::Email);
    assert_eq!(email_cred.email.as_deref(), Some("alice@corp.com"));
    // Duplicate (case-insensitive) for the same user conflicts.
    let err = repos
        .credentials
        .create_email_identity(alice.id, "ALICE@corp.com", t0())
        .await
        .expect_err("duplicate email identity");
    assert_eq!(err.code(), "conflict");
    // The same address as somebody else's identity is fine — uniqueness is per user.
    repos.credentials.create_email_identity(bob.id, "alice@corp.com", t0()).await.expect("other user same email");

    // Listing is oldest-first and complete.
    let creds = repos.credentials.list_for_user(alice.id).await.expect("list");
    assert_eq!(creds.len(), 3);
    assert_eq!(creds[0].id, cred.id);
    assert_eq!(creds[1].id, cred2.id);
    assert_eq!(creds[2].id, email_cred.id);
}

/// `CredentialRepo` second factor (S-05): TOTP enrollment with an atomic monotonic replay
/// floor, single-use recovery codes, and full second-factor removal.
pub async fn second_factor(repos: &Repositories) {
    let alice = seed_user(repos, "alice2fa@corp.com", "Alice").await;
    let sealed = b"opaque-kek-sealed-seed".to_vec();

    // No enrollment yet.
    assert_eq!(repos.credentials.find_totp(alice.id).await.expect("find none"), None);

    // Enroll: the sealed seed and the confirmation step round-trip.
    let cred = repos.credentials.create_totp(alice.id, &sealed, 41, t0()).await.expect("create totp");
    assert_eq!(cred.credential_type, CredentialType::Totp);
    let stored = repos.credentials.find_totp(alice.id).await.expect("find").expect("enrolled");
    assert_eq!(stored.id, cred.id);
    assert_eq!(stored.secret_enc, sealed);
    assert_eq!(stored.last_step, Some(41));

    // Double enrollment conflicts (one active TOTP per user).
    let err = repos.credentials.create_totp(alice.id, &sealed, 1, t0()).await.expect_err("double enroll");
    assert_eq!(err.code(), "conflict");

    // The replay floor only ever moves forward: same or older steps are rejected.
    assert!(repos.credentials.commit_totp_step(cred.id, 42, t0()).await.expect("advance"));
    assert!(!repos.credentials.commit_totp_step(cred.id, 42, t0()).await.expect("replay"), "same step must fail");
    assert!(!repos.credentials.commit_totp_step(cred.id, 41, t0()).await.expect("older"), "older step must fail");
    assert!(repos.credentials.commit_totp_step(cred.id, 44, t0()).await.expect("skip forward"));
    assert_eq!(repos.credentials.find_totp(alice.id).await.expect("find").expect("row").last_step, Some(44));

    // Recovery codes: replace, list, consume exactly once.
    let hashes: Vec<String> = (0..3).map(|i| format!("$argon2id$fake-{i}")).collect();
    repos.credentials.replace_recovery_codes(alice.id, &hashes, t0()).await.expect("store codes");
    let listed = repos.credentials.list_recovery_codes(alice.id).await.expect("list codes");
    assert_eq!(listed.len(), 3);
    let mut phcs: Vec<&str> = listed.iter().map(|c| c.phc.as_str()).collect();
    phcs.sort_unstable();
    assert_eq!(phcs, ["$argon2id$fake-0", "$argon2id$fake-1", "$argon2id$fake-2"]);

    let victim = listed[0].id;
    assert!(repos.credentials.consume_recovery_code(victim).await.expect("consume"));
    assert!(!repos.credentials.consume_recovery_code(victim).await.expect("re-consume"), "single-use (S-05)");
    assert_eq!(repos.credentials.list_recovery_codes(alice.id).await.expect("list").len(), 2);

    // Replacing wipes the remainder and installs the new set.
    let fresh: Vec<String> = (0..2).map(|i| format!("$argon2id$new-{i}")).collect();
    repos.credentials.replace_recovery_codes(alice.id, &fresh, t0() + hours(1)).await.expect("replace");
    assert_eq!(repos.credentials.list_recovery_codes(alice.id).await.expect("list").len(), 2);

    // Disable removes TOTP + recovery in one sweep, and is idempotent.
    let removed = repos.credentials.delete_second_factor(alice.id).await.expect("disable");
    assert_eq!(removed, 3, "one totp row + two recovery rows");
    assert_eq!(repos.credentials.find_totp(alice.id).await.expect("find"), None);
    assert!(repos.credentials.list_recovery_codes(alice.id).await.expect("list").is_empty());
    assert_eq!(repos.credentials.delete_second_factor(alice.id).await.expect("again"), 0);

    // A fresh enrollment works after disable.
    repos.credentials.create_totp(alice.id, &sealed, 7, t0() + hours(2)).await.expect("re-enroll");
}

/// `OrgRepo` core: create (creator becomes Owner atomically), lookups, member ops, and the
/// last-Owner invariant.
pub async fn org_repo(repos: &Repositories) {
    repos.orgs.ping().await.expect("ping");

    let alice = seed_user(repos, "alice@corp.com", "Alice").await;
    let bob = seed_user(repos, "bob@corp.com", "Bob").await;

    let org = seed_org(repos, "acme", alice.id).await;
    assert_eq!(org.slug, "acme");
    assert_eq!(org.created_at, t0());

    // The creator is Owner from the same transaction.
    let owner = repos.orgs.get_member(org.id, alice.id).await.expect("get member").expect("creator membership");
    assert_eq!(owner.role, RoleLevel::OWNER);

    // Lookups; slug matching is case-insensitive.
    assert_eq!(repos.orgs.get(org.id).await.expect("get"), Some(org.clone()));
    assert_eq!(repos.orgs.get(OrgId::new()).await.expect("get unknown"), None);
    assert_eq!(repos.orgs.get_by_slug("ACME").await.expect("slug"), Some(org.clone()));
    assert_eq!(repos.orgs.get_by_slug("nope").await.expect("slug unknown"), None);

    // Duplicate slug differing only by case conflicts.
    let err = repos.orgs.create(NewOrg::new("Acme 2", "AcMe"), alice.id, t0()).await.expect_err("duplicate slug");
    assert_eq!(err.code(), "conflict");

    // Decision 01: a fresh org inherits the instance's proxy posture, and the policy is a
    // durable, separately-settable field — flipping it changes what an entire team resolves.
    assert_eq!(org.upstream_policy, UpstreamPolicy::Allow);
    let blocked =
        repos.orgs.set_upstream_policy(org.id, UpstreamPolicy::Block, t0() + hours(6)).await.expect("block upstream");
    assert_eq!(blocked.upstream_policy, UpstreamPolicy::Block);
    assert_eq!(blocked.updated_at, t0() + hours(6));
    assert_eq!(blocked.created_at, t0(), "a policy change is not a re-creation");
    // Every read path carries it, not just the one that wrote it.
    assert_eq!(repos.orgs.get(org.id).await.expect("get").expect("org").upstream_policy, UpstreamPolicy::Block);
    assert_eq!(
        repos.orgs.get_by_slug("acme").await.expect("slug").expect("org").upstream_policy,
        UpstreamPolicy::Block
    );
    repos.orgs.set_upstream_policy(org.id, UpstreamPolicy::Allow, t0() + hours(7)).await.expect("restore");
    let err = repos.orgs.set_upstream_policy(OrgId::new(), UpstreamPolicy::Block, t0()).await.expect_err("unknown org");
    assert_eq!(err.code(), "not_found");

    // add_member: happy path, duplicates, invalid role, unknown user.
    let member = repos.orgs.add_member(org.id, bob.id, RoleLevel::READ, t0() + hours(1)).await.expect("add member");
    assert_eq!(member.role, RoleLevel::READ);
    let err = repos.orgs.add_member(org.id, bob.id, RoleLevel::WRITE, t0()).await.expect_err("duplicate member");
    assert_eq!(err.code(), "conflict");
    let err = repos.orgs.add_member(org.id, bob.id, RoleLevel::NONE, t0()).await.expect_err("role 0");
    assert_eq!(err.code(), "invalid_argument");
    let err = repos.orgs.add_member(org.id, UserId::new(), RoleLevel::READ, t0()).await.expect_err("unknown user");
    assert_eq!(err.code(), "not_found");

    // list_for_user reflects memberships and roles.
    let bob_orgs = repos.orgs.list_for_user(bob.id).await.expect("list orgs");
    assert_eq!(bob_orgs.len(), 1);
    assert_eq!(bob_orgs[0].org.id, org.id);
    assert_eq!(bob_orgs[0].org.upstream_policy, UpstreamPolicy::Allow, "the joined listing carries the policy too");
    assert_eq!(bob_orgs[0].role, RoleLevel::READ);

    // update_member_role: happy path and NotFound.
    let member =
        repos.orgs.update_member_role(org.id, bob.id, RoleLevel::WRITE, t0() + hours(2)).await.expect("promote");
    assert_eq!(member.role, RoleLevel::WRITE);
    assert_eq!(member.updated_at, t0() + hours(2));
    let err = repos
        .orgs
        .update_member_role(org.id, UserId::new(), RoleLevel::READ, t0())
        .await
        .expect_err("unknown membership");
    assert_eq!(err.code(), "not_found");

    // Last-Owner invariant: the only Owner can be neither demoted nor removed.
    let err =
        repos.orgs.update_member_role(org.id, alice.id, RoleLevel::ADMIN, t0()).await.expect_err("demote last owner");
    assert_eq!(err.code(), "last_owner");
    let err = repos.orgs.remove_member(org.id, alice.id).await.expect_err("remove last owner");
    assert_eq!(err.code(), "last_owner");

    // With a second Owner both operations pass.
    repos.orgs.update_member_role(org.id, bob.id, RoleLevel::OWNER, t0() + hours(3)).await.expect("second owner");
    repos.orgs.update_member_role(org.id, alice.id, RoleLevel::ADMIN, t0() + hours(4)).await.expect("demote ok now");
    // … but now bob is the last Owner.
    let err = repos.orgs.remove_member(org.id, bob.id).await.expect_err("bob is last owner now");
    assert_eq!(err.code(), "last_owner");
    repos.orgs.update_member_role(org.id, alice.id, RoleLevel::OWNER, t0() + hours(5)).await.expect("re-promote");
    repos.orgs.remove_member(org.id, bob.id).await.expect("remove non-last owner");
    assert_eq!(repos.orgs.get_member(org.id, bob.id).await.expect("gone"), None);
    let err = repos.orgs.remove_member(org.id, bob.id).await.expect_err("remove twice");
    assert_eq!(err.code(), "not_found");
}

/// `OrgRepo` invitations: hashed single-use token, email binding, expiry, revocation,
/// role-raising acceptance.
pub async fn invitations(repos: &Repositories) {
    let alice = seed_user(repos, "alice@corp.com", "Alice").await;
    let bob = seed_user(repos, "bob@corp.com", "Bob").await;
    let mallory = seed_user(repos, "mallory@evil.com", "Mallory").await;
    let org = seed_org(repos, "acme", alice.id).await;
    let expires = t0() + days(7);

    // Create: default role is Read; hash is unique.
    let inv = repos
        .orgs
        .create_invitation(NewInvitation::new(org.id, "bob@corp.com", alice.id, "inv-hash-1", expires), t0())
        .await
        .expect("create invitation");
    assert_eq!(inv.role, RoleLevel::READ);
    assert_eq!(inv.email, "bob@corp.com");
    assert_eq!(inv.expires_at, expires);
    assert_eq!((inv.accepted_at, inv.revoked_at), (None, None));
    let err = repos
        .orgs
        .create_invitation(NewInvitation::new(org.id, "x@corp.com", alice.id, "inv-hash-1", expires), t0())
        .await
        .expect_err("duplicate token hash");
    assert_eq!(err.code(), "conflict");

    // Lookup by hash.
    assert_eq!(repos.orgs.find_invitation_by_token_hash("inv-hash-1").await.expect("find"), Some(inv.clone()));
    assert_eq!(repos.orgs.find_invitation_by_token_hash("nope").await.expect("find miss"), None);

    // Email binding: wrong email is Forbidden, unverified matching email too.
    let err = repos.orgs.accept_invitation("inv-hash-1", mallory.id, t0() + days(1)).await.expect_err("wrong email");
    assert_eq!(err.code(), "forbidden");
    let carol = repos
        .users
        .create(
            NewUser { email: Some("carol@corp.com".to_owned()), email_verified: false, display_name: "C".to_owned() },
            t0(),
        )
        .await
        .expect("carol");
    let inv_carol = repos
        .orgs
        .create_invitation(NewInvitation::new(org.id, "carol@corp.com", alice.id, "inv-hash-c", expires), t0())
        .await
        .expect("carol invitation");
    let err = repos.orgs.accept_invitation("inv-hash-c", carol.id, t0() + days(1)).await.expect_err("unverified email");
    assert_eq!(err.code(), "forbidden");

    // Unknown hash is NotFound.
    let err = repos.orgs.accept_invitation("nope", bob.id, t0()).await.expect_err("unknown invitation");
    assert_eq!(err.code(), "not_found");

    // Accept: consume + membership in one step; email match is case-insensitive.
    let accepted = repos.orgs.accept_invitation("inv-hash-1", bob.id, t0() + days(2)).await.expect("accept");
    assert_eq!(accepted.accepted_at, Some(t0() + days(2)));
    assert_eq!(accepted.accepted_by, Some(bob.id));
    let member = repos.orgs.get_member(org.id, bob.id).await.expect("member").expect("bob joined");
    assert_eq!(member.role, RoleLevel::READ);

    // Double-accept is a conflict (single-use).
    let err = repos.orgs.accept_invitation("inv-hash-1", bob.id, t0() + days(3)).await.expect_err("double accept");
    assert_eq!(err.code(), "conflict");

    // Expiry: acceptance strictly before expires_at only. The invited email deliberately
    // differs in case from Bob's stored address — the binding must match case-insensitively.
    repos
        .orgs
        .create_invitation(
            NewInvitation {
                role: RoleLevel::WRITE,
                ..NewInvitation::new(org.id, "BOB@Corp.COM", alice.id, "inv-hash-2", expires)
            },
            t0(),
        )
        .await
        .expect("second invitation");
    let err = repos.orgs.accept_invitation("inv-hash-2", bob.id, expires).await.expect_err("expired at boundary");
    assert_eq!(err.code(), "expired");
    // Still valid one second earlier — and acceptance raises Bob's role to Write.
    let accepted = repos
        .orgs
        .accept_invitation("inv-hash-2", bob.id, expires - chrono::Duration::seconds(1))
        .await
        .expect("accept before expiry");
    assert_eq!(accepted.role, RoleLevel::WRITE);
    let member = repos.orgs.get_member(org.id, bob.id).await.expect("member").expect("bob");
    assert_eq!(member.role, RoleLevel::WRITE, "invitation must raise the role");

    // A Read invitation for a Write member never lowers the role.
    repos
        .orgs
        .create_invitation(NewInvitation::new(org.id, "bob@corp.com", alice.id, "inv-hash-3", expires), t0())
        .await
        .expect("third invitation");
    repos.orgs.accept_invitation("inv-hash-3", bob.id, t0() + days(3)).await.expect("accept lower");
    let member = repos.orgs.get_member(org.id, bob.id).await.expect("member").expect("bob");
    assert_eq!(member.role, RoleLevel::WRITE, "invitation must never lower the role");

    // Revocation: pending only, then acceptance fails with conflict.
    let revoked = repos.orgs.revoke_invitation(inv_carol.id, t0() + days(1)).await.expect("revoke");
    assert_eq!(revoked.revoked_at, Some(t0() + days(1)));
    let err = repos.orgs.accept_invitation("inv-hash-c", carol.id, t0() + days(2)).await.expect_err("accept revoked");
    assert_eq!(err.code(), "conflict");
    let err = repos.orgs.revoke_invitation(inv_carol.id, t0()).await.expect_err("revoke twice");
    assert_eq!(err.code(), "conflict");
    let err = repos.orgs.revoke_invitation(pub_core::InvitationId::new(), t0()).await.expect_err("revoke unknown");
    assert_eq!(err.code(), "not_found");

    // Listing shows every lifecycle state.
    let all = repos.orgs.list_invitations(org.id).await.expect("list");
    assert_eq!(all.len(), 4);
    assert!(all.iter().any(|i| i.revoked_at.is_some()));
    assert!(all.iter().any(|i| i.accepted_at.is_some()));
}

/// `SessionRepo`: rotation with reuse detection, idle/absolute predicates, throttled touch,
/// revocation.
pub async fn session_repo(repos: &Repositories) {
    repos.sessions.ping().await.expect("ping");

    let alice = seed_user(repos, "alice@corp.com", "Alice").await;
    let limits = SessionLimits::DEFAULT; // idle 30 d, absolute 90 d

    let session = repos
        .sessions
        .create(
            NewSession {
                user_id: alice.id,
                refresh_hash: "hash-a".to_owned(),
                user_agent: Some("Firefox".to_owned()),
                ip: Some("203.0.113.7".to_owned()),
            },
            t0(),
        )
        .await
        .expect("create session");
    assert_eq!(session.created_at, t0());
    assert_eq!(session.last_seen_at, t0());
    assert_eq!(session.revoked_at, None);
    // Device metadata round-trips verbatim (PG stores the ip as INET — no /32 suffix leaks).
    assert_eq!(session.user_agent.as_deref(), Some("Firefox"));
    assert_eq!(session.ip.as_deref(), Some("203.0.113.7"));

    // Hash lookup respects the idle window…
    assert_eq!(
        repos.sessions.find_by_refresh_hash("hash-a", &limits, t0() + days(29)).await.expect("find"),
        Some(session.clone())
    );
    assert_eq!(repos.sessions.find_by_refresh_hash("hash-a", &limits, t0() + days(31)).await.expect("idle"), None);
    assert_eq!(repos.sessions.find_by_refresh_hash("nope", &limits, t0()).await.expect("unknown"), None);

    // …and the absolute cap, independently of activity: keep the session fresh via touch,
    // then cross the 90-day line.
    assert!(repos.sessions.touch(session.id, Duration::from_secs(3600), t0() + days(89)).await.expect("touch"));
    assert!(
        repos
            .sessions
            .find_by_refresh_hash("hash-a", &limits, t0() + days(89) + hours(1))
            .await
            .expect("fresh again")
            .is_some()
    );
    assert_eq!(
        repos.sessions.find_by_refresh_hash("hash-a", &limits, t0() + days(91)).await.expect("absolute"),
        None,
        "absolute cap must invalidate an otherwise active session"
    );

    // Rotation: atomic swap, session identity stable.
    let rotated = repos.sessions.rotate("hash-a", "hash-b", &limits, t0() + days(89) + hours(2)).await.expect("rotate");
    assert_eq!(rotated.id, session.id);
    assert_eq!(rotated.last_seen_at, t0() + days(89) + hours(2));
    assert!(
        repos
            .sessions
            .find_by_refresh_hash("hash-a", &limits, t0() + days(89) + hours(2))
            .await
            .expect("old hash gone")
            .is_none()
    );
    assert!(
        repos
            .sessions
            .find_by_refresh_hash("hash-b", &limits, t0() + days(89) + hours(2))
            .await
            .expect("new hash live")
            .is_some()
    );

    // Reuse detection: the rotated-out hash is a theft signal naming the session (S-08).
    let err = repos
        .sessions
        .rotate("hash-a", "hash-x", &limits, t0() + days(89) + hours(3))
        .await
        .expect_err("reuse of rotated hash");
    assert_eq!(err.code(), "refresh_reused");
    match err {
        pub_core::Error::RefreshReused { session: sid } => assert_eq!(sid, session.id),
        other => panic!("expected RefreshReused, got {other:?}"),
    }

    // Rotating an unknown hash is NotFound; rotating an out-of-window session is Expired.
    let err = repos.sessions.rotate("nope", "hash-y", &limits, t0()).await.expect_err("unknown rotate");
    assert_eq!(err.code(), "not_found");
    let stale = repos
        .sessions
        .create(
            NewSession { user_id: alice.id, refresh_hash: "hash-stale".to_owned(), user_agent: None, ip: None },
            t0(),
        )
        .await
        .expect("stale session");
    let err =
        repos.sessions.rotate("hash-stale", "hash-z", &limits, t0() + days(31)).await.expect_err("expired rotate");
    assert_eq!(err.code(), "expired");

    // Touch is write-throttled: within the throttle window nothing is written.
    let s3 = repos
        .sessions
        .create(NewSession { user_id: alice.id, refresh_hash: "hash-t".to_owned(), user_agent: None, ip: None }, t0())
        .await
        .expect("touch session");
    // A refresh hash is unique across sessions (S-08): a duplicate is a conflict.
    let err = repos
        .sessions
        .create(NewSession { user_id: alice.id, refresh_hash: "hash-t".to_owned(), user_agent: None, ip: None }, t0())
        .await
        .expect_err("duplicate refresh hash");
    assert_eq!(err.code(), "conflict");
    let throttle = Duration::from_secs(15 * 60);
    assert!(!repos.sessions.touch(s3.id, throttle, t0() + chrono::Duration::minutes(10)).await.expect("throttled"));
    assert!(repos.sessions.touch(s3.id, throttle, t0() + chrono::Duration::minutes(20)).await.expect("past throttle"));
    assert!(!repos.sessions.touch(pub_core::SessionId::new(), throttle, t0()).await.expect("unknown touch"));

    // Revocation: durable, idempotent; revoked sessions vanish from lookups and rotation.
    repos.sessions.revoke(rotated.id, t0() + days(89) + hours(4)).await.expect("revoke");
    assert!(
        repos
            .sessions
            .find_by_refresh_hash("hash-b", &limits, t0() + days(89) + hours(4))
            .await
            .expect("revoked lookup")
            .is_none()
    );
    let err = repos
        .sessions
        .rotate("hash-b", "hash-w", &limits, t0() + days(89) + hours(4))
        .await
        .expect_err("rotate revoked");
    assert_eq!(err.code(), "not_found");
    repos.sessions.revoke(rotated.id, t0() + days(90)).await.expect("revoke is idempotent");
    let err = repos.sessions.revoke(pub_core::SessionId::new(), t0()).await.expect_err("revoke unknown");
    assert_eq!(err.code(), "not_found");

    // list_for_user: non-revoked only, most recently seen first.
    let listed = repos.sessions.list_for_user(alice.id).await.expect("list");
    let ids: Vec<_> = listed.iter().map(|s| s.id).collect();
    assert_eq!(ids, vec![s3.id, stale.id], "most recently seen first, revoked excluded");

    // revoke_all_for_user sweeps the rest.
    assert_eq!(repos.sessions.revoke_all_for_user(alice.id, t0() + days(1)).await.expect("revoke all"), 2);
    assert!(repos.sessions.list_for_user(alice.id).await.expect("list empty").is_empty());
    assert_eq!(repos.sessions.revoke_all_for_user(alice.id, t0() + days(1)).await.expect("nothing left"), 0);
}

/// `TokenRepo`: active-by-hash semantics (expiry, revocation, the D37 holder-status gate),
/// throttled usage tracking, listings.
pub async fn token_repo(repos: &Repositories) {
    repos.tokens.ping().await.expect("ping");

    let alice = seed_user(repos, "alice@corp.com", "Alice").await;
    let org = seed_org(repos, "acme", alice.id).await;

    let token = repos
        .tokens
        .create(
            NewToken {
                user_id: alice.id,
                org_id: org.id,
                name: "CI deploy".to_owned(),
                token_hash: "tok-hash-1".to_owned(),
                display_hint: "pub_a1b2".to_owned(),
                scopes: vec![TokenScope::Read, TokenScope::Publish],
                package_patterns: vec!["flutter_*".to_owned()],
                expires_at: Some(t0() + days(90)),
            },
            t0(),
        )
        .await
        .expect("create token");
    assert_eq!(token.scopes, vec![TokenScope::Read, TokenScope::Publish]);
    assert_eq!(token.package_patterns, vec!["flutter_*".to_owned()]);
    assert_eq!(token.expires_at, Some(t0() + days(90)));
    assert_eq!((token.last_used_at, token.revoked_at), (None, None));

    // Empty scopes are invalid; duplicate hashes conflict.
    let err = repos
        .tokens
        .create(
            NewToken {
                user_id: alice.id,
                org_id: org.id,
                name: "bad".to_owned(),
                token_hash: "tok-hash-x".to_owned(),
                display_hint: "pub_xxxx".to_owned(),
                scopes: vec![],
                package_patterns: vec![],
                expires_at: None,
            },
            t0(),
        )
        .await
        .expect_err("empty scopes");
    assert_eq!(err.code(), "invalid_argument");
    let err = repos
        .tokens
        .create(
            NewToken {
                user_id: alice.id,
                org_id: org.id,
                name: "dup".to_owned(),
                token_hash: "tok-hash-1".to_owned(),
                display_hint: "pub_dupe".to_owned(),
                scopes: vec![TokenScope::Read],
                package_patterns: vec![],
                expires_at: None,
            },
            t0(),
        )
        .await
        .expect_err("duplicate hash");
    assert_eq!(err.code(), "conflict");

    // Active lookup: live within expiry, gone at/after it; unknown hashes miss.
    assert!(repos.tokens.find_active_by_hash("tok-hash-1", t0() + days(1)).await.expect("live").is_some());
    assert!(repos.tokens.find_active_by_hash("tok-hash-1", t0() + days(90)).await.expect("expired").is_none());
    assert!(repos.tokens.find_active_by_hash("nope", t0()).await.expect("unknown").is_none());

    // A non-expiring token stays active arbitrarily far out.
    let forever = repos
        .tokens
        .create(
            NewToken {
                user_id: alice.id,
                org_id: org.id,
                name: "read forever".to_owned(),
                token_hash: "tok-hash-2".to_owned(),
                display_hint: "pub_c3d4".to_owned(),
                scopes: vec![TokenScope::Read],
                package_patterns: vec![],
                expires_at: None,
            },
            t0() + chrono::Duration::seconds(1),
        )
        .await
        .expect("non-expiring");
    assert!(repos.tokens.find_active_by_hash("tok-hash-2", t0() + days(10_000)).await.expect("eternal").is_some());

    // Throttled usage tracking.
    let throttle = Duration::from_secs(300);
    assert!(
        repos
            .tokens
            .touch_last_used(token.id, Some("203.0.113.9"), throttle, t0() + hours(1))
            .await
            .expect("first touch")
    );
    // The write is visible: last_used_at and the IP round-trip through the active lookup.
    let touched = repos
        .tokens
        .find_active_by_hash("tok-hash-1", t0() + hours(1))
        .await
        .expect("re-fetch touched")
        .expect("still active");
    assert_eq!(touched.last_used_at, Some(t0() + hours(1)));
    assert_eq!(touched.last_used_ip.as_deref(), Some("203.0.113.9"));
    assert!(
        !repos
            .tokens
            .touch_last_used(token.id, Some("203.0.113.9"), throttle, t0() + hours(1) + chrono::Duration::minutes(2))
            .await
            .expect("throttled touch")
    );
    assert!(
        repos.tokens.touch_last_used(token.id, None, throttle, t0() + hours(2)).await.expect("touch past throttle")
    );
    assert!(!repos.tokens.touch_last_used(pub_core::TokenId::new(), None, throttle, t0()).await.expect("unknown"));

    // Revocation: token disappears from the active lookup immediately.
    repos.tokens.revoke(token.id, t0() + hours(3)).await.expect("revoke");
    assert!(
        repos.tokens.find_active_by_hash("tok-hash-1", t0() + hours(3)).await.expect("revoked absent").is_none(),
        "a revoked token must be absent from find_active_by_hash"
    );
    assert!(!repos.tokens.touch_last_used(token.id, None, throttle, t0() + days(1)).await.expect("touch revoked"));
    repos.tokens.revoke(token.id, t0() + hours(4)).await.expect("revoke is idempotent");
    let err = repos.tokens.revoke(pub_core::TokenId::new(), t0()).await.expect_err("revoke unknown");
    assert_eq!(err.code(), "not_found");

    // Listings: newest first, revoked excluded, org and user views agree.
    let for_user = repos.tokens.list_for_user(alice.id).await.expect("list user");
    let ids: Vec<_> = for_user.iter().map(|t| t.id).collect();
    assert_eq!(ids, vec![forever.id]);
    let for_org = repos.tokens.list_for_org(org.id).await.expect("list org");
    assert_eq!(for_org.len(), 1);
    assert_eq!(for_org[0].id, forever.id);

    // D37 (decision 13 addendum): suspension gates the credential plane at this very lookup —
    // a suspended holder's token authenticates nothing, while the row itself is untouched, so
    // reinstatement restores it without a re-mint.
    repos.users.update_status(alice.id, UserStatus::Suspended, t0() + days(2)).await.expect("suspend");
    assert!(
        repos.tokens.find_active_by_hash("tok-hash-2", t0() + days(2)).await.expect("suspended lookup").is_none(),
        "a suspended user's token must not be found by find_active_by_hash"
    );
    assert_eq!(
        repos.tokens.list_for_user(alice.id).await.expect("list survives").len(),
        1,
        "suspension gates authentication, not the token list — the row is not revoked"
    );
    repos.users.update_status(alice.id, UserStatus::Active, t0() + days(3)).await.expect("reinstate");
    assert!(
        repos.tokens.find_active_by_hash("tok-hash-2", t0() + days(3)).await.expect("reinstated lookup").is_some(),
        "unsuspension must restore the token automatically"
    );

    // D37, the other half of the holder-status gate: it is `status = 'active'`, not "not
    // suspended", so a *deleted* holder's token dies at this same lookup. A second user
    // carries this leg — alice's rows above must stay exactly as asserted.
    let bob = seed_user(repos, "bob@corp.com", "Bob").await;
    repos
        .tokens
        .create(
            NewToken {
                user_id: bob.id,
                org_id: org.id,
                name: "outlives nobody".to_owned(),
                token_hash: "tok-hash-3".to_owned(),
                display_hint: "pub_e5f6".to_owned(),
                scopes: vec![TokenScope::Read],
                package_patterns: vec![],
                expires_at: None,
            },
            t0() + days(3),
        )
        .await
        .expect("bob token");
    assert!(
        repos.tokens.find_active_by_hash("tok-hash-3", t0() + days(3)).await.expect("live holder").is_some(),
        "the token authenticates while its holder is active"
    );
    repos.users.update_status(bob.id, UserStatus::Deleted, t0() + days(4)).await.expect("delete bob");
    assert!(
        repos.tokens.find_active_by_hash("tok-hash-3", t0() + days(4)).await.expect("deleted lookup").is_none(),
        "a deleted holder's token must not be found by find_active_by_hash"
    );
}

/// `AuditRepo`: append-only writes and filtered, cursor-stable listing.
pub async fn audit_repo(repos: &Repositories) {
    repos.audit.ping().await.expect("ping");

    let alice = seed_user(repos, "alice@corp.com", "Alice").await;
    let org = seed_org(repos, "acme", alice.id).await;
    let actor = AuditActor::User(alice.id);

    // Rich event: every field round-trips.
    let event = repos
        .audit
        .append(
            NewAuditEvent {
                actor,
                ip: Some("203.0.113.7".to_owned()),
                user_agent: Some("Firefox".to_owned()),
                org_id: Some(org.id),
                action: "org.member.add".to_owned(),
                target: Some("bob".to_owned()),
                result: AuditResult::Success,
                metadata: Some(serde_json::json!({"role": "read"})),
            },
            t0(),
        )
        .await
        .expect("append");
    assert_eq!(event.id.as_str().len(), 26);
    assert_eq!(event.created_at, t0());
    assert_eq!(event.actor, actor);
    assert_eq!(event.org_id, Some(org.id));
    assert_eq!(event.metadata, Some(serde_json::json!({"role": "read"})));
    // The ip round-trips verbatim (PG stores it as INET — no /32 suffix leaks).
    assert_eq!(event.ip.as_deref(), Some("203.0.113.7"));
    assert_eq!(event.user_agent.as_deref(), Some("Firefox"));
    assert_eq!(event.target.as_deref(), Some("bob"));
    assert_eq!(event.result, AuditResult::Success);

    // A spread of events for the filters.
    let sys = repos
        .audit
        .append(NewAuditEvent::new(AuditActor::System, "system.job.gc"), t0() + hours(1))
        .await
        .expect("sys");
    assert_eq!(sys.actor, AuditActor::System);
    repos
        .audit
        .append(
            NewAuditEvent { result: AuditResult::Failure, ..NewAuditEvent::new(actor, "auth.login.otp") },
            t0() + hours(2),
        )
        .await
        .expect("failure event");
    repos.audit.append(NewAuditEvent::new(actor, "auth.logout"), t0() + hours(3)).await.expect("logout");
    // LIKE metacharacters in actions must not act as wildcards in prefix filters.
    repos.audit.append(NewAuditEvent::new(actor, "a_b.probe"), t0() + hours(4)).await.expect("underscore");
    repos.audit.append(NewAuditEvent::new(actor, "axb.probe"), t0() + hours(4)).await.expect("wildcard bait");

    let all = repos.audit.list(&AuditFilter::default(), None, 100).await.expect("list all");
    assert_eq!(all.items.len(), 6);
    assert!(!all.has_more);
    assert_eq!(all.cursor, None);
    // Newest first.
    let times: Vec<_> = all.items.iter().map(|e| e.created_at).collect();
    let mut sorted = times.clone();
    sorted.sort_by(|a, b| b.cmp(a));
    assert_eq!(times, sorted);

    // Filters.
    let by_org =
        repos.audit.list(&AuditFilter { org: Some(org.id), ..Default::default() }, None, 100).await.expect("org");
    assert_eq!(by_org.items.len(), 1);
    let by_prefix = repos
        .audit
        .list(&AuditFilter { action_prefix: Some("auth.".to_owned()), ..Default::default() }, None, 100)
        .await
        .expect("prefix");
    assert_eq!(by_prefix.items.len(), 2);
    let underscore = repos
        .audit
        .list(&AuditFilter { action_prefix: Some("a_b".to_owned()), ..Default::default() }, None, 100)
        .await
        .expect("escaped underscore");
    assert_eq!(underscore.items.len(), 1, "LIKE `_` must be escaped in prefix filters");
    assert_eq!(underscore.items[0].action, "a_b.probe");
    let by_system = repos
        .audit
        .list(&AuditFilter { actor: Some(AuditActor::System), ..Default::default() }, None, 100)
        .await
        .expect("system actor");
    assert_eq!(by_system.items.len(), 1);
    let by_actor = repos
        .audit
        .list(&AuditFilter { actor: Some(actor), ..Default::default() }, None, 100)
        .await
        .expect("user actor");
    assert_eq!(by_actor.items.len(), 5);
    let in_window = repos
        .audit
        .list(
            &AuditFilter { from: Some(t0() + hours(1)), until: Some(t0() + hours(3)), ..Default::default() },
            None,
            100,
        )
        .await
        .expect("time range");
    assert_eq!(in_window.items.len(), 2, "half-open [from, until)");

    // Cursor pagination stays stable across equal timestamps: five events sharing one instant.
    let same_instant = t0() + days(1);
    for i in 0..5 {
        repos
            .audit
            .append(NewAuditEvent::new(AuditActor::System, format!("burst.{i}")), same_instant)
            .await
            .expect("burst");
    }
    let filter = AuditFilter { action_prefix: Some("burst.".to_owned()), ..Default::default() };
    let mut seen = Vec::new();
    let mut cursor: Option<String> = None;
    let mut pages = 0;
    loop {
        let page = repos.audit.list(&filter, cursor.as_deref(), 2).await.expect("page");
        assert!(page.items.len() <= 2);
        seen.extend(page.items.iter().map(|e| e.id.clone()));
        pages += 1;
        assert_eq!(page.cursor.is_some(), page.has_more, "cursor is Some iff has_more");
        if !page.has_more {
            break;
        }
        cursor = page.cursor;
    }
    assert_eq!(pages, 3);
    assert_eq!(seen.len(), 5, "no skips or duplicates across pages");
    let mut unique = seen.clone();
    unique.sort();
    unique.dedup();
    assert_eq!(unique.len(), 5);

    // Malformed cursors are rejected, tiny limits are clamped to one item.
    let err = repos.audit.list(&AuditFilter::default(), Some("not-a-ulid"), 10).await.expect_err("bad cursor");
    assert_eq!(err.code(), "invalid_argument");
    let one = repos.audit.list(&AuditFilter::default(), None, 0).await.expect("clamped limit");
    assert_eq!(one.items.len(), 1);
    assert!(one.has_more);
}

/// `SettingsRepo`: version bumps per key and the monotonic instance version.
pub async fn settings_repo(repos: &Repositories) {
    repos.settings.ping().await.expect("ping");

    assert!(repos.settings.get_all().await.expect("empty").is_empty());
    assert_eq!(repos.settings.get_version().await.expect("version 0"), 0);

    // First write of a key is version 1.
    let smtp = serde_json::json!({"host": "smtp.corp.com", "port": 587});
    assert_eq!(repos.settings.upsert("smtp", &smtp, t0()).await.expect("insert"), 1);
    assert_eq!(repos.settings.get_version().await.expect("version"), 1);

    // Updating the same key bumps its version.
    let smtp2 = serde_json::json!({"host": "smtp2.corp.com", "port": 465});
    assert_eq!(repos.settings.upsert("smtp", &smtp2, t0() + hours(1)).await.expect("update"), 2);
    assert_eq!(repos.settings.get_version().await.expect("version"), 2);

    // A different key starts at 1 again; the instance version keeps growing monotonically.
    assert_eq!(repos.settings.upsert("rate_limits", &serde_json::json!({"login": 10}), t0()).await.expect("other"), 1);
    assert_eq!(repos.settings.get_version().await.expect("version"), 3);

    // get_all: ordered by key, values round-trip.
    let all = repos.settings.get_all().await.expect("get_all");
    let keys: Vec<_> = all.iter().map(|e| e.key.as_str()).collect();
    assert_eq!(keys, vec!["rate_limits", "smtp"]);
    let smtp_entry = all.iter().find(|e| e.key == "smtp").unwrap();
    assert_eq!(smtp_entry.value, smtp2);
    assert_eq!(smtp_entry.version, 2);

    // `delete` (decision 29): the offline `pubd reset-smtp` path, and the only way a section
    // returns to "no stored decision" rather than "stored as empty".
    assert!(repos.settings.delete("smtp").await.expect("delete"), "deleting a present key reports true");
    let all = repos.settings.get_all().await.expect("get_all after delete");
    assert_eq!(all.iter().map(|e| e.key.as_str()).collect::<Vec<_>>(), vec!["rate_limits"]);
    // The instance version *drops* — the deleted key's 2 leaves the sum. The reconciliation
    // poll compares for inequality precisely so a peer still reloads on the way down; a `>`
    // comparison there would leave every other replica serving the section this just removed.
    assert_eq!(repos.settings.get_version().await.expect("version after delete"), 1);

    // Deleting an absent key is not an error, and says so rather than pretending it worked:
    // `reset-smtp` prints a different sentence for "there was nothing stored".
    assert!(!repos.settings.delete("smtp").await.expect("second delete"), "deleting an absent key reports false");
    assert!(!repos.settings.delete("never_written").await.expect("unknown key"));

    // Re-writing a deleted key starts at version 1 again, not at the version it had before.
    assert_eq!(repos.settings.upsert("smtp", &smtp, t0() + hours(2)).await.expect("re-insert"), 1);
    assert_eq!(repos.settings.get_version().await.expect("version after re-insert"), 2);
}

/// Builds a publish payload for `(org, name, version)` with deterministic content.
fn new_version(org: OrgId, name: &str, version: &str, publisher: UserId) -> NewVersion {
    NewVersion {
        format: Format::Pub,
        package_name: name.to_owned(),
        org_id: org,
        visibility: Visibility::Private,
        version: SemVer::parse(version).expect("valid version"),
        pubspec: serde_json::json!({ "name": name, "version": version }),
        // Distinct content per (name, version) — sha256 shape only matters to the column.
        archive_sha256: format!("{:0>64}", format!("{name}{version}").replace('.', "")),
        archive_size: 1024,
        published_by: Publisher { user_id: publisher, token_id: None },
        readme_html: None,
        changelog_html: None,
    }
}

/// `PackageRepo` package surface: creation, lookups, keyset listing, and option replacement.
pub async fn package_repo(repos: &Repositories) {
    repos.packages.ping().await.expect("ping");

    let alice = seed_user(repos, "alice@corp.com", "Alice").await;
    let org = seed_org(repos, "acme", alice.id).await;
    let other = seed_org(repos, "other", alice.id).await;

    // create_package claims the name in the same step (decision 01).
    let package = repos
        .packages
        .create_package(
            NewPackage {
                format: Format::Pub,
                name: "acme_core".to_owned(),
                org_id: org.id,
                visibility: Visibility::Public,
            },
            t0(),
        )
        .await
        .expect("create package");
    assert_eq!(package.name, "acme_core");
    assert_eq!(package.visibility, Visibility::Public);
    assert!(!package.discontinued && !package.unlisted);
    assert_eq!(package.replaced_by, None);
    assert_eq!((package.created_at, package.updated_at), (t0(), t0()));

    let claim = repos.packages.lookup_claim(Format::Pub, "acme_core").await.expect("claim").expect("claimed");
    assert_eq!(claim.org_id, org.id);
    assert_eq!(claim.claimed_at, t0());

    // Lookups: hit and miss.
    assert_eq!(repos.packages.get_package(package.id).await.expect("get"), Some(package.clone()));
    assert_eq!(repos.packages.get_package(pub_core::PackageId::new()).await.expect("miss"), None);
    assert_eq!(repos.packages.get_by_name(Format::Pub, "acme_core").await.expect("by name"), Some(package.clone()));
    assert_eq!(repos.packages.get_by_name(Format::Pub, "nope").await.expect("by name miss"), None);

    // The name is taken instance-wide — even for another org (decision 01: names are flat).
    let err = repos
        .packages
        .create_package(
            NewPackage {
                format: Format::Pub,
                name: "acme_core".to_owned(),
                org_id: other.id,
                visibility: Visibility::Public,
            },
            t0(),
        )
        .await
        .expect_err("name is claimed");
    assert_eq!(err.code(), "conflict");

    // claim_name: idempotent for the holder, conflict for anybody else.
    let again = repos.packages.claim_name(Format::Pub, "acme_core", org.id, t0() + hours(1)).await.expect("re-claim");
    assert_eq!(again.claimed_at, t0(), "re-claiming must not move the claim date");
    let err = repos.packages.claim_name(Format::Pub, "acme_core", other.id, t0()).await.expect_err("foreign re-claim");
    assert_eq!(err.code(), "conflict");
    // A reserved-but-unpublished name has a claim and no package.
    repos.packages.claim_name(Format::Pub, "acme_reserved", org.id, t0()).await.expect("reserve");
    assert!(repos.packages.get_by_name(Format::Pub, "acme_reserved").await.expect("no package").is_none());

    // set_options replaces the whole option set and bumps updated_at.
    let updated = repos
        .packages
        .set_options(
            package.id,
            &PackageOptions {
                visibility: Visibility::Private,
                discontinued: true,
                replaced_by: Some("acme_core2".to_owned()),
                unlisted: true,
            },
            t0() + hours(2),
        )
        .await
        .expect("set options");
    assert_eq!(updated.visibility, Visibility::Private);
    assert!(updated.discontinued && updated.unlisted);
    assert_eq!(updated.replaced_by.as_deref(), Some("acme_core2"));
    assert_eq!(updated.updated_at, t0() + hours(2));
    assert_eq!(updated.created_at, t0());
    // Clearing works through the same replace payload.
    let cleared = repos
        .packages
        .set_options(package.id, &PackageOptions::from(&package), t0() + hours(3))
        .await
        .expect("clear options");
    assert!(!cleared.discontinued && !cleared.unlisted);
    assert_eq!(cleared.replaced_by, None);
    let err = repos
        .packages
        .set_options(pub_core::PackageId::new(), &PackageOptions::from(&package), t0())
        .await
        .expect_err("unknown package");
    assert_eq!(err.code(), "not_found");

    // list_for_org: name order, keyset-paginated, unlisted/discontinued rows included.
    for name in ["acme_ui", "acme_net", "acme_db"] {
        repos
            .packages
            .create_package(
                NewPackage {
                    format: Format::Pub,
                    name: name.to_owned(),
                    org_id: org.id,
                    visibility: Visibility::Private,
                },
                t0(),
            )
            .await
            .expect("create");
    }
    let all = repos.packages.list_for_org(org.id, None, 100).await.expect("list");
    let names: Vec<&str> = all.items.iter().map(|p| p.name.as_str()).collect();
    assert_eq!(names, vec!["acme_core", "acme_db", "acme_net", "acme_ui"]);
    assert!(!all.has_more);
    assert_eq!(all.cursor, None);
    // Another org's packages never appear.
    assert!(repos.packages.list_for_org(other.id, None, 100).await.expect("empty").items.is_empty());

    let mut seen = Vec::new();
    let mut cursor: Option<String> = None;
    let mut pages = 0;
    loop {
        let page = repos.packages.list_for_org(org.id, cursor.as_deref(), 2).await.expect("page");
        assert!(page.items.len() <= 2);
        assert_eq!(page.cursor.is_some(), page.has_more, "cursor is Some iff has_more");
        seen.extend(page.items.iter().map(|p| p.name.clone()));
        pages += 1;
        if !page.has_more {
            break;
        }
        cursor = page.cursor;
    }
    assert_eq!(pages, 2);
    assert_eq!(seen, vec!["acme_core", "acme_db", "acme_net", "acme_ui"], "no skips or duplicates across pages");

    let err = repos.packages.list_for_org(org.id, Some("not-a-cursor"), 10).await.expect_err("bad cursor");
    assert_eq!(err.code(), "invalid_argument");
    let one = repos.packages.list_for_org(org.id, None, 0).await.expect("clamped limit");
    assert_eq!(one.items.len(), 1);
    assert!(one.has_more);

    // `list_all` is the reindex job's work queue: every package on the instance, ordered by
    // (format, name), keyset-paginated over that pair — and deliberately unfiltered, because a
    // filtered enumeration would make some package permanently unindexable.
    repos
        .packages
        .create_package(
            NewPackage {
                format: Format::Pub,
                name: "zz_other".to_owned(),
                org_id: other.id,
                visibility: Visibility::Private,
            },
            t0(),
        )
        .await
        .expect("second package");
    let all = repos.packages.list_all(None, 100).await.expect("list all");
    assert_eq!(
        all.items.iter().map(|p| p.name.clone()).collect::<Vec<_>>(),
        vec![
            "acme_core".to_owned(),
            "acme_db".to_owned(),
            "acme_net".to_owned(),
            "acme_ui".to_owned(),
            "zz_other".to_owned()
        ],
        "ordered by (format, name), across orgs and visibilities"
    );
    let mut walked = Vec::new();
    let mut cursor: Option<String> = None;
    loop {
        let page = repos.packages.list_all(cursor.as_deref(), 2).await.expect("page");
        assert_eq!(page.cursor.is_some(), page.has_more);
        walked.extend(page.items.iter().map(|p| p.name.clone()));
        if !page.has_more {
            break;
        }
        cursor = page.cursor;
    }
    assert_eq!(walked, all.items.iter().map(|p| p.name.clone()).collect::<Vec<_>>(), "no skips or duplicates");
    assert_eq!(repos.packages.list_all(Some("%%%"), 10).await.expect_err("bad cursor").code(), "invalid_argument");
}

/// `PackageRepo` version ordering: semver precedence (pre-releases included), retraction
/// flags, and keyset pagination over the ordered listing.
pub async fn version_ordering(repos: &Repositories) {
    let alice = seed_user(repos, "alice@corp.com", "Alice").await;
    let org = seed_org(repos, "acme", alice.id).await;

    // Deliberately inserted out of order, and covering the spec's pre-release ladder.
    //
    // Three entries are adversarial on purpose: they fail loudly if the ordering column is
    // ever compared under a locale collation rather than bytewise (`COLLATE "C"` on Postgres,
    // BINARY on SQLite). `1.0.0-Beta` — ASCII puts uppercase before lowercase, ICU does not;
    // the `a.b` / `a-b` pair — identifier-by-identifier comparison, which a
    // punctuation-folding collation reverses.
    let ordered = [
        "0.9.9",
        "1.0.0-Beta",
        "1.0.0-a.b",
        "1.0.0-a-b",
        "1.0.0-alpha",
        "1.0.0-alpha.1",
        "1.0.0-alpha.beta",
        "1.0.0-beta",
        "1.0.0-beta.2",
        "1.0.0-beta.11",
        "1.0.0-rc.1",
        "1.0.0",
        "1.0.1",
        "1.2.0",
        "2.0.0",
        "10.0.0",
    ];
    let insertion = [
        "2.0.0",
        "1.0.0-beta.11",
        "10.0.0",
        "1.0.0",
        "1.0.0-alpha.1",
        "0.9.9",
        "1.0.0-rc.1",
        "1.2.0",
        "1.0.0-alpha",
        "1.0.1",
        "1.0.0-beta",
        "1.0.0-alpha.beta",
        "1.0.0-beta.2",
        "1.0.0-a-b",
        "1.0.0-Beta",
        "1.0.0-a.b",
    ];
    let mut package_id = None;
    for (index, version) in insertion.iter().enumerate() {
        let published = repos
            .packages
            .create_version(
                new_version(org.id, "acme_core", version, alice.id),
                t0() + chrono::Duration::minutes(index as i64),
            )
            .await
            .unwrap_or_else(|err| panic!("publish {version}: {err}"));
        assert_eq!(published.package_created, index == 0, "only the first publish creates the package");
        package_id = Some(published.package.id);
    }
    let package_id = package_id.expect("package");

    let listed = repos.packages.list_versions(package_id, None, 100).await.expect("list");
    let versions: Vec<String> = listed.items.iter().map(|v| v.version.to_string()).collect();
    assert_eq!(versions, ordered, "listing must be in semver precedence order, not string order");

    // get_version finds an exact version, including pre-releases.
    let beta = SemVer::parse("1.0.0-beta.11").expect("parse");
    let found = repos.packages.get_version(package_id, &beta).await.expect("get").expect("exists");
    assert_eq!(found.version, beta);
    assert_eq!(found.pubspec["version"], "1.0.0-beta.11");
    assert!(!found.is_retracted());
    assert_eq!(repos.packages.get_version(package_id, &SemVer::parse("9.9.9").unwrap()).await.expect("miss"), None);

    // Retracted versions stay listed and are flagged (docs/protocol.md sharp edge 9).
    let retracted = repos.packages.set_retracted(found.id, true, t0() + days(1)).await.expect("retract");
    assert_eq!(retracted.retracted_at, Some(t0() + days(1)));
    let listed = repos.packages.list_versions(package_id, None, 100).await.expect("list");
    assert_eq!(listed.items.len(), ordered.len(), "retraction must not remove the version from the listing");
    let flagged: Vec<&str> =
        listed.items.iter().filter(|v| v.is_retracted()).map(|v| v.version.to_string().leak() as &str).collect();
    assert_eq!(flagged, vec!["1.0.0-beta.11"]);

    // Keyset pagination walks the same order without gaps or repeats.
    let mut seen = Vec::new();
    let mut cursor: Option<String> = None;
    loop {
        let page = repos.packages.list_versions(package_id, cursor.as_deref(), 3).await.expect("page");
        assert!(page.items.len() <= 3);
        assert_eq!(page.cursor.is_some(), page.has_more, "cursor is Some iff has_more");
        seen.extend(page.items.iter().map(|v| v.version.to_string()));
        if !page.has_more {
            break;
        }
        cursor = page.cursor;
    }
    assert_eq!(seen, ordered, "paginated order must equal the full listing order");

    let err = repos.packages.list_versions(package_id, Some("%%%"), 10).await.expect_err("bad cursor");
    assert_eq!(err.code(), "invalid_argument");

    // The web UI's ordering: the exact reverse, paginated the same way. Reversing a page in the
    // API layer instead would give newest-first *within* a page while paging from the oldest.
    let mut descending = Vec::new();
    let mut cursor: Option<String> = None;
    loop {
        let page = repos.packages.list_versions_desc(package_id, cursor.as_deref(), 5).await.expect("page");
        assert_eq!(page.cursor.is_some(), page.has_more, "cursor is Some iff has_more");
        descending.extend(page.items.iter().map(|v| v.version.to_string()));
        if !page.has_more {
            break;
        }
        cursor = page.cursor;
    }
    let mut expected: Vec<&str> = ordered.to_vec();
    expected.reverse();
    assert_eq!(descending, expected, "descending pagination must be the exact reverse, gaps included");
    assert_eq!(
        repos.packages.list_versions_desc(package_id, Some("%%%"), 10).await.expect_err("bad cursor").code(),
        "invalid_argument"
    );
}

/// `PackageRepo` publish invariants: claim ownership, duplicate rejection, tombstones burning
/// a number forever, retract/unretract flags, and blob reference counting.
pub async fn publish_invariants(repos: &Repositories) {
    let alice = seed_user(repos, "alice@corp.com", "Alice").await;
    let mallory = seed_user(repos, "mallory@evil.com", "Mallory").await;
    let org = seed_org(repos, "acme", alice.id).await;
    let rival = seed_org(repos, "rival", mallory.id).await;

    let published = repos
        .packages
        .create_version(new_version(org.id, "acme_core", "1.0.0", alice.id), t0())
        .await
        .expect("first publish");
    assert!(published.package_created);
    assert_eq!(published.package.org_id, org.id);
    assert_eq!(published.version.archive_size, 1024);
    assert_eq!(published.version.published_at, t0());

    // Claim ownership: another org cannot publish under a claimed name.
    let err = repos
        .packages
        .create_version(new_version(rival.id, "acme_core", "2.0.0", mallory.id), t0() + hours(1))
        .await
        .expect_err("foreign claim");
    assert_eq!(err.code(), "forbidden");
    // …and the failed attempt created nothing.
    assert_eq!(
        repos.packages.get_version(published.package.id, &SemVer::parse("2.0.0").unwrap()).await.expect("get"),
        None
    );

    // Duplicate version — same content or different — is a conflict (S-18 immutability).
    let err = repos
        .packages
        .create_version(new_version(org.id, "acme_core", "1.0.0", alice.id), t0() + hours(2))
        .await
        .expect_err("duplicate version");
    assert_eq!(err.code(), "conflict");
    let mut different = new_version(org.id, "acme_core", "1.0.0", alice.id);
    different.archive_sha256 = "f".repeat(64);
    let err = repos.packages.create_version(different, t0() + hours(2)).await.expect_err("duplicate version");
    assert_eq!(err.code(), "conflict");

    // Retract / unretract flags, idempotently.
    let retracted = repos.packages.set_retracted(published.version.id, true, t0() + days(1)).await.expect("retract");
    assert_eq!(retracted.retracted_at, Some(t0() + days(1)));
    let again = repos.packages.set_retracted(published.version.id, true, t0() + days(2)).await.expect("re-retract");
    assert_eq!(again.retracted_at, Some(t0() + days(1)), "re-retracting keeps the original instant");
    let restored = repos.packages.set_retracted(published.version.id, false, t0() + days(3)).await.expect("restore");
    assert_eq!(restored.retracted_at, None);
    let err = repos.packages.set_retracted(pub_core::VersionId::new(), true, t0()).await.expect_err("unknown version");
    assert_eq!(err.code(), "not_found");

    // `count_versions` is what keeps the package page off a full version walk: it counts live
    // rows only, so a tombstone stops being counted the moment it is burned (asserted below).
    assert_eq!(repos.packages.count_versions(published.package.id).await.expect("count"), 1);
    assert_eq!(repos.packages.count_versions(PackageId::new()).await.expect("count unknown"), 0);

    // Blob reference counting: two versions may share one content hash.
    let shared = published.version.archive_sha256.clone();
    assert_eq!(repos.packages.count_versions_with_sha256(&shared).await.expect("count"), 1);
    let mut twin = new_version(org.id, "acme_twin", "1.0.0", alice.id);
    twin.archive_sha256 = shared.clone();
    repos.packages.create_version(twin, t0() + hours(3)).await.expect("twin publish");
    assert_eq!(repos.packages.count_versions_with_sha256(&shared).await.expect("count"), 2);
    assert_eq!(repos.packages.count_versions_with_sha256(&"0".repeat(64)).await.expect("count"), 0);

    // The batch form the blob collector actually runs on (decision 31): same question, asked
    // once for a whole batch of candidate keys, answered as the referenced subset.
    let absent = "0".repeat(64);
    let batch = vec![shared.clone(), absent.clone()];
    let referenced = repos.packages.live_sha256s(&batch).await.expect("batch");
    assert_eq!(referenced.len(), 1, "only the hash a live version points at");
    assert!(referenced.contains(&shared));
    assert!(!referenced.contains(&absent));
    // An empty input must not reach the database — and must certainly not answer "everything".
    assert!(repos.packages.live_sha256s(&[]).await.expect("empty batch").is_empty());
    // A repeated hash is one row in the answer, not two: the collector dedups before asking and
    // this makes the contract explicit either way.
    let repeated = repos.packages.live_sha256s(&[shared.clone(), shared.clone()]).await.expect("repeat");
    assert_eq!(repeated.len(), 1);

    // Hard delete: the row becomes a tombstone with its payload cleared…
    let tombstone = repos.packages.hard_delete_version(published.version.id).await.expect("hard delete");
    assert!(tombstone.tombstone);
    assert_eq!(tombstone.pubspec, serde_json::json!({}));
    assert_eq!(tombstone.readme_html, None);
    assert_eq!(tombstone.archive_sha256, shared, "the hash survives for GC accounting");
    // …the version leaves the listing…
    let listed = repos.packages.list_versions(published.package.id, None, 50).await.expect("list");
    assert!(listed.items.is_empty());
    // …stops counting as a blob reference…
    assert_eq!(repos.packages.count_versions_with_sha256(&shared).await.expect("count"), 1);
    assert_eq!(repos.packages.count_versions(published.package.id).await.expect("count"), 0, "tombstones are not live");
    // …but remains findable by exact version, so callers can tell "burned" from "never was".
    let found = repos
        .packages
        .get_version(published.package.id, &SemVer::parse("1.0.0").unwrap())
        .await
        .expect("get")
        .expect("tombstone row");
    assert!(found.tombstone);

    // The number can never be republished (decision 06, S-18).
    let err = repos
        .packages
        .create_version(new_version(org.id, "acme_core", "1.0.0", alice.id), t0() + days(5))
        .await
        .expect_err("tombstoned number");
    assert_eq!(err.code(), "conflict");

    // Tombstoned versions cannot be retracted or deleted again.
    let err = repos.packages.set_retracted(published.version.id, true, t0() + days(5)).await.expect_err("tombstoned");
    assert_eq!(err.code(), "conflict");
    let err = repos.packages.hard_delete_version(published.version.id).await.expect_err("already deleted");
    assert_eq!(err.code(), "conflict");
    let err = repos.packages.hard_delete_version(pub_core::VersionId::new()).await.expect_err("unknown");
    assert_eq!(err.code(), "not_found");

    // A new, never-used version number still publishes fine after all of that.
    repos
        .packages
        .create_version(new_version(org.id, "acme_core", "1.0.1", alice.id), t0() + days(6))
        .await
        .expect("publish after tombstone");
}

/// `PackageRepo::resolve` visibility matrix (decision 05 / S-04): public/private ×
/// member/non-member/anonymous, plus claimed-but-unpublished and unclaimed names.
pub async fn resolve_visibility(repos: &Repositories) {
    let alice = seed_user(repos, "alice@corp.com", "Alice").await;
    let bob = seed_user(repos, "bob@corp.com", "Bob").await;
    let org = seed_org(repos, "acme", alice.id).await;
    let outsider_org = seed_org(repos, "outside", bob.id).await;

    let member = ActorContext::user(alice.id, BTreeMap::from([(org.id, RoleLevel::READ)]));
    // A member of *another* org holds no role here.
    let non_member = ActorContext::user(bob.id, BTreeMap::from([(outsider_org.id, RoleLevel::OWNER)]));
    let anonymous = ActorContext::anonymous();

    let public = repos
        .packages
        .create_package(
            NewPackage {
                format: Format::Pub,
                name: "acme_public".to_owned(),
                org_id: org.id,
                visibility: Visibility::Public,
            },
            t0(),
        )
        .await
        .expect("public package");
    let private = repos
        .packages
        .create_package(
            NewPackage {
                format: Format::Pub,
                name: "acme_private".to_owned(),
                org_id: org.id,
                visibility: Visibility::Private,
            },
            t0(),
        )
        .await
        .expect("private package");

    // Public packages are readable by everyone, including anonymous callers (decision 05).
    for actor in [&member, &non_member, &anonymous] {
        assert_eq!(
            repos.packages.resolve(Format::Pub, "acme_public", actor).await.expect("resolve"),
            Resolution::Readable(public.clone())
        );
    }

    // Private packages: only members at Read level or above.
    assert_eq!(
        repos.packages.resolve(Format::Pub, "acme_private", &member).await.expect("resolve"),
        Resolution::Readable(private.clone())
    );
    for actor in [&non_member, &anonymous] {
        assert_eq!(
            repos.packages.resolve(Format::Pub, "acme_private", actor).await.expect("resolve"),
            Resolution::Restricted { owner: org.id },
            "a private package must be invisible outside its org"
        );
    }
    // Below Read the ladder denies (decision 19 boundary).
    let too_low = ActorContext::user(bob.id, BTreeMap::from([(org.id, RoleLevel::new(49))]));
    assert_eq!(
        repos.packages.resolve(Format::Pub, "acme_private", &too_low).await.expect("resolve"),
        Resolution::Restricted { owner: org.id }
    );
    // Write and above obviously read.
    let writer = ActorContext::user(bob.id, BTreeMap::from([(org.id, RoleLevel::WRITE)]));
    assert!(matches!(
        repos.packages.resolve(Format::Pub, "acme_private", &writer).await.expect("resolve"),
        Resolution::Readable(_)
    ));

    // A claimed-but-unpublished name is local and must never fall through to upstream (S-16).
    repos.packages.claim_name(Format::Pub, "acme_reserved", org.id, t0()).await.expect("reserve");
    assert_eq!(
        repos.packages.resolve(Format::Pub, "acme_reserved", &member).await.expect("resolve"),
        Resolution::Restricted { owner: org.id }
    );

    // An unclaimed name is the only proxy candidate.
    assert_eq!(repos.packages.resolve(Format::Pub, "http", &member).await.expect("resolve"), Resolution::Unclaimed);
    assert_eq!(repos.packages.resolve(Format::Pub, "http", &anonymous).await.expect("resolve"), Resolution::Unclaimed);

    // Visibility follows the package: flipping it to public opens the door immediately.
    repos
        .packages
        .set_options(
            private.id,
            &PackageOptions { visibility: Visibility::Public, ..PackageOptions::from(&private) },
            t0() + hours(1),
        )
        .await
        .expect("publish it");
    assert!(matches!(
        repos.packages.resolve(Format::Pub, "acme_private", &anonymous).await.expect("resolve"),
        Resolution::Readable(_)
    ));
    // Unlisted is a discovery flag, not an access-control one: it stays resolvable by name.
    repos
        .packages
        .set_options(
            private.id,
            &PackageOptions { visibility: Visibility::Public, unlisted: true, ..PackageOptions::from(&private) },
            t0() + hours(2),
        )
        .await
        .expect("unlist");
    assert!(matches!(
        repos.packages.resolve(Format::Pub, "acme_private", &anonymous).await.expect("resolve"),
        Resolution::Readable(_)
    ));
}

/// `PackageRepo::resolve_in_base` — decision 01's resolution order as seen from each virtual
/// registry base, on both backends.
///
/// The two rows that make this more than a rerun of [`resolve_visibility`]:
///
/// - inside `/o/{org}/pub`, **another org's private package is invisible even to its own
///   members** — the URL is the namespace, not the principal, so the same `PUB_HOSTED_URL`
///   resolves to the same package set for everyone who can use it at all;
/// - at the public root nothing private resolves, not even the caller's own package.
pub async fn resolve_in_base_scope(repos: &Repositories) {
    let alice = seed_user(repos, "alice@corp.com", "Alice").await;
    let bob = seed_user(repos, "bob@corp.com", "Bob").await;
    let acme = seed_org(repos, "acme", alice.id).await;
    let other = seed_org(repos, "other", bob.id).await;

    let mut packages = Vec::new();
    for (name, org, visibility) in [
        ("acme_private", acme.id, Visibility::Private),
        ("acme_public", acme.id, Visibility::Public),
        ("other_private", other.id, Visibility::Private),
        ("other_public", other.id, Visibility::Public),
    ] {
        packages.push(
            repos
                .packages
                .create_package(
                    NewPackage { format: Format::Pub, name: name.to_owned(), org_id: org, visibility },
                    t0(),
                )
                .await
                .expect("seed package"),
        );
    }

    // A principal who is a member of *both* orgs — the interesting case, because a
    // principal-scoped policy would leak `other_private` into acme's base for them.
    let both =
        ActorContext::user(alice.id, BTreeMap::from([(acme.id, RoleLevel::OWNER), (other.id, RoleLevel::OWNER)]));
    let anonymous = ActorContext::anonymous();

    let readable = |resolution: &Resolution| matches!(resolution, Resolution::Readable(_));

    // --- inside /o/acme/pub ---
    let scope = BaseScope::Org(acme.id);
    for (name, expected) in
        [("acme_private", true), ("acme_public", true), ("other_public", true), ("other_private", false)]
    {
        let resolution = repos.packages.resolve_in_base(Format::Pub, name, scope, &both).await.expect("resolve");
        assert_eq!(readable(&resolution), expected, "{name} in /o/acme/pub for a member of both orgs");
    }
    // Anonymous sees only what is public.
    for (name, expected) in
        [("acme_private", false), ("acme_public", true), ("other_public", true), ("other_private", false)]
    {
        let resolution = repos.packages.resolve_in_base(Format::Pub, name, scope, &anonymous).await.expect("resolve");
        assert_eq!(readable(&resolution), expected, "{name} in /o/acme/pub for an anonymous caller");
    }

    // --- at the public root ---
    for actor in [&both, &anonymous] {
        for (name, expected) in
            [("acme_private", false), ("acme_public", true), ("other_public", true), ("other_private", false)]
        {
            let resolution =
                repos.packages.resolve_in_base(Format::Pub, name, BaseScope::PublicRoot, actor).await.expect("resolve");
            assert_eq!(readable(&resolution), expected, "{name} at /pub");
        }
    }

    // Local always wins (S-16): a claimed-but-unpublished name is `Restricted`, never a proxy
    // candidate; only a name claimed nowhere is `Unclaimed`.
    repos.packages.claim_name(Format::Pub, "acme_reserved", acme.id, t0()).await.expect("reserve");
    assert_eq!(
        repos.packages.resolve_in_base(Format::Pub, "acme_reserved", BaseScope::PublicRoot, &both).await.expect("r"),
        Resolution::Restricted { owner: acme.id }
    );
    assert_eq!(
        repos.packages.resolve_in_base(Format::Pub, "http", BaseScope::Org(acme.id), &both).await.expect("r"),
        Resolution::Unclaimed
    );
}

/// Builds one upstream version payload with deterministic content.
fn upstream_version(version: &str, sha256: &str, retracted: bool) -> NewUpstreamVersion {
    NewUpstreamVersion {
        version: SemVer::parse(version).expect("semver"),
        pubspec: serde_json::json!({ "name": "http", "version": version, "description": "upstream fixture" }),
        archive_sha256: sha256.to_owned(),
        archive_size: Some(1024),
        retracted,
        published_at: Some(t0()),
    }
}

/// Builds an upstream listing snapshot for `http`.
fn upstream_snapshot(versions: Vec<NewUpstreamVersion>, discontinued: bool) -> UpstreamSnapshot {
    UpstreamSnapshot {
        format: Format::Pub,
        name: "http".to_owned(),
        upstream: "https://pub.dev".to_owned(),
        discontinued,
        replaced_by: discontinued.then(|| "http2".to_owned()),
        advisories_updated: Some("2026-08-01T00:00:00Z".to_owned()),
        listing: Some(serde_json::json!({ "name": "http", "versions": [] })),
        versions,
    }
}

/// `UpstreamRepo` (decision 07, S-19): snapshot upsert semantics, precedence ordering, the
/// cached-hash freeze that makes byte-drift detectable, and `mark_cached`'s hash predicate.
pub async fn upstream_repo(repos: &Repositories) {
    repos.upstream.ping().await.expect("ping");
    assert!(repos.upstream.get_package(Format::Pub, "http").await.expect("miss").is_none());

    // A first snapshot creates the package row and every version, flags verbatim.
    let sha_a = "a".repeat(64);
    let sha_b = "b".repeat(64);
    let sha_c = "c".repeat(64);
    let stored = repos
        .upstream
        .save_snapshot(
            upstream_snapshot(
                vec![
                    upstream_version("1.0.0", &sha_a, false),
                    upstream_version("1.0.0-beta.11", &sha_b, true),
                    upstream_version("1.0.0-beta.2", &sha_c, false),
                ],
                false,
            ),
            t0(),
        )
        .await
        .expect("first snapshot");
    assert_eq!(stored.name, "http");
    assert_eq!(stored.upstream, "https://pub.dev");
    assert!(!stored.discontinued);
    assert_eq!(stored.advisories_updated.as_deref(), Some("2026-08-01T00:00:00Z"));
    assert_eq!(stored.fetched_at, t0());
    assert!(stored.listing.is_some(), "the raw document is what archive urls are re-derived from");

    // Ordering is semver precedence, not text: `1.0.0-beta.2` before `1.0.0-beta.11`.
    let versions = repos.upstream.list_versions(stored.id).await.expect("list");
    let order: Vec<String> = versions.iter().map(|v| v.version.to_string()).collect();
    assert_eq!(order, ["1.0.0-beta.2", "1.0.0-beta.11", "1.0.0"]);
    let beta11 = versions.iter().find(|v| v.version.to_string() == "1.0.0-beta.11").expect("beta.11");
    assert!(beta11.retracted, "upstream's retraction flag is preserved verbatim");
    assert!(!beta11.cached, "a snapshot records metadata, never bytes");
    assert_eq!(beta11.archive_size, Some(1024));
    assert_eq!(beta11.pubspec["description"], "upstream fixture");
    assert_eq!(beta11.published_at, Some(t0()));

    // get_version: hit and miss.
    let one = SemVer::parse("1.0.0").unwrap();
    let cached_row = repos.upstream.get_version(stored.id, &one).await.expect("get").expect("1.0.0");
    assert_eq!(cached_row.archive_sha256, sha_a);
    assert!(repos.upstream.get_version(stored.id, &SemVer::parse("9.9.9").unwrap()).await.expect("get").is_none());

    // mark_cached is guarded by the hash: a row whose hash moved must not be marked cached for
    // content it no longer advertises.
    assert!(
        !repos.upstream.mark_cached(cached_row.id, &sha_b, 4096, t0()).await.expect("wrong hash"),
        "hash must match"
    );
    assert!(repos.upstream.mark_cached(cached_row.id, &sha_a, 4096, t0() + hours(1)).await.expect("mark"));
    assert!(!repos.upstream.mark_cached(pub_core::VersionId::new(), &sha_a, 4096, t0()).await.expect("unknown id"));

    // A second snapshot upserts: package flags change, new versions appear, **missing ones
    // survive** (we may already hold their bytes), and a cached version's hash is frozen —
    // which is what makes S-19 byte-drift detectable instead of silently applied.
    let drifted = "d".repeat(64);
    let refreshed = repos
        .upstream
        .save_snapshot(
            upstream_snapshot(
                vec![
                    // 1.0.0 is cached; upstream now claims different bytes for it.
                    upstream_version("1.0.0", &drifted, true),
                    // 1.0.0-beta.2 is not cached; its hash is upstream's to correct.
                    upstream_version("1.0.0-beta.2", &drifted, false),
                    upstream_version("2.0.0", &drifted, false),
                ],
                true,
            ),
            t0() + hours(2),
        )
        .await
        .expect("second snapshot");
    assert!(refreshed.discontinued, "package-level flags follow upstream");
    assert_eq!(refreshed.replaced_by.as_deref(), Some("http2"));
    assert_eq!(refreshed.id, stored.id, "the snapshot upserts rather than creating a second row");
    assert_eq!(refreshed.fetched_at, t0() + hours(2));

    let versions = repos.upstream.list_versions(stored.id).await.expect("list again");
    let order: Vec<String> = versions.iter().map(|v| v.version.to_string()).collect();
    assert_eq!(order, ["1.0.0-beta.2", "1.0.0-beta.11", "1.0.0", "2.0.0"], "a dropped version keeps its row");

    let one_row = repos.upstream.get_version(stored.id, &one).await.expect("get").expect("1.0.0");
    assert_eq!(one_row.archive_sha256, sha_a, "S-19: a cached version's hash never moves");
    assert!(one_row.cached, "and it stays cached");
    assert_eq!(one_row.archive_size, Some(4096), "nor does the size we measured while caching");
    assert!(one_row.retracted, "everything else about it does follow upstream");

    let beta2 = versions.iter().find(|v| v.version.to_string() == "1.0.0-beta.2").expect("beta.2");
    assert_eq!(beta2.archive_sha256, drifted, "an uncached version's hash is upstream's to correct");

    // Formats do not collide: the same name under another format is a different row.
    assert!(repos.upstream.get_package(Format::Pub, "other_pkg").await.expect("miss").is_none());
}

/// `UpstreamRepo` mirror-facing reads (decision 07 second half): the oldest-snapshot queue the
/// mirror worker walks, the admin cache inventory with its sizes, and the second half of the
/// GC reference check.
pub async fn upstream_mirror_reads(repos: &Repositories) {
    let sha_a = "a".repeat(64);
    let sha_b = "b".repeat(64);

    // Two packages fetched at different times.
    let http = repos
        .upstream
        .save_snapshot(
            upstream_snapshot(
                vec![upstream_version("1.0.0", &sha_a, false), upstream_version("2.0.0", &sha_b, false)],
                false,
            ),
            t0(),
        )
        .await
        .expect("http snapshot");
    let mut other = upstream_snapshot(vec![upstream_version("1.0.0", &sha_a, false)], false);
    other.name = "path".to_owned();
    other.versions[0].pubspec = serde_json::json!({ "name": "path", "version": "1.0.0" });
    repos.upstream.save_snapshot(other, t0() + hours(2)).await.expect("path snapshot");

    // The mirror's steady-state queue is oldest-snapshot-first and bounded by the cutoff.
    let stale = repos.upstream.list_stale(Format::Pub, t0() + hours(1), 10).await.expect("stale");
    assert_eq!(
        stale.iter().map(|p| p.name.as_str()).collect::<Vec<_>>(),
        ["http"],
        "only snapshots older than the cutoff"
    );
    let all = repos.upstream.list_stale(Format::Pub, t0() + hours(3), 10).await.expect("stale");
    assert_eq!(all.iter().map(|p| p.name.as_str()).collect::<Vec<_>>(), ["http", "path"], "oldest first");
    assert_eq!(
        repos.upstream.list_stale(Format::Pub, t0() + hours(3), 1).await.expect("stale").len(),
        1,
        "limit holds"
    );
    assert!(repos.upstream.list_stale(Format::Pub, t0(), 10).await.expect("stale").is_empty());

    // GC's second register: only *cached* versions count as blob references.
    assert_eq!(repos.upstream.count_cached_with_sha256(&sha_a).await.expect("count"), 0, "a snapshot holds no bytes");
    let cached_row =
        repos.upstream.get_version(http.id, &SemVer::parse("1.0.0").unwrap()).await.expect("get").expect("row");
    assert!(repos.upstream.mark_cached(cached_row.id, &sha_a, 2048, t0() + hours(3)).await.expect("mark"));
    assert_eq!(repos.upstream.count_cached_with_sha256(&sha_a).await.expect("count"), 1);
    assert_eq!(repos.upstream.count_cached_with_sha256(&sha_b).await.expect("count"), 0);

    // The batch form (decision 31). `sha_b` is known to the snapshot but holds no bytes, so a
    // collector that read this answer as "both are referenced" would keep garbage forever, and
    // one that read it as "neither" would delete `sha_a`'s archive out from under a lockfile.
    let batch = vec![sha_a.clone(), sha_b.clone()];
    let cached_set = repos.upstream.cached_sha256s(&batch).await.expect("batch");
    assert_eq!(cached_set.len(), 1);
    assert!(cached_set.contains(&sha_a));
    assert!(!cached_set.contains(&sha_b), "a snapshot row is not a blob reference");
    assert!(repos.upstream.cached_sha256s(&[]).await.expect("empty batch").is_empty());

    // The admin inventory aggregates per package: version counts and the bytes we actually hold.
    let page = repos.upstream.list_cached(Format::Pub, None, 50).await.expect("inventory");
    assert!(!page.has_more);
    let names: Vec<&str> = page.items.iter().map(|entry| entry.name.as_str()).collect();
    assert_eq!(names, ["http", "path"], "ordered by name");
    let http_entry = &page.items[0];
    assert_eq!(http_entry.versions, 2);
    assert_eq!(http_entry.cached_versions, 1, "only one version has bytes");
    assert_eq!(http_entry.cached_bytes, 2048, "and only measured sizes are summed");
    assert_eq!(page.items[1].cached_bytes, 0);
    assert_eq!(http_entry.upstream, "https://pub.dev");

    // Keyset pagination over the name.
    let first = repos.upstream.list_cached(Format::Pub, None, 1).await.expect("page 1");
    assert!(first.has_more);
    let second = repos.upstream.list_cached(Format::Pub, first.cursor.as_deref(), 1).await.expect("page 2");
    assert_eq!(second.items[0].name, "path");
    assert!(!second.has_more);
    assert_eq!(
        repos.upstream.list_cached(Format::Pub, Some("not-a-cursor"), 10).await.unwrap_err().code(),
        "invalid_argument"
    );
}

/// The two supply-chain registers (S-17 shadowing, S-19 quarantine): one row per incident,
/// counters instead of duplicates, and "raised" reported exactly once per incident.
pub async fn supply_chain_registers(repos: &Repositories) {
    let alice = seed_user(repos, "alice@corp.com", "Alice").await;
    let org = seed_org(repos, "acme", alice.id).await;
    repos.packages.claim_name(Format::Pub, "acme_core", org.id, t0()).await.expect("claim");

    // --- S-19 quarantine: repeated refusals of one version collapse onto one row ---
    let entry = |actual: &str| pub_core::package::NewQuarantineEntry {
        format: Format::Pub,
        name: "http".to_owned(),
        version: "1.0.0".to_owned(),
        upstream: "https://pub.dev".to_owned(),
        expected_sha256: "a".repeat(64),
        actual_sha256: actual.to_owned(),
    };
    let first = repos.upstream.record_quarantine(entry(&"b".repeat(64)), t0()).await.expect("quarantine");
    assert_eq!(first.occurrences, 1);
    assert_eq!(first.first_seen_at, t0());
    let again = repos.upstream.record_quarantine(entry(&"c".repeat(64)), t0() + hours(1)).await.expect("again");
    assert_eq!(again.occurrences, 2, "a package under active tampering is fetched by the whole team");
    assert_eq!(again.first_seen_at, t0(), "the first sighting is the incident's start");
    assert_eq!(again.last_seen_at, t0() + hours(1));
    assert_eq!(again.actual_sha256, "c".repeat(64), "the newest evidence wins");

    let listed = repos.upstream.list_quarantine(None, 10).await.expect("list");
    assert_eq!(listed.items.len(), 1);
    assert_eq!(listed.items[0].name, "http");
    assert_eq!(listed.items[0].expected_sha256, "a".repeat(64));
    assert!(!listed.has_more);
    assert!(listed.cursor.is_none(), "a complete page carries no cursor");

    // --- S-17 shadowing: raised once per incident, counted thereafter ---
    let alarm = |version: Option<&str>| pub_core::package::NewShadowingAlarm {
        format: Format::Pub,
        name: "acme_core".to_owned(),
        org_id: org.id,
        upstream: "https://pub.dev".to_owned(),
        upstream_version: version.map(ToOwned::to_owned),
    };
    let (raised, is_new) = repos.upstream.record_shadowing(alarm(Some("9.9.9")), t0()).await.expect("raise");
    assert!(is_new, "the first sighting raises the alarm");
    assert_eq!(raised.org_id, org.id, "the claim holder is the audience");
    assert_eq!(raised.upstream_version.as_deref(), Some("9.9.9"));
    assert_eq!(raised.observations, 1);
    assert!(raised.is_active());

    let (again, is_new) = repos.upstream.record_shadowing(alarm(Some("9.9.10")), t0() + hours(1)).await.expect("again");
    assert!(!is_new, "a sweep re-observing an ongoing condition must not re-page anybody");
    assert_eq!(again.observations, 2);
    assert_eq!(again.first_seen_at, t0(), "the incident keeps its start");
    assert_eq!(again.last_seen_at, t0() + hours(1));
    assert_eq!(again.upstream_version.as_deref(), Some("9.9.10"), "the newest sighting wins");

    assert_eq!(repos.upstream.list_shadowing(Some(true), None, 10).await.expect("active").items.len(), 1);

    // Acknowledging is bookkeeping — and idempotent.
    assert!(repos.upstream.acknowledge_shadowing(Format::Pub, "acme_core", t0() + hours(2)).await.expect("ack"));
    assert!(!repos.upstream.acknowledge_shadowing(Format::Pub, "acme_core", t0() + hours(3)).await.expect("ack again"));
    assert!(!repos.upstream.acknowledge_shadowing(Format::Pub, "nope_pkg", t0()).await.expect("unknown"));
    assert!(repos.upstream.list_shadowing(Some(true), None, 10).await.expect("active").items.is_empty());
    // The three slices of one register: open, acknowledged, everything.
    let acknowledged = repos.upstream.list_shadowing(Some(false), None, 10).await.expect("acknowledged");
    assert_eq!(acknowledged.items.len(), 1);
    assert!(!acknowledged.items[0].is_active());
    let all = repos.upstream.list_shadowing(None, None, 10).await.expect("all");
    assert_eq!(all.items.len(), 1);
    assert!(!all.items[0].is_active());

    // A sighting after an acknowledgement is a *new* incident: it raises again and restarts the
    // clock, so an admin who cleared the alarm hears about it coming back.
    let (reraised, is_new) = repos.upstream.record_shadowing(alarm(None), t0() + days(1)).await.expect("re-raise");
    assert!(is_new);
    assert!(reraised.is_active());
    assert_eq!(reraised.observations, 1);
    assert_eq!(reraised.first_seen_at, t0() + days(1));
}

/// The registers' operator surface: a keyset walk that is total across ties, and two retention
/// windows that cannot delete evidence somebody still needs
/// ([decision 33](../../../docs/decisions.md#33), S-17.b, S-19.b, S-23.b).
pub async fn supply_chain_register_pages(repos: &Repositories) {
    let alice = seed_user(repos, "alice@corp.com", "Alice").await;
    let org = seed_org(repos, "acme", alice.id).await;

    // **Every row shares one `last_seen_at`.** This is the shape the register actually produces —
    // one fetch loop refusing a package's versions, one sweep raising a block of alarms — and the
    // shape a cursor over the timestamp alone gets wrong.
    for index in 0..5 {
        repos
            .upstream
            .record_quarantine(
                pub_core::package::NewQuarantineEntry {
                    format: Format::Pub,
                    name: "http".to_owned(),
                    version: format!("1.0.{index}"),
                    upstream: "https://pub.dev".to_owned(),
                    expected_sha256: "a".repeat(64),
                    actual_sha256: "b".repeat(64),
                },
                t0(),
            )
            .await
            .expect("quarantine");
    }

    // Walk it two at a time and assert the walk is total: five distinct rows, no repeats, no gaps.
    let mut seen: Vec<String> = Vec::new();
    let mut cursor: Option<String> = None;
    for _ in 0..10 {
        let page = repos.upstream.list_quarantine(cursor.as_deref(), 2).await.expect("page");
        assert!(page.items.len() <= 2, "the page must respect its limit");
        seen.extend(page.items.iter().map(|entry| entry.version.clone()));
        match page.cursor {
            Some(next) => {
                assert!(page.has_more, "a cursor without has_more is a page that lies about the walk");
                cursor = Some(next);
            }
            None => {
                assert!(!page.has_more);
                break;
            }
        }
    }
    seen.sort();
    seen.dedup();
    assert_eq!(seen.len(), 5, "the walk skipped or repeated rows across an identical timestamp: {seen:?}");

    // A malformed cursor is a clean 400, never a database error — including one whose envelope
    // decodes but whose timestamp does not, which is the component a caller can most easily
    // corrupt by hand.
    assert_eq!(
        repos.upstream.list_quarantine(Some("!!not-base64!!"), 10).await.unwrap_err().code(),
        "invalid_argument"
    );
    let bad_time = pub_core::page::encode_cursor(&["not-a-timestamp", "pub", "http", "1.0.0"]);
    assert_eq!(repos.upstream.list_quarantine(Some(&bad_time), 10).await.unwrap_err().code(), "invalid_argument");

    // --- S-23.b: what each window can and cannot reach ---
    let deleted = repos.upstream.purge_quarantine_before(t0() - days(1), 100).await.expect("purge none");
    assert_eq!(deleted, 0, "a refusal still being observed is outside every window");
    let deleted = repos.upstream.purge_quarantine_before(t0() + days(1), 2).await.expect("purge batch");
    assert_eq!(deleted, 2, "the delete is bounded by its batch, so one statement cannot hold the write lock");
    let deleted = repos.upstream.purge_quarantine_before(t0() + days(1), 100).await.expect("purge rest");
    assert_eq!(deleted, 3, "the caller's loop converges");
    assert!(repos.upstream.list_quarantine(None, 10).await.expect("empty").items.is_empty());

    // An **active** alarm is undeletable at every window. This is the property that makes the
    // number harmless: retention that could reach an open alarm would have the mirror sweep
    // re-raise it with a fresh `first_seen_at`, silently rewriting the incident's start date.
    repos.packages.claim_name(Format::Pub, "acme_core", org.id, t0()).await.expect("claim");
    let alarm = pub_core::package::NewShadowingAlarm {
        format: Format::Pub,
        name: "acme_core".to_owned(),
        org_id: org.id,
        upstream: "https://pub.dev".to_owned(),
        upstream_version: None,
    };
    repos.upstream.record_shadowing(alarm, t0()).await.expect("raise");
    let deleted = repos.upstream.purge_shadowing_before(t0() + days(10_000), 100).await.expect("purge active");
    assert_eq!(deleted, 0, "an active alarm survives even an absurd window");
    assert_eq!(repos.upstream.list_shadowing(Some(true), None, 10).await.expect("active").items.len(), 1);

    // Once acknowledged it ages from the acknowledgement, never from the sighting: a window
    // shorter than the alarm's age still keeps it until it has been *cleared* that long.
    repos.upstream.acknowledge_shadowing(Format::Pub, "acme_core", t0() + days(5)).await.expect("ack");
    let deleted = repos.upstream.purge_shadowing_before(t0() + days(4), 100).await.expect("purge before ack");
    assert_eq!(deleted, 0, "the age is the acknowledgement, not the sighting");
    let deleted = repos.upstream.purge_shadowing_before(t0() + days(6), 100).await.expect("purge after ack");
    assert_eq!(deleted, 1);
    assert!(repos.upstream.list_shadowing(None, None, 10).await.expect("all").items.is_empty());
}

/// `JobRepo` (decision 03): resume-across-restart semantics, additive counters, and the
/// success/failure bracket the admin surface reads.
pub async fn job_repo(repos: &Repositories) {
    use pub_core::jobs::{JobOutcome, JobProgress};

    repos.jobs.ping().await.expect("ping");
    assert!(repos.jobs.get("mirror-sync").await.expect("unknown job").is_none());
    assert!(repos.jobs.list().await.expect("list").is_empty());

    // First run creates the row; there is nothing to resume from yet.
    let started = repos.jobs.begin_run("mirror-sync", t0()).await.expect("begin");
    assert_eq!(started.runs, 1);
    assert_eq!(started.cursor, None);
    assert_eq!(started.last_run_at, Some(t0()));
    assert_eq!(started.last_success_at, None);

    // Checkpoints set the cursor absolutely and *add* their counters, so two checkpoints in one
    // run cannot lose each other's work.
    let progress = JobProgress {
        cursor: Some("{\"page\":null,\"offset\":200}".to_owned()),
        phase: "sweep".to_owned(),
        processed: 200,
        failed: 3,
    };
    let mid = repos.jobs.checkpoint("mirror-sync", &progress, t0() + hours(1)).await.expect("checkpoint");
    assert_eq!(mid.processed, 200);
    assert_eq!(mid.failures, 3);
    assert_eq!(mid.phase, "sweep");
    let progress =
        JobProgress { cursor: Some("{\"page\":null,\"offset\":400}".to_owned()), processed: 200, ..progress };
    let mid = repos.jobs.checkpoint("mirror-sync", &progress, t0() + hours(2)).await.expect("checkpoint");
    assert_eq!(mid.processed, 400, "counters accumulate");
    assert_eq!(mid.failures, 6);
    assert_eq!(mid.cursor.as_deref(), Some("{\"page\":null,\"offset\":400}"));

    // A failure keeps the cursor: the next run continues instead of starting over.
    let failed = repos
        .jobs
        .finish_run("mirror-sync", JobOutcome::Failure("upstream down".to_owned()), t0() + hours(3))
        .await
        .expect("finish");
    assert_eq!(failed.last_error.as_deref(), Some("upstream down"));
    assert_eq!(failed.last_success_at, None);
    assert_eq!(failed.cursor.as_deref(), Some("{\"page\":null,\"offset\":400}"));
    assert_eq!(failed.lag_seconds(t0() + hours(3)), None, "a job that never succeeded has no lag, it has an alarm");

    // The next run — the restart case — resumes from exactly that cursor.
    let resumed = repos.jobs.begin_run("mirror-sync", t0() + hours(4)).await.expect("resume");
    assert_eq!(resumed.runs, 2);
    assert_eq!(resumed.cursor.as_deref(), Some("{\"page\":null,\"offset\":400}"));
    assert_eq!(resumed.processed, 400, "counters survive the run boundary");
    assert_eq!(resumed.last_error.as_deref(), Some("upstream down"), "still the last known outcome");

    // A success clears the error and stamps the freshness the admin surface reads.
    let done = repos.jobs.finish_run("mirror-sync", JobOutcome::Success, t0() + hours(5)).await.expect("finish");
    assert_eq!(done.last_error, None);
    assert_eq!(done.last_success_at, Some(t0() + hours(5)));
    assert_eq!(done.lag_seconds(t0() + hours(6)), Some(3600));

    // Clearing the cursor is how a completed sweep hands over to the steady-state phase.
    let cleared = repos
        .jobs
        .checkpoint(
            "mirror-sync",
            &JobProgress { cursor: None, phase: "recent".to_owned(), ..JobProgress::default() },
            t0() + hours(6),
        )
        .await
        .expect("clear");
    assert_eq!(cleared.cursor, None);
    assert_eq!(cleared.phase, "recent");

    // Jobs are independent, listed by name, and finishing an unknown one is NotFound.
    repos.jobs.begin_run("blob-gc", t0() + hours(7)).await.expect("second job");
    let listed: Vec<String> = repos.jobs.list().await.expect("list").into_iter().map(|job| job.name).collect();
    assert_eq!(listed, ["blob-gc", "mirror-sync"]);
    assert_eq!(repos.jobs.finish_run("never-ran", JobOutcome::Success, t0()).await.unwrap_err().code(), "not_found");
}

// ---------------------------------------------------------------- search & statistics (11)

/// Builds a search document for `package` with deterministic, distinguishable content.
fn document(package: &pub_core::package::Package, org_slug: &str, latest: &str) -> SearchDocument {
    SearchDocument {
        package_id: package.id,
        format: package.format,
        name: package.name.clone(),
        org_id: package.org_id,
        org_slug: org_slug.to_owned(),
        visibility: package.visibility,
        discontinued: package.discontinued,
        replaced_by: package.replaced_by.clone(),
        unlisted: package.unlisted,
        description: String::new(),
        readme_text: String::new(),
        topics: Vec::new(),
        dependencies: Vec::new(),
        dev_dependencies: Vec::new(),
        latest_version: latest.to_owned(),
        latest_version_sort: SemVer::parse(latest).expect("version").sort_key(),
        latest_retracted: false,
        versions_count: 1,
        published_at: t0(),
        created_at: t0(),
        updated_at: t0(),
    }
}

/// Creates a package and indexes it, returning the document that was written.
async fn seed_indexed(
    repos: &Repositories,
    org: &pub_core::org::Org,
    name: &str,
    visibility: Visibility,
    build: impl FnOnce(&mut SearchDocument),
) -> SearchDocument {
    let package = repos
        .packages
        .create_package(NewPackage { format: Format::Pub, name: name.to_owned(), org_id: org.id, visibility }, t0())
        .await
        .unwrap_or_else(|err| panic!("seed package {name}: {err}"));
    let mut doc = document(&package, &org.slug, "1.0.0");
    build(&mut doc);
    repos.search.index(&doc).await.unwrap_or_else(|err| panic!("index {name}: {err}"));
    doc
}

/// The names on a search page, in order.
fn names(page: &pub_core::Page<SearchHit>) -> Vec<String> {
    page.items.iter().map(|hit| hit.name.clone()).collect()
}

/// Runs a query string for a view and returns the matching names in result order.
async fn run(repos: &Repositories, raw: &str, view: &SearchView) -> Vec<String> {
    let query = parse_query(raw, SearchSort::Relevance);
    let page = repos.search.search(&query, view, None, 50).await.unwrap_or_else(|err| panic!("search {raw:?}: {err}"));
    names(&page)
}

/// `PackageSearch`: indexing, text relevance, the filter vocabulary, ordering, and cursors.
pub async fn package_search(repos: &Repositories) {
    repos.search.ping().await.expect("ping");

    let alice = seed_user(repos, "alice@corp.com", "Alice").await;
    let acme = seed_org(repos, "acme", alice.id).await;
    let other = seed_org(repos, "other", alice.id).await;
    let anonymous = SearchView::anonymous();

    seed_indexed(repos, &acme, "bloc", Visibility::Public, |doc| {
        doc.description = "Predictable state management library".to_owned();
        doc.topics = vec!["state-management".to_owned()];
        doc.dependencies = vec!["meta".to_owned()];
        doc.updated_at = t0() + hours(3);
        doc.published_at = t0() + hours(3);
    })
    .await;
    seed_indexed(repos, &acme, "flutter_bloc", Visibility::Public, |doc| {
        doc.description = "Flutter widgets for the bloc state management library".to_owned();
        doc.topics = vec!["state-management".to_owned(), "widgets".to_owned()];
        doc.dependencies = vec!["bloc".to_owned(), "meta".to_owned()];
        doc.updated_at = t0() + hours(2);
        doc.published_at = t0() + hours(2);
    })
    .await;
    seed_indexed(repos, &other, "other_http", Visibility::Public, |doc| {
        doc.description = "A composable HTTP client".to_owned();
        doc.readme_text = "Send requests over the network with a tiny bloc of code".to_owned();
        doc.dev_dependencies = vec!["bloc".to_owned()];
        doc.discontinued = true;
        doc.replaced_by = Some("other_http2".to_owned());
        doc.updated_at = t0() + hours(1);
        doc.published_at = t0() + hours(1);
    })
    .await;

    // --- free text: the exact name wins, and every field is searchable ---
    let hits = run(repos, "bloc", &anonymous).await;
    assert_eq!(hits.first().map(String::as_str), Some("bloc"), "an exact name match must rank first: {hits:?}");
    assert!(hits.contains(&"flutter_bloc".to_owned()), "a description match must be found: {hits:?}");
    assert!(hits.contains(&"other_http".to_owned()), "a README match must be found: {hits:?}");
    assert!(run(repos, "composable", &anonymous).await.contains(&"other_http".to_owned()));
    // Prefix matching: the search box is used while typing.
    assert!(run(repos, "compos", &anonymous).await.contains(&"other_http".to_owned()));
    // A phrase is an adjacency constraint, not two words.
    assert!(run(repos, "\"state management\"", &anonymous).await.contains(&"bloc".to_owned()));
    assert!(run(repos, "\"management state\"", &anonymous).await.is_empty(), "a phrase must respect word order");
    // Nothing matches nothing — and does not error.
    assert!(run(repos, "zzzznotapackage", &anonymous).await.is_empty());

    // --- text that cannot become a term is an empty result, never an error or a full listing ---
    for junk in ["%%%", "***", "'; DROP TABLE packages; --", "\") OR 1=1 --"] {
        assert!(run(repos, junk, &anonymous).await.is_empty(), "{junk:?} must match nothing");
    }
    // Engine operators inside a term are data.
    assert!(run(repos, "bloc OR other_http", &anonymous).await.len() <= 1, "OR must not be an operator");

    // --- filters ---
    let mut listed = run(repos, "org:acme", &anonymous).await;
    listed.sort();
    assert_eq!(listed, vec!["bloc".to_owned(), "flutter_bloc".to_owned()]);
    assert_eq!(run(repos, "org:nosuchorg", &anonymous).await, Vec::<String>::new());
    assert_eq!(run(repos, "topic:widgets", &anonymous).await, vec!["flutter_bloc".to_owned()]);
    assert_eq!(run(repos, "is:discontinued", &anonymous).await, vec!["other_http".to_owned()]);
    let mut live = run(repos, "-is:discontinued", &anonymous).await;
    live.sort();
    assert_eq!(live, vec!["bloc".to_owned(), "flutter_bloc".to_owned()], "negation excludes");
    assert_eq!(run(repos, "format:pub -org:acme", &anonymous).await, vec!["other_http".to_owned()]);
    // `dependency:` reads both dependency kinds from the stored pubspecs.
    let mut dependents = run(repos, "dependency:bloc", &anonymous).await;
    dependents.sort();
    assert_eq!(dependents, vec!["flutter_bloc".to_owned(), "other_http".to_owned()]);
    // Two values of one dimension are OR; two dimensions are AND.
    let mut either = run(repos, "org:acme org:other", &anonymous).await;
    either.sort();
    assert_eq!(either.len(), 3);
    assert_eq!(run(repos, "org:acme topic:widgets", &anonymous).await, vec!["flutter_bloc".to_owned()]);
    // Text and filters compose.
    assert_eq!(run(repos, "bloc org:other", &anonymous).await, vec!["other_http".to_owned()]);
    // An unknown filter is ignored, not searched as text — the whole set comes back.
    assert_eq!(run(repos, "license:mit", &anonymous).await.len(), 3);

    // --- ordering ---
    let updated = parse_query("sort:updated", SearchSort::Relevance);
    assert_eq!(
        names(&repos.search.search(&updated, &anonymous, None, 50).await.expect("updated")),
        vec!["bloc".to_owned(), "flutter_bloc".to_owned(), "other_http".to_owned()],
        "sort:updated is newest first"
    );
    let by_name = parse_query("sort:name", SearchSort::Relevance);
    assert_eq!(
        names(&repos.search.search(&by_name, &anonymous, None, 50).await.expect("name")),
        vec!["bloc".to_owned(), "flutter_bloc".to_owned(), "other_http".to_owned()]
    );

    // --- cursors ---
    let mut seen = Vec::new();
    let mut cursor: Option<String> = None;
    loop {
        let page = repos.search.search(&by_name, &anonymous, cursor.as_deref(), 1).await.expect("page");
        assert!(page.items.len() <= 1);
        assert_eq!(page.cursor.is_some(), page.has_more, "cursor is Some iff has_more");
        seen.extend(names(&page));
        if !page.has_more {
            break;
        }
        cursor = page.cursor;
    }
    assert_eq!(seen, vec!["bloc".to_owned(), "flutter_bloc".to_owned(), "other_http".to_owned()], "no gaps or repeats");

    // A cursor is bound to the ordering that produced it (contract 3).
    let first = repos.search.search(&by_name, &anonymous, None, 1).await.expect("first");
    let cursor = first.cursor.expect("cursor");
    let err = repos.search.search(&updated, &anonymous, Some(&cursor), 1).await.expect_err("wrong ordering");
    assert_eq!(err.code(), "invalid_argument");
    for bad in ["%%%", "", "Zm9v"] {
        assert_eq!(
            repos.search.search(&by_name, &anonymous, Some(bad), 1).await.expect_err("bad cursor").code(),
            "invalid_argument",
            "{bad:?}"
        );
    }
    // Relevance pages too, and its cursor is ordering-bound as well.
    let text = parse_query("bloc", SearchSort::Relevance);
    let page = repos.search.search(&text, &anonymous, None, 1).await.expect("relevance page");
    assert!(page.has_more, "three documents mention bloc");
    let next = repos.search.search(&text, &anonymous, page.cursor.as_deref(), 5).await.expect("relevance page 2");
    assert!(!names(&next).contains(&page.items[0].name), "keyset must not repeat the previous page");

    // --- facets and counters agree with the listing ---
    let facets = repos.search.facets(&parse_query("", SearchSort::Relevance), &anonymous, 10).await.expect("facets");
    assert_eq!(facets.total, 3);
    let mut buckets: Vec<(String, i64)> = facets.orgs.iter().map(|f| (f.value.clone(), f.count)).collect();
    buckets.sort();
    assert_eq!(buckets, vec![("acme".to_owned(), 2), ("other".to_owned(), 1)]);
    // Facets respect the same filters as the page they describe.
    let filtered = repos.search.facets(&parse_query("org:acme", SearchSort::Relevance), &anonymous, 10).await.unwrap();
    assert_eq!(filtered.total, 2);

    let counters = repos.search.counters(&anonymous).await.expect("counters");
    assert_eq!(counters.packages, 3);
    assert_eq!(counters.versions, 3, "one live version per seeded document");
    assert_eq!(counters.orgs, 2);

    // --- index maintenance ---
    let package = repos.packages.get_by_name(Format::Pub, "bloc").await.unwrap().unwrap();
    let mut updated_doc = document(&package, "acme", "2.0.0");
    updated_doc.description = "Renamed description".to_owned();
    updated_doc.versions_count = 7;
    repos.search.index(&updated_doc).await.expect("reindex");
    let hit = repos
        .search
        .search(&parse_query("renamed", SearchSort::Relevance), &anonymous, None, 5)
        .await
        .expect("search")
        .items
        .pop()
        .expect("hit");
    assert_eq!(hit.name, "bloc");
    assert_eq!(hit.latest_version, "2.0.0");
    assert_eq!(hit.versions_count, 7);
    // Re-indexing replaces the old text rather than adding to it.
    assert!(run(repos, "predictable", &anonymous).await.is_empty(), "the previous description must be gone");
    assert_eq!(repos.search.counters(&anonymous).await.unwrap().versions, 9);

    // Downloads are written back by the rollup job and are what `sort:downloads` reads.
    repos.search.set_downloads(package.id, DownloadTotals { total: 500, recent: 42 }).await.expect("set downloads");
    let popular = parse_query("sort:downloads", SearchSort::Relevance);
    let page = repos.search.search(&popular, &anonymous, None, 5).await.expect("downloads");
    assert_eq!(page.items[0].name, "bloc");
    assert_eq!(page.items[0].downloads_total, 500);
    assert_eq!(page.items[0].downloads_recent, 42);
    // An unknown package is a no-op, not an error (the job races a hard delete).
    repos.search.set_downloads(pub_core::PackageId::new(), DownloadTotals::default()).await.expect("no-op");

    // Removal takes the package out of every surface at once.
    repos.search.remove(package.id).await.expect("remove");
    assert!(!run(repos, "sort:name", &anonymous).await.contains(&"bloc".to_owned()));
    assert_eq!(repos.search.counters(&anonymous).await.unwrap().packages, 2);
    repos.search.remove(package.id).await.expect("removing twice is not an error");
}

/// **S-04**: the search index never reveals a package the principal cannot read.
///
/// The matrix is the point: three visibility states × four principals, asserted on the listing,
/// on a text query, on an explicit `is:` filter that tries to ask for the hidden rows, on the
/// facet counts, and on the instance counters — every surface that could leak a name.
pub async fn search_visibility(repos: &Repositories) {
    let alice = seed_user(repos, "alice@corp.com", "Alice").await;
    let bob = seed_user(repos, "bob@corp.com", "Bob").await;
    let acme = seed_org(repos, "acme", alice.id).await;
    let other = seed_org(repos, "other", bob.id).await;

    seed_indexed(repos, &acme, "acme_public", Visibility::Public, |doc| {
        doc.description = "shared secretword library".to_owned();
    })
    .await;
    seed_indexed(repos, &acme, "acme_private", Visibility::Private, |doc| {
        doc.description = "internal secretword library".to_owned();
    })
    .await;
    seed_indexed(repos, &acme, "acme_hidden", Visibility::Public, |doc| {
        doc.description = "unlisted secretword library".to_owned();
        doc.unlisted = true;
    })
    .await;
    seed_indexed(repos, &other, "other_private", Visibility::Private, |doc| {
        doc.description = "foreign secretword library".to_owned();
    })
    .await;

    let anonymous = SearchView::anonymous();
    let member = SearchView::for_actor(&ActorContext::user(alice.id, BTreeMap::from([(acme.id, RoleLevel::READ)])));
    let outsider = SearchView::for_actor(&ActorContext::user(bob.id, BTreeMap::from([(other.id, RoleLevel::OWNER)])));
    // A membership below Read is not a membership for this purpose (decision 19 boundary).
    let too_low = SearchView::for_actor(&ActorContext::user(bob.id, BTreeMap::from([(acme.id, RoleLevel::new(49))])));

    // (view, expected visible names) — everything else must be invisible on every surface.
    let matrix: [(&str, &SearchView, Vec<&str>); 4] = [
        ("anonymous", &anonymous, vec!["acme_public"]),
        ("acme member", &member, vec!["acme_hidden", "acme_private", "acme_public"]),
        ("other org's owner", &outsider, vec!["acme_public", "other_private"]),
        ("below Read in acme", &too_low, vec!["acme_public"]),
    ];

    for (label, view, expected) in &matrix {
        // 1. The plain listing.
        let mut listed = run(repos, "sort:name", view).await;
        listed.sort();
        assert_eq!(&listed, expected, "listing for {label}");

        // 2. A text query that matches every document — the index must not widen visibility.
        let mut text = run(repos, "secretword", view).await;
        text.sort();
        assert_eq!(&text, expected, "text search for {label}");

        // 3. Asking for the hidden rows explicitly must not produce them.
        for probe in ["is:private", "is:unlisted", "org:acme is:private", "org:other is:private"] {
            for name in run(repos, probe, view).await {
                assert!(expected.contains(&name.as_str()), "{label} saw {name} through {probe:?}");
            }
        }
        // 4. An exact-name query for a package the principal cannot read finds nothing.
        for hidden in ["acme_private", "other_private", "acme_hidden"] {
            if !expected.contains(&hidden) {
                assert!(!run(repos, hidden, view).await.contains(&hidden.to_owned()), "{label} found {hidden} by name");
            }
        }

        // 5. Facet totals and counters must agree with the listing, or the count leaks what the
        // listing hides.
        let facets = repos.search.facets(&parse_query("", SearchSort::Relevance), view, 10).await.expect("facets");
        assert_eq!(facets.total as usize, expected.len(), "facet total for {label}");
        let counted: i64 = facets.orgs.iter().map(|bucket| bucket.count).sum();
        assert_eq!(counted as usize, expected.len(), "facet buckets for {label}");
        let counters = repos.search.counters(view).await.expect("counters");
        assert_eq!(counters.packages as usize, expected.len(), "counters for {label}");
    }

    // Unlisted is a *discovery* flag, not an access-control one: a member finds their own
    // unlisted package, and everybody else — including callers who ask for it by name — does
    // not. (Resolution by name through the pub protocol is unaffected; that is `resolve`.)
    assert!(run(repos, "is:unlisted", &member).await.contains(&"acme_hidden".to_owned()));
    assert!(run(repos, "is:unlisted", &anonymous).await.is_empty());

    // Visibility follows the document: reindexing the private package as public opens it, and
    // no cursor or filter had to change.
    let package = repos.packages.get_by_name(Format::Pub, "acme_private").await.unwrap().unwrap();
    let mut doc = document(&package, "acme", "1.0.0");
    doc.visibility = Visibility::Public;
    doc.description = "internal secretword library".to_owned();
    repos.search.index(&doc).await.expect("reindex public");
    assert!(run(repos, "secretword", &anonymous).await.contains(&"acme_private".to_owned()));
}

/// `StatsRepo`: additive daily rollups, trailing-window totals, and the job's write-back read.
pub async fn download_stats(repos: &Repositories) {
    repos.stats.ping().await.expect("ping");

    let alice = seed_user(repos, "alice@corp.com", "Alice").await;
    let org = seed_org(repos, "acme", alice.id).await;
    let first = repos
        .packages
        .create_version(new_version(org.id, "acme_core", "1.0.0", alice.id), t0())
        .await
        .expect("publish 1.0.0");
    let second = repos
        .packages
        .create_version(new_version(org.id, "acme_core", "1.1.0", alice.id), t0() + hours(1))
        .await
        .expect("publish 1.1.0");
    let package = first.package.id;

    let day = |offset: i64| (t0() + days(offset)).date_naive();
    assert_eq!(repos.stats.add_downloads(&[]).await.expect("empty batch"), 0);

    repos
        .stats
        .add_downloads(&[
            DownloadDelta { package_id: package, version_id: first.version.id, date: day(0), count: 3 },
            DownloadDelta { package_id: package, version_id: second.version.id, date: day(0), count: 2 },
            DownloadDelta { package_id: package, version_id: first.version.id, date: day(40), count: 10 },
        ])
        .await
        .expect("first flush");

    // The contract that matters: a second flush **adds** rather than replacing, because every
    // instance in a cluster writes its own counts.
    repos
        .stats
        .add_downloads(&[DownloadDelta { package_id: package, version_id: first.version.id, date: day(0), count: 5 }])
        .await
        .expect("second flush");

    let totals = repos.stats.package_totals(package, day(30)).await.expect("totals");
    assert_eq!(totals.total, 20, "3 + 2 + 10 + 5");
    assert_eq!(totals.recent, 10, "only the day-40 row is inside a window starting at day 30");
    // A window that covers everything sees everything; `since` is inclusive.
    assert_eq!(repos.stats.package_totals(package, day(0)).await.unwrap().recent, 20);

    // Non-positive deltas are ignored rather than corrupting a counter.
    repos
        .stats
        .add_downloads(&[DownloadDelta { package_id: package, version_id: first.version.id, date: day(0), count: 0 }])
        .await
        .expect("zero delta");
    assert_eq!(repos.stats.package_totals(package, day(0)).await.unwrap().total, 20);

    // A package with nothing recorded reports zeroes, not an error.
    assert_eq!(
        repos.stats.package_totals(pub_core::PackageId::new(), day(0)).await.expect("unknown"),
        DownloadTotals::default()
    );

    // The job's write-back input: bounded, and silent about packages with no downloads.
    assert!(repos.stats.totals_for(&[], day(0)).await.expect("empty").is_empty());
    let unknown = pub_core::PackageId::new();
    let batch = repos.stats.totals_for(&[package, unknown], day(30)).await.expect("totals_for");
    assert_eq!(batch.len(), 1, "packages with nothing recorded are omitted");
    assert_eq!(batch[0].package_id, package);
    assert_eq!(batch[0].totals, DownloadTotals { total: 20, recent: 10 });
}

// ------------------------------------------------------- management & administration (0008)

/// `UserRepo` administration surface: the instance-admin flag and its atomic bootstrap, the
/// filtered/keyset user listing, and the dashboard counts.
pub async fn instance_admins(repos: &Repositories) {
    let alice = seed_user(repos, "alice@corp.com", "Alice").await;
    let bob = seed_user(repos, "bob@corp.com", "Bob").await;
    let carol = seed_user(repos, "carol@other.com", "Carol").await;

    // A fresh account is never an administrator.
    assert!(!alice.is_instance_admin);

    // `claim_first_admin` is the empty-instance bootstrap: the *first* caller wins and every
    // later one is a no-op, because the condition is inside the UPDATE. Two accounts racing on
    // two instances therefore cannot both become the first administrator.
    assert!(repos.users.claim_first_admin(alice.id, t0()).await.expect("claim"));
    assert!(!repos.users.claim_first_admin(bob.id, t0()).await.expect("second claim"));
    // Idempotent for the holder too — a re-run of the bootstrap must not report a new grant.
    assert!(!repos.users.claim_first_admin(alice.id, t0()).await.expect("repeat claim"));
    assert!(repos.users.get(alice.id).await.expect("get").expect("alice").is_instance_admin);
    assert!(!repos.users.get(bob.id).await.expect("get").expect("bob").is_instance_admin);

    // The explicit setter grants and revokes, and bumps updated_at.
    let promoted = repos.users.set_instance_admin(bob.id, true, t0() + hours(1)).await.expect("promote");
    assert!(promoted.is_instance_admin);
    assert_eq!(promoted.updated_at, t0() + hours(1));
    let demoted = repos.users.set_instance_admin(bob.id, false, t0() + hours(2)).await.expect("demote");
    assert!(!demoted.is_instance_admin);
    let err = repos.users.set_instance_admin(UserId::new(), true, t0()).await.expect_err("unknown user");
    assert_eq!(err.code(), "not_found");

    // Counts.
    repos.users.update_status(carol.id, UserStatus::Suspended, t0()).await.expect("suspend");
    let counts = repos.users.counts().await.expect("counts");
    assert_eq!(counts.total, 3);
    assert_eq!(counts.active, 2);
    assert_eq!(counts.suspended, 1);
    assert_eq!(counts.deleted, 0);
    assert_eq!(counts.admins, 1);

    // Listing: newest account first, keyset over the (time-ordered) id.
    let page = repos.users.list(&UserFilter::default(), None, 2).await.expect("page 1");
    assert_eq!(page.items.len(), 2);
    assert!(page.has_more);
    assert_eq!(page.items[0].id, carol.id, "newest first");
    let rest = repos.users.list(&UserFilter::default(), page.cursor.as_deref(), 10).await.expect("page 2");
    assert_eq!(rest.items.iter().map(|u| u.id).collect::<Vec<_>>(), vec![alice.id]);
    assert!(!rest.has_more);
    assert_eq!(rest.cursor, None);

    // Filters combine with AND.
    let admins = repos.users.list(&UserFilter { admins_only: true, ..Default::default() }, None, 10).await.expect("a");
    assert_eq!(admins.items.iter().map(|u| u.id).collect::<Vec<_>>(), vec![alice.id]);
    let suspended = repos
        .users
        .list(&UserFilter { status: Some(UserStatus::Suspended), ..Default::default() }, None, 10)
        .await
        .expect("s");
    assert_eq!(suspended.items.iter().map(|u| u.id).collect::<Vec<_>>(), vec![carol.id]);

    // Text search matches email or display name, case-insensitively on both backends.
    let by_email =
        repos.users.list(&UserFilter { query: Some("OTHER.com".to_owned()), ..Default::default() }, None, 10).await;
    assert_eq!(by_email.expect("by email").items.len(), 1);
    let by_name = repos.users.list(&UserFilter { query: Some("ali".to_owned()), ..Default::default() }, None, 10).await;
    assert_eq!(by_name.expect("by name").items.len(), 1);

    // LIKE metacharacters in the query are data, not wildcards: `%` must match nothing here.
    let wildcard = repos.users.list(&UserFilter { query: Some("%".to_owned()), ..Default::default() }, None, 10).await;
    assert!(wildcard.expect("wildcard").items.is_empty(), "a literal % must not match every account");

    // A malformed cursor is a clean invalid_argument, never a reset listing.
    let err = repos.users.list(&UserFilter::default(), Some("!!!"), 10).await.expect_err("bad cursor");
    assert_eq!(err.code(), "invalid_argument");
}

/// `OrgRepo` management surface: profile updates, member listing, the admin org table,
/// invitation lookups behind the registration gate and the S-24 budget.
pub async fn org_management(repos: &Repositories) {
    let alice = seed_user(repos, "alice@corp.com", "Alice").await;
    let bob = seed_user(repos, "bob@corp.com", "Bob").await;
    let org = seed_org(repos, "acme", alice.id).await;
    seed_org(repos, "zeta", alice.id).await;
    assert_eq!(repos.orgs.count().await.expect("count"), 2);

    // A new org carries the payload's policy and description rather than a column default.
    let created = repos
        .orgs
        .create(
            NewOrg {
                name: "Blocked".to_owned(),
                slug: "blocked".to_owned(),
                description: "no upstream".to_owned(),
                upstream_policy: UpstreamPolicy::Block,
            },
            alice.id,
            t0(),
        )
        .await
        .expect("create with policy");
    assert_eq!(created.upstream_policy, UpstreamPolicy::Block);
    assert_eq!(created.description, "no upstream");
    assert!(!created.is_archived());

    // Profile replace: name, description, policy — and the slug is untouched by construction.
    let profile = OrgProfile {
        name: "Acme Inc".to_owned(),
        description: "The Acme organization".to_owned(),
        upstream_policy: UpstreamPolicy::Block,
    };
    let updated = repos.orgs.update_profile(org.id, &profile, t0() + hours(1)).await.expect("update");
    assert_eq!(updated.name, "Acme Inc");
    assert_eq!(updated.description, "The Acme organization");
    assert_eq!(updated.upstream_policy, UpstreamPolicy::Block);
    assert_eq!(updated.slug, "acme");
    assert_eq!(updated.updated_at, t0() + hours(1));
    let err = repos.orgs.update_profile(OrgId::new(), &profile, t0()).await.expect_err("unknown org");
    assert_eq!(err.code(), "not_found");

    // Members: highest role first.
    repos.orgs.add_member(org.id, bob.id, RoleLevel::WRITE, t0()).await.expect("add member");
    let members = repos.orgs.list_members(org.id).await.expect("members");
    assert_eq!(members.iter().map(|m| m.role).collect::<Vec<_>>(), vec![RoleLevel::OWNER, RoleLevel::WRITE]);
    assert_eq!(members[0].user_id, alice.id);
    assert!(repos.orgs.list_members(OrgId::new()).await.expect("unknown org").is_empty());

    // The admin org table pages over the slug and carries the counts the delete guard uses.
    let page = repos.orgs.list_all(None, 2).await.expect("orgs page 1");
    assert_eq!(page.items.iter().map(|row| row.org.slug.as_str()).collect::<Vec<_>>(), vec!["acme", "blocked"]);
    assert!(page.has_more);
    assert_eq!(page.items[0].members, 2);
    assert_eq!(page.items[0].packages, 0);
    let rest = repos.orgs.list_all(page.cursor.as_deref(), 10).await.expect("orgs page 2");
    assert_eq!(rest.items.iter().map(|row| row.org.slug.as_str()).collect::<Vec<_>>(), vec!["zeta"]);

    // Invitation lookups: the `invite`-only registration gate and the S-24 per-org budget.
    assert!(!repos.orgs.has_pending_invitation("bob@corp.com", t0()).await.expect("none yet"));
    repos
        .orgs
        .create_invitation(NewInvitation::new(org.id, "New.Hire@corp.com", alice.id, "inv-1", t0() + days(7)), t0())
        .await
        .expect("invite");
    // Case-insensitive, like every other email lookup.
    assert!(repos.orgs.has_pending_invitation("new.hire@CORP.com", t0()).await.expect("pending"));
    // Expiry is a fact about the row, not about when somebody asks.
    assert!(!repos.orgs.has_pending_invitation("new.hire@corp.com", t0() + days(8)).await.expect("expired"));
    assert_eq!(repos.orgs.count_invitations_since(org.id, t0() - days(1)).await.expect("count"), 1);
    assert_eq!(repos.orgs.count_invitations_since(org.id, t0() + hours(1)).await.expect("window"), 0);

    // **S-24.h**, the per-actor half. Bob invites twice, an hour apart, into the same org Alice
    // invited into. What has to hold: the actor count is *narrower* than the org count, it is
    // scoped to one org, and its window rolls the same way the org count's does.
    for (index, at) in [t0(), t0() + hours(1)].into_iter().enumerate() {
        repos
            .orgs
            .create_invitation(
                NewInvitation::new(
                    org.id,
                    format!("hire{index}@corp.com"),
                    bob.id,
                    format!("bob-inv-{index}"),
                    at + days(7),
                ),
                at,
            )
            .await
            .expect("bob invites");
    }
    // Alice's one and Bob's two share the org budget; Bob's own budget counts only his.
    assert_eq!(repos.orgs.count_invitations_since(org.id, t0() - days(1)).await.expect("org budget"), 3);
    assert_eq!(
        repos.orgs.count_invitations_since_by_actor(org.id, bob.id, t0() - days(1)).await.expect("actor budget"),
        2
    );
    assert_eq!(
        repos.orgs.count_invitations_since_by_actor(org.id, alice.id, t0() - days(1)).await.expect("other actor"),
        1,
        "one member's sending must not spend another's budget"
    );
    // Rolling, not tumbling: `since` is an instant, so a window opened after the first send sees
    // only what came later.
    assert_eq!(
        repos.orgs.count_invitations_since_by_actor(org.id, bob.id, t0() + minutes(30)).await.expect("window"),
        1
    );
    assert_eq!(
        repos.orgs.count_invitations_since_by_actor(org.id, bob.id, t0() + hours(2)).await.expect("past window"),
        0
    );
    // Scoped to one org: the same actor's invitations elsewhere are somebody else's budget. This
    // is the assertion an index-only implementation on `(invited_by, created_at)` fails if it
    // ever drops the `org_id` predicate.
    let elsewhere = seed_org(repos, "elsewhere", bob.id).await;
    repos
        .orgs
        .create_invitation(
            NewInvitation::new(elsewhere.id, "hire@corp.com", bob.id, "bob-inv-elsewhere", t0() + days(7)),
            t0(),
        )
        .await
        .expect("bob invites into his own org");
    assert_eq!(
        repos.orgs.count_invitations_since_by_actor(org.id, bob.id, t0() - days(1)).await.expect("still scoped"),
        2,
        "an invitation into another org must not spend this org's per-actor budget"
    );
    assert_eq!(
        repos.orgs.count_invitations_since_by_actor(elsewhere.id, bob.id, t0() - days(1)).await.expect("other org"),
        1
    );
    // An actor who has sent nothing here is at zero rather than an error.
    assert_eq!(
        repos.orgs.count_invitations_since_by_actor(org.id, UserId::new(), t0() - days(1)).await.expect("stranger"),
        0
    );

    // A revoked invitation stops being redeemable, so it stops opening the registration gate.
    let pending = repos.orgs.find_invitation_by_token_hash("inv-1").await.expect("find").expect("row");
    repos.orgs.revoke_invitation(pending.id, t0() + hours(1)).await.expect("revoke");
    assert!(!repos.orgs.has_pending_invitation("new.hire@corp.com", t0() + hours(2)).await.expect("revoked"));
}

/// Org deletion and the archive fallback: an org that owns packages cannot be erased, because
/// decision 06 / S-18 keep its name claims and version rows forever.
pub async fn org_deletion(repos: &Repositories) {
    let alice = seed_user(repos, "alice@corp.com", "Alice").await;
    let bob = seed_user(repos, "bob@corp.com", "Bob").await;
    let empty = seed_org(repos, "empty", alice.id).await;
    let owning = seed_org(repos, "owning", alice.id).await;

    // An org with nothing durable behind it is erased outright, memberships, invitations, and
    // org-bound tokens with it.
    repos.orgs.add_member(empty.id, bob.id, RoleLevel::READ, t0()).await.expect("member");
    repos
        .orgs
        .create_invitation(NewInvitation::new(empty.id, "x@corp.com", alice.id, "inv-e", t0() + days(7)), t0())
        .await
        .expect("invitation");
    repos
        .tokens
        .create(
            NewToken {
                user_id: alice.id,
                org_id: empty.id,
                name: "ci".to_owned(),
                token_hash: "tok-empty".to_owned(),
                display_hint: "pub_aaaa".to_owned(),
                scopes: vec![TokenScope::Read],
                package_patterns: vec![],
                expires_at: None,
            },
            t0(),
        )
        .await
        .expect("token");
    repos.orgs.delete(empty.id).await.expect("delete empty org");
    assert_eq!(repos.orgs.get(empty.id).await.expect("gone"), None);
    assert!(repos.orgs.list_members(empty.id).await.expect("members").is_empty());
    assert!(repos.orgs.list_invitations(empty.id).await.expect("invitations").is_empty());
    assert!(repos.tokens.list_for_org(empty.id).await.expect("tokens").is_empty());
    assert_eq!(repos.orgs.delete(empty.id).await.expect_err("already gone").code(), "not_found");

    // An org that owns a package refuses erasure — before touching anything.
    repos
        .packages
        .create_version(new_version(owning.id, "owning_pkg", "1.0.0", alice.id), t0())
        .await
        .expect("publish");
    let err = repos.orgs.delete(owning.id).await.expect_err("owns packages");
    assert_eq!(err.code(), "conflict");
    assert!(repos.orgs.get(owning.id).await.expect("still there").is_some());

    // Archiving is the fallback: authority is stripped, the row and its claims survive.
    repos.orgs.add_member(owning.id, bob.id, RoleLevel::ADMIN, t0()).await.expect("member");
    repos
        .tokens
        .create(
            NewToken {
                user_id: alice.id,
                org_id: owning.id,
                name: "ci".to_owned(),
                token_hash: "tok-owning".to_owned(),
                display_hint: "pub_bbbb".to_owned(),
                scopes: vec![TokenScope::Publish],
                package_patterns: vec![],
                expires_at: None,
            },
            t0(),
        )
        .await
        .expect("token");
    let archived = repos.orgs.archive(owning.id, t0() + hours(3)).await.expect("archive");
    assert_eq!(archived.archived_at, Some(t0() + hours(3)));
    assert!(archived.is_archived());
    assert!(repos.orgs.list_members(owning.id).await.expect("members").is_empty());
    assert!(repos.tokens.list_for_org(owning.id).await.expect("tokens").is_empty(), "org tokens are revoked");
    // The package and its claim are untouched: the number stays burned (S-18).
    assert!(repos.packages.get_by_name(Format::Pub, "owning_pkg").await.expect("package").is_some());
    assert!(repos.packages.lookup_claim(Format::Pub, "owning_pkg").await.expect("claim").is_some());

    // Idempotent: re-archiving keeps the first stamp.
    let again = repos.orgs.archive(owning.id, t0() + days(1)).await.expect("re-archive");
    assert_eq!(again.archived_at, Some(t0() + hours(3)));
    assert_eq!(repos.orgs.archive(OrgId::new(), t0()).await.expect_err("unknown").code(), "not_found");
}

/// Package transfer and the instance statistics the admin dashboard reads.
pub async fn package_transfer_and_stats(repos: &Repositories) {
    let alice = seed_user(repos, "alice@corp.com", "Alice").await;
    let from = seed_org(repos, "from", alice.id).await;
    let to = seed_org(repos, "to", alice.id).await;

    let published = repos
        .packages
        .create_version(new_version(from.id, "moving_pkg", "1.0.0", alice.id), t0())
        .await
        .expect("publish");
    repos.packages.create_version(new_version(from.id, "staying_pkg", "1.0.0", alice.id), t0()).await.expect("second");
    assert_eq!(repos.packages.count_for_org(from.id).await.expect("count"), 2);
    assert_eq!(repos.packages.count_for_org(to.id).await.expect("count"), 0);

    // The claim moves with the package, in one transaction — otherwise the new owner could not
    // publish the name they now hold, and an S-17 alarm would page the wrong admins.
    let moved = repos.packages.transfer(published.package.id, to.id, t0() + hours(1)).await.expect("transfer");
    assert_eq!(moved.org_id, to.id);
    assert_eq!(moved.updated_at, t0() + hours(1));
    let claim = repos.packages.lookup_claim(Format::Pub, "moving_pkg").await.expect("claim").expect("row");
    assert_eq!(claim.org_id, to.id);
    assert_eq!(repos.packages.count_for_org(from.id).await.expect("count"), 1);
    assert_eq!(repos.packages.count_for_org(to.id).await.expect("count"), 1);

    // Transferring to the current owner is a no-op that still answers with the row.
    let same = repos.packages.transfer(published.package.id, to.id, t0() + hours(2)).await.expect("no-op");
    assert_eq!(same.org_id, to.id);
    assert_eq!(same.updated_at, t0() + hours(1), "a no-op must not bump updated_at");
    let err = repos.packages.transfer(PackageId::new(), to.id, t0()).await.expect_err("unknown package");
    assert_eq!(err.code(), "not_found");

    // Instance statistics.
    repos.packages.create_version(new_version(to.id, "moving_pkg", "2.0.0", alice.id), t0()).await.expect("v2");
    let v1 = repos
        .packages
        .get_version(published.package.id, &SemVer::parse("1.0.0").unwrap())
        .await
        .expect("get")
        .expect("row");
    repos.packages.set_retracted(v1.id, true, t0() + hours(3)).await.expect("retract");
    let public =
        PackageOptions { visibility: Visibility::Public, discontinued: false, replaced_by: None, unlisted: false };
    repos.packages.set_options(published.package.id, &public, t0()).await.expect("publicize");

    let stats = repos.packages.stats().await.expect("stats");
    assert_eq!(stats.packages, 2);
    assert_eq!(stats.public_packages, 1);
    assert_eq!(stats.versions, 3);
    assert_eq!(stats.retracted_versions, 1);
    assert_eq!(stats.tombstoned_versions, 0);
    assert_eq!(stats.archive_bytes, 3 * 1024, "the fixture stores 1 KiB per version");

    // A hard delete moves a version from live to tombstoned and stops counting its bytes.
    repos.packages.hard_delete_version(v1.id).await.expect("hard delete");
    let after = repos.packages.stats().await.expect("stats after");
    assert_eq!(after.versions, 2);
    assert_eq!(after.retracted_versions, 0, "a tombstone is no longer a live retracted version");
    assert_eq!(after.tombstoned_versions, 1);
    assert_eq!(after.archive_bytes, 2 * 1024);

    // The proxy cache reports its own totals; an untouched cache is all zeroes rather than an
    // error, so a fresh instance's dashboard renders.
    let empty_cache = repos.upstream.cache_stats(Format::Pub).await.expect("cache stats");
    assert_eq!(empty_cache, pub_core::package::UpstreamCacheStats::default());
    repos
        .upstream
        .save_snapshot(
            UpstreamSnapshot {
                format: Format::Pub,
                name: "http".to_owned(),
                upstream: "https://pub.dev".to_owned(),
                discontinued: false,
                replaced_by: None,
                advisories_updated: None,
                listing: None,
                versions: vec![
                    NewUpstreamVersion {
                        version: SemVer::parse("1.0.0").unwrap(),
                        pubspec: serde_json::json!({"name": "http"}),
                        archive_sha256: "a".repeat(64),
                        archive_size: None,
                        retracted: false,
                        published_at: None,
                    },
                    NewUpstreamVersion {
                        version: SemVer::parse("1.1.0").unwrap(),
                        pubspec: serde_json::json!({"name": "http"}),
                        archive_sha256: "b".repeat(64),
                        archive_size: None,
                        retracted: false,
                        published_at: None,
                    },
                ],
            },
            t0(),
        )
        .await
        .expect("snapshot");
    let snapshot = repos.upstream.get_package(Format::Pub, "http").await.expect("get").expect("row");
    let cached_version = repos.upstream.list_versions(snapshot.id).await.expect("versions")[0].id;
    repos.upstream.mark_cached(cached_version, &"a".repeat(64), 2048, t0()).await.expect("mark cached");
    let cache = repos.upstream.cache_stats(Format::Pub).await.expect("cache stats");
    assert_eq!(cache.packages, 1);
    assert_eq!(cache.versions, 2);
    assert_eq!(cache.cached_versions, 1);
    assert_eq!(cache.cached_bytes, 2048);
}

/// **S-20.b.** The storage quota's two halves: the number it is checked against
/// (`OrgRepo::set_storage_quota`) and the number it checks (`PackageRepo::org_storage_bytes`).
///
/// Every clause of the sum is a rule somebody could reasonably implement the other way round, so
/// each gets its own assertion: a **retracted** version still costs storage because it is still
/// downloadable, a **tombstoned** one does not because its bytes are collectable, another org's
/// versions are not this org's problem, and two versions sharing one `archive_sha256` are
/// **both** charged — the deliberate over-count decision 32 takes so that one org's quota cannot
/// depend on another org's behaviour.
pub async fn storage_quota(repos: &Repositories) {
    let alice = seed_user(repos, "alice@corp.com", "Alice").await;
    let org = seed_org(repos, "acme", alice.id).await;
    let other = seed_org(repos, "other", alice.id).await;

    // An org that owns nothing is at zero bytes rather than in an error state — the caller
    // compares this against a quota, and "no packages yet" is the state every org starts in.
    assert_eq!(repos.packages.org_storage_bytes(org.id).await.expect("empty org"), 0);
    // An id that never existed answers the same way, for the same reason: the question is "how
    // many bytes", and nothing has any.
    assert_eq!(repos.packages.org_storage_bytes(OrgId::new()).await.expect("unknown org"), 0);

    let publish = async |owner: OrgId, name: &str, version: &str, size: i64, sha: &str| {
        repos
            .packages
            .create_version(
                NewVersion {
                    archive_size: size,
                    archive_sha256: sha.to_owned(),
                    ..new_version(owner, name, version, alice.id)
                },
                t0(),
            )
            .await
            .expect("publish")
    };
    let bytes = async |owner: OrgId| repos.packages.org_storage_bytes(owner).await.expect("org bytes");

    publish(org.id, "kept_pkg", "1.0.0", 1_000, &"a".repeat(64)).await;
    assert_eq!(bytes(org.id).await, 1_000);

    // Byte-identical content under a new version number: content addressing means one blob backs
    // both rows, and both are charged. Deliberate (decision 32) — the alternative makes an org's
    // usage fall when a stranger publishes the same bytes.
    publish(org.id, "kept_pkg", "2.0.0", 2_000, &"a".repeat(64)).await;
    assert_eq!(bytes(org.id).await, 3_000, "deduplicated bytes are deliberately over-counted");

    // A retracted version is still downloadable (sharp edge 9), so its bytes are still stored.
    let retracted = publish(org.id, "retracted_pkg", "1.0.0", 4_000, &"b".repeat(64)).await;
    repos.packages.set_retracted(retracted.version.id, true, t0() + hours(1)).await.expect("retract");
    assert_eq!(bytes(org.id).await, 7_000, "a retracted version still occupies storage");

    // A tombstone does not: a hard delete is how an org frees space.
    let deleted = publish(org.id, "deleted_pkg", "1.0.0", 8_000, &"c".repeat(64)).await;
    assert_eq!(bytes(org.id).await, 15_000);
    repos.packages.hard_delete_version(deleted.version.id).await.expect("hard delete");
    assert_eq!(bytes(org.id).await, 7_000, "a tombstoned version stops being charged");

    // Another org's bytes are its own. Without the join predicate this reads instance-wide, and
    // every assertion above would still pass on a single-org fixture.
    publish(other.id, "elsewhere_pkg", "1.0.0", 16_000, &"d".repeat(64)).await;
    assert_eq!(bytes(org.id).await, 7_000, "another org's versions must not count against this one");
    assert_eq!(bytes(other.id).await, 16_000);

    // **Proxied upstream archives never count** — the third contract rule, and the one no
    // fixture used to exercise. `upstream_versions` has no org column by design and the cache is
    // instance-wide, so an implementation that unioned it in would charge every org for one
    // org's `dart pub get` — and would pass every assertion above, because none of them puts a
    // row in that table. Both dialects, because a UNION is a query somebody writes once.
    repos
        .upstream
        .save_snapshot(
            upstream_snapshot(vec![upstream_version("1.0.0", &"e".repeat(64), false)], false),
            t0() + hours(1),
        )
        .await
        .expect("upstream snapshot");
    let cached = repos.upstream.get_package(Format::Pub, "http").await.expect("get").expect("row");
    let cached_version = repos.upstream.list_versions(cached.id).await.expect("versions")[0].id;
    // Cached, so the bytes are genuinely sitting in this instance's blob store — and still not
    // this org's, nor anybody's.
    repos.upstream.mark_cached(cached_version, &"e".repeat(64), 32_000, t0() + hours(1)).await.expect("mark cached");
    assert_eq!(bytes(org.id).await, 7_000, "a proxied upstream archive is not an org's stored bytes");
    assert_eq!(bytes(other.id).await, 16_000, "…for any org");

    // --- one package's share of that total (the number a transfer moves) --------------------
    let package_bytes = async |name: &str| {
        let package = repos.packages.get_by_name(Format::Pub, name).await.expect("get").expect("package");
        repos.packages.package_storage_bytes(package.id).await.expect("package bytes")
    };
    // The same three rules, narrowed to one package: two live versions charged (including the
    // deduplicated pair), the retracted one still charged, the tombstoned one no longer.
    assert_eq!(package_bytes("kept_pkg").await, 3_000, "every live version of the package, deduplication included");
    assert_eq!(package_bytes("retracted_pkg").await, 4_000, "a retracted version still occupies storage");
    assert_eq!(package_bytes("deleted_pkg").await, 0, "a tombstoned version stops being charged");
    // The sum over an org's packages is the org's own total — the property the transfer guard
    // rests on, since `transfer` re-attributes exactly these bytes.
    assert_eq!(
        package_bytes("kept_pkg").await + package_bytes("retracted_pkg").await + package_bytes("deleted_pkg").await,
        bytes(org.id).await,
        "one package's bytes are the org's bytes, partitioned by package"
    );
    // An id that never existed answers 0 rather than erroring, like an unknown org.
    assert_eq!(repos.packages.package_storage_bytes(PackageId::new()).await.expect("unknown package"), 0);
    // …and a package belonging to another org is read on its own terms: the method is keyed on
    // the package, so it must not smuggle in the org filter its sibling has.
    assert_eq!(package_bytes("elsewhere_pkg").await, 16_000);

    // --- the override -------------------------------------------------------------------
    assert_eq!(org.storage_quota_bytes, None, "a new org has no override and follows the instance default");

    let limited = repos.orgs.set_storage_quota(org.id, Some(10_000), t0() + hours(2)).await.expect("set quota");
    assert_eq!(limited.storage_quota_bytes, Some(10_000));
    assert_eq!(limited.updated_at, t0() + hours(2));
    assert_eq!(limited.created_at, t0(), "setting a quota is not a re-creation");
    // Every read path carries it, not just the one that wrote it.
    assert_eq!(repos.orgs.get(org.id).await.expect("get").expect("org").storage_quota_bytes, Some(10_000));
    assert_eq!(repos.orgs.get_by_slug("ACME").await.expect("slug").expect("org").storage_quota_bytes, Some(10_000));
    let listed = repos.orgs.list_all(None, 10).await.expect("list");
    let row = listed.items.iter().find(|row| row.org.id == org.id).expect("acme in the admin listing");
    assert_eq!(row.org.storage_quota_bytes, Some(10_000));
    let memberships = repos.orgs.list_for_user(alice.id).await.expect("memberships");
    let joined = memberships.iter().find(|row| row.org.id == org.id).expect("acme among alice's orgs");
    assert_eq!(joined.org.storage_quota_bytes, Some(10_000), "the joined listing carries the override too");

    // The separation decision 32 buys: the profile write an **org Admin** can reach must not be
    // able to touch the quota. `OrgProfile` has no field for it, and this is the assertion that
    // keeps it that way if somebody adds one.
    let profile = OrgProfile {
        name: "Acme Inc".to_owned(),
        description: "renamed".to_owned(),
        upstream_policy: UpstreamPolicy::Block,
    };
    let renamed = repos.orgs.update_profile(org.id, &profile, t0() + hours(3)).await.expect("profile write");
    assert_eq!(renamed.storage_quota_bytes, Some(10_000), "a profile write must not disturb the quota");

    // `Some(0)` is an explicit "unlimited for this org" and is a different row from `None`:
    // `None` follows an instance default an operator may change later, `Some(0)` does not.
    let unlimited = repos.orgs.set_storage_quota(org.id, Some(0), t0() + hours(4)).await.expect("explicit unlimited");
    assert_eq!(unlimited.storage_quota_bytes, Some(0));
    let cleared = repos.orgs.set_storage_quota(org.id, None, t0() + hours(5)).await.expect("clear override");
    assert_eq!(cleared.storage_quota_bytes, None);
    assert_eq!(repos.orgs.get(org.id).await.expect("get").expect("org").storage_quota_bytes, None);

    let err = repos.orgs.set_storage_quota(OrgId::new(), Some(1), t0()).await.expect_err("unknown org");
    assert_eq!(err.code(), "not_found");
}

/// `NotificationRepo`: the per-user feed, the unread badge, mark-read semantics, and
/// per-category preferences (decision 20).
///
/// The load-bearing assertion is the scoping one: every method takes a user, and a foreign id
/// handed to `mark_read` changes nothing and reports nothing — anything else would be an
/// existence oracle over another account's notification ids.
pub async fn notifications(repos: &Repositories) {
    repos.notifications.ping().await.expect("ping");

    let alice = seed_user(repos, "alice@corp.com", "Alice").await;
    let bob = seed_user(repos, "bob@corp.com", "Bob").await;
    let org = seed_org(repos, "acme", alice.id).await;

    let file = async |user: UserId, title: &str, at: DateTime<Utc>| {
        repos
            .notifications
            .create(
                NewNotification {
                    user_id: user,
                    category: NotificationCategory::Package,
                    event_id: None,
                    event: "package.publish".to_owned(),
                    title: title.to_owned(),
                    org_id: Some(org.id),
                    payload: serde_json::json!({ "type": "package_published", "name": title }),
                },
                at,
            )
            .await
            .expect("file notification")
    };

    let first = file(alice.id, "acme_core 1.0.0", t0()).await;
    assert_eq!(first.user_id, alice.id);
    assert_eq!(first.category, NotificationCategory::Package);
    assert_eq!(first.org_id, Some(org.id));
    assert_eq!(first.created_at, t0());
    assert!(first.is_unread());
    assert_eq!(first.payload["name"], "acme_core 1.0.0", "the payload round-trips verbatim");

    let second = file(alice.id, "acme_core 1.1.0", t0() + hours(1)).await;
    let foreign = file(bob.id, "acme_core 1.2.0", t0() + hours(2)).await;

    // The feed is newest first and never crosses accounts.
    let page = repos.notifications.list(alice.id, false, None, 50).await.expect("feed");
    assert_eq!(
        page.items.iter().map(|n| n.id).collect::<Vec<_>>(),
        vec![second.id, first.id],
        "newest first, and bob's row is invisible"
    );
    assert!(!page.has_more);
    assert_eq!(repos.notifications.unread_count(alice.id).await.expect("unread"), 2);
    assert_eq!(repos.notifications.unread_count(bob.id).await.expect("unread"), 1);

    // Keyset pagination walks the whole feed without skips or duplicates.
    let mut walked = Vec::new();
    let mut cursor: Option<String> = None;
    loop {
        let page = repos.notifications.list(alice.id, false, cursor.as_deref(), 1).await.expect("page");
        assert_eq!(page.cursor.is_some(), page.has_more);
        walked.extend(page.items.iter().map(|n| n.id));
        if !page.has_more {
            break;
        }
        cursor = page.cursor;
    }
    assert_eq!(walked, vec![second.id, first.id]);
    assert_eq!(
        repos.notifications.list(alice.id, false, Some("%%%"), 10).await.expect_err("bad cursor").code(),
        "invalid_argument"
    );

    // mark_read is scoped, idempotent, and monotonic.
    let marked =
        repos.notifications.mark_read(alice.id, &[first.id, foreign.id], t0() + hours(3)).await.expect("mark read");
    assert_eq!(marked, 1, "bob's notification is not alice's to mark");
    assert_eq!(repos.notifications.unread_count(bob.id).await.expect("unread"), 1, "and it stayed unread for bob");
    let again = repos
        .notifications
        .mark_read(alice.id, std::slice::from_ref(&first.id), t0() + hours(4))
        .await
        .expect("mark again");
    assert_eq!(again, 0, "re-marking changes nothing");
    let read_row = repos
        .notifications
        .list(alice.id, false, None, 50)
        .await
        .expect("feed")
        .items
        .into_iter()
        .find(|n| n.id == first.id)
        .expect("row");
    assert_eq!(read_row.read_at, Some(t0() + hours(3)), "the original read instant survives");
    assert_eq!(repos.notifications.mark_read(alice.id, &[], t0()).await.expect("empty"), 0);

    // unread_only narrows to the unread rows.
    let unread = repos.notifications.list(alice.id, true, None, 50).await.expect("unread feed");
    assert_eq!(unread.items.iter().map(|n| n.id).collect::<Vec<_>>(), vec![second.id]);

    // mark_all_read touches only this account's unread rows.
    assert_eq!(repos.notifications.mark_all_read(alice.id, t0() + hours(5)).await.expect("all"), 1);
    assert_eq!(repos.notifications.unread_count(alice.id).await.expect("unread"), 0);
    assert_eq!(repos.notifications.unread_count(bob.id).await.expect("unread"), 1, "bob is untouched");
    assert_eq!(repos.notifications.mark_all_read(alice.id, t0() + hours(6)).await.expect("all again"), 0);

    // Preferences: nothing stored means nothing returned; the defaults live in core.
    assert!(repos.notifications.preferences(alice.id).await.expect("prefs").is_empty());
    let stored = repos
        .notifications
        .set_preferences(
            alice.id,
            &[
                NotificationPreference { category: NotificationCategory::Package, in_app: false, email: false },
                NotificationPreference { category: NotificationCategory::Security, in_app: true, email: false },
            ],
            t0() + hours(7),
        )
        .await
        .expect("set prefs");
    assert_eq!(stored.len(), 2);
    let effective = NotificationPreferences::from_rows(&stored);
    assert!(!effective.for_category(NotificationCategory::Package).in_app);
    assert!(!effective.for_category(NotificationCategory::Security).email);
    assert!(effective.for_category(NotificationCategory::Org).email, "an untouched category keeps its default");

    // Upsert, not insert: a second write replaces the row rather than conflicting.
    let updated = repos
        .notifications
        .set_preferences(
            alice.id,
            &[NotificationPreference { category: NotificationCategory::Package, in_app: true, email: true }],
            t0() + hours(8),
        )
        .await
        .expect("update prefs");
    assert_eq!(updated.len(), 2, "the untouched stored row survives");
    let effective = NotificationPreferences::from_rows(&updated);
    assert!(effective.for_category(NotificationCategory::Package).email);

    // The batch lookup the fan-out uses returns stored rows only, for the asked category only.
    let batch = repos
        .notifications
        .stored_preferences(&[alice.id, bob.id], NotificationCategory::Package)
        .await
        .expect("batch prefs");
    assert_eq!(batch.len(), 1, "bob stored nothing, so bob is absent and takes the default");
    assert_eq!(batch[0].0, alice.id);
    assert!(batch[0].1.email);
    assert!(repos.notifications.stored_preferences(&[], NotificationCategory::Org).await.expect("empty").is_empty());
    assert_eq!(
        repos.notifications.stored_preferences(&[bob.id], NotificationCategory::Org).await.expect("miss").len(),
        0
    );

    // The batched write the asynchronous fan-out uses (decision 26): one statement per chunk,
    // ids minted in input order.
    let batched = |user: UserId, title: &str| NewNotification {
        user_id: user,
        category: NotificationCategory::Org,
        event_id: None,
        event: "org.membership".to_owned(),
        title: title.to_owned(),
        org_id: Some(org.id),
        payload: serde_json::json!({ "type": "org_membership_changed", "title": title }),
    };
    let filed = repos
        .notifications
        .create_many(
            &[batched(alice.id, "alice first"), batched(bob.id, "bob"), batched(alice.id, "alice second")],
            t0() + hours(9),
        )
        .await
        .expect("create_many");
    assert_eq!(
        filed.iter().map(|row| (row.user_id, row.title.as_str())).collect::<Vec<_>>(),
        vec![(alice.id, "alice first"), (bob.id, "bob"), (alice.id, "alice second")],
        "the rows come back in input order"
    );
    assert!(filed.windows(2).all(|pair| pair[0].id < pair[1].id), "ids are minted in input order");
    assert!(filed.iter().all(|row| row.created_at == t0() + hours(9) && row.is_unread()));
    assert_eq!(filed[0].payload["title"], "alice first", "the payload round-trips verbatim");
    // Which is what makes the recipient's feed read back in the order the audience resolved.
    let feed = repos.notifications.list(alice.id, true, None, 50).await.expect("feed");
    assert_eq!(
        feed.items.iter().map(|row| row.title.as_str()).collect::<Vec<_>>(),
        vec!["alice second", "alice first"],
        "newest first inside one batch"
    );
    assert!(repos.notifications.create_many(&[], t0()).await.expect("empty batch").is_empty());
    let oversized: Vec<NewNotification> = (0..=MAX_NOTIFICATION_BATCH).map(|_| batched(alice.id, "flood")).collect();
    assert_eq!(
        repos.notifications.create_many(&oversized, t0()).await.expect_err("oversized batch").code(),
        "invalid_argument",
        "a batch past the cap is a caller error, never a statement of unbounded size"
    );

    // The batched badge lookup: grouped, and silent about users with nothing unread.
    let stranger = UserId::new();
    let counts = repos.notifications.unread_counts(&[alice.id, bob.id, stranger]).await.expect("unread counts");
    let counts: BTreeMap<UserId, i64> = counts.into_iter().collect();
    assert_eq!(counts.get(&alice.id), Some(&2), "the two rows the batch filed");
    assert_eq!(counts.get(&bob.id), Some(&2), "one older row plus one from the batch");
    assert_eq!(counts.get(&stranger), None, "a user with nothing unread is absent, not zero");
    for (user, count) in &counts {
        assert_eq!(
            *count,
            repos.notifications.unread_count(*user).await.expect("single"),
            "the batch agrees with the single read"
        );
    }
    assert!(repos.notifications.unread_counts(&[]).await.expect("empty").is_empty());
    let flood: Vec<UserId> = (0..=MAX_NOTIFICATION_BATCH).map(|_| alice.id).collect();
    assert_eq!(repos.notifications.unread_counts(&flood).await.expect_err("oversized").code(), "invalid_argument");

    // Exactly-once fan-out (decision 26's amendment): `(user_id, event_id)` is unique, so a
    // fan-out re-run after a crash — or any future path that re-emits one event — converges on
    // the rows that are already there instead of filing everybody a second copy. Migration
    // 0009's own header claimed "one row per (recipient, event)" and nothing enforced it. What
    // the caller gets back is *what this call created*, which is what lets it announce only the
    // rows it actually wrote.
    let emission = EventId::generate();
    let from_event =
        |user: UserId, title: &str| NewNotification { event_id: Some(emission.clone()), ..batched(user, title) };
    let before = repos.notifications.list(alice.id, false, None, 50).await.expect("feed").items.len();
    let first_run = repos
        .notifications
        .create_many(&[from_event(alice.id, "one event"), from_event(bob.id, "one event")], t0() + hours(10))
        .await
        .expect("first fan-out");
    assert_eq!(first_run.len(), 2, "both recipients are new");
    let second_run = repos
        .notifications
        .create_many(&[from_event(alice.id, "one event"), from_event(bob.id, "one event")], t0() + hours(11))
        .await
        .expect("re-run fan-out");
    assert!(second_run.is_empty(), "a re-run files nothing and reports nothing: {second_run:?}");
    assert_eq!(
        repos.notifications.list(alice.id, false, None, 50).await.expect("feed").items.len(),
        before + 1,
        "the two runs of one emission left exactly one row"
    );
    // A *different* emission is different work, and a row that names no emission never
    // collides — otherwise one recipient could hold at most one notification.
    let reemitted = repos
        .notifications
        .create_many(
            &[NewNotification { event_id: Some(EventId::generate()), ..batched(alice.id, "second emission") }],
            t0() + hours(12),
        )
        .await
        .expect("second emission");
    assert_eq!(reemitted.len(), 1, "a second emission is a second row");
    let unkeyed = repos
        .notifications
        .create_many(&[batched(alice.id, "no event id"), batched(alice.id, "no event id either")], t0() + hours(13))
        .await
        .expect("unkeyed batch");
    assert_eq!(unkeyed.len(), 2, "rows that name no emission must not collide with each other");
    // A batch that repeats one recipient inside a single statement is the same conflict seen
    // from the other side: the first wins, the second is skipped rather than erroring.
    let repeated = EventId::generate();
    let doubled = repos
        .notifications
        .create_many(
            &[
                NewNotification { event_id: Some(repeated.clone()), ..batched(bob.id, "once") },
                NewNotification { event_id: Some(repeated), ..batched(bob.id, "twice") },
            ],
            t0() + hours(14),
        )
        .await
        .expect("a batch that repeats a recipient");
    assert_eq!(doubled.len(), 1, "one row per (recipient, event), even inside one statement");
    assert_eq!(doubled[0].title, "once");
}

/// `JobQueueRepo`: the durable work queue behind asynchronous fan-out and outbound mail
/// (decision 26).
///
/// Two assertions carry the weight, because they are the properties the drain worker relies on
/// without re-checking. **A claim is exclusive**: two drains racing over one backlog receive
/// disjoint sets, or one publish notifies everybody twice and one sign-in sends two codes.
/// **A suppressed row is a dead end**: nothing here — not `claim`, not `complete`, not the
/// lease reaper — can turn the row a policy-rejected address files into a deliverable message
/// (S-04.a, S-31). The rest of the walk is the retry ladder: backoff, lease expiry, the dead
/// letter, and the retention that keeps this table from becoming the next one that grows
/// forever.
pub async fn job_queue(repos: &Repositories) {
    repos.queue.ping().await.expect("ping");
    let lease = Duration::from_secs(60);
    let backoff = Duration::from_secs(30);
    // One cutoff per terminal state (decision 26); `at` moves all three together for the walk below.
    let retention_at = |instant: DateTime<Utc>| QueueRetention {
        done_before: instant,
        suppressed_before: instant,
        dead_before: instant,
    };

    // An empty queue answers every question without a special case.
    assert!(repos.queue.depth().await.expect("depth").is_empty());
    assert!(repos.queue.claim(&JobKind::ALL, 10, lease, t0()).await.expect("claim").is_empty());
    assert_eq!(repos.queue.reap_expired_leases(t0()).await.expect("reap"), 0);
    assert_eq!(repos.queue.purge(&retention_at(t0()), PURGE_BATCH).await.expect("purge"), QueuePurged::default());
    assert_eq!(repos.queue.get(QueuedJobId::new()).await.expect("get unknown"), None);

    // Enqueue: the stored row is the item plus the defaults the caller did not state.
    let mail = repos
        .queue
        .enqueue(&NewQueuedJob::pending(MailJob::KIND, mail_payload("alice@corp.com")), t0())
        .await
        .expect("enqueue")
        .expect("a fresh item is stored");
    assert_eq!(mail.kind, JobKind::MailSend);
    assert_eq!(mail.state, QueueState::Pending);
    assert_eq!(mail.priority, NewQueuedJob::INTERACTIVE, "the default is the priority a person waits at");
    assert_eq!(mail.attempts, 0);
    assert_eq!(mail.run_after, t0(), "no delay means runnable now");
    assert_eq!(mail.locked_until, None);
    assert_eq!(mail.dedupe_key, None);
    assert_eq!(mail.last_error, None);
    assert_eq!(mail.created_at, t0());
    assert_eq!(mail.updated_at, t0());
    assert_eq!(mail.payload["to"], "alice@corp.com", "the payload round-trips verbatim");
    assert_eq!(repos.queue.get(mail.id).await.expect("get"), Some(mail.clone()));

    // A dedupe key makes a retried enqueue a no-op rather than a second copy of the work.
    let fanout = NewQueuedJob::pending(JobKind::NotificationFanout, serde_json::json!({ "envelope": "opaque" }))
        .with_dedupe_key("fanout:01K0000000000000000000000A");
    let queued = repos.queue.enqueue(&fanout, t0()).await.expect("enqueue").expect("the first wins");
    assert_eq!(queued.dedupe_key.as_deref(), Some("fanout:01K0000000000000000000000A"));
    assert!(
        repos.queue.enqueue(&fanout, t0() + minutes(1)).await.expect("re-enqueue").is_none(),
        "a second enqueue under one key is a no-op"
    );
    assert_eq!(queue_depth(repos, JobKind::NotificationFanout, QueueState::Pending).await, 1);

    // Only the two states the request path decides between may be filed.
    let mut illegal = NewQueuedJob::pending(MailJob::KIND, mail_payload("nobody@corp.com"));
    illegal.state = QueueState::Done;
    assert_eq!(
        repos.queue.enqueue(&illegal, t0()).await.expect_err("done is not an enqueueable state").code(),
        "invalid_argument"
    );

    // A claim leases exactly once, and only the kinds it asked for.
    let claimed = repos.queue.claim(&[JobKind::MailSend], 10, lease, t0()).await.expect("claim");
    assert_eq!(claimed.iter().map(|job| job.id).collect::<Vec<_>>(), vec![mail.id], "the fan-out row is another kind");
    assert_eq!(claimed[0].state, QueueState::Running);
    assert_eq!(claimed[0].attempts, 1, "the attempt is spent when the lease is taken");
    assert_eq!(claimed[0].locked_until, Some(t0() + seconds(60)));
    assert!(
        repos.queue.claim(&[JobKind::MailSend], 10, lease, t0()).await.expect("second claim").is_empty(),
        "a leased item is nobody else's until its lease runs out"
    );

    // Degenerate requests are an empty batch, not an empty query.
    assert!(repos.queue.claim(&[], 10, lease, t0()).await.expect("no kinds").is_empty());
    assert!(repos.queue.claim(&JobKind::ALL, 0, lease, t0()).await.expect("no room").is_empty());

    // A retry re-arms run_after, records why, and does not refund the attempt.
    repos
        .queue
        .complete(mail.id, QueueOutcome::Retry("smtp unreachable".to_owned()), backoff, t0() + seconds(5))
        .await
        .expect("retry");
    let stored = repos.queue.get(mail.id).await.expect("get").expect("row");
    assert_eq!(stored.state, QueueState::Pending);
    assert_eq!(stored.run_after, t0() + seconds(35), "now + backoff, measured from the completion");
    assert_eq!(stored.last_error.as_deref(), Some("smtp unreachable"));
    assert_eq!(stored.locked_until, None);
    assert_eq!(stored.attempts, 1);
    assert!(
        repos.queue.claim(&[JobKind::MailSend], 10, lease, t0() + seconds(34)).await.expect("early").is_empty(),
        "backoff is a floor, not a hint"
    );
    let claimed = repos.queue.claim(&[JobKind::MailSend], 10, lease, t0() + seconds(35)).await.expect("claim");
    assert_eq!(claimed[0].attempts, 2);
    assert_eq!(claimed[0].locked_until, Some(t0() + seconds(95)));

    // A worker that died mid-run: the lease expires, the item comes back, the attempt stays spent.
    assert_eq!(
        repos.queue.reap_expired_leases(t0() + seconds(94)).await.expect("reap early"),
        0,
        "a live lease is not an expired one"
    );
    assert_eq!(repos.queue.reap_expired_leases(t0() + seconds(95)).await.expect("reap"), 1);
    let stored = repos.queue.get(mail.id).await.expect("get").expect("row");
    assert_eq!(stored.state, QueueState::Pending);
    assert_eq!(stored.locked_until, None);
    assert_eq!(stored.attempts, 2, "refunding it is how an item that kills its worker retries forever");

    // The worker gives up — the attempt budget is its policy, never the repository's. From here
    // the dead letter is final, and it is the operator's record of mail that never arrived.
    let claimed = repos.queue.claim(&[JobKind::MailSend], 10, lease, t0() + minutes(2)).await.expect("claim");
    assert_eq!(claimed[0].attempts, 3);
    repos
        .queue
        .complete(mail.id, QueueOutcome::Dead("mailbox does not exist".to_owned()), backoff, t0() + minutes(3))
        .await
        .expect("dead letter");
    let dead = repos.queue.get(mail.id).await.expect("get").expect("row");
    assert_eq!(dead.state, QueueState::Dead);
    assert_eq!(dead.last_error.as_deref(), Some("mailbox does not exist"));
    assert_eq!(dead.locked_until, None);

    // S-04.a / S-31: a policy-rejected address files a row so both branches of the request cost
    // the same. It must never become a deliverable message.
    let suppressed = repos
        .queue
        .enqueue(&NewQueuedJob::suppressed(MailJob::KIND, mail_payload("blocked@evil.test")), t0() + minutes(5))
        .await
        .expect("enqueue")
        .expect("stored");
    assert_eq!(suppressed.state, QueueState::Suppressed);
    let claimed = repos.queue.claim(&JobKind::ALL, 10, lease, t0() + days(1)).await.expect("claim");
    assert_eq!(
        claimed.iter().map(|job| job.id).collect::<Vec<_>>(),
        vec![queued.id],
        "neither the dead letter nor the suppressed row is claimable, whatever the clock says"
    );
    repos
        .queue
        .complete(suppressed.id, QueueOutcome::Retry("deliver me".to_owned()), backoff, t0() + days(1))
        .await
        .expect("complete");
    assert_eq!(
        repos.queue.get(suppressed.id).await.expect("get"),
        Some(suppressed.clone()),
        "a completion for a row nobody leased leaves it exactly as it was"
    );
    repos
        .queue
        .complete(mail.id, QueueOutcome::Retry("too late".to_owned()), backoff, t0() + days(1))
        .await
        .expect("complete");
    assert_eq!(
        repos.queue.get(mail.id).await.expect("get").expect("row").state,
        QueueState::Dead,
        "and a dead letter cannot be resurrected by a worker whose lease was already reaped"
    );
    repos.queue.complete(QueuedJobId::new(), QueueOutcome::Done, backoff, t0()).await.expect("unknown id");

    // A success clears the failure the admin surface was showing.
    repos
        .queue
        .complete(queued.id, QueueOutcome::Retry("boom".to_owned()), backoff, t0() + days(1))
        .await
        .expect("retry");
    let claimed = repos.queue.claim(&[JobKind::NotificationFanout], 10, lease, t0() + days(2)).await.expect("claim");
    assert_eq!(claimed[0].last_error.as_deref(), Some("boom"), "the failure survives while the item is retried");
    repos.queue.complete(queued.id, QueueOutcome::Done, backoff, t0() + days(2)).await.expect("done");
    let done = repos.queue.get(queued.id).await.expect("get").expect("row");
    assert_eq!(done.state, QueueState::Done);
    assert_eq!(done.last_error, None);
    assert_eq!(done.updated_at, t0() + days(2));

    // Retention: every terminal state has its own cutoff, and a state whose cutoff has not
    // arrived is untouched by a pass that deletes another one (decision 26 — before this, `done` was
    // the only state with a bound and the other two grew forever).
    let at_the_bound = QueueRetention { done_before: t0() + days(2), suppressed_before: t0(), dead_before: t0() };
    assert_eq!(
        repos.queue.purge(&at_the_bound, PURGE_BATCH).await.expect("purge"),
        QueuePurged::default(),
        "the bound is strict: a row written at it is not older than it"
    );
    let done_only = QueueRetention { done_before: t0() + days(3), suppressed_before: t0(), dead_before: t0() };
    assert_eq!(
        repos.queue.purge(&done_only, PURGE_BATCH).await.expect("purge"),
        QueuePurged { done: 1, suppressed: 0, dead: 0 },
        "one state's cutoff is not another's"
    );
    assert_eq!(repos.queue.get(queued.id).await.expect("get"), None);
    assert_eq!(repos.queue.get(dead.id).await.expect("get").expect("row").state, QueueState::Dead);
    assert_eq!(repos.queue.get(suppressed.id).await.expect("get").expect("row").state, QueueState::Suppressed);

    // The suppressed row goes when *its* window closes: it is filed by an unauthenticated
    // endpoint, one per policy-rejected sign-in attempt, and carries the attempted address in
    // the clear with nothing left to read it (S-04.a/S-31).
    let suppressed_only = QueueRetention { done_before: t0(), suppressed_before: t0() + days(3), dead_before: t0() };
    assert_eq!(
        repos.queue.purge(&suppressed_only, PURGE_BATCH).await.expect("purge"),
        QueuePurged { done: 0, suppressed: 1, dead: 0 }
    );
    assert_eq!(repos.queue.get(suppressed.id).await.expect("get"), None);
    assert_eq!(
        repos.queue.get(dead.id).await.expect("get").expect("row").state,
        QueueState::Dead,
        "the operator's record outlives both of them"
    );

    // And the dead letter goes last, at a window measured in weeks rather than hours.
    assert_eq!(
        repos.queue.purge(&retention_at(t0() + days(365)), PURGE_BATCH).await.expect("purge"),
        QueuePurged { done: 0, suppressed: 0, dead: 1 }
    );
    assert_eq!(repos.queue.get(dead.id).await.expect("get"), None);

    // Depth is what the admin job table and the metrics gauge read, and retention has just
    // emptied every terminal state.
    assert!(repos.queue.depth().await.expect("depth").is_empty());

    // Priority is claimed ahead of arrival (decision 26's amendment). The bulk rows below are
    // filed *first* and are still claimed last: this is the whole point — a CI pipeline
    // publishing into a large org files thousands of broadcast messages, and the sign-in code
    // requested a minute later must not wait behind them, because it expires in ten.
    let fair = t0() + days(300);
    let mut bulk = Vec::new();
    for index in 0..3 {
        let job = NewQueuedJob::bulk(MailJob::KIND, mail_payload(&format!("member{index}@corp.com")));
        bulk.push(repos.queue.enqueue(&job, fair).await.expect("enqueue").expect("stored").id);
    }
    let interactive = repos
        .queue
        .enqueue(&NewQueuedJob::pending(MailJob::KIND, mail_payload("late@corp.com")), fair + minutes(1))
        .await
        .expect("enqueue")
        .expect("stored");
    assert_eq!(interactive.priority, NewQueuedJob::INTERACTIVE);
    assert_eq!(repos.queue.get(bulk[0]).await.expect("get").expect("row").priority, NewQueuedJob::BULK);
    let claimed = repos.queue.claim(&[JobKind::MailSend], 10, lease, fair + minutes(2)).await.expect("claim");
    assert_eq!(
        claimed.iter().map(|job| job.id).collect::<Vec<_>>(),
        std::iter::once(interactive.id).chain(bulk.iter().copied()).collect::<Vec<_>>(),
        "the newest interactive row precedes every older bulk row, and bulk stays in arrival order"
    );
    for job in &claimed {
        repos.queue.complete(job.id, QueueOutcome::Done, backoff, fair + minutes(2)).await.expect("done");
    }
    assert_eq!(
        repos.queue.purge(&retention_at(fair + days(2)), PURGE_BATCH).await.expect("purge"),
        QueuePurged { done: 4, suppressed: 0, dead: 0 }
    );

    // A lane the claim does not drain is refused at the enqueue. The claim seeks `priority = ?`
    // one lane at a time — the only shape in which `run_after` stays a seek bound instead of a
    // post-filter over the whole pending partition — so a row filed between the lanes would sit
    // in the table forever, claimed by nobody and visible only as a depth gauge that never
    // falls. Filing it has to fail loudly instead.
    let off_lane = NewQueuedJob {
        priority: NewQueuedJob::BULK - 1,
        ..NewQueuedJob::pending(MailJob::KIND, mail_payload("nobody@corp.com"))
    };
    let refused = repos.queue.enqueue(&off_lane, fair).await.expect_err("a lane nothing drains must be refused");
    assert_eq!(refused.code(), "invalid_argument");
    assert!(repos.queue.depth().await.expect("depth").is_empty(), "and nothing was written");

    // Inside a lane the order is *how long an item has been runnable*, not how long ago it was
    // filed: `run_after` before the id. The two coincide for a row that never failed — its
    // `run_after` is its enqueue instant — and differ for a retried one, which is the point. An
    // item that has failed six times and just came off its hour-long backoff must not cut in
    // front of everything filed while it was waiting; ordering by id would put it first forever.
    let ladder = t0() + days(320);
    let retried = repos
        .queue
        .enqueue(
            &NewQueuedJob::pending(MailJob::KIND, mail_payload("retried@corp.com")).with_run_after(ladder + minutes(5)),
            ladder,
        )
        .await
        .expect("enqueue")
        .expect("stored");
    let fresh = repos
        .queue
        .enqueue(&NewQueuedJob::pending(MailJob::KIND, mail_payload("fresh@corp.com")), ladder + minutes(1))
        .await
        .expect("enqueue")
        .expect("stored");
    assert!(retried.id < fresh.id, "the backed-off row is the older one by arrival");
    // One at a time, because a batch large enough to hold both would prove nothing about the
    // statement's own `ORDER BY … LIMIT`: what has to be true is that the *first* row the
    // engine hands back is the one that became runnable first.
    let mut order = Vec::new();
    for _ in 0..2 {
        let claimed = repos.queue.claim(&[JobKind::MailSend], 1, lease, ladder + minutes(6)).await.expect("claim");
        assert_eq!(claimed.len(), 1);
        repos.queue.complete(claimed[0].id, QueueOutcome::Done, backoff, ladder + minutes(6)).await.expect("done");
        order.push(claimed[0].id);
    }
    assert_eq!(order, vec![fresh.id, retried.id], "the row that became runnable first is claimed first");
    assert_eq!(
        repos.queue.purge(&retention_at(ladder + days(2)), PURGE_BATCH).await.expect("purge"),
        QueuePurged { done: 2, suppressed: 0, dead: 0 }
    );

    // Two drains racing over one backlog. On Postgres this is the `FOR UPDATE SKIP LOCKED`
    // path; on SQLite it is the single writer. Either way the sets must be disjoint.
    let racing = t0() + days(400);
    let mut filed = Vec::new();
    for index in 0..6 {
        let job = NewQueuedJob::pending(MailJob::KIND, mail_payload(&format!("racer{index}@corp.com")));
        filed.push(repos.queue.enqueue(&job, racing).await.expect("enqueue").expect("stored").id);
    }
    let (left, right) = interleave(
        repos.queue.claim(&[JobKind::MailSend], 3, lease, racing),
        repos.queue.claim(&[JobKind::MailSend], 3, lease, racing),
    )
    .await;
    let mut taken: Vec<QueuedJobId> =
        left.expect("left claim").into_iter().chain(right.expect("right claim")).map(|job| job.id).collect();
    assert_eq!(taken.len(), 6, "between them the two drains leased the whole backlog");
    taken.sort_unstable();
    taken.dedup();
    filed.sort_unstable();
    assert_eq!(taken, filed, "and no item was leased twice");
}

/// S-23 retention across every table that has a window (decision 30).
///
/// The properties worth a cross-dialect contract are the ones a single-backend test cannot see:
/// the batch bound is real SQL in both dialects, the invitation predicate is an indexed `COALESCE`
/// expression, the download-stats key is composite so its bound is a row value, and the audit floor
/// is enforced in Rust on SQLite and *again* inside `pub_audit_prune` on Postgres — where the app
/// role may execute the function and does not hold the `DELETE` it performs (S-22.a).
pub async fn retention(repos: &Repositories) {
    let user = repos
        .users
        .create(
            NewUser { email: Some("root@corp.com".into()), email_verified: true, display_name: "Root".into() },
            t0(),
        )
        .await
        .expect("user");
    let org = repos.orgs.create(NewOrg::new("Acme", "acme"), user.id, t0()).await.expect("org");

    // --- sessions: aged from `last_seen_at`, which is what makes the predicate safe ---
    let stale = repos
        .sessions
        .create(
            NewSession {
                user_id: user.id,
                refresh_hash: "a".repeat(64),
                user_agent: Some("cli".into()),
                ip: Some("203.0.113.9".into()),
            },
            t0() - days(40),
        )
        .await
        .expect("stale session");
    let live = repos
        .sessions
        .create(
            NewSession {
                user_id: user.id,
                refresh_hash: "b".repeat(64),
                user_agent: Some("cli".into()),
                ip: Some("203.0.113.9".into()),
            },
            t0() - days(2),
        )
        .await
        .expect("live session");
    // A third session created LONG ago and used recently. This is what makes the test discriminate
    // between the two candidate anchors: `create` writes the same stamp to `created_at` and
    // `last_seen_at`, so a fixture built only from `create` cannot tell them apart, and a predicate
    // silently moved to `created_at` would pass. This row must survive — deleting it is a silent
    // sign-out of exactly the long-lived sessions the window is supposed to keep.
    let long_lived = repos
        .sessions
        .create(
            NewSession {
                user_id: user.id,
                refresh_hash: "f".repeat(64),
                user_agent: Some("cli".into()),
                ip: Some("203.0.113.9".into()),
            },
            t0() - days(80),
        )
        .await
        .expect("long-lived session");
    assert!(
        repos.sessions.touch(long_lived.id, Duration::from_secs(1), t0() - days(1)).await.expect("touch"),
        "the fixture only discriminates if the activity bump actually wrote"
    );

    assert_eq!(repos.sessions.purge_before(t0() - days(30), PURGE_BATCH).await.expect("purge"), 1);
    let remaining = repos.sessions.list_for_user(user.id).await.expect("list");
    assert_eq!(remaining.len(), 2, "a session that can still authenticate is never retention's");
    assert!(remaining.iter().any(|session| session.id == live.id));
    assert!(
        remaining.iter().any(|session| session.id == long_lived.id),
        "a session created 80 days ago and used yesterday must survive a 30-day window: the anchor \
         is `last_seen_at`, not `created_at`"
    );
    assert!(remaining.iter().all(|session| session.id != stale.id));
    // The bound is strict on both dialects: a row written exactly at the cutoff is not older.
    assert_eq!(repos.sessions.purge_before(t0() - days(2), PURGE_BATCH).await.expect("purge"), 0);

    // And the batch bound is real SQL here too, not only on the notification path. Two more stale
    // rows, deleted one statement at a time.
    for (index, hash) in [(0u8, "1"), (1, "2")] {
        repos
            .sessions
            .create(
                NewSession {
                    user_id: user.id,
                    refresh_hash: hash.repeat(64),
                    user_agent: Some("cli".into()),
                    ip: Some("203.0.113.9".into()),
                },
                t0() - days(50 + i64::from(index)),
            )
            .await
            .expect("stale session");
    }
    assert_eq!(repos.sessions.purge_before(t0() - days(30), 1).await.expect("purge"), 1, "one row per statement");
    assert_eq!(repos.sessions.purge_before(t0() - days(30), 1).await.expect("purge"), 1);
    assert_eq!(repos.sessions.purge_before(t0() - days(30), 1).await.expect("purge"), 0);

    // --- invitations: aged from whenever they settled, never from creation ---
    for (email, hash, expires) in
        [("live@corp.com", "c".repeat(64), t0() + days(5)), ("expired@corp.com", "d".repeat(64), t0() - days(40))]
    {
        repos
            .orgs
            .create_invitation(
                NewInvitation {
                    org_id: org.id,
                    email: email.into(),
                    role: RoleLevel::READ,
                    invited_by: user.id,
                    token_hash: hash,
                    expires_at: expires,
                },
                expires - days(7),
            )
            .await
            .expect("invitation");
    }
    // A one-day window — shorter than the seven-day invitation TTL — and the live link survives it
    // anyway. That property comes from the predicate, not from a validator keeping the window long.
    assert_eq!(repos.orgs.purge_invitations_before(t0() - days(1), PURGE_BATCH).await.expect("purge"), 1);
    let pending = repos.orgs.list_invitations(org.id).await.expect("list");
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].email, "live@corp.com");

    // The batch bound, on the one predicate that is an indexed expression rather than a column.
    for (index, hash) in [(0u8, "5"), (1, "6")] {
        repos
            .orgs
            .create_invitation(
                NewInvitation {
                    org_id: org.id,
                    email: format!("expired{index}@corp.com"),
                    role: RoleLevel::READ,
                    invited_by: user.id,
                    token_hash: hash.repeat(64),
                    expires_at: t0() - days(40 + i64::from(index)),
                },
                t0() - days(50),
            )
            .await
            .expect("invitation");
    }
    assert_eq!(repos.orgs.purge_invitations_before(t0() - days(1), 1).await.expect("purge"), 1);
    assert_eq!(repos.orgs.purge_invitations_before(t0() - days(1), 1).await.expect("purge"), 1);
    assert_eq!(repos.orgs.purge_invitations_before(t0() - days(1), 1).await.expect("purge"), 0);

    // --- notifications: by age, across accounts, read state irrelevant ---
    let mut written = Vec::new();
    for (index, at) in [t0() - days(200), t0() - days(200), t0() - days(10)].into_iter().enumerate() {
        let rows = repos
            .notifications
            .create_many(
                &[NewNotification {
                    user_id: user.id,
                    category: NotificationCategory::Package,
                    event_id: None,
                    event: "package.published".into(),
                    title: format!("row {index}"),
                    org_id: Some(org.id),
                    payload: serde_json::json!({}),
                }],
                at,
            )
            .await
            .expect("notification");
        written.push(rows[0].id);
    }
    repos.notifications.mark_read(user.id, &written[..1], t0()).await.expect("mark read");
    assert_eq!(repos.notifications.purge_before(t0() - days(180), PURGE_BATCH).await.expect("purge"), 2);
    let feed = repos.notifications.list(user.id, false, None, 50).await.expect("feed");
    assert_eq!(feed.items.len(), 1, "one read and one unread row of the same age both went");
    assert_eq!(feed.items[0].id, written[2]);

    // --- the batch bound is real SQL, not a parameter the backends accept and ignore ---
    for index in 0..5 {
        repos
            .notifications
            .create_many(
                &[NewNotification {
                    user_id: user.id,
                    category: NotificationCategory::Package,
                    event_id: None,
                    event: "package.published".into(),
                    title: format!("backlog {index}"),
                    org_id: Some(org.id),
                    payload: serde_json::json!({}),
                }],
                t0() - days(300),
            )
            .await
            .expect("notification");
    }
    assert_eq!(
        repos.notifications.purge_before(t0() - days(180), 2).await.expect("purge"),
        2,
        "an ignored bound would return 5 here, and the caller's convergence loop would be deleting \
         a released backlog in one write-lock hold — which is the whole of D47"
    );
    assert_eq!(repos.notifications.purge_before(t0() - days(180), 2).await.expect("purge"), 2);
    assert_eq!(repos.notifications.purge_before(t0() - days(180), 2).await.expect("purge"), 1, "the short pass");
    assert_eq!(repos.notifications.purge_before(t0() - days(180), 2).await.expect("purge"), 0);

    // --- download stats: a composite key, so the bound is a row value ---
    let package = repos
        .packages
        .create_package(
            NewPackage {
                format: Format::Pub,
                name: "acme_core".into(),
                org_id: org.id,
                visibility: Visibility::Public,
            },
            t0(),
        )
        .await
        .expect("package");
    let version = repos
        .packages
        .create_version(
            NewVersion {
                format: Format::Pub,
                package_name: "acme_core".into(),
                org_id: org.id,
                visibility: Visibility::Public,
                version: SemVer::parse("1.0.0").expect("semver"),
                pubspec: serde_json::json!({ "name": "acme_core", "version": "1.0.0" }),
                archive_sha256: "e".repeat(64),
                archive_size: 10,
                published_by: Publisher { user_id: user.id, token_id: None },
                readme_html: None,
                changelog_html: None,
            },
            t0(),
        )
        .await
        .expect("version");
    for day in 1..=3 {
        repos
            .stats
            .add_downloads(&[DownloadDelta {
                package_id: package.id,
                version_id: version.version.id,
                date: (t0() - days(day)).date_naive(),
                count: 1,
            }])
            .await
            .expect("downloads");
    }
    assert_eq!(repos.stats.purge_before((t0() - days(2)).date_naive(), PURGE_BATCH).await.expect("purge"), 1);
    assert_eq!(
        repos.stats.package_totals(package.id, (t0() - days(30)).date_naive()).await.expect("totals").total,
        2,
        "only the row dated before the cutoff went"
    );
    // The batch bound on a row-value `IN` — the shape this table needs because its key is composite
    // — is worth its own assertion: a backend that accepted the parameter and ignored it would take
    // both remaining rows in one statement.
    assert_eq!(repos.stats.purge_before((t0() + days(1)).date_naive(), 1).await.expect("purge"), 1);
    assert_eq!(repos.stats.purge_before((t0() + days(1)).date_naive(), 1).await.expect("purge"), 1);
    assert_eq!(repos.stats.purge_before((t0() + days(1)).date_naive(), 1).await.expect("purge"), 0);

    // --- the queue's own batch bound, on the table D47 was filed about ---
    //
    // Every other queue scenario in this suite has one row per terminal state, so a `LIMIT` the
    // backend accepted and ignored would be invisible there — and an ignored LIMIT is exactly D47
    // reinstated: one unbounded DELETE per state, holding SQLite's single writer for its full scan.
    for index in 0..3 {
        repos
            .queue
            .enqueue(
                &NewQueuedJob::suppressed(JobKind::MailSend, mail_payload(&format!("blocked{index}@evil.test"))),
                t0() - days(2),
            )
            .await
            .expect("enqueue")
            .expect("row");
    }
    let released = QueueRetention { done_before: t0(), suppressed_before: t0(), dead_before: t0() };
    assert_eq!(
        repos.queue.purge(&released, 2).await.expect("purge"),
        QueuePurged { done: 0, suppressed: 2, dead: 0 },
        "a bound the backend ignored would take all three in one statement"
    );
    assert_eq!(repos.queue.purge(&released, 2).await.expect("purge"), QueuePurged { done: 0, suppressed: 1, dead: 0 });
    assert_eq!(repos.queue.purge(&released, 2).await.expect("purge"), QueuePurged::default());

    // --- audit: the floor is enforced below the caller, on both dialects ---
    //
    // Real wall-clock time here, not `t0()`: the Postgres function compares the cutoff against the
    // database's own `now()`, so a scenario pinned to a fixture instant would be asserting against
    // two different clocks.
    for index in 0..3 {
        repos
            .audit
            .append(
                NewAuditEvent {
                    actor: AuditActor::System,
                    ip: None,
                    user_agent: None,
                    org_id: Some(org.id),
                    action: format!("test.event.{index}"),
                    target: None,
                    result: AuditResult::Success,
                    metadata: None,
                },
                Utc::now() - days(400),
            )
            .await
            .expect("audit row");
    }
    let now = Utc::now();
    let err = repos
        .audit
        .prune_before(now - days(29), now, PURGE_BATCH)
        .await
        .expect_err("a cutoff inside the 30-day floor must be refused, not clamped");
    assert_eq!(err.code(), "invalid_argument");
    assert_eq!(
        repos.audit.list(&AuditFilter::default(), None, 50).await.expect("list").items.len(),
        3,
        "a refused prune deletes nothing"
    );
    // Outside the floor it works, and it honours its batch.
    assert_eq!(repos.audit.prune_before(now - days(31), now, 2).await.expect("prune"), 2);
    assert_eq!(repos.audit.prune_before(now - days(31), now, 2).await.expect("prune"), 1);
    assert_eq!(repos.audit.prune_before(now - days(31), now, 2).await.expect("prune"), 0);
    assert!(repos.audit.list(&AuditFilter::default(), None, 50).await.expect("list").items.is_empty());
}

/// The `mail.send` payload, as the OTP path would file it (sealed — see S-26.b).
fn mail_payload(to: &str) -> serde_json::Value {
    serde_json::to_value(MailJob {
        to: to.to_owned(),
        subject: "Your sign-in code".to_owned(),
        text: "c2VhbGVk".to_owned(),
        html: None,
        sealed: true,
    })
    .expect("encode mail job")
}

/// How many items sit in one `(kind, state)` cell; absent cells read as zero.
async fn queue_depth(repos: &Repositories, kind: JobKind, state: QueueState) -> i64 {
    repos
        .queue
        .depth()
        .await
        .expect("depth")
        .into_iter()
        .find(|(row_kind, row_state, _)| *row_kind == kind && *row_state == state)
        .map_or(0, |(_, _, count)| count)
}

/// Polls two repository calls against each other on one task.
///
/// This crate has no async runtime among its dependencies — it is a library the backends' test
/// binaries drive — so there is no `join!` to reach for. It is worth the hand-rolled poll
/// because a claim exercised only sequentially proves nothing about exclusivity, which is the
/// one queue property the drain worker relies on without re-checking.
async fn interleave<T>(left: impl Future<Output = T>, right: impl Future<Output = T>) -> (T, T) {
    let mut left = Box::pin(left);
    let mut right = Box::pin(right);
    let mut left_done: Option<T> = None;
    let mut right_done: Option<T> = None;
    std::future::poll_fn(move |cx| {
        if left_done.is_none()
            && let Poll::Ready(value) = left.as_mut().poll(cx)
        {
            left_done = Some(value);
        }
        if right_done.is_none()
            && let Poll::Ready(value) = right.as_mut().poll(cx)
        {
            right_done = Some(value);
        }
        match (left_done.take(), right_done.take()) {
            (Some(left), Some(right)) => Poll::Ready((left, right)),
            (left, right) => {
                left_done = left;
                right_done = right;
                Poll::Pending
            }
        }
    })
    .await
}
