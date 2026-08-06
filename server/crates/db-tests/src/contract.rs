//! The contract functions. Each takes a freshly migrated, empty database and exercises one
//! repository trait end to end, corner cases included. Panics (assert) on violation — the
//! caller wraps each function in its own test.

use std::collections::BTreeMap;
use std::time::Duration;

use chrono::{DateTime, TimeZone as _, Utc};
use pub_core::audit::{AuditActor, AuditFilter, AuditResult, NewAuditEvent};
use pub_core::authorize::ActorContext;
use pub_core::credential::CredentialType;
use pub_core::org::{NewInvitation, NewOrg};
use pub_core::package::{BaseScope, NewPackage, NewVersion, PackageOptions, Publisher, Resolution, Visibility};
use pub_core::session::{NewSession, SessionLimits};
use pub_core::token::{NewToken, TokenScope};
use pub_core::traits::Repositories;
use pub_core::user::{NewUser, UserStatus};
use pub_core::{Format, OrgId, RoleLevel, SemVer, UserId};

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
    repos.orgs.create(NewOrg { name: slug.to_uppercase(), slug: slug.to_owned() }, owner, t0()).await.expect("seed org")
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
    let err = repos
        .orgs
        .create(NewOrg { name: "Acme 2".to_owned(), slug: "AcMe".to_owned() }, alice.id, t0())
        .await
        .expect_err("duplicate slug");
    assert_eq!(err.code(), "conflict");

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

/// `TokenRepo`: active-by-hash semantics (expiry, revocation), throttled usage tracking,
/// listings.
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

    // Blob reference counting: two versions may share one content hash.
    let shared = published.version.archive_sha256.clone();
    assert_eq!(repos.packages.count_versions_with_sha256(&shared).await.expect("count"), 1);
    let mut twin = new_version(org.id, "acme_twin", "1.0.0", alice.id);
    twin.archive_sha256 = shared.clone();
    repos.packages.create_version(twin, t0() + hours(3)).await.expect("twin publish");
    assert_eq!(repos.packages.count_versions_with_sha256(&shared).await.expect("count"), 2);
    assert_eq!(repos.packages.count_versions_with_sha256(&"0".repeat(64)).await.expect("count"), 0);

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
