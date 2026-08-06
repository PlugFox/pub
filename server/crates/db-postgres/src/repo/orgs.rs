//! `OrgRepo` over Postgres: orgs, memberships (≥1-Owner invariant), invitations.
//!
//! Postgres runs writers concurrently, so every invariant-guarded read-then-write sequence
//! locks its serialization anchor first: [`lock_org`] takes `FOR UPDATE` on the org row before
//! owner counting or membership writes, and invitation acceptance locks the invitation row so
//! single-use consumption cannot race itself.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use pub_core::org::{Invitation, NewInvitation, NewOrg, Org, OrgMember, OrgMembership};
use pub_core::traits::OrgRepo;
use pub_core::{Error, InvitationId, OrgId, Result, RoleLevel, UserId};
use sqlx::postgres::PgRow;
use sqlx::{PgPool, Row as _};
use uuid::Uuid;

use super::{db_err, q, write_err};

/// All org columns, in [`OrgRow`] order.
const ORG_COLS: &str = "id, name, slug, created_at, updated_at";
/// All membership columns, in [`MemberRow`] order.
const MEMBER_COLS: &str = "org_id, user_id, role_level, created_at, updated_at";
/// All invitation columns, in [`InvitationRow`] order.
const INV_COLS: &str =
    "id, org_id, email, role_level, invited_by, created_at, expires_at, accepted_at, accepted_by, revoked_at";

/// Postgres-backed [`OrgRepo`].
#[derive(Debug, Clone)]
pub struct PgOrgRepo {
    pool: PgPool,
}

impl PgOrgRepo {
    /// Wraps a pool handle.
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[derive(sqlx::FromRow)]
struct OrgRow {
    id: Uuid,
    name: String,
    slug: String,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

impl From<OrgRow> for Org {
    fn from(row: OrgRow) -> Self {
        Org {
            id: OrgId::from_uuid(row.id),
            name: row.name,
            slug: row.slug,
            created_at: row.created_at,
            updated_at: row.updated_at,
        }
    }
}

#[derive(sqlx::FromRow)]
struct MemberRow {
    org_id: Uuid,
    user_id: Uuid,
    role_level: i16,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

impl TryFrom<MemberRow> for OrgMember {
    type Error = Error;

    fn try_from(row: MemberRow) -> Result<Self> {
        Ok(OrgMember {
            org_id: OrgId::from_uuid(row.org_id),
            user_id: UserId::from_uuid(row.user_id),
            role: role_from_i16(row.role_level)?,
            created_at: row.created_at,
            updated_at: row.updated_at,
        })
    }
}

#[derive(sqlx::FromRow)]
struct InvitationRow {
    id: Uuid,
    org_id: Uuid,
    email: String,
    role_level: i16,
    invited_by: Uuid,
    created_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
    accepted_at: Option<DateTime<Utc>>,
    accepted_by: Option<Uuid>,
    revoked_at: Option<DateTime<Utc>>,
}

impl TryFrom<InvitationRow> for Invitation {
    type Error = Error;

    fn try_from(row: InvitationRow) -> Result<Self> {
        Ok(Invitation {
            id: InvitationId::from_uuid(row.id),
            org_id: OrgId::from_uuid(row.org_id),
            email: row.email,
            role: role_from_i16(row.role_level)?,
            invited_by: UserId::from_uuid(row.invited_by),
            created_at: row.created_at,
            expires_at: row.expires_at,
            accepted_at: row.accepted_at,
            accepted_by: row.accepted_by.map(UserId::from_uuid),
            revoked_at: row.revoked_at,
        })
    }
}

fn role_from_i16(raw: i16) -> Result<RoleLevel> {
    u8::try_from(raw).map(RoleLevel::new).map_err(|_| Error::Database { message: format!("corrupt role level {raw}") })
}

/// Rejects the storage-invalid "not a member" level on write paths.
fn require_member_role(role: RoleLevel) -> Result<()> {
    if role == RoleLevel::NONE {
        return Err(Error::Invalid { message: "role level 0 means 'not a member'; remove the member instead".into() });
    }
    Ok(())
}

/// Locks the org row (`FOR UPDATE`) as the serialization anchor for owner-invariant checks
/// and membership writes; concurrent member mutations on the same org queue behind it.
/// Unknown org → `NotFound`.
async fn lock_org(tx: &mut sqlx::Transaction<'_, sqlx::Postgres>, org: OrgId) -> Result<()> {
    let row: Option<PgRow> = sqlx::query("SELECT id FROM orgs WHERE id = $1 FOR UPDATE")
        .bind(*org.as_uuid())
        .fetch_optional(&mut **tx)
        .await
        .map_err(db_err)?;
    row.map(|_| ()).ok_or_else(|| Error::NotFound { what: format!("org {org}") })
}

/// Counts Owners of `org` other than `except` (inside the caller's transaction, under the
/// org-row lock).
async fn other_owner_count(tx: &mut sqlx::Transaction<'_, sqlx::Postgres>, org: OrgId, except: UserId) -> Result<i64> {
    let row: PgRow =
        sqlx::query("SELECT COUNT(*) AS n FROM org_members WHERE org_id = $1 AND role_level >= $2 AND user_id <> $3")
            .bind(*org.as_uuid())
            .bind(i16::from(RoleLevel::OWNER.level()))
            .bind(*except.as_uuid())
            .fetch_one(&mut **tx)
            .await
            .map_err(db_err)?;
    Ok(row.get("n"))
}

#[async_trait]
impl OrgRepo for PgOrgRepo {
    async fn ping(&self) -> Result<()> {
        sqlx::query("SELECT 1").execute(&self.pool).await.map_err(db_err)?;
        Ok(())
    }

    async fn create(&self, new: NewOrg, creator: UserId, now: DateTime<Utc>) -> Result<Org> {
        let mut tx = self.pool.begin().await.map_err(db_err)?;
        let row: OrgRow = sqlx::query_as(q!(
            "INSERT INTO orgs (id, name, slug, created_at, updated_at) VALUES ($1, $2, $3, $4, $5) \
             RETURNING {ORG_COLS}"
        ))
        .bind(*OrgId::new().as_uuid())
        .bind(&new.name)
        .bind(&new.slug)
        .bind(now)
        .bind(now)
        .fetch_one(&mut *tx)
        .await
        .map_err(|err| write_err(err, "org slug already taken", "org"))?;

        // The creator becomes Owner in the same transaction — an org never exists ownerless.
        sqlx::query(
            "INSERT INTO org_members (org_id, user_id, role_level, created_at, updated_at) VALUES ($1, $2, $3, $4, $5)",
        )
        .bind(row.id)
        .bind(*creator.as_uuid())
        .bind(i16::from(RoleLevel::OWNER.level()))
        .bind(now)
        .bind(now)
        .execute(&mut *tx)
        .await
        .map_err(|err| write_err(err, "creator is already a member", "user"))?;

        tx.commit().await.map_err(db_err)?;
        Ok(row.into())
    }

    async fn get(&self, id: OrgId) -> Result<Option<Org>> {
        let row: Option<OrgRow> = sqlx::query_as(q!("SELECT {ORG_COLS} FROM orgs WHERE id = $1"))
            .bind(*id.as_uuid())
            .fetch_optional(&self.pool)
            .await
            .map_err(db_err)?;
        Ok(row.map(Into::into))
    }

    async fn get_by_slug(&self, slug: &str) -> Result<Option<Org>> {
        // Case-insensitive match, aligned with the lower() unique index.
        let row: Option<OrgRow> = sqlx::query_as(q!("SELECT {ORG_COLS} FROM orgs WHERE lower(slug) = lower($1)"))
            .bind(slug)
            .fetch_optional(&self.pool)
            .await
            .map_err(db_err)?;
        Ok(row.map(Into::into))
    }

    async fn list_for_user(&self, user: UserId) -> Result<Vec<OrgMembership>> {
        #[derive(sqlx::FromRow)]
        struct MembershipRow {
            #[sqlx(flatten)]
            org: OrgRow,
            role_level: i16,
        }

        let rows: Vec<MembershipRow> = sqlx::query_as(q!(
            "SELECT o.{}, m.role_level FROM orgs o \
             JOIN org_members m ON m.org_id = o.id WHERE m.user_id = $1 ORDER BY o.created_at, o.id",
            ORG_COLS.replace(", ", ", o.")
        ))
        .bind(*user.as_uuid())
        .fetch_all(&self.pool)
        .await
        .map_err(db_err)?;

        rows.into_iter()
            .map(|row| Ok(OrgMembership { org: row.org.into(), role: role_from_i16(row.role_level)? }))
            .collect()
    }

    async fn get_member(&self, org: OrgId, user: UserId) -> Result<Option<OrgMember>> {
        let row: Option<MemberRow> =
            sqlx::query_as(q!("SELECT {MEMBER_COLS} FROM org_members WHERE org_id = $1 AND user_id = $2"))
                .bind(*org.as_uuid())
                .bind(*user.as_uuid())
                .fetch_optional(&self.pool)
                .await
                .map_err(db_err)?;
        row.map(TryInto::try_into).transpose()
    }

    async fn add_member(&self, org: OrgId, user: UserId, role: RoleLevel, now: DateTime<Utc>) -> Result<OrgMember> {
        require_member_role(role)?;
        let row: MemberRow =
            sqlx::query_as(q!("INSERT INTO org_members (org_id, user_id, role_level, created_at, updated_at) \
             VALUES ($1, $2, $3, $4, $5) RETURNING {MEMBER_COLS}"))
            .bind(*org.as_uuid())
            .bind(*user.as_uuid())
            .bind(i16::from(role.level()))
            .bind(now)
            .bind(now)
            .fetch_one(&self.pool)
            .await
            .map_err(|err| write_err(err, "user is already a member of this org", "org or user"))?;
        row.try_into()
    }

    async fn update_member_role(
        &self,
        org: OrgId,
        user: UserId,
        role: RoleLevel,
        now: DateTime<Utc>,
    ) -> Result<OrgMember> {
        require_member_role(role)?;
        let mut tx = self.pool.begin().await.map_err(db_err)?;
        lock_org(&mut tx, org).await?;
        let current: Option<MemberRow> =
            sqlx::query_as(q!("SELECT {MEMBER_COLS} FROM org_members WHERE org_id = $1 AND user_id = $2"))
                .bind(*org.as_uuid())
                .bind(*user.as_uuid())
                .fetch_optional(&mut *tx)
                .await
                .map_err(db_err)?;
        let current = current.ok_or_else(|| Error::NotFound { what: format!("membership of {user} in org {org}") })?;

        let was_owner = role_from_i16(current.role_level)?.satisfies(RoleLevel::OWNER);
        if was_owner && !role.satisfies(RoleLevel::OWNER) && other_owner_count(&mut tx, org, user).await? == 0 {
            return Err(Error::LastOwner { org });
        }

        let row: MemberRow = sqlx::query_as(q!("UPDATE org_members SET role_level = $1, updated_at = $2 \
             WHERE org_id = $3 AND user_id = $4 RETURNING {MEMBER_COLS}"))
        .bind(i16::from(role.level()))
        .bind(now)
        .bind(*org.as_uuid())
        .bind(*user.as_uuid())
        .fetch_one(&mut *tx)
        .await
        .map_err(db_err)?;
        tx.commit().await.map_err(db_err)?;
        row.try_into()
    }

    async fn remove_member(&self, org: OrgId, user: UserId) -> Result<()> {
        let mut tx = self.pool.begin().await.map_err(db_err)?;
        lock_org(&mut tx, org).await?;
        let current: Option<MemberRow> =
            sqlx::query_as(q!("SELECT {MEMBER_COLS} FROM org_members WHERE org_id = $1 AND user_id = $2"))
                .bind(*org.as_uuid())
                .bind(*user.as_uuid())
                .fetch_optional(&mut *tx)
                .await
                .map_err(db_err)?;
        let current = current.ok_or_else(|| Error::NotFound { what: format!("membership of {user} in org {org}") })?;

        if role_from_i16(current.role_level)?.satisfies(RoleLevel::OWNER)
            && other_owner_count(&mut tx, org, user).await? == 0
        {
            return Err(Error::LastOwner { org });
        }

        sqlx::query("DELETE FROM org_members WHERE org_id = $1 AND user_id = $2")
            .bind(*org.as_uuid())
            .bind(*user.as_uuid())
            .execute(&mut *tx)
            .await
            .map_err(db_err)?;
        tx.commit().await.map_err(db_err)
    }

    async fn create_invitation(&self, new: NewInvitation, now: DateTime<Utc>) -> Result<Invitation> {
        require_member_role(new.role)?;
        let row: InvitationRow = sqlx::query_as(q!(
            "INSERT INTO invitations (id, org_id, email, role_level, token_hash, invited_by, created_at, expires_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING {INV_COLS}"
        ))
        .bind(*InvitationId::new().as_uuid())
        .bind(*new.org_id.as_uuid())
        .bind(&new.email)
        .bind(i16::from(new.role.level()))
        .bind(&new.token_hash)
        .bind(*new.invited_by.as_uuid())
        .bind(now)
        .bind(new.expires_at)
        .fetch_one(&self.pool)
        .await
        .map_err(|err| write_err(err, "invitation token hash already exists", "org or inviter"))?;
        row.try_into()
    }

    async fn find_invitation_by_token_hash(&self, token_hash: &str) -> Result<Option<Invitation>> {
        let row: Option<InvitationRow> = sqlx::query_as(q!("SELECT {INV_COLS} FROM invitations WHERE token_hash = $1"))
            .bind(token_hash)
            .fetch_optional(&self.pool)
            .await
            .map_err(db_err)?;
        row.map(TryInto::try_into).transpose()
    }

    async fn accept_invitation(&self, token_hash: &str, user: UserId, now: DateTime<Utc>) -> Result<Invitation> {
        let mut tx = self.pool.begin().await.map_err(db_err)?;
        // FOR UPDATE: single-use consumption must not race a concurrent accept of the same
        // invitation.
        let inv: Option<InvitationRow> =
            sqlx::query_as(q!("SELECT {INV_COLS} FROM invitations WHERE token_hash = $1 FOR UPDATE"))
                .bind(token_hash)
                .fetch_optional(&mut *tx)
                .await
                .map_err(db_err)?;
        let inv = inv.ok_or_else(|| Error::NotFound { what: "invitation".to_owned() })?;

        if inv.accepted_at.is_some() || inv.revoked_at.is_some() {
            return Err(Error::Conflict { message: "invitation already accepted or revoked".to_owned() });
        }
        if inv.expires_at <= now {
            return Err(Error::Expired { what: "invitation".to_owned() });
        }

        // Email binding: only a user holding the invited email, verified, may accept.
        let user_row: Option<PgRow> = sqlx::query("SELECT email, email_verified FROM users WHERE id = $1")
            .bind(*user.as_uuid())
            .fetch_optional(&mut *tx)
            .await
            .map_err(db_err)?;
        let user_row = user_row.ok_or_else(|| Error::NotFound { what: format!("user {user}") })?;
        let user_email: Option<String> = user_row.get("email");
        let email_verified: bool = user_row.get("email_verified");
        let email_matches =
            user_email.as_deref().is_some_and(|email| email.eq_ignore_ascii_case(&inv.email)) && email_verified;
        if !email_matches {
            return Err(Error::Forbidden { message: "invitation is bound to a different verified email".to_owned() });
        }

        // Membership: create, or raise to the invited role — an invitation never lowers.
        // The org-row lock serializes this read-then-write against other member mutations.
        lock_org(&mut tx, OrgId::from_uuid(inv.org_id)).await?;
        let existing: Option<MemberRow> =
            sqlx::query_as(q!("SELECT {MEMBER_COLS} FROM org_members WHERE org_id = $1 AND user_id = $2"))
                .bind(inv.org_id)
                .bind(*user.as_uuid())
                .fetch_optional(&mut *tx)
                .await
                .map_err(db_err)?;
        match existing {
            None => {
                sqlx::query(
                    "INSERT INTO org_members (org_id, user_id, role_level, created_at, updated_at) \
                     VALUES ($1, $2, $3, $4, $5)",
                )
                .bind(inv.org_id)
                .bind(*user.as_uuid())
                .bind(inv.role_level)
                .bind(now)
                .bind(now)
                .execute(&mut *tx)
                .await
                .map_err(db_err)?;
            }
            Some(member) if member.role_level < inv.role_level => {
                sqlx::query(
                    "UPDATE org_members SET role_level = $1, updated_at = $2 WHERE org_id = $3 AND user_id = $4",
                )
                .bind(inv.role_level)
                .bind(now)
                .bind(inv.org_id)
                .bind(*user.as_uuid())
                .execute(&mut *tx)
                .await
                .map_err(db_err)?;
            }
            Some(_) => {} // Existing role is equal or higher — keep it.
        }

        let row: InvitationRow = sqlx::query_as(q!(
            "UPDATE invitations SET accepted_at = $1, accepted_by = $2 WHERE id = $3 RETURNING {INV_COLS}"
        ))
        .bind(now)
        .bind(*user.as_uuid())
        .bind(inv.id)
        .fetch_one(&mut *tx)
        .await
        .map_err(db_err)?;
        tx.commit().await.map_err(db_err)?;
        row.try_into()
    }

    async fn revoke_invitation(&self, id: InvitationId, now: DateTime<Utc>) -> Result<Invitation> {
        let row: Option<InvitationRow> = sqlx::query_as(q!("UPDATE invitations SET revoked_at = $1 \
             WHERE id = $2 AND accepted_at IS NULL AND revoked_at IS NULL RETURNING {INV_COLS}"))
        .bind(now)
        .bind(*id.as_uuid())
        .fetch_optional(&self.pool)
        .await
        .map_err(db_err)?;
        match row {
            Some(row) => row.try_into(),
            None => {
                let exists: Option<PgRow> = sqlx::query("SELECT id FROM invitations WHERE id = $1")
                    .bind(*id.as_uuid())
                    .fetch_optional(&self.pool)
                    .await
                    .map_err(db_err)?;
                if exists.is_some() {
                    Err(Error::Conflict { message: "invitation already accepted or revoked".to_owned() })
                } else {
                    Err(Error::NotFound { what: format!("invitation {id}") })
                }
            }
        }
    }

    async fn list_invitations(&self, org: OrgId) -> Result<Vec<Invitation>> {
        let rows: Vec<InvitationRow> = sqlx::query_as(q!(
            "SELECT {INV_COLS} FROM invitations WHERE org_id = $1 ORDER BY created_at DESC, id DESC"
        ))
        .bind(*org.as_uuid())
        .fetch_all(&self.pool)
        .await
        .map_err(db_err)?;
        rows.into_iter().map(TryInto::try_into).collect()
    }
}
