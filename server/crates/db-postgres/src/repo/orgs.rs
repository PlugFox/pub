//! `OrgRepo` over Postgres: orgs, memberships (≥1-Owner invariant), invitations.
//!
//! Postgres runs writers concurrently, so every invariant-guarded read-then-write sequence
//! locks its serialization anchor first: [`lock_org`] takes `FOR UPDATE` on the org row before
//! owner counting or membership writes, and invitation acceptance locks the invitation row so
//! single-use consumption cannot race itself.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use pub_core::org::{
    Invitation, NewInvitation, NewOrg, Org, OrgMember, OrgMembership, OrgOverview, OrgProfile, UpstreamPolicy,
};
use pub_core::page::{Page, decode_cursor, encode_cursor};
use pub_core::traits::OrgRepo;
use pub_core::{Error, InvitationId, OrgId, Result, RoleLevel, UserId};
use sqlx::postgres::PgRow;
use sqlx::{PgPool, Postgres, QueryBuilder, Row as _};
use uuid::Uuid;

use super::{db_err, parse_col, q, write_err};

/// Hard cap on page size; requests are clamped into `1..=MAX_PAGE`.
const MAX_PAGE: u32 = 200;

/// All org columns, in [`OrgRow`] order.
const ORG_COLS: &str =
    "id, name, slug, description, upstream_policy, storage_quota_bytes, archived_at, created_at, updated_at";
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
    description: String,
    upstream_policy: String,
    storage_quota_bytes: Option<i64>,
    archived_at: Option<DateTime<Utc>>,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

impl TryFrom<OrgRow> for Org {
    type Error = Error;

    fn try_from(row: OrgRow) -> Result<Self> {
        Ok(Org {
            id: OrgId::from_uuid(row.id),
            name: row.name,
            slug: row.slug,
            description: row.description,
            upstream_policy: parse_col::<UpstreamPolicy>(&row.upstream_policy)?,
            storage_quota_bytes: row.storage_quota_bytes,
            archived_at: row.archived_at,
            created_at: row.created_at,
            updated_at: row.updated_at,
        })
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
        // The upstream policy arrives on the payload (from runtime settings — decision 09)
        // rather than defaulting in the column: an operator who blocks upstream by policy must
        // not have to re-block every org somebody creates afterwards.
        let row: OrgRow = sqlx::query_as(q!(
            "INSERT INTO orgs (id, name, slug, description, upstream_policy, created_at, updated_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING {ORG_COLS}"
        ))
        .bind(*OrgId::new().as_uuid())
        .bind(&new.name)
        .bind(&new.slug)
        .bind(&new.description)
        .bind(new.upstream_policy.as_str())
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
        row.try_into()
    }

    async fn get(&self, id: OrgId) -> Result<Option<Org>> {
        let row: Option<OrgRow> = sqlx::query_as(q!("SELECT {ORG_COLS} FROM orgs WHERE id = $1"))
            .bind(*id.as_uuid())
            .fetch_optional(&self.pool)
            .await
            .map_err(db_err)?;
        row.map(TryInto::try_into).transpose()
    }

    async fn get_by_slug(&self, slug: &str) -> Result<Option<Org>> {
        // Case-insensitive match, aligned with the lower() unique index.
        let row: Option<OrgRow> = sqlx::query_as(q!("SELECT {ORG_COLS} FROM orgs WHERE lower(slug) = lower($1)"))
            .bind(slug)
            .fetch_optional(&self.pool)
            .await
            .map_err(db_err)?;
        row.map(TryInto::try_into).transpose()
    }

    async fn update_profile(&self, id: OrgId, profile: &OrgProfile, now: DateTime<Utc>) -> Result<Org> {
        let row: Option<OrgRow> =
            sqlx::query_as(q!("UPDATE orgs SET name = $1, description = $2, upstream_policy = $3, updated_at = $4 \
             WHERE id = $5 RETURNING {ORG_COLS}"))
            .bind(&profile.name)
            .bind(&profile.description)
            .bind(profile.upstream_policy.as_str())
            .bind(now)
            .bind(*id.as_uuid())
            .fetch_optional(&self.pool)
            .await
            .map_err(db_err)?;
        row.ok_or_else(|| Error::NotFound { what: format!("org {id}") })?.try_into()
    }

    async fn list_all(&self, cursor: Option<&str>, limit: u32) -> Result<Page<OrgOverview>> {
        #[derive(sqlx::FromRow)]
        struct OverviewRow {
            #[sqlx(flatten)]
            org: OrgRow,
            members: i64,
            packages: i64,
        }

        let limit = limit.clamp(1, MAX_PAGE) as i64;
        let mut query: QueryBuilder<Postgres> = QueryBuilder::new(format!(
            "SELECT {}, \
             (SELECT COUNT(*) FROM org_members m WHERE m.org_id = o.id) AS members, \
             (SELECT COUNT(*) FROM packages p WHERE p.org_id = o.id) AS packages \
             FROM orgs o",
            ORG_COLS.replace(", ", ", o.").replace("id,", "o.id,")
        ));
        if let Some(cursor) = cursor {
            // The slug is unique instance-wide (case-insensitively), so it is a total order on
            // its own; `lower()` matches the unique index and the SQLite backend's NOCASE.
            let parts = decode_cursor(cursor, 1)?;
            query.push(" WHERE lower(o.slug) > lower(").push_bind(parts[0].clone()).push(")");
        }
        query.push(" ORDER BY lower(o.slug) LIMIT ").push_bind(limit + 1);

        let rows: Vec<OverviewRow> = query.build_query_as().fetch_all(&self.pool).await.map_err(db_err)?;
        let has_more = rows.len() as i64 > limit;
        let items: Vec<OrgOverview> = rows
            .into_iter()
            .take(limit as usize)
            .map(|row| Ok(OrgOverview { org: row.org.try_into()?, members: row.members, packages: row.packages }))
            .collect::<Result<_>>()?;
        let cursor = has_more.then(|| items.last().map(|row| encode_cursor(&[&row.org.slug]))).flatten();
        Ok(Page { items, cursor, has_more })
    }

    async fn count(&self) -> Result<i64> {
        let row: PgRow = sqlx::query("SELECT COUNT(*) AS n FROM orgs").fetch_one(&self.pool).await.map_err(db_err)?;
        Ok(row.get("n"))
    }

    async fn delete(&self, id: OrgId) -> Result<()> {
        let mut tx = self.pool.begin().await.map_err(db_err)?;
        let key = *id.as_uuid();
        // Refuse before deleting anything: a package row or a name claim outlives its org by
        // design (decision 06 / S-18), so erasing the org would either fail on the foreign key
        // halfway through or, worse, un-burn a claimed name.
        for (table, what) in [("packages", "packages"), ("name_claims", "name claims")] {
            let row: PgRow = sqlx::query(super::q!("SELECT COUNT(*) AS n FROM {table} WHERE org_id = $1"))
                .bind(key)
                .fetch_one(&mut *tx)
                .await
                .map_err(db_err)?;
            let count: i64 = row.get("n");
            if count > 0 {
                return Err(Error::Conflict {
                    message: format!("org {id} still owns {count} {what}; archive it instead of deleting it"),
                });
            }
        }
        for statement in [
            "DELETE FROM tokens WHERE org_id = $1",
            "DELETE FROM invitations WHERE org_id = $1",
            "DELETE FROM org_members WHERE org_id = $1",
        ] {
            sqlx::query(super::q!("{statement}")).bind(key).execute(&mut *tx).await.map_err(db_err)?;
        }
        let deleted =
            sqlx::query("DELETE FROM orgs WHERE id = $1").bind(key).execute(&mut *tx).await.map_err(db_err)?;
        if deleted.rows_affected() == 0 {
            return Err(Error::NotFound { what: format!("org {id}") });
        }
        tx.commit().await.map_err(db_err)
    }

    async fn archive(&self, id: OrgId, now: DateTime<Utc>) -> Result<Org> {
        let key = *id.as_uuid();
        let mut tx = self.pool.begin().await.map_err(db_err)?;
        lock_org(&mut tx, id).await?;
        // Idempotent: `archived_at IS NULL` keeps the first stamp on a repeat call.
        sqlx::query("UPDATE orgs SET archived_at = $1, updated_at = $2 WHERE id = $3 AND archived_at IS NULL")
            .bind(now)
            .bind(now)
            .bind(key)
            .execute(&mut *tx)
            .await
            .map_err(db_err)?;
        // Nobody is left holding authority over an archived org: memberships and invitations
        // go, and org-bound CLI tokens are revoked rather than deleted so the audit trail can
        // still name the credential that acted (S-22).
        sqlx::query("UPDATE tokens SET revoked_at = $1 WHERE org_id = $2 AND revoked_at IS NULL")
            .bind(now)
            .bind(key)
            .execute(&mut *tx)
            .await
            .map_err(db_err)?;
        sqlx::query("DELETE FROM invitations WHERE org_id = $1 AND accepted_at IS NULL AND revoked_at IS NULL")
            .bind(key)
            .execute(&mut *tx)
            .await
            .map_err(db_err)?;
        sqlx::query("DELETE FROM org_members WHERE org_id = $1").bind(key).execute(&mut *tx).await.map_err(db_err)?;

        let row: Option<OrgRow> = sqlx::query_as(q!("SELECT {ORG_COLS} FROM orgs WHERE id = $1"))
            .bind(key)
            .fetch_optional(&mut *tx)
            .await
            .map_err(db_err)?;
        let row = row.ok_or_else(|| Error::NotFound { what: format!("org {id}") })?;
        tx.commit().await.map_err(db_err)?;
        row.try_into()
    }

    async fn set_upstream_policy(&self, id: OrgId, policy: UpstreamPolicy, now: DateTime<Utc>) -> Result<Org> {
        let row: Option<OrgRow> = sqlx::query_as(q!(
            "UPDATE orgs SET upstream_policy = $1, updated_at = $2 WHERE id = $3 RETURNING {ORG_COLS}"
        ))
        .bind(policy.as_str())
        .bind(now)
        .bind(*id.as_uuid())
        .fetch_optional(&self.pool)
        .await
        .map_err(db_err)?;
        row.ok_or_else(|| Error::NotFound { what: format!("org {id}") })?.try_into()
    }

    async fn set_storage_quota(&self, id: OrgId, quota: Option<i64>, now: DateTime<Utc>) -> Result<Org> {
        // `quota` binds as NULL when it is `None`, which is the "no override" row rather than a
        // zero — the two are different states and the column is nullable to keep them so.
        let row: Option<OrgRow> = sqlx::query_as(q!(
            "UPDATE orgs SET storage_quota_bytes = $1, updated_at = $2 WHERE id = $3 RETURNING {ORG_COLS}"
        ))
        .bind(quota)
        .bind(now)
        .bind(*id.as_uuid())
        .fetch_optional(&self.pool)
        .await
        .map_err(db_err)?;
        row.ok_or_else(|| Error::NotFound { what: format!("org {id}") })?.try_into()
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
            .map(|row| Ok(OrgMembership { org: row.org.try_into()?, role: role_from_i16(row.role_level)? }))
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

    async fn list_members(&self, org: OrgId) -> Result<Vec<OrgMember>> {
        let rows: Vec<MemberRow> = sqlx::query_as(q!(
            "SELECT {MEMBER_COLS} FROM org_members WHERE org_id = $1 ORDER BY role_level DESC, created_at, user_id"
        ))
        .bind(*org.as_uuid())
        .fetch_all(&self.pool)
        .await
        .map_err(db_err)?;
        rows.into_iter().map(TryInto::try_into).collect()
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

    async fn has_pending_invitation(&self, email: &str, now: DateTime<Utc>) -> Result<bool> {
        // Case-insensitive match, aligned with the lower() partial index.
        let row: Option<PgRow> = sqlx::query(
            "SELECT 1 FROM invitations \
             WHERE lower(email) = lower($1) AND accepted_at IS NULL AND revoked_at IS NULL AND expires_at > $2 \
             LIMIT 1",
        )
        .bind(email)
        .bind(now)
        .fetch_optional(&self.pool)
        .await
        .map_err(db_err)?;
        Ok(row.is_some())
    }

    async fn count_invitations_since(&self, org: OrgId, since: DateTime<Utc>) -> Result<i64> {
        let row: PgRow = sqlx::query("SELECT COUNT(*) AS n FROM invitations WHERE org_id = $1 AND created_at >= $2")
            .bind(*org.as_uuid())
            .bind(since)
            .fetch_one(&self.pool)
            .await
            .map_err(db_err)?;
        Ok(row.get("n"))
    }

    async fn count_invitations_since_by_actor(&self, org: OrgId, actor: UserId, since: DateTime<Utc>) -> Result<i64> {
        // `invitations_actor_created_idx (invited_by, created_at)` (migration 0014) seeks the
        // actor and ranges over the window; `org_id` is a residual test on the few rows that
        // come back.
        let row: PgRow = sqlx::query(
            "SELECT COUNT(*) AS n FROM invitations WHERE org_id = $1 AND invited_by = $2 AND created_at >= $3",
        )
        .bind(*org.as_uuid())
        .bind(*actor.as_uuid())
        .bind(since)
        .fetch_one(&self.pool)
        .await
        .map_err(db_err)?;
        Ok(row.get("n"))
    }

    async fn purge_invitations_before(&self, cutoff: DateTime<Utc>, batch: u32) -> Result<u64> {
        // `COALESCE(accepted_at, revoked_at, expires_at)` is the settle time, and using it rather
        // than `created_at` is what makes a **live pending invitation structurally undeletable**:
        // its `expires_at` is in the future, so no cutoff at or before `now` can match it, whatever
        // the operator configured. Deriving that from the predicate instead of from a validator
        // matters because the invitation TTL is a policy value in the admin crate, not a config key
        // the retention validator can see. `invitations_settled_idx` (migration 0012) indexes the
        // same expression, so the sweep seeks rather than scans.
        let result = sqlx::query(
            "DELETE FROM invitations WHERE id IN (SELECT id FROM invitations \
             WHERE COALESCE(accepted_at, revoked_at, expires_at) < $1 \
             ORDER BY COALESCE(accepted_at, revoked_at, expires_at) LIMIT $2)",
        )
        .bind(cutoff)
        .bind(i64::from(batch))
        .execute(&self.pool)
        .await
        .map_err(db_err)?;
        Ok(result.rows_affected())
    }
}
