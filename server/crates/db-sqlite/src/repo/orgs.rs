//! `OrgRepo` over SQLite: orgs, memberships (≥1-Owner invariant), invitations.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use pub_core::org::{Invitation, NewInvitation, NewOrg, Org, OrgMember, OrgMembership};
use pub_core::traits::OrgRepo;
use pub_core::{Error, InvitationId, OrgId, Result, RoleLevel, UserId};
use sqlx::sqlite::SqliteRow;
use sqlx::{Row as _, SqlitePool};

use super::{db_err, parse_col, parse_ts, parse_ts_opt, q, write_err};

/// All org columns, in [`OrgRow`] order.
const ORG_COLS: &str = "id, name, slug, created_at, updated_at";
/// All membership columns, in [`MemberRow`] order.
const MEMBER_COLS: &str = "org_id, user_id, role_level, created_at, updated_at";
/// All invitation columns, in [`InvitationRow`] order.
const INV_COLS: &str =
    "id, org_id, email, role_level, invited_by, created_at, expires_at, accepted_at, accepted_by, revoked_at";

/// SQLite-backed [`OrgRepo`].
#[derive(Debug, Clone)]
pub struct SqliteOrgRepo {
    pool: SqlitePool,
}

impl SqliteOrgRepo {
    /// Wraps a pool handle.
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }
}

#[derive(sqlx::FromRow)]
struct OrgRow {
    id: String,
    name: String,
    slug: String,
    created_at: String,
    updated_at: String,
}

impl TryFrom<OrgRow> for Org {
    type Error = Error;

    fn try_from(row: OrgRow) -> Result<Self> {
        Ok(Org {
            id: parse_col(&row.id)?,
            name: row.name,
            slug: row.slug,
            created_at: parse_ts(&row.created_at)?,
            updated_at: parse_ts(&row.updated_at)?,
        })
    }
}

#[derive(sqlx::FromRow)]
struct MemberRow {
    org_id: String,
    user_id: String,
    role_level: i64,
    created_at: String,
    updated_at: String,
}

impl TryFrom<MemberRow> for OrgMember {
    type Error = Error;

    fn try_from(row: MemberRow) -> Result<Self> {
        Ok(OrgMember {
            org_id: parse_col(&row.org_id)?,
            user_id: parse_col(&row.user_id)?,
            role: role_from_i64(row.role_level)?,
            created_at: parse_ts(&row.created_at)?,
            updated_at: parse_ts(&row.updated_at)?,
        })
    }
}

#[derive(sqlx::FromRow)]
struct InvitationRow {
    id: String,
    org_id: String,
    email: String,
    role_level: i64,
    invited_by: String,
    created_at: String,
    expires_at: String,
    accepted_at: Option<String>,
    accepted_by: Option<String>,
    revoked_at: Option<String>,
}

impl TryFrom<InvitationRow> for Invitation {
    type Error = Error;

    fn try_from(row: InvitationRow) -> Result<Self> {
        Ok(Invitation {
            id: parse_col(&row.id)?,
            org_id: parse_col(&row.org_id)?,
            email: row.email,
            role: role_from_i64(row.role_level)?,
            invited_by: parse_col(&row.invited_by)?,
            created_at: parse_ts(&row.created_at)?,
            expires_at: parse_ts(&row.expires_at)?,
            accepted_at: parse_ts_opt(row.accepted_at.as_deref())?,
            accepted_by: row.accepted_by.as_deref().map(parse_col).transpose()?,
            revoked_at: parse_ts_opt(row.revoked_at.as_deref())?,
        })
    }
}

fn role_from_i64(raw: i64) -> Result<RoleLevel> {
    u8::try_from(raw).map(RoleLevel::new).map_err(|_| Error::Database { message: format!("corrupt role level {raw}") })
}

/// Rejects the storage-invalid "not a member" level on write paths.
fn require_member_role(role: RoleLevel) -> Result<()> {
    if role == RoleLevel::NONE {
        return Err(Error::Invalid { message: "role level 0 means 'not a member'; remove the member instead".into() });
    }
    Ok(())
}

/// Counts Owners of `org` other than `except` (inside the caller's transaction).
async fn other_owner_count(tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>, org: OrgId, except: UserId) -> Result<i64> {
    let row: SqliteRow =
        sqlx::query("SELECT COUNT(*) AS n FROM org_members WHERE org_id = ? AND role_level >= ? AND user_id <> ?")
            .bind(org.to_string())
            .bind(i64::from(RoleLevel::OWNER.level()))
            .bind(except.to_string())
            .fetch_one(&mut **tx)
            .await
            .map_err(db_err)?;
    Ok(row.get("n"))
}

#[async_trait]
impl OrgRepo for SqliteOrgRepo {
    async fn ping(&self) -> Result<()> {
        sqlx::query("SELECT 1").execute(&self.pool).await.map_err(db_err)?;
        Ok(())
    }

    async fn create(&self, new: NewOrg, creator: UserId, now: DateTime<Utc>) -> Result<Org> {
        let stamp = super::ts(now);
        let mut tx = self.pool.begin().await.map_err(db_err)?;
        let row: OrgRow = sqlx::query_as(q!(
            "INSERT INTO orgs (id, name, slug, created_at, updated_at) VALUES (?, ?, ?, ?, ?) RETURNING {ORG_COLS}"
        ))
        .bind(OrgId::new().to_string())
        .bind(&new.name)
        .bind(&new.slug)
        .bind(&stamp)
        .bind(&stamp)
        .fetch_one(&mut *tx)
        .await
        .map_err(|err| write_err(err, "org slug already taken", "org"))?;

        // The creator becomes Owner in the same transaction — an org never exists ownerless.
        sqlx::query(
            "INSERT INTO org_members (org_id, user_id, role_level, created_at, updated_at) VALUES (?, ?, ?, ?, ?)",
        )
        .bind(&row.id)
        .bind(creator.to_string())
        .bind(i64::from(RoleLevel::OWNER.level()))
        .bind(&stamp)
        .bind(&stamp)
        .execute(&mut *tx)
        .await
        .map_err(|err| write_err(err, "creator is already a member", "user"))?;

        tx.commit().await.map_err(db_err)?;
        row.try_into()
    }

    async fn get(&self, id: OrgId) -> Result<Option<Org>> {
        let row: Option<OrgRow> = sqlx::query_as(q!("SELECT {ORG_COLS} FROM orgs WHERE id = ?"))
            .bind(id.to_string())
            .fetch_optional(&self.pool)
            .await
            .map_err(db_err)?;
        row.map(TryInto::try_into).transpose()
    }

    async fn get_by_slug(&self, slug: &str) -> Result<Option<Org>> {
        // The slug column carries COLLATE NOCASE, so `=` matches case-insensitively.
        let row: Option<OrgRow> = sqlx::query_as(q!("SELECT {ORG_COLS} FROM orgs WHERE slug = ?"))
            .bind(slug)
            .fetch_optional(&self.pool)
            .await
            .map_err(db_err)?;
        row.map(TryInto::try_into).transpose()
    }

    async fn list_for_user(&self, user: UserId) -> Result<Vec<OrgMembership>> {
        #[derive(sqlx::FromRow)]
        struct MembershipRow {
            #[sqlx(flatten)]
            org: OrgRow,
            role_level: i64,
        }

        let rows: Vec<MembershipRow> = sqlx::query_as(q!(
            "SELECT o.{}, m.role_level FROM orgs o \
             JOIN org_members m ON m.org_id = o.id WHERE m.user_id = ? ORDER BY o.created_at, o.id",
            ORG_COLS.replace(", ", ", o.")
        ))
        .bind(user.to_string())
        .fetch_all(&self.pool)
        .await
        .map_err(db_err)?;

        rows.into_iter()
            .map(|row| Ok(OrgMembership { org: row.org.try_into()?, role: role_from_i64(row.role_level)? }))
            .collect()
    }

    async fn get_member(&self, org: OrgId, user: UserId) -> Result<Option<OrgMember>> {
        let row: Option<MemberRow> =
            sqlx::query_as(q!("SELECT {MEMBER_COLS} FROM org_members WHERE org_id = ? AND user_id = ?"))
                .bind(org.to_string())
                .bind(user.to_string())
                .fetch_optional(&self.pool)
                .await
                .map_err(db_err)?;
        row.map(TryInto::try_into).transpose()
    }

    async fn add_member(&self, org: OrgId, user: UserId, role: RoleLevel, now: DateTime<Utc>) -> Result<OrgMember> {
        require_member_role(role)?;
        let stamp = super::ts(now);
        let row: MemberRow =
            sqlx::query_as(q!("INSERT INTO org_members (org_id, user_id, role_level, created_at, updated_at) \
             VALUES (?, ?, ?, ?, ?) RETURNING {MEMBER_COLS}"))
            .bind(org.to_string())
            .bind(user.to_string())
            .bind(i64::from(role.level()))
            .bind(&stamp)
            .bind(&stamp)
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
        let current: Option<MemberRow> =
            sqlx::query_as(q!("SELECT {MEMBER_COLS} FROM org_members WHERE org_id = ? AND user_id = ?"))
                .bind(org.to_string())
                .bind(user.to_string())
                .fetch_optional(&mut *tx)
                .await
                .map_err(db_err)?;
        let current = current.ok_or_else(|| Error::NotFound { what: format!("membership of {user} in org {org}") })?;

        let was_owner = role_from_i64(current.role_level)?.satisfies(RoleLevel::OWNER);
        if was_owner && !role.satisfies(RoleLevel::OWNER) && other_owner_count(&mut tx, org, user).await? == 0 {
            return Err(Error::LastOwner { org });
        }

        let row: MemberRow = sqlx::query_as(q!("UPDATE org_members SET role_level = ?, updated_at = ? \
             WHERE org_id = ? AND user_id = ? RETURNING {MEMBER_COLS}"))
        .bind(i64::from(role.level()))
        .bind(super::ts(now))
        .bind(org.to_string())
        .bind(user.to_string())
        .fetch_one(&mut *tx)
        .await
        .map_err(db_err)?;
        tx.commit().await.map_err(db_err)?;
        row.try_into()
    }

    async fn remove_member(&self, org: OrgId, user: UserId) -> Result<()> {
        let mut tx = self.pool.begin().await.map_err(db_err)?;
        let current: Option<MemberRow> =
            sqlx::query_as(q!("SELECT {MEMBER_COLS} FROM org_members WHERE org_id = ? AND user_id = ?"))
                .bind(org.to_string())
                .bind(user.to_string())
                .fetch_optional(&mut *tx)
                .await
                .map_err(db_err)?;
        let current = current.ok_or_else(|| Error::NotFound { what: format!("membership of {user} in org {org}") })?;

        if role_from_i64(current.role_level)?.satisfies(RoleLevel::OWNER)
            && other_owner_count(&mut tx, org, user).await? == 0
        {
            return Err(Error::LastOwner { org });
        }

        sqlx::query("DELETE FROM org_members WHERE org_id = ? AND user_id = ?")
            .bind(org.to_string())
            .bind(user.to_string())
            .execute(&mut *tx)
            .await
            .map_err(db_err)?;
        tx.commit().await.map_err(db_err)
    }

    async fn create_invitation(&self, new: NewInvitation, now: DateTime<Utc>) -> Result<Invitation> {
        require_member_role(new.role)?;
        let row: InvitationRow = sqlx::query_as(q!(
            "INSERT INTO invitations (id, org_id, email, role_level, token_hash, invited_by, created_at, expires_at) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?) RETURNING {INV_COLS}"
        ))
        .bind(InvitationId::new().to_string())
        .bind(new.org_id.to_string())
        .bind(&new.email)
        .bind(i64::from(new.role.level()))
        .bind(&new.token_hash)
        .bind(new.invited_by.to_string())
        .bind(super::ts(now))
        .bind(super::ts(new.expires_at))
        .fetch_one(&self.pool)
        .await
        .map_err(|err| write_err(err, "invitation token hash already exists", "org or inviter"))?;
        row.try_into()
    }

    async fn find_invitation_by_token_hash(&self, token_hash: &str) -> Result<Option<Invitation>> {
        let row: Option<InvitationRow> = sqlx::query_as(q!("SELECT {INV_COLS} FROM invitations WHERE token_hash = ?"))
            .bind(token_hash)
            .fetch_optional(&self.pool)
            .await
            .map_err(db_err)?;
        row.map(TryInto::try_into).transpose()
    }

    async fn accept_invitation(&self, token_hash: &str, user: UserId, now: DateTime<Utc>) -> Result<Invitation> {
        let mut tx = self.pool.begin().await.map_err(db_err)?;
        let inv: Option<InvitationRow> = sqlx::query_as(q!("SELECT {INV_COLS} FROM invitations WHERE token_hash = ?"))
            .bind(token_hash)
            .fetch_optional(&mut *tx)
            .await
            .map_err(db_err)?;
        let inv = inv.ok_or_else(|| Error::NotFound { what: "invitation".to_owned() })?;

        if inv.accepted_at.is_some() || inv.revoked_at.is_some() {
            return Err(Error::Conflict { message: "invitation already accepted or revoked".to_owned() });
        }
        if parse_ts(&inv.expires_at)? <= now {
            return Err(Error::Expired { what: "invitation".to_owned() });
        }

        // Email binding: only a user holding the invited email, verified, may accept.
        let user_row: Option<SqliteRow> = sqlx::query("SELECT email, email_verified FROM users WHERE id = ?")
            .bind(user.to_string())
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
        let stamp = super::ts(now);
        let existing: Option<MemberRow> =
            sqlx::query_as(q!("SELECT {MEMBER_COLS} FROM org_members WHERE org_id = ? AND user_id = ?"))
                .bind(&inv.org_id)
                .bind(user.to_string())
                .fetch_optional(&mut *tx)
                .await
                .map_err(db_err)?;
        match existing {
            None => {
                sqlx::query(
                    "INSERT INTO org_members (org_id, user_id, role_level, created_at, updated_at) VALUES (?, ?, ?, ?, ?)",
                )
                .bind(&inv.org_id)
                .bind(user.to_string())
                .bind(inv.role_level)
                .bind(&stamp)
                .bind(&stamp)
                .execute(&mut *tx)
                .await
                .map_err(db_err)?;
            }
            Some(member) if member.role_level < inv.role_level => {
                sqlx::query("UPDATE org_members SET role_level = ?, updated_at = ? WHERE org_id = ? AND user_id = ?")
                    .bind(inv.role_level)
                    .bind(&stamp)
                    .bind(&inv.org_id)
                    .bind(user.to_string())
                    .execute(&mut *tx)
                    .await
                    .map_err(db_err)?;
            }
            Some(_) => {} // Existing role is equal or higher — keep it.
        }

        let row: InvitationRow = sqlx::query_as(q!(
            "UPDATE invitations SET accepted_at = ?, accepted_by = ? WHERE id = ? RETURNING {INV_COLS}"
        ))
        .bind(&stamp)
        .bind(user.to_string())
        .bind(&inv.id)
        .fetch_one(&mut *tx)
        .await
        .map_err(db_err)?;
        tx.commit().await.map_err(db_err)?;
        row.try_into()
    }

    async fn revoke_invitation(&self, id: InvitationId, now: DateTime<Utc>) -> Result<Invitation> {
        let row: Option<InvitationRow> = sqlx::query_as(q!("UPDATE invitations SET revoked_at = ? \
             WHERE id = ? AND accepted_at IS NULL AND revoked_at IS NULL RETURNING {INV_COLS}"))
        .bind(super::ts(now))
        .bind(id.to_string())
        .fetch_optional(&self.pool)
        .await
        .map_err(db_err)?;
        match row {
            Some(row) => row.try_into(),
            None => {
                let exists: Option<SqliteRow> = sqlx::query("SELECT id FROM invitations WHERE id = ?")
                    .bind(id.to_string())
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
        let rows: Vec<InvitationRow> =
            sqlx::query_as(q!("SELECT {INV_COLS} FROM invitations WHERE org_id = ? ORDER BY created_at DESC, id DESC"))
                .bind(org.to_string())
                .fetch_all(&self.pool)
                .await
                .map_err(db_err)?;
        rows.into_iter().map(TryInto::try_into).collect()
    }
}
