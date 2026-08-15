//! The instance-administration surface (`/api/v1/admin/…`).
//!
//! Every route takes the [`InstanceAdmin`] extractor, which reads the flag off the **durable
//! user row** and runs it through the `authorize()` chokepoint. Nothing here consults an org
//! role: an org Owner administers their org, not the instance (decision 19 — the two ladders
//! are orthogonal planes).
//!
//! Settings writes go through [`AdminService`](pub_admin::AdminService), which owns the
//! repository → cache → broker ordering and the S-26 sealing of the SMTP password. The
//! handlers only translate DTOs.

use std::sync::Arc;

use axum::Json;
use axum::extract::{Path, State};
use pub_admin::instance::{SettingsPatch, SmtpPatch};
use pub_auth::ratelimit::{self, Decision};
use pub_core::audit::{AuditActor, AuditFilter};
use pub_core::settings::{
    BrandingSettings, RateLimitSettings, RegistrationMode, RegistrationSettings, RegistrySettings, UpstreamSettings,
};
use pub_core::user::{UserFilter, UserStatus};
use pub_core::{Error, OrgId, UserId};
use serde::Deserialize;
use utoipa::IntoParams;

use crate::dto::{
    AdminOrgDto, AdminOrgPatchBody, AdminOrgQuotaDto, AdminSettingsDto, AdminSettingsPatchBody, AdminStatsDto,
    AdminUserDto, AuditEventDto, BrandingSettingsDto, JobRunDto, JobStateDto, ListDto, OrgDto, QuarantineDto,
    RateLimitSettingsDto, RegistrationSettingsDto, ShadowingAckDto, ShadowingDto, SmtpSettingsDto,
    UpstreamCacheStatsDto, UpstreamSettingsDto, UserCountsDto,
};
use crate::dto::{RegistrySettingsDto, RegistryStatsDto, SmtpSettingsPatchDto, SmtpTestResultDto};
use crate::envelope::{ErrorEnvelope, OkEnvelope};
use crate::error::ApiError;
use crate::extract::{InstanceAdmin, QueryParams, RequestMeta, require_step_up};
use crate::routes::actor_meta;
use crate::routes::packages::PageParams;
use crate::state::AppState;

/// Full-log audit exports one administrator may **start** per hour ([decision 30](../../../../docs/decisions.md#30--retention-one-window-per-table-a-delete-that-stays-bounded-and-a-privilege-that-survives-the-feature)).
///
/// A constant rather than a config key: there is no deployment shape in which an operator
/// legitimately needs to walk the whole audit log more often than this, and it is generous enough
/// for a resumed export whose connection kept breaking.
///
/// **It bounds starts, not concurrency**, and the difference is worth stating rather than glossing.
/// The window is fixed and aligned (`ratelimit::hit` keys on `now / window`), so twelve at the end
/// of one hour and twelve at the start of the next is twenty-four walks inside a couple of seconds;
/// and because the walk outlives its own response head, those walks are outside the D8 concurrency
/// permit and the D13 deadline both — which is [D38](../../../../docs/roadmap.md) restated for a
/// second surface. What keeps that from being a self-inflicted outage is [`MAX_CONCURRENT_EXPORTS`],
/// which bounds the walks actually in flight; this constant bounds how often one administrator may
/// ask.
const EXPORT_BUDGET_PER_HOUR: u32 = 12;

/// Audit-log walks allowed in flight across the whole instance.
///
/// The hourly budget above cannot bound this on its own: it is per administrator and its window is
/// aligned, and a walk keeps issuing queries after the response head has released the request's
/// concurrency permit. Without a ceiling here, twenty-four concurrent walks against SQLite's
/// five-connection pool queue ordinary traffic on `acquire` for up to the instance-wide request
/// deadline — sign-in and publish-finalize start failing because somebody exported the audit log.
///
/// Two is deliberate and not tuning: an export is an operator action, not a workload, and the
/// thirteenth-in-flight case answers 429 with the same shape as the hourly budget.
pub(crate) const MAX_CONCURRENT_EXPORTS: usize = 2;

/// The effective runtime settings (secrets excluded — S-26).
#[utoipa::path(
    get,
    path = "/api/v1/admin/settings",
    tag = "admin",
    security(("bearer_auth" = [])),
    responses(
        (status = OK, description = "Effective runtime settings", body = OkEnvelope<AdminSettingsDto>),
        (status = FORBIDDEN, description = "Not an instance administrator", body = ErrorEnvelope),
    )
)]
pub async fn get_settings(
    State(state): State<AppState>,
    InstanceAdmin(_auth): InstanceAdmin,
) -> Result<Json<OkEnvelope<AdminSettingsDto>>, ApiError> {
    Ok(Json(OkEnvelope::new(settings_dto(state.admin.settings()))))
}

/// Updates runtime settings: durable write, local reload, cross-instance invalidation.
#[utoipa::path(
    patch,
    path = "/api/v1/admin/settings",
    tag = "admin",
    security(("bearer_auth" = [])),
    request_body = AdminSettingsPatchBody,
    responses(
        (status = OK, description = "Settings after the write, with the new version", body = OkEnvelope<AdminSettingsDto>),
        (status = BAD_REQUEST, description = "No sections supplied, or a value the validator refuses", body = ErrorEnvelope),
        (status = FORBIDDEN, description = "Not an instance administrator", body = ErrorEnvelope),
    )
)]
pub async fn update_settings(
    State(state): State<AppState>,
    InstanceAdmin(auth): InstanceAdmin,
    RequestMeta(meta): RequestMeta,
    Json(body): Json<AdminSettingsPatchBody>,
) -> Result<Json<OkEnvelope<AdminSettingsDto>>, ApiError> {
    let patch = SettingsPatch {
        registration: body.registration.map(registration_from).transpose()?,
        rate_limits: body.rate_limits.map(|limits| RateLimitSettings {
            otp_per_email_hour: limits.otp_per_email_hour,
            otp_per_ip_hour: limits.otp_per_ip_hour,
            login_per_ip_minute: limits.login_per_ip_minute,
            token_auth_fail_per_ip_minute: limits.token_auth_fail_per_ip_minute,
            publish_per_hour_org: limits.publish_per_hour_org,
            read_per_ip_minute: limits.read_per_ip_minute,
            read_per_identity_minute: limits.read_per_identity_minute,
            write_per_ip_minute: limits.write_per_ip_minute,
            write_per_identity_minute: limits.write_per_identity_minute,
            invitations_per_day_org: limits.invitations_per_day_org,
            invitations_per_day_actor: limits.invitations_per_day_actor,
        }),
        smtp: body.smtp.map(smtp_from),
        branding: body.branding.map(|branding| BrandingSettings {
            name: branding.name,
            tagline: branding.tagline,
            logo_url: branding.logo_url,
            primary_color: branding.primary_color,
        }),
        upstream: body.upstream.map(upstream_from).transpose()?,
        registry: body.registry.map(|registry| RegistrySettings {
            require_auth_for_read: registry.require_auth_for_read,
            storage_quota_bytes: registry.storage_quota_bytes,
        }),
    };
    let now = (state.clock)();
    let view = state.admin.update_settings(patch, &actor_meta(&auth, &meta), now).await?;
    Ok(Json(OkEnvelope::new(settings_dto(view))))
}

/// Sends a test message to the acting administrator's own verified address.
///
/// The recipient is not a parameter: pinning it to the caller removes the mail-bomb vector
/// instead of rate-limiting it. Not step-up gated (S-06) — it neither escalates authority nor
/// destroys anything — and it calls the mailer directly rather than riding the jobs queue,
/// because synchronous diagnosis is the whole purpose.
#[utoipa::path(
    post,
    path = "/api/v1/admin/settings/smtp/test",
    tag = "admin",
    security(("bearer_auth" = [])),
    responses(
        (status = OK, description = "The delivery attempt's outcome — a refused delivery is reported here, not as a 5xx", body = OkEnvelope<SmtpTestResultDto>),
        (status = BAD_REQUEST, description = "The acting administrator has no verified email address", body = ErrorEnvelope),
        (status = FORBIDDEN, description = "Not an instance administrator", body = ErrorEnvelope),
    )
)]
pub async fn test_smtp(
    State(state): State<AppState>,
    InstanceAdmin(auth): InstanceAdmin,
    RequestMeta(meta): RequestMeta,
) -> Result<Json<OkEnvelope<SmtpTestResultDto>>, ApiError> {
    let now = (state.clock)();
    let report = state.admin.send_test_email(&actor_meta(&auth, &meta), now).await?;
    Ok(Json(OkEnvelope::new(SmtpTestResultDto {
        delivered: report.delivered,
        host: report.host,
        security: report.security,
        credentialed: report.credentialed,
        detail: report.detail,
    })))
}

/// Query parameters for the admin user listing.
#[derive(Debug, Deserialize, IntoParams)]
pub struct UsersQuery {
    /// Case-insensitive substring of the email or display name.
    pub q: Option<String>,
    /// Narrow to one lifecycle status: `active` | `suspended` | `deleted`.
    pub status: Option<String>,
    /// Only instance administrators.
    pub admins: Option<bool>,
    /// Opaque cursor from the previous page.
    pub cursor: Option<String>,
    /// Page size, 1..=100 (default 20).
    pub limit: Option<u32>,
}

/// The user table, newest account first.
#[utoipa::path(
    get,
    path = "/api/v1/admin/users",
    tag = "admin",
    security(("bearer_auth" = [])),
    params(UsersQuery),
    responses(
        (status = OK, description = "Accounts, newest first", body = OkEnvelope<ListDto<AdminUserDto>>),
        (status = FORBIDDEN, description = "Not an instance administrator", body = ErrorEnvelope),
    )
)]
pub async fn list_users(
    State(state): State<AppState>,
    InstanceAdmin(_auth): InstanceAdmin,
    QueryParams(query): QueryParams<UsersQuery>,
) -> Result<Json<OkEnvelope<ListDto<AdminUserDto>>>, ApiError> {
    let status = query.status.as_deref().map(str::parse::<UserStatus>).transpose()?;
    let filter = UserFilter { query: query.q.clone(), status, admins_only: query.admins.unwrap_or(false) };
    let page = state
        .admin
        .list_users(&filter, query.cursor.as_deref(), PageParams { cursor: None, limit: query.limit }.limit())
        .await?;
    Ok(Json(OkEnvelope::new(ListDto {
        items: page.items.iter().map(AdminUserDto::from).collect(),
        cursor: page.cursor,
        has_more: page.has_more,
    })))
}

/// Suspends an account: sign-in is refused and every live session is revoked (S-09).
#[utoipa::path(
    post,
    path = "/api/v1/admin/users/{id}/suspend",
    tag = "admin",
    security(("bearer_auth" = [])),
    params(("id" = String, Path, description = "User id")),
    responses(
        (status = OK, description = "Account suspended and its sessions revoked", body = OkEnvelope<AdminUserDto>),
        (status = BAD_REQUEST, description = "An administrator cannot suspend their own account", body = ErrorEnvelope),
        (status = FORBIDDEN, description = "Not an instance administrator", body = ErrorEnvelope),
        (status = NOT_FOUND, description = "Unknown user", body = ErrorEnvelope),
    )
)]
pub async fn suspend_user(
    State(state): State<AppState>,
    admin: InstanceAdmin,
    meta: RequestMeta,
    path: Path<String>,
) -> Result<Json<OkEnvelope<AdminUserDto>>, ApiError> {
    set_suspended(state, admin, meta, path, true).await
}

/// Reinstates a suspended account.
#[utoipa::path(
    post,
    path = "/api/v1/admin/users/{id}/unsuspend",
    tag = "admin",
    security(("bearer_auth" = [])),
    params(("id" = String, Path, description = "User id")),
    responses(
        (status = OK, description = "Account reinstated", body = OkEnvelope<AdminUserDto>),
        (status = FORBIDDEN, description = "Not an instance administrator", body = ErrorEnvelope),
        (status = NOT_FOUND, description = "Unknown user", body = ErrorEnvelope),
    )
)]
pub async fn unsuspend_user(
    State(state): State<AppState>,
    admin: InstanceAdmin,
    meta: RequestMeta,
    path: Path<String>,
) -> Result<Json<OkEnvelope<AdminUserDto>>, ApiError> {
    set_suspended(state, admin, meta, path, false).await
}

/// The shared body of suspend and unsuspend.
async fn set_suspended(
    state: AppState,
    InstanceAdmin(auth): InstanceAdmin,
    RequestMeta(meta): RequestMeta,
    Path(id): Path<String>,
    suspended: bool,
) -> Result<Json<OkEnvelope<AdminUserDto>>, ApiError> {
    let id: UserId = id.parse().map_err(|_| Error::NotFound { what: format!("user {}", clip(&id)) })?;
    let now = (state.clock)();
    let user = state.admin.set_user_suspended(id, suspended, &actor_meta(&auth, &meta), now).await?;
    Ok(Json(OkEnvelope::new(AdminUserDto::from(&user))))
}

/// Every org with its member and package counts.
#[utoipa::path(
    get,
    path = "/api/v1/admin/orgs",
    tag = "admin",
    security(("bearer_auth" = [])),
    params(PageParams),
    responses(
        (status = OK, description = "Orgs by slug, archived ones included", body = OkEnvelope<ListDto<AdminOrgDto>>),
        (status = FORBIDDEN, description = "Not an instance administrator", body = ErrorEnvelope),
        (status = BAD_REQUEST, description = "Malformed cursor", body = ErrorEnvelope),
    )
)]
pub async fn list_orgs(
    State(state): State<AppState>,
    InstanceAdmin(_auth): InstanceAdmin,
    QueryParams(params): QueryParams<PageParams>,
) -> Result<Json<OkEnvelope<ListDto<AdminOrgDto>>>, ApiError> {
    let page = state.admin.list_orgs(params.cursor.as_deref(), params.limit()).await?;
    // One snapshot for the whole page: the instance default is a runtime setting, and resolving
    // half a page against one value and half against another would report a table no operator
    // action ever produced.
    let instance_default = state.runtime.current().registry.storage_quota_bytes;
    Ok(Json(OkEnvelope::new(ListDto {
        items: page
            .items
            .iter()
            .map(|row| AdminOrgDto {
                org: OrgDto::from(&row.org),
                members: row.members,
                packages: row.packages,
                storage_quota_bytes: quota_out(row.org.storage_quota_bytes),
                // Resolved here rather than by the caller, through the one function that owns
                // the rule (S-20.b). The listing is the only surface that showed what an
                // operator *set* and never what an org is actually measured against.
                effective_quota_bytes: pub_registry::publish::effective_storage_quota(
                    row.org.storage_quota_bytes,
                    instance_default,
                ),
            })
            .collect(),
        cursor: page.cursor,
        has_more: page.has_more,
    })))
}

/// Sets or clears one org's storage-quota override (S-20.b, decision 32).
///
/// **The first write the admin plane has ever had over an org**, and the reason it is here
/// rather than on `PATCH /api/v1/orgs/{slug}` is the requirement itself: that route is reachable
/// by an org Admin, and a quota an org can raise for itself is not a quota. The separation is
/// structural rather than a role check — the field is absent from
/// [`pub_core::org::OrgProfile`], which is the only payload that route can write.
///
/// Not step-up gated (S-06). It escalates no authority and destroys nothing: the worst a stolen
/// admin session does here is stop an org publishing, which is loud, audited, and reversed by
/// one more request.
#[utoipa::path(
    patch,
    path = "/api/v1/admin/orgs/{id}",
    tag = "admin",
    security(("bearer_auth" = [])),
    params(("id" = String, Path, description = "Org id")),
    request_body = AdminOrgPatchBody,
    responses(
        (status = OK, description = "The stored override and what it resolves to", body = OkEnvelope<AdminOrgQuotaDto>),
        (status = BAD_REQUEST, description = "No fields supplied, or a quota outside 0..=i64::MAX", body = ErrorEnvelope),
        (status = FORBIDDEN, description = "Not an instance administrator", body = ErrorEnvelope),
        // A malformed id is the same 404 an unknown one gets, and this route documents it as
        // such: an id that is not a UUID names no org, and S-04 gives "never existed" and
        // "cannot exist" the same answer rather than telling a caller which of the two it hit.
        (status = NOT_FOUND, description = "Unknown org, or a malformed org id", body = ErrorEnvelope),
    )
)]
pub async fn update_org(
    State(state): State<AppState>,
    InstanceAdmin(auth): InstanceAdmin,
    RequestMeta(meta): RequestMeta,
    Path(id): Path<String>,
    Json(body): Json<AdminOrgPatchBody>,
) -> Result<Json<OkEnvelope<AdminOrgQuotaDto>>, ApiError> {
    let id: OrgId = id.parse().map_err(|_| Error::NotFound { what: format!("organization {}", clip(&id)) })?;
    // An absent field is refused rather than read as one of the three states. `null` here means
    // "clear the override" and is a real request; `{}` means the caller sent nothing, and
    // answering 200 to it would report a quota nobody set.
    let Some(quota) = body.storage_quota_bytes else {
        return Err(ApiError(Error::Invalid { message: "no fields were supplied".to_owned() }));
    };
    // The body parses a **signed** number (see `AdminOrgPatchBody`) so that a negative arrives
    // here as a value rather than dying inside serde as a 422 outside the error envelope: the
    // refusal is `AdminService::set_org_storage_quota`'s, which is where the sentence explaining
    // `0` and `null` lives, and it is unreachable unless a negative parses. The other direction
    // — above `i64::MAX` — is the deserializer's 422 and stays that way; widening the parse to
    // catch it was tried and `serde_json` refuses `i128` at the number, which took the negative
    // case down with it.
    let now = (state.clock)();
    let org = state.admin.set_org_storage_quota(id, quota, &actor_meta(&auth, &meta), now).await?;
    let effective = pub_registry::publish::effective_storage_quota(
        org.storage_quota_bytes,
        state.runtime.current().registry.storage_quota_bytes,
    );
    Ok(Json(OkEnvelope::new(AdminOrgQuotaDto {
        id: org.id.to_string(),
        slug: org.slug.clone(),
        storage_quota_bytes: quota_out(org.storage_quota_bytes),
        effective_quota_bytes: effective,
    })))
}

/// Projects the stored override onto the wire. Negative rows cannot be written through this
/// surface; one that exists anyway is reported as absent rather than as a negative byte count,
/// which is also how the publish path reads it.
fn quota_out(stored: Option<i64>) -> Option<u64> {
    stored.map(|bytes| bytes.max(0) as u64)
}

/// Clips a caller-supplied path segment before it enters an error message
/// ([S-20.a](../../../../docs/security.md#4-supply-chain--registry-integrity)).
///
/// Every id on this surface is a UUID, so 64 characters is far more than any legitimate value
/// needs and far less than an unbounded reflection: without it a 100 KB path segment comes back
/// in the response body, in the log line, and in whatever aggregator reads either. `manage.rs`
/// clips its own package and version segments the same way.
///
/// `chars`, not bytes: slicing a UTF-8 string at a byte offset panics mid-codepoint, and the
/// segment is attacker-chosen.
fn clip(segment: &str) -> String {
    segment.chars().take(64).collect()
}

/// Query parameters for the audit viewer.
#[derive(Debug, Deserialize, IntoParams)]
pub struct AuditQuery {
    /// Only events in this org (id).
    pub org: Option<String>,
    /// Only events whose dot-namespaced action starts with this prefix, e.g. `org.member.`.
    pub action: Option<String>,
    /// Only events by this actor id. Interpreted per `actor_kind`.
    pub actor: Option<String>,
    /// How to read `actor`: `user` (default) | `token`.
    pub actor_kind: Option<String>,
    /// Only events at or after this time (RFC3339, inclusive).
    pub from: Option<chrono::DateTime<chrono::Utc>>,
    /// Only events before this time (RFC3339, exclusive).
    pub until: Option<chrono::DateTime<chrono::Utc>>,
    /// Opaque cursor from the previous page.
    pub cursor: Option<String>,
    /// Page size, 1..=100 (default 20). Ignored by the export, which sizes its own round trips.
    pub limit: Option<u32>,
}

impl AuditQuery {
    /// Parses the query into the repository filter shared by the viewer and the export.
    ///
    /// One implementation on purpose: an export whose filters resolved differently from the viewer
    /// that produced them would hand somebody a file that does not match what they were looking at.
    fn to_filter(&self) -> Result<AuditFilter, ApiError> {
        let org = self
            .org
            .as_deref()
            .map(|raw| raw.parse::<OrgId>().map_err(|_| Error::Invalid { message: "org must be a UUID".to_owned() }))
            .transpose()?;
        // The actor filter is `(kind, id)`, not an id alone. The two id spaces are distinct UUIDs,
        // so a bare id *looks* unambiguous — but the stored row is keyed on the pair, and a filter
        // that guessed `user` for a token id would silently answer "no events by that actor" for a
        // CLI token that has been publishing all week. The kind is explicit and defaults to `user`.
        let actor = self
            .actor
            .as_deref()
            .map(|raw| {
                let id =
                    raw.parse::<UserId>().map_err(|_| Error::Invalid { message: "actor must be a UUID".to_owned() })?;
                match self.actor_kind.as_deref().unwrap_or("user") {
                    "user" => Ok(AuditActor::User(id)),
                    "token" => Ok(AuditActor::Token(pub_core::TokenId::from_uuid(*id.as_uuid()))),
                    other => {
                        Err(Error::Invalid { message: format!("unknown actor_kind {other:?}: use user or token") })
                    }
                }
            })
            .transpose()?;
        Ok(AuditFilter { org, action_prefix: self.action.clone(), actor, from: self.from, until: self.until })
    }

    /// Validates the resume cursor, which [`Self::to_filter`] does **not** cover.
    ///
    /// A cursor is not part of `AuditFilter` — the repositories take it as a separate argument and
    /// parse it themselves. On the paginated viewer that is fine: the parse error becomes a 400. On
    /// the export it is not, because by the time the repository sees the cursor the walk is already
    /// inside a spawned task and `200 OK` has been committed to the wire — so a typo would spend a
    /// slot of the hourly budget, write an `audit.export` row recording a success that delivered
    /// nothing, and hand the caller exactly the signal S-23 reserves for a genuine mid-walk failure
    /// (a body with no terminator). The prescribed client response to that signal is to retry from
    /// the same cursor, so a caller's bookkeeping bug would spend the whole hour's budget.
    fn validated_cursor(&self) -> Result<Option<String>, ApiError> {
        self.cursor
            .as_deref()
            .map(|raw| {
                raw.parse::<pub_core::audit::AuditId>()
                    .map(|id| id.to_string())
                    .map_err(|_| Error::Invalid { message: format!("malformed cursor: {raw}") })
            })
            .transpose()
            .map_err(ApiError)
    }
}

/// The append-only audit log, newest first (S-22/S-23).
#[utoipa::path(
    get,
    path = "/api/v1/admin/audit",
    tag = "admin",
    security(("bearer_auth" = [])),
    params(AuditQuery),
    responses(
        (status = OK, description = "Audit events, newest first", body = OkEnvelope<ListDto<AuditEventDto>>),
        (status = FORBIDDEN, description = "Not an instance administrator", body = ErrorEnvelope),
        (status = BAD_REQUEST, description = "Malformed cursor or filter", body = ErrorEnvelope),
    )
)]
pub async fn list_audit(
    State(state): State<AppState>,
    InstanceAdmin(_auth): InstanceAdmin,
    QueryParams(query): QueryParams<AuditQuery>,
) -> Result<Json<OkEnvelope<ListDto<AuditEventDto>>>, ApiError> {
    let filter = query.to_filter()?;
    let page = state
        .admin
        .list_audit(&filter, query.cursor.as_deref(), PageParams { cursor: None, limit: query.limit }.limit())
        .await?;
    Ok(Json(OkEnvelope::new(ListDto {
        items: page.items.iter().map(AuditEventDto::from).collect(),
        cursor: page.cursor,
        has_more: page.has_more,
    })))
}

/// The audit export's keyset walk, as a state machine.
///
/// Explicit rather than a `loop` with a flag because the terminator is a state, not a side effect:
/// the only way this stream ends without writing it is a database error mid-walk, which is exactly
/// the "truncated export" a caller must be able to detect.
enum ExportStep {
    /// Read the next page from this cursor; `count` is what has already gone out.
    Page { cursor: Option<String>, count: u64 },
    /// Every row is written; the terminator line is next.
    Terminate { count: u64 },
    /// Nothing more.
    Done,
}

/// Streams the audit log as NDJSON over a keyset walk (S-23).
///
/// One request gets the whole filtered log: the handler walks pages internally and writes each one
/// to the wire before reading the next, so the response is a stream and never a buffer. Three
/// properties are the design and are worth stating where the code is:
///
/// - **Step-up gated** ([S-06.c](../../../../docs/security.md#1-authentication)). S-06's list is
///   about escalation and this grants nothing — but one request hands the caller every actor id, IP
///   and user agent the instance has recorded, which is the highest-value single read on the
///   surface and precisely what a stolen stale admin session is for. The *viewer* stays ungated:
///   the line is bulk, not sensitivity.
/// - **It ends with `{"done":true,"count":N}`.** Once the response head is sent there is no status
///   code left to report a failure, and a silently truncated compliance export is worse than a
///   failed one. A client that does not see the terminator has an incomplete file and can tell.
/// - **It is resumable.** `cursor` accepts the id of the last event a caller received, so a broken
///   connection costs the rows already written and nothing more.
///
/// The response body has no bound, which is [D38](../../../../docs/roadmap.md) — the deadline covers
/// the head and the concurrency permit is released on it. That is unchanged and deliberate here: an
/// export is a long response by design.
#[utoipa::path(
    get,
    path = "/api/v1/admin/audit/export",
    tag = "admin",
    security(("bearer_auth" = [])),
    params(AuditQuery),
    responses(
        (status = OK, description = "The filtered audit log as NDJSON, one event per line, \
                                     terminated by {\"done\":true,\"count\":N}", body = String),
        (status = FORBIDDEN, description = "Not an instance administrator, or step-up required", body = ErrorEnvelope),
        (status = BAD_REQUEST, description = "Malformed cursor or filter", body = ErrorEnvelope),
        (status = TOO_MANY_REQUESTS, description = "Past the per-administrator export budget", body = ErrorEnvelope),
    )
)]
pub async fn export_audit(
    State(state): State<AppState>,
    InstanceAdmin(auth): InstanceAdmin,
    RequestMeta(meta): RequestMeta,
    QueryParams(query): QueryParams<AuditQuery>,
) -> Result<axum::response::Response, ApiError> {
    require_step_up(&state, &auth).await?;
    let now = (state.clock)();
    // Both the filter and the cursor are parsed before the budget is spent and before the response
    // head is committed, so a malformed either costs a 400 rather than one of the twelve exports an
    // administrator gets in an hour plus an audit row claiming an export succeeded.
    let filter = query.to_filter()?;
    let cursor = query.validated_cursor()?;
    // Its own bucket, not the S-24.f read budget this route also rides. That one is 3000 reads a
    // minute per identity, which is the right number for `dart pub get` and the wrong number for a
    // statement that walks the whole audit log: a legitimate admin script in a retry loop is a
    // self-inflicted outage at that rate. Fails **open** like every other cost quota — this is a
    // bound on work, not an access gate, and the gate above it is a fresh second factor.
    match ratelimit::hit(
        state.kv.as_ref(),
        &format!("rl:audit_export:{}", auth.claims.sub),
        EXPORT_BUDGET_PER_HOUR,
        chrono::Duration::hours(1),
        now,
    )
    .await
    {
        Ok(Decision::Allowed) => {}
        Ok(Decision::Limited { retry_after_secs, .. }) => {
            metrics::counter!("rate_limit_trips_total", "limit" => "audit_export").increment(1);
            return Err(ApiError(Error::RateLimited { retry_after_secs }));
        }
        Err(err) => tracing::warn!(error = %err, "audit-export budget unavailable; allowing the request"),
    }

    // The bound that is actually about cost. Acquired before the head is sent so the refusal is a
    // clean 429, and held by the walker for the whole walk — the permit is what the hourly budget
    // cannot be, because a walk outlives the request that started it.
    let Ok(slot) = Arc::clone(&state.export_slots).try_acquire_owned() else {
        metrics::counter!("rate_limit_trips_total", "limit" => "audit_export_concurrent").increment(1);
        return Err(ApiError(Error::RateLimited { retry_after_secs: 30 }));
    };

    // Before a single row leaves, not after the walk: an export that is cut off halfway still
    // happened, and a row appended after a stream that never finished would not exist.
    state.admin.audit_export_requested(&actor_meta(&auth, &meta), &filter, now).await;

    // A bounded channel written by a walker task, the same shape the SSE writer uses. Bounded is
    // the point: the sender blocks while a slow reader drains, so the export's memory is one page
    // and a few chunks rather than the whole log, and a client that disconnects fails the send and
    // ends the walk instead of reading the table for nobody.
    let (tx, rx) = tokio::sync::mpsc::channel::<Result<axum::body::Bytes, std::io::Error>>(4);
    let admin = Arc::clone(&state.admin);
    tokio::spawn(async move {
        // Moved into the walker, not dropped at the end of the handler: the walk is the thing being
        // bounded, and it starts after the handler returns.
        let _slot = slot;
        let mut step = ExportStep::Page { cursor, count: 0 };
        loop {
            let chunk = match step {
                ExportStep::Page { cursor, count } => match admin.export_audit_page(&filter, cursor.as_deref()).await {
                    Ok(page) => {
                        let mut body = String::new();
                        let mut failed = None;
                        for event in &page.items {
                            match serde_json::to_string(&AuditEventDto::from(event)) {
                                Ok(line) => {
                                    body.push_str(&line);
                                    body.push('\n');
                                }
                                Err(err) => {
                                    failed = Some(format!("encoding an audit event: {err}"));
                                    break;
                                }
                            }
                        }
                        if let Some(message) = failed {
                            step = ExportStep::Done;
                            Err(std::io::Error::other(message))
                        } else {
                            let count = count + page.items.len() as u64;
                            // A page that claims more but hands back no cursor cannot be continued
                            // (resuming from the top would make a bounded export unbounded) and must
                            // not be *terminated* either: writing `{"done":true}` there would be the
                            // one outcome decision 30 forbids — a truncated export declaring itself
                            // whole. It ends the body without a terminator, which is the same signal
                            // a mid-walk database error gives, and the caller can tell.
                            match (page.has_more, page.cursor) {
                                (true, Some(next)) => {
                                    step = ExportStep::Page { cursor: Some(next), count };
                                    Ok(axum::body::Bytes::from(body))
                                }
                                (true, None) => {
                                    tracing::error!(
                                        "audit export page claimed more rows with no cursor; \
                                         ending the body without a terminator"
                                    );
                                    step = ExportStep::Done;
                                    Err(std::io::Error::other("export cursor did not advance"))
                                }
                                (false, _) => {
                                    step = ExportStep::Terminate { count };
                                    Ok(axum::body::Bytes::from(body))
                                }
                            }
                        }
                    }
                    Err(err) => {
                        // The stream ends without its terminator, which is how the caller learns
                        // the file is incomplete.
                        tracing::error!(error = %err, "audit export failed mid-stream");
                        step = ExportStep::Done;
                        Err(std::io::Error::other(err.to_string()))
                    }
                },
                ExportStep::Terminate { count } => {
                    step = ExportStep::Done;
                    Ok(axum::body::Bytes::from(format!("{}\n", serde_json::json!({ "done": true, "count": count }))))
                }
                ExportStep::Done => break,
            };
            let failed = chunk.is_err();
            if tx.send(chunk).await.is_err() || failed {
                break;
            }
        }
    });
    let stream = tokio_stream::wrappers::ReceiverStream::new(rx);

    axum::response::Response::builder()
        .header(axum::http::header::CONTENT_TYPE, "application/x-ndjson")
        // The export is a snapshot of an append-only table read through a cursor; nothing about it
        // is cacheable, and S-28 already says so for every API response.
        .header(axum::http::header::CACHE_CONTROL, "no-store")
        .body(axum::body::Body::from_stream(stream))
        .map_err(|err| ApiError(Error::Internal { message: format!("building the export response: {err}") }))
}

/// Instance counters, storage, the supply-chain registers, and job state.
#[utoipa::path(
    get,
    path = "/api/v1/admin/stats",
    tag = "admin",
    security(("bearer_auth" = [])),
    responses(
        (status = OK, description = "Instance statistics", body = OkEnvelope<AdminStatsDto>),
        (status = FORBIDDEN, description = "Not an instance administrator", body = ErrorEnvelope),
    )
)]
pub async fn stats(
    State(state): State<AppState>,
    InstanceAdmin(_auth): InstanceAdmin,
) -> Result<Json<OkEnvelope<AdminStatsDto>>, ApiError> {
    let now = (state.clock)();
    let stats = state.admin.stats(now).await?;
    Ok(Json(OkEnvelope::new(AdminStatsDto {
        users: UserCountsDto {
            total: stats.users.total,
            active: stats.users.active,
            suspended: stats.users.suspended,
            deleted: stats.users.deleted,
            admins: stats.users.admins,
        },
        orgs: stats.orgs,
        registry: RegistryStatsDto {
            packages: stats.registry.packages,
            public_packages: stats.registry.public_packages,
            versions: stats.registry.versions,
            retracted_versions: stats.registry.retracted_versions,
            tombstoned_versions: stats.registry.tombstoned_versions,
            archive_bytes: stats.registry.archive_bytes,
        },
        upstream_cache: UpstreamCacheStatsDto {
            packages: stats.upstream_cache.packages,
            versions: stats.upstream_cache.versions,
            cached_versions: stats.upstream_cache.cached_versions,
            cached_bytes: stats.upstream_cache.cached_bytes,
        },
        // The same conversion the full registers use, so the dashboard sample and the paged
        // listing can never disagree about what a row looks like.
        quarantine: stats.quarantine.iter().map(QuarantineDto::from).collect(),
        shadowing: stats.shadowing.iter().map(ShadowingDto::from).collect(),
        shadowing_active: stats.shadowing_active,
        jobs: stats
            .jobs
            .iter()
            .map(|job| JobStateDto {
                name: job.name.clone(),
                phase: job.phase.clone(),
                last_run_at: job.last_run_at,
                last_success_at: job.last_success_at,
                lag_seconds: job.lag_seconds(now),
                last_error: job.last_error.clone(),
                runs: job.runs,
                processed: job.processed,
                failures: job.failures,
            })
            .collect(),
        runnable_jobs: stats.runnable_jobs,
        settings_version: stats.settings_version,
    })))
}

/// Runs a background job now.
#[utoipa::path(
    post,
    path = "/api/v1/admin/jobs/{job}/run",
    tag = "admin",
    security(("bearer_auth" = [])),
    params(("job" = String, Path, description = "Job name, from `runnable_jobs` in /admin/stats")),
    responses(
        (status = OK, description = "The job's own summary", body = OkEnvelope<JobRunDto>),
        (status = CONFLICT, description = "Already running somewhere in the cluster", body = ErrorEnvelope),
        (status = FORBIDDEN, description = "Not an instance administrator", body = ErrorEnvelope),
        (status = NOT_FOUND, description = "Unknown or disabled job on this instance", body = ErrorEnvelope),
    )
)]
pub async fn run_job(
    State(state): State<AppState>,
    InstanceAdmin(auth): InstanceAdmin,
    RequestMeta(meta): RequestMeta,
    Path(job): Path<String>,
) -> Result<Json<OkEnvelope<JobRunDto>>, ApiError> {
    let now = (state.clock)();
    let summary = state.admin.run_job(&job, &actor_meta(&auth, &meta), now).await?;
    Ok(Json(OkEnvelope::new(JobRunDto { job, summary })))
}

// ------------------------------------------------------------------- supply-chain registers

/// Query parameters of the shadowing register.
#[derive(Debug, Deserialize, IntoParams)]
pub struct ShadowingQuery {
    /// `true` = only alarms still asking for attention, `false` = only acknowledged ones,
    /// absent = the whole register.
    pub active: Option<bool>,
    /// Opaque cursor from the previous page.
    pub cursor: Option<String>,
    /// Page size, 1..=100 (default 20).
    pub limit: Option<u32>,
}

/// The quarantine register: upstream archives the proxy refused
/// ([S-19.b](../../../../docs/security.md#4-supply-chain--registry-integrity)).
///
/// Instance-admin, newest observation first. The dashboard shows the newest twenty of these
/// inside `/admin/stats`; this is the register behind that sample, and it is the surface an
/// operator investigating a supply-chain incident actually needs.
///
/// There is no delete and no acknowledge. A quarantine row is evidence written *after* the
/// bytes were already refused, so nothing here can change what the proxy serves — and a row an
/// admin session could clear is a row an attacker with one could clear.
#[utoipa::path(
    get,
    path = "/api/v1/admin/quarantine",
    tag = "admin",
    security(("bearer_auth" = [])),
    params(PageParams),
    responses(
        (status = OK, description = "Refused upstream archives, newest first", body = OkEnvelope<ListDto<QuarantineDto>>),
        (status = FORBIDDEN, description = "Not an instance administrator", body = ErrorEnvelope),
        (status = BAD_REQUEST, description = "Malformed cursor", body = ErrorEnvelope),
    )
)]
pub async fn list_quarantine(
    State(state): State<AppState>,
    InstanceAdmin(_auth): InstanceAdmin,
    QueryParams(params): QueryParams<PageParams>,
) -> Result<Json<OkEnvelope<ListDto<QuarantineDto>>>, ApiError> {
    let page = state.admin.list_quarantine(params.cursor.as_deref(), params.limit()).await?;
    Ok(Json(OkEnvelope::new(ListDto {
        items: page.items.iter().map(QuarantineDto::from).collect(),
        cursor: page.cursor,
        has_more: page.has_more,
    })))
}

/// The shadowing register: locally claimed names observed upstream
/// ([S-17.b](../../../../docs/security.md#4-supply-chain--registry-integrity)).
///
/// Instance-admin, newest sighting first, sliced by `active`. Reading it does not change
/// resolution and never could: the local package wins by decision 01, before and after.
#[utoipa::path(
    get,
    path = "/api/v1/admin/shadowing",
    tag = "admin",
    security(("bearer_auth" = [])),
    params(ShadowingQuery),
    responses(
        (status = OK, description = "Shadowing alarms, newest sighting first", body = OkEnvelope<ListDto<ShadowingDto>>),
        (status = FORBIDDEN, description = "Not an instance administrator", body = ErrorEnvelope),
        (status = BAD_REQUEST, description = "Malformed cursor", body = ErrorEnvelope),
    )
)]
pub async fn list_shadowing(
    State(state): State<AppState>,
    InstanceAdmin(_auth): InstanceAdmin,
    QueryParams(query): QueryParams<ShadowingQuery>,
) -> Result<Json<OkEnvelope<ListDto<ShadowingDto>>>, ApiError> {
    let limit = PageParams { cursor: None, limit: query.limit }.limit();
    let page = state.admin.list_shadowing(query.active, query.cursor.as_deref(), limit).await?;
    Ok(Json(OkEnvelope::new(ListDto {
        items: page.items.iter().map(ShadowingDto::from).collect(),
        cursor: page.cursor,
        has_more: page.has_more,
    })))
}

/// Acknowledges one shadowing alarm (S-17.b) — bookkeeping, never policy.
///
/// **Not step-up gated** (S-06.b: the list is about escalation). It grants nothing, deletes
/// nothing, and changes no resolution; the next upstream sighting raises the alarm again as a
/// new incident. `acknowledged: false` means there was no *active* alarm under that key — an
/// unknown name and an already-acknowledged one answer the same way, and neither writes a row.
#[utoipa::path(
    post,
    path = "/api/v1/admin/shadowing/{format}/{name}/acknowledge",
    tag = "admin",
    security(("bearer_auth" = [])),
    params(
        ("format" = String, Path, description = "Artifact format, e.g. `pub`"),
        ("name" = String, Path, description = "The shadowed package name"),
    ),
    responses(
        (status = OK, description = "Whether an active alarm was acknowledged", body = OkEnvelope<ShadowingAckDto>),
        (status = BAD_REQUEST, description = "Unknown artifact format", body = ErrorEnvelope),
        (status = FORBIDDEN, description = "Not an instance administrator", body = ErrorEnvelope),
    )
)]
pub async fn acknowledge_shadowing(
    State(state): State<AppState>,
    InstanceAdmin(auth): InstanceAdmin,
    RequestMeta(meta): RequestMeta,
    Path((format, name)): Path<(String, String)>,
) -> Result<Json<OkEnvelope<ShadowingAckDto>>, ApiError> {
    let format: pub_core::Format = format.parse()?;
    let now = (state.clock)();
    // The name is clipped before it reaches the service, like every other attacker-chosen path
    // segment on this surface: it travels into an audit row and an error message.
    let acknowledged = state.admin.acknowledge_shadowing(format, &clip(&name), &actor_meta(&auth, &meta), now).await?;
    Ok(Json(OkEnvelope::new(ShadowingAckDto { acknowledged })))
}

// --------------------------------------------------------------------------------- mapping

/// Projects the service's credential-free view onto the wire DTO.
fn settings_dto(view: pub_admin::SettingsView) -> AdminSettingsDto {
    AdminSettingsDto {
        version: view.version,
        registration: RegistrationSettingsDto {
            mode: view.registration.mode.as_str().to_owned(),
            allowed_email_domains: view.registration.allowed_email_domains,
        },
        rate_limits: RateLimitSettingsDto {
            otp_per_email_hour: view.rate_limits.otp_per_email_hour,
            otp_per_ip_hour: view.rate_limits.otp_per_ip_hour,
            login_per_ip_minute: view.rate_limits.login_per_ip_minute,
            token_auth_fail_per_ip_minute: view.rate_limits.token_auth_fail_per_ip_minute,
            publish_per_hour_org: view.rate_limits.publish_per_hour_org,
            read_per_ip_minute: view.rate_limits.read_per_ip_minute,
            read_per_identity_minute: view.rate_limits.read_per_identity_minute,
            write_per_ip_minute: view.rate_limits.write_per_ip_minute,
            write_per_identity_minute: view.rate_limits.write_per_identity_minute,
            invitations_per_day_org: view.rate_limits.invitations_per_day_org,
            invitations_per_day_actor: view.rate_limits.invitations_per_day_actor,
        },
        smtp: SmtpSettingsDto {
            host: view.smtp.host,
            port: view.smtp.port,
            username: view.smtp.username,
            from: view.smtp.from,
            security: view.smtp.security,
            password_set: view.smtp.password_set,
        },
        branding: BrandingSettingsDto {
            name: view.branding.name,
            tagline: view.branding.tagline,
            logo_url: view.branding.logo_url,
            primary_color: view.branding.primary_color,
        },
        upstream: UpstreamSettingsDto {
            enabled: view.upstream.enabled,
            default_org_policy: view.upstream.default_org_policy.as_str().to_owned(),
        },
        registry: RegistrySettingsDto {
            require_auth_for_read: view.registry.require_auth_for_read,
            storage_quota_bytes: view.registry.storage_quota_bytes,
        },
    }
}

/// Parses the registration section, rejecting unknown modes rather than defaulting them.
fn registration_from(dto: RegistrationSettingsDto) -> Result<RegistrationSettings, ApiError> {
    Ok(RegistrationSettings {
        mode: dto.mode.parse::<RegistrationMode>()?,
        allowed_email_domains: dto.allowed_email_domains,
    })
}

/// Parses the upstream section.
fn upstream_from(dto: UpstreamSettingsDto) -> Result<UpstreamSettings, ApiError> {
    Ok(UpstreamSettings {
        enabled: dto.enabled,
        default_org_policy: dto.default_org_policy.parse::<pub_core::org::UpstreamPolicy>()?,
    })
}

/// Carries the SMTP section across, password included (it is sealed one layer down).
fn smtp_from(dto: SmtpSettingsPatchDto) -> SmtpPatch {
    SmtpPatch {
        host: dto.host,
        port: dto.port,
        username: dto.username,
        from: dto.from,
        security: dto.security,
        password: dto.password,
    }
}
