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

use axum::Json;
use axum::extract::{Path, State};
use pub_admin::instance::{SettingsPatch, SmtpPatch};
use pub_core::audit::{AuditActor, AuditFilter};
use pub_core::settings::{
    BrandingSettings, RateLimitSettings, RegistrationMode, RegistrationSettings, UpstreamSettings,
};
use pub_core::user::{UserFilter, UserStatus};
use pub_core::{Error, OrgId, UserId};
use serde::Deserialize;
use utoipa::IntoParams;

use crate::dto::{
    AdminOrgDto, AdminSettingsDto, AdminSettingsPatchBody, AdminStatsDto, AdminUserDto, AuditEventDto,
    BrandingSettingsDto, JobRunDto, JobStateDto, ListDto, OrgDto, QuarantineDto, RateLimitSettingsDto,
    RegistrationSettingsDto, ShadowingDto, SmtpSettingsDto, UpstreamCacheStatsDto, UpstreamSettingsDto, UserCountsDto,
};
use crate::dto::{RegistryStatsDto, SmtpSettingsPatchDto};
use crate::envelope::{ErrorEnvelope, OkEnvelope};
use crate::error::ApiError;
use crate::extract::{InstanceAdmin, QueryParams, RequestMeta};
use crate::routes::actor_meta;
use crate::routes::packages::PageParams;
use crate::state::AppState;

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
        }),
        smtp: body.smtp.map(smtp_from),
        branding: body.branding.map(|branding| BrandingSettings {
            name: branding.name,
            tagline: branding.tagline,
            logo_url: branding.logo_url,
            primary_color: branding.primary_color,
        }),
        upstream: body.upstream.map(upstream_from).transpose()?,
    };
    let now = (state.clock)();
    let view = state.admin.update_settings(patch, &actor_meta(&auth, &meta), now).await?;
    Ok(Json(OkEnvelope::new(settings_dto(view))))
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
    let id: UserId = id.parse().map_err(|_| Error::NotFound { what: format!("user {id}") })?;
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
    Ok(Json(OkEnvelope::new(ListDto {
        items: page
            .items
            .iter()
            .map(|row| AdminOrgDto { org: OrgDto::from(&row.org), members: row.members, packages: row.packages })
            .collect(),
        cursor: page.cursor,
        has_more: page.has_more,
    })))
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
    /// Page size, 1..=100 (default 20).
    pub limit: Option<u32>,
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
    let org = query
        .org
        .as_deref()
        .map(|raw| raw.parse::<OrgId>().map_err(|_| Error::Invalid { message: "org must be a UUID".to_owned() }))
        .transpose()?;
    // The actor filter is `(kind, id)`, not an id alone. The two id spaces are distinct UUIDs,
    // so a bare id *looks* unambiguous — but the stored row is keyed on the pair, and a filter
    // that guessed `user` for a token id would silently answer "no events by that actor" for a
    // CLI token that has been publishing all week. The kind is explicit and defaults to `user`.
    let actor = query
        .actor
        .as_deref()
        .map(|raw| {
            let id =
                raw.parse::<UserId>().map_err(|_| Error::Invalid { message: "actor must be a UUID".to_owned() })?;
            match query.actor_kind.as_deref().unwrap_or("user") {
                "user" => Ok(AuditActor::User(id)),
                "token" => Ok(AuditActor::Token(pub_core::TokenId::from_uuid(*id.as_uuid()))),
                other => Err(Error::Invalid { message: format!("unknown actor_kind {other:?}: use user or token") }),
            }
        })
        .transpose()?;
    let filter = AuditFilter { org, action_prefix: query.action.clone(), actor, from: query.from, until: query.until };
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
        quarantine: stats
            .quarantine
            .iter()
            .map(|entry| QuarantineDto {
                name: entry.name.clone(),
                version: entry.version.clone(),
                upstream: entry.upstream.clone(),
                expected_sha256: entry.expected_sha256.clone(),
                actual_sha256: entry.actual_sha256.clone(),
                occurrences: entry.occurrences,
                last_seen_at: entry.last_seen_at,
            })
            .collect(),
        shadowing: stats
            .shadowing
            .iter()
            .map(|alarm| ShadowingDto {
                name: alarm.name.clone(),
                org_id: alarm.org_id.to_string(),
                upstream: alarm.upstream.clone(),
                upstream_version: alarm.upstream_version.clone(),
                observations: alarm.observations,
                active: alarm.is_active(),
                last_seen_at: alarm.last_seen_at,
            })
            .collect(),
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
