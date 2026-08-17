//! The caller's own account ([S-29](../../../../docs/security.md#7-platform), decision 39):
//! profile, the address change that proves both ends, the export, and the deletion.
//!
//! Four of these six routes are step-up gated, which is unusual density for one module and is the
//! point: everything here either changes what an account *is* or hands over everything the
//! instance knows about it. The one that is not gated is `GET /me`, and the one that changes only
//! a display name is not either — S-06's list is about escalation and bulk, and prompting for a
//! second factor to fix a typo is how a prompt becomes noise people click through.

use std::sync::Arc;

use axum::Json;
use axum::extract::State;
use axum::response::IntoResponse as _;
use pub_core::Error;
use pub_core::user::User;

use crate::dto::{
    AccountDeleteBody, AccountDeletedDto, AuditEventDto, EmailChangeBody, EmailChangeStartedDto, EmailChangeVerifyBody,
    MeDto, NotificationDto, OrgMembershipDto, ProfileUpdateBody, SessionDto, TokenDto,
};
use crate::envelope::{ErrorEnvelope, OkEnvelope};
use crate::error::ApiError;
use crate::extract::{AuthContext, RequestMeta, StepUp};
use crate::routes::actor_meta;
use crate::state::AppState;

/// How many exports one account may take per hour.
///
/// The same shape as the audit export's budget and for the same reason: this is a bound on *work*
/// rather than an access gate — the gate is a fresh second factor — so it fails open like every
/// other cost quota. Twelve is far past any real use of a "download my data" button and far below
/// what a script in a retry loop would cost the database.
const EXPORT_BUDGET_PER_HOUR: u32 = 12;

/// The caller's account row plus whether a second factor is enrolled.
#[utoipa::path(
    get,
    path = "/api/v1/me",
    tag = "account",
    security(("bearer_auth" = [])),
    responses(
        (status = OK, description = "The caller's account", body = OkEnvelope<MeDto>),
        (status = UNAUTHORIZED, description = "Missing or invalid access token", body = ErrorEnvelope),
    )
)]
pub async fn me(State(state): State<AppState>, auth: AuthContext) -> Result<Json<OkEnvelope<MeDto>>, ApiError> {
    let profile = state.accounts.profile(auth.claims.sub).await?;
    Ok(Json(OkEnvelope::new(MeDto::from(&profile))))
}

/// Renames the account.
#[utoipa::path(
    patch,
    path = "/api/v1/me",
    tag = "account",
    security(("bearer_auth" = [])),
    request_body = ProfileUpdateBody,
    responses(
        (status = OK, description = "Updated account", body = OkEnvelope<MeDto>),
        (status = BAD_REQUEST, description = "Empty, overlong, or control-bearing name", body = ErrorEnvelope),
        (status = UNAUTHORIZED, description = "Missing or invalid access token", body = ErrorEnvelope),
    )
)]
pub async fn update_profile(
    State(state): State<AppState>,
    auth: AuthContext,
    RequestMeta(meta): RequestMeta,
    Json(body): Json<ProfileUpdateBody>,
) -> Result<Json<OkEnvelope<MeDto>>, ApiError> {
    let user = current_user(&state, &auth).await?;
    let now = (state.clock)();
    state.accounts.rename(&user, &body.display_name, &actor_meta(&auth, &meta), now).await?;
    let profile = state.accounts.profile(auth.claims.sub).await?;
    Ok(Json(OkEnvelope::new(MeDto::from(&profile))))
}

/// Starts an email change: a code goes to the **new** address; nothing on the account moves yet.
///
/// **Step-up gated** (S-06 has listed "changing email" since the first draft; this is the
/// endpoint it was waiting for).
#[utoipa::path(
    post,
    path = "/api/v1/me/email",
    tag = "account",
    security(("bearer_auth" = [])),
    request_body = EmailChangeBody,
    responses(
        (status = OK, description = "A confirmation code was queued", body = OkEnvelope<EmailChangeStartedDto>),
        (status = BAD_REQUEST, description = "Malformed address, the current one, or a blocked domain", body = ErrorEnvelope),
        (status = CONFLICT, description = "The address already belongs to an account", body = ErrorEnvelope),
        (status = FORBIDDEN, description = "step_up_required — re-authenticate first", body = ErrorEnvelope),
        (status = TOO_MANY_REQUESTS, description = "Per-account or per-address budget spent", body = ErrorEnvelope),
    )
)]
pub async fn request_email_change(
    State(state): State<AppState>,
    StepUp(auth): StepUp,
    RequestMeta(meta): RequestMeta,
    Json(body): Json<EmailChangeBody>,
) -> Result<Json<OkEnvelope<EmailChangeStartedDto>>, ApiError> {
    let user = current_user(&state, &auth).await?;
    let now = (state.clock)();
    let pending_id = state.auth.request_email_change(&user, &body.email, &meta, now).await?;
    Ok(Json(OkEnvelope::new(EmailChangeStartedDto { pending_id, email: body.email.trim().to_lowercase() })))
}

/// Confirms an email change and moves the address.
///
/// **Step-up gated**, at both ends of the flow: a stale session that somehow reached the request
/// must not be able to finish it fifteen minutes later.
#[utoipa::path(
    post,
    path = "/api/v1/me/email/verify",
    tag = "account",
    security(("bearer_auth" = [])),
    request_body = EmailChangeVerifyBody,
    responses(
        (status = OK, description = "The address moved", body = OkEnvelope<MeDto>),
        (status = BAD_REQUEST, description = "invalid_code — unknown, expired, wrong, or spent", body = ErrorEnvelope),
        (status = CONFLICT, description = "The address was taken while the code was in flight", body = ErrorEnvelope),
        (status = FORBIDDEN, description = "step_up_required — re-authenticate first", body = ErrorEnvelope),
    )
)]
pub async fn verify_email_change(
    State(state): State<AppState>,
    StepUp(auth): StepUp,
    RequestMeta(meta): RequestMeta,
    Json(body): Json<EmailChangeVerifyBody>,
) -> Result<Json<OkEnvelope<MeDto>>, ApiError> {
    let user = current_user(&state, &auth).await?;
    let now = (state.clock)();
    state.auth.confirm_email_change(&user, &body.pending_id, &body.code, &meta, now).await?;
    let profile = state.accounts.profile(auth.claims.sub).await?;
    Ok(Json(OkEnvelope::new(MeDto::from(&profile))))
}

/// Deletes the account: erases the identity, keeps the attribution (S-29.a).
///
/// **Step-up gated and confirmation-guarded** (S-06.b). Irreversible, with no grace period and no
/// operator-side restore — decision 39 records that as the owner's choice rather than an omission.
#[utoipa::path(
    delete,
    path = "/api/v1/me",
    tag = "account",
    security(("bearer_auth" = [])),
    request_body = AccountDeleteBody,
    responses(
        (status = OK, description = "The account is a tombstone", body = OkEnvelope<AccountDeletedDto>),
        (status = BAD_REQUEST, description = "confirm does not repeat the account's address", body = ErrorEnvelope),
        (status = CONFLICT, description = "The caller is the last owner of an organization", body = ErrorEnvelope),
        (status = FORBIDDEN, description = "step_up_required — re-authenticate first", body = ErrorEnvelope),
    )
)]
pub async fn delete_account(
    State(state): State<AppState>,
    StepUp(auth): StepUp,
    RequestMeta(meta): RequestMeta,
    Json(body): Json<AccountDeleteBody>,
) -> Result<Json<OkEnvelope<AccountDeletedDto>>, ApiError> {
    let user = current_user(&state, &auth).await?;
    // Every account that can reach this endpoint has an address: `None` belongs to the tombstone,
    // and a tombstone cannot authenticate. Fail closed anyway rather than let an empty `confirm`
    // match an absent address.
    let Some(address) = user.email.as_deref() else {
        return Err(Error::Invalid { message: "this account has no address to confirm with".to_owned() }.into());
    };
    if !body.confirm.trim().eq_ignore_ascii_case(address) {
        return Err(Error::Invalid { message: "confirm must repeat the account's email address".to_owned() }.into());
    }
    let now = (state.clock)();
    let outcome = state.accounts.delete(&user, &actor_meta(&auth, &meta), now).await?;
    Ok(Json(OkEnvelope::new(AccountDeletedDto::from(outcome))))
}

/// Streams everything the instance holds about the caller as NDJSON (S-29.b).
///
/// The shape is the S-23 audit export's, deliberately: a bounded channel written by a walker
/// task, one record per line, and an explicit `{"done":true}` terminator whose **absence** is how
/// a caller learns the file is incomplete. **Step-up gated** for S-06.c's reason — the line is
/// bulk, not sensitivity, and one request hands over every IP address the instance recorded.
#[utoipa::path(
    get,
    path = "/api/v1/me/export",
    tag = "account",
    security(("bearer_auth" = [])),
    responses(
        (status = OK, description = "NDJSON export, terminated by {\"done\":true}", content_type = "application/x-ndjson"),
        (status = FORBIDDEN, description = "step_up_required — re-authenticate first", body = ErrorEnvelope),
        (status = TOO_MANY_REQUESTS, description = "Hourly export budget spent", body = ErrorEnvelope),
    )
)]
pub async fn export(State(state): State<AppState>, StepUp(auth): StepUp) -> Result<axum::response::Response, ApiError> {
    let now = (state.clock)();
    let user = auth.claims.sub;
    match pub_auth::ratelimit::hit(
        state.kv.as_ref(),
        &format!("rl:account_export:{user}"),
        EXPORT_BUDGET_PER_HOUR,
        chrono::Duration::hours(1),
        now,
    )
    .await
    {
        Ok(pub_auth::ratelimit::Decision::Allowed) => {}
        Ok(pub_auth::ratelimit::Decision::Limited { retry_after_secs, .. }) => {
            metrics::counter!("rate_limit_trips_total", "limit" => "account_export").increment(1);
            return Err(ApiError(Error::RateLimited { retry_after_secs }));
        }
        Err(err) => tracing::warn!(error = %err, "account-export budget unavailable; allowing the request"),
    }

    // The same permit pool the audit export holds. One pool, because the resource is identical —
    // this instance's database pool, held by a walk that outlives the response head — and two
    // would only let the two exports starve each other in a different order.
    let Ok(slot) = Arc::clone(&state.export_slots).try_acquire_owned() else {
        metrics::counter!("rate_limit_trips_total", "limit" => "account_export_concurrent").increment(1);
        return Err(ApiError(Error::RateLimited { retry_after_secs: 30 }));
    };

    // The bounded half is read before the head is committed: it is five small queries, and a
    // failure here is a clean 500 rather than a truncated file that looks like a network problem.
    let snapshot = state.accounts.snapshot(user).await?;
    let sid = auth.claims.sid;

    let (tx, rx) = tokio::sync::mpsc::channel::<Result<axum::body::Bytes, std::io::Error>>(4);
    let accounts = Arc::clone(&state.accounts);
    tokio::spawn(async move {
        let _slot = slot;
        let mut body = String::new();
        // A header line first, so a file that ends early still says whose it is and when it was
        // taken — the two facts a truncated export is otherwise missing entirely.
        let mut records = vec![
            serde_json::json!({ "section": "meta", "user_id": user.to_string(), "generated_at": now }),
            serde_json::json!({ "section": "profile", "record": MeDto::from(&snapshot.profile) }),
        ];
        records.extend(snapshot.memberships.iter().map(|membership| {
            serde_json::json!({ "section": "organizations", "record": OrgMembershipDto::from(membership) })
        }));
        records.extend(snapshot.sessions.iter().map(
            |session| serde_json::json!({ "section": "sessions", "record": SessionDto::from_session(session, sid) }),
        ));
        records.extend(
            snapshot
                .tokens
                .iter()
                .map(|token| serde_json::json!({ "section": "tokens", "record": TokenDto::from(token) })),
        );
        records.extend(snapshot.preferences.iter().map(|preference| {
            serde_json::json!({
                "section": "notification_preferences",
                "record": {
                    "category": preference.category.as_str(),
                    "in_app": preference.in_app,
                    "email": preference.email,
                },
            })
        }));
        for record in &records {
            if !push(&mut body, record) {
                return;
            }
        }
        if tx.send(Ok(axum::body::Bytes::from(std::mem::take(&mut body)))).await.is_err() {
            return;
        }

        // The two unbounded sections, each walked by its own keyset cursor. A page that claims
        // more rows and hands back no cursor cannot be continued and must not be *terminated*
        // either: the body ends without `{"done":true}`, which is the same signal a mid-walk
        // database error gives, and the caller can tell.
        let mut cursor: Option<String> = None;
        loop {
            let page = match accounts.export_notifications_page(user, cursor.as_deref()).await {
                Ok(page) => page,
                Err(error) => {
                    tracing::error!(%error, "account export failed inside the notification walk");
                    return;
                }
            };
            let mut chunk = String::new();
            for notification in &page.items {
                let record =
                    serde_json::json!({ "section": "notifications", "record": NotificationDto::from(notification) });
                if !push(&mut chunk, &record) {
                    return;
                }
            }
            if tx.send(Ok(axum::body::Bytes::from(chunk))).await.is_err() {
                return;
            }
            match (page.has_more, page.cursor) {
                (true, Some(next)) => cursor = Some(next),
                (true, None) => {
                    tracing::error!("notification export page claimed more rows with no cursor");
                    return;
                }
                (false, _) => break,
            }
        }

        let mut cursor: Option<String> = None;
        loop {
            let page = match accounts.export_audit_page(user, cursor.as_deref()).await {
                Ok(page) => page,
                Err(error) => {
                    tracing::error!(%error, "account export failed inside the audit walk");
                    return;
                }
            };
            let mut chunk = String::new();
            for event in &page.items {
                let record = serde_json::json!({ "section": "audit", "record": AuditEventDto::from(event) });
                if !push(&mut chunk, &record) {
                    return;
                }
            }
            if tx.send(Ok(axum::body::Bytes::from(chunk))).await.is_err() {
                return;
            }
            match (page.has_more, page.cursor) {
                (true, Some(next)) => cursor = Some(next),
                (true, None) => {
                    tracing::error!("audit export page claimed more rows with no cursor");
                    return;
                }
                (false, _) => break,
            }
        }

        let _ = tx.send(Ok(axum::body::Bytes::from("{\"done\":true}\n"))).await;
    });

    let stream = tokio_stream::wrappers::ReceiverStream::new(rx);
    let mut response = axum::body::Body::from_stream(stream).into_response();
    response
        .headers_mut()
        .insert(axum::http::header::CONTENT_TYPE, axum::http::HeaderValue::from_static("application/x-ndjson"));
    Ok(response)
}

/// Appends one NDJSON record; `false` means the walk must stop.
///
/// A record that cannot be encoded **ends the export without its terminator**, which is the same
/// signal a mid-walk database error gives. Skipping it instead would produce the one outcome
/// [decision 30](../../../../docs/decisions.md#30--retention-one-window-per-table-a-delete-that-stays-bounded-and-a-privilege-that-survives-the-feature)
/// forbids for the audit export and S-29.b inherits: a file that is missing rows and declares
/// itself whole.
fn push(body: &mut String, value: &serde_json::Value) -> bool {
    match serde_json::to_string(value) {
        Ok(line) => {
            body.push_str(&line);
            body.push('\n');
            true
        }
        Err(error) => {
            tracing::error!(%error, "encoding an export record; ending the body without a terminator");
            false
        }
    }
}

/// Loads the account behind the request, or fails the way a revoked one should.
///
/// `AuthContext` proves a *token* is valid; this proves the account behind it still exists. They
/// are not the same question for as long as an access token outlives a deletion by up to one TTL.
async fn current_user(state: &AppState, auth: &AuthContext) -> Result<User, ApiError> {
    state
        .repos
        .users
        .get(auth.claims.sub)
        .await?
        .filter(|user| user.status == pub_core::user::UserStatus::Active)
        .ok_or_else(|| ApiError(Error::Unauthorized { message: "account unavailable".to_owned() }))
}
