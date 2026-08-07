//! The notification center's REST surface (decision 20): the feed, the unread badge, marking
//! read, and per-category delivery preferences.
//!
//! Every route here is scoped to the caller and to nobody else — there is no `user_id`
//! parameter anywhere in this module, so a notification belonging to another account is not
//! addressable, let alone readable. The repository re-states the same rule in SQL, which is
//! what makes it a property rather than a convention.

use axum::Json;
use axum::extract::State;
use pub_core::Error;
use pub_core::NotificationId;
use pub_core::notification::{NotificationCategory, NotificationPreference, NotificationPreferences};
use serde::Deserialize;
use utoipa::IntoParams;

use crate::dto::{
    NotificationDto, NotificationFeedDto, NotificationPreferenceDto, NotificationPreferencesBody,
    NotificationPreferencesDto, NotificationsReadBody, NotificationsReadDto,
};
use crate::envelope::{ErrorEnvelope, OkEnvelope};
use crate::error::ApiError;
use crate::extract::{AuthContext, QueryParams};
use crate::state::AppState;

/// Default page size.
const DEFAULT_LIMIT: u32 = 20;

/// Largest page this surface returns.
const MAX_LIMIT: u32 = 100;

/// Query parameters for the feed.
#[derive(Debug, Deserialize, IntoParams)]
pub struct FeedParams {
    /// Only unread notifications.
    pub unread: Option<bool>,
    /// Opaque cursor from the previous page.
    pub cursor: Option<String>,
    /// Page size, 1..=100 (default 20).
    pub limit: Option<u32>,
}

/// The caller's notification feed, newest first, with the unread count.
#[utoipa::path(
    get,
    path = "/api/v1/notifications",
    tag = "notifications",
    security(("bearer_auth" = [])),
    params(FeedParams),
    responses(
        (status = OK, description = "Notifications, newest first, plus the unread badge count", body = OkEnvelope<NotificationFeedDto>),
        (status = UNAUTHORIZED, description = "Missing or invalid access token", body = ErrorEnvelope),
        (status = BAD_REQUEST, description = "Malformed cursor", body = ErrorEnvelope),
    )
)]
pub async fn list(
    State(state): State<AppState>,
    auth: AuthContext,
    QueryParams(params): QueryParams<FeedParams>,
) -> Result<Json<OkEnvelope<NotificationFeedDto>>, ApiError> {
    let limit = params.limit.unwrap_or(DEFAULT_LIMIT).clamp(1, MAX_LIMIT);
    let page = state
        .repos
        .notifications
        .list(auth.claims.sub, params.unread.unwrap_or(false), params.cursor.as_deref(), limit)
        .await?;
    // Always the *total* unread count, not the count on this page: it is a badge, and a badge
    // that changed with the page size would be worse than none.
    let unread = state.repos.notifications.unread_count(auth.claims.sub).await?;
    Ok(Json(OkEnvelope::new(NotificationFeedDto {
        items: page.items.iter().map(NotificationDto::from).collect(),
        cursor: page.cursor,
        has_more: page.has_more,
        unread,
    })))
}

/// Marks notifications read — either the listed ids or every unread one.
///
/// One endpoint rather than two because they are the same operation with a different selector,
/// and both answer with the resulting unread count so a client never has to guess the badge.
#[utoipa::path(
    post,
    path = "/api/v1/notifications/read",
    tag = "notifications",
    security(("bearer_auth" = [])),
    request_body = NotificationsReadBody,
    responses(
        (status = OK, description = "How many rows changed, and the unread count afterwards", body = OkEnvelope<NotificationsReadDto>),
        (status = UNAUTHORIZED, description = "Missing or invalid access token", body = ErrorEnvelope),
        (status = BAD_REQUEST, description = "Neither ids nor all, a malformed id, or too many ids", body = ErrorEnvelope),
    )
)]
pub async fn mark_read(
    State(state): State<AppState>,
    auth: AuthContext,
    Json(body): Json<NotificationsReadBody>,
) -> Result<Json<OkEnvelope<NotificationsReadDto>>, ApiError> {
    let now = (state.clock)();
    let marked = if body.all {
        state.repos.notifications.mark_all_read(auth.claims.sub, now).await?
    } else {
        let ids = parse_ids(&body.ids)?;
        if ids.is_empty() {
            return Err(Error::Invalid { message: "supply ids, or all = true".to_owned() }.into());
        }
        // Ids the caller does not own are silently no-ops rather than errors: reporting
        // "not yours" would turn this endpoint into an existence oracle over other accounts'
        // notification ids (S-04).
        state.repos.notifications.mark_read(auth.claims.sub, &ids, now).await?
    };
    let unread = state.repos.notifications.unread_count(auth.claims.sub).await?;
    Ok(Json(OkEnvelope::new(NotificationsReadDto { marked, unread })))
}

/// The caller's per-category delivery preferences, defaults filled in.
#[utoipa::path(
    get,
    path = "/api/v1/notifications/preferences",
    tag = "notifications",
    security(("bearer_auth" = [])),
    responses(
        (status = OK, description = "Every category with its effective preference", body = OkEnvelope<NotificationPreferencesDto>),
        (status = UNAUTHORIZED, description = "Missing or invalid access token", body = ErrorEnvelope),
    )
)]
pub async fn preferences(
    State(state): State<AppState>,
    auth: AuthContext,
) -> Result<Json<OkEnvelope<NotificationPreferencesDto>>, ApiError> {
    let stored = state.repos.notifications.preferences(auth.claims.sub).await?;
    Ok(Json(OkEnvelope::new(view(&NotificationPreferences::from_rows(&stored)))))
}

/// Replaces the preferences for the listed categories; unlisted categories keep their value.
#[utoipa::path(
    patch,
    path = "/api/v1/notifications/preferences",
    tag = "notifications",
    security(("bearer_auth" = [])),
    request_body = NotificationPreferencesBody,
    responses(
        (status = OK, description = "Every category with its preference after the write", body = OkEnvelope<NotificationPreferencesDto>),
        (status = UNAUTHORIZED, description = "Missing or invalid access token", body = ErrorEnvelope),
        (status = BAD_REQUEST, description = "Unknown category, or a duplicated one", body = ErrorEnvelope),
    )
)]
pub async fn update_preferences(
    State(state): State<AppState>,
    auth: AuthContext,
    Json(body): Json<NotificationPreferencesBody>,
) -> Result<Json<OkEnvelope<NotificationPreferencesDto>>, ApiError> {
    if body.preferences.is_empty() {
        return Err(Error::Invalid { message: "supply at least one category preference".to_owned() }.into());
    }
    let mut parsed: Vec<NotificationPreference> = Vec::with_capacity(body.preferences.len());
    for entry in &body.preferences {
        let category = entry.category.parse::<NotificationCategory>()?;
        if parsed.iter().any(|pref| pref.category == category) {
            // Two entries for one category have no defined winner; refusing beats picking one.
            return Err(Error::Invalid { message: format!("category {category} appears twice") }.into());
        }
        parsed.push(NotificationPreference { category, in_app: entry.in_app, email: entry.email });
    }
    let now = (state.clock)();
    let stored = state.repos.notifications.set_preferences(auth.claims.sub, &parsed, now).await?;
    Ok(Json(OkEnvelope::new(view(&NotificationPreferences::from_rows(&stored)))))
}

/// Projects the complete preference set onto the wire.
fn view(prefs: &NotificationPreferences) -> NotificationPreferencesDto {
    NotificationPreferencesDto {
        preferences: prefs
            .all()
            .iter()
            .map(|pref| NotificationPreferenceDto {
                category: pref.category.as_str().to_owned(),
                in_app: pref.in_app,
                email: pref.email,
            })
            .collect(),
    }
}

/// Parses the requested notification ids. A malformed id is a 400, not a silent skip: unlike a
/// path segment it is not an existence question, and dropping it would make `marked` disagree
/// with what the caller asked for.
fn parse_ids(raw: &[String]) -> Result<Vec<NotificationId>, ApiError> {
    raw.iter()
        .map(|id| {
            id.parse::<NotificationId>()
                .map_err(|_| Error::Invalid { message: "ids must be notification UUIDs".to_owned() }.into())
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn malformed_notification_ids_are_rejected_rather_than_skipped() {
        let err = parse_ids(&["not-a-uuid".to_owned()]).unwrap_err();
        assert_eq!(err.0.code(), "invalid_argument");
        assert!(parse_ids(&[]).unwrap().is_empty());
        assert_eq!(parse_ids(&[NotificationId::new().to_string()]).unwrap().len(), 1);
    }

    #[test]
    fn the_preference_view_always_covers_every_category() {
        let dto = view(&NotificationPreferences::default());
        assert_eq!(dto.preferences.len(), NotificationCategory::ALL.len());
        let security = dto.preferences.iter().find(|pref| pref.category == "security").expect("security");
        assert!(security.email, "security is high-importance and defaults to email");
    }
}
