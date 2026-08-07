//! The landing dashboard: instance identity, counters, and two package rails.
//!
//! One request, because that is what a landing page needs: a cold visitor should not have to
//! make four round trips before anything renders. Everything in the payload is
//! visibility-scoped through the same [`SearchView`] the search route uses, so a signed-in
//! member's dashboard includes their org's private packages and an anonymous visitor's does
//! not — including in the counters, which would otherwise publish the size of every org's
//! private inventory.

use axum::Json;
use axum::extract::State;
use pub_core::search::{SearchQuery, SearchSort, SearchView};

use crate::dto::{CountersDto, HomeDto, InstanceDto, PackageSummaryDto};
use crate::envelope::OkEnvelope;
use crate::error::ApiError;
use crate::extract::MaybeAuth;
use crate::state::AppState;

/// How many packages each rail carries.
const RAIL_SIZE: u32 = 10;

/// Landing/dashboard payload.
#[utoipa::path(
    get,
    path = "/api/v1/home",
    tag = "home",
    responses(
        (status = OK, description = "Instance identity, counters, and package rails", body = OkEnvelope<HomeDto>),
    )
)]
pub async fn home(State(state): State<AppState>, auth: MaybeAuth) -> Result<Json<OkEnvelope<HomeDto>>, ApiError> {
    let view = SearchView::for_actor(auth.actor());
    let counters = state.repos.search.counters(&view).await?;
    let recent = state.repos.search.search(&SearchQuery::browse(SearchSort::Updated), &view, None, RAIL_SIZE).await?;
    // Ordered by the totals the rollup job denormalized onto the index; on a fresh instance
    // every count is zero and the rail degrades to a stable arbitrary order rather than to an
    // error, which is the right behaviour for a page that must always render.
    let popular =
        state.repos.search.search(&SearchQuery::browse(SearchSort::Downloads), &view, None, RAIL_SIZE).await?;

    // Branding is a runtime setting (decision 09): an administrator renaming the instance is
    // visible on the next request, not on the next restart.
    let settings = state.runtime.current();
    let branding = &settings.branding;
    Ok(Json(OkEnvelope::new(HomeDto {
        instance: InstanceDto {
            name: branding.name.clone(),
            tagline: non_empty(&branding.tagline),
            logo_url: non_empty(&branding.logo_url),
            primary_color: non_empty(&branding.primary_color),
            public_url: state.settings.server.public_url.clone(),
        },
        counters: CountersDto { packages: counters.packages, versions: counters.versions, orgs: counters.orgs },
        recently_updated: recent.items.iter().map(PackageSummaryDto::from).collect(),
        most_downloaded: popular.items.iter().map(PackageSummaryDto::from).collect(),
    })))
}

/// An unset branding field is `null` on the wire, not `""` — the UI branches on presence.
fn non_empty(value: &str) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() { None } else { Some(trimmed.to_owned()) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blank_branding_fields_are_absent_rather_than_empty() {
        assert_eq!(non_empty("  "), None);
        assert_eq!(non_empty(""), None);
        assert_eq!(non_empty(" Acme Registry "), Some("Acme Registry".to_owned()));
    }
}
