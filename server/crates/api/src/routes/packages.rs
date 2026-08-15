//! The public package read model: search, package pages, version lists, and the reverse
//! dependency graph.
//!
//! Every route here is a `GET`, is anonymous-reachable by default (decision 05), and answers
//! the **same 404** for a package the caller may not read as for one that does not exist
//! (S-04). That is not per-handler discipline: visibility is decided in exactly two places —
//! [`PackageRepo::resolve`](pub_core::traits::PackageRepo::resolve) for by-name lookups and the
//! [`SearchView`] a backend applies to every listing query — and both run the
//! [`authorize`](pub_core::authorize::authorize) chokepoint.
//!
//! ```text
//!   GET /api/v1/packages                      search + facets   → PackageSearch
//!   GET /api/v1/packages/{name}               detail            → resolve() → versions
//!   GET /api/v1/packages/{name}/versions      newest-first list → resolve() → list_versions_desc
//!   GET /api/v1/packages/{name}/versions/{v}  one version       → resolve() → get_version
//!   GET /api/v1/packages/{name}/dependents    reverse deps      → PackageSearch (dependency:)
//! ```
//!
//! **Scope note for the frontend:** these routes serve the *local* read model only. A name that
//! resolves through the upstream proxy (decision 07) has no package row here and answers 404 —
//! proxied packages are installable but not browsable, which is the gap the advisories/upstream
//! browse surface closes later.

use std::collections::HashMap;

use axum::Json;
use axum::extract::{Path, State};
use pub_core::authorize::{Action, ActorContext, Resource, authorize};
use pub_core::package::{Package, Resolution, Version};
use pub_core::search::{SearchQuery, SearchSort, SearchView, parse_query};
use pub_core::{Error, Format, SemVer, UserId};
use serde::Deserialize;
use utoipa::IntoParams;

use crate::dto::{
    DownloadsDto, FacetDto, FacetsDto, ListDto, PackageDetailDto, PackageLinksDto, PackageSummaryDto, PublisherDto,
    SearchResultsDto, VersionDetailDto, VersionSummaryDto,
};
use crate::envelope::{ErrorEnvelope, OkEnvelope};
use crate::error::ApiError;
use crate::extract::{MaybeAuth, QueryParams};
use crate::state::AppState;

/// The format this read model serves (decision 21: `npm`/`cargo` mount their own later).
pub(crate) const FORMAT: Format = Format::Pub;

/// Default page size when the caller does not ask for one.
const DEFAULT_LIMIT: u32 = 20;

/// Largest page any of these routes will return.
const MAX_LIMIT: u32 = 100;

/// Facet buckets returned with a search page.
const FACET_BUCKETS: u32 = 10;

/// Query parameters shared by the search and listing routes.
#[derive(Debug, Deserialize, IntoParams)]
pub struct SearchParams {
    /// Free text plus filter tags: `format:` `org:` `topic:` `dependency:` `is:` `sort:`,
    /// quoted phrases, and a leading `-` to negate a filter. Unparseable tokens are ignored
    /// and echoed back in `unknown_filters`.
    #[param(example = "bloc org:acme is:public -is:discontinued")]
    pub q: Option<String>,
    /// `relevance` (default) | `updated` | `name` | `downloads`. A `sort:` tag inside `q` wins.
    pub sort: Option<String>,
    /// Opaque cursor from the previous page; only valid for the same `sort`.
    pub cursor: Option<String>,
    /// Page size, 1..=100 (default 20).
    pub limit: Option<u32>,
}

/// Query parameters for the plain cursor listings (versions, dependents, org packages).
#[derive(Debug, Deserialize, IntoParams)]
pub struct PageParams {
    /// Opaque cursor from the previous page.
    pub cursor: Option<String>,
    /// Page size, 1..=100 (default 20).
    pub limit: Option<u32>,
}

impl PageParams {
    /// The clamped page size.
    pub fn limit(&self) -> u32 {
        self.limit.unwrap_or(DEFAULT_LIMIT).clamp(1, MAX_LIMIT)
    }
}

/// Package search and browse.
#[utoipa::path(
    get,
    path = "/api/v1/packages",
    tag = "packages",
    params(SearchParams),
    responses(
        (status = OK, description = "Matching packages plus facet counts", body = OkEnvelope<SearchResultsDto>),
        (status = BAD_REQUEST, description = "Malformed cursor, or one from a different ordering", body = ErrorEnvelope),
    )
)]
pub async fn search(
    State(state): State<AppState>,
    auth: MaybeAuth,
    QueryParams(params): QueryParams<SearchParams>,
) -> Result<Json<OkEnvelope<SearchResultsDto>>, ApiError> {
    let default_sort = parse_sort(params.sort.as_deref())?;
    let query = parse_query(params.q.as_deref().unwrap_or_default(), default_sort);
    let view = SearchView::for_actor(auth.actor());
    let limit = params.limit.unwrap_or(DEFAULT_LIMIT).clamp(1, MAX_LIMIT);

    let page = state.repos.search.search(&query, &view, params.cursor.as_deref(), limit).await?;
    let facets = state.repos.search.facets(&query, &view, FACET_BUCKETS).await?;

    Ok(Json(OkEnvelope::new(SearchResultsDto {
        items: page.items.iter().map(PackageSummaryDto::from).collect(),
        cursor: page.cursor,
        has_more: page.has_more,
        total: facets.total,
        facets: FacetsDto {
            orgs: facets.orgs.into_iter().map(|bucket| FacetDto { value: bucket.value, count: bucket.count }).collect(),
        },
        sort: query.effective_sort().to_string(),
        unknown_filters: query.unknown.clone(),
    })))
}

/// Package detail: metadata, the newest live version, links, flags, counters, README.
#[utoipa::path(
    get,
    path = "/api/v1/packages/{name}",
    tag = "packages",
    params(("name" = String, Path, description = "Package name")),
    responses(
        (status = OK, description = "Package detail", body = OkEnvelope<PackageDetailDto>),
        (status = NOT_FOUND, description = "Unknown name, or one this principal may not read (S-04)", body = ErrorEnvelope),
    )
)]
pub async fn detail(
    State(state): State<AppState>,
    auth: MaybeAuth,
    Path(name): Path<String>,
) -> Result<Json<OkEnvelope<PackageDetailDto>>, ApiError> {
    let package = readable(&state, auth.actor(), &name).await?;
    // A package row whose versions are all tombstoned is not browsable, and saying so with the
    // same 404 keeps it indistinguishable from a name nobody ever claimed.
    //
    // `latest_and_newest` is the registry's own bounded newest-first scan, shared with the
    // search indexer (decision 32): the page and the search document cannot disagree about
    // which version `latest` is, because they are the same read of the same window.
    let (latest, newest) =
        pub_registry::index::latest_and_newest(&state.repos, package.id).await?.ok_or_else(|| missing(&name))?;
    let (latest, newest) = (&latest, &newest);
    let versions_count = state.repos.packages.count_versions(package.id).await?;

    let org = state
        .repos
        .orgs
        .get(package.org_id)
        .await?
        .ok_or_else(|| Error::Internal { message: format!("package {name} has no owning org") })?;
    let totals = state.repos.stats.package_totals(package.id, recent_since(&state)).await?;
    let show_publisher = may_see_publisher(&auth, &package);
    let publisher = if show_publisher { resolve_publisher(&state, latest.published_by.user_id).await? } else { None };

    let summary = PackageSummaryDto {
        name: package.name.clone(),
        format: package.format.as_str().to_owned(),
        org: org.slug.clone(),
        visibility: package.visibility.as_str().to_owned(),
        description: pubspec_string(&latest.pubspec, "description").unwrap_or_default(),
        topics: pubspec_topics(&latest.pubspec),
        latest_version: latest.version.to_string(),
        latest_retracted: newest.is_retracted(),
        versions_count,
        discontinued: package.discontinued,
        replaced_by: package.replaced_by.clone().filter(|_| package.discontinued),
        unlisted: package.unlisted,
        published_at: newest.published_at,
        updated_at: package.updated_at.max(newest.published_at),
        downloads: DownloadsDto { total: totals.total, recent: totals.recent },
    };

    Ok(Json(OkEnvelope::new(PackageDetailDto {
        summary,
        org_name: org.name,
        created_at: package.created_at,
        links: links_of(&latest.pubspec),
        latest: version_summary(latest, publisher),
        readme_html: latest.readme_html.clone(),
    })))
}

/// A package's versions, newest first.
#[utoipa::path(
    get,
    path = "/api/v1/packages/{name}/versions",
    tag = "packages",
    params(("name" = String, Path, description = "Package name"), PageParams),
    responses(
        (status = OK, description = "Versions, newest first", body = OkEnvelope<ListDto<VersionSummaryDto>>),
        (status = NOT_FOUND, description = "Unknown name, or one this principal may not read (S-04)", body = ErrorEnvelope),
        (status = BAD_REQUEST, description = "Malformed cursor", body = ErrorEnvelope),
    )
)]
pub async fn versions(
    State(state): State<AppState>,
    auth: MaybeAuth,
    Path(name): Path<String>,
    QueryParams(params): QueryParams<PageParams>,
) -> Result<Json<OkEnvelope<ListDto<VersionSummaryDto>>>, ApiError> {
    let package = readable(&state, auth.actor(), &name).await?;
    let page = state.repos.packages.list_versions_desc(package.id, params.cursor.as_deref(), params.limit()).await?;

    // One batch lookup for the whole page, not one per row: a version history is a listing, and
    // a listing that reads an account per item is an N+1 by construction.
    let publishers = if may_see_publisher(&auth, &package) {
        let mut ids: Vec<UserId> = page.items.iter().map(|version| version.published_by.user_id).collect();
        ids.sort_unstable();
        ids.dedup();
        resolve_publishers(&state, &ids).await?
    } else {
        HashMap::new()
    };
    let items = page
        .items
        .iter()
        .map(|version| version_summary(version, publishers.get(&version.published_by.user_id).cloned()))
        .collect();

    Ok(Json(OkEnvelope::new(ListDto { items, cursor: page.cursor, has_more: page.has_more })))
}

/// One version in full: rendered README and CHANGELOG plus the pubspec document.
#[utoipa::path(
    get,
    path = "/api/v1/packages/{name}/versions/{version}",
    tag = "packages",
    params(
        ("name" = String, Path, description = "Package name"),
        ("version" = String, Path, description = "Exact version"),
    ),
    responses(
        (status = OK, description = "Version detail", body = OkEnvelope<VersionDetailDto>),
        (status = NOT_FOUND, description = "Unknown package or version, or one this principal may not read", body = ErrorEnvelope),
    )
)]
pub async fn version_detail(
    State(state): State<AppState>,
    auth: MaybeAuth,
    Path((name, version)): Path<(String, String)>,
) -> Result<Json<OkEnvelope<VersionDetailDto>>, ApiError> {
    let package = readable(&state, auth.actor(), &name).await?;
    let requested = SemVer::parse(&version).map_err(|_| missing_version(&name, &version))?;
    let found = state
        .repos
        .packages
        .get_version(package.id, &requested)
        .await?
        // A tombstone is "burned", not "browsable": its metadata and bytes are gone
        // (decision 06), so the read model has nothing to render.
        .filter(|found| !found.tombstone)
        .ok_or_else(|| missing_version(&name, &version))?;

    let org = state
        .repos
        .orgs
        .get(package.org_id)
        .await?
        .ok_or_else(|| Error::Internal { message: format!("package {name} has no owning org") })?;
    let publisher = if may_see_publisher(&auth, &package) {
        resolve_publisher(&state, found.published_by.user_id).await?
    } else {
        None
    };
    // The archive URL is the org's virtual registry base (decision 01) — the same URL the pub
    // client downloads from, so a browser download and a `dart pub get` fetch the same bytes
    // through the same policy.
    let archive_url = format!(
        "{}/o/{}/{}/api/archives/{}-{}.tar.gz",
        state.settings.server.public_url.trim_end_matches('/'),
        org.slug,
        FORMAT.as_str(),
        package.name,
        found.version
    );

    Ok(Json(OkEnvelope::new(VersionDetailDto {
        name: package.name.clone(),
        summary: version_summary(&found, publisher),
        archive_url,
        pubspec: found.pubspec.clone(),
        readme_html: found.readme_html.clone(),
        changelog_html: found.changelog_html.clone(),
    })))
}

/// Packages that depend on this one, from the stored pubspecs.
///
/// Reverse dependencies are the `dependency:` search filter with the ordering pinned to `name`,
/// not a second query path — so a package hidden from search is hidden here too, by the same
/// predicate.
#[utoipa::path(
    get,
    path = "/api/v1/packages/{name}/dependents",
    tag = "packages",
    params(("name" = String, Path, description = "Package name"), PageParams),
    responses(
        (status = OK, description = "Dependent packages, by name", body = OkEnvelope<ListDto<PackageSummaryDto>>),
        (status = NOT_FOUND, description = "Unknown name, or one this principal may not read (S-04)", body = ErrorEnvelope),
        (status = BAD_REQUEST, description = "Malformed cursor", body = ErrorEnvelope),
    )
)]
pub async fn dependents(
    State(state): State<AppState>,
    auth: MaybeAuth,
    Path(name): Path<String>,
    QueryParams(params): QueryParams<PageParams>,
) -> Result<Json<OkEnvelope<ListDto<PackageSummaryDto>>>, ApiError> {
    // The subject itself has to be readable first: otherwise "who depends on acme_secret"
    // would confirm the name exists to somebody who cannot see it (S-04).
    let package = readable(&state, auth.actor(), &name).await?;

    let mut query = SearchQuery::browse(SearchSort::Name);
    query.dependencies.any.push(package.name.to_ascii_lowercase());
    let view = SearchView::for_actor(auth.actor());
    let page = state.repos.search.search(&query, &view, params.cursor.as_deref(), params.limit()).await?;

    Ok(Json(OkEnvelope::new(ListDto {
        items: page.items.iter().map(PackageSummaryDto::from).collect(),
        cursor: page.cursor,
        has_more: page.has_more,
    })))
}

// ----------------------------------------------------------------------------------- helpers

/// Resolves a name for this principal, or answers the anti-enumeration 404.
///
/// Goes through [`PackageRepo::resolve`](pub_core::traits::PackageRepo::resolve) — the
/// instance-wide question the web UI asks, as opposed to `resolve_in_base`, which answers the
/// per-virtual-registry question the pub protocol asks. Both non-readable outcomes
/// (`Restricted`, `Unclaimed`) collapse into one 404 with one message.
pub(crate) async fn readable(state: &AppState, actor: &ActorContext, name: &str) -> Result<Package, ApiError> {
    // A name that could never be claimed cannot exist; answering 400 here would make the route
    // a name-syntax oracle with a status a real miss does not have.
    if pub_registry::validate_package_name(name).is_err() {
        return Err(missing(name).into());
    }
    match state.repos.packages.resolve(FORMAT, name, actor).await? {
        Resolution::Readable(package) => Ok(package),
        _ => Err(missing(name).into()),
    }
}

/// Whether this caller may be told which *account* published a version.
///
/// The owning organization is public information (orgs are this registry's publishers); the
/// individual behind a release is not, so it is shown only inside the org.
fn may_see_publisher(auth: &MaybeAuth, package: &Package) -> bool {
    authorize(auth.actor(), Action::ReadPackages, &Resource::Org(package.org_id)).is_ok()
}

/// Projects a domain version onto its list row.
fn version_summary(version: &Version, publisher: Option<PublisherDto>) -> VersionSummaryDto {
    VersionSummaryDto {
        version: version.version.to_string(),
        retracted: version.is_retracted(),
        retracted_at: version.retracted_at,
        published_at: version.published_at,
        publisher,
        archive_size: version.archive_size,
        archive_sha256: version.archive_sha256.clone(),
    }
}

/// Looks up a publisher's display name; a deleted (anonymized) account yields `None`.
async fn resolve_publisher(state: &AppState, user: UserId) -> Result<Option<PublisherDto>, ApiError> {
    Ok(resolve_publishers(state, &[user]).await?.remove(&user))
}

/// The same lookup for a whole page, as one query. Accounts that are gone or suspended are
/// simply absent — a version keeps its attribution row, the *name* behind it does not survive
/// anonymization (S-29).
async fn resolve_publishers(state: &AppState, users: &[UserId]) -> Result<HashMap<UserId, PublisherDto>, ApiError> {
    Ok(state
        .repos
        .users
        .get_many(users)
        .await?
        .into_iter()
        .filter(|user| user.status == pub_core::user::UserStatus::Active)
        .map(|user| (user.id, PublisherDto { id: user.id.to_string(), display_name: user.display_name }))
        .collect())
}

/// The first day inside the instance's trailing statistics window.
fn recent_since(state: &AppState) -> chrono::NaiveDate {
    let days = state.settings.jobs.downloads.recent_window_days.max(1);
    ((state.clock)() - chrono::Duration::days(days)).date_naive()
}

/// A pubspec string field, trimmed; `None` when absent, empty, or the wrong type.
fn pubspec_string(pubspec: &serde_json::Value, key: &str) -> Option<String> {
    pubspec
        .get(key)
        .and_then(serde_json::Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

/// The pubspec's `topics` list.
fn pubspec_topics(pubspec: &serde_json::Value) -> Vec<String> {
    pubspec
        .get("topics")
        .and_then(serde_json::Value::as_array)
        .map(|values| {
            values
                .iter()
                .filter_map(serde_json::Value::as_str)
                .map(|topic| topic.trim().to_ascii_lowercase())
                .filter(|topic| !topic.is_empty())
                .collect()
        })
        .unwrap_or_default()
}

/// The four link fields a package page renders.
fn links_of(pubspec: &serde_json::Value) -> PackageLinksDto {
    PackageLinksDto {
        homepage: pubspec_string(pubspec, "homepage"),
        repository: pubspec_string(pubspec, "repository"),
        issue_tracker: pubspec_string(pubspec, "issue_tracker"),
        documentation: pubspec_string(pubspec, "documentation"),
    }
}

/// The one 404 every unreadable outcome collapses into (S-04).
fn missing(name: &str) -> Error {
    Error::NotFound { what: format!("package {}", clip(name)) }
}

/// The 404 for a version of a package the caller *can* read.
fn missing_version(name: &str, version: &str) -> ApiError {
    Error::NotFound { what: format!("version {} of package {}", clip(version), clip(name)) }.into()
}

/// Bounds a caller-supplied path segment before it is quoted back in an error message.
fn clip(text: &str) -> String {
    const MAX: usize = 80;

    if text.len() <= MAX {
        return text.to_owned();
    }
    let mut end = MAX;
    while end > 0 && !text.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}…", &text[..end])
}

/// Parses the `sort` query parameter.
fn parse_sort(raw: Option<&str>) -> Result<SearchSort, ApiError> {
    match raw {
        None => Ok(SearchSort::default()),
        Some(value) => SearchSort::parse(value).ok_or_else(|| {
            Error::Invalid { message: format!("unknown sort {value:?}: use relevance, updated, name, or downloads") }
                .into()
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sort_parameter_rejects_junk_instead_of_guessing() {
        assert_eq!(parse_sort(None).unwrap(), SearchSort::Relevance);
        assert_eq!(parse_sort(Some("downloads")).unwrap(), SearchSort::Downloads);
        let err = parse_sort(Some("sideways")).unwrap_err();
        assert_eq!(err.0.code(), "invalid_argument");
    }

    #[test]
    fn page_limits_are_clamped_into_range() {
        assert_eq!(PageParams { cursor: None, limit: None }.limit(), DEFAULT_LIMIT);
        assert_eq!(PageParams { cursor: None, limit: Some(0) }.limit(), 1);
        assert_eq!(PageParams { cursor: None, limit: Some(10_000) }.limit(), MAX_LIMIT);
    }

    #[test]
    fn pubspec_projection_tolerates_every_wrong_shape() {
        let junk = serde_json::json!({ "description": 7, "topics": "ui", "homepage": "  " });
        assert_eq!(pubspec_string(&junk, "description"), None);
        assert_eq!(pubspec_string(&junk, "homepage"), None, "a blank link is no link");
        assert!(pubspec_topics(&junk).is_empty());
        assert_eq!(links_of(&serde_json::json!(null)).repository, None);

        let good = serde_json::json!({
            "description": " A parser. ",
            "topics": ["UI", "", "widgets"],
            "repository": "https://example.test/x",
        });
        assert_eq!(pubspec_string(&good, "description").as_deref(), Some("A parser."));
        assert_eq!(pubspec_topics(&good), vec!["ui".to_owned(), "widgets".to_owned()]);
        assert_eq!(links_of(&good).repository.as_deref(), Some("https://example.test/x"));
    }

    #[test]
    fn caller_supplied_names_are_clipped_before_they_reach_a_message() {
        let long = "a".repeat(4000);
        let err = missing(&long);
        assert!(err.to_string().len() < 200, "unbounded reflection: {}", err.to_string().len());
    }
}
