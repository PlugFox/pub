//! The virtual registry base (decision 01) as a typed extractor, plus the absolute-URL
//! builder every response depends on.
//!
//! A pub-protocol request always arrives on one of two bases: `/o/{org}/pub`, the org's own
//! registry, or `/pub`, the instance's public root. The base is not decoration — it *is* the
//! namespace a package name resolves in ([`pub_core::package::BaseScope`]), and it is the
//! prefix every URL we hand back must live under, because the pub client attaches
//! `Authorization` to an archive or finalize URL only when its configured hosted URL is a
//! case-insensitive prefix of it (docs/protocol.md sharp edge 4).
//!
//! # Subpaths
//!
//! URLs are built from the instance's configured `server.public_url` — **including any path
//! prefix it carries** — and never from the request's own `Host`/`X-Forwarded-*` headers.
//! Reverse proxies that mount the registry under a subpath (`https://host/registry/o/acme/pub`)
//! therefore work by construction, and a client cannot make us emit URLs pointing at a host it
//! chose (docs/protocol.md sharp edge 8; subpath breakage was unpub's most common bug class).

use axum::extract::{FromRequestParts, RawPathParams};
use axum::http::request::Parts;
use pub_core::Format;
use pub_core::org::Org;
use pub_core::package::BaseScope;

use crate::protocol::error::ProtocolError;
use crate::state::AppState;

/// Path parameters of the matched route, read once and shared by every handler.
///
/// A plain `Path<T>` extractor cannot serve both bases: the same handler is mounted under
/// `/pub/...` and `/o/{org}/pub/...`, so the tuple arity would differ per mount. Reading the
/// raw params by name keeps one handler per endpoint.
pub struct PathParams(Vec<(String, String)>);

impl PathParams {
    /// The value of a path parameter, if the matched route had one.
    pub fn get(&self, key: &str) -> Option<&str> {
        self.0.iter().find(|(name, _)| name == key).map(|(_, value)| value.as_str())
    }

    /// The value of a path parameter that the route guarantees.
    ///
    /// A miss means the route and the handler disagree — a wiring bug, not a client error, so
    /// it surfaces as a 404 rather than a panic on a request path.
    pub fn require(&self, key: &str) -> Result<&str, ProtocolError> {
        self.get(key).ok_or_else(|| ProtocolError::not_found(format!("missing path parameter {key}")))
    }
}

impl FromRequestParts<AppState> for PathParams {
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, Self::Rejection> {
        // A route with no parameters yields no `UrlParams` extension at all; that is an empty
        // parameter set, not an error.
        let params = RawPathParams::from_request_parts(parts, state)
            .await
            .map(|raw| raw.iter().map(|(key, value)| (key.to_owned(), value.to_owned())).collect())
            .unwrap_or_default();
        Ok(Self(params))
    }
}

/// The virtual registry base this request arrived on.
pub struct Base {
    /// Artifact format served by the mount.
    pub format: Format,
    /// The org whose registry this is; `None` for the public root.
    pub org: Option<Org>,
    /// Base path under the instance root, e.g. `/o/acme/pub` — always without a trailing slash.
    path: String,
    /// Instance public URL without its trailing slash.
    public_url: String,
}

impl Base {
    /// The resolution scope this base implies (decision 01).
    pub fn scope(&self) -> BaseScope {
        match &self.org {
            Some(org) => BaseScope::Org(org.id),
            None => BaseScope::PublicRoot,
        }
    }

    /// An absolute URL for a path *relative to this base* (`suffix` starts with `/`).
    ///
    /// Everything we hand to the client — `archive_url`, the upload URL, the finalize URL —
    /// goes through here, which is what keeps them all under the credential prefix.
    pub fn absolute(&self, suffix: &str) -> String {
        format!("{}{}{}", self.public_url, self.path, suffix)
    }

    /// The base's own absolute URL — the exact string a user puts in `dart pub token add`.
    pub fn url(&self) -> String {
        format!("{}{}", self.public_url, self.path)
    }
}

impl FromRequestParts<AppState> for Base {
    type Rejection = ProtocolError;

    /// Resolves the `{org}` segment, when the mount has one.
    ///
    /// An unknown slug is **404**, exactly like an unknown package: org slugs are as
    /// enumerable as package names, and a distinct "no such org" status would map the
    /// instance's customer list for anyone with curl (S-04).
    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, Self::Rejection> {
        let params = PathParams::from_request_parts(parts, state).await.unwrap_or_else(|never| match never {});
        let format = MOUNTED_FORMAT;
        let org = match params.get("org") {
            Some(slug) => Some(
                state
                    .repos
                    .orgs
                    .get_by_slug(slug)
                    .await?
                    .ok_or_else(|| ProtocolError::not_found(format!("registry /o/{slug}/{format}")))?,
            ),
            None => None,
        };
        // The canonical slug, not the one the caller typed: it keeps every emitted URL
        // byte-identical across case variants, so a `PUB_CACHE` entry cannot be split in two.
        let path = match &org {
            Some(org) => format!("/o/{}/{}", org.slug, format),
            None => format!("/{format}"),
        };
        Ok(Self { format, org, path, public_url: trim_base(&state.settings.server.public_url) })
    }
}

/// The format every mount in this module serves.
///
/// A constant rather than a path segment: the format is decided by *which module* is mounted
/// (decision 21 reserves `/o/{org}/npm`, `/o/{org}/cargo` for sibling modules), so deriving it
/// from the URL would let a request pick its own protocol adapter.
const MOUNTED_FORMAT: Format = Format::Pub;

/// The base URL a message can quote before the org row has been loaded (used by the auth
/// extractor, which runs ahead of [`Base`] so that credentials are judged before existence).
pub fn advertised_base_url(public_url: &str, org_slug: Option<&str>) -> String {
    match org_slug {
        Some(slug) => format!("{}/o/{}/{}", trim_base(public_url), slug, MOUNTED_FORMAT),
        None => format!("{}/{}", trim_base(public_url), MOUNTED_FORMAT),
    }
}

/// Drops trailing slashes so `public_url` and the base path never produce `//`.
fn trim_base(public_url: &str) -> String {
    public_url.trim_end_matches('/').to_owned()
}

#[cfg(test)]
mod tests {
    use chrono::Utc;
    use pub_core::OrgId;

    use super::*;

    fn base(public_url: &str, org: Option<&str>) -> Base {
        let org = org.map(|slug| Org {
            id: OrgId::new(),
            name: slug.to_owned(),
            slug: slug.to_owned(),
            description: String::new(),
            upstream_policy: pub_core::org::UpstreamPolicy::Allow,
            storage_quota_bytes: None,
            archived_at: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        });
        let path = match &org {
            Some(org) => format!("/o/{}/pub", org.slug),
            None => "/pub".to_owned(),
        };
        Base { format: Format::Pub, org, path, public_url: trim_base(public_url) }
    }

    #[test]
    fn org_base_urls_live_under_the_org_prefix() {
        let base = base("https://pub.corp.test", Some("acme"));
        assert_eq!(base.url(), "https://pub.corp.test/o/acme/pub");
        assert_eq!(
            base.absolute("/api/archives/acme_core-1.0.0.tar.gz"),
            "https://pub.corp.test/o/acme/pub/api/archives/acme_core-1.0.0.tar.gz"
        );
    }

    #[test]
    fn a_reverse_proxy_subpath_is_carried_into_every_url() {
        // docs/protocol.md sharp edge 8 — the prefix must survive into archive/upload URLs,
        // or the client downloads from a path that does not exist.
        let base = base("https://corp.test/registry/", Some("acme"));
        assert_eq!(
            base.absolute("/api/packages/versions/newUpload"),
            "https://corp.test/registry/o/acme/pub/api/packages/versions/newUpload"
        );
        assert_eq!(
            advertised_base_url("https://corp.test/registry/", Some("acme")),
            "https://corp.test/registry/o/acme/pub"
        );
    }

    #[test]
    fn the_public_root_has_no_org_segment() {
        let base = base("https://pub.corp.test/", None);
        assert_eq!(base.url(), "https://pub.corp.test/pub");
        assert_eq!(base.scope(), BaseScope::PublicRoot);
        assert_eq!(advertised_base_url("https://pub.corp.test", None), "https://pub.corp.test/pub");
    }

    #[test]
    fn scope_follows_the_org() {
        let base = base("https://pub.corp.test", Some("acme"));
        let org_id = base.org.as_ref().unwrap().id;
        assert_eq!(base.scope(), BaseScope::Org(org_id));
    }

    #[test]
    fn path_params_are_looked_up_by_name() {
        let params =
            PathParams(vec![("org".to_owned(), "acme".to_owned()), ("name".to_owned(), "acme_core".to_owned())]);
        assert_eq!(params.get("name"), Some("acme_core"));
        assert_eq!(params.get("missing"), None);
        assert_eq!(params.require("org").unwrap(), "acme");
        assert_eq!(params.require("missing").unwrap_err().status(), axum::http::StatusCode::NOT_FOUND);
    }
}
