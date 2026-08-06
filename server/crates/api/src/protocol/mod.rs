//! Package-format protocol surfaces — one module per format (decision 21).
//!
//! These routes are a different API family from `/api/v1/…` and share nothing with it: no
//! envelope, no CSRF-style mutation guard, no browser JWTs. Their wire contract is
//! `docs/protocol.md`, their status ladder is decision 05, and the conformance suite
//! (`crates/api/tests/protocol.rs`) is the gate for changing any of it.
//!
//! ```text
//!   B = /o/{org}/pub  (an org's registry)      B = /pub  (the instance's public root)
//!        │                                          │
//!        ├── GET  B/api/packages/{name}             ← version listing (the hot path)
//!        ├── GET  B/api/packages/versions/new       ┐
//!        ├── POST B/api/packages/versions/newUpload ├ 3-step publish, all under B so the
//!        ├── GET  B/api/packages/versions/…Finish/… ┘ client's prefix rule keeps sending auth
//!        ├── GET  B/api/archives/{name}-{ver}.tar.gz
//!        ├── GET  B/api/packages/{name}/versions/{v}          (legacy, pre-Dart-2.8)
//!        └── GET  B/packages/{name}/versions/{v}.tar.gz       (legacy archive)
//! ```
//!
//! Both bases are served by the *same* handlers; [`base::Base`] turns the mount into a
//! resolution scope and a URL prefix. Mounting is [`router`].

pub mod base;
pub mod error;
pub mod pub_v2;
pub mod tokens;

use axum::extract::FromRequestParts;
use axum::http::header;
use axum::http::request::Parts;
use utoipa_axum::router::OpenApiRouter;

use crate::protocol::error::ProtocolError;
use crate::state::AppState;

/// The Hosted Pub Repository Spec version this server implements.
const SUPPORTED_PUB_API_VERSION: u32 = 2;

/// Mounts every format protocol on its virtual bases.
///
/// The pub format gets two mounts of one router: the per-org registry and the public root
/// (decision 01). `nest` prefixes the OpenAPI paths as well as the axum routes, so both
/// mounts are documented and neither can silently drift from the other.
pub fn router(state: &AppState) -> OpenApiRouter<AppState> {
    OpenApiRouter::new().nest("/o/{org}/pub", pub_v2::router(state)).nest("/pub", pub_v2::router(state))
}

/// Accept-header negotiation (docs/protocol.md sharp edge 6).
///
/// Two rules, and the second one is the sharp edge:
///
/// - **An absent `Accept` means v2.** The client omits it on archive downloads and uploads,
///   and older clients omit it everywhere; defaulting to anything else would break them.
/// - **406 is reserved for "we do not speak your API version".** The CLI turns that status
///   into "upgrade your SDK", so spending it on ordinary content negotiation would send users
///   chasing a nonexistent upgrade. A request that asks for `application/json` or `*/*` — or
///   that lists our media type among others — is served normally; only a request that asks
///   *exclusively* for a pub API version we do not implement is refused.
pub struct ApiVersion;

impl FromRequestParts<AppState> for ApiVersion {
    type Rejection = ProtocolError;

    async fn from_request_parts(parts: &mut Parts, _state: &AppState) -> Result<Self, Self::Rejection> {
        let accept = parts.headers.get(header::ACCEPT).and_then(|value| value.to_str().ok()).unwrap_or("");
        match negotiate(accept) {
            Ok(()) => Ok(Self),
            Err(requested) => Err(ProtocolError::unsupported_api_version(format!(
                "this server implements pub repository API v{SUPPORTED_PUB_API_VERSION}; \
                 the client asked for v{requested} — upgrade the Dart SDK"
            ))),
        }
    }
}

/// `Ok(())` when the Accept header is satisfiable; `Err(version)` naming a pub API version we
/// do not implement when it is not.
fn negotiate(accept: &str) -> Result<(), u32> {
    let mut unsupported = None;
    for range in accept.split(',') {
        // Drop parameters (`;q=0.9`) and surrounding whitespace before matching.
        let media = range.split(';').next().unwrap_or("").trim();
        let Some(version) = pub_api_version(media) else {
            // Any non-pub range (`*/*`, `application/json`, `text/html`) is not a version
            // demand and cannot make the request unserviceable.
            continue;
        };
        if version == SUPPORTED_PUB_API_VERSION {
            return Ok(());
        }
        unsupported.get_or_insert(version);
    }
    match unsupported {
        Some(version) => Err(version),
        None => Ok(()),
    }
}

/// The `N` in `application/vnd.pub.vN+json`, if this media range is one.
fn pub_api_version(media: &str) -> Option<u32> {
    let rest = media.to_ascii_lowercase();
    let rest = rest.strip_prefix("application/vnd.pub.v")?;
    rest.strip_suffix("+json")?.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accept_header_absent_defaults_to_v2() {
        assert_eq!(negotiate(""), Ok(()));
    }

    #[test]
    fn the_clients_own_accept_header_is_satisfiable() {
        assert_eq!(negotiate("application/vnd.pub.v2+json"), Ok(()));
        assert_eq!(negotiate("application/vnd.pub.v2+json; q=1.0"), Ok(()));
        assert_eq!(negotiate("APPLICATION/VND.PUB.V2+JSON"), Ok(()));
    }

    #[test]
    fn generic_ranges_are_served_not_refused() {
        for accept in ["*/*", "application/json", "text/html, */*;q=0.8", ""] {
            assert_eq!(negotiate(accept), Ok(()), "406 for {accept:?} would be a bogus upgrade prompt");
        }
    }

    #[test]
    fn an_unimplemented_pub_version_is_406() {
        assert_eq!(negotiate("application/vnd.pub.v3+json"), Err(3));
        assert_eq!(negotiate("application/vnd.pub.v1+json"), Err(1));
    }

    #[test]
    fn a_client_that_also_accepts_v2_is_served() {
        // Content negotiation, not a version demand: v2 is on the list, so we can answer.
        assert_eq!(negotiate("application/vnd.pub.v3+json, application/vnd.pub.v2+json"), Ok(()));
    }

    #[test]
    fn malformed_pub_media_types_are_not_version_demands() {
        for media in ["application/vnd.pub.vX+json", "application/vnd.pub.v2", "application/vnd.pub+json"] {
            assert_eq!(pub_api_version(media), None, "{media} must not parse as a version");
            assert_eq!(negotiate(media), Ok(()));
        }
    }
}
