//! Typed auth extractor (docs/rules/api.md: auth context arrives via `FromRequestParts`,
//! never raw extensions) plus request-metadata helpers.

use std::collections::BTreeMap;

use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use axum::http::{HeaderMap, header};
use pub_auth::flows::ClientMeta;
use pub_auth::jwt::Claims;
use pub_core::RoleLevel;
use pub_core::authorize::ActorContext;

use crate::error::ApiError;
use crate::state::AppState;

/// Maximum stored user-agent length — coarse UA only (S-10).
const MAX_USER_AGENT: usize = 256;

/// Authenticated request context: verified claims plus the derived [`ActorContext`] for the
/// `authorize()` chokepoint (decision 19).
pub struct AuthContext {
    /// Verified access-token claims.
    pub claims: Claims,
    /// Actor for `authorize(actor, action, resource)`.
    pub actor: ActorContext,
}

impl FromRequestParts<AppState> for AuthContext {
    type Rejection = ApiError;

    /// Bearer JWT → keyring verification (S-07) → revoked-`sid` fast path (S-09).
    ///
    /// A KV failure during the revocation check propagates as `kv_error` → **503**: the
    /// fast path fails closed rather than accepting a possibly-revoked session.
    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, Self::Rejection> {
        let token = parts
            .headers
            .get(header::AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.strip_prefix("Bearer "))
            .filter(|token| !token.is_empty())
            .ok_or_else(|| ApiError::unauthorized("missing bearer token"))?;

        let now = (state.clock)();
        let claims = state.auth.verify_access(token, now).map_err(ApiError)?;
        if state.auth.is_sid_revoked(claims.sid).await.map_err(ApiError)? {
            return Err(ApiError::unauthorized("session revoked"));
        }

        let orgs: BTreeMap<_, _> = claims.orgs.iter().map(|(org, level)| (*org, RoleLevel::new(*level))).collect();
        let actor = ActorContext::user(claims.sub, orgs);
        Ok(Self { claims, actor })
    }
}

/// Client IP as reported by the reverse proxy (`X-Forwarded-For`, first hop).
///
/// The skeleton serves behind a proxy or on localhost; socket-level fallback arrives with
/// the deployment hardening step.
pub fn client_ip(headers: &HeaderMap) -> Option<String> {
    let raw = headers.get("x-forwarded-for")?.to_str().ok()?;
    let first = raw.split(',').next()?.trim();
    (!first.is_empty()).then(|| first.to_owned())
}

/// Captures audit/session metadata from request headers (S-10/S-22).
pub fn client_meta(headers: &HeaderMap) -> ClientMeta {
    let user_agent = headers
        .get(header::USER_AGENT)
        .and_then(|value| value.to_str().ok())
        .map(|ua| ua.chars().take(MAX_USER_AGENT).collect::<String>());
    ClientMeta { ip: client_ip(headers), user_agent }
}

#[cfg(test)]
mod tests {
    use axum::http::HeaderValue;

    use super::*;

    #[test]
    fn client_ip_takes_the_first_forwarded_hop() {
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", HeaderValue::from_static("203.0.113.7, 10.0.0.1"));
        assert_eq!(client_ip(&headers).as_deref(), Some("203.0.113.7"));
    }

    #[test]
    fn client_ip_absent_without_header() {
        assert_eq!(client_ip(&HeaderMap::new()), None);
    }

    #[test]
    fn client_meta_truncates_the_user_agent() {
        let mut headers = HeaderMap::new();
        let long = "x".repeat(1000);
        headers.insert(header::USER_AGENT, HeaderValue::from_str(&long).unwrap());
        let meta = client_meta(&headers);
        assert_eq!(meta.user_agent.unwrap().len(), MAX_USER_AGENT);
        assert_eq!(meta.ip, None);
    }
}
