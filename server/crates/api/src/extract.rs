//! Typed auth extractor (docs/rules/api.md: auth context arrives via `FromRequestParts`,
//! never raw extensions) plus request-metadata helpers.

use std::collections::BTreeMap;
use std::net::SocketAddr;

use axum::extract::{ConnectInfo, FromRequestParts};
use axum::http::request::Parts;
use axum::http::{Extensions, HeaderMap, header};
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

/// S-06 step-up guard: an [`AuthContext`] whose session is additionally step-up-fresh —
/// either a login within the step-up window (a login runs the account's strongest factor
/// chain, TOTP included) or an explicit `POST /api/v1/auth/step-up` within it.
///
/// Routes on the S-06 action list take this extractor instead of `AuthContext`; a stale
/// session gets the distinct `step_up_required` 403 so the UI can prompt. A KV failure
/// during the freshness check propagates as 503 — the gate fails closed.
pub struct StepUp(pub AuthContext);

impl FromRequestParts<AppState> for StepUp {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, Self::Rejection> {
        let auth = AuthContext::from_request_parts(parts, state).await?;
        require_step_up(state, &auth).await?;
        Ok(Self(auth))
    }
}

/// The S-06 freshness check behind [`StepUp`], reusable where gating is conditional
/// (e.g. token minting gates only `publish`/`admin` scopes, decided after body parsing).
pub async fn require_step_up(state: &AppState, auth: &AuthContext) -> Result<(), ApiError> {
    let now = (state.clock)();
    if state.auth.step_up_satisfied(auth.claims.sub, auth.claims.sid, now).await.map_err(ApiError)? {
        Ok(())
    } else {
        Err(ApiError(pub_core::Error::StepUpRequired))
    }
}

/// Audit/session metadata for the current request (S-10/S-22), resolved against the
/// instance's trusted-proxy stance.
///
/// A typed extractor rather than a free function over `HeaderMap`, because the client IP is
/// only trustworthy once both the socket peer and the configuration are in scope — handlers
/// must not be able to reach for the raw header instead.
pub struct RequestMeta(pub ClientMeta);

impl FromRequestParts<AppState> for RequestMeta {
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, Self::Rejection> {
        Ok(Self(client_meta(&parts.headers, &parts.extensions, state.trust_proxy_headers())))
    }
}

/// Resolves the client IP under the instance's trusted-proxy stance (S-24 amendment).
///
/// `trust_proxy_headers = false` (default): forwarding headers are **ignored** and the socket
/// peer address wins, because any client can put anything in `X-Forwarded-For` — trusting it
/// on a directly exposed listener both hands out unlimited fresh rate-limit buckets and lets
/// an attacker exhaust someone else's.
///
/// `trust_proxy_headers = true`: exactly one trusted reverse proxy is assumed in front, so the
/// **rightmost** `X-Forwarded-For` entry is used — that is the address the proxy itself
/// observed. The leftmost entries are client-supplied and are never authoritative.
pub fn client_ip(headers: &HeaderMap, extensions: &Extensions, trust_proxy_headers: bool) -> Option<String> {
    if trust_proxy_headers
        && let Some(forwarded) = headers.get("x-forwarded-for").and_then(|value| value.to_str().ok())
        && let Some(last) = forwarded.rsplit(',').map(str::trim).find(|hop| !hop.is_empty())
    {
        return Some(last.to_owned());
    }
    extensions.get::<ConnectInfo<SocketAddr>>().map(|ConnectInfo(addr)| addr.ip().to_string())
}

/// Captures audit/session metadata from a request (S-10/S-22).
pub fn client_meta(headers: &HeaderMap, extensions: &Extensions, trust_proxy_headers: bool) -> ClientMeta {
    let user_agent = headers
        .get(header::USER_AGENT)
        .and_then(|value| value.to_str().ok())
        .map(|ua| ua.chars().take(MAX_USER_AGENT).collect::<String>());
    ClientMeta { ip: client_ip(headers, extensions, trust_proxy_headers), user_agent }
}

#[cfg(test)]
mod tests {
    use axum::http::HeaderValue;

    use super::*;

    fn forwarded(value: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", HeaderValue::from_str(value).unwrap());
        headers
    }

    fn peer(addr: &str) -> Extensions {
        let mut extensions = Extensions::new();
        extensions.insert(ConnectInfo(addr.parse::<SocketAddr>().unwrap()));
        extensions
    }

    #[test]
    fn s24_untrusted_forwarded_header_is_ignored_in_favour_of_the_socket_peer() {
        // Default stance: a client-supplied XFF must not mint a fresh rate-limit bucket, and
        // must not let the caller pose as another address.
        let headers = forwarded("198.51.100.66");
        assert_eq!(client_ip(&headers, &peer("203.0.113.7:44321"), false).as_deref(), Some("203.0.113.7"));
    }

    #[test]
    fn s24_trusted_forwarded_header_takes_the_last_hop() {
        // `proxy_add_x_forwarded_for` appends the observed peer, so the rightmost entry is
        // the trusted one; the leftmost is whatever the client claimed.
        let headers = forwarded("10.9.9.9, 203.0.113.7");
        assert_eq!(client_ip(&headers, &Extensions::new(), true).as_deref(), Some("203.0.113.7"));
        // Even with a socket peer present the trusted proxy's view wins.
        assert_eq!(client_ip(&headers, &peer("127.0.0.1:8080"), true).as_deref(), Some("203.0.113.7"));
    }

    #[test]
    fn s24_garbage_forwarded_header_falls_back_to_the_peer() {
        for garbage in ["", " ", ",", " , "] {
            let headers = forwarded(garbage);
            assert_eq!(
                client_ip(&headers, &peer("203.0.113.7:1"), true).as_deref(),
                Some("203.0.113.7"),
                "accepted garbage {garbage:?}"
            );
        }
    }

    #[test]
    fn client_ip_absent_without_header_or_peer() {
        assert_eq!(client_ip(&HeaderMap::new(), &Extensions::new(), true), None);
        assert_eq!(client_ip(&HeaderMap::new(), &Extensions::new(), false), None);
    }

    #[test]
    fn client_meta_truncates_the_user_agent() {
        let mut headers = HeaderMap::new();
        let long = "x".repeat(1000);
        headers.insert(header::USER_AGENT, HeaderValue::from_str(&long).unwrap());
        let meta = client_meta(&headers, &Extensions::new(), true);
        assert_eq!(meta.user_agent.unwrap().len(), MAX_USER_AGENT);
        assert_eq!(meta.ip, None);
    }
}
