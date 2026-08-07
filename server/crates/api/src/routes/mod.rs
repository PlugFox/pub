//! App-API route modules. Every route is registered through utoipa's `OpenApiRouter`
//! (docs/rules/api.md) — routes and OpenAPI can never drift.

pub mod admin;
pub mod auth;
pub mod events;
pub mod home;
pub mod manage;
pub mod members;
pub mod mfa;
pub mod notifications;
pub mod oidc;
pub mod orgs;
pub mod packages;
pub mod sessions;
pub mod system;
pub mod tokens;

use pub_auth::flows::ClientMeta;
use pub_registry::ActorMeta;

use crate::extract::AuthContext;

/// Builds the actor a domain service records against (S-21 provenance, S-22 audit context).
///
/// `token_id` is always `None` here: the app API is the **web session plane** (decision 03),
/// and a CLI token can never reach these routes. The two planes stay distinguishable in the
/// audit log precisely because this function cannot invent a token id.
pub(crate) fn actor_meta(auth: &AuthContext, meta: &ClientMeta) -> ActorMeta {
    ActorMeta { user_id: auth.claims.sub, token_id: None, ip: meta.ip.clone(), user_agent: meta.user_agent.clone() }
}
