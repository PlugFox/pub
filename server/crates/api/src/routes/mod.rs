//! App-API route modules. Every route is registered through utoipa's `OpenApiRouter`
//! (docs/rules/api.md) — routes and OpenAPI can never drift.

pub mod auth;
pub mod mfa;
pub mod oidc;
pub mod orgs;
pub mod sessions;
pub mod system;
pub mod tokens;
