//! HTTP surface of the Pub registry: axum routers, OpenAPI (utoipa), embedded static
//! assets, and the tower middleware stack.
//!
//! Current scope: system endpoints, the full v1 auth surface — email OTP (S-03/S-04),
//! multi-provider OIDC (S-01/S-02), TOTP second factor + step-up (S-05/S-06) — session and
//! CLI-token management (S-08/S-09/S-13), minimal orgs, and the Hosted Pub Repository Spec v2
//! surface on both virtual bases (`/o/{org}/pub`, `/pub` — see [`protocol`]).
//!
//! Middleware order (docs/rules/api.md): request-id → tracing → security headers → rate
//! limit → auth (typed extractors in handlers). The two app-API guards deliberately scope
//! themselves to `/api/…`: the pub protocol has its own contract (no custom header, no JSON
//! bodies, no browser origin) and must never inherit them.

use axum::Json;
use axum::Router;
use axum::http::{HeaderValue, header};
use axum::routing::get;
use tower::ServiceBuilder;
use tower_http::request_id::{MakeRequestUuid, PropagateRequestIdLayer, SetRequestIdLayer};
use tower_http::set_header::SetResponseHeaderLayer;
use tower_http::trace::TraceLayer;
use utoipa::openapi::security::{HttpAuthScheme, HttpBuilder, SecurityScheme};
use utoipa::{Modify, OpenApi};
use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;

mod assets;
pub mod dto;
pub mod envelope;
pub mod error;
pub mod extract;
pub mod guard;
pub mod protocol;
pub mod routes;
mod state;

pub use state::{AppState, Clock};

/// Registers the `bearer_auth` scheme referenced by authed routes (docs/rules/api.md).
struct SecurityAddon;

impl Modify for SecurityAddon {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        let components = openapi.components.get_or_insert_with(Default::default);
        components.add_security_scheme(
            "bearer_auth",
            SecurityScheme::Http(HttpBuilder::new().scheme(HttpAuthScheme::Bearer).bearer_format("JWT").build()),
        );
    }
}

/// Root OpenAPI document; route annotations are merged in by [`router`].
#[derive(OpenApi)]
#[openapi(
    info(
        title = "Pub API",
        description = "Self-hosted package registry — app REST API and system endpoints."
    ),
    modifiers(&SecurityAddon),
    tags(
        (name = "system", description = "Health and system endpoints"),
        (name = "auth", description = "Sign-in (email OTP, OIDC), TOTP second factor, step-up, refresh, logout"),
        (name = "sessions", description = "Web session management"),
        (name = "tokens", description = "CLI/API tokens"),
        (name = "orgs", description = "Organizations"),
        (name = "pub", description = "Hosted Pub Repository Spec v2 (docs/protocol.md) — spec shapes, no envelope"),
    )
)]
struct ApiDoc;

/// Builds the full application router: API routes, OpenAPI JSON, embedded static assets,
/// and the middleware stack.
pub fn router(state: AppState) -> Router {
    let (api_router, openapi) = OpenApiRouter::<AppState>::with_openapi(ApiDoc::openapi())
        .routes(routes!(routes::system::healthz))
        .routes(routes!(routes::system::ping))
        .routes(routes!(routes::auth::otp_request))
        .routes(routes!(routes::auth::otp_verify))
        .routes(routes!(routes::auth::refresh))
        .routes(routes!(routes::auth::logout))
        .routes(routes!(routes::oidc::providers))
        .routes(routes!(routes::oidc::start))
        .routes(routes!(routes::oidc::callback))
        .routes(routes!(routes::mfa::totp_enroll))
        .routes(routes!(routes::mfa::totp_confirm))
        .routes(routes!(routes::mfa::totp_verify))
        .routes(routes!(routes::mfa::totp_disable))
        .routes(routes!(routes::mfa::step_up))
        .routes(routes!(routes::sessions::list))
        .routes(routes!(routes::sessions::revoke))
        .routes(routes!(routes::sessions::revoke_all))
        .routes(routes!(routes::tokens::create, routes::tokens::list))
        .routes(routes!(routes::tokens::revoke))
        .routes(routes!(routes::orgs::create, routes::orgs::list))
        // Pub protocol on both virtual bases (decision 01); spec shapes, never the envelope.
        .merge(protocol::router(&state))
        .split_for_parts();

    Router::new()
        .merge(api_router)
        // OpenAPI is generated from route annotations, never hand-edited (docs/rules/api.md).
        .route("/api/openapi.json", get(move || std::future::ready(Json(openapi.clone()))))
        // Everything that is not an API route is served from the embedded frontend build.
        .fallback(assets::spa_fallback)
        .layer(
            ServiceBuilder::new()
                .layer(SetRequestIdLayer::x_request_id(MakeRequestUuid))
                .layer(PropagateRequestIdLayer::x_request_id())
                .layer(TraceLayer::new_for_http())
                .layer(SetResponseHeaderLayer::if_not_present(
                    header::X_CONTENT_TYPE_OPTIONS,
                    HeaderValue::from_static("nosniff"),
                ))
                .layer(SetResponseHeaderLayer::if_not_present(
                    header::CONTENT_SECURITY_POLICY,
                    HeaderValue::from_static("frame-ancestors 'none'"),
                ))
                .layer(SetResponseHeaderLayer::if_not_present(
                    header::X_FRAME_OPTIONS,
                    HeaderValue::from_static("DENY"),
                ))
                // Auth rate limits (S-24) run after the header layers, before handlers; the
                // guard scopes itself to auth paths internally.
                .layer(axum::middleware::from_fn_with_state(state.clone(), guard::auth_rate_limit))
                // S-12 mutation guard: Origin/Sec-Fetch-Site + custom header + JSON-only
                // bodies on /api mutations.
                .layer(axum::middleware::from_fn_with_state(state.clone(), guard::mutation_guard)),
        )
        .with_state(state)
}
