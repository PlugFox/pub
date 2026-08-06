//! HTTP surface of the Pub registry: axum routers, OpenAPI (utoipa), embedded static
//! assets, and the tower middleware stack.
//!
//! Skeleton scope: `/healthz`, `/api/v1/ping`, `/api/openapi.json`, and SPA-style serving of
//! the embedded frontend. Protocol routes (`/o/{org}/pub/…`, `/pub/…`), auth extractors,
//! and rate limiting land in later roadmap steps.
//!
//! Middleware order (docs/rules/api.md): request-id → tracing → security headers.

use axum::Json;
use axum::Router;
use axum::http::{HeaderValue, header};
use axum::routing::get;
use tower::ServiceBuilder;
use tower_http::request_id::{MakeRequestUuid, PropagateRequestIdLayer, SetRequestIdLayer};
use tower_http::set_header::SetResponseHeaderLayer;
use tower_http::trace::TraceLayer;
use utoipa::OpenApi;
use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;

mod assets;
pub mod envelope;
pub mod routes;
mod state;

pub use state::AppState;

/// Root OpenAPI document; route annotations are merged in by [`router`].
#[derive(OpenApi)]
#[openapi(
    info(
        title = "Pub API",
        description = "Self-hosted package registry — app REST API and system endpoints."
    ),
    tags((name = "system", description = "Health and system endpoints"))
)]
struct ApiDoc;

/// Builds the full application router: API routes, OpenAPI JSON, embedded static assets,
/// and the middleware stack.
pub fn router(state: AppState) -> Router {
    let (api_router, openapi) = OpenApiRouter::<AppState>::with_openapi(ApiDoc::openapi())
        .routes(routes!(routes::healthz))
        .routes(routes!(routes::ping))
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
                )),
        )
        .with_state(state)
}
