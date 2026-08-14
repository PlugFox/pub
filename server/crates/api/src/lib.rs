//! HTTP surface of the Pub registry: axum routers, OpenAPI (utoipa), embedded static
//! assets, and the tower middleware stack.
//!
//! Current scope: system endpoints, the full v1 auth surface — email OTP (S-03/S-04),
//! multi-provider OIDC (S-01/S-02), TOTP second factor + step-up (S-05/S-06) — session and
//! CLI-token management (S-08/S-09/S-13), minimal orgs, and the Hosted Pub Repository Spec v2
//! surface on both virtual bases (`/o/{org}/pub`, `/pub` — see [`protocol`]).
//!
//! Middleware order (docs/rules/api.md): request-id → tracing → security headers → CORS →
//! load-shed → timeout → 413 reshape → body cap → rate limit → auth (typed extractors in
//! handlers). The
//! shed and the deadline sit *inside* the header/CORS layers so their 503/408 responses carry
//! the same headers as everything else, and *outside* the guards so guard I/O rides the
//! deadline too. The two app-API guards deliberately scope themselves to `/api/…`: the pub
//! protocol has its own contract (no custom header, no JSON bodies, no browser origin) and
//! must never inherit them.

use std::sync::Arc;
use std::time::Duration;

use axum::Json;
use axum::Router;
use axum::extract::DefaultBodyLimit;
use axum::http::{HeaderName, HeaderValue, Method, header};
use axum::routing::get;
use tokio::sync::Semaphore;
use tower::ServiceBuilder;
use tower_http::cors::{AllowOrigin, CorsLayer};
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
pub mod hygiene;
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
        (name = "orgs", description = "Organizations: profile, members, invitations, danger zone"),
        (name = "packages", description = "Package read model and management: search, pages, options, retraction, transfer"),
        (name = "home", description = "Landing dashboard: instance identity, counters, package rails"),
        (name = "events", description = "Server-Sent Events stream of domain events (decision 20, S-32)"),
        (name = "notifications", description = "Notification center: feed, unread count, mark-read, per-category preferences"),
        (name = "admin", description = "Instance administration: runtime settings, users, orgs, audit, stats, jobs"),
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
        .routes(routes!(routes::orgs::profile, routes::orgs::update, routes::orgs::delete))
        // Org management (decision 19; S-06 step-up gates, S-09 session revocation).
        .routes(routes!(routes::members::list, routes::members::add))
        .routes(routes!(routes::members::update_role, routes::members::remove))
        .routes(routes!(routes::members::list_invitations, routes::members::invite))
        .routes(routes!(routes::members::revoke_invitation))
        .routes(routes!(routes::members::accept))
        // Package management (decisions 06/19).
        .routes(routes!(routes::manage::set_options))
        .routes(routes!(routes::manage::retract))
        .routes(routes!(routes::manage::unretract))
        .routes(routes!(routes::manage::transfer))
        // Instance administration.
        .routes(routes!(routes::admin::get_settings, routes::admin::update_settings))
        .routes(routes!(routes::admin::list_users))
        .routes(routes!(routes::admin::suspend_user))
        .routes(routes!(routes::admin::unsuspend_user))
        .routes(routes!(routes::admin::list_orgs))
        .routes(routes!(routes::admin::list_audit))
        .routes(routes!(routes::admin::stats))
        .routes(routes!(routes::admin::run_job))
        .routes(routes!(routes::admin::test_smtp))
        // Public read model (decision 11 search + the package/org/home screens of
        // docs/product.md). All GET, all anonymous-reachable, all visibility-filtered.
        .routes(routes!(routes::packages::search))
        .routes(routes!(routes::packages::detail))
        .routes(routes!(routes::packages::versions))
        // `version_detail` (GET) and `hard_delete` (DELETE) share one path, so they share one
        // `routes!` group — utoipa merges the methods onto a single OpenAPI path item.
        .routes(routes!(routes::packages::version_detail, routes::manage::hard_delete))
        .routes(routes!(routes::packages::dependents))
        .routes(routes!(routes::home::home))
        // Realtime: the SSE stream (S-32) and the notification center it announces.
        .routes(routes!(routes::events::stream))
        .routes(routes!(routes::notifications::list))
        .routes(routes!(routes::notifications::mark_read))
        .routes(routes!(routes::notifications::preferences, routes::notifications::update_preferences))
        // Pub protocol on both virtual bases (decision 01); spec shapes, never the envelope.
        .merge(protocol::router(&state))
        .split_for_parts();

    let http = state.settings.http;
    // One process-wide budget of in-flight requests (D8). Created here, not per layer clone:
    // the semaphore *is* the instance's capacity, so every route shares it.
    let capacity = Arc::new(Semaphore::new(http.concurrency_limit));

    // S-11: compute the document CSP now. The scanner panics on a malformed embedded build
    // (an unclosed inline block would truncate the scan and ship a wrong policy), and that
    // refusal belongs at startup, not on the first HTML request of a running instance.
    assets::init_document_csp();

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
                // RED metrics (decision 28) outside the shed and the deadline, so the 503s and
                // 408s an operator is paging about are counted rather than missing.
                .layer(axum::middleware::from_fn_with_state(state.clone(), hygiene::http_metrics))
                // S-28 baseline headers on every response. `if_not_present`, so a handler that
                // knows better wins: assets.rs sets the hashed document CSP on HTML (S-11).
                .layer(SetResponseHeaderLayer::if_not_present(
                    header::X_CONTENT_TYPE_OPTIONS,
                    HeaderValue::from_static("nosniff"),
                ))
                // The API-family CSP (S-11): API and pub responses are data, not documents —
                // nothing may load, embed, or frame them.
                .layer(SetResponseHeaderLayer::if_not_present(
                    header::CONTENT_SECURITY_POLICY,
                    HeaderValue::from_static("default-src 'none'; frame-ancestors 'none'"),
                ))
                .layer(SetResponseHeaderLayer::if_not_present(
                    header::X_FRAME_OPTIONS,
                    HeaderValue::from_static("DENY"),
                ))
                .layer(SetResponseHeaderLayer::if_not_present(
                    header::REFERRER_POLICY,
                    HeaderValue::from_static("no-referrer"),
                ))
                .layer(SetResponseHeaderLayer::if_not_present(
                    HeaderName::from_static("permissions-policy"),
                    HeaderValue::from_static("camera=(), microphone=(), geolocation=(), payment=(), usb=()"),
                ))
                // HSTS (https deployments only) and the no-store cache tier for API/pub JSON.
                .layer(axum::middleware::from_fn_with_state(state.clone(), hygiene::response_headers))
                // S-12: CORS locked to the instance origin by explicit config. Sits inside the
                // header layers (preflights get them) and outside the shed (a preflight is
                // answered even under load — it carries no work).
                .layer(cors_layer(&state.settings.server.public_url))
                // D8 load shedding, then the D13 request deadline — shed first so a saturated
                // instance answers 503 without spending a timeout slot, deadline outside the
                // guards so their KV I/O is bounded too.
                .layer(axum::middleware::from_fn(move |request, next| {
                    hygiene::concurrency_shed(Arc::clone(&capacity), request, next)
                }))
                .layer(axum::middleware::from_fn_with_state(state.clone(), hygiene::request_timeout))
                // Body-cap rejections answer in the family's shape, like the 408/503 bodies
                // do. Inside CORS (so the reshaped 413 keeps its CORS headers), outside the
                // body cap and the handlers whose body reads produce the bare 413.
                .layer(axum::middleware::from_fn(hygiene::reshape_body_limit))
                // Global request-body cap (D8). The publish upload subrouter overrides it with
                // the archive cap + multipart envelope — an inner `DefaultBodyLimit` wins.
                .layer(DefaultBodyLimit::max(http.max_body_bytes))
                // Auth rate limits (S-24) run after the header layers, before handlers; the
                // guard scopes itself to auth paths internally.
                .layer(axum::middleware::from_fn_with_state(state.clone(), guard::auth_rate_limit))
                // Read-path buckets (S-24.f), keyed by identity and failing open. Inside the
                // auth buckets so a credential-endpoint POST is refused by the stricter gate
                // first, and outside the handlers so a refused read costs no database work.
                .layer(axum::middleware::from_fn_with_state(state.clone(), guard::read_rate_limit))
                // S-12 mutation guard: Origin/Sec-Fetch-Site + custom header + JSON-only
                // bodies on /api mutations.
                .layer(axum::middleware::from_fn_with_state(state.clone(), guard::mutation_guard)),
        )
        .with_state(state)
}

/// Explicit CORS (S-12): exactly the instance origin, the app API's methods and headers, no
/// credentials — the API is cookieless (decision 03), so there is nothing for a browser to
/// attach and nothing to allow.
///
/// This layer replaces "locked by omission" with "locked by config"; the *server-side* origin
/// comparison in [`guard::mutation_guard`] stays untouched as the non-delegating layer
/// (S-12.a) — CORS enforcement lives in the browser, the guard's does not.
fn cors_layer(public_url: &str) -> CorsLayer {
    // An unparseable public URL yields an empty allowlist: CORS stays fully locked rather
    // than silently open. (`server.public_url` is validated at boot — S-12.)
    let origin = url::Url::parse(public_url)
        .ok()
        .map(|url| url.origin().ascii_serialization())
        // A non-special scheme has an *opaque* origin, which `ascii_serialization` renders as
        // the literal "null" — and browsers genuinely send `Origin: null` from sandboxed
        // iframes and file: pages, so allow-listing it would open the API to every sandboxed
        // attacker page. Config validation refuses such URLs at boot; if one slips through
        // anyway (defence in depth), emit no allow-origin at all: locked, not null (S-12).
        .filter(|origin| origin != "null")
        .and_then(|origin| HeaderValue::from_str(&origin).ok());
    CorsLayer::new()
        .allow_origin(AllowOrigin::list(origin))
        .allow_methods([Method::GET, Method::POST, Method::PUT, Method::PATCH, Method::DELETE, Method::OPTIONS])
        .allow_headers([header::AUTHORIZATION, header::CONTENT_TYPE, HeaderName::from_static(guard::CUSTOM_HEADER)])
        .max_age(Duration::from_secs(3600))
}
