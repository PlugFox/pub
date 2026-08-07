//! Embedded frontend serving (decision 04): the Astro build output is compiled into the
//! binary via `rust-embed`. Unknown API paths return the JSON error envelope; everything else
//! resolves against the build output the way a static host would.
//!
//! Astro emits **directory-style** routes (`/app/search` → `app/search/index.html`) plus one
//! prerendered shell for the client-routed island (`app/index.html`) and a `404.html`. A
//! resolver that only tries the literal path therefore answers the *landing page* for every
//! app deep link, which is a blank marketing page where the SPA should have mounted. The
//! ladder below is what makes a reload of `/app/orgs/acme` behave like the first load:
//!
//! 1. the exact file (`/_astro/App.hash.js`, `/sw.js`);
//! 2. its directory index (`/app/search` → `app/search/index.html`, `/` → `index.html`);
//! 3. its `.html` sibling, for a host that emitted flat files;
//! 4. the app shell for anything under `/app` — @solidjs/router owns those paths in the
//!    browser and renders the in-app 404 itself (`apps/site/src/pages/app/[...rest].astro`);
//! 5. `404.html` with a real **404** status for everything else. A typo outside the app is
//!    not the landing page, and answering 200 would tell crawlers and the service worker that
//!    it is.

use axum::Json;
use axum::http::{StatusCode, Uri, header};
use axum::response::{IntoResponse, Response};
use rust_embed::EmbeddedFile;

use crate::envelope::ErrorEnvelope;

/// Frontend build output. The committed placeholder mirrors the real tree's shape (root page,
/// app shell, 404) and is overwritten with `web/apps/site/dist` by the Docker build.
#[derive(rust_embed::RustEmbed)]
#[folder = "embedded/"]
struct Assets;

/// Prerendered shell mounting the SolidJS island; the fallback for every client-routed path.
const APP_SHELL: &str = "app/index.html";
/// Static not-found page emitted by the Astro build.
const NOT_FOUND_PAGE: &str = "404.html";
/// Root document, and the last-resort fallback when the build has no dedicated 404 page.
const INDEX: &str = "index.html";

/// Router fallback: JSON 404 for unknown API routes, the embedded frontend for everything else.
pub async fn spa_fallback(uri: Uri) -> Response {
    let path = uri.path();
    if path == "/api" || path.starts_with("/api/") {
        let body = ErrorEnvelope::new("not_found", format!("no route for {path}"));
        return (StatusCode::NOT_FOUND, Json(body)).into_response();
    }
    serve_embedded(path)
}

fn serve_embedded(path: &str) -> Response {
    let trimmed = path.trim_matches('/');
    // Defence in depth: rust-embed refuses to escape its folder, but a request that even
    // *contains* a traversal segment is never a legitimate asset path.
    if trimmed.split('/').any(|segment| segment == ".." || segment == ".") {
        return not_found();
    }

    if trimmed.is_empty() {
        return match Assets::get(INDEX) {
            Some(file) => file_response(INDEX, StatusCode::OK, file),
            None => not_found(),
        };
    }

    for candidate in [trimmed.to_owned(), format!("{trimmed}/{INDEX}"), format!("{trimmed}.html")] {
        if let Some(file) = Assets::get(&candidate) {
            return file_response(&candidate, StatusCode::OK, file);
        }
    }

    // Client-side routes under /app resolve to the prerendered shell, which mounts the island;
    // the router then decides whether the path is a screen or the in-app 404.
    if trimmed == "app" || trimmed.starts_with("app/") {
        if let Some(file) = Assets::get(APP_SHELL) {
            return file_response(APP_SHELL, StatusCode::OK, file);
        }
        // A build without a dedicated app shell (the committed placeholder, a split deployment
        // serving one document) still has to hand the browser *something* that boots.
        if let Some(file) = Assets::get(INDEX) {
            return file_response(INDEX, StatusCode::OK, file);
        }
    }

    not_found()
}

/// The static 404 page with a 404 status, or the bare status when the build has none.
fn not_found() -> Response {
    match Assets::get(NOT_FOUND_PAGE) {
        Some(file) => file_response(NOT_FOUND_PAGE, StatusCode::NOT_FOUND, file),
        None => match Assets::get(INDEX) {
            Some(file) => file_response(INDEX, StatusCode::NOT_FOUND, file),
            None => StatusCode::NOT_FOUND.into_response(),
        },
    }
}

fn file_response(path: &str, status: StatusCode, file: EmbeddedFile) -> Response {
    let mime = mime_guess::from_path(path).first_or_octet_stream();
    (status, [(header::CONTENT_TYPE, mime.to_string())], file.data.into_owned()).into_response()
}
