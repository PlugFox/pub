//! Embedded frontend serving (decision 04): the Astro build output is compiled into the
//! binary via `rust-embed`. Unknown non-API paths fall back to `index.html` (SPA routing);
//! unknown API paths return the JSON error envelope.

use axum::Json;
use axum::http::{StatusCode, Uri, header};
use axum::response::{IntoResponse, Response};
use rust_embed::EmbeddedFile;

use crate::envelope::ErrorEnvelope;

/// Frontend build output. The committed placeholder is overwritten with the real
/// `web/apps/site/dist` by the Docker build.
#[derive(rust_embed::RustEmbed)]
#[folder = "embedded/"]
struct Assets;

/// Router fallback: JSON 404 for unknown API routes, embedded assets (with SPA fallback to
/// `index.html`) for everything else.
pub async fn spa_fallback(uri: Uri) -> Response {
    let path = uri.path();
    if path == "/api" || path.starts_with("/api/") {
        let body = ErrorEnvelope::new("not_found", format!("no route for {path}"));
        return (StatusCode::NOT_FOUND, Json(body)).into_response();
    }
    serve_embedded(path)
}

fn serve_embedded(path: &str) -> Response {
    let trimmed = path.trim_start_matches('/');
    let candidate = if trimmed.is_empty() { "index.html" } else { trimmed };
    if let Some(file) = Assets::get(candidate) {
        return file_response(candidate, file);
    }
    // SPA-style fallback: client-side routes resolve to the app shell.
    match Assets::get("index.html") {
        Some(file) => file_response("index.html", file),
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

fn file_response(path: &str, file: EmbeddedFile) -> Response {
    let mime = mime_guess::from_path(path).first_or_octet_stream();
    ([(header::CONTENT_TYPE, mime.to_string())], file.data.into_owned()).into_response()
}
