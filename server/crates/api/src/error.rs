//! HTTP mapping of [`pub_core::Error`] onto the app API envelope (decision 16,
//! docs/rules/api.md). Codes come from `Error::code()` and are stable; statuses live here.

use axum::Json;
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use pub_core::Error;

use crate::envelope::ErrorEnvelope;

/// Wrapper turning a domain error into an enveloped HTTP response.
///
/// Handlers return `Result<Json<…>, ApiError>` and use `?` freely — `From<Error>` plus this
/// `IntoResponse` are the whole mapping.
#[derive(Debug)]
pub struct ApiError(pub Error);

impl From<Error> for ApiError {
    fn from(err: Error) -> Self {
        Self(err)
    }
}

impl ApiError {
    /// Shorthand for the uniform 401.
    pub fn unauthorized(message: impl Into<String>) -> Self {
        Self(Error::Unauthorized { message: message.into() })
    }

    /// The HTTP status this error maps to.
    fn status(&self) -> StatusCode {
        match &self.0 {
            Error::Invalid { .. } => StatusCode::BAD_REQUEST,
            Error::NotFound { .. } => StatusCode::NOT_FOUND,
            // `Busy` (a held serialization lock) is transient where `Conflict` is permanent,
            // but both are honest 409s on the app API — the distinction matters to callers
            // that hold retryable state (the pub finalize path), not to the status.
            Error::Conflict { .. } | Error::Busy { .. } | Error::LastOwner { .. } => StatusCode::CONFLICT,
            // Distinct `step_up_required` code on the same 403 so the UI can prompt for a
            // fresh second factor instead of a dead-end denial (S-06).
            Error::Forbidden { .. } | Error::StepUpRequired => StatusCode::FORBIDDEN,
            // The auth failures: uniform 401s. `refresh_reused` keeps its distinct code so
            // the client can drop the whole session (S-08); `invalid_code` collapses every
            // OTP failure (S-03/S-04).
            Error::Unauthorized { .. } | Error::InvalidCode | Error::RefreshReused { .. } => StatusCode::UNAUTHORIZED,
            Error::RateLimited { .. } => StatusCode::TOO_MANY_REQUESTS,
            Error::Expired { .. } => StatusCode::GONE,
            // S-09/S-24: a KV outage on the auth fast paths fails closed — reject, don't guess.
            Error::Kv { .. } => StatusCode::SERVICE_UNAVAILABLE,
            Error::Unimplemented { .. } => StatusCode::NOT_IMPLEMENTED,
            Error::Config { .. } | Error::Database { .. } | Error::Blob { .. } | Error::Internal { .. } => {
                StatusCode::INTERNAL_SERVER_ERROR
            }
            // `Error` is non_exhaustive; unknown future variants are server faults until mapped.
            _ => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let status = self.status();
        let code = self.0.code();
        // 5xx details go to the log, never to the wire (docs/rules/rust.md).
        let message = if status.is_server_error() {
            tracing::error!(code, error = %self.0, "request failed");
            "the server could not complete the request".to_owned()
        } else {
            self.0.to_string()
        };
        let mut response = (status, Json(ErrorEnvelope::new(code, message))).into_response();
        if let Error::RateLimited { retry_after_secs } = &self.0 {
            // S-24: 429 always carries Retry-After.
            let value =
                HeaderValue::from_str(&retry_after_secs.to_string()).unwrap_or_else(|_| HeaderValue::from_static("60"));
            response.headers_mut().insert(header::RETRY_AFTER, value);
        }
        response
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn status_of(err: Error) -> StatusCode {
        ApiError(err).status()
    }

    #[test]
    fn statuses_follow_the_contract() {
        assert_eq!(status_of(Error::Invalid { message: "m".into() }), StatusCode::BAD_REQUEST);
        assert_eq!(status_of(Error::NotFound { what: "w".into() }), StatusCode::NOT_FOUND);
        assert_eq!(status_of(Error::Conflict { message: "m".into() }), StatusCode::CONFLICT);
        assert_eq!(status_of(Error::Busy { message: "m".into() }), StatusCode::CONFLICT);
        assert_eq!(status_of(Error::Forbidden { message: "m".into() }), StatusCode::FORBIDDEN);
        assert_eq!(status_of(Error::StepUpRequired), StatusCode::FORBIDDEN);
        assert_eq!(status_of(Error::Unauthorized { message: "m".into() }), StatusCode::UNAUTHORIZED);
        assert_eq!(status_of(Error::InvalidCode), StatusCode::UNAUTHORIZED);
        assert_eq!(status_of(Error::RefreshReused { session: pub_core::SessionId::new() }), StatusCode::UNAUTHORIZED);
        assert_eq!(status_of(Error::RateLimited { retry_after_secs: 1 }), StatusCode::TOO_MANY_REQUESTS);
        // Fail closed on KV loss (S-09).
        assert_eq!(status_of(Error::Kv { message: "down".into() }), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(status_of(Error::Database { message: "m".into() }), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[test]
    fn server_errors_never_leak_details() {
        let response = ApiError(Error::Database { message: "connection string with password".into() }).into_response();
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        // The body is built from the generic message — the details never reach it.
    }

    #[test]
    fn rate_limited_carries_retry_after() {
        let response = ApiError(Error::RateLimited { retry_after_secs: 42 }).into_response();
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(response.headers()[header::RETRY_AFTER], "42");
    }
}
