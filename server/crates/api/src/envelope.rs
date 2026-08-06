//! App API envelope (docs/rules/api.md): `{"status":"ok","data":…}` /
//! `{"status":"error","error":{"code","message"}}`. Pub protocol routes use the spec error
//! shape instead — the two families never mix.

use serde::Serialize;
use utoipa::ToSchema;

/// Successful app API response.
#[derive(Debug, Serialize, ToSchema)]
pub struct OkEnvelope<T> {
    /// Always `"ok"`.
    pub status: String,
    /// Endpoint-specific payload.
    pub data: T,
}

impl<T> OkEnvelope<T> {
    /// Wraps a payload in the success envelope.
    pub fn new(data: T) -> Self {
        Self { status: "ok".to_owned(), data }
    }
}

/// Failed app API response.
#[derive(Debug, Serialize, ToSchema)]
pub struct ErrorEnvelope {
    /// Always `"error"`.
    pub status: String,
    /// Machine-readable error details.
    pub error: ErrorBody,
}

/// Error details inside [`ErrorEnvelope`].
#[derive(Debug, Serialize, ToSchema)]
pub struct ErrorBody {
    /// Stable machine-readable code (`core::Error::code()`).
    pub code: String,
    /// Human-readable description; never parsed by clients.
    pub message: String,
}

impl ErrorEnvelope {
    /// Builds the error envelope from a stable code and a human-readable message.
    pub fn new(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self { status: "error".to_owned(), error: ErrorBody { code: code.into(), message: message.into() } }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ok_envelope_shape() {
        let json = serde_json::to_value(OkEnvelope::new("pong")).unwrap();
        assert_eq!(json, serde_json::json!({"status": "ok", "data": "pong"}));
    }

    #[test]
    fn error_envelope_shape() {
        let json = serde_json::to_value(ErrorEnvelope::new("not_found", "no route")).unwrap();
        assert_eq!(json, serde_json::json!({"status": "error", "error": {"code": "not_found", "message": "no route"}}));
    }
}
