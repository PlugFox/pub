//! The pub-protocol error shape and the status ladder (decision 05, S-04/S-14,
//! docs/protocol.md sharp edges 1, 2 and 6).
//!
//! Nothing here is shared with the app API: pub-protocol responses carry the spec's bare
//! `{"error":{"code","message"}}` object, never the `{"status":"ok"|"error"}` envelope
//! (docs/rules/api.md — "the two families never mix").
//!
//! Two client behaviors dictate the design:
//!
//! - **A 401 destroys the user's stored credential.** The pub client deletes its token on any
//!   401 and prints the `message` from the `WWW-Authenticate` challenge. So 401 is reserved
//!   for credentials that are genuinely absent or invalid, and *both* 401 and 403 carry the
//!   challenge — it is the only channel we have into the CLI.
//! - **The client retries 408, 429, and every ≥500 up to 7 times.** A permanent failure that
//!   escapes as 5xx becomes seven hammering requests and a nonsense error message, so every
//!   caller-caused rejection maps into 4xx here; the mapping is asserted by
//!   [`tests::permanent_failures_never_map_to_5xx`].

use axum::Json;
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use pub_core::Error;
use serde::Serialize;
use utoipa::ToSchema;

/// Media type of every pub-protocol JSON response (spec v2).
pub const PUB_V2_MEDIA_TYPE: &str = "application/vnd.pub.v2+json";

/// Longest `message` we put inside a `WWW-Authenticate` challenge (docs/protocol.md sharp
/// edge 1). The client truncates beyond this; we do it first so the header stays well-formed.
const MAX_CHALLENGE_MESSAGE: usize = 1024;

/// Fallback challenge used if a message somehow cannot become a header value. The challenge
/// itself must never be dropped: a 401 without it leaves the CLI with a deleted token and no
/// explanation.
const FALLBACK_CHALLENGE: &str = "Bearer realm=\"pub\"";

/// The spec's error body — `{"error":{"code","message"}}`.
///
/// Only `message` is ever shown to a user; `code` exists for tooling and our own tests.
#[derive(Debug, Serialize, ToSchema)]
pub struct SpecError {
    /// The error detail object.
    pub error: SpecErrorBody,
}

/// Contents of [`SpecError::error`].
#[derive(Debug, Serialize, ToSchema)]
pub struct SpecErrorBody {
    /// Stable machine-readable code (from [`pub_core::Error::code`] where one exists).
    pub code: String,
    /// Human-readable text; this is what the CLI prints.
    pub message: String,
}

/// A pub-protocol failure: status, spec body, and — on 401/403 — the `WWW-Authenticate`
/// challenge that carries our message into the CLI.
#[derive(Debug)]
pub struct ProtocolError {
    status: StatusCode,
    code: &'static str,
    message: String,
    challenge: bool,
    retry_after_secs: Option<u64>,
}

impl ProtocolError {
    /// 401 + challenge. **Only** for absent, malformed, or unusable credentials (S-14): the
    /// client deletes its stored token on this status, so a 401 for anything else silently
    /// logs the user out.
    pub fn unauthorized(message: impl Into<String>) -> Self {
        Self::challenged(StatusCode::UNAUTHORIZED, "unauthorized", message)
    }

    /// 403 + challenge. For a valid credential with insufficient scope or role on a resource
    /// the principal can *see*; the token survives and the message explains how to get access.
    pub fn forbidden(message: impl Into<String>) -> Self {
        Self::challenged(StatusCode::FORBIDDEN, "forbidden", message)
    }

    /// 404, no challenge. Everything the principal may not read — another org's private
    /// package, an unclaimed name, an unknown org — collapses here (S-04 anti-enumeration).
    pub fn not_found(message: impl Into<String>) -> Self {
        Self::plain(StatusCode::NOT_FOUND, "not_found", message)
    }

    /// 400 for malformed input.
    pub fn invalid(message: impl Into<String>) -> Self {
        Self::plain(StatusCode::BAD_REQUEST, "invalid_argument", message)
    }

    /// 405, no challenge. A route that exists under a registry base but not for this method.
    ///
    /// Exists so the spec error shape covers the responses axum's method router produces on
    /// its own: an empty 405 body is not parseable JSON, and "the response body is JSON" is
    /// what every client-side error path here assumes.
    pub fn method_not_allowed(message: impl Into<String>) -> Self {
        Self::plain(StatusCode::METHOD_NOT_ALLOWED, "method_not_allowed", message)
    }

    /// 406 — reserved **exclusively** for "this client speaks an API version we do not"
    /// (docs/protocol.md sharp edge 6). The CLI turns this status into an upgrade prompt, so
    /// using it for ordinary content negotiation would tell users to upgrade for no reason.
    pub fn unsupported_api_version(message: impl Into<String>) -> Self {
        Self::plain(StatusCode::NOT_ACCEPTABLE, "unsupported_api_version", message)
    }

    /// Maps a domain error onto the ladder.
    ///
    /// The interesting rows: `Conflict` becomes **400**, not 409, because the finalize step's
    /// entire contract is `200 {"success":…}` or `400 {"error":…}` (docs/protocol.md endpoint
    /// 4) and "this version already exists" is its most common outcome. `Forbidden` and
    /// `Unauthorized` keep their challenge. Only genuine server faults reach 5xx.
    pub fn from_domain(err: Error) -> Self {
        match err {
            Error::NotFound { what } => Self::not_found(format!("{what} was not found")),
            Error::Unauthorized { message } => Self::unauthorized(message),
            Error::Forbidden { message } => Self::forbidden(message),
            Error::Invalid { message } => Self::invalid(message),
            Error::Conflict { message } => Self::plain(StatusCode::BAD_REQUEST, "conflict", message),
            Error::Expired { what } => Self::plain(StatusCode::BAD_REQUEST, "expired", format!("{what} has expired")),
            Error::StepUpRequired => Self::forbidden(err.to_string()),
            Error::RateLimited { retry_after_secs } => Self {
                status: StatusCode::TOO_MANY_REQUESTS,
                code: "rate_limited",
                message: format!("too many requests; retry in {retry_after_secs}s"),
                challenge: false,
                retry_after_secs: Some(retry_after_secs),
            },
            // S-09/S-24: the KV fast paths fail closed. 503 is honest *and* correct for the
            // client — a KV outage is transient, so retrying is the right behavior.
            Error::Kv { .. } => Self::server_fault(StatusCode::SERVICE_UNAVAILABLE, err),
            other => Self::server_fault(StatusCode::INTERNAL_SERVER_ERROR, other),
        }
    }

    /// The mapped status (used by the finalize handler to decide whether an upload session is
    /// dead — permanent failures burn it, transient ones leave it retryable).
    pub fn status(&self) -> StatusCode {
        self.status
    }

    /// The caller-facing message — the text the CLI prints.
    pub fn message(&self) -> &str {
        &self.message
    }

    fn challenged(status: StatusCode, code: &'static str, message: impl Into<String>) -> Self {
        Self { status, code, message: message.into(), challenge: true, retry_after_secs: None }
    }

    fn plain(status: StatusCode, code: &'static str, message: impl Into<String>) -> Self {
        Self { status, code, message: message.into(), challenge: false, retry_after_secs: None }
    }

    /// A server fault: logged with its detail, answered with a generic sentence. Backend error
    /// text can carry connection strings and bucket names (docs/rules/rust.md).
    fn server_fault(status: StatusCode, err: Error) -> Self {
        tracing::error!(code = err.code(), error = %err, "pub protocol request failed");
        Self {
            status,
            code: err.code(),
            message: "the server could not complete the request".to_owned(),
            challenge: false,
            retry_after_secs: None,
        }
    }
}

impl From<Error> for ProtocolError {
    fn from(err: Error) -> Self {
        Self::from_domain(err)
    }
}

impl IntoResponse for ProtocolError {
    fn into_response(self) -> Response {
        let body = SpecError { error: SpecErrorBody { code: self.code.to_owned(), message: self.message.clone() } };
        let mut response = (self.status, Json(body)).into_response();
        let headers = response.headers_mut();
        headers.insert(header::CONTENT_TYPE, HeaderValue::from_static(PUB_V2_MEDIA_TYPE));
        if self.challenge {
            headers.insert(header::WWW_AUTHENTICATE, challenge_value(&self.message));
        }
        if let Some(secs) = self.retry_after_secs {
            let value = HeaderValue::from_str(&secs.to_string()).unwrap_or_else(|_| HeaderValue::from_static("60"));
            headers.insert(header::RETRY_AFTER, value);
        }
        response
    }
}

/// Builds `Bearer realm="pub", message="…"` with the message sanitized for a header value.
///
/// Sanitizing is not cosmetic: `message` is assembled from package names, org slugs, and
/// backend text, and a stray quote, backslash, newline, or non-ASCII byte would either
/// truncate the challenge or make the whole header unsendable — losing the only explanation
/// the CLI will ever show for a denial.
fn challenge_value(message: &str) -> HeaderValue {
    let sanitized: String = message
        .chars()
        .map(|c| if c == '"' || c == '\\' { '\'' } else { c })
        .filter(|c| c.is_ascii_graphic() || *c == ' ')
        .take(MAX_CHALLENGE_MESSAGE)
        .collect();
    HeaderValue::from_str(&format!("Bearer realm=\"pub\", message=\"{sanitized}\""))
        .unwrap_or_else(|_| HeaderValue::from_static(FALLBACK_CHALLENGE))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn header_of(err: ProtocolError) -> Option<String> {
        let response = err.into_response();
        response.headers().get(header::WWW_AUTHENTICATE).map(|value| value.to_str().unwrap().to_owned())
    }

    #[test]
    fn s14_401_and_403_both_carry_the_same_challenge_shape() {
        for challenge in
            [header_of(ProtocolError::unauthorized("add a token")), header_of(ProtocolError::forbidden("ask an admin"))]
        {
            let challenge = challenge.expect("both statuses must challenge");
            assert!(challenge.starts_with("Bearer realm=\"pub\", message=\""), "bad challenge: {challenge}");
        }
    }

    #[test]
    fn s04_404_never_challenges() {
        // A challenge on a 404 would tell an anonymous prober that the name exists.
        assert_eq!(header_of(ProtocolError::not_found("no such package")), None);
    }

    #[test]
    fn challenge_message_is_sanitized_and_bounded() {
        let challenge = header_of(ProtocolError::unauthorized("say \"hi\"\nand \\escape\u{00e9}")).unwrap();
        assert_eq!(challenge, "Bearer realm=\"pub\", message=\"say 'hi'and 'escape\"");
        let long = header_of(ProtocolError::unauthorized("x".repeat(5000))).unwrap();
        assert_eq!(long.len(), "Bearer realm=\"pub\", message=\"\"".len() + MAX_CHALLENGE_MESSAGE);
    }

    #[test]
    fn permanent_failures_never_map_to_5xx() {
        // docs/protocol.md sharp edge 2: the client retries 5xx up to 7 times, so a doomed
        // request answered with 5xx is hammered six more times for nothing.
        let permanent = [
            Error::Invalid { message: "bad".into() },
            Error::NotFound { what: "package".into() },
            Error::Conflict { message: "exists".into() },
            Error::Forbidden { message: "nope".into() },
            Error::Unauthorized { message: "nope".into() },
            Error::Expired { what: "session".into() },
            Error::StepUpRequired,
        ];
        for err in permanent {
            let code = err.code();
            let status = ProtocolError::from_domain(err).status;
            assert!(status.is_client_error(), "{code} mapped to {status}, which the client would retry");
        }
    }

    #[test]
    fn duplicate_version_conflict_is_400_not_409() {
        // The finalize contract is 200-or-400; a 409 body would still render, but the status
        // ladder we promise (and test) is the spec's.
        let err = ProtocolError::from_domain(Error::Conflict { message: "version 1.0.0 already exists".into() });
        assert_eq!(err.status, StatusCode::BAD_REQUEST);
        assert_eq!(err.code, "conflict");
    }

    #[test]
    fn server_faults_do_not_leak_backend_text() {
        let err = ProtocolError::from_domain(Error::Database { message: "postgres://user:hunter2@db/pub".into() });
        assert_eq!(err.status, StatusCode::INTERNAL_SERVER_ERROR);
        assert!(!err.message.contains("hunter2"), "leaked: {}", err.message);
    }

    #[test]
    fn kv_outage_is_503_and_rate_limits_carry_retry_after() {
        assert_eq!(
            ProtocolError::from_domain(Error::Kv { message: "down".into() }).status,
            StatusCode::SERVICE_UNAVAILABLE
        );
        let response = ProtocolError::from_domain(Error::RateLimited { retry_after_secs: 17 }).into_response();
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(response.headers()[header::RETRY_AFTER], "17");
    }

    #[test]
    fn a_wrong_method_is_a_permanent_4xx_without_a_challenge() {
        let err = ProtocolError::method_not_allowed("POST is not supported here");
        assert_eq!(err.status, StatusCode::METHOD_NOT_ALLOWED);
        assert!(err.status.is_client_error(), "a retryable status here would loop the client");
        assert_eq!(header_of(err), None);
    }

    #[test]
    fn every_error_response_is_the_spec_shape_with_the_v2_media_type() {
        let response = ProtocolError::not_found("acme_core was not found").into_response();
        assert_eq!(response.headers()[header::CONTENT_TYPE], PUB_V2_MEDIA_TYPE);
    }
}
