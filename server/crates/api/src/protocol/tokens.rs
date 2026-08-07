//! The CLI-token credential plane for pub-protocol routes (S-13/S-14, decisions 03 and 13).
//!
//! This is the *only* credential accepted here. Browser access JWTs are structurally rejected:
//! [`pub_auth::token::validate`] demands the instance token prefix, a fixed length, a base62
//! charset, and a matching CRC32, and a JWT (`eyJ…` with dots) fails all four before any
//! lookup happens. That is the "two planes, never mixed" rule of decision 03 enforced by the
//! credential format rather than by a hand-written `if`.
//!
//! # Where the token may travel
//!
//! The `Authorization: Bearer …` header, and nowhere else. The pub client sends its credential
//! that way on every request whose URL matches the stored prefix (docs/protocol.md, "Client-side
//! facts"), and the spec has no query-parameter form — so we do not accept `?token=`. A query
//! credential would be a real regression: URLs land in access logs, proxy logs, and
//! `Referer` headers, and `archive_url` values end up in users' `pubspec.lock` files.
//!
//! # Ladder
//!
//! - No `Authorization` at all → anonymous, unless `registry.require_auth_for_read` is on, in
//!   which case the spec-mandated **401** with an onboarding message (decision 05).
//! - An `Authorization` header we cannot use → **401**. The client deletes its stored token on
//!   this status, which is correct: the credential it holds does not work here.
//! - A working token with too little scope or role → **403** on a resource the principal can
//!   see, **404** on anything it cannot (S-04) — decided by the handlers, not here.

use axum::extract::FromRequestParts;
use axum::http::header;
use axum::http::request::Parts;
use pub_core::Error;
use pub_core::authorize::ActorContext;
use pub_core::package::{Resolution, Visibility};
use pub_core::token::{Token, TokenScope, patterns_allow};

use crate::extract::client_meta;
use crate::protocol::base::{PathParams, advertised_base_url};
use crate::protocol::error::ProtocolError;
use crate::state::AppState;

/// An authenticated CLI token plus the principal it acts as.
pub struct TokenContext {
    /// The token row (scopes, org binding, package patterns).
    pub token: Token,
    /// Actor for the `authorize()` chokepoint, derived from the **current** org membership.
    pub actor: ActorContext,
}

impl TokenContext {
    /// Whether the token carries `scope`.
    pub fn has_scope(&self, scope: TokenScope) -> bool {
        self.token.scopes.contains(&scope)
    }

    /// Asserts `scope`, with a message that tells the user how to fix it — 403 is the only
    /// place the CLI will render an explanation (S-14).
    pub fn require_scope(&self, scope: TokenScope, base_url: &str) -> Result<(), ProtocolError> {
        if self.has_scope(scope) {
            return Ok(());
        }
        Err(ProtocolError::forbidden(format!(
            "this token does not have the '{scope}' scope; create one that does and run \
             `dart pub token add {base_url}`"
        )))
    }

    /// Whether the token's package-pattern narrowing admits `name` (S-13).
    pub fn allows_package(&self, name: &str) -> bool {
        patterns_allow(&self.token.package_patterns, name)
    }
}

/// Who is making a pub-protocol request.
///
/// The token arm is boxed so the anonymous arm — the common case on a public instance — stays
/// a bare discriminant instead of carrying a token row's worth of padding.
pub enum Principal {
    /// No credential presented, and none required (decision 05 default).
    Anonymous,
    /// A working CLI token.
    Token(Box<TokenContext>),
}

impl Principal {
    /// The actor for `authorize(actor, action, resource)`; anonymous holds no roles.
    pub fn actor(&self) -> &ActorContext {
        static ANONYMOUS: std::sync::LazyLock<ActorContext> = std::sync::LazyLock::new(ActorContext::anonymous);
        match self {
            Self::Anonymous => &ANONYMOUS,
            Self::Token(ctx) => &ctx.actor,
        }
    }

    /// The token context, when one was presented.
    pub fn token(&self) -> Option<&TokenContext> {
        match self {
            Self::Anonymous => None,
            Self::Token(ctx) => Some(ctx.as_ref()),
        }
    }

    /// Narrows a base resolution by the token's package patterns (S-13).
    ///
    /// Narrowing only ever *removes* access, so it cannot affect decision 01's ordering — a
    /// name that resolved locally still never falls through to upstream. Public packages are
    /// deliberately left alone: they are readable with no credential at all, so letting a
    /// pattern hide one would make holding a token strictly worse than holding none.
    pub fn narrow(&self, resolved: Resolution) -> Resolution {
        let Resolution::Readable(package) = &resolved else {
            return resolved;
        };
        if package.visibility == Visibility::Public {
            return resolved;
        }
        match self.token() {
            Some(ctx) if !ctx.allows_package(&package.name) => Resolution::Restricted { owner: package.org_id },
            _ => resolved,
        }
    }
}

impl FromRequestParts<AppState> for Principal {
    type Rejection = ProtocolError;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, Self::Rejection> {
        // The base URL for messages is derived from the path, not from a loaded org row: this
        // extractor deliberately runs *before* `Base`, so that "who are you" is answered
        // before "does that org exist" and `require_auth_for_read` cannot be probed for org
        // names by an anonymous caller.
        let params = PathParams::from_request_parts(parts, state).await.unwrap_or_else(|never| match never {});
        let base_url = advertised_base_url(&state.settings.server.public_url, params.get("org"));

        let presented =
            parts.headers.get(header::AUTHORIZATION).map(|value| value.to_str().ok().and_then(bearer_secret));

        let secret = match presented {
            Some(Some(secret)) => secret.to_owned(),
            // A header we cannot use (wrong scheme, empty, non-ASCII) is an invalid
            // credential, not an absent one.
            Some(None) => return Err(ProtocolError::unauthorized(rejected_token(&base_url))),
            None => {
                // The runtime cache, not boot config: the flag is a `registry` settings section
                // an administrator flips without a restart (decision 05 amendment). Boot config
                // remains its default, so an instance whose table was never written behaves
                // exactly as its config file says.
                return if state.runtime.current().registry.require_auth_for_read {
                    Err(ProtocolError::unauthorized(onboarding(&base_url)))
                } else {
                    Ok(Self::Anonymous)
                };
            }
        };

        let now = (state.clock)();
        let meta = client_meta(&parts.headers, &parts.extensions, state.trust_proxy_headers());
        let token = state.auth.authenticate_cli_token(&secret, &meta, now).await.map_err(|err| match err {
            // The uniform "unknown, revoked, or expired" denial gets an actionable message;
            // everything else (throttled, KV down) keeps its own mapping.
            Error::Unauthorized { .. } => ProtocolError::unauthorized(rejected_token(&base_url)),
            other => ProtocolError::from_domain(other),
        })?;
        let actor = state.auth.token_actor(&token).await?;
        state.auth.touch_cli_token(&token, meta.ip.as_deref(), now).await;
        Ok(Self::Token(Box::new(TokenContext { token, actor })))
    }
}

/// The secret out of an `Authorization` header value, if it is a non-empty `Bearer` credential.
///
/// The scheme is matched **case-insensitively** (RFC 9110 §11.1: auth schemes are
/// case-insensitive). That is not pedantry here: on this plane a rejected credential is a 401,
/// and a 401 makes the pub client *delete the user's stored token*. A proxy that normalizes the
/// scheme, or any client that spells it `bearer`, must not cost a developer their credential.
fn bearer_secret(raw: &str) -> Option<&str> {
    let (scheme, rest) = raw.split_once(' ')?;
    if !scheme.eq_ignore_ascii_case("bearer") {
        return None;
    }
    let secret = rest.trim();
    if secret.is_empty() { None } else { Some(secret) }
}

/// The message an anonymous caller sees when the instance requires authentication.
fn onboarding(base_url: &str) -> String {
    format!("this registry requires authentication; run `dart pub token add {base_url}` with a token from {base_url}")
}

/// The message a caller sees when the credential it presented does not work here.
///
/// Worded as "not valid **for this registry**" on purpose: the client is about to delete the
/// token it holds, and the most common cause is a token minted for another instance or org.
fn rejected_token(base_url: &str) -> String {
    format!(
        "the credential presented is not valid for this registry; \
         run `dart pub token add {base_url}` with a current token"
    )
}

#[cfg(test)]
mod tests {
    use chrono::Utc;
    use pub_core::package::Package;
    use pub_core::{Format, OrgId, PackageId, RoleLevel, TokenId, UserId};

    use super::*;

    fn token(patterns: &[&str], scopes: &[TokenScope]) -> Token {
        Token {
            id: TokenId::new(),
            user_id: UserId::new(),
            org_id: OrgId::new(),
            name: "ci".to_owned(),
            display_hint: "pub_abcd".to_owned(),
            scopes: scopes.to_vec(),
            package_patterns: patterns.iter().map(|p| (*p).to_owned()).collect(),
            created_at: Utc::now(),
            expires_at: None,
            last_used_at: None,
            last_used_ip: None,
            revoked_at: None,
        }
    }

    fn principal(patterns: &[&str]) -> Principal {
        let token = token(patterns, &[TokenScope::Read]);
        let actor = ActorContext::user(token.user_id, [(token.org_id, RoleLevel::READ)].into_iter().collect());
        Principal::Token(Box::new(TokenContext { token, actor }))
    }

    fn package(name: &str, visibility: Visibility) -> Package {
        Package {
            id: PackageId::new(),
            format: Format::Pub,
            name: name.to_owned(),
            org_id: OrgId::new(),
            visibility,
            discontinued: false,
            replaced_by: None,
            unlisted: false,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    #[test]
    fn s13_patterns_hide_private_packages_outside_them() {
        let principal = principal(&["acme_*"]);
        let inside = Resolution::Readable(package("acme_core", Visibility::Private));
        assert!(matches!(principal.narrow(inside), Resolution::Readable(_)));
        let outside = Resolution::Readable(package("other_pkg", Visibility::Private));
        assert!(matches!(principal.narrow(outside), Resolution::Restricted { .. }));
    }

    #[test]
    fn s13_patterns_never_hide_a_public_package() {
        // A public package resolves with no credential at all; narrowing it would make the
        // token worse than anonymous.
        let principal = principal(&["acme_*"]);
        let public = Resolution::Readable(package("other_pkg", Visibility::Public));
        assert!(matches!(principal.narrow(public), Resolution::Readable(_)));
    }

    #[test]
    fn narrowing_leaves_non_readable_resolutions_alone() {
        let principal = principal(&["acme_*"]);
        // Local-always-wins: narrowing must never turn a claimed name into a proxy candidate.
        assert!(matches!(
            principal.narrow(Resolution::Restricted { owner: OrgId::new() }),
            Resolution::Restricted { .. }
        ));
        assert!(matches!(principal.narrow(Resolution::Unclaimed), Resolution::Unclaimed));
        assert!(matches!(Principal::Anonymous.narrow(Resolution::Unclaimed), Resolution::Unclaimed));
    }

    #[test]
    fn an_unpatterned_token_reads_everything_its_role_allows() {
        let principal = principal(&[]);
        let private = Resolution::Readable(package("other_pkg", Visibility::Private));
        assert!(matches!(principal.narrow(private), Resolution::Readable(_)));
    }

    #[test]
    fn s14_missing_scope_is_a_403_that_explains_itself() {
        let ctx = TokenContext { token: token(&[], &[TokenScope::Read]), actor: ActorContext::anonymous() };
        assert!(ctx.has_scope(TokenScope::Read));
        let err = ctx.require_scope(TokenScope::Publish, "https://pub.corp.test/o/acme/pub").unwrap_err();
        assert_eq!(err.status(), axum::http::StatusCode::FORBIDDEN);
        let message = err.message();
        assert!(message.contains("'publish' scope"), "message must name the scope: {message}");
        assert!(message.contains("https://pub.corp.test/o/acme/pub"), "message must name the base: {message}");
    }

    #[test]
    fn anonymous_holds_no_roles() {
        assert_eq!(Principal::Anonymous.actor().role_in(OrgId::new()), RoleLevel::NONE);
        assert!(Principal::Anonymous.token().is_none());
    }

    #[test]
    fn the_bearer_scheme_is_case_insensitive_but_the_secret_is_not_touched() {
        // A 401 deletes the user's stored token, so header casing must never cause one.
        assert_eq!(bearer_secret("Bearer pub_abc"), Some("pub_abc"));
        assert_eq!(bearer_secret("bearer pub_abc"), Some("pub_abc"));
        assert_eq!(bearer_secret("BEARER  pub_abc  "), Some("pub_abc"));
        // Anything that is not a bearer credential still is not one.
        for raw in ["Basic dXNlcjpwYXNz", "Bearer", "Bearer ", "pub_abc", "Bearerpub_abc", ""] {
            assert_eq!(bearer_secret(raw), None, "accepted {raw:?}");
        }
    }

    #[test]
    fn messages_quote_the_exact_token_add_command() {
        let base = "https://pub.corp.test/o/acme/pub";
        assert!(onboarding(base).contains("dart pub token add https://pub.corp.test/o/acme/pub"));
        assert!(rejected_token(base).contains("dart pub token add https://pub.corp.test/o/acme/pub"));
    }
}
