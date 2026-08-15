//! CLI/API tokens (decision 13, S-13): the second credential plane, fully separate from web
//! sessions.
//!
//! Tokens are opaque `<prefix>_…` strings; only the SHA-256 hash and a first-8-chars display
//! hint are stored. Scopes are the fine-grained, non-linear permission plane next to the
//! linear org role ladder (decision 19).

use std::fmt;
use std::str::FromStr;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::authorize::Action;
use crate::{Error, OrgId, TokenId, UserId};

/// Token scope. Stored and serialized as a lowercase string.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TokenScope {
    /// Resolve and download packages.
    Read,
    /// Publish new versions.
    Publish,
    /// Retract / unretract versions.
    Retract,
    /// Org administration through the REST API (CI automation).
    Admin,
}

impl TokenScope {
    /// Canonical lowercase name as stored and used on the wire.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Read => "read",
            Self::Publish => "publish",
            Self::Retract => "retract",
            Self::Admin => "admin",
        }
    }

    /// The org-role action this scope is worth on the decision 19 ladder.
    ///
    /// The **single source** for "what a scope is worth": the token mint gate checks the
    /// holder's role against it, and the D37 post-demotion token sweep (decision 13 addendum)
    /// uses the same mapping to decide which tokens a lowered role can no longer hold. The
    /// comparison always happens in Rust — never duplicated into per-dialect SQL.
    pub const fn required_action(self) -> Action {
        match self {
            Self::Read => Action::ReadPackages,
            // Retract manages own versions — Write level, like publishing (S-06 step-up for
            // the dangerous variants arrives with the TOTP slice).
            Self::Publish | Self::Retract => Action::PublishPackages,
            Self::Admin => Action::ManageMembers,
        }
    }
}

impl fmt::Display for TokenScope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for TokenScope {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "read" => Ok(Self::Read),
            "publish" => Ok(Self::Publish),
            "retract" => Ok(Self::Retract),
            "admin" => Ok(Self::Admin),
            other => Err(Error::Invalid { message: format!("unknown token scope: {other}") }),
        }
    }
}

/// Whether `name` is inside a token's package-pattern narrowing (S-13).
///
/// An **empty** pattern list means "no narrowing" — the token's org binding and scopes are the
/// only limits. Otherwise the name must match at least one pattern.
///
/// The pattern vocabulary is deliberately one wildcard wide: a trailing `*` matches any suffix
/// (`acme_*`), everything else is an exact name. Package names are `[a-z0-9_]` (no dots, no
/// slashes, no `*`), so this covers the only grouping that exists in a flat namespace — the
/// org's name prefix — without inviting a regex engine into an authorization decision, where
/// a catastrophic-backtracking pattern would be a denial of service with extra steps.
pub fn patterns_allow(patterns: &[String], name: &str) -> bool {
    if patterns.is_empty() {
        return true;
    }
    patterns.iter().any(|pattern| match pattern.strip_suffix('*') {
        Some(prefix) => name.starts_with(prefix),
        None => pattern == name,
    })
}

/// Most patterns one token may carry.
///
/// A narrowing needs a handful of prefixes; a list this long is a caller building an allowlist
/// out of exact names, which is a job for a second token.
pub const MAX_TOKEN_PATTERNS: usize = 32;

/// Longest single pattern, matching the package-name bound the registry enforces at publish.
pub const MAX_PATTERN_LEN: usize = 64;

/// Validates and normalizes a token's package patterns against the grammar
/// [`patterns_allow`] actually reads ([S-13.c](../../../docs/security.md#3-cliapi-tokens)).
///
/// Checked at the **mint**, because the matcher never fails: a pattern it cannot satisfy does
/// not produce a narrower token, it produces a token that authorizes **nothing**, and its owner
/// discovers that at the first CI publish. The vocabulary is one wildcard wide — a single
/// trailing `*` is a prefix match, anything else is an exact name — so everything outside it is
/// refused here rather than stored as an authorization rule nobody can satisfy:
///
/// - a leading or interior `*`, or more than one `*` (there is no glob engine behind this, and
///   inviting one into an authorization decision is how a pattern becomes a denial of service);
/// - a bare `*`, because an empty list already means "no narrowing" and two spellings of one
///   meaning is a thing an operator has to test to believe;
/// - an empty pattern, one over [`MAX_PATTERN_LEN`], or any character outside the package-name
///   alphabet `[a-z0-9_]` once the trailing `*` is stripped — a package name can never contain a
///   dot, a dash, a slash or an upper-case letter, so such a pattern matches nothing forever;
/// - more than [`MAX_TOKEN_PATTERNS`] of them.
///
/// Duplicates are dropped and the caller's order is preserved, so what the token list renders is
/// what the mint stored.
pub fn validate_patterns(patterns: &[String]) -> Result<Vec<String>, Error> {
    if patterns.len() > MAX_TOKEN_PATTERNS {
        return Err(Error::Invalid {
            message: format!("at most {MAX_TOKEN_PATTERNS} package patterns per token, got {}", patterns.len()),
        });
    }
    let mut normalized: Vec<String> = Vec::with_capacity(patterns.len());
    for pattern in patterns {
        let invalid = |reason: &str| Error::Invalid {
            // The pattern is caller-supplied text going into an error message; it is bounded
            // above by the length check below, but a rejected one may be arbitrarily long, so it
            // is clipped rather than echoed whole.
            message: format!("package pattern {:?} is invalid: {reason}", clip_pattern(pattern)),
        };
        if pattern.is_empty() {
            return Err(invalid("it is empty"));
        }
        // `chars`, not bytes: the message says "characters" and a message that means bytes is
        // the kind of unasserted claim this codebase keeps finding. A multi-byte pattern is
        // refused by the charset rule below either way — but for the right reason.
        if pattern.chars().count() > MAX_PATTERN_LEN {
            return Err(invalid("it is longer than 64 characters"));
        }
        if pattern == "*" {
            return Err(invalid("an empty pattern list already means every package"));
        }
        let stem = pattern.strip_suffix('*').unwrap_or(pattern);
        if stem.contains('*') {
            return Err(invalid("the only wildcard is a single trailing '*'"));
        }
        if !stem.chars().all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == '_') {
            return Err(invalid("package names are lower-case [a-z0-9_], so this can never match"));
        }
        if !normalized.iter().any(|kept| kept == pattern) {
            normalized.push(pattern.clone());
        }
    }
    Ok(normalized)
}

/// First 64 characters of a rejected pattern, for an error message.
fn clip_pattern(pattern: &str) -> String {
    pattern.chars().take(MAX_PATTERN_LEN).collect()
}

/// A CLI/API token. The hash is deliberately not exposed on the domain struct — lookups go
/// through hash-keyed repository methods.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Token {
    /// Entity id (UUID v7).
    pub id: TokenId,
    /// User the token acts as.
    pub user_id: UserId,
    /// Org the token is bound to (S-13: tokens are org-bound).
    pub org_id: OrgId,
    /// User-chosen label ("CI deploy", …).
    pub name: String,
    /// First 8 characters of the plaintext, for the token list UI (S-13 display hint).
    pub display_hint: String,
    /// Granted scopes; never empty.
    pub scopes: Vec<TokenScope>,
    /// Optional package-name patterns narrowing the token further; empty = every package the
    /// org binding allows.
    pub package_patterns: Vec<String>,
    /// Creation time (UTC).
    pub created_at: DateTime<Utc>,
    /// Expiry (UTC); `None` = non-expiring (allowed only for pure-`read` tokens — S-13,
    /// enforced by the token-mint flow, not the repo).
    pub expires_at: Option<DateTime<Utc>>,
    /// Last use (UTC), write-throttled (S-13).
    pub last_used_at: Option<DateTime<Utc>>,
    /// IP of the last use, write-throttled together with `last_used_at`.
    pub last_used_ip: Option<String>,
    /// Revocation time; revoked tokens never authenticate again.
    pub revoked_at: Option<DateTime<Utc>>,
}

/// Payload for minting a token (id and `created_at` are assigned by the repo).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NewToken {
    /// User the token acts as.
    pub user_id: UserId,
    /// Org binding.
    pub org_id: OrgId,
    /// User-chosen label.
    pub name: String,
    /// SHA-256 hex of the plaintext token (S-13; plaintext is shown once and never stored).
    pub token_hash: String,
    /// First 8 characters of the plaintext.
    pub display_hint: String,
    /// Granted scopes; must not be empty.
    pub scopes: Vec<TokenScope>,
    /// Optional package-name patterns; empty = no narrowing.
    pub package_patterns: Vec<String>,
    /// Expiry (UTC), if any.
    pub expires_at: Option<DateTime<Utc>>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scope_round_trips_through_from_str() {
        for scope in [TokenScope::Read, TokenScope::Publish, TokenScope::Retract, TokenScope::Admin] {
            assert_eq!(scope.as_str().parse::<TokenScope>().unwrap(), scope);
        }
    }

    #[test]
    fn unknown_scope_is_invalid() {
        assert_eq!("delete".parse::<TokenScope>().unwrap_err().code(), "invalid_argument");
    }

    #[test]
    fn scope_role_mapping_matches_decision_19() {
        use crate::RoleLevel;
        assert_eq!(TokenScope::Read.required_action(), Action::ReadPackages);
        assert_eq!(TokenScope::Publish.required_action(), Action::PublishPackages);
        assert_eq!(TokenScope::Retract.required_action(), Action::PublishPackages);
        assert_eq!(TokenScope::Admin.required_action(), Action::ManageMembers);
        // The levels behind the actions — the numbers the mint gate and the D37 sweep compare.
        assert_eq!(TokenScope::Read.required_action().required_level(), Some(RoleLevel::READ));
        assert_eq!(TokenScope::Publish.required_action().required_level(), Some(RoleLevel::WRITE));
        assert_eq!(TokenScope::Retract.required_action().required_level(), Some(RoleLevel::WRITE));
        assert_eq!(TokenScope::Admin.required_action().required_level(), Some(RoleLevel::ADMIN));
    }

    #[test]
    fn serde_uses_lowercase() {
        assert_eq!(
            serde_json::to_string(&vec![TokenScope::Read, TokenScope::Publish]).unwrap(),
            r#"["read","publish"]"#
        );
    }

    #[test]
    fn no_patterns_means_no_narrowing() {
        assert!(patterns_allow(&[], "anything"));
    }

    #[test]
    fn prefix_pattern_matches_the_prefix_only() {
        let patterns = vec!["acme_*".to_owned()];
        assert!(patterns_allow(&patterns, "acme_core"));
        assert!(patterns_allow(&patterns, "acme_"));
        assert!(!patterns_allow(&patterns, "acme"));
        assert!(!patterns_allow(&patterns, "other_acme_core"));
    }

    #[test]
    fn bare_pattern_is_an_exact_name() {
        let patterns = vec!["acme_core".to_owned()];
        assert!(patterns_allow(&patterns, "acme_core"));
        // No implicit prefix semantics: a bare pattern never matches a longer name.
        assert!(!patterns_allow(&patterns, "acme_core_extra"));
    }

    #[test]
    fn any_matching_pattern_admits() {
        let patterns = vec!["acme_*".to_owned(), "shared_utils".to_owned()];
        assert!(patterns_allow(&patterns, "shared_utils"));
        assert!(patterns_allow(&patterns, "acme_core"));
        assert!(!patterns_allow(&patterns, "evil_pkg"));
    }

    #[test]
    fn a_lone_star_admits_everything() {
        assert!(patterns_allow(&["*".to_owned()], "whatever"));
    }

    fn patterns(raw: &[&str]) -> Vec<String> {
        raw.iter().map(|p| (*p).to_owned()).collect()
    }

    #[test]
    fn s13_c_the_grammar_the_matcher_reads_is_the_grammar_the_mint_accepts() {
        let accepted = patterns(&["acme_*", "shared_utils", "a", "_", "pkg9_*"]);
        assert_eq!(validate_patterns(&accepted).unwrap(), accepted);
    }

    #[test]
    fn s13_c_everything_the_matcher_cannot_satisfy_is_refused() {
        // Each of these would mint a token that authorizes nothing: `patterns_allow` reads one
        // trailing `*` or an exact lower-case name, and a package name can carry none of these
        // characters, so the pattern could never match anything for the life of the token.
        for bad in ["", "*", "*acme", "ac*me", "acme_**", "acme-*", "Acme_*", "acme.core", "acme/core", "acme core"] {
            let err = validate_patterns(&patterns(&[bad])).unwrap_err();
            assert_eq!(err.code(), "invalid_argument", "{bad:?} should have been refused");
        }
        let long = "a".repeat(MAX_PATTERN_LEN + 1);
        assert_eq!(validate_patterns(&[long]).unwrap_err().code(), "invalid_argument");
        // Sixty-four multi-byte characters is 128 bytes and still sixty-four characters: it is
        // refused for its alphabet, which is what the message would say, rather than for a
        // length it does not exceed.
        let cyrillic = "ы".repeat(MAX_PATTERN_LEN);
        let err = validate_patterns(&[cyrillic]).unwrap_err();
        assert!(err.to_string().contains("lower-case"), "refused for the wrong reason: {err}");
        let many: Vec<String> = (0..=MAX_TOKEN_PATTERNS).map(|i| format!("pkg{i}")).collect();
        assert_eq!(validate_patterns(&many).unwrap_err().code(), "invalid_argument");
    }

    #[test]
    fn s13_c_a_pattern_at_the_bounds_is_kept() {
        // The refusals above must be off-by-one-proof in the permissive direction too: the
        // longest legal pattern and a full list are ordinary inputs, not edge failures.
        let longest = "a".repeat(MAX_PATTERN_LEN);
        assert_eq!(validate_patterns(std::slice::from_ref(&longest)).unwrap(), vec![longest]);
        let full: Vec<String> = (0..MAX_TOKEN_PATTERNS).map(|i| format!("pkg{i}")).collect();
        assert_eq!(validate_patterns(&full).unwrap().len(), MAX_TOKEN_PATTERNS);
    }

    #[test]
    fn s13_c_duplicates_collapse_and_order_survives() {
        let stored = validate_patterns(&patterns(&["b_*", "a_x", "b_*", "a_x"])).unwrap();
        assert_eq!(stored, patterns(&["b_*", "a_x"]), "the token list renders what the mint stored");
    }

    #[test]
    fn s13_c_a_rejected_pattern_is_clipped_out_of_the_message() {
        // Caller-supplied text reaching an error message is clipped everywhere else in this
        // codebase; a pattern refused *for its length* is the one input that would otherwise
        // echo an unbounded string back.
        let err = validate_patterns(&["Z".repeat(4096)]).unwrap_err();
        assert!(err.to_string().len() < 200, "an over-long pattern must not be echoed whole: {err}");
    }
}
