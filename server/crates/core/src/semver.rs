//! Semantic versions with semver.org precedence ordering.
//!
//! Package versions are the registry's sort key: the pub client resolves against the version
//! listing, so "which version is newer" must match [semver.org §11](https://semver.org/#spec-item-11)
//! exactly — including the pre-release rules that make `1.0.0-alpha < 1.0.0-alpha.1 <
//! 1.0.0-beta < 1.0.0` and the rule that build metadata is ignored for precedence.
//!
//! Two orderings live here and they are deliberately different:
//!
//! - [`SemVer::precedence_cmp`] is the spec's ordering — build metadata is invisible to it.
//! - [`Ord`] is `precedence_cmp` with build metadata as a **final tiebreaker**, so that
//!   `a == b` holds if and only if `cmp(a, b) == Equal` (Rust requires `Ord` to agree with
//!   `Eq`; two versions differing only in build metadata are distinct values here because the
//!   registry stores them as distinct rows).
//!
//! [`SemVer::sort_key`] projects a version onto a byte string whose **lexicographic** order
//! equals `precedence_cmp`. That is what the database stores and orders by, so version
//! listings and keyset pagination are one indexed scan rather than an in-memory sort.

use std::cmp::Ordering;
use std::fmt;
use std::str::FromStr;

use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::{Error, Result};

/// Width every numeric identifier is zero-padded to inside a [`SemVer::sort_key`]:
/// `u64::MAX` is 20 digits, so equal width means digit-wise comparison equals numeric
/// comparison.
const NUMERIC_WIDTH: usize = 20;

/// Separator between pre-release identifiers inside a sort key.
///
/// Must be **lower** than every byte legal in an identifier (`[0-9A-Za-z-]`, minimum `-` =
/// 0x2D), otherwise `1.0.0-a-b` and `1.0.0-a.b` would order the wrong way round: the spec
/// compares identifier by identifier, so the *shorter first identifier* (`a` < `a-b`) must
/// win, which only happens when the separator sorts before `-`.
const KEY_SEPARATOR: char = '!';

/// Marker byte appended to the numeric core: a pre-release sorts *before* the release it
/// leads to, so its marker must be the lower of the two.
const KEY_PRERELEASE: char = '0';

/// Marker byte for "no pre-release" — see [`KEY_PRERELEASE`].
const KEY_RELEASE: char = '1';

/// Marker byte prefixing a numeric pre-release identifier: numeric identifiers always have
/// lower precedence than alphanumeric ones (spec §11.4.3), so `0` must sort before `1`.
const KEY_NUMERIC: char = '0';

/// Marker byte prefixing an alphanumeric pre-release identifier — see [`KEY_NUMERIC`].
const KEY_ALPHANUMERIC: char = '1';

/// One dot-separated pre-release identifier.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
enum Identifier {
    /// All-digits identifier, compared numerically (spec §11.4.1).
    Numeric(u64),
    /// Identifier with letters or hyphens, compared in ASCII order (spec §11.4.2).
    Alphanumeric(String),
}

impl Identifier {
    /// Spec §11.4.3: numeric identifiers always have lower precedence than alphanumeric ones.
    fn cmp_spec(&self, other: &Self) -> Ordering {
        match (self, other) {
            (Self::Numeric(a), Self::Numeric(b)) => a.cmp(b),
            (Self::Alphanumeric(a), Self::Alphanumeric(b)) => a.cmp(b),
            (Self::Numeric(_), Self::Alphanumeric(_)) => Ordering::Less,
            (Self::Alphanumeric(_), Self::Numeric(_)) => Ordering::Greater,
        }
    }

    /// This identifier's contribution to a [`SemVer::sort_key`].
    fn write_key(&self, out: &mut String) {
        out.push(KEY_SEPARATOR);
        match self {
            Self::Numeric(value) => {
                out.push(KEY_NUMERIC);
                out.push_str(&format!("{value:0NUMERIC_WIDTH$}"));
            }
            Self::Alphanumeric(text) => {
                out.push(KEY_ALPHANUMERIC);
                out.push_str(text);
            }
        }
    }
}

impl fmt::Display for Identifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Numeric(value) => write!(f, "{value}"),
            Self::Alphanumeric(text) => f.write_str(text),
        }
    }
}

/// A parsed semantic version.
///
/// Parsing is **strict** (no `v` prefix, no missing patch component, no leading zeros): a
/// registry that accepts sloppy spellings ends up with two rows for one version.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct SemVer {
    major: u64,
    minor: u64,
    patch: u64,
    pre: Vec<Identifier>,
    build: Option<String>,
}

impl SemVer {
    /// Parses a version string per semver.org, rejecting every non-canonical spelling.
    pub fn parse(raw: &str) -> Result<Self> {
        let invalid = |reason: &str| Error::Invalid { message: format!("invalid semantic version {raw:?}: {reason}") };

        if raw.is_empty() {
            return Err(invalid("empty"));
        }
        if !raw.is_ascii() {
            return Err(invalid("must be ASCII"));
        }

        // Build metadata is everything after the first `+`; it never contains `+` itself.
        let (head, build) = match raw.split_once('+') {
            Some((head, build)) => {
                if !is_dot_separated_identifiers(build) {
                    return Err(invalid("malformed build metadata"));
                }
                (head, Some(build.to_owned()))
            }
            None => (raw, None),
        };

        // The numeric core contains no `-`, so the first hyphen starts the pre-release.
        let (core, pre_raw) = match head.split_once('-') {
            Some((core, pre)) => (core, Some(pre)),
            None => (head, None),
        };

        let mut parts = core.split('.');
        let mut next_number = |field: &str| -> Result<u64> {
            let part = parts.next().ok_or_else(|| invalid(&format!("missing {field}")))?;
            parse_numeric(part).ok_or_else(|| invalid(&format!("malformed {field}")))
        };
        let major = next_number("major")?;
        let minor = next_number("minor")?;
        let patch = next_number("patch")?;
        if parts.next().is_some() {
            return Err(invalid("the numeric core has exactly three components"));
        }

        let pre = match pre_raw {
            None => Vec::new(),
            Some(pre) => {
                let mut identifiers = Vec::new();
                for part in pre.split('.') {
                    if part.is_empty() || !part.bytes().all(is_identifier_byte) {
                        return Err(invalid("malformed pre-release identifier"));
                    }
                    identifiers.push(match parse_numeric(part) {
                        Some(number) => Identifier::Numeric(number),
                        // All-digit identifiers with leading zeros are rejected outright
                        // (spec §9) rather than silently treated as alphanumeric.
                        None if part.bytes().all(|b| b.is_ascii_digit()) => {
                            return Err(invalid("numeric pre-release identifier with a leading zero"));
                        }
                        None => Identifier::Alphanumeric(part.to_owned()),
                    });
                }
                identifiers
            }
        };

        Ok(Self { major, minor, patch, pre, build })
    }

    /// Major component.
    pub const fn major(&self) -> u64 {
        self.major
    }

    /// Minor component.
    pub const fn minor(&self) -> u64 {
        self.minor
    }

    /// Patch component.
    pub const fn patch(&self) -> u64 {
        self.patch
    }

    /// Whether this is a pre-release (`1.0.0-beta`), which resolvers exclude by default.
    pub fn is_pre_release(&self) -> bool {
        !self.pre.is_empty()
    }

    /// Build metadata (`+sha.abc`) without its `+`; `None` when absent.
    pub fn build(&self) -> Option<&str> {
        self.build.as_deref()
    }

    /// semver.org §11 precedence: build metadata is **not** part of it.
    pub fn precedence_cmp(&self, other: &Self) -> Ordering {
        self.major
            .cmp(&other.major)
            .then_with(|| self.minor.cmp(&other.minor))
            .then_with(|| self.patch.cmp(&other.patch))
            .then_with(|| match (self.pre.is_empty(), other.pre.is_empty()) {
                // A pre-release has lower precedence than the associated release (§11.3).
                (true, true) => Ordering::Equal,
                (true, false) => Ordering::Greater,
                (false, true) => Ordering::Less,
                (false, false) => {
                    for (mine, theirs) in self.pre.iter().zip(other.pre.iter()) {
                        match mine.cmp_spec(theirs) {
                            Ordering::Equal => continue,
                            other => return other,
                        }
                    }
                    // A larger set of pre-release fields wins when all preceding ones are
                    // equal (§11.4.4).
                    self.pre.len().cmp(&other.pre.len())
                }
            })
    }

    /// A byte string whose lexicographic order equals [`SemVer::precedence_cmp`].
    ///
    /// Stored alongside the version text so the database can order and keyset-paginate
    /// versions with one index scan. The encoding is:
    /// `<major:020>.<minor:020>.<patch:020>.<marker><pre-release>` where `marker` is `1` for
    /// a release and `0` for a pre-release, and each pre-release identifier is appended as
    /// `!0<value:020>` (numeric) or `!1<text>` (alphanumeric).
    ///
    /// **Comparison must be bytewise** (`BINARY` on SQLite, `COLLATE "C"` on Postgres); a
    /// locale-aware collation ignores punctuation and case and would break the order.
    pub fn sort_key(&self) -> String {
        let mut key = String::with_capacity(72 + self.pre.len() * 24);
        key.push_str(&format!(
            "{:0width$}.{:0width$}.{:0width$}.",
            self.major,
            self.minor,
            self.patch,
            width = NUMERIC_WIDTH
        ));
        if self.pre.is_empty() {
            key.push(KEY_RELEASE);
        } else {
            key.push(KEY_PRERELEASE);
            for identifier in &self.pre {
                identifier.write_key(&mut key);
            }
        }
        key
    }
}

/// Parses a canonical numeric identifier: digits only, no leading zero unless the value *is*
/// zero, must fit in `u64`.
fn parse_numeric(part: &str) -> Option<u64> {
    if part.is_empty() || !part.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    if part.len() > 1 && part.starts_with('0') {
        return None;
    }
    part.parse::<u64>().ok()
}

/// Whether `byte` may appear in a pre-release or build identifier (`[0-9A-Za-z-]`).
fn is_identifier_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'-'
}

/// Whether `text` is a non-empty dot-separated list of non-empty identifiers.
fn is_dot_separated_identifiers(text: &str) -> bool {
    !text.is_empty() && text.split('.').all(|part| !part.is_empty() && part.bytes().all(is_identifier_byte))
}

impl fmt::Display for SemVer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)?;
        if !self.pre.is_empty() {
            f.write_str("-")?;
            for (index, identifier) in self.pre.iter().enumerate() {
                if index > 0 {
                    f.write_str(".")?;
                }
                write!(f, "{identifier}")?;
            }
        }
        if let Some(build) = &self.build {
            write!(f, "+{build}")?;
        }
        Ok(())
    }
}

impl FromStr for SemVer {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        Self::parse(s)
    }
}

impl Ord for SemVer {
    /// Precedence first, then build metadata as a tiebreaker so `Ord` agrees with `Eq`
    /// (see the module docs).
    fn cmp(&self, other: &Self) -> Ordering {
        self.precedence_cmp(other).then_with(|| self.build.cmp(&other.build))
    }
}

impl PartialOrd for SemVer {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Serialize for SemVer {
    /// Versions travel as their canonical string on the wire and in JSON columns.
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for SemVer {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        let raw = String::deserialize(deserializer)?;
        Self::parse(&raw).map_err(D::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The precedence table from semver.org §11, in ascending order.
    const SPEC_TABLE: &[&str] = &[
        "1.0.0-alpha",
        "1.0.0-alpha.1",
        "1.0.0-alpha.beta",
        "1.0.0-beta",
        "1.0.0-beta.2",
        "1.0.0-beta.11",
        "1.0.0-rc.1",
        "1.0.0",
    ];

    fn v(raw: &str) -> SemVer {
        SemVer::parse(raw).unwrap_or_else(|err| panic!("{raw} must parse: {err}"))
    }

    #[test]
    fn spec_precedence_table_is_exhaustively_ordered() {
        // Every pair, both directions — not just neighbours.
        for (i, left) in SPEC_TABLE.iter().enumerate() {
            for (j, right) in SPEC_TABLE.iter().enumerate() {
                let expected = i.cmp(&j);
                assert_eq!(
                    v(left).precedence_cmp(&v(right)),
                    expected,
                    "precedence_cmp({left}, {right}) must be {expected:?}"
                );
                assert_eq!(
                    v(left).sort_key().cmp(&v(right).sort_key()),
                    expected,
                    "sort_key order must match precedence for ({left}, {right})"
                );
            }
        }
    }

    #[test]
    fn numeric_core_precedence() {
        let ascending = ["0.0.1", "0.1.0", "0.1.1", "1.0.0", "1.0.1", "1.1.0", "2.0.0", "10.0.0"];
        for pair in ascending.windows(2) {
            assert!(v(pair[0]) < v(pair[1]), "{} must precede {}", pair[0], pair[1]);
            assert!(v(pair[0]).sort_key() < v(pair[1]).sort_key(), "sort key order for {pair:?}");
        }
    }

    #[test]
    fn numeric_identifiers_compare_numerically_not_lexically() {
        assert!(v("1.0.0-2") < v("1.0.0-11"));
        assert!(v("1.0.0-alpha.2") < v("1.0.0-alpha.11"));
        assert!(v("1.0.0-2").sort_key() < v("1.0.0-11").sort_key());
    }

    #[test]
    fn numeric_identifiers_precede_alphanumeric_ones() {
        assert!(v("1.0.0-1") < v("1.0.0-alpha"));
        assert!(v("1.0.0-99999") < v("1.0.0-a"));
        assert!(v("1.0.0-99999").sort_key() < v("1.0.0-a").sort_key());
    }

    #[test]
    fn a_longer_identifier_set_wins_when_prefixes_are_equal() {
        assert!(v("1.0.0-alpha") < v("1.0.0-alpha.0"));
        assert!(v("1.0.0-alpha.1") < v("1.0.0-alpha.1.0"));
        assert!(v("1.0.0-alpha").sort_key() < v("1.0.0-alpha.0").sort_key());
    }

    #[test]
    fn hyphens_inside_identifiers_sort_after_a_shorter_identifier() {
        // `a` < `a-b` lexically, so `1.0.0-a.b` (first identifier `a`) precedes `1.0.0-a-b`
        // (single identifier `a-b`). This is exactly the case a naive sort-key separator
        // (`.` or `-`) gets wrong.
        assert!(v("1.0.0-a.b") < v("1.0.0-a-b"));
        assert!(v("1.0.0-a.b").sort_key() < v("1.0.0-a-b").sort_key());
    }

    #[test]
    fn build_metadata_is_ignored_by_precedence() {
        assert_eq!(v("1.0.0+build.1").precedence_cmp(&v("1.0.0+build.2")), Ordering::Equal);
        assert_eq!(v("1.0.0+exp.sha.5114f85").precedence_cmp(&v("1.0.0")), Ordering::Equal);
        assert_eq!(v("1.0.0-alpha+a").precedence_cmp(&v("1.0.0-alpha+b")), Ordering::Equal);
        assert_eq!(v("1.0.0+a").sort_key(), v("1.0.0+b").sort_key());
        // …but they remain distinct values, and `Ord` stays consistent with `Eq`.
        assert_ne!(v("1.0.0+a"), v("1.0.0+b"));
        assert_ne!(v("1.0.0+a").cmp(&v("1.0.0+b")), Ordering::Equal);
        assert_eq!(v("1.0.0").cmp(&v("1.0.0")), Ordering::Equal);
    }

    #[test]
    fn display_round_trips_every_shape() {
        for raw in ["0.0.0", "1.2.3", "1.0.0-alpha.1", "1.0.0+build.5", "1.0.0-rc.1+exp.sha.5114f85", "1.0.0--"] {
            assert_eq!(v(raw).to_string(), raw);
            assert_eq!(v(raw), v(&v(raw).to_string()));
        }
    }

    #[test]
    fn parse_rejects_non_canonical_and_malformed_input() {
        for raw in [
            "",
            "1",
            "1.0",
            "1.0.0.0",
            "01.0.0",
            "1.01.0",
            "1.0.00",
            "v1.0.0",
            "1.0.0-",
            "1.0.0-01",
            "1.0.0-alpha..1",
            "1.0.0+",
            "1.0.0+build..1",
            "1.0.0-alpha beta",
            "1.0.0-alpha_beta",
            "1.0.0-α",
            "-1.0.0",
            "1.0.0-alpha+",
            "18446744073709551616.0.0", // u64 overflow
        ] {
            assert!(SemVer::parse(raw).is_err(), "must reject {raw:?}");
        }
    }

    #[test]
    fn parse_errors_are_invalid_argument() {
        assert_eq!(SemVer::parse("nope").unwrap_err().code(), "invalid_argument");
    }

    #[test]
    fn accessors_and_flags() {
        let version = v("1.2.3-beta.4+sha.abc");
        assert_eq!((version.major(), version.minor(), version.patch()), (1, 2, 3));
        assert!(version.is_pre_release());
        assert_eq!(version.build(), Some("sha.abc"));
        assert!(!v("1.2.3").is_pre_release());
        assert_eq!(v("1.2.3").build(), None);
    }

    #[test]
    fn serde_uses_the_canonical_string() {
        let version = v("1.0.0-rc.1+exp");
        let json = serde_json::to_string(&version).unwrap();
        assert_eq!(json, "\"1.0.0-rc.1+exp\"");
        assert_eq!(serde_json::from_str::<SemVer>(&json).unwrap(), version);
        assert!(serde_json::from_str::<SemVer>("\"not-a-version\"").is_err());
    }

    #[test]
    fn sort_keys_have_a_stable_shape() {
        let padded = |n: u64| format!("{n:0NUMERIC_WIDTH$}");
        assert_eq!(v("1.2.3").sort_key(), format!("{}.{}.{}.1", padded(1), padded(2), padded(3)));
        assert_eq!(
            v("1.0.0-alpha.1").sort_key(),
            format!("{}.{}.{}.0!1alpha!0{}", padded(1), padded(0), padded(0), padded(1))
        );
        // Every segment is fixed width, so the key length only grows with the pre-release.
        // Three padded numbers, three dots, one release marker.
        assert_eq!(v("0.0.0").sort_key().len(), 3 * NUMERIC_WIDTH + 4);
    }

    #[test]
    fn sorting_a_shuffled_set_yields_precedence_order() {
        let mut versions: Vec<SemVer> = ["1.0.0", "1.0.0-beta", "0.9.9", "1.0.0-alpha.1", "1.0.1", "1.0.0-alpha"]
            .iter()
            .map(|raw| v(raw))
            .collect();
        versions.sort();
        let ordered: Vec<String> = versions.iter().map(ToString::to_string).collect();
        assert_eq!(ordered, ["0.9.9", "1.0.0-alpha", "1.0.0-alpha.1", "1.0.0-beta", "1.0.0", "1.0.1"]);

        // The same set ordered by sort key must agree.
        let mut keys: Vec<(String, String)> = ordered.iter().map(|raw| (v(raw).sort_key(), raw.clone())).collect();
        keys.sort();
        let by_key: Vec<String> = keys.into_iter().map(|(_, raw)| raw).collect();
        assert_eq!(by_key, ordered);
    }
}
