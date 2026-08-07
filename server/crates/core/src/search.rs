//! Package search: the typed query, its parser, the visibility view, and the result shapes
//! ([decision 11](../../../docs/decisions.md#11--search-behind-a-trait)).
//!
//! Everything here is backend-agnostic. The two implementations — Postgres `tsvector` + GIN +
//! `pg_trgm`, SQLite FTS5 — receive a [`SearchQuery`] and a [`SearchView`] and are responsible
//! for translating them into their own dialect; the *meaning* of a query lives here, once, so
//! the two engines cannot disagree about what a filter means.
//!
//! # The parser is ours, and it never fails
//!
//! A search box is the one input where a syntax error must not be an error page. Every token
//! that is not understood is recorded in [`SearchQuery::unknown`] and dropped, so a query is
//! always executable and the API can tell the UI what it ignored. That also removes a whole
//! class of oracle: a malformed filter and a filter that matched nothing are indistinguishable
//! in the results.
//!
//! Untrusted text never reaches an engine's query language as syntax — the backends quote
//! every term (FTS5 `"…"`, tsquery `'…'`), so operators like `OR`, `NEAR`, `*`, `&`, `!`, and
//! `:` inside a search term are data. The parser's job is only to decide which characters are
//! *structure* (quotes, the filter colon, the leading `-`).
//!
//! # Visibility is not a filter
//!
//! [`SearchView`] carries the orgs whose private packages the principal may read, and it is
//! built by running the **same** [`authorize`] chokepoint the resolution path uses over the
//! actor's memberships — not by a second copy of the rule. Implementations must apply it as a
//! mandatory predicate that no query text can widen; see
//! [`PackageSearch`](crate::traits::PackageSearch).

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::authorize::{Action, ActorContext, Resource, authorize};
use crate::package::Visibility;
use crate::{Format, OrgId, PackageId};

/// Longest raw query string considered; the remainder is dropped.
///
/// A search box is anonymous-reachable, and both engines' cost grows with the number of terms.
pub const MAX_QUERY_BYTES: usize = 512;

/// Most tokens (terms + filters) taken from one query; the remainder is dropped.
pub const MAX_TOKENS: usize = 32;

/// Longest single term or filter value kept.
pub const MAX_TERM_BYTES: usize = 64;

/// How results are ordered.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SearchSort {
    /// Best text match first (falls back to [`SearchSort::Updated`] when there is no text —
    /// see [`SearchQuery::effective_sort`]).
    #[default]
    Relevance,
    /// Most recently updated first.
    Updated,
    /// Package name, ascending.
    Name,
    /// Most downloaded first.
    Downloads,
}

impl SearchSort {
    /// Canonical lowercase name, as used on the wire and in `sort:` tags.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Relevance => "relevance",
            Self::Updated => "updated",
            Self::Name => "name",
            Self::Downloads => "downloads",
        }
    }

    /// One-character cursor tag. A cursor is only valid for the ordering it was produced by, so
    /// the tag is what turns "same cursor, different sort" into a clean `invalid_argument`
    /// instead of a silently reshuffled page.
    pub const fn cursor_tag(self) -> &'static str {
        match self {
            Self::Relevance => "r",
            Self::Updated => "u",
            Self::Name => "n",
            Self::Downloads => "d",
        }
    }

    /// Parses a sort name; `None` for anything else.
    pub fn parse(raw: &str) -> Option<Self> {
        match raw {
            "relevance" | "score" | "best" => Some(Self::Relevance),
            "updated" | "recent" | "recently-updated" => Some(Self::Updated),
            "name" | "alpha" => Some(Self::Name),
            "downloads" | "popular" | "popularity" => Some(Self::Downloads),
            _ => None,
        }
    }
}

impl std::fmt::Display for SearchSort {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The `is:` vocabulary — package-state predicates.
///
/// Deliberately **not** `#[non_exhaustive]`, unlike most of the domain enums here: every
/// variant is a column predicate that each search backend has to spell out in its own dialect,
/// and a wildcard arm would let a new flag compile into a filter that silently matches
/// everything. Adding one should break both backends until they implement it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SearchFlag {
    /// `is:private` — the package is org-private.
    Private,
    /// `is:public` — the package is instance-public.
    Public,
    /// `is:discontinued` — the package is marked discontinued.
    Discontinued,
    /// `is:unlisted` — the package is hidden from discovery. Only ever matches inside the
    /// caller's own orgs: unlisted means "do not surface", and the exception exists so an org
    /// can still manage its own packages.
    Unlisted,
    /// `is:retracted-latest` — the newest version of the package is retracted.
    RetractedLatest,
}

impl SearchFlag {
    /// Canonical `is:` value.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Private => "private",
            Self::Public => "public",
            Self::Discontinued => "discontinued",
            Self::Unlisted => "unlisted",
            Self::RetractedLatest => "retracted-latest",
        }
    }

    /// Parses an `is:` value; `None` for anything else.
    pub fn parse(raw: &str) -> Option<Self> {
        match raw {
            "private" => Some(Self::Private),
            "public" => Some(Self::Public),
            "discontinued" => Some(Self::Discontinued),
            "unlisted" => Some(Self::Unlisted),
            "retracted-latest" | "retracted" => Some(Self::RetractedLatest),
            _ => None,
        }
    }
}

/// A filter dimension: values that must match, and values that must not.
///
/// Semantics are the same for every dimension, which is what keeps the two SQL dialects honest:
/// **`any` is OR, `none` is AND-NOT**, and the dimensions AND together. `org:a org:b` means
/// "a or b"; `-org:a -org:b` means "neither".
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FilterSet<T> {
    /// At least one of these must match (empty = no constraint).
    pub any: Vec<T>,
    /// None of these may match.
    pub none: Vec<T>,
}

// Hand-written so the empty set exists for every `T`: the derive would demand `T: Default`,
// which is meaningless for a filter value (there is no "default org").
impl<T> Default for FilterSet<T> {
    fn default() -> Self {
        Self { any: Vec::new(), none: Vec::new() }
    }
}

impl<T: PartialEq> FilterSet<T> {
    /// Whether this dimension constrains anything.
    pub fn is_empty(&self) -> bool {
        self.any.is_empty() && self.none.is_empty()
    }

    fn push(&mut self, value: T, negated: bool) {
        let bucket = if negated { &mut self.none } else { &mut self.any };
        if !bucket.contains(&value) {
            bucket.push(value);
        }
    }
}

/// A parsed search query.
///
/// Produced only by [`parse_query`]; the fields are public so backends can read them, but a
/// hand-built query is fine too (the home dashboard builds an empty one with a sort).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SearchQuery {
    /// Free-text words, in the order they appeared, lowercased and length-capped.
    pub words: Vec<String>,
    /// Quoted phrases, verbatim (minus the quotes) — matched as adjacent-word phrases.
    pub phrases: Vec<String>,
    /// `format:` — artifact format (decision 21).
    pub formats: FilterSet<Format>,
    /// `org:` — owning org slug.
    pub orgs: FilterSet<String>,
    /// `topic:` — pubspec topic.
    pub topics: FilterSet<String>,
    /// `dependency:` — packages that depend on this name (from stored pubspecs).
    pub dependencies: FilterSet<String>,
    /// `is:` — package-state predicates.
    pub flags: FilterSet<SearchFlag>,
    /// Requested ordering.
    pub sort: SearchSort,
    /// Tokens that were not understood, verbatim — echoed back so the UI can say what it
    /// ignored instead of silently returning surprising results.
    pub unknown: Vec<String>,
}

impl SearchQuery {
    /// An empty query with the given ordering — the listing/browse case.
    pub fn browse(sort: SearchSort) -> Self {
        Self { sort, ..Self::default() }
    }

    /// Whether the query carries any free text at all.
    pub fn has_text(&self) -> bool {
        !self.words.is_empty() || !self.phrases.is_empty()
    }

    /// Whether the query carries any filter.
    pub fn has_filters(&self) -> bool {
        !self.formats.is_empty()
            || !self.orgs.is_empty()
            || !self.topics.is_empty()
            || !self.dependencies.is_empty()
            || !self.flags.is_empty()
    }

    /// The ordering actually applied.
    ///
    /// Relevance without text has nothing to rank, and ordering by an all-zero score would make
    /// pagination depend on the database's row order. Browsing therefore falls back to
    /// "recently updated", which is what a landing page wants anyway.
    pub fn effective_sort(&self) -> SearchSort {
        match self.sort {
            SearchSort::Relevance if !self.has_text() => SearchSort::Updated,
            other => other,
        }
    }
}

/// Parses a raw query string into a [`SearchQuery`].
///
/// Never fails: unparseable pieces land in [`SearchQuery::unknown`]. `default_sort` applies
/// unless the string carries a `sort:` tag, which wins — the tag is the more specific,
/// user-typed intent.
///
/// Grammar (whitespace-separated tokens, double quotes group):
///
/// ```text
/// token   := ['-'] key ':' value | ['-'] key ':' '"' value '"' | word | '"' phrase '"'
/// key     := format | org | topic | dependency | dependencies | is | sort
/// ```
pub fn parse_query(raw: &str, default_sort: SearchSort) -> SearchQuery {
    let mut query = SearchQuery { sort: default_sort, ..SearchQuery::default() };
    for token in tokenize(raw) {
        if query.words.len() + query.phrases.len() + query.unknown.len() >= MAX_TOKENS {
            break;
        }
        apply_token(&mut query, token);
    }
    query
}

/// One lexical token, with its quotes already stripped.
///
/// `leading_quote` is the structural bit: a token that *opens* with a quote is text and nothing
/// else (`"org:acme is:public"` is a phrase), while a quote further in only groups a filter's
/// value (`org:"acme corp"` is a filter). Without the distinction the two are indistinguishable
/// once the quotes are gone.
struct Token {
    text: String,
    quoted: bool,
    leading_quote: bool,
}

/// Splits a query into tokens, honouring double quotes.
///
/// An unterminated quote runs to the end of the string rather than invalidating the query —
/// a user typing `"flutter widget` mid-word must still get results.
fn tokenize(raw: &str) -> Vec<Token> {
    let raw: String = raw.chars().take(MAX_QUERY_BYTES).collect();
    let mut tokens = Vec::new();
    let mut current = String::new();
    let mut quote_at: Option<usize> = None;
    let mut in_quotes = false;

    let flush = |current: &mut String, quote_at: &mut Option<usize>, tokens: &mut Vec<Token>| {
        if !current.trim().is_empty() || quote_at.is_some() {
            tokens.push(Token {
                text: std::mem::take(current),
                quoted: quote_at.is_some(),
                leading_quote: *quote_at == Some(0),
            });
        } else {
            current.clear();
        }
        *quote_at = None;
    };

    for ch in raw.chars() {
        match ch {
            '"' => {
                in_quotes = !in_quotes;
                quote_at.get_or_insert(current.len());
            }
            c if c.is_whitespace() && !in_quotes => flush(&mut current, &mut quote_at, &mut tokens),
            c => current.push(c),
        }
        if tokens.len() >= MAX_TOKENS {
            return tokens;
        }
    }
    flush(&mut current, &mut quote_at, &mut tokens);
    tokens
}

/// Folds one token into the query.
fn apply_token(query: &mut SearchQuery, token: Token) {
    let raw = token.text.trim();
    if raw.is_empty() {
        return;
    }
    if token.leading_quote {
        push_text(query, raw, true);
        return;
    }
    let (negated, body) = match raw.strip_prefix('-') {
        Some(rest) if !rest.is_empty() && rest.contains(':') => (true, rest),
        _ => (false, raw),
    };

    // A quoted token with no colon is a phrase; `key:"value"` still parses as a filter because
    // the colon precedes the quote and the tokenizer strips quotes, not structure.
    let Some((key, value)) = body.split_once(':').filter(|(key, _)| !key.is_empty()) else {
        push_text(query, raw, token.quoted);
        return;
    };
    let key = key.to_ascii_lowercase();
    let value = clip(value).to_ascii_lowercase();
    if value.is_empty() {
        push_unknown(query, raw);
        return;
    }

    match key.as_str() {
        "format" => match value.parse::<Format>() {
            Ok(format) => query.formats.push(format, negated),
            // An unknown format is not an error — v1 ships `pub` and `format:npm` is a query
            // about a format this instance does not serve, which is "no results", not a 400.
            Err(_) => push_unknown(query, raw),
        },
        "org" | "publisher" => query.orgs.push(value, negated),
        "topic" => query.topics.push(value, negated),
        "dependency" | "dependencies" | "depends" => query.dependencies.push(value, negated),
        "is" => match SearchFlag::parse(&value) {
            Some(flag) => query.flags.push(flag, negated),
            None => push_unknown(query, raw),
        },
        // `sort:` is a tag rather than only a query parameter because it is what a user types
        // in the one box the UI gives them. Negating it is meaningless.
        "sort" if !negated => match SearchSort::parse(&value) {
            Some(sort) => query.sort = sort,
            None => push_unknown(query, raw),
        },
        _ => push_unknown(query, raw),
    }
}

/// Records a free-text word or phrase.
fn push_text(query: &mut SearchQuery, raw: &str, quoted: bool) {
    let text = clip(raw).to_ascii_lowercase();
    if text.is_empty() {
        return;
    }
    // A quoted token with an internal space is a phrase; a quoted single word is just a word
    // whose quoting only meant "do not treat me as syntax".
    if quoted && text.contains(' ') {
        if !query.phrases.contains(&text) {
            query.phrases.push(text);
        }
    } else if !query.words.contains(&text) {
        query.words.push(text);
    }
}

/// Records a token that was not understood.
fn push_unknown(query: &mut SearchQuery, raw: &str) {
    let text = clip(raw).to_owned();
    if !query.unknown.contains(&text) {
        query.unknown.push(text);
    }
}

/// Caps a term at [`MAX_TERM_BYTES`] on a char boundary and trims it.
fn clip(raw: &str) -> &str {
    let raw = raw.trim();
    if raw.len() <= MAX_TERM_BYTES {
        return raw;
    }
    let mut end = MAX_TERM_BYTES;
    while end > 0 && !raw.is_char_boundary(end) {
        end -= 1;
    }
    raw[..end].trim_end()
}

/// The set of orgs whose private packages a principal may read.
///
/// Built by running the [`authorize`] chokepoint over the actor's memberships, so search
/// visibility is the *same* rule as resolution visibility rather than a second implementation
/// of it (decision 19, S-04). Backends turn it into a mandatory `visibility = 'public' OR
/// org_id IN (…)` predicate.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SearchView {
    readable_orgs: Vec<OrgId>,
}

impl SearchView {
    /// The view an unauthenticated caller gets: public packages only.
    pub fn anonymous() -> Self {
        Self::default()
    }

    /// The view for `actor`.
    pub fn for_actor(actor: &ActorContext) -> Self {
        let mut readable_orgs: Vec<OrgId> = actor
            .org_roles
            .keys()
            .copied()
            .filter(|org| authorize(actor, Action::ReadPackages, &Resource::Org(*org)).is_ok())
            .collect();
        // Deterministic order keeps the generated SQL (and its query-plan cache entry) stable.
        readable_orgs.sort_unstable();
        Self { readable_orgs }
    }

    /// The orgs whose private packages are visible, ascending.
    pub fn readable_orgs(&self) -> &[OrgId] {
        &self.readable_orgs
    }

    /// Whether the principal can see anything beyond public packages.
    pub fn is_public_only(&self) -> bool {
        self.readable_orgs.is_empty()
    }
}

/// The denormalized document one package contributes to the index.
///
/// Built from the package row plus its newest live version (see `pub_registry::index`), and
/// written by the publish/retract/options paths. A package with no live version has **no**
/// document: search results carry a version, and "exists but has nothing to show" is not a
/// search result.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SearchDocument {
    /// The package.
    pub package_id: PackageId,
    /// Artifact format.
    pub format: Format,
    /// Package name.
    pub name: String,
    /// Owning org.
    pub org_id: OrgId,
    /// Owning org's slug — denormalized so `org:` filters and result rows need no join.
    pub org_slug: String,
    /// Who may read it.
    pub visibility: Visibility,
    /// Discontinued flag.
    pub discontinued: bool,
    /// Suggested replacement (only meaningful while discontinued).
    pub replaced_by: Option<String>,
    /// Hidden from discovery.
    pub unlisted: bool,
    /// `description:` from the newest live version's metadata document.
    pub description: String,
    /// Plain text extracted from the newest live version's rendered README, capped.
    pub readme_text: String,
    /// `topics:` from the metadata document.
    pub topics: Vec<String>,
    /// Runtime dependency names from the metadata document.
    pub dependencies: Vec<String>,
    /// Dev-dependency names from the metadata document.
    pub dev_dependencies: Vec<String>,
    /// Newest live version, canonical text.
    pub latest_version: String,
    /// Newest live version's precedence key (kept so the index can be re-sorted without
    /// re-parsing semver).
    pub latest_version_sort: String,
    /// Whether the newest live version is retracted (`is:retracted-latest`).
    pub latest_retracted: bool,
    /// How many live versions the package has.
    pub versions_count: i64,
    /// When the newest live version was published.
    pub published_at: DateTime<Utc>,
    /// When the package row was created.
    pub created_at: DateTime<Utc>,
    /// Freshness for `sort:updated` — the later of the package's last metadata change and its
    /// newest publish.
    pub updated_at: DateTime<Utc>,
}

/// One search result row — everything a result card renders, with no further queries.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SearchHit {
    /// The package.
    pub package_id: PackageId,
    /// Artifact format.
    pub format: Format,
    /// Package name.
    pub name: String,
    /// Owning org's slug.
    pub org_slug: String,
    /// Who may read it.
    pub visibility: Visibility,
    /// Discontinued flag.
    pub discontinued: bool,
    /// Suggested replacement.
    pub replaced_by: Option<String>,
    /// Hidden from discovery.
    pub unlisted: bool,
    /// Package description.
    pub description: String,
    /// Topics.
    pub topics: Vec<String>,
    /// Newest live version.
    pub latest_version: String,
    /// Whether that version is retracted.
    pub latest_retracted: bool,
    /// Live version count.
    pub versions_count: i64,
    /// When the newest version was published.
    pub published_at: DateTime<Utc>,
    /// Freshness used by `sort:updated`.
    pub updated_at: DateTime<Utc>,
    /// All-time downloads, as of the last rollup.
    pub downloads_total: i64,
    /// Downloads in the trailing stats window, as of the last rollup.
    pub downloads_recent: i64,
    /// Relevance score, **ascending = better** on every backend. `0.0` when the ordering is
    /// not relevance. Exposed because it is the cursor's sort key, not because a client should
    /// interpret its magnitude.
    pub score: f64,
}

/// Encodes the keyset position of `hit` under `sort` (see [`decode_hit_cursor`]).
///
/// Lives here rather than in each backend so the two produce **byte-identical** cursors: a
/// token minted on SQLite has to keep working after a migration to Postgres, and the only way
/// to guarantee that is one codec.
pub fn encode_hit_cursor(sort: SearchSort, hit: &SearchHit) -> String {
    let key = sort_key_of(sort, hit);
    crate::page::encode_cursor(&[sort.cursor_tag(), &key, &hit.package_id.to_string()])
}

/// The value of `hit`'s sort key under `sort`, in the cursor's textual form.
fn sort_key_of(sort: SearchSort, hit: &SearchHit) -> String {
    match sort {
        // Shortest round-trippable decimal: parsing it back yields the same f64 bit pattern,
        // so the keyset comparison cannot straddle the row it resumes from.
        SearchSort::Relevance => hit.score.to_string(),
        SearchSort::Updated => timestamp_key(hit.updated_at),
        SearchSort::Name => hit.name.clone(),
        SearchSort::Downloads => hit.downloads_total.to_string(),
    }
}

/// Fixed-width RFC3339 UTC — the exact form the SQLite backend stores, so a cursor value can be
/// compared as text there and parsed as an instant on Postgres.
fn timestamp_key(at: DateTime<Utc>) -> String {
    at.to_rfc3339_opts(chrono::SecondsFormat::Micros, true)
}

/// Decodes a cursor produced by [`encode_hit_cursor`], returning `(sort key, package id)`.
///
/// A cursor minted under a **different** ordering is [`crate::Error::Invalid`], not a silently
/// reshuffled page: its key means nothing under the new sort, and continuing anyway would skip
/// or repeat arbitrary results.
pub fn decode_hit_cursor(sort: SearchSort, cursor: &str) -> crate::Result<(String, PackageId)> {
    let invalid = || crate::Error::Invalid { message: format!("malformed cursor: {cursor}") };
    let parts = crate::page::decode_cursor(cursor, 3)?;
    if parts[0] != sort.cursor_tag() {
        return Err(crate::Error::Invalid {
            message: format!("this cursor belongs to a different ordering; restart the listing with sort={sort}"),
        });
    }
    let package: PackageId = parts[2].parse().map_err(|_| invalid())?;
    Ok((parts[1].clone(), package))
}

/// One facet bucket.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FacetCount {
    /// Bucket key (an org slug today).
    pub value: String,
    /// How many matches fall in it.
    pub count: i64,
}

/// Aggregates over the same filtered set a search page came from.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SearchFacets {
    /// Total matches (not just this page).
    pub total: i64,
    /// Top owning orgs by match count, descending, capped by the caller's limit.
    pub orgs: Vec<FacetCount>,
}

/// Instance-wide counters for the landing dashboard, **scoped to what the caller may see**.
///
/// Scoped rather than absolute on purpose: an absolute package count on a public page publishes
/// the size of every org's private inventory, and an absolute count of zero on a fully private
/// instance is a useless dashboard. Same predicate as search, so the numbers always agree with
/// what a listing would return.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct InstanceCounters {
    /// Visible packages holding at least one live version.
    pub packages: i64,
    /// Live versions of those packages.
    pub versions: i64,
    /// Organizations on the instance.
    pub orgs: i64,
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;
    use crate::{RoleLevel, UserId};

    fn parse(raw: &str) -> SearchQuery {
        parse_query(raw, SearchSort::Relevance)
    }

    #[test]
    fn plain_words_become_lowercased_terms() {
        let query = parse("Flutter  Widget");
        assert_eq!(query.words, vec!["flutter", "widget"]);
        assert!(query.phrases.is_empty());
        assert!(query.unknown.is_empty());
        assert!(query.has_text());
        assert!(!query.has_filters());
    }

    #[test]
    fn quoted_phrases_stay_together() {
        let query = parse("\"state management\" bloc");
        assert_eq!(query.phrases, vec!["state management"]);
        assert_eq!(query.words, vec!["bloc"]);
    }

    #[test]
    fn an_unterminated_quote_still_produces_a_query() {
        // Mid-typing must not be a syntax error.
        let query = parse("\"state management");
        assert_eq!(query.phrases, vec!["state management"]);
        assert!(query.unknown.is_empty());
    }

    #[test]
    fn a_quoted_single_word_is_a_word_not_a_phrase() {
        let query = parse("\"bloc\"");
        assert_eq!(query.words, vec!["bloc"]);
        assert!(query.phrases.is_empty());
    }

    #[test]
    fn the_whole_filter_vocabulary_parses() {
        let query = parse("format:pub org:acme topic:ui dependency:http is:public is:discontinued");
        assert_eq!(query.formats.any, vec![Format::Pub]);
        assert_eq!(query.orgs.any, vec!["acme".to_owned()]);
        assert_eq!(query.topics.any, vec!["ui".to_owned()]);
        assert_eq!(query.dependencies.any, vec!["http".to_owned()]);
        assert_eq!(query.flags.any, vec![SearchFlag::Public, SearchFlag::Discontinued]);
        assert!(!query.has_text());
        assert!(query.has_filters());
    }

    #[test]
    fn filters_negate_with_a_leading_dash() {
        let query = parse("-is:discontinued -org:acme widgets");
        assert_eq!(query.flags.none, vec![SearchFlag::Discontinued]);
        assert_eq!(query.orgs.none, vec!["acme".to_owned()]);
        assert_eq!(query.words, vec!["widgets"]);
        // A dash on a plain word is text, not a negation: package names contain dashes.
        assert_eq!(parse("-widgets").words, vec!["-widgets"]);
    }

    #[test]
    fn repeated_values_collapse_and_or_together() {
        let query = parse("org:acme org:acme org:other");
        assert_eq!(query.orgs.any, vec!["acme".to_owned(), "other".to_owned()]);
    }

    #[test]
    fn sort_comes_from_the_tag_and_overrides_the_default() {
        assert_eq!(parse_query("x", SearchSort::Name).sort, SearchSort::Name);
        assert_eq!(parse_query("x sort:downloads", SearchSort::Name).sort, SearchSort::Downloads);
        for (raw, expected) in [
            ("sort:relevance", SearchSort::Relevance),
            ("sort:updated", SearchSort::Updated),
            ("sort:name", SearchSort::Name),
            ("sort:downloads", SearchSort::Downloads),
            ("sort:popular", SearchSort::Downloads),
        ] {
            assert_eq!(parse(raw).sort, expected, "{raw}");
        }
    }

    #[test]
    fn relevance_without_text_falls_back_to_updated() {
        assert_eq!(parse("org:acme").effective_sort(), SearchSort::Updated);
        assert_eq!(parse("bloc").effective_sort(), SearchSort::Relevance);
        assert_eq!(parse("sort:name").effective_sort(), SearchSort::Name);
    }

    #[test]
    fn unknown_filters_are_reported_and_never_searched_as_text() {
        let query = parse("license:mit is:sponsored format:npm sort:sideways org: -bogus:x");
        assert_eq!(
            query.unknown,
            vec![
                "license:mit".to_owned(),
                "is:sponsored".to_owned(),
                "format:npm".to_owned(),
                "sort:sideways".to_owned(),
                "org:".to_owned(),
                "-bogus:x".to_owned(),
            ]
        );
        assert!(query.words.is_empty(), "an unknown filter must not leak into the text query");
        assert_eq!(query.sort, SearchSort::Relevance, "an unparseable sort keeps the default");
    }

    #[test]
    fn filter_values_may_be_quoted() {
        let query = parse("org:\"acme corp\" topic:\"machine learning\"");
        assert_eq!(query.orgs.any, vec!["acme corp".to_owned()]);
        assert_eq!(query.topics.any, vec!["machine learning".to_owned()]);
    }

    #[test]
    fn a_quoted_filter_looking_token_is_a_phrase() {
        // The quotes are around the whole token, so there is no filter structure to find.
        let query = parse("\"org:acme is:public\"");
        assert_eq!(query.phrases, vec!["org:acme is:public"]);
        assert!(query.orgs.is_empty() && query.flags.is_empty());
    }

    #[test]
    fn injection_attempts_are_data_not_syntax() {
        // Nothing here may become a filter, a sort, or an empty query; the backends quote every
        // term, so operators are matched literally.
        let table = [
            "'; DROP TABLE packages; --",
            "\") OR 1=1 --",
            "a OR b",
            "foo NEAR bar",
            "name:*",
            "%",
            "*",
            "a & b | !c",
            "\u{0}nul",
        ];
        for raw in table {
            let query = parse(raw);
            assert!(query.formats.is_empty(), "{raw} produced a format filter");
            assert!(query.orgs.is_empty(), "{raw} produced an org filter");
            assert!(query.flags.is_empty(), "{raw} produced a flag filter");
            assert!(query.dependencies.is_empty(), "{raw} produced a dependency filter");
            assert_eq!(query.sort, SearchSort::Relevance, "{raw} changed the sort");
        }
        // `name:*` is an unknown filter key, not a wildcard the engine sees.
        assert_eq!(parse("name:*").unknown, vec!["name:*".to_owned()]);
    }

    #[test]
    fn oversized_input_is_bounded() {
        let long_term = "a".repeat(500);
        let query = parse(&long_term);
        assert_eq!(query.words[0].len(), MAX_TERM_BYTES);

        let many = (0..200).map(|i| format!("w{i}")).collect::<Vec<_>>().join(" ");
        let query = parse(&many);
        assert!(query.words.len() <= MAX_TOKENS, "{} tokens survived", query.words.len());

        // A single huge string cannot make the tokenizer walk megabytes.
        let flood = "x ".repeat(100_000);
        assert!(parse(&flood).words.len() <= MAX_TOKENS);
    }

    #[test]
    fn multibyte_terms_are_clipped_on_char_boundaries() {
        let query = parse(&"日".repeat(100));
        assert!(query.words[0].len() <= MAX_TERM_BYTES);
        assert!(std::str::from_utf8(query.words[0].as_bytes()).is_ok());
    }

    #[test]
    fn empty_and_whitespace_queries_are_empty_browses() {
        for raw in ["", "   ", "\t\n", "\"\""] {
            let query = parse(raw);
            assert!(!query.has_text(), "{raw:?} produced text");
            assert!(!query.has_filters(), "{raw:?} produced filters");
            assert_eq!(query.effective_sort(), SearchSort::Updated);
        }
    }

    #[test]
    fn search_view_is_built_through_the_authorize_chokepoint() {
        let reader = OrgId::new();
        let below_read = OrgId::new();
        let owner = OrgId::new();
        let actor = ActorContext::user(
            UserId::new(),
            BTreeMap::from([(reader, RoleLevel::READ), (below_read, RoleLevel::new(49)), (owner, RoleLevel::OWNER)]),
        );
        let view = SearchView::for_actor(&actor);
        // Exactly the orgs `authorize(ReadPackages)` grants — the 49-level membership is not one.
        let mut expected = vec![reader, owner];
        expected.sort_unstable();
        assert_eq!(view.readable_orgs(), expected.as_slice());
        assert!(!view.is_public_only());

        assert!(SearchView::anonymous().is_public_only());
        assert!(SearchView::for_actor(&ActorContext::anonymous()).readable_orgs().is_empty());
    }

    fn hit() -> SearchHit {
        SearchHit {
            package_id: PackageId::new(),
            format: Format::Pub,
            name: "acme_core".to_owned(),
            org_slug: "acme".to_owned(),
            visibility: Visibility::Public,
            discontinued: false,
            replaced_by: None,
            unlisted: false,
            description: "Core".to_owned(),
            topics: vec!["ui".to_owned()],
            latest_version: "1.2.3".to_owned(),
            latest_retracted: false,
            versions_count: 3,
            published_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
            downloads_total: 42,
            downloads_recent: 7,
            score: -1.375e-3,
        }
    }

    #[test]
    fn hit_cursors_round_trip_every_ordering() {
        let hit = hit();
        for sort in [SearchSort::Relevance, SearchSort::Updated, SearchSort::Name, SearchSort::Downloads] {
            let cursor = encode_hit_cursor(sort, &hit);
            let (key, package) = decode_hit_cursor(sort, &cursor).expect("round trip");
            assert_eq!(package, hit.package_id);
            assert_eq!(key, sort_key_of(sort, &hit));
        }
        // The float key survives exactly — a rounded one would straddle the row it resumes from.
        let cursor = encode_hit_cursor(SearchSort::Relevance, &hit);
        let (key, _) = decode_hit_cursor(SearchSort::Relevance, &cursor).unwrap();
        assert_eq!(key.parse::<f64>().unwrap().to_bits(), hit.score.to_bits());
    }

    #[test]
    fn a_cursor_from_another_ordering_is_rejected() {
        let cursor = encode_hit_cursor(SearchSort::Name, &hit());
        let err = decode_hit_cursor(SearchSort::Downloads, &cursor).unwrap_err();
        assert_eq!(err.code(), "invalid_argument");
    }

    #[test]
    fn malformed_cursors_are_invalid_argument() {
        for raw in ["", "!!!", "Zm9v", &crate::page::encode_cursor(&["n", "acme_core", "not-a-uuid"])] {
            assert_eq!(decode_hit_cursor(SearchSort::Name, raw).unwrap_err().code(), "invalid_argument", "{raw:?}");
        }
    }

    #[test]
    fn cursor_tags_are_distinct_per_ordering() {
        let tags: Vec<_> = [SearchSort::Relevance, SearchSort::Updated, SearchSort::Name, SearchSort::Downloads]
            .into_iter()
            .map(SearchSort::cursor_tag)
            .collect();
        let unique: std::collections::BTreeSet<_> = tags.iter().collect();
        assert_eq!(unique.len(), tags.len(), "cursor tags must identify the ordering");
    }
}
