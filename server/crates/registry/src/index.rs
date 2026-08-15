//! Building and maintaining the package search index (decision 11).
//!
//! The index is a **projection**, not a source of truth: one [`SearchDocument`] per package,
//! derived from the package row plus its newest live version. Everything here is therefore
//! rebuildable — [`PackageIndexer::reindex_page`] walks the whole instance and produces exactly
//! what the publish path would have written — which is what makes it safe for the publish path
//! to log an indexing failure instead of failing the publish over it.
//!
//! ```text
//!  packages ─┐
//!            ├─► build_document ─► SearchDocument ─► PackageSearch::index
//!  versions ─┘        │
//!                     ├── description / topics / dependencies  (metadata document)
//!                     └── readme_text                          (rendered HTML, stripped)
//! ```
//!
//! Three decisions worth naming:
//!
//! - **"Latest" has two meanings and the document carries both.** [`SearchDocument::
//!   latest_version`] is the version a user is told to install — the same rule the pub protocol
//!   applies for `latest` ([`latest_index`]: newest live stable, else newest live pre-release,
//!   else the newest there is). [`SearchDocument::latest_retracted`] is about the *newest*
//!   version by precedence, because that is what the `is:retracted-latest` tag asks: "did the
//!   newest release get pulled?".
//! - **A package with no live version has no document.** A name reservation, or a package whose
//!   versions were all hard-deleted, is removed from the index rather than indexed with an
//!   empty version — a search result that cannot be installed is not a result.
//! - **Building a document reads two bounded queries, never the version list.**
//!   [`build_document`] runs inside the publisher's HTTP request on every publish, retraction,
//!   option change, hard delete and transfer, so its cost is part of what a publish costs: the
//!   count is one aggregate ([`pub_core::traits::PackageRepo::count_versions`]) and the two
//!   version rows come from [`latest_and_newest`], a newest-first scan that stops at the first
//!   live stable release ([D23](../../../../docs/roadmap.md), decision 32).

use pub_core::package::{Package, Version};
use pub_core::search::SearchDocument;
use pub_core::traits::Repositories;
use pub_core::{PackageId, Result};

/// Page size of the newest-first scan behind [`latest_and_newest`].
const VERSION_PAGE: u32 = 100;

/// How many of the newest live versions the `latest` rule is evaluated over (decision 32).
///
/// This is **not** how many versions a surface carries — the pub protocol's listing carries up
/// to `MAX_LISTED_VERSIONS` (10 000) of them, the package page's version list is
/// cursor-paginated, and a search document carries one. This is the bound on the scan that
/// decides which single version `latest` *names*, and every surface uses this one number so
/// that two of them cannot name two different versions for the same package.
pub const LATEST_WINDOW: usize = 1_000;

/// Longest description kept in the index (pub.dev truncates around 180 characters; this leaves
/// headroom without letting a pubspec park a novel in the search table).
const MAX_DESCRIPTION: usize = 512;

/// Longest README extract handed to the backend, which caps it again for its own column.
const MAX_README: usize = 16 * 1024;

/// Most topics kept from one pubspec.
const MAX_TOPICS: usize = 32;

/// Most dependency names kept per kind.
const MAX_DEPENDENCIES: usize = 512;

/// Longest single tag value (a package name is capped at 64; a topic at 32).
const MAX_TAG_LEN: usize = 64;

/// The `latest` rule itself, evaluated **newest first** over at most [`LATEST_WINDOW`] versions
/// — the single evaluation every surface goes through (decision 32).
///
/// The rule: highest live stable, else highest live pre-release, else the highest version there
/// is. A package whose every version is retracted still has to report *something*, and
/// reporting the newest keeps `latest` consistent with the listing's tail.
///
/// Newest-first is what makes the rule terminate: the first live stable release ends the scan,
/// which is one repository page for essentially every package in existence. The scan keeps at
/// most the three rows the rule can possibly return — the newest, the newest live one, and the
/// newest live stable one — so scanning a thousand versions costs three rows and not a
/// thousand, which is what lets the two repository-backed callers share it.
///
/// Its two drivers:
///
/// - [`latest_and_newest`] — the search indexer and the package page, over a descending
///   repository scan;
/// - [`latest_index`] — the pub protocol's local and proxied listings, backwards over the
///   ascending array they already hold.
#[derive(Debug)]
pub struct LatestScan<T> {
    newest: Option<T>,
    live: Option<T>,
    stable: Option<T>,
    scanned: usize,
}

impl<T: Clone> Default for LatestScan<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T: Clone> LatestScan<T> {
    /// A scan that has seen nothing.
    pub fn new() -> Self {
        Self { newest: None, live: None, stable: None, scanned: 0 }
    }

    /// Offers the next version, **newest first**, and answers [`Self::wants_more`].
    ///
    /// Offering past the point where the answer is settled is a no-op rather than an error: a
    /// caller reading fixed-size pages cannot stop the page it is already holding.
    pub fn offer(&mut self, item: T, retracted: bool, pre_release: bool) -> bool {
        if !self.wants_more() {
            return false;
        }
        self.scanned += 1;
        if self.newest.is_none() {
            self.newest = Some(item.clone());
        }
        if !retracted {
            if self.live.is_none() {
                self.live = Some(item.clone());
            }
            if !pre_release {
                self.stable = Some(item);
            }
        }
        self.wants_more()
    }

    /// Whether an older version could still change the answer.
    ///
    /// False once a live stable release has been seen — nothing older can beat it — and false
    /// once [`LATEST_WINDOW`] versions have been offered, which is the bound that makes the
    /// surfaces agree.
    pub fn wants_more(&self) -> bool {
        self.stable.is_none() && self.scanned < LATEST_WINDOW
    }

    /// Whether the scan stopped because the **window** ran out rather than because the rule
    /// settled — the condition worth logging, and the one where an older stable release exists
    /// but is deliberately not consulted.
    pub fn window_exhausted(&self) -> bool {
        self.stable.is_none() && self.scanned >= LATEST_WINDOW
    }

    /// How many versions have been offered.
    pub fn scanned(&self) -> usize {
        self.scanned
    }

    /// `(latest, newest)`, or `None` when nothing was ever offered.
    pub fn finish(self) -> Option<(T, T)> {
        let newest = self.newest?;
        let latest = self.stable.or(self.live).unwrap_or_else(|| newest.clone());
        Some((latest, newest))
    }
}

/// Index of the version a fresh `pub add` should pick, given `(retracted, pre_release)` flags
/// in ascending precedence order — the entry point for a caller that already holds the listing.
///
/// Highest live stable, else highest live pre-release, else the highest version there is,
/// evaluated by [`LatestScan`] over the newest [`LATEST_WINDOW`] entries and no further.
///
/// One rule **and one window** for the pub protocol's listing, the proxy's re-emission, the
/// package page and the search index, so a client cannot be told two different "latest"
/// versions by two surfaces of the same registry. The shared window is *why* that holds rather
/// than a hope: before decision 32 each surface bounded its own read differently — the indexer
/// not at all, the listing at 10 000 ascending, the page at 1 000 descending — and a package
/// large enough to reach the smallest bound got a different answer from each.
///
/// For a package whose newest [`LATEST_WINDOW`] live versions contain **no live stable
/// release**, all four surfaces report the same thing: the newest live pre-release inside the
/// window (or, if every version inside it is retracted, the newest version inside it). An older
/// stable release below the window is not consulted anywhere. That is the divergence decision
/// 32 records rather than hides: it is a uniform answer replacing three different ones.
pub fn latest_index(versions: &[(bool, bool)]) -> usize {
    debug_assert!(!versions.is_empty(), "callers must reject empty listings first");
    let mut scan = LatestScan::new();
    for (index, (retracted, pre_release)) in versions.iter().enumerate().rev() {
        if !scan.offer(index, *retracted, *pre_release) {
            break;
        }
    }
    scan.finish().map_or(0, |(latest, _newest)| latest)
}

/// The two versions every package surface needs — the one `pub add` would install and the
/// newest one — read with a bounded newest-first repository scan.
///
/// `Ok(None)` means the package has no live version at all: a name reservation, or one whose
/// versions were all hard-deleted.
///
/// Shared by the search indexer ([`build_document`]) and the package page, which is what makes
/// their answers the same answer rather than two computations that happen to agree. Both are
/// hot: the page is anonymous-reachable in a loop and the indexer runs inside the publisher's
/// request.
///
/// What the code does at its bound: it reads `VERSION_PAGE` rows at a time, newest first, and
/// stops at the first live stable release — one query for essentially every package in
/// existence — or after [`LATEST_WINDOW`] versions, whichever comes first. Stopping at the
/// window means the newest thousand releases contain no live stable one; the answer is then the
/// newest live pre-release inside the window, an older stable release below it is **not**
/// consulted, and the truncation is logged rather than silent. The pub protocol's listing and
/// the search document answer the same way for the same package, because they evaluate the same
/// rule over the same window.
pub async fn latest_and_newest(repos: &Repositories, package: PackageId) -> Result<Option<(Version, Version)>> {
    let mut scan = LatestScan::new();
    let mut cursor: Option<String> = None;
    loop {
        let page = repos.packages.list_versions_desc(package, cursor.as_deref(), VERSION_PAGE).await?;
        for version in page.items {
            let (retracted, pre_release) = (version.is_retracted(), version.version.is_pre_release());
            if !scan.offer(version, retracted, pre_release) {
                break;
            }
        }
        match page.cursor {
            Some(next) if scan.wants_more() => cursor = Some(next),
            Some(_) => {
                if scan.window_exhausted() {
                    // A counter rather than a `warn!`, because this runs on the **anonymous**
                    // package page as well as on publish. A log line here lets an unauthenticated
                    // caller choose the log volume — `read_per_ip_minute` is 600, so a bare read
                    // loop writes 600 lines a minute per address, against the one sink an
                    // operator cannot rotate away from mid-incident. That is the same
                    // amplification `first_in_window` exists to stop for `audit_log`, one sink
                    // over. The counter says the same thing, once per occurrence, bounded by
                    // construction, and it is the shape `docs/ops/monitoring.md` can alert on.
                    metrics::counter!("latest_window_exhausted_total").increment(1);
                    tracing::debug!(
                        %package,
                        scanned = scan.scanned(),
                        window = LATEST_WINDOW,
                        "latest-version scan stopped at its window; older versions were not considered"
                    );
                }
                break;
            }
            None => break,
        }
    }
    Ok(scan.finish())
}

/// Keeps the search index in step with the registry.
///
/// Held by [`crate::RegistryService`] (which refreshes one package after every publish,
/// retraction, hard delete, and option change) and by the reindex job (which walks the
/// instance). Both go through the same [`build_document`], so a rebuilt index is
/// byte-for-byte what incremental maintenance would have produced.
pub struct PackageIndexer {
    repos: Repositories,
}

impl std::fmt::Debug for PackageIndexer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PackageIndexer").finish_non_exhaustive()
    }
}

impl PackageIndexer {
    /// Builds the indexer over the configured repositories.
    pub fn new(repos: Repositories) -> Self {
        Self { repos }
    }

    /// Rebuilds one package's document, or removes it when nothing is left to show.
    pub async fn refresh(&self, package: &Package) -> Result<bool> {
        match build_document(&self.repos, package).await? {
            Some(document) => {
                self.repos.search.index(&document).await?;
                Ok(true)
            }
            None => {
                self.repos.search.remove(package.id).await?;
                Ok(false)
            }
        }
    }

    /// Rebuilds one page of the instance-wide walk and returns the next cursor.
    ///
    /// Chunked and resumable on purpose: a full reindex on a large instance must not hold a job
    /// lock for minutes, and an interrupted pass has to continue rather than restart.
    pub async fn reindex_page(&self, cursor: Option<&str>, limit: u32) -> Result<ReindexPage> {
        let page = self.repos.packages.list_all(cursor, limit).await?;
        let mut indexed = 0usize;
        let mut removed = 0usize;
        for package in &page.items {
            if self.refresh(package).await? {
                indexed += 1;
            } else {
                removed += 1;
            }
        }
        Ok(ReindexPage { indexed, removed, cursor: page.cursor, has_more: page.has_more })
    }
}

/// One chunk of a reindex walk.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ReindexPage {
    /// Packages whose document was written.
    pub indexed: usize,
    /// Packages dropped from the index (nothing live to show).
    pub removed: usize,
    /// Where to resume; `None` when the walk is finished.
    pub cursor: Option<String>,
    /// Whether more packages remain.
    pub has_more: bool,
}

/// Projects a package plus its live versions onto a search document.
///
/// `Ok(None)` means "this package must not be in the index" — no live versions.
///
/// Two bounded queries, never a walk of the version list (D23): [`latest_and_newest`] stops at
/// the first live stable release, and the count is an index-only aggregate. `newest` is the
/// newest version *whether or not it is retracted* — `is:retracted-latest` asks about that one,
/// not about the one we recommend installing.
pub async fn build_document(repos: &Repositories, package: &Package) -> Result<Option<SearchDocument>> {
    let Some((display, newest)) = latest_and_newest(repos, package.id).await? else {
        return Ok(None);
    };
    let versions_count = repos.packages.count_versions(package.id).await?;

    let org_slug = repos
        .orgs
        .get(package.org_id)
        .await?
        .map(|org| org.slug)
        // An org row that vanished under a package is corruption, not a reason to skip the
        // package: index it with an unmatchable slug so it is still findable by name.
        .unwrap_or_default();

    let metadata = Metadata::from_pubspec(&display.pubspec);
    Ok(Some(SearchDocument {
        package_id: package.id,
        format: package.format,
        name: package.name.clone(),
        org_id: package.org_id,
        org_slug,
        visibility: package.visibility,
        discontinued: package.discontinued,
        replaced_by: package.replaced_by.clone(),
        unlisted: package.unlisted,
        description: metadata.description,
        readme_text: display.readme_html.as_deref().map(html_to_text).unwrap_or_default(),
        topics: metadata.topics,
        dependencies: metadata.dependencies,
        dev_dependencies: metadata.dev_dependencies,
        latest_version: display.version.to_string(),
        latest_version_sort: display.version.sort_key(),
        latest_retracted: newest.is_retracted(),
        versions_count,
        published_at: newest.published_at,
        created_at: package.created_at,
        // Freshness the UI sorts by: the later of "the metadata changed" and "a version
        // shipped". Using only `packages.updated_at` would leave a busy package looking stale.
        updated_at: package.updated_at.max(newest.published_at),
    }))
}

/// The searchable fields of a metadata document.
#[derive(Debug, Default, PartialEq, Eq)]
struct Metadata {
    description: String,
    topics: Vec<String>,
    dependencies: Vec<String>,
    dev_dependencies: Vec<String>,
}

impl Metadata {
    /// Extracts them from a pubspec, tolerating every shape a published document may hold.
    ///
    /// Nothing here rejects: the pubspec already passed the publish validator, and a field this
    /// projection does not understand must degrade to "not indexed", never to a failed publish.
    fn from_pubspec(pubspec: &serde_json::Value) -> Self {
        let description = pubspec
            .get("description")
            .and_then(serde_json::Value::as_str)
            .map(|raw| clip(collapse_whitespace(raw).as_str(), MAX_DESCRIPTION))
            .unwrap_or_default();
        let topics = pubspec
            .get("topics")
            .and_then(serde_json::Value::as_array)
            .map(|values| {
                values.iter().filter_map(serde_json::Value::as_str).filter_map(normalize_tag).take(MAX_TOPICS).collect()
            })
            .unwrap_or_default();
        Self {
            description,
            topics,
            dependencies: dependency_names(pubspec, "dependencies"),
            dev_dependencies: dependency_names(pubspec, "dev_dependencies"),
        }
    }
}

/// The keys of a pubspec dependency map (the constraint values are irrelevant to the graph).
fn dependency_names(pubspec: &serde_json::Value, key: &str) -> Vec<String> {
    pubspec
        .get(key)
        .and_then(serde_json::Value::as_object)
        .map(|map| map.keys().filter_map(|name| normalize_tag(name)).take(MAX_DEPENDENCIES).collect())
        .unwrap_or_default()
}

/// Normalizes a tag value (topic or dependency name) for exact-match filtering.
///
/// Lowercased and length-capped, and rejected outright when it contains whitespace or control
/// characters: a filter value is compared with `=`, so a tag nobody could ever type is dead
/// weight in the index.
fn normalize_tag(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() || trimmed.len() > MAX_TAG_LEN {
        return None;
    }
    if trimmed.chars().any(|ch| ch.is_whitespace() || ch.is_control()) {
        return None;
    }
    Some(trimmed.to_ascii_lowercase())
}

/// Strips tags and decodes the handful of entities a sanitized README can contain.
///
/// The stored HTML is already ammonia-sanitized (S-11), so this is a projection for the text
/// index rather than a security boundary: there is no `<script>` left to worry about, and the
/// worst a malformed fragment can do is contribute a few odd words to a search document.
pub fn html_to_text(html: &str) -> String {
    let mut out = String::with_capacity(html.len().min(MAX_README));
    let mut in_tag = false;
    let mut entity: Option<String> = None;
    for ch in html.chars() {
        if out.len() >= MAX_README {
            break;
        }
        match ch {
            '<' => {
                // A tag boundary is a word boundary: `<b>a</b><b>b</b>` is two words.
                if !in_tag {
                    out.push(' ');
                }
                in_tag = true;
            }
            '>' if in_tag => in_tag = false,
            _ if in_tag => {}
            '&' => entity = Some(String::new()),
            ';' if entity.is_some() => {
                let name = entity.take().unwrap_or_default();
                out.push_str(decode_entity(&name));
            }
            _ => match &mut entity {
                // An unterminated entity (`a & b`) is plain text; flush it rather than eating
                // the rest of the document.
                Some(buffer) if buffer.len() > 12 || ch.is_whitespace() => {
                    out.push('&');
                    out.push_str(buffer);
                    out.push(ch);
                    entity = None;
                }
                Some(buffer) => buffer.push(ch),
                None => out.push(ch),
            },
        }
    }
    if let Some(buffer) = entity {
        out.push('&');
        out.push_str(&buffer);
    }
    collapse_whitespace(&out)
}

/// The five entities comrak emits plus the space one; anything else stays literal.
fn decode_entity(name: &str) -> &'static str {
    match name {
        "amp" => "&",
        "lt" => "<",
        "gt" => ">",
        "quot" => "\"",
        "#39" | "apos" => "'",
        "nbsp" | "#160" => " ",
        _ => " ",
    }
}

/// Collapses every whitespace run to one space and trims.
fn collapse_whitespace(raw: &str) -> String {
    raw.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// Caps a string at `max` bytes on a char boundary.
fn clip(raw: &str, max: usize) -> String {
    if raw.len() <= max {
        return raw.to_owned();
    }
    let mut end = max;
    while end > 0 && !raw.is_char_boundary(end) {
        end -= 1;
    }
    raw[..end].trim_end().to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The rule as it was written before it had a window, over the whole listing — the
    /// reference implementation the windowed one must agree with whenever the listing fits.
    fn unwindowed(versions: &[(bool, bool)]) -> usize {
        versions
            .iter()
            .rposition(|(retracted, pre_release)| !retracted && !pre_release)
            .or_else(|| versions.iter().rposition(|(retracted, _)| !retracted))
            .unwrap_or(versions.len().saturating_sub(1))
    }

    #[test]
    fn latest_prefers_the_newest_live_stable() {
        // (retracted, pre_release) in ascending precedence order.
        assert_eq!(latest_index(&[(false, false), (false, false), (false, true)]), 1);
        assert_eq!(latest_index(&[(false, false), (true, false)]), 0);
        assert_eq!(latest_index(&[(false, true), (false, true)]), 1);
        // Everything retracted: still has to name one, and the newest is the least wrong.
        assert_eq!(latest_index(&[(true, false), (true, false)]), 1);
    }

    /// Exhaustive over every listing of up to five versions: adding the window must not have
    /// changed a single answer for a package that fits inside it. A rule rewritten in terms of
    /// [`LatestScan`] that got a clause backwards would show up here on 1 364 inputs.
    #[test]
    fn the_windowed_rule_matches_the_unwindowed_one_for_every_listing_that_fits() {
        let mut ladder: Vec<(bool, bool)> = Vec::new();
        fn walk(ladder: &mut Vec<(bool, bool)>, depth: usize) {
            if !ladder.is_empty() {
                assert_eq!(latest_index(ladder), unwindowed(ladder), "disagreed on {ladder:?}");
            }
            if depth == 0 {
                return;
            }
            for flags in [(false, false), (false, true), (true, false), (true, true)] {
                ladder.push(flags);
                walk(ladder, depth - 1);
                ladder.pop();
            }
        }
        walk(&mut ladder, 5);
    }

    #[test]
    fn the_window_stops_at_latest_window_versions_and_ignores_an_older_stable() {
        // One live stable, then a full window of live pre-releases above it. Unwindowed, the
        // rule reaches down to the stable; windowed, it must not — this is the divergence
        // decision 32 records, and the whole reason the three surfaces can agree.
        let mut ladder = vec![(false, false)];
        ladder.extend(std::iter::repeat_n((false, true), LATEST_WINDOW));
        assert_eq!(unwindowed(&ladder), 0, "the pre-window rule reached the old stable");
        assert_eq!(latest_index(&ladder), ladder.len() - 1, "the newest pre-release, not the stable below the window");

        // One version short of the window, the stable is still inside it and still wins.
        let mut inside = vec![(false, false)];
        inside.extend(std::iter::repeat_n((false, true), LATEST_WINDOW - 1));
        assert_eq!(latest_index(&inside), 0);

        // The same boundary with retraction: a window of retracted versions over a live stable.
        let mut retracted = vec![(false, false)];
        retracted.extend(std::iter::repeat_n((true, false), LATEST_WINDOW));
        assert_eq!(latest_index(&retracted), retracted.len() - 1, "nothing live inside the window: name the newest");
    }

    #[test]
    fn the_scan_settles_without_reading_past_the_first_live_stable() {
        // The property the two repository callers depend on: once a live stable has been
        // offered, the scan stops asking — that is what keeps a publish from paging through a
        // package's whole history (D23).
        let mut scan = LatestScan::new();
        assert!(scan.wants_more(), "an empty scan has to read something");
        // `offer` answers `wants_more`: a live pre-release settles nothing on its own, because
        // an older stable release would still beat it; the first live stable ends the scan.
        assert!(scan.offer("2.0.0-beta", false, true));
        assert!(!scan.offer("1.9.0", false, false));
        assert!(!scan.wants_more());
        assert!(!scan.window_exhausted(), "the rule settled; the window did not run out");
        assert_eq!(scan.scanned(), 2);
        assert_eq!(scan.finish(), Some(("1.9.0", "2.0.0-beta")));
    }

    #[test]
    fn a_full_window_of_nothing_live_reports_the_newest_and_says_so() {
        let mut scan = LatestScan::new();
        for index in 0..LATEST_WINDOW + 10 {
            scan.offer(index, true, false);
        }
        assert_eq!(scan.scanned(), LATEST_WINDOW, "offering past the bound must not extend the window");
        assert!(scan.window_exhausted(), "this is the case an operator gets warned about");
        assert_eq!(scan.finish(), Some((0, 0)), "everything retracted: the newest is the least wrong answer");
    }

    #[test]
    fn a_scan_that_saw_nothing_has_no_answer() {
        assert_eq!(LatestScan::<usize>::new().finish(), None);
    }

    #[test]
    fn metadata_extracts_the_searchable_fields() {
        let pubspec = serde_json::json!({
            "name": "acme_core",
            "description": "  A  core\nlibrary.  ",
            "topics": ["UI", "widgets", "", "  ", "with space", "x".repeat(200)],
            "dependencies": { "http": "^1.0.0", "meta": "any" },
            "dev_dependencies": { "test": "^1.0.0" },
        });
        let metadata = Metadata::from_pubspec(&pubspec);
        assert_eq!(metadata.description, "A core library.");
        assert_eq!(metadata.topics, vec!["ui".to_owned(), "widgets".to_owned()]);
        let mut deps = metadata.dependencies.clone();
        deps.sort();
        assert_eq!(deps, vec!["http".to_owned(), "meta".to_owned()]);
        assert_eq!(metadata.dev_dependencies, vec!["test".to_owned()]);
    }

    #[test]
    fn metadata_tolerates_every_wrong_shape() {
        for pubspec in [
            serde_json::json!({}),
            serde_json::json!({ "description": 42, "topics": "ui", "dependencies": [] }),
            serde_json::json!({ "topics": [1, true, null] }),
            serde_json::json!(null),
        ] {
            let metadata = Metadata::from_pubspec(&pubspec);
            assert_eq!(metadata, Metadata::default(), "{pubspec} produced {metadata:?}");
        }
    }

    #[test]
    fn descriptions_are_clipped_on_char_boundaries() {
        let pubspec = serde_json::json!({ "description": "é".repeat(1000) });
        let metadata = Metadata::from_pubspec(&pubspec);
        assert!(metadata.description.len() <= MAX_DESCRIPTION);
        assert!(std::str::from_utf8(metadata.description.as_bytes()).is_ok());
    }

    #[test]
    fn html_becomes_searchable_text() {
        let html = "<h1>Acme Core</h1>\n<p>A <strong>fast</strong> parser for JSON &amp; YAML.</p>";
        assert_eq!(html_to_text(html), "Acme Core A fast parser for JSON & YAML.");
    }

    #[test]
    fn html_stripping_never_glues_words_together() {
        // Adjacent inline tags used to produce "onetwo", which then matched neither word.
        assert_eq!(html_to_text("<b>one</b><i>two</i>"), "one two");
    }

    #[test]
    fn html_stripping_survives_malformed_input() {
        assert_eq!(html_to_text("<p>unclosed"), "unclosed");
        assert_eq!(html_to_text("a & b"), "a & b");
        assert_eq!(html_to_text("&notanentity"), "&notanentity");
        // A stray `>` outside a tag is literal text, which is what a README that talks about
        // shell redirection contains.
        assert_eq!(html_to_text("<<>>"), ">");
        assert_eq!(html_to_text(""), "");
    }

    #[test]
    fn html_extracts_are_bounded() {
        let huge = format!("<p>{}</p>", "word ".repeat(100_000));
        assert!(html_to_text(&huge).len() <= MAX_README);
    }

    #[test]
    fn tags_that_could_never_be_typed_are_dropped() {
        assert_eq!(normalize_tag("UI"), Some("ui".to_owned()));
        assert_eq!(normalize_tag(" http "), Some("http".to_owned()));
        assert_eq!(normalize_tag("two words"), None);
        assert_eq!(normalize_tag("with\u{0}nul"), None);
        assert_eq!(normalize_tag(""), None);
        assert_eq!(normalize_tag(&"a".repeat(MAX_TAG_LEN + 1)), None);
    }
}
