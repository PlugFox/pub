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
//! Two decisions worth naming:
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

use pub_core::package::{Package, Version};
use pub_core::search::SearchDocument;
use pub_core::traits::Repositories;
use pub_core::{PackageId, Result};

/// Page size used when walking a package's versions.
const VERSION_PAGE: u32 = 200;

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

/// Index of the version a fresh `pub add` should pick, given `(retracted, pre_release)` flags
/// in ascending precedence order.
///
/// Highest live stable, else highest live pre-release, else the highest version there is — a
/// package whose every version is retracted still has to report *something*, and reporting the
/// newest keeps `latest` consistent with the array's tail. One rule for the pub protocol's
/// listing, the proxy's re-emission, and the search index, so a client cannot be told two
/// different "latest" versions by two surfaces of the same registry.
pub fn latest_index(versions: &[(bool, bool)]) -> usize {
    debug_assert!(!versions.is_empty(), "callers must reject empty listings first");
    versions
        .iter()
        .rposition(|(retracted, pre_release)| !retracted && !pre_release)
        .or_else(|| versions.iter().rposition(|(retracted, _)| !retracted))
        .unwrap_or(versions.len().saturating_sub(1))
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
pub async fn build_document(repos: &Repositories, package: &Package) -> Result<Option<SearchDocument>> {
    let versions = load_live_versions(repos, package.id).await?;
    if versions.is_empty() {
        return Ok(None);
    }
    let flags: Vec<(bool, bool)> = versions.iter().map(|v| (v.is_retracted(), v.version.is_pre_release())).collect();
    let display = &versions[latest_index(&flags)];
    // The *newest* version, retracted or not — `is:retracted-latest` asks about this one, not
    // about the one we recommend installing.
    let newest = versions.last().expect("non-empty");

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
        versions_count: versions.len() as i64,
        published_at: newest.published_at,
        created_at: package.created_at,
        // Freshness the UI sorts by: the later of "the metadata changed" and "a version
        // shipped". Using only `packages.updated_at` would leave a busy package looking stale.
        updated_at: package.updated_at.max(newest.published_at),
    }))
}

/// Every live version of a package, ascending by semver precedence.
async fn load_live_versions(repos: &Repositories, package: PackageId) -> Result<Vec<Version>> {
    let mut all = Vec::new();
    let mut cursor: Option<String> = None;
    loop {
        let page = repos.packages.list_versions(package, cursor.as_deref(), VERSION_PAGE).await?;
        all.extend(page.items);
        match page.cursor {
            Some(next) => cursor = Some(next),
            None => break,
        }
    }
    Ok(all)
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

    #[test]
    fn latest_prefers_the_newest_live_stable() {
        // (retracted, pre_release) in ascending precedence order.
        assert_eq!(latest_index(&[(false, false), (false, false), (false, true)]), 1);
        assert_eq!(latest_index(&[(false, false), (true, false)]), 0);
        assert_eq!(latest_index(&[(false, true), (false, true)]), 1);
        // Everything retracted: still has to name one, and the newest is the least wrong.
        assert_eq!(latest_index(&[(true, false), (true, false)]), 1);
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
