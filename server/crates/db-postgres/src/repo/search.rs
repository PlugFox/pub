//! `PackageSearch` over Postgres: `package_search` with a generated `tsvector` (GIN) plus a
//! `pg_trgm` index on the name (decision 11, migration 0007).
//!
//! Three things carry the contract here:
//!
//! - **The visibility predicate is emitted first and unconditionally**, by
//!   [`push_visibility`], on every statement this module builds — search, facets, and counters
//!   alike. It is not reachable from the query grammar, so no combination of filters, text, or
//!   cursor can widen it (S-04).
//! - **User text never becomes `tsquery` syntax.** Every lexeme is wrapped in single quotes
//!   with internal quotes and backslashes doubled, so `&`, `|`, `!`, `<->`, `(`, `)`, and `:`
//!   inside a search term are matched literally ([`tsquery_expression`]).
//! - **Ordering is keyset-paginated on indexed columns** for the browse sorts, and on the
//!   materialized rank for relevance.
//!
//! Backend difference worth knowing: Postgres additionally does **fuzzy** name matching through
//! `pg_trgm` (`similarity(name, :q)`), which SQLite's FTS5 cannot — a full-text index matches
//! lexemes, and a typo is not a lexeme. Both backends agree on everything the contract suite
//! asserts; the trigram branch only ever *adds* rows a user was plausibly looking for.

use async_trait::async_trait;
use chrono::{DateTime, NaiveDate, Utc};
use pub_core::package::Visibility;
use pub_core::search::{
    FacetCount, InstanceCounters, SearchDocument, SearchFacets, SearchFlag, SearchHit, SearchQuery, SearchSort,
    SearchView, decode_hit_cursor, encode_hit_cursor,
};
use pub_core::stats::{DownloadDelta, DownloadTotals, PackageDownloads};
use pub_core::traits::{PackageSearch, StatsRepo};
use pub_core::{Error, PackageId, Page, Result};
use sqlx::postgres::PgRow;
use sqlx::{PgPool, Postgres, QueryBuilder, Row as _};
use uuid::Uuid;

use super::{db_err, parse_col};

/// Hard cap on page size; requests are clamped into `1..=MAX_PAGE`.
const MAX_PAGE: u32 = 100;

/// Hard cap on facet buckets returned.
const MAX_FACETS: u32 = 50;

/// Longest README extract kept in the index.
const MAX_INDEXED_README: usize = 16 * 1024;

/// Trigram similarity a name must reach to be considered a fuzzy match.
///
/// 0.3 is Postgres' own default for the `%` operator; naming it here keeps the behaviour
/// independent of `pg_trgm.similarity_threshold`, which is a per-session GUC anybody could
/// change underneath us.
const TRIGRAM_THRESHOLD: f64 = 0.3;

/// Score bonuses, mirroring the SQLite backend's ladder (exact name ≫ prefix ≫ text rank).
const EXACT_NAME_BONUS: f64 = 3.0;
const PREFIX_NAME_BONUS: f64 = 2.0;

/// Result columns, in [`HitRow`] order.
const HIT_COLS: &str = "ps.package_id, ps.format, ps.name, ps.org_slug, ps.visibility, ps.discontinued, \
                        ps.replaced_by, ps.unlisted, ps.description, ps.topics, ps.latest_version, \
                        ps.latest_retracted, ps.versions_count, ps.published_at, ps.updated_at, \
                        ps.downloads_total, ps.downloads_recent";

/// Postgres-backed [`PackageSearch`].
#[derive(Debug, Clone)]
pub struct PgPackageSearch {
    pool: PgPool,
}

impl PgPackageSearch {
    /// Wraps a pool handle.
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[derive(sqlx::FromRow)]
struct HitRow {
    package_id: Uuid,
    format: String,
    name: String,
    org_slug: String,
    visibility: String,
    discontinued: bool,
    replaced_by: Option<String>,
    unlisted: bool,
    description: String,
    topics: String,
    latest_version: String,
    latest_retracted: bool,
    versions_count: i64,
    published_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
    downloads_total: i64,
    downloads_recent: i64,
    score: f64,
}

impl TryFrom<HitRow> for SearchHit {
    type Error = Error;

    fn try_from(row: HitRow) -> Result<Self> {
        Ok(SearchHit {
            package_id: PackageId::from_uuid(row.package_id),
            format: parse_col(&row.format)?,
            name: row.name,
            org_slug: row.org_slug,
            visibility: parse_col::<Visibility>(&row.visibility)?,
            discontinued: row.discontinued,
            replaced_by: row.replaced_by,
            unlisted: row.unlisted,
            description: row.description,
            topics: split_topics(&row.topics),
            latest_version: row.latest_version,
            latest_retracted: row.latest_retracted,
            versions_count: row.versions_count,
            published_at: row.published_at,
            updated_at: row.updated_at,
            downloads_total: row.downloads_total,
            downloads_recent: row.downloads_recent,
            score: row.score,
        })
    }
}

/// Splits the stored space-separated topic list.
fn split_topics(raw: &str) -> Vec<String> {
    raw.split_whitespace().map(ToOwned::to_owned).collect()
}

#[async_trait]
impl PackageSearch for PgPackageSearch {
    async fn ping(&self) -> Result<()> {
        sqlx::query("SELECT 1").execute(&self.pool).await.map_err(db_err)?;
        Ok(())
    }

    async fn index(&self, document: &SearchDocument) -> Result<()> {
        let mut tx = self.pool.begin().await.map_err(db_err)?;
        sqlx::query(
            "INSERT INTO package_search (package_id, format, name, org_id, org_slug, visibility, discontinued, \
             replaced_by, unlisted, description, readme_text, topics, latest_version, latest_version_sort, \
             latest_retracted, versions_count, published_at, created_at, updated_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19) \
             ON CONFLICT (package_id) DO UPDATE SET \
             format = excluded.format, name = excluded.name, org_id = excluded.org_id, \
             org_slug = excluded.org_slug, visibility = excluded.visibility, \
             discontinued = excluded.discontinued, replaced_by = excluded.replaced_by, \
             unlisted = excluded.unlisted, description = excluded.description, \
             readme_text = excluded.readme_text, topics = excluded.topics, \
             latest_version = excluded.latest_version, latest_version_sort = excluded.latest_version_sort, \
             latest_retracted = excluded.latest_retracted, versions_count = excluded.versions_count, \
             published_at = excluded.published_at, created_at = excluded.created_at, \
             updated_at = excluded.updated_at",
        )
        .bind(*document.package_id.as_uuid())
        .bind(document.format.as_str())
        .bind(&document.name)
        .bind(*document.org_id.as_uuid())
        .bind(&document.org_slug)
        .bind(document.visibility.as_str())
        .bind(document.discontinued)
        .bind(document.replaced_by.as_deref())
        .bind(document.unlisted)
        .bind(&document.description)
        .bind(clip_readme(&document.readme_text))
        .bind(document.topics.join(" "))
        .bind(&document.latest_version)
        .bind(&document.latest_version_sort)
        .bind(document.latest_retracted)
        .bind(document.versions_count)
        .bind(document.published_at)
        .bind(document.created_at)
        .bind(document.updated_at)
        .execute(&mut *tx)
        .await
        .map_err(db_err)?;

        // Tags are rewritten wholesale: a dependency dropped from the newest pubspec must
        // disappear from the reverse graph, and diffing would be more code for the same result.
        sqlx::query("DELETE FROM package_tags WHERE package_id = $1")
            .bind(*document.package_id.as_uuid())
            .execute(&mut *tx)
            .await
            .map_err(db_err)?;
        for (kind, values) in [
            ("topic", &document.topics),
            ("dependency", &document.dependencies),
            ("dev_dependency", &document.dev_dependencies),
        ] {
            for value in values {
                sqlx::query(
                    "INSERT INTO package_tags (package_id, kind, value) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING",
                )
                .bind(*document.package_id.as_uuid())
                .bind(kind)
                .bind(value)
                .execute(&mut *tx)
                .await
                .map_err(db_err)?;
            }
        }
        tx.commit().await.map_err(db_err)
    }

    async fn remove(&self, package: PackageId) -> Result<()> {
        let mut tx = self.pool.begin().await.map_err(db_err)?;
        sqlx::query("DELETE FROM package_tags WHERE package_id = $1")
            .bind(*package.as_uuid())
            .execute(&mut *tx)
            .await
            .map_err(db_err)?;
        sqlx::query("DELETE FROM package_search WHERE package_id = $1")
            .bind(*package.as_uuid())
            .execute(&mut *tx)
            .await
            .map_err(db_err)?;
        tx.commit().await.map_err(db_err)
    }

    async fn search(
        &self,
        query: &SearchQuery,
        view: &SearchView,
        cursor: Option<&str>,
        limit: u32,
    ) -> Result<Page<SearchHit>> {
        let sort = query.effective_sort();
        let limit = limit.clamp(1, MAX_PAGE) as i64;
        let position = cursor.map(|cursor| decode_hit_cursor(sort, cursor)).transpose()?;

        let text = TextQuery::build(query);
        if text.is_unmatchable() {
            // The caller typed something no tokenizer can turn into a lexeme (`%%%`, `++`).
            // Answering "no results" keeps that indistinguishable from a genuine miss.
            return Ok(Page::empty());
        }

        let mut builder: QueryBuilder<Postgres> = QueryBuilder::new(String::new());
        if sort == SearchSort::Relevance {
            builder.push("SELECT * FROM (");
        }
        push_select(&mut builder, sort, &text);
        builder.push(" FROM package_search ps");
        push_where(&mut builder, query, view, &text);

        match sort {
            SearchSort::Relevance => {
                builder.push(") AS ranked");
                if let Some((key, package)) = &position {
                    let score: f64 = key.parse().map_err(|_| malformed(cursor))?;
                    builder.push(" WHERE (score > ").push_bind(score);
                    builder.push(" OR (score = ").push_bind(score);
                    builder.push(" AND package_id > ").push_bind(*package.as_uuid()).push("))");
                }
                builder.push(" ORDER BY score, package_id LIMIT ").push_bind(limit + 1);
            }
            SearchSort::Updated => {
                if let Some((key, package)) = &position {
                    let at = parse_instant(key, cursor)?;
                    builder.push(" AND (ps.updated_at < ").push_bind(at);
                    builder.push(" OR (ps.updated_at = ").push_bind(at);
                    builder.push(" AND ps.package_id > ").push_bind(*package.as_uuid()).push("))");
                }
                builder.push(" ORDER BY ps.updated_at DESC, ps.package_id LIMIT ").push_bind(limit + 1);
            }
            SearchSort::Downloads => {
                if let Some((key, package)) = &position {
                    let downloads: i64 = key.parse().map_err(|_| malformed(cursor))?;
                    builder.push(" AND (ps.downloads_total < ").push_bind(downloads);
                    builder.push(" OR (ps.downloads_total = ").push_bind(downloads);
                    builder.push(" AND ps.package_id > ").push_bind(*package.as_uuid()).push("))");
                }
                builder.push(" ORDER BY ps.downloads_total DESC, ps.package_id LIMIT ").push_bind(limit + 1);
            }
            SearchSort::Name => {
                if let Some((key, package)) = &position {
                    builder.push(" AND (ps.name > ").push_bind(key.clone());
                    builder.push(" OR (ps.name = ").push_bind(key.clone());
                    builder.push(" AND ps.package_id > ").push_bind(*package.as_uuid()).push("))");
                }
                builder.push(" ORDER BY ps.name, ps.package_id LIMIT ").push_bind(limit + 1);
            }
        }

        let rows: Vec<HitRow> = builder.build_query_as().fetch_all(&self.pool).await.map_err(db_err)?;
        page_of(rows, limit, sort)
    }

    async fn facets(&self, query: &SearchQuery, view: &SearchView, facet_limit: u32) -> Result<SearchFacets> {
        let text = TextQuery::build(query);
        if text.is_unmatchable() {
            return Ok(SearchFacets::default());
        }
        let facet_limit = facet_limit.clamp(1, MAX_FACETS) as i64;

        let mut total_query: QueryBuilder<Postgres> =
            QueryBuilder::new("SELECT COUNT(*) AS n FROM package_search ps".to_owned());
        push_where(&mut total_query, query, view, &text);
        let row: PgRow = total_query.build().fetch_one(&self.pool).await.map_err(db_err)?;
        let total: i64 = row.get("n");

        let mut org_query: QueryBuilder<Postgres> =
            QueryBuilder::new("SELECT ps.org_slug AS value, COUNT(*) AS n FROM package_search ps".to_owned());
        push_where(&mut org_query, query, view, &text);
        // Slug breaks count ties so the bucket order is stable across identical requests.
        org_query.push(" GROUP BY ps.org_slug ORDER BY n DESC, ps.org_slug LIMIT ").push_bind(facet_limit);
        let rows: Vec<PgRow> = org_query.build().fetch_all(&self.pool).await.map_err(db_err)?;
        let orgs = rows.into_iter().map(|row| FacetCount { value: row.get("value"), count: row.get("n") }).collect();

        Ok(SearchFacets { total, orgs })
    }

    async fn counters(&self, view: &SearchView) -> Result<InstanceCounters> {
        let mut builder: QueryBuilder<Postgres> = QueryBuilder::new(
            "SELECT COUNT(*) AS packages, COALESCE(SUM(ps.versions_count), 0)::bigint AS versions \
             FROM package_search ps WHERE "
                .to_owned(),
        );
        push_visibility(&mut builder, view);
        let row: PgRow = builder.build().fetch_one(&self.pool).await.map_err(db_err)?;
        let orgs: PgRow = sqlx::query("SELECT COUNT(*) AS n FROM orgs").fetch_one(&self.pool).await.map_err(db_err)?;
        Ok(InstanceCounters { packages: row.get("packages"), versions: row.get("versions"), orgs: orgs.get("n") })
    }

    async fn set_downloads(&self, package: PackageId, totals: DownloadTotals) -> Result<()> {
        sqlx::query("UPDATE package_search SET downloads_total = $1, downloads_recent = $2 WHERE package_id = $3")
            .bind(totals.total)
            .bind(totals.recent)
            .bind(*package.as_uuid())
            .execute(&self.pool)
            .await
            .map_err(db_err)?;
        Ok(())
    }
}

/// Postgres-backed [`StatsRepo`].
#[derive(Debug, Clone)]
pub struct PgStatsRepo {
    pool: PgPool,
}

impl PgStatsRepo {
    /// Wraps a pool handle.
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl StatsRepo for PgStatsRepo {
    async fn ping(&self) -> Result<()> {
        sqlx::query("SELECT 1").execute(&self.pool).await.map_err(db_err)?;
        Ok(())
    }

    async fn add_downloads(&self, deltas: &[DownloadDelta]) -> Result<u64> {
        if deltas.is_empty() {
            return Ok(0);
        }
        let mut tx = self.pool.begin().await.map_err(db_err)?;
        let mut written = 0u64;
        for delta in deltas {
            if delta.count <= 0 {
                continue;
            }
            // `count = count + excluded.count` is the whole contract: several instances flush
            // the same day concurrently and the stored value must be the sum.
            let result = sqlx::query(
                "INSERT INTO download_stats (package_id, version_id, date, count) VALUES ($1, $2, $3, $4) \
                 ON CONFLICT (package_id, version_id, date) \
                 DO UPDATE SET count = download_stats.count + excluded.count",
            )
            .bind(*delta.package_id.as_uuid())
            .bind(*delta.version_id.as_uuid())
            .bind(delta.date)
            .bind(delta.count)
            .execute(&mut *tx)
            .await
            .map_err(db_err)?;
            written += result.rows_affected();
        }
        tx.commit().await.map_err(db_err)?;
        Ok(written)
    }

    async fn package_totals(&self, package: PackageId, since: NaiveDate) -> Result<DownloadTotals> {
        let row: PgRow = sqlx::query(
            "SELECT COALESCE(SUM(count), 0)::bigint AS total, \
             COALESCE(SUM(CASE WHEN date >= $1 THEN count ELSE 0 END), 0)::bigint AS recent \
             FROM download_stats WHERE package_id = $2",
        )
        .bind(since)
        .bind(*package.as_uuid())
        .fetch_one(&self.pool)
        .await
        .map_err(db_err)?;
        Ok(DownloadTotals { total: row.get("total"), recent: row.get("recent") })
    }

    async fn totals_for(&self, packages: &[PackageId], since: NaiveDate) -> Result<Vec<PackageDownloads>> {
        if packages.is_empty() {
            return Ok(Vec::new());
        }
        let mut builder: QueryBuilder<Postgres> = QueryBuilder::new(
            "SELECT package_id, COALESCE(SUM(count), 0)::bigint AS total, \
             COALESCE(SUM(CASE WHEN date >= "
                .to_owned(),
        );
        builder.push_bind(since);
        builder.push(" THEN count ELSE 0 END), 0)::bigint AS recent FROM download_stats WHERE package_id IN (");
        let mut separated = builder.separated(", ");
        for package in packages {
            separated.push_bind(*package.as_uuid());
        }
        builder.push(") GROUP BY package_id");

        let rows: Vec<PgRow> = builder.build().fetch_all(&self.pool).await.map_err(db_err)?;
        Ok(rows
            .into_iter()
            .map(|row| PackageDownloads {
                package_id: PackageId::from_uuid(row.get("package_id")),
                totals: DownloadTotals { total: row.get("total"), recent: row.get("recent") },
            })
            .collect())
    }

    async fn purge_before(&self, cutoff: NaiveDate, batch: u32) -> Result<u64> {
        // No `id` column here — the key is `(package_id, version_id, date)` — so the batch is bound
        // by a row-value `IN`, which both dialects support and which keeps this statement the same
        // shape as every other retention delete. Not `rowid`/`ctid`: those are per-backend physical
        // identifiers, and a retention statement that reads differently per dialect is one the
        // contract suite cannot assert once.
        let result = sqlx::query(
            "DELETE FROM download_stats WHERE (package_id, version_id, date) IN \
             (SELECT package_id, version_id, date FROM download_stats WHERE date < $1 ORDER BY date LIMIT $2)",
        )
        .bind(cutoff)
        .bind(i64::from(batch))
        .execute(&self.pool)
        .await
        .map_err(db_err)?;
        Ok(result.rows_affected())
    }
}

// ----------------------------------------------------------------------------- query building

/// The free-text half of a query, already translated into `tsquery` syntax.
struct TextQuery {
    /// The `to_tsquery` argument; `None` when the query carries no text at all.
    expression: Option<String>,
    /// The raw text, for the exact/prefix/trigram name branches.
    raw: String,
    /// The query carried text but nothing usable survived lexeme extraction.
    unmatchable: bool,
}

impl TextQuery {
    fn build(query: &SearchQuery) -> Self {
        let raw = query.words.join(" ");
        match tsquery_expression(query) {
            Some(expression) => Self { expression: Some(expression), raw, unmatchable: false },
            None if query.has_text() => Self { expression: None, raw, unmatchable: true },
            None => Self { expression: None, raw, unmatchable: false },
        }
    }

    fn is_unmatchable(&self) -> bool {
        self.unmatchable
    }

    /// The text to compare against a package *name*, when there is any.
    ///
    /// `None` for a query built only from quoted phrases: the raw word list is empty there, and
    /// an empty probe would turn `name LIKE '%'` into "every package" — a phrase query that
    /// silently matched the whole instance. Phrases are matched by the tsquery alone.
    fn name_probe(&self) -> Option<&str> {
        Some(self.raw.as_str()).filter(|raw| !raw.is_empty())
    }
}

/// The SELECT list, including the score expression.
///
/// `ts_rank_cd` is negated so that **ascending score is best-first on every backend** — SQLite's
/// bm25 is already negative, and one ordering convention is what lets the cursor codec live in
/// `pub-core` instead of being written twice.
fn push_select(builder: &mut QueryBuilder<Postgres>, sort: SearchSort, text: &TextQuery) {
    let Some(expression) = text.expression.as_ref().filter(|_| sort == SearchSort::Relevance) else {
        builder.push(format!("SELECT {HIT_COLS}, 0.0::float8 AS score"));
        return;
    };
    builder.push(format!("SELECT {HIT_COLS}, -("));
    builder.push("ts_rank_cd(ps.tsv, to_tsquery('simple', ").push_bind(expression.clone()).push("))");
    if let Some(probe) = text.name_probe() {
        builder.push(" + similarity(ps.name, ").push_bind(probe.to_owned()).push(")");
        builder.push(" + CASE WHEN ps.name = ");
        builder.push_bind(probe.to_owned());
        builder.push(format!(" THEN {EXACT_NAME_BONUS} ELSE 0.0 END"));
        builder.push(" + CASE WHEN ps.name LIKE ");
        builder.push_bind(like_prefix(probe));
        builder.push(format!(" ESCAPE '\\' THEN {PREFIX_NAME_BONUS} ELSE 0.0 END"));
    }
    builder.push(")::float8 AS score");
}

/// The WHERE clause: the mandatory visibility predicate, then the text match, then the filters.
fn push_where(builder: &mut QueryBuilder<Postgres>, query: &SearchQuery, view: &SearchView, text: &TextQuery) {
    builder.push(" WHERE ");
    push_visibility(builder, view);
    if let Some(expression) = &text.expression {
        // Full text OR trigram: `pg_trgm` is what makes a typo (`blok`) find `flutter_bloc`,
        // which a lexeme index structurally cannot. The name branches only exist when the query
        // has plain words — a phrase-only query has no name probe, and an empty one would widen
        // `name LIKE '%'` to the whole instance.
        builder.push(" AND (ps.tsv @@ to_tsquery('simple', ").push_bind(expression.clone()).push(")");
        if let Some(probe) = text.name_probe() {
            builder.push(" OR ps.name LIKE ").push_bind(like_prefix(probe)).push(" ESCAPE '\\'");
            builder.push(" OR similarity(ps.name, ").push_bind(probe.to_owned()).push(") > ");
            builder.push_bind(TRIGRAM_THRESHOLD);
        }
        builder.push(")");
    }
    push_filters(builder, query);
}

/// The visibility and discoverability predicate — the one thing no query may relax.
///
/// Two rules, both from S-04 and the meaning of `unlisted`: a private package is visible only
/// inside an org the principal may read, and an unlisted package never leaves its own org at
/// all (it stays resolvable by name through the pub protocol, which is a different question).
fn push_visibility(builder: &mut QueryBuilder<Postgres>, view: &SearchView) {
    let orgs = view.readable_orgs();
    if orgs.is_empty() {
        builder.push("(ps.visibility = 'public' AND NOT ps.unlisted)");
        return;
    }
    builder.push("(ps.visibility = 'public' OR ps.org_id IN (");
    let mut separated = builder.separated(", ");
    for org in orgs {
        separated.push_bind(*org.as_uuid());
    }
    builder.push(")) AND (NOT ps.unlisted OR ps.org_id IN (");
    let mut separated = builder.separated(", ");
    for org in orgs {
        separated.push_bind(*org.as_uuid());
    }
    builder.push("))");
}

/// The filter dimensions: `any` is OR within a dimension, `none` is AND-NOT, dimensions AND.
fn push_filters(builder: &mut QueryBuilder<Postgres>, query: &SearchQuery) {
    push_in(builder, "ps.format", &query.formats.any.iter().map(|f| f.as_str().to_owned()).collect::<Vec<_>>(), false);
    push_in(builder, "ps.format", &query.formats.none.iter().map(|f| f.as_str().to_owned()).collect::<Vec<_>>(), true);
    push_in(builder, "ps.org_slug", &query.orgs.any, false);
    push_in(builder, "ps.org_slug", &query.orgs.none, true);
    push_tags(builder, TOPIC_KINDS, &query.topics.any, false);
    push_tags(builder, TOPIC_KINDS, &query.topics.none, true);
    push_tags(builder, DEPENDENCY_KINDS, &query.dependencies.any, false);
    push_tags(builder, DEPENDENCY_KINDS, &query.dependencies.none, true);

    if !query.flags.any.is_empty() {
        builder.push(" AND (");
        for (index, flag) in query.flags.any.iter().enumerate() {
            if index > 0 {
                builder.push(" OR ");
            }
            builder.push(flag_predicate(*flag));
        }
        builder.push(")");
    }
    for flag in &query.flags.none {
        builder.push(" AND NOT (").push(flag_predicate(*flag)).push(")");
    }
}

/// Tag kinds behind `topic:` and `dependency:`.
const TOPIC_KINDS: &[&str] = &["topic"];
const DEPENDENCY_KINDS: &[&str] = &["dependency", "dev_dependency"];

/// `column IN (…)` / `column NOT IN (…)`, skipped when the value list is empty.
fn push_in(builder: &mut QueryBuilder<Postgres>, column: &str, values: &[String], negated: bool) {
    if values.is_empty() {
        return;
    }
    builder.push(" AND ");
    builder.push(column);
    builder.push(if negated { " NOT IN (" } else { " IN (" });
    let mut separated = builder.separated(", ");
    for value in values {
        separated.push_bind(value.clone());
    }
    builder.push(")");
}

/// `EXISTS`/`NOT EXISTS` over `package_tags` for one dimension.
fn push_tags(builder: &mut QueryBuilder<Postgres>, kinds: &[&str], values: &[String], negated: bool) {
    if values.is_empty() {
        return;
    }
    builder.push(if negated { " AND NOT EXISTS (" } else { " AND EXISTS (" });
    builder.push("SELECT 1 FROM package_tags t WHERE t.package_id = ps.package_id AND t.kind IN (");
    let mut separated = builder.separated(", ");
    for kind in kinds {
        separated.push_bind((*kind).to_owned());
    }
    builder.push(") AND t.value IN (");
    let mut separated = builder.separated(", ");
    for value in values {
        separated.push_bind(value.clone());
    }
    builder.push("))");
}

/// SQL for one `is:` flag.
fn flag_predicate(flag: SearchFlag) -> &'static str {
    match flag {
        SearchFlag::Private => "ps.visibility = 'private'",
        SearchFlag::Public => "ps.visibility = 'public'",
        SearchFlag::Discontinued => "ps.discontinued",
        SearchFlag::Unlisted => "ps.unlisted",
        SearchFlag::RetractedLatest => "ps.latest_retracted",
    }
}

/// Turns the free text into one `to_tsquery` argument, or `None` when nothing is usable.
///
/// Every lexeme is a **quoted** tsquery string, so the operator vocabulary (`&`, `|`, `!`,
/// `<->`, `(`, `)`, `:`) inside a search term is data. Words get `:*` for prefix matching;
/// phrases become `<->`-joined adjacency, which is what a quoted phrase means.
fn tsquery_expression(query: &SearchQuery) -> Option<String> {
    let mut parts = Vec::new();
    for word in &query.words {
        if let Some(lexeme) = tsquery_lexeme(word) {
            parts.push(format!("{lexeme}:*"));
        }
    }
    for phrase in &query.phrases {
        let adjacent: Vec<String> = phrase.split_whitespace().filter_map(tsquery_lexeme).collect();
        if !adjacent.is_empty() {
            parts.push(format!("({})", adjacent.join(" <-> ")));
        }
    }
    if parts.is_empty() { None } else { Some(parts.join(" & ")) }
}

/// Quotes one term as a tsquery lexeme, or `None` when it holds nothing indexable.
///
/// Inside `'…'` Postgres takes every character literally except `'` and `\`, both of which must
/// be doubled — that is the whole escape surface, and it is why this cannot be a `format!`.
fn tsquery_lexeme(term: &str) -> Option<String> {
    if !term.chars().any(char::is_alphanumeric) {
        return None;
    }
    Some(format!("'{}'", term.replace('\\', "\\\\").replace('\'', "''")))
}

/// Escapes a `LIKE` pattern's wildcards and appends `%`.
///
/// Package names contain `_`, which is a single-character wildcard — without escaping,
/// `flutter_bloc%` would also match `flutterXbloc`, and the "prefix" bonus would land on the
/// wrong rows.
fn like_prefix(raw: &str) -> String {
    let mut escaped = String::with_capacity(raw.len() + 1);
    for ch in raw.chars() {
        if matches!(ch, '%' | '_' | '\\') {
            escaped.push('\\');
        }
        escaped.push(ch);
    }
    escaped.push('%');
    escaped
}

/// Caps the indexed README extract on a char boundary.
fn clip_readme(raw: &str) -> &str {
    if raw.len() <= MAX_INDEXED_README {
        return raw;
    }
    let mut end = MAX_INDEXED_README;
    while end > 0 && !raw.is_char_boundary(end) {
        end -= 1;
    }
    &raw[..end]
}

fn malformed(cursor: Option<&str>) -> Error {
    Error::Invalid { message: format!("malformed cursor: {}", cursor.unwrap_or_default()) }
}

/// Parses a cursor's RFC3339 timestamp component.
fn parse_instant(raw: &str, cursor: Option<&str>) -> Result<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(raw).map(|at| at.with_timezone(&Utc)).map_err(|_| malformed(cursor))
}

/// Turns an over-fetched row set into a page with its continuation cursor.
fn page_of(rows: Vec<HitRow>, limit: i64, sort: SearchSort) -> Result<Page<SearchHit>> {
    let has_more = rows.len() as i64 > limit;
    let items: Vec<SearchHit> = rows.into_iter().take(limit as usize).map(TryInto::try_into).collect::<Result<_>>()?;
    let cursor = if has_more { items.last().map(|hit| encode_hit_cursor(sort, hit)) } else { None };
    Ok(Page { items, cursor, has_more })
}

#[cfg(test)]
mod tests {
    use pub_core::search::{SearchSort, parse_query};

    use super::*;

    #[test]
    fn tsquery_lexemes_are_quoted_so_operators_are_data() {
        let query = parse_query("a | b", SearchSort::Relevance);
        assert_eq!(tsquery_expression(&query).unwrap(), "'a':* & 'b':*");
        // Quotes and backslashes inside a term cannot escape their own quoting.
        let query = parse_query("o'brien c:\\\\x", SearchSort::Relevance);
        let expression = tsquery_expression(&query).unwrap();
        assert!(expression.contains("'o''brien':*"), "{expression}");
    }

    #[test]
    fn phrases_become_adjacency_groups() {
        let query = parse_query("\"state management\"", SearchSort::Relevance);
        assert_eq!(tsquery_expression(&query).unwrap(), "('state' <-> 'management')");
    }

    #[test]
    fn terms_with_nothing_indexable_produce_no_expression() {
        for raw in ["%%%", "***", "-- ;", "\"\""] {
            let query = parse_query(raw, SearchSort::Relevance);
            assert_eq!(tsquery_expression(&query), None, "{raw} produced a tsquery");
        }
    }

    #[test]
    fn like_prefixes_escape_the_wildcards_in_package_names() {
        assert_eq!(like_prefix("flutter_bloc"), "flutter\\_bloc%");
        assert_eq!(like_prefix("100%"), "100\\%%");
        assert_eq!(like_prefix("a\\b"), "a\\\\b%");
    }

    #[test]
    fn readme_extracts_are_clipped_on_char_boundaries() {
        let long = "é".repeat(MAX_INDEXED_README);
        let clipped = clip_readme(&long);
        assert!(clipped.len() <= MAX_INDEXED_README);
        assert!(std::str::from_utf8(clipped.as_bytes()).is_ok());
    }
}
