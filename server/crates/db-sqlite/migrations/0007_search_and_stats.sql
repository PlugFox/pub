-- 0007_search_and_stats (sqlite): the package search index (decision 11) and the daily
-- download rollup (docs/architecture.md `download_stats`).
--
-- Two structures, one purpose: everything the web read model renders — search results, the
-- landing dashboard, reverse dependencies, download counters — is answered from here rather
-- than from `packages` + `versions` + a JSON scan of every pubspec.
--
-- The index is **derived data**. Every row can be rebuilt from `packages` and `versions` by
-- the reindex job, which is why nothing here is a foreign key onto a mutable projection and
-- why the publish path may fail to write it without failing the publish.

-- ------------------------------------------------------------------- package_search
-- One row per package that has at least one live version. A package with nothing published
-- (an explicit name reservation, or one whose versions were all hard-deleted) is absent: a
-- search result always carries a version, so "exists but has nothing to show" is not a result.
--
-- `seq` is an INTEGER PRIMARY KEY, i.e. the rowid, purely so the FTS5 index below can be an
-- external-content table keyed on it (FTS5 addresses rows by rowid; our ids are TEXT UUIDs).
--
-- The three text columns are NOT NULL DEFAULT '' rather than nullable: FTS5's external-content
-- 'delete' command has to be handed the *original* column values to remove the right postings,
-- and a NULL there silently desynchronizes the index from its content table.
CREATE TABLE package_search (
    seq                 INTEGER PRIMARY KEY,
    package_id          TEXT NOT NULL UNIQUE REFERENCES packages (id),
    format              TEXT NOT NULL,
    name                TEXT NOT NULL,
    org_id              TEXT NOT NULL REFERENCES orgs (id),
    org_slug            TEXT NOT NULL,                     -- denormalized: `org:` filters need no join
    visibility          TEXT NOT NULL CHECK (visibility IN ('public', 'private')),
    discontinued        INTEGER NOT NULL DEFAULT 0 CHECK (discontinued IN (0, 1)),
    replaced_by         TEXT,
    unlisted            INTEGER NOT NULL DEFAULT 0 CHECK (unlisted IN (0, 1)),
    description         TEXT NOT NULL DEFAULT '',          -- from the newest live version
    readme_text         TEXT NOT NULL DEFAULT '',          -- plain text from the rendered README
    topics              TEXT NOT NULL DEFAULT '',          -- space-separated, also fed to FTS
    latest_version      TEXT NOT NULL,
    latest_version_sort TEXT NOT NULL,                     -- precedence key (core::SemVer::sort_key)
    latest_retracted    INTEGER NOT NULL DEFAULT 0 CHECK (latest_retracted IN (0, 1)),
    versions_count      INTEGER NOT NULL DEFAULT 0,
    published_at        TEXT NOT NULL,                     -- newest version's publish time
    created_at          TEXT NOT NULL,
    updated_at          TEXT NOT NULL,                     -- sort:updated
    downloads_total     INTEGER NOT NULL DEFAULT 0,        -- denormalized by the rollup job
    downloads_recent    INTEGER NOT NULL DEFAULT 0
) STRICT;

-- The mandatory visibility predicate leads every query, so it leads every index.
CREATE INDEX package_search_visibility_idx ON package_search (visibility, org_id);
-- sort:updated / sort:downloads / sort:name, each as one keyset scan.
CREATE INDEX package_search_updated_idx ON package_search (updated_at, package_id);
CREATE INDEX package_search_downloads_idx ON package_search (downloads_total, package_id);
CREATE INDEX package_search_name_idx ON package_search (format, name);
CREATE INDEX package_search_org_idx ON package_search (org_slug, name);

-- --------------------------------------------------------------- package_search_fts
-- FTS5 over the same rows, external-content so the text is stored once. `unicode61` with
-- diacritic folding is the right tokenizer for package metadata: identifiers, not prose, so no
-- stemmer — `flutter_bloc` must not stem to something that stops matching `flutter_bloc`.
-- `remove_diacritics 2` folds the whole Unicode range rather than only Latin-1.
CREATE VIRTUAL TABLE package_search_fts USING fts5 (
    name,
    description,
    readme_text,
    topics,
    content = 'package_search',
    content_rowid = 'seq',
    tokenize = "unicode61 remove_diacritics 2"
);

-- Sync triggers (docs/rules/migrations.md: SQLite idiom). The 'delete' command form is
-- mandatory for external-content tables — a plain DELETE would leave the postings behind.
CREATE TRIGGER package_search_ai AFTER INSERT ON package_search BEGIN
    INSERT INTO package_search_fts (rowid, name, description, readme_text, topics)
    VALUES (new.seq, new.name, new.description, new.readme_text, new.topics);
END;

CREATE TRIGGER package_search_ad AFTER DELETE ON package_search BEGIN
    INSERT INTO package_search_fts (package_search_fts, rowid, name, description, readme_text, topics)
    VALUES ('delete', old.seq, old.name, old.description, old.readme_text, old.topics);
END;

CREATE TRIGGER package_search_au AFTER UPDATE ON package_search BEGIN
    INSERT INTO package_search_fts (package_search_fts, rowid, name, description, readme_text, topics)
    VALUES ('delete', old.seq, old.name, old.description, old.readme_text, old.topics);
    INSERT INTO package_search_fts (rowid, name, description, readme_text, topics)
    VALUES (new.seq, new.name, new.description, new.readme_text, new.topics);
END;

-- --------------------------------------------------------------------- package_tags
-- The exact-match dimensions of a query: `topic:` and `dependency:`, plus the reverse
-- dependency graph behind `GET /api/v1/packages/{name}/dependents`.
--
-- One table for both because they are the same shape (a package points at a string) and the
-- same lifecycle (rewritten wholesale whenever the package's document is rebuilt). Splitting
-- them would double the write path for no query benefit.
CREATE TABLE package_tags (
    package_id TEXT NOT NULL REFERENCES packages (id),
    kind       TEXT NOT NULL CHECK (kind IN ('topic', 'dependency', 'dev_dependency')),
    value      TEXT NOT NULL,
    PRIMARY KEY (package_id, kind, value)
) STRICT;

-- The reverse lookup: "who depends on X", "what carries topic Y".
CREATE INDEX package_tags_value_idx ON package_tags (kind, value, package_id);

-- ------------------------------------------------------------------- download_stats
-- Daily rollups, one row per (package, version, day). Counts are **added to**, never written:
-- every instance flushes its own buffered deltas, and a write that set the value would make
-- the last flush win and discard its peers'.
--
-- Version granularity is stored even though v1 only surfaces package totals — the per-version
-- chart of v1.1 cannot be reconstructed from package-level rows after the fact, and the extra
-- cardinality is one row per version per active day.
CREATE TABLE download_stats (
    package_id TEXT NOT NULL REFERENCES packages (id),
    version_id TEXT NOT NULL REFERENCES versions (id),
    date       TEXT NOT NULL,                              -- 'YYYY-MM-DD', UTC
    count      INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (package_id, version_id, date)
) STRICT;

-- Per-package totals, all-time and trailing-window, as one index scan.
CREATE INDEX download_stats_package_date_idx ON download_stats (package_id, date);
