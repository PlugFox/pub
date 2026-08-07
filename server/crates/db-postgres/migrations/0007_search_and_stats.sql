-- 0007_search_and_stats (postgres): the package search index (decision 11) and the daily
-- download rollup (docs/architecture.md `download_stats`). Logically identical to the sqlite
-- migration of the same number; dialect-idiomatic per docs/rules/migrations.md.
--
-- Two structures, one purpose: everything the web read model renders — search results, the
-- landing dashboard, reverse dependencies, download counters — is answered from here rather
-- than from `packages` + `versions` + a JSONB scan of every pubspec.
--
-- The index is **derived data**. Every row can be rebuilt from `packages` and `versions` by
-- the reindex job, which is why the publish path may fail to write it without failing the
-- publish.

-- `pg_trgm` powers name prefix/fuzzy matching (decision 11): a `%` similarity match and a
-- GIN trigram index let `blok` find `flutter_bloc`, which a tsvector cannot do — full-text
-- search matches lexemes, and a typo is not a lexeme. Trusted extension since PG13, so a
-- database owner can create it without superuser.
CREATE EXTENSION IF NOT EXISTS pg_trgm;

-- ------------------------------------------------------------------- package_search
-- One row per package that has at least one live version. A package with nothing published
-- (an explicit name reservation, or one whose versions were all hard-deleted) is absent: a
-- search result always carries a version, so "exists but has nothing to show" is not a result.
--
-- The three text columns are NOT NULL DEFAULT '' so the generated tsvector never has to
-- coalesce, and so both backends store the same thing.
CREATE TABLE package_search (
    package_id          UUID PRIMARY KEY REFERENCES packages (id),
    format              TEXT NOT NULL,
    name                TEXT NOT NULL,
    org_id              UUID NOT NULL REFERENCES orgs (id),
    org_slug            TEXT NOT NULL,                     -- denormalized: `org:` filters need no join
    visibility          TEXT NOT NULL CHECK (visibility IN ('public', 'private')),
    discontinued        BOOLEAN NOT NULL DEFAULT FALSE,
    replaced_by         TEXT,
    unlisted            BOOLEAN NOT NULL DEFAULT FALSE,
    description         TEXT NOT NULL DEFAULT '',          -- from the newest live version
    readme_text         TEXT NOT NULL DEFAULT '',          -- plain text from the rendered README
    topics              TEXT NOT NULL DEFAULT '',          -- space-separated, also fed to the tsvector
    latest_version      TEXT NOT NULL,
    latest_version_sort TEXT NOT NULL COLLATE "C",         -- precedence key (core::SemVer::sort_key)
    latest_retracted    BOOLEAN NOT NULL DEFAULT FALSE,
    versions_count      BIGINT NOT NULL DEFAULT 0,
    published_at        TIMESTAMPTZ NOT NULL,              -- newest version's publish time
    created_at          TIMESTAMPTZ NOT NULL,
    updated_at          TIMESTAMPTZ NOT NULL,              -- sort:updated
    downloads_total     BIGINT NOT NULL DEFAULT 0,         -- denormalized by the rollup job
    downloads_recent    BIGINT NOT NULL DEFAULT 0,
    -- Generated rather than trigger-maintained: `to_tsvector('simple', …)` is immutable, so
    -- the column cannot drift from its inputs, and there is no second write path to forget.
    --
    -- `'simple'` (no stemmer, no stop words) is deliberate: package metadata is identifiers,
    -- not prose. An English stemmer would fold `bloc`/`block` together and drop `a`/`in`/`no`
    -- from names like `flutter_no_op`. Weights rank a name match above a description match
    -- above README prose.
    tsv                 TSVECTOR GENERATED ALWAYS AS (
                            setweight(to_tsvector('simple', name), 'A')
                         || setweight(to_tsvector('simple', topics), 'B')
                         || setweight(to_tsvector('simple', description), 'C')
                         || setweight(to_tsvector('simple', readme_text), 'D')
                        ) STORED
);

CREATE INDEX package_search_tsv_idx ON package_search USING GIN (tsv);
-- Trigram index for prefix and fuzzy name matching (`name % :q`, `name LIKE 'q%'`).
CREATE INDEX package_search_name_trgm_idx ON package_search USING GIN (name gin_trgm_ops);
-- The mandatory visibility predicate leads every query, so it leads every index.
CREATE INDEX package_search_visibility_idx ON package_search (visibility, org_id);
-- sort:updated / sort:downloads / sort:name, each as one keyset scan.
CREATE INDEX package_search_updated_idx ON package_search (updated_at, package_id);
CREATE INDEX package_search_downloads_idx ON package_search (downloads_total, package_id);
CREATE INDEX package_search_name_idx ON package_search (format, name);
CREATE INDEX package_search_org_idx ON package_search (org_slug, name);

-- --------------------------------------------------------------------- package_tags
-- The exact-match dimensions of a query: `topic:` and `dependency:`, plus the reverse
-- dependency graph behind `GET /api/v1/packages/{name}/dependents`.
--
-- One table for both because they are the same shape (a package points at a string) and the
-- same lifecycle (rewritten wholesale whenever the package's document is rebuilt).
CREATE TABLE package_tags (
    package_id UUID NOT NULL REFERENCES packages (id),
    kind       TEXT NOT NULL CHECK (kind IN ('topic', 'dependency', 'dev_dependency')),
    value      TEXT NOT NULL,
    PRIMARY KEY (package_id, kind, value)
);

-- The reverse lookup: "who depends on X", "what carries topic Y".
CREATE INDEX package_tags_value_idx ON package_tags (kind, value, package_id);

-- ------------------------------------------------------------------- download_stats
-- Daily rollups, one row per (package, version, day). Counts are **added to**, never written:
-- every instance flushes its own buffered deltas, and a write that set the value would make
-- the last flush win and discard its peers'.
--
-- Version granularity is stored even though v1 only surfaces package totals — the per-version
-- chart of v1.1 cannot be reconstructed from package-level rows after the fact.
CREATE TABLE download_stats (
    package_id UUID NOT NULL REFERENCES packages (id),
    version_id UUID NOT NULL REFERENCES versions (id),
    date       DATE NOT NULL,                              -- UTC day
    count      BIGINT NOT NULL DEFAULT 0,
    PRIMARY KEY (package_id, version_id, date)
);

-- Per-package totals, all-time and trailing-window, as one index scan.
CREATE INDEX download_stats_package_date_idx ON download_stats (package_id, date);
