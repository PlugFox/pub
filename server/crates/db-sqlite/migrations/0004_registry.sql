-- 0004_registry (sqlite): the registry schema — name claims, packages, immutable versions,
-- and the upstream proxy cache. Format-agnostic from day one (decision 21): every entity is
-- keyed by (format, name), and the format's own metadata document is stored as JSON.
--
-- SQLite idioms (docs/rules/migrations.md): STRICT tables, TEXT UUID v7 ids, TEXT RFC3339 UTC
-- timestamps, partial indexes for live-row lookups. Text comparison is BINARY here (no column
-- carries COLLATE NOCASE), which is what `version_sort` requires — see below.

-- ------------------------------------------------------------------------ name_claims
-- A name belongs to exactly one org per format (decision 01). Written at the first publish or
-- by an explicit reservation; consulted by resolution ("local always wins", S-16) and by the
-- shadowing alarm (S-17). Package names are validated lowercase, so BINARY comparison is
-- exact-match by construction.
CREATE TABLE name_claims (
    format     TEXT NOT NULL,                             -- 'pub' (npm/cargo later)
    name       TEXT NOT NULL,
    org_id     TEXT NOT NULL REFERENCES orgs (id),
    claimed_at TEXT NOT NULL,                             -- RFC3339 UTC
    PRIMARY KEY (format, name)
) STRICT;

CREATE INDEX name_claims_org_idx ON name_claims (org_id, name);

-- --------------------------------------------------------------------------- packages
CREATE TABLE packages (
    id           TEXT NOT NULL PRIMARY KEY,               -- UUID v7
    format       TEXT NOT NULL,
    name         TEXT NOT NULL,
    org_id       TEXT NOT NULL REFERENCES orgs (id),
    visibility   TEXT NOT NULL CHECK (visibility IN ('public', 'private')),
    discontinued INTEGER NOT NULL DEFAULT 0 CHECK (discontinued IN (0, 1)),
    replaced_by  TEXT,                                    -- suggested successor (listing field)
    unlisted     INTEGER NOT NULL DEFAULT 0 CHECK (unlisted IN (0, 1)),
    created_at   TEXT NOT NULL,
    updated_at   TEXT NOT NULL,
    FOREIGN KEY (format, name) REFERENCES name_claims (format, name)
) STRICT;

-- Unique per instance per format (decision 21). Mirrors the claim key, so a package can never
-- exist without owning its name.
CREATE UNIQUE INDEX packages_format_name_key ON packages (format, name);
-- Org listing hot path, keyset-paginated over (name, id).
CREATE INDEX packages_org_idx ON packages (org_id, name, id);
-- Public browsing / search feed: listed public packages per format.
CREATE INDEX packages_public_idx ON packages (format, name)
    WHERE visibility = 'public' AND unlisted = 0;

-- --------------------------------------------------------------------------- versions
-- Immutable (decision 06, S-18). The only mutable columns are `retracted_at` and the
-- tombstone set by a hard delete; the row itself is never removed, because the version number
-- must stay burned forever.
CREATE TABLE versions (
    id                 TEXT NOT NULL PRIMARY KEY,         -- UUID v7
    package_id         TEXT NOT NULL REFERENCES packages (id),
    version            TEXT NOT NULL,                     -- canonical semver text
    version_sort       TEXT NOT NULL,                     -- precedence key (core::SemVer::sort_key)
    pubspec            TEXT NOT NULL,                     -- metadata document as JSON; '{}' once tombstoned
    archive_sha256     TEXT NOT NULL,                     -- 64 lowercase hex; the client pins this
    archive_size       INTEGER NOT NULL,
    published_by       TEXT NOT NULL REFERENCES users (id),
    published_by_token TEXT REFERENCES tokens (id),       -- provenance-lite (S-21)
    published_at       TEXT NOT NULL,
    retracted_at       TEXT,                              -- still downloadable when set
    tombstone          INTEGER NOT NULL DEFAULT 0 CHECK (tombstone IN (0, 1)),
    readme_html        TEXT,                              -- sanitized at publish, immutable (S-11)
    changelog_html     TEXT
) STRICT;

-- Deliberately NOT a partial index: it must cover tombstoned rows so a hard-deleted version
-- number can never be published again (decision 06, S-18).
CREATE UNIQUE INDEX versions_package_version_key ON versions (package_id, version);
-- The version-listing hot path: live rows of one package in precedence order.
--
-- `version_sort` is compared bytewise (SQLite's default BINARY collation), which is what makes
-- lexicographic order equal semver precedence; a case- or punctuation-folding collation would
-- silently break the ordering.
CREATE INDEX versions_listing_idx ON versions (package_id, version_sort, id)
    WHERE tombstone = 0;
-- Blob reference counting: "is any live version still backed by these bytes?" before a hard
-- delete removes them, plus unreferenced-blob GC.
CREATE INDEX versions_sha256_idx ON versions (archive_sha256) WHERE tombstone = 0;

-- ------------------------------------------------------------------ upstream_packages
-- Proxy cache metadata (decision 07). The pipeline lands later; the schema lands now so the
-- resolution and ingest code has a stable shape to build against. Upstream flags are stored
-- verbatim (S-19) — only `archive_url` is ever rewritten, and that happens at serve time.
CREATE TABLE upstream_packages (
    id                 TEXT NOT NULL PRIMARY KEY,         -- UUID v7
    format             TEXT NOT NULL,
    name               TEXT NOT NULL,
    upstream           TEXT NOT NULL,                     -- upstream base URL (https://pub.dev)
    discontinued       INTEGER NOT NULL DEFAULT 0 CHECK (discontinued IN (0, 1)),
    replaced_by        TEXT,
    advisories_updated TEXT,                              -- RFC3339 string, verbatim from upstream
    listing            TEXT,                              -- raw listing JSON snapshot
    fetched_at         TEXT NOT NULL
) STRICT;

CREATE UNIQUE INDEX upstream_packages_format_name_key ON upstream_packages (format, name);
-- Mirror-mode drift repair walks the cache oldest-snapshot first.
CREATE INDEX upstream_packages_stale_idx ON upstream_packages (fetched_at);

-- ------------------------------------------------------------------ upstream_versions
CREATE TABLE upstream_versions (
    id                  TEXT NOT NULL PRIMARY KEY,        -- UUID v7
    upstream_package_id TEXT NOT NULL REFERENCES upstream_packages (id),
    version             TEXT NOT NULL,
    version_sort        TEXT NOT NULL,                    -- same precedence key as `versions`
    pubspec             TEXT NOT NULL,                    -- upstream metadata document, verbatim
    archive_sha256      TEXT NOT NULL,                    -- verified at ingest, re-verified on serve (S-19)
    archive_size        INTEGER,
    retracted           INTEGER NOT NULL DEFAULT 0 CHECK (retracted IN (0, 1)),
    cached              INTEGER NOT NULL DEFAULT 0 CHECK (cached IN (0, 1)),
    published_at        TEXT,
    fetched_at          TEXT NOT NULL
) STRICT;

CREATE UNIQUE INDEX upstream_versions_key ON upstream_versions (upstream_package_id, version);
CREATE INDEX upstream_versions_listing_idx ON upstream_versions (upstream_package_id, version_sort, id);
