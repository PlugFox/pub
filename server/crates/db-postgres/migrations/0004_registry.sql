-- 0004_registry (postgres): the registry schema — name claims, packages, immutable versions,
-- and the upstream proxy cache. Logically identical to the sqlite migration of the same
-- number; dialect-idiomatic per docs/rules/migrations.md: UUID ids, TIMESTAMPTZ, JSONB,
-- BOOLEAN, BIGINT, partial indexes matching the live-row predicates.

-- ------------------------------------------------------------------------ name_claims
-- A name belongs to exactly one org per format (decision 01). Written at the first publish or
-- by an explicit reservation; consulted by resolution ("local always wins", S-16) and by the
-- shadowing alarm (S-17).
CREATE TABLE name_claims (
    format     TEXT NOT NULL,                             -- 'pub' (npm/cargo later)
    name       TEXT NOT NULL,
    org_id     UUID NOT NULL REFERENCES orgs (id),
    claimed_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (format, name)
);

CREATE INDEX name_claims_org_idx ON name_claims (org_id, name);

-- --------------------------------------------------------------------------- packages
CREATE TABLE packages (
    id           UUID PRIMARY KEY,                        -- UUID v7
    format       TEXT NOT NULL,
    name         TEXT NOT NULL,
    org_id       UUID NOT NULL REFERENCES orgs (id),
    visibility   TEXT NOT NULL CHECK (visibility IN ('public', 'private')),
    discontinued BOOLEAN NOT NULL DEFAULT FALSE,
    replaced_by  TEXT,                                    -- suggested successor (listing field)
    unlisted     BOOLEAN NOT NULL DEFAULT FALSE,
    created_at   TIMESTAMPTZ NOT NULL,
    updated_at   TIMESTAMPTZ NOT NULL,
    FOREIGN KEY (format, name) REFERENCES name_claims (format, name)
);

-- Unique per instance per format (decision 21). Mirrors the claim key, so a package can never
-- exist without owning its name.
CREATE UNIQUE INDEX packages_format_name_key ON packages (format, name);
-- Org listing hot path, keyset-paginated over (name, id).
CREATE INDEX packages_org_idx ON packages (org_id, name, id);
-- Public browsing / search feed: listed public packages per format.
CREATE INDEX packages_public_idx ON packages (format, name)
    WHERE visibility = 'public' AND NOT unlisted;

-- --------------------------------------------------------------------------- versions
-- Immutable (decision 06, S-18). The only mutable columns are `retracted_at` and the
-- tombstone set by a hard delete; the row itself is never removed, because the version number
-- must stay burned forever.
--
-- `version_sort` carries an explicit `COLLATE "C"`: the precedence key orders correctly only
-- under **bytewise** comparison. A locale collation (the cluster default is usually
-- en_US.UTF-8 or an ICU locale) folds punctuation and case, which would silently reorder
-- pre-releases — the one place where a wrong ORDER BY produces wrong resolution results
-- rather than an error.
CREATE TABLE versions (
    id                 UUID PRIMARY KEY,                  -- UUID v7
    package_id         UUID NOT NULL REFERENCES packages (id),
    version            TEXT NOT NULL,                     -- canonical semver text
    version_sort       TEXT NOT NULL COLLATE "C",         -- precedence key (core::SemVer::sort_key)
    pubspec            JSONB NOT NULL,                    -- metadata document; '{}' once tombstoned
    archive_sha256     TEXT NOT NULL,                     -- 64 lowercase hex; the client pins this
    archive_size       BIGINT NOT NULL,
    published_by       UUID NOT NULL REFERENCES users (id),
    published_by_token UUID REFERENCES tokens (id),       -- provenance-lite (S-21)
    published_at       TIMESTAMPTZ NOT NULL,
    retracted_at       TIMESTAMPTZ,                       -- still downloadable when set
    tombstone          BOOLEAN NOT NULL DEFAULT FALSE,
    readme_html        TEXT,                              -- sanitized at publish, immutable (S-11)
    changelog_html     TEXT
);

-- Deliberately NOT a partial index: it must cover tombstoned rows so a hard-deleted version
-- number can never be published again (decision 06, S-18).
CREATE UNIQUE INDEX versions_package_version_key ON versions (package_id, version);
-- The version-listing hot path: live rows of one package in precedence order.
CREATE INDEX versions_listing_idx ON versions (package_id, version_sort, id)
    WHERE NOT tombstone;
-- Blob reference counting: "is any live version still backed by these bytes?" before a hard
-- delete removes them, plus unreferenced-blob GC.
CREATE INDEX versions_sha256_idx ON versions (archive_sha256) WHERE NOT tombstone;

-- ------------------------------------------------------------------ upstream_packages
-- Proxy cache metadata (decision 07). The pipeline lands later; the schema lands now so the
-- resolution and ingest code has a stable shape to build against. Upstream flags are stored
-- verbatim (S-19) — only `archive_url` is ever rewritten, and that happens at serve time.
CREATE TABLE upstream_packages (
    id                 UUID PRIMARY KEY,                  -- UUID v7
    format             TEXT NOT NULL,
    name               TEXT NOT NULL,
    upstream           TEXT NOT NULL,                     -- upstream base URL (https://pub.dev)
    discontinued       BOOLEAN NOT NULL DEFAULT FALSE,
    replaced_by        TEXT,
    advisories_updated TEXT,                              -- RFC3339 string, verbatim from upstream
    listing            JSONB,                             -- raw listing snapshot
    fetched_at         TIMESTAMPTZ NOT NULL
);

CREATE UNIQUE INDEX upstream_packages_format_name_key ON upstream_packages (format, name);
-- Mirror-mode drift repair walks the cache oldest-snapshot first.
CREATE INDEX upstream_packages_stale_idx ON upstream_packages (fetched_at);

-- ------------------------------------------------------------------ upstream_versions
CREATE TABLE upstream_versions (
    id                  UUID PRIMARY KEY,                 -- UUID v7
    upstream_package_id UUID NOT NULL REFERENCES upstream_packages (id),
    version             TEXT NOT NULL,
    version_sort        TEXT NOT NULL COLLATE "C",        -- same precedence key as `versions`
    pubspec             JSONB NOT NULL,                   -- upstream metadata document, verbatim
    archive_sha256      TEXT NOT NULL,                    -- verified at ingest, re-verified on serve (S-19)
    archive_size        BIGINT,
    retracted           BOOLEAN NOT NULL DEFAULT FALSE,
    cached              BOOLEAN NOT NULL DEFAULT FALSE,
    published_at        TIMESTAMPTZ,
    fetched_at          TIMESTAMPTZ NOT NULL
);

CREATE UNIQUE INDEX upstream_versions_key ON upstream_versions (upstream_package_id, version);
CREATE INDEX upstream_versions_listing_idx ON upstream_versions (upstream_package_id, version_sort, id);
