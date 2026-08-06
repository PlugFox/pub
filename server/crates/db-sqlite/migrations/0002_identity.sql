-- 0002_identity (sqlite): identity & access schema — users, credentials, orgs, org_members,
-- invitations, sessions, tokens, audit_log, settings.
--
-- SQLite idioms (docs/rules/migrations.md): STRICT tables, TEXT UUID v7 ids, TEXT RFC3339 UTC
-- timestamps (fixed-width, lexicographically ordered), COLLATE NOCASE for case-insensitive
-- uniqueness (ASCII folding), partial indexes for active-row lookups. Foreign keys rely on
-- PRAGMA foreign_keys = ON (set by the pool in the db-sqlite crate). Append-only enforcement
-- for audit_log lives in the repository implementation — SQLite has no roles/grants.

-- ---------------------------------------------------------------------------- users
CREATE TABLE users (
    id             TEXT NOT NULL PRIMARY KEY,                -- UUID v7
    email          TEXT COLLATE NOCASE,                      -- NULL after anonymization (S-29)
    email_verified INTEGER NOT NULL DEFAULT 0 CHECK (email_verified IN (0, 1)),
    display_name   TEXT NOT NULL,
    status         TEXT NOT NULL CHECK (status IN ('active', 'suspended', 'deleted')),
    created_at     TEXT NOT NULL,                            -- RFC3339 UTC
    updated_at     TEXT NOT NULL
) STRICT;

-- Case-insensitivity comes from the column's NOCASE collation.
CREATE UNIQUE INDEX users_email_key ON users (email) WHERE email IS NOT NULL;

-- ---------------------------------------------------------------------- credentials
-- Polymorphic over type (decision 12); which optional columns are set depends on it.
CREATE TABLE credentials (
    id         TEXT NOT NULL PRIMARY KEY,                    -- UUID v7
    user_id    TEXT NOT NULL REFERENCES users (id),
    type       TEXT NOT NULL CHECK (type IN ('oidc', 'email', 'totp', 'recovery', 'webauthn')),
    issuer     TEXT,                                         -- oidc: issuer URL
    subject    TEXT,                                         -- oidc: subject claim
    email      TEXT COLLATE NOCASE,                          -- email identity
    secret_enc BLOB,                                         -- totp/recovery/webauthn material,
                                                             --   KEK-encrypted or hashed (S-05)
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
) STRICT;

-- Identity key for OIDC is (iss, sub) instance-wide (S-01).
CREATE UNIQUE INDEX credentials_oidc_key ON credentials (type, issuer, subject)
    WHERE issuer IS NOT NULL AND subject IS NOT NULL;
-- One email identity per (user, email).
CREATE UNIQUE INDEX credentials_email_key ON credentials (user_id, email) WHERE type = 'email';
CREATE INDEX credentials_user_idx ON credentials (user_id);

-- ----------------------------------------------------------------------------- orgs
CREATE TABLE orgs (
    id         TEXT NOT NULL PRIMARY KEY,                    -- UUID v7
    name       TEXT NOT NULL,
    slug       TEXT NOT NULL COLLATE NOCASE,                 -- virtual registry base /o/{slug}/pub
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
) STRICT;

CREATE UNIQUE INDEX orgs_slug_key ON orgs (slug);

-- ---------------------------------------------------------------------- org_members
-- role_level: cumulative ladder 50/100/200/250 with gaps (decision 19); a row always means
-- membership, so 0 ("none") is banned. The ≥1-Owner invariant is transactional app logic.
CREATE TABLE org_members (
    org_id     TEXT NOT NULL REFERENCES orgs (id),
    user_id    TEXT NOT NULL REFERENCES users (id),
    role_level INTEGER NOT NULL CHECK (role_level > 0 AND role_level <= 255),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    PRIMARY KEY (org_id, user_id)
) STRICT;

CREATE INDEX org_members_user_idx ON org_members (user_id);

-- ---------------------------------------------------------------------- invitations
-- Single-use, email-bound, expiring (7-day default), hashed token (S-06).
CREATE TABLE invitations (
    id          TEXT NOT NULL PRIMARY KEY,                   -- UUID v7
    org_id      TEXT NOT NULL REFERENCES orgs (id),
    email       TEXT NOT NULL COLLATE NOCASE,
    role_level  INTEGER NOT NULL CHECK (role_level > 0 AND role_level <= 255),
    token_hash  TEXT NOT NULL,                               -- SHA-256; plaintext only in the email
    invited_by  TEXT NOT NULL REFERENCES users (id),
    created_at  TEXT NOT NULL,
    expires_at  TEXT NOT NULL,
    accepted_at TEXT,
    accepted_by TEXT REFERENCES users (id),
    revoked_at  TEXT
) STRICT;

CREATE UNIQUE INDEX invitations_token_hash_key ON invitations (token_hash);
CREATE INDEX invitations_pending_org_idx ON invitations (org_id)
    WHERE accepted_at IS NULL AND revoked_at IS NULL;

-- ------------------------------------------------------------------------- sessions
-- Server-side half of the rotating refresh token (decision 03, S-08/S-09).
CREATE TABLE sessions (
    id                TEXT NOT NULL PRIMARY KEY,             -- UUID v7, JWT `sid`
    user_id           TEXT NOT NULL REFERENCES users (id),
    refresh_hash      TEXT NOT NULL,                         -- SHA-256 of the current token
    prev_refresh_hash TEXT,                                  -- rotated-out hash; reuse detection
    user_agent        TEXT,
    ip                TEXT,
    created_at        TEXT NOT NULL,                         -- anchor of the absolute cap
    last_seen_at      TEXT NOT NULL,                         -- anchor of the idle window
    revoked_at        TEXT                                   -- durable revocation truth (S-09)
) STRICT;

CREATE UNIQUE INDEX sessions_refresh_hash_key ON sessions (refresh_hash);
-- Reuse detection: lookups by rotated-out hash (S-08).
CREATE INDEX sessions_prev_hash_idx ON sessions (prev_refresh_hash) WHERE prev_refresh_hash IS NOT NULL;
-- Active-session lookups: session list UI, revoke-all.
CREATE INDEX sessions_active_user_idx ON sessions (user_id) WHERE revoked_at IS NULL;

-- --------------------------------------------------------------------------- tokens
-- CLI/API credential plane (decision 13, S-13): SHA-256 at rest, org-bound, scoped.
CREATE TABLE tokens (
    id               TEXT NOT NULL PRIMARY KEY,              -- UUID v7
    user_id          TEXT NOT NULL REFERENCES users (id),
    org_id           TEXT NOT NULL REFERENCES orgs (id),
    name             TEXT NOT NULL,
    token_hash       TEXT NOT NULL,                          -- SHA-256; plaintext shown once
    display_hint     TEXT NOT NULL,                          -- first 8 chars, list UI
    scopes           TEXT NOT NULL,                          -- JSON array: read|publish|retract|admin
    package_patterns TEXT NOT NULL,                          -- JSON array; [] = no narrowing
    created_at       TEXT NOT NULL,
    expires_at       TEXT,                                   -- NULL = non-expiring (read-only tokens)
    last_used_at     TEXT,                                   -- write-throttled (S-13)
    last_used_ip     TEXT,
    revoked_at       TEXT
) STRICT;

CREATE UNIQUE INDEX tokens_hash_key ON tokens (token_hash);
-- The auth hot path: active-token lookup by hash.
CREATE INDEX tokens_active_hash_idx ON tokens (token_hash) WHERE revoked_at IS NULL;
CREATE INDEX tokens_user_idx ON tokens (user_id);
CREATE INDEX tokens_org_idx ON tokens (org_id);

-- ------------------------------------------------------------------------ audit_log
-- Append-only (S-22). SQLite has no roles, so append-only is enforced by the AuditRepo trait
-- surface (no update/delete exists) — the Postgres migration additionally documents an
-- INSERT-only role grant. No foreign keys: audit rows must outlive every referenced entity.
CREATE TABLE audit_log (
    id         TEXT NOT NULL PRIMARY KEY,                    -- ULID; newest-first cursor key
    created_at TEXT NOT NULL,
    actor_type TEXT NOT NULL CHECK (actor_type IN ('user', 'token', 'system')),
    actor_id   TEXT,                                         -- NULL for system
    ip         TEXT,
    user_agent TEXT,
    org_id     TEXT,
    action     TEXT NOT NULL,                                -- dot-namespaced: org.member.add
    target     TEXT,
    result     TEXT NOT NULL CHECK (result IN ('success', 'failure')),
    metadata   TEXT                                          -- JSON before/after context
) STRICT;

-- Keyset pagination is `ORDER BY id DESC`; these serve the filter combinations.
CREATE INDEX audit_org_idx ON audit_log (org_id, id);
CREATE INDEX audit_action_idx ON audit_log (action, id);
CREATE INDEX audit_created_idx ON audit_log (created_at);

-- ------------------------------------------------------------------------- settings
-- Runtime-changeable key → JSON (decision 09). Per-key version bumps on every upsert; the
-- instance version (reconciliation poll) is SUM(version) — a monotonic change counter.
CREATE TABLE settings (
    key        TEXT NOT NULL PRIMARY KEY,
    value      TEXT NOT NULL,                                -- JSON
    version    INTEGER NOT NULL DEFAULT 1,
    updated_at TEXT NOT NULL
) STRICT;
