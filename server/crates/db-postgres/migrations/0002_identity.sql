-- 0002_identity (postgres): identity & access schema — users, credentials, orgs, org_members,
-- invitations, sessions, tokens, audit_log, settings. Logically identical to the sqlite
-- migration of the same number; dialect-idiomatic per docs/rules/migrations.md: UUID ids,
-- TIMESTAMPTZ, INET, JSONB, SMALLINT role levels, lower() expression indexes for
-- case-insensitive uniqueness, partial indexes for active-row lookups.

-- ---------------------------------------------------------------------------- users
CREATE TABLE users (
    id             UUID PRIMARY KEY,                          -- UUID v7
    email          TEXT,                                      -- NULL after anonymization (S-29)
    email_verified BOOLEAN NOT NULL DEFAULT FALSE,
    display_name   TEXT NOT NULL,
    status         TEXT NOT NULL CHECK (status IN ('active', 'suspended', 'deleted')),
    created_at     TIMESTAMPTZ NOT NULL,
    updated_at     TIMESTAMPTZ NOT NULL
);

-- Case-insensitive uniqueness via lower(); repositories match with lower() too.
CREATE UNIQUE INDEX users_email_key ON users (lower(email)) WHERE email IS NOT NULL;

-- ---------------------------------------------------------------------- credentials
-- Polymorphic over type (decision 12); which optional columns are set depends on it.
CREATE TABLE credentials (
    id         UUID PRIMARY KEY,                              -- UUID v7
    user_id    UUID NOT NULL REFERENCES users (id),
    type       TEXT NOT NULL CHECK (type IN ('oidc', 'email', 'totp', 'recovery', 'webauthn')),
    issuer     TEXT,                                          -- oidc: issuer URL
    subject    TEXT,                                          -- oidc: subject claim
    email      TEXT,                                          -- email identity
    secret_enc BYTEA,                                         -- totp/recovery/webauthn material,
                                                              --   KEK-encrypted or hashed (S-05)
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL
);

-- Identity key for OIDC is (iss, sub) instance-wide (S-01).
CREATE UNIQUE INDEX credentials_oidc_key ON credentials (type, issuer, subject)
    WHERE issuer IS NOT NULL AND subject IS NOT NULL;
-- One email identity per (user, email), case-insensitive.
CREATE UNIQUE INDEX credentials_email_key ON credentials (user_id, lower(email)) WHERE type = 'email';
CREATE INDEX credentials_user_idx ON credentials (user_id);

-- ----------------------------------------------------------------------------- orgs
CREATE TABLE orgs (
    id         UUID PRIMARY KEY,                              -- UUID v7
    name       TEXT NOT NULL,
    slug       TEXT NOT NULL,                                 -- virtual registry base /o/{slug}/pub
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL
);

CREATE UNIQUE INDEX orgs_slug_key ON orgs (lower(slug));

-- ---------------------------------------------------------------------- org_members
-- role_level: cumulative ladder 50/100/200/250 with gaps (decision 19); a row always means
-- membership, so 0 ("none") is banned. The ≥1-Owner invariant is transactional app logic.
CREATE TABLE org_members (
    org_id     UUID NOT NULL REFERENCES orgs (id),
    user_id    UUID NOT NULL REFERENCES users (id),
    role_level SMALLINT NOT NULL CHECK (role_level > 0 AND role_level <= 255),
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (org_id, user_id)
);

CREATE INDEX org_members_user_idx ON org_members (user_id);

-- ---------------------------------------------------------------------- invitations
-- Single-use, email-bound, expiring (7-day default), hashed token (S-06).
CREATE TABLE invitations (
    id          UUID PRIMARY KEY,                             -- UUID v7
    org_id      UUID NOT NULL REFERENCES orgs (id),
    email       TEXT NOT NULL,
    role_level  SMALLINT NOT NULL CHECK (role_level > 0 AND role_level <= 255),
    token_hash  TEXT NOT NULL,                                -- SHA-256; plaintext only in the email
    invited_by  UUID NOT NULL REFERENCES users (id),
    created_at  TIMESTAMPTZ NOT NULL,
    expires_at  TIMESTAMPTZ NOT NULL,
    accepted_at TIMESTAMPTZ,
    accepted_by UUID REFERENCES users (id),
    revoked_at  TIMESTAMPTZ
);

CREATE UNIQUE INDEX invitations_token_hash_key ON invitations (token_hash);
CREATE INDEX invitations_pending_org_idx ON invitations (org_id)
    WHERE accepted_at IS NULL AND revoked_at IS NULL;

-- ------------------------------------------------------------------------- sessions
-- Server-side half of the rotating refresh token (decision 03, S-08/S-09).
CREATE TABLE sessions (
    id                UUID PRIMARY KEY,                       -- UUID v7, JWT `sid`
    user_id           UUID NOT NULL REFERENCES users (id),
    refresh_hash      TEXT NOT NULL,                          -- SHA-256 of the current token
    prev_refresh_hash TEXT,                                   -- rotated-out hash; reuse detection
    user_agent        TEXT,
    ip                INET,
    created_at        TIMESTAMPTZ NOT NULL,                   -- anchor of the absolute cap
    last_seen_at      TIMESTAMPTZ NOT NULL,                   -- anchor of the idle window
    revoked_at        TIMESTAMPTZ                             -- durable revocation truth (S-09)
);

CREATE UNIQUE INDEX sessions_refresh_hash_key ON sessions (refresh_hash);
-- Reuse detection: lookups by rotated-out hash (S-08).
CREATE INDEX sessions_prev_hash_idx ON sessions (prev_refresh_hash) WHERE prev_refresh_hash IS NOT NULL;
-- Active-session lookups: session list UI, revoke-all.
CREATE INDEX sessions_active_user_idx ON sessions (user_id) WHERE revoked_at IS NULL;

-- --------------------------------------------------------------------------- tokens
-- CLI/API credential plane (decision 13, S-13): SHA-256 at rest, org-bound, scoped.
CREATE TABLE tokens (
    id               UUID PRIMARY KEY,                        -- UUID v7
    user_id          UUID NOT NULL REFERENCES users (id),
    org_id           UUID NOT NULL REFERENCES orgs (id),
    name             TEXT NOT NULL,
    token_hash       TEXT NOT NULL,                           -- SHA-256; plaintext shown once
    display_hint     TEXT NOT NULL,                           -- first 8 chars, list UI
    scopes           JSONB NOT NULL,                          -- array: read|publish|retract|admin
    package_patterns JSONB NOT NULL,                          -- array; [] = no narrowing
    created_at       TIMESTAMPTZ NOT NULL,
    expires_at       TIMESTAMPTZ,                             -- NULL = non-expiring (read-only tokens)
    last_used_at     TIMESTAMPTZ,                             -- write-throttled (S-13)
    last_used_ip     INET,
    revoked_at       TIMESTAMPTZ
);

CREATE UNIQUE INDEX tokens_hash_key ON tokens (token_hash);
-- The auth hot path: active-token lookup by hash.
CREATE INDEX tokens_active_hash_idx ON tokens (token_hash) WHERE revoked_at IS NULL;
CREATE INDEX tokens_user_idx ON tokens (user_id);
CREATE INDEX tokens_org_idx ON tokens (org_id);

-- ------------------------------------------------------------------------ audit_log
-- Append-only (S-22). No foreign keys: audit rows must outlive every referenced entity.
CREATE TABLE audit_log (
    id         TEXT PRIMARY KEY,                              -- ULID; newest-first cursor key
    created_at TIMESTAMPTZ NOT NULL,
    actor_type TEXT NOT NULL CHECK (actor_type IN ('user', 'token', 'system')),
    actor_id   TEXT,                                          -- NULL for system
    ip         INET,
    user_agent TEXT,
    org_id     UUID,
    action     TEXT NOT NULL,                                 -- dot-namespaced: org.member.add
    target     TEXT,
    result     TEXT NOT NULL CHECK (result IN ('success', 'failure')),
    metadata   JSONB                                          -- before/after context
);

-- Keyset pagination is `ORDER BY id DESC`; these serve the filter combinations.
CREATE INDEX audit_org_idx ON audit_log (org_id, id);
CREATE INDEX audit_action_idx ON audit_log (action, id);
CREATE INDEX audit_created_idx ON audit_log (created_at);

-- S-22 defense in depth: the audit log is INSERT-only at the database level. Roles are
-- cluster-global and environment-specific, so role management happens at deploy time — the
-- statements below are a *template*, deliberately not executed by this migration. Run them
-- (adapted) when provisioning the application role; once the app connects as that role,
-- UPDATE/DELETE on audit_log fails at the DB even if application code regresses. The
-- repository layer independently exposes no mutating operations.
--
--   CREATE ROLE pub_app LOGIN PASSWORD :'app_password';
--   GRANT CONNECT ON DATABASE pub TO pub_app;
--   GRANT USAGE ON SCHEMA public TO pub_app;
--   GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO pub_app;
--   -- audit_log is the exception: reads and appends only.
--   REVOKE UPDATE, DELETE, TRUNCATE ON audit_log FROM pub_app;

-- ------------------------------------------------------------------------- settings
-- Runtime-changeable key → JSON (decision 09). Per-key version bumps on every upsert; the
-- instance version (reconciliation poll) is SUM(version) — a monotonic change counter.
CREATE TABLE settings (
    key        TEXT PRIMARY KEY,
    value      JSONB NOT NULL,
    version    BIGINT NOT NULL DEFAULT 1,
    updated_at TIMESTAMPTZ NOT NULL
);
