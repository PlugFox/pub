-- 0008_management (postgres): the management and administration surface. Logically identical
-- to the sqlite migration of the same number; see it for the rationale behind each column.
--
-- Dialect notes: BOOLEAN instead of a CHECKed INTEGER, TIMESTAMPTZ instead of RFC3339 TEXT,
-- and partial indexes matching the predicates the repositories actually emit.

ALTER TABLE users ADD COLUMN is_instance_admin BOOLEAN NOT NULL DEFAULT FALSE;

-- The bootstrap check ("does this instance have an admin yet?") and the admin filter both run
-- against this partial index rather than a full table scan.
CREATE INDEX users_instance_admin_idx ON users (id) WHERE is_instance_admin;

-- Admin listing ordering/filtering: newest account first, optionally narrowed by status.
CREATE INDEX users_status_idx ON users (status, id);

ALTER TABLE orgs ADD COLUMN description TEXT NOT NULL DEFAULT '';
ALTER TABLE orgs ADD COLUMN archived_at TIMESTAMPTZ;

-- The admin org table pages over the slug; lower() matches the case-insensitive unique index.
CREATE INDEX orgs_slug_page_idx ON orgs (lower(slug), id);

-- Membership listing: highest role first inside one org.
CREATE INDEX org_members_org_role_idx ON org_members (org_id, role_level DESC);

-- The `invite`-only registration gate looks up redeemable invitations by email (S-31), and the
-- S-24 per-org invitation budget counts them by (org, created_at).
CREATE INDEX invitations_email_idx ON invitations (lower(email))
    WHERE accepted_at IS NULL AND revoked_at IS NULL;
CREATE INDEX invitations_org_created_idx ON invitations (org_id, created_at);
