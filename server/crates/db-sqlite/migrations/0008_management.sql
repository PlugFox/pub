-- 0008_management (sqlite): the management and administration surface.
--
-- Three additions, all to existing tables:
--   * users.is_instance_admin — the instance-administration plane (orthogonal to the org role
--     ladder of decision 19). Bootstrapped from a config email list or by the first account to
--     exist; see docs/decisions.md 19.
--   * orgs.description        — free text on the org profile.
--   * orgs.archived_at        — the terminal state of a *forced* org deletion. An org that owns
--     packages cannot be erased: decision 06 / S-18 keep name claims and version rows forever
--     and both hang off the org row. Archiving strips members, invitations, and tokens and
--     leaves the slug taken, which is the only outcome that deletes the organization without
--     un-burning a package name.
--
-- SQLite `ALTER TABLE ... ADD COLUMN` requires a constant default for NOT NULL columns; all
-- three are cheap metadata-only changes.

ALTER TABLE users ADD COLUMN is_instance_admin INTEGER NOT NULL DEFAULT 0
    CHECK (is_instance_admin IN (0, 1));

-- The bootstrap check ("does this instance have an admin yet?") and the admin filter both run
-- against this partial index rather than a full table scan.
CREATE INDEX users_instance_admin_idx ON users (id) WHERE is_instance_admin = 1;

-- Admin listing ordering/filtering: newest account first, optionally narrowed by status.
CREATE INDEX users_status_idx ON users (status, id);

ALTER TABLE orgs ADD COLUMN description TEXT NOT NULL DEFAULT '';
ALTER TABLE orgs ADD COLUMN archived_at TEXT;

-- The admin org table pages over the slug.
CREATE INDEX orgs_slug_page_idx ON orgs (slug, id);

-- Membership listing: highest role first inside one org.
CREATE INDEX org_members_org_role_idx ON org_members (org_id, role_level DESC);

-- The `invite`-only registration gate looks up redeemable invitations by email (S-31), and the
-- S-24 per-org invitation budget counts them by (org, created_at).
CREATE INDEX invitations_email_idx ON invitations (email) WHERE accepted_at IS NULL AND revoked_at IS NULL;
CREATE INDEX invitations_org_created_idx ON invitations (org_id, created_at);
