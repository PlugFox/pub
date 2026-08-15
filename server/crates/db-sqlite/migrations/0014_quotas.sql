-- 0014_quotas (sqlite): the per-org storage quota column, the index its usage read seeks, and
-- the index the per-actor invitation cap seeks ([decision 32], S-20.b, S-24.h). Forward-only.
--
-- ------------------------------------------------------------------ orgs.storage_quota_bytes
-- The per-org override of `registry.storage_quota_bytes`. **Nullable on purpose, and the NULL
-- is load-bearing**: three states have to be distinguishable — "no override, use the instance
-- default" (NULL), "unlimited for this org" (0, the same spelling the instance default uses)
-- and "this many bytes" (positive). `NOT NULL DEFAULT 0` would collapse the first two and
-- silently give every existing org an explicit unlimited override, which is not the same row
-- and stops following the instance default when an operator later sets one.
--
-- Writable only by an instance admin (decision 32): it is deliberately *not* part of
-- `OrgProfile`, which is what `PATCH /api/v1/orgs/{slug}` — reachable by an org Admin — writes.
ALTER TABLE orgs ADD COLUMN storage_quota_bytes INTEGER;

-- --------------------------------------------------------------------- versions_org_bytes_idx
-- The quota's usage read: the sum of `archive_size` over an org's live version rows, asked once
-- per publish (S-20.b's two checkpoints) at up to `publish_per_hour_org` per org per hour.
--
-- The statement it must make seekable is `SqlitePackageRepo::ORG_STORAGE_BYTES_SQL`, which the
-- plan test in `db-tests/tests/sqlite.rs` EXPLAINs by reading that constant rather than by
-- copying its text (roadmap D52):
--
--   SELECT COALESCE(SUM(v.archive_size), 0) FROM versions v
--     JOIN packages p ON p.id = v.package_id
--    WHERE p.org_id = ? AND v.tombstone = 0
--
-- Two seeks, no table row read on either side: `packages_org_idx (org_id, name, id)` (0004)
-- turns the org into a list of package ids, and this index turns each package id into that
-- package's live archive sizes. `archive_size` is in the index for exactly that reason — it is
-- the aggregated column, so including it is what keeps the scan inside the index instead of
-- fetching every version row of the org to read one integer from it.
--
-- Partial on `tombstone`, mirroring `versions_listing_idx` and `versions_sha256_idx`: a
-- tombstoned version's bytes are collectable and S-20.b does not charge for them, so the rows
-- the predicate excludes are rows the sum must never see. The predicate in the index is exactly
-- the predicate in the statement, and the statement writes `tombstone = 0` as a **literal** —
-- with it bound, SQLite cannot infer the partial index and this plans as a scan of `versions`.
CREATE INDEX versions_org_bytes_idx ON versions (package_id, archive_size)
    WHERE tombstone = 0;

-- ----------------------------------------------------------------- invitations_actor_created_idx
-- The per-actor half of the S-24.h invitation cap, the sibling of `invitations_org_created_idx`
-- (0008) which serves the per-org half. The statement it must make seekable is
-- `OrgRepo::count_invitations_since_by_actor`:
--
--   SELECT COUNT(*) FROM invitations WHERE org_id = ? AND invited_by = ? AND created_at >= ?
--
-- The seek is bounded by `invited_by =` and `created_at >=`; `org_id` stays a residual filter on
-- the rows the seek returns, and that is the deliberate shape decision 32 names. The column
-- order is what makes the rolling window a range rather than a filter: `(created_at,
-- invited_by)` would have to read every invitation sent on the instance in the last day. One
-- actor's invitations across all orgs inside a 24-hour window is a handful of rows, so the
-- residual `org_id` test costs nothing measurable — where a third column would cost a wider
-- index on every invitation write.
CREATE INDEX invitations_actor_created_idx ON invitations (invited_by, created_at);
