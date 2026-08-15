-- 0015_register_pages (sqlite): the indexes the two supply-chain registers' keyset walks and
-- their new retention deletes seek ([decision 33], S-17.b, S-19.b, S-23.b). Forward-only.
--
-- Nothing here changes a table. Both registers gained an operator surface that pages through
-- them and a retention window that deletes from them, and 0006 indexed each on `last_seen_at`
-- alone — enough for "the newest twenty rows", not for either new statement.
--
-- **Why the whole key is in the index, not just the timestamp.** A keyset walk resumes at the
-- last row it returned, so its ORDER BY has to be a *total* order; `last_seen_at` is not one on
-- either table. One mirror sweep stamps every alarm it raises with the same instant, and a
-- tampering incident across a package's versions writes a block of quarantine rows inside one
-- fetch loop — ties are the normal shape here, not the edge case. With the timestamp alone in
-- the index the tie-break columns are a post-filter over an unbounded run of equal timestamps.
--
-- **Why every column is DESC.** The listings are newest-first and the tie-breaks ride along in
-- the same direction, so the statement's ORDER BY is uniformly descending and the seek predicate
-- is one row-value comparison. An index can serve an ORDER BY only when its direction pattern
-- matches the statement's or is its exact mirror; a mixed `last_seen_at DESC, name ASC` would
-- match neither of these and would sort. The plan tests in `db-tests/tests/sqlite.rs` assert the
-- seek's usable columns for the statement the repository emits — they read the SQL from the
-- repository rather than copying it (roadmap D52).

-- ------------------------------------------------------------------ upstream_quarantine_page_idx
-- `GET /api/v1/admin/quarantine` (S-19.b) and the `retain_quarantine_days` delete (S-23.b),
-- which seeks the `last_seen_at` prefix of this same index.
DROP INDEX IF EXISTS upstream_quarantine_recent_idx;
CREATE INDEX upstream_quarantine_page_idx
    ON upstream_quarantine (last_seen_at DESC, format DESC, name DESC, version DESC);

-- ------------------------------------------------------------------- shadowing_alarms_page_idx
-- `GET /api/v1/admin/shadowing` with no filter, and the acknowledged-only slice (which has no
-- partial index of its own: `acknowledged_at IS NOT NULL` is the *large* side of the table once
-- an operator has worked through a backlog, so a partial index over it would duplicate this one).
CREATE INDEX shadowing_alarms_page_idx
    ON shadowing_alarms (last_seen_at DESC, format DESC, name DESC);

-- ----------------------------------------------------------------- shadowing_alarms_active_idx
-- The active slice keeps its partial predicate and gains the tie-break columns. This is the
-- page an operator actually opens — "what is asking for attention right now" — and the partial
-- index keeps it proportional to the alarms still open rather than to every alarm ever raised.
DROP INDEX IF EXISTS shadowing_alarms_active_idx;
CREATE INDEX shadowing_alarms_active_idx
    ON shadowing_alarms (last_seen_at DESC, format DESC, name DESC)
    WHERE acknowledged_at IS NULL;

-- -------------------------------------------------------------------- shadowing_alarms_ack_idx
-- The `retain_shadowing_days` delete (S-23.b): `acknowledged_at IS NOT NULL AND
-- acknowledged_at < ?`. Partial on the same predicate the statement carries, so an instance
-- whose alarms are all still active pays nothing for the window being switched on — and so the
-- index cannot be used by a statement that forgot the `IS NOT NULL` half, which is the half
-- that makes an **active** alarm undeletable at every window.
CREATE INDEX shadowing_alarms_ack_idx
    ON shadowing_alarms (acknowledged_at)
    WHERE acknowledged_at IS NOT NULL;
