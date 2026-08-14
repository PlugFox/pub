-- 0012_retention (sqlite): the indexes S-23 retention seeks on, per decision 30. Forward-only.
--
-- Every statement the lifecycle job issues is a bounded DELETE of the shape
-- `DELETE FROM t WHERE id IN (SELECT id FROM t WHERE <age predicate> LIMIT :batch)` — the inner
-- SELECT is what these indexes serve. Bounded matters more here than anywhere else in the
-- schema: on SQLite a DELETE holds the process's single write lock for its full duration, and a
-- scan of a table that has grown for a year is exactly the hold that turns a concurrent
-- publish-finalize or sign-in into SQLITE_BUSY rather than a wait (the failure class 0011's
-- header argues about, which 0011 addressed by shortening the scan and never by bounding the
-- statement — that half is decision 30's).
--
-- `audit_log` needs nothing: `audit_created_idx (created_at)` from 0002 already serves it.
-- `job_queue` needs nothing: 0011's three per-state partial indexes already serve it.
-- `download_stats` needs one, and the reason is at the bottom of this file.

-- Sessions age from `last_seen_at`, not from creation and not from revocation. That is the one
-- anchor that makes the predicate safe by construction — a row outside the idle window can no
-- longer authenticate, so a cutoff at or beyond `auth.refresh_idle_days` can only ever delete a
-- session that was already unusable, and a revoked row is covered by the same predicate because
-- its `last_seen_at` stops advancing. Not partial: the sweep must see revoked and live rows
-- alike, and `sessions_active_user_idx` is partial on `revoked_at IS NULL` for the opposite
-- reason.
CREATE INDEX sessions_last_seen_idx ON sessions (last_seen_at);

-- Invitations age from whenever they *settled*. Indexing the COALESCE expression rather than a
-- column is what lets the sweep seek on the same term the predicate uses: an accepted or revoked
-- invitation ages from the moment it stopped being live, an untouched one from the moment it
-- expired, and a live pending invitation is unreachable at any cutoff at or before `now` because
-- its `expires_at` is in the future. Getting that property from the predicate instead of from a
-- validator is deliberate — a one-day retention window must not be able to delete a live
-- seven-day invitation link.
CREATE INDEX invitations_settled_idx ON invitations (COALESCE(accepted_at, revoked_at, expires_at));

-- The notification feed is indexed on `(user_id, id DESC)` for reading; retention sweeps by age
-- across every account, which that index cannot serve at all.
CREATE INDEX notifications_created_idx ON notifications (created_at);

-- Retention on `download_stats` sweeps by **date across every package**, and the existing
-- `download_stats_package_date_idx (package_id, date)` cannot serve that: `date` is not its leading
-- column, so `WHERE date < ? ORDER BY date` degrades to a full scan plus a temp B-tree — inside a
-- write statement, which is the one place this schema cannot afford one. Caught by the query-plan
-- test rather than by review, which is the argument for having plan tests on statements that write.
--
-- Added even though this window ships **disabled**: the whole point of shipping it disabled is that
-- an operator may turn it on, and a first-time-enabled retention on a table with years of daily rows
-- is exactly when a missing index costs the most.
CREATE INDEX download_stats_date_idx ON download_stats (date);
