-- 0012_retention (postgres): the indexes S-23 retention seeks on, plus the one privileged
-- primitive it needs — a `SECURITY DEFINER` prune that lets the app role delete old audit rows
-- without ever holding `DELETE` on `audit_log` ([decision 30], [S-22.a]). Forward-only.
--
-- The problem this solves, stated plainly. 0002 ships a documented, deliberately unexecuted
-- provisioning template whose last line is
--
--     REVOKE UPDATE, DELETE, TRUNCATE ON audit_log FROM pub_app;
--
-- because S-22 wants the audit log to be INSERT-only at the database even if application code
-- regresses. S-23 retention needs a delete on exactly that table. The two obvious resolutions
-- both give something real away: granting the app role `DELETE ON audit_log` hands a code
-- regression or an injection precisely the *recent* rows an attacker wants gone, and moving
-- retention out of process means a default install grows forever, which is the outcome the
-- owner's constraint on this feature rules out.
--
-- So the app role gets a capability instead of a privilege. `pub_audit_prune` runs as its owner
-- (the migration role, which does hold DELETE), it can only delete rows older than 30 days, and
-- it can only delete `batch` of them per call. The reachable capability is therefore "delete
-- audit rows older than a month, in bounded batches" — not "delete audit rows" — and the REVOKE
-- in 0002 stands unchanged. 0002 is not edited: its template is still correct, and a migration
-- that has already been applied is not the place to add a line.
--
-- Three hardening details, none optional:
--
--   * `SECURITY DEFINER` needs BOTH a pinned `search_path` AND schema-qualified table references,
--     and the pin alone is not enough — which is worth stating flatly, because an earlier version of
--     this comment claimed it was. Postgres searches an implicit `pg_temp` FIRST for relation names
--     unless `pg_temp` appears in `search_path` explicitly, so `SET search_path = pg_catalog, public`
--     left a caller free to `CREATE TEMP TABLE audit_log (...)` and have this function delete from
--     *that* instead: the prune returns a plausible row count, the lifecycle job records a converged
--     sweep, and the real audit log grows forever while every signal says retention is working. The
--     direction is fail-safe for S-22 (evidence is preserved, not destroyed) and it is not an
--     escalation route — the app role holds `USAGE` and not `CREATE` on the schema, so it has
--     nowhere to put a trigger function, and a rule's actions are permission-checked against the
--     rule's owner rather than the definer. It is still a silent no-op on the one job whose whole
--     promise is that it is never silent. Both defences are in place below: `pg_temp` is demoted to
--     last, and every reference is `public.`-qualified. The function therefore assumes the schema is
--     `public`, which is what the 0002 template already assumes (`GRANT USAGE ON SCHEMA public`); a
--     deployment on another schema must adapt it, and finds out at the first prune through the job's
--     refusal path rather than silently.
--   * The `batch <= 0` guard is not decoration. In Postgres `LIMIT -1` is *unbounded* — a
--     negative batch would turn the one statement whose bound is the point of this design into a
--     full-table delete holding a lock over the whole audit log. That is a failure mode nothing
--     else in this path catches.
--   * The floor is checked here **and** in Rust before the call, and the two are deliberately NOT
--     equal. Rust enforces the real floor — exactly 30 × 24 h before the `now` it was handed — and
--     this copy exists for a caller that is not this code, so it is a backstop rather than the
--     primary. A backstop set to the same instant as the primary is a bug: `INTERVAL '30 days'` is
--     *calendar* arithmetic in the session's TimeZone while `chrono::Duration::days(30)` is exactly
--     720 h, so across an autumn DST transition the interval is 721 h and the two disagree by an
--     hour in the refusing direction — and any NTP skew between the application host and the
--     database host does the same. With `retain_audit_days = 30` (a legal, validated configuration)
--     that turns into a prune that fails every pass for about a month, diagnosed by a log line
--     telling the operator to add a grant they already have. So the backstop gets a day of slack:
--     it refuses anything newer than 29 days, the application refuses anything newer than 30, and
--     the reachable capability is still bounded to "not recent" by an order of magnitude more than
--     any clock can drift.
--
-- EXECUTE is REVOKEd from PUBLIC below, and that is a deliberate reversal of the obvious default.
-- Postgres grants EXECUTE on new functions to PUBLIC, which would have meant "no operator action
-- required" — but on a shared cluster it also means every role that can reach this database holds
-- the prune capability over THIS instance's audit log. Trading an explicit grant for that is the
-- wrong trade on a security-relevant table, particularly since the missing-grant path is already
-- built and loud: the lifecycle job reports the table as refused, names this grant in the log, sets
-- `retention_refused_tables`, and keeps sweeping every other table (decision 30).
--
-- The grant itself is commented out for the same reason the rest of the role template is: roles are
-- cluster-global and environment-specific, so role management happens at deploy time. An instance
-- whose application connects as the database owner needs nothing — the owner may execute its own
-- function.
--
--   GRANT EXECUTE ON FUNCTION pub_audit_prune(TIMESTAMPTZ, INT) TO pub_app;

CREATE FUNCTION pub_audit_prune(cutoff TIMESTAMPTZ, batch INT)
RETURNS BIGINT
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public, pg_temp
AS $$
DECLARE
    deleted BIGINT;
BEGIN
    IF batch IS NULL OR batch <= 0 THEN
        RAISE EXCEPTION 'pub_audit_prune: batch must be positive (got %); a negative LIMIT is unbounded', batch;
    END IF;
    -- 29, not 30, and the slack is the point — see the floor note in the header. The application
    -- enforces 30 against its own clock; this refuses anything a clock could not plausibly explain.
    IF cutoff IS NULL OR cutoff > now() - INTERVAL '29 days' THEN
        RAISE EXCEPTION 'pub_audit_prune: refusing a cutoff newer than the 29-day backstop (got %)', cutoff;
    END IF;

    -- Schema-qualified, not bare: see the pg_temp note in the header. A bare `audit_log` here
    -- resolves through the caller's implicit temp schema first.
    DELETE FROM public.audit_log
     WHERE id IN (
        SELECT id FROM public.audit_log WHERE created_at < cutoff ORDER BY created_at LIMIT batch
     );
    GET DIAGNOSTICS deleted = ROW_COUNT;
    RETURN deleted;
END;
$$;

REVOKE EXECUTE ON FUNCTION pub_audit_prune(TIMESTAMPTZ, INT) FROM PUBLIC;

COMMENT ON FUNCTION pub_audit_prune(TIMESTAMPTZ, INT) IS
    'S-23 retention for audit_log. SECURITY DEFINER so the INSERT-only app role (S-22) can spend '
    'it without holding DELETE; refuses any cutoff newer than a 29-day backstop (the application enforces the real 30-day floor) and any non-positive batch.';

-- --------------------------------------------------------------------------- indexes
-- Every other statement the lifecycle job issues is a bounded
-- `DELETE ... WHERE id IN (SELECT id ... WHERE <age predicate> ... LIMIT :batch)`; the inner
-- SELECT is what these serve.
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
