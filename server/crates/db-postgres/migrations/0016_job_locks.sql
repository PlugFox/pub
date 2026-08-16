-- 0016_job_locks (postgres): leader election that leaves the process, per decision 36.
-- Forward-only.
--
-- One row per lock name, held until `expires_at`. `token` is the acquisition that holds it —
-- a fresh UUID per `try_acquire`, compared by `release` so a holder that overran its TTL
-- cannot free the lock its successor took (the `LockToken` contract `core` already states).
--
-- Why a table rather than `pg_try_advisory_lock`: an advisory lock lives in the session that
-- took it, so a pooled implementation must pin one connection per *held* lock. The per-name
-- publish lock is keyed on the package, so simultaneously held locks scale with simultaneous
-- publishes, and a burst larger than the pool would deadlock the instance on its own database
-- handles; a pooled implementation that does not pin is worse still, because two acquisitions
-- landing on one session are re-entrant and both succeed. An advisory lock also has no TTL,
-- and the trait's whole ownership model is expiry.
--
-- `expires_at` is written from the **database's** clock, never the caller's: two replicas with
-- skewed clocks would be two holders, which is the failure this table exists to remove.
--
-- No index beyond the primary key on purpose. Every statement is a point lookup by name, and
-- the table's size is the number of distinct lock names an instance uses — six jobs plus the
-- packages currently being published. Expired rows are overwritten in place by the next
-- acquisition rather than swept: a sweeper would delete rows a `try_acquire` is about to reuse,
-- for a table whose steady state is a few dozen rows.
CREATE TABLE job_locks (
    name        TEXT PRIMARY KEY,
    token       UUID        NOT NULL,
    expires_at  TIMESTAMPTZ NOT NULL,
    acquired_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

COMMENT ON TABLE job_locks IS
    'Leader-election leases (decision 36). One row per lock name; `token` identifies the acquisition.';
