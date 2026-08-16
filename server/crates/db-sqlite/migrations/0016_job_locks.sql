-- 0016_job_locks (sqlite): leader election that leaves the process, per decision 36.
-- Forward-only.
--
-- One row per lock name, held until `expires_at`. `token` is the acquisition that holds it —
-- a fresh UUID per `try_acquire`, compared by `release` so a holder that overran its TTL
-- cannot free the lock its successor took (the `LockToken` contract `core` already states).
--
-- SQLite deployments are single-instance by construction and take the in-process lock, so this
-- table is not on their hot path. It exists because the contract functions run against both
-- dialects: "two acquisitions of one name cannot both win" is asserted on the everyday local
-- backend as well as on the deployable one, which is how every other repository property in
-- this schema is proven (decision 36, decision 35).
--
-- Timestamps are the fixed-width RFC3339 UTC strings this schema uses everywhere, so string
-- comparison is time comparison — and they are written by the **database's** clock
-- (`strftime`), not the caller's, for the same reason the Postgres table uses `now()`.
CREATE TABLE job_locks (
    name        TEXT PRIMARY KEY,
    token       TEXT NOT NULL,
    expires_at  TEXT NOT NULL,
    acquired_at TEXT NOT NULL
) STRICT;
