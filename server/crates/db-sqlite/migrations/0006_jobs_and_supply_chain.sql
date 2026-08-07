-- 0006_jobs_and_supply_chain (sqlite): durable background-job state plus the two supply-chain
-- registers the mirror worker and the proxy write into (decision 07 second half, S-17/S-19).
--
-- Why these three tables arrive together: they are the mirror worker's whole persistence
-- surface. A sweep over an upstream name list has to survive a restart (`jobs.cursor`), a name
-- it finds that we already claim is an S-17 alarm somebody has to see (`shadowing_alarms`), and
-- an archive whose bytes disagree with their advertised hash is an S-19 refusal somebody has to
-- be able to list (`upstream_quarantine`) — until now the refusal existed only as a log line
-- and an audit row.

-- --------------------------------------------------------------------------------- jobs
-- One row per background job, keyed by the same name its JobLock uses so the lock and the
-- state can never drift apart. The cursor is opaque here on purpose: interpreting it would put
-- job logic into the schema, and every job resumes from something different (a package name,
-- an upstream page token, a timestamp).
--
-- Counters are added to, never written: a run reports deltas, so two checkpoints in one run
-- cannot lose each other's work and a crash leaves partial progress recorded.
CREATE TABLE jobs (
    name            TEXT NOT NULL PRIMARY KEY,     -- also the JobLock key
    cursor          TEXT,                          -- resume point; NULL = from the beginning
    phase           TEXT NOT NULL DEFAULT '',      -- job-defined stage the cursor belongs to
    last_run_at     TEXT,                          -- RFC3339 UTC
    last_success_at TEXT,                          -- the freshness an operator watches
    last_error      TEXT,                          -- cleared by the next success
    runs            INTEGER NOT NULL DEFAULT 0,
    processed       INTEGER NOT NULL DEFAULT 0,
    failures        INTEGER NOT NULL DEFAULT 0,
    updated_at      TEXT NOT NULL
) STRICT;

-- ------------------------------------------------------------------- upstream_quarantine
-- Archives refused because their bytes did not match the sha256 upstream advertised (S-19).
-- The row is evidence, never enforcement: the bytes were already refused when it is written.
--
-- Keyed by (format, name, version) rather than appended per attempt: a package under active
-- tampering is fetched by every developer on the team, and a row per attempt would bury the
-- signal the register exists to raise.
CREATE TABLE upstream_quarantine (
    format          TEXT NOT NULL,
    name            TEXT NOT NULL,
    version         TEXT NOT NULL,
    upstream        TEXT NOT NULL,                 -- upstream base URL the bytes came from
    expected_sha256 TEXT NOT NULL,                 -- what the listing advertised
    actual_sha256   TEXT NOT NULL,                 -- what arrived
    occurrences     INTEGER NOT NULL DEFAULT 1,
    first_seen_at   TEXT NOT NULL,
    last_seen_at    TEXT NOT NULL,
    PRIMARY KEY (format, name, version)
) STRICT;

-- The admin listing is "what is the proxy refusing right now", newest first.
CREATE INDEX upstream_quarantine_recent_idx ON upstream_quarantine (last_seen_at);

-- --------------------------------------------------------------------- shadowing_alarms
-- A name claimed on this instance was observed upstream (S-17). Resolution does not change —
-- local always wins (decision 01) — so this is a notification register, not a policy table.
--
-- One row per shadowed name, because the condition is about the *name*: a squatted name gains
-- versions upstream, and an alarm per version would be noise about one fact.
CREATE TABLE shadowing_alarms (
    format           TEXT NOT NULL,
    name             TEXT NOT NULL,
    org_id           TEXT NOT NULL REFERENCES orgs (id),   -- the claim holder = the audience
    upstream         TEXT NOT NULL,
    upstream_version TEXT,                                 -- highest version seen upstream
    observations     INTEGER NOT NULL DEFAULT 1,
    first_seen_at    TEXT NOT NULL,                        -- of the *current* incident
    last_seen_at     TEXT NOT NULL,
    acknowledged_at  TEXT,                                 -- NULL = active
    PRIMARY KEY (format, name)
) STRICT;

-- The org admin surface: this org's alarms, newest sighting first.
CREATE INDEX shadowing_alarms_org_idx ON shadowing_alarms (org_id, last_seen_at);
-- The instance surface: only the ones still asking for attention.
CREATE INDEX shadowing_alarms_active_idx ON shadowing_alarms (last_seen_at)
    WHERE acknowledged_at IS NULL;
