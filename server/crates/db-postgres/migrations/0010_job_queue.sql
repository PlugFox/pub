-- 0010_job_queue (postgres): the durable work queue (decision 26). Logically identical to the
-- sqlite migration of the same number; see it for why the table exists, why it is in the
-- database rather than behind the `Kv` seam (no key enumeration —
-- server/crates/registry/src/stats.rs:1-30), and why `state` is CHECKed while `kind` is not.
--
-- Dialect notes: UUID ids, JSONB payload, TIMESTAMPTZ instants, BIGINT attempts, and partial
-- indexes matching the predicates the repository emits. The claim here is
-- `UPDATE … WHERE id IN (SELECT … FOR UPDATE SKIP LOCKED) RETURNING`: SQLite gets exclusivity
-- from its single writer, Postgres has to ask for it. That claim is written now, before
-- multi-instance deployment exists, because retrofitting a claim strategy onto a queue that is
-- already carrying sign-in mail is a change to a live path.

CREATE TABLE job_queue (
    id           UUID PRIMARY KEY,                         -- UUID v7: arrival order = claim order
    kind         TEXT NOT NULL,                            -- dispatch key, deliberately unconstrained
    payload      JSONB NOT NULL,                           -- the handler's document (sealed for mail)
    state        TEXT NOT NULL CHECK (state IN ('pending', 'running', 'done', 'dead', 'suppressed')),
    attempts     BIGINT NOT NULL DEFAULT 0,                -- spent at claim time, never refunded
    run_after    TIMESTAMPTZ NOT NULL,                     -- backoff / deliberately delayed enqueue
    locked_until TIMESTAMPTZ,                              -- lease deadline; NULL unless running
    dedupe_key   TEXT,                                     -- idempotency key, one namespace for all kinds
    last_error   TEXT,
    created_at   TIMESTAMPTZ NOT NULL,
    updated_at   TIMESTAMPTZ NOT NULL
);

-- The claim query: runnable items of some kinds, oldest first. Partial on the state the claim
-- filters by, so the index holds the backlog rather than the history.
CREATE INDEX job_queue_claim_idx ON job_queue (kind, run_after, id) WHERE state = 'pending';
-- The lease reaper's scan (items whose worker died mid-run).
CREATE INDEX job_queue_lease_idx ON job_queue (locked_until) WHERE state = 'running';
-- Idempotency: a retried enqueue under a key already present is a no-op, not a second copy.
-- The predicate is what lets `ON CONFLICT (dedupe_key) WHERE dedupe_key IS NOT NULL` infer
-- this index.
CREATE UNIQUE INDEX job_queue_dedupe_idx ON job_queue (dedupe_key) WHERE dedupe_key IS NOT NULL;
