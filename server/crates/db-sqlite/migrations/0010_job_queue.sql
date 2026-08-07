-- 0010_job_queue (sqlite): the durable work queue (decision 26).
--
-- One row per thing to do, which is a different table from `jobs` (0006) on purpose: that one
-- holds a *cursor* per job name so a restarted sweep resumes, this one holds *work items*,
-- each with its own attempts, its own backoff and its own dead-letter state. Notification
-- fan-out and every outbound message move here so a publish finalize and a sign-in request do
-- constant work instead of ~400 queries and up to 200 blocking SMTP conversations.
--
-- Why the database and not the KV: the `Kv` seam deliberately has no key enumeration, so
-- nothing could ever find the items again to drain them. That rationale is written out in
-- server/crates/registry/src/stats.rs:1-30, which rejected a KV-backed store for the same
-- reason; it is not re-derived here.
--
-- Three column choices carry design decisions:
--   * `id` is a UUID v7, so arrival order is claim order and the claim query needs no separate
--     sequence column.
--   * `state` is CHECKed, `kind` is not. Decision 26 promises webhook delivery (S-33) lands as
--     one more kind plus one more handler, and "one more handler and a schema migration" is
--     not the promise that was made. The state ladder is the opposite case: `suppressed` rows
--     (S-04.a/S-31: a policy-rejected address files a row so both branches cost the same, and
--     it is never claimable) must not be inventable by a typo.
--   * `payload` holds the handler's own document. For `mail.send` it is a rendered message
--     body — a live credential — sealed under the boot KEK before it is written (S-26.b).
--
-- SQLite idioms (docs/rules/migrations.md): STRICT table, TEXT UUID v7 ids, TEXT RFC3339 UTC
-- timestamps (fixed width, so string comparison is time comparison), partial indexes matching
-- the predicates the repository emits. Single-writer note: the claim is an
-- `UPDATE … WHERE id IN (SELECT … LIMIT ?) RETURNING`, which is exclusive here because SQLite
-- serializes writers; the Postgres migration's sibling needs `FOR UPDATE SKIP LOCKED`.

CREATE TABLE job_queue (
    id           TEXT NOT NULL PRIMARY KEY,                -- UUID v7: arrival order = claim order
    kind         TEXT NOT NULL,                            -- dispatch key, deliberately unconstrained
    payload      TEXT NOT NULL,                            -- the handler's document (sealed for mail)
    state        TEXT NOT NULL CHECK (state IN ('pending', 'running', 'done', 'dead', 'suppressed')),
    attempts     INTEGER NOT NULL DEFAULT 0,               -- spent at claim time, never refunded
    run_after    TEXT NOT NULL,                            -- backoff / deliberately delayed enqueue
    locked_until TEXT,                                     -- lease deadline; NULL unless running
    dedupe_key   TEXT,                                     -- idempotency key, one namespace for all kinds
    last_error   TEXT,
    created_at   TEXT NOT NULL,
    updated_at   TEXT NOT NULL
) STRICT;

-- The claim query: runnable items of some kinds, oldest first. Partial on the state the claim
-- filters by, so the index holds the backlog rather than the history.
CREATE INDEX job_queue_claim_idx ON job_queue (kind, run_after, id) WHERE state = 'pending';
-- The lease reaper's scan (items whose worker died mid-run).
CREATE INDEX job_queue_lease_idx ON job_queue (locked_until) WHERE state = 'running';
-- Idempotency: a retried enqueue under a key already present is a no-op, not a second copy.
-- Partial, because most items have no key and NULLs would not collide anyway — stating the
-- predicate is what lets `ON CONFLICT (dedupe_key) WHERE dedupe_key IS NOT NULL` infer it.
CREATE UNIQUE INDEX job_queue_dedupe_idx ON job_queue (dedupe_key) WHERE dedupe_key IS NOT NULL;
