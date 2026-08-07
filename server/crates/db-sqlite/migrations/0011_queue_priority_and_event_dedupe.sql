-- 0011_queue_priority_and_event_dedupe (sqlite): what the wave-1 adversarial review found in
-- the queue and in the fan-out (decision 26's 2026-08-07 amendment). Forward-only, so 0010 and
-- 0009 are left exactly as they were applied.
--
-- Four changes, one migration because they touch the same two hot statements:
--
--   1. `job_queue.priority` — the claim was one FIFO across kinds, so a CI pipeline publishing
--      into a large org could file thousands of per-recipient broadcast rows ahead of the next
--      sign-in code and starve it past the ten-minute OTP TTL. Unrelated traffic taking sign-in
--      down instance-wide is not a tuning problem, it is a missing dimension: lower runs first,
--      interactive work at 0 and bulk at 100, ordered ahead of the id.
--   2. The claim index is replaced to match the new ORDER BY. The old one is dropped rather
--      than kept: two partial indexes over the same backlog cost every enqueue and every claim
--      a second write for a plan nothing emits any more.
--   3. Retention and depth get the indexes 0010 promised ("partial indexes matching the
--      predicates the repository emits") but did not carry. Both statements run on **every**
--      drain tick — five seconds by default — against a table that only grows, and on SQLite
--      the retention DELETE is a write statement, so its scan holds the single write lock
--      against every concurrent publish and sign-in.
--   4. `notifications.event_id` plus a partial unique index on `(user_id, event_id)`. 0009's
--      own header already claimed "one row per (recipient, event)" and nothing enforced it: a
--      fan-out that crashed between writing the recipients' rows and completing its queue item
--      re-ran and filed everybody a second copy. The constraint is stronger than the
--      transaction decision 26 originally asked for, because it also holds against a future
--      path that re-emits the same event. Nullable, so every row 0009 wrote stays valid and
--      only rows that name an emission take part.

ALTER TABLE job_queue ADD COLUMN priority INTEGER NOT NULL DEFAULT 0;

-- The claim query: runnable items of some kinds, highest priority first, then arrival order.
DROP INDEX job_queue_claim_idx;
CREATE INDEX job_queue_claim_prio_idx ON job_queue (kind, priority, run_after, id) WHERE state = 'pending';
-- Retention, which now covers every terminal state: `done` after a day, `suppressed` after an
-- hour (an unauthenticated endpoint files one per rejected sign-in, each carrying the attempted
-- address in the clear, and nothing reads them after that request), `dead` after a month.
--
-- One partial index per state rather than one on `(state, updated_at)`, for two reasons. A
-- partial index holds only the rows in its own terminal state, so `pending` and `running` rows —
-- the working set — cost nothing to index; and a shared `(state, …)` index is also the best
-- available plan for `state = 'running'`, so it would quietly take the lease reaper's scan off
-- the index built for it. The repository spells each state as a **literal** for the same reason
-- the dedupe predicate is repeated in its conflict target: neither engine can prove that a bound
-- parameter satisfies a partial index's predicate.
CREATE INDEX job_queue_retention_done_idx ON job_queue (updated_at) WHERE state = 'done';
CREATE INDEX job_queue_retention_suppressed_idx ON job_queue (updated_at) WHERE state = 'suppressed';
CREATE INDEX job_queue_retention_dead_idx ON job_queue (updated_at) WHERE state = 'dead';
-- The per-(kind, state) depth gauges, so the tick's GROUP BY is an index scan, not a heap one.
CREATE INDEX job_queue_depth_idx ON job_queue (kind, state);

ALTER TABLE notifications ADD COLUMN event_id TEXT;

-- Exactly-once fan-out. Partial, because rows that name no emission must not collide with each
-- other — and stating the predicate is also how SQLite infers the index for
-- `ON CONFLICT (user_id, event_id) WHERE event_id IS NOT NULL DO NOTHING`.
CREATE UNIQUE INDEX notifications_event_idx ON notifications (user_id, event_id) WHERE event_id IS NOT NULL;
