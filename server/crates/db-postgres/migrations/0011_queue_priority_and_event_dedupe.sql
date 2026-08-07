-- 0011_queue_priority_and_event_dedupe (postgres): logically identical to the sqlite migration
-- of the same number; see it for why each of the four changes exists (queue priority, the
-- replaced claim index, the retention and depth indexes, and the exactly-once fan-out
-- constraint). Forward-only: 0009 and 0010 are left exactly as they were applied.
--
-- Dialect notes: INTEGER priority and TEXT event_id (an event id is a 26-character ULID, not a
-- UUID — see core::event::EventId), and `IF EXISTS` on the dropped index for the same reason
-- every other statement here is idempotent-friendly: a migration that has to be re-pointed at a
-- partially migrated database should fail on data, never on an index name.

ALTER TABLE job_queue ADD COLUMN priority INTEGER NOT NULL DEFAULT 0;

-- The claim query: runnable items of some kinds, highest priority first, then arrival order.
DROP INDEX IF EXISTS job_queue_claim_idx;
CREATE INDEX job_queue_claim_prio_idx ON job_queue (kind, priority, run_after, id) WHERE state = 'pending';
-- Retention, which now covers every terminal state (done / suppressed / dead, each with its own
-- cutoff). One partial index per state rather than one on `(state, updated_at)`: see the sqlite
-- sibling for why (the working set stays unindexed, and the lease reaper keeps its own plan).
CREATE INDEX job_queue_retention_done_idx ON job_queue (updated_at) WHERE state = 'done';
CREATE INDEX job_queue_retention_suppressed_idx ON job_queue (updated_at) WHERE state = 'suppressed';
CREATE INDEX job_queue_retention_dead_idx ON job_queue (updated_at) WHERE state = 'dead';
-- The per-(kind, state) depth gauges, so the tick's GROUP BY is an index-only aggregate.
CREATE INDEX job_queue_depth_idx ON job_queue (kind, state);

ALTER TABLE notifications ADD COLUMN event_id TEXT;

-- Exactly-once fan-out. Partial, because rows that name no emission must not collide with each
-- other — and the predicate is what lets
-- `ON CONFLICT (user_id, event_id) WHERE event_id IS NOT NULL DO NOTHING` infer this index.
CREATE UNIQUE INDEX notifications_event_idx ON notifications (user_id, event_id) WHERE event_id IS NOT NULL;
