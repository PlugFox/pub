-- 0009_notifications (postgres): the notification center (decision 20). Logically identical
-- to the sqlite migration of the same number; see it for the rationale behind each table.
--
-- Dialect notes: UUID ids, TIMESTAMPTZ, JSONB payloads, BOOLEAN instead of CHECKed INTEGER,
-- and a partial index matching the unread predicate the repository emits.

CREATE TABLE notifications (
    id         UUID PRIMARY KEY,                          -- UUID v7: time-ordered, the cursor
    user_id    UUID NOT NULL REFERENCES users (id),
    category   TEXT NOT NULL CHECK (category IN ('package', 'org', 'security')),
    event      TEXT NOT NULL,                             -- dot-namespaced event name
    title      TEXT NOT NULL,
    -- No foreign key, deliberately, and for the same reason audit_log.org_id has none: a
    -- notification is a record of something that happened, and it has to stay readable after
    -- the organization it happened in is erased. An FK would also make erasing an org fail on
    -- somebody's feed.
    org_id     UUID,                                     -- NULL for instance-scoped events
    payload    JSONB NOT NULL,                            -- the event document, verbatim
    created_at TIMESTAMPTZ NOT NULL,
    read_at    TIMESTAMPTZ
);

-- The feed: newest first inside one account. The id is UUID v7, so ordering by it is ordering
-- by time and pagination needs no second column.
CREATE INDEX notifications_feed_idx ON notifications (user_id, id DESC);
-- The unread badge and the unread-only feed run against the partial index rather than
-- filtering the whole history.
CREATE INDEX notifications_unread_idx ON notifications (user_id, id DESC) WHERE read_at IS NULL;

CREATE TABLE notification_prefs (
    user_id    UUID NOT NULL REFERENCES users (id),
    category   TEXT NOT NULL CHECK (category IN ('package', 'org', 'security')),
    in_app     BOOLEAN NOT NULL,
    email      BOOLEAN NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (user_id, category)
);
