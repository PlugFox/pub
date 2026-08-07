-- 0009_notifications (sqlite): the notification center (decision 20).
--
-- Two tables:
--   * notifications         — the per-user feed the SSE stream announces. One row per
--     (recipient, event): fan-out happens at write time, so a read is one indexed scan and a
--     later membership change cannot retroactively reveal or hide a row somebody already has.
--   * notification_prefs    — per-category delivery preferences. Absent rows mean "the
--     default", which is what lets a category added by a later release behave correctly for
--     accounts that predate it (see core::notification::NotificationPreferences).
--
-- SQLite idioms (docs/rules/migrations.md): STRICT tables, TEXT UUID v7 ids, TEXT RFC3339 UTC
-- timestamps, CHECKed INTEGER booleans, partial index for the unread predicate.

CREATE TABLE notifications (
    id         TEXT NOT NULL PRIMARY KEY,                 -- UUID v7: time-ordered, the cursor
    user_id    TEXT NOT NULL REFERENCES users (id),
    category   TEXT NOT NULL CHECK (category IN ('package', 'org', 'security')),
    event      TEXT NOT NULL,                             -- dot-namespaced event name
    title      TEXT NOT NULL,
    -- No foreign key, deliberately, and for the same reason audit_log.org_id has none: a
    -- notification is a record of something that happened, and it has to stay readable after
    -- the organization it happened in is erased ("you were removed from acme" outliving acme
    -- is the point). An FK would also make erasing an org fail on somebody's feed.
    org_id     TEXT,                                     -- NULL for instance-scoped events
    payload    TEXT NOT NULL,                             -- the event document, verbatim
    created_at TEXT NOT NULL,
    read_at    TEXT
) STRICT;

-- The feed: newest first inside one account. The id is UUID v7, so ordering by it is ordering
-- by time and pagination needs no second column.
CREATE INDEX notifications_feed_idx ON notifications (user_id, id DESC);
-- The unread badge and the unread-only feed run against the partial index rather than
-- filtering the whole history.
CREATE INDEX notifications_unread_idx ON notifications (user_id, id DESC) WHERE read_at IS NULL;

CREATE TABLE notification_prefs (
    user_id    TEXT NOT NULL REFERENCES users (id),
    category   TEXT NOT NULL CHECK (category IN ('package', 'org', 'security')),
    in_app     INTEGER NOT NULL CHECK (in_app IN (0, 1)),
    email      INTEGER NOT NULL CHECK (email IN (0, 1)),
    updated_at TEXT NOT NULL,
    PRIMARY KEY (user_id, category)
) STRICT;
