-- 0001_init (sqlite): skeleton schema marker.
-- Real domain tables land in later roadmap steps; this migration only proves the
-- migration pipeline end-to-end. SQLite idioms per docs/rules/migrations.md:
-- STRICT tables, TEXT RFC3339 timestamps, single-writer assumptions documented
-- in the crate docs.
CREATE TABLE schema_meta (
    key        TEXT NOT NULL PRIMARY KEY,
    value      TEXT NOT NULL,
    updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
) STRICT;
