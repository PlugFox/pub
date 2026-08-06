-- 0001_init (postgres): skeleton schema marker.
-- Real domain tables land in later roadmap steps; this migration only proves the
-- migration pipeline end-to-end. Postgres idioms per docs/rules/migrations.md:
-- TIMESTAMPTZ timestamps (INET/JSONB/partial indexes arrive with the real schema).
CREATE TABLE schema_meta (
    key        TEXT NOT NULL PRIMARY KEY,
    value      TEXT NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
