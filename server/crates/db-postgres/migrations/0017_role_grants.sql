-- 0017_role_grants (postgres): the provisioning template, corrected — a grant that reaches the
-- tables a later migration adds, plus a self-check that says so out loud when an upgrade runs
-- ([decision 37], [S-22.a], closes roadmap D64). Forward-only, and no schema change: the only
-- thing this migration adds to the database is a way to ask a question.
--
-- The defect, stated plainly. 0002 ships a documented, deliberately unexecuted provisioning
-- template for the application role, whose table grant is
--
--     GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO pub_app;
--
-- and `ON ALL TABLES` in PostgreSQL means "on all tables that exist at this instant". Nothing
-- carries that grant to an object created afterwards unless ALTER DEFAULT PRIVILEGES says so, and
-- the template never said so. A deployment provisioned once and upgraded since therefore holds no
-- privilege at all on every table migrations 0004-0016 added — job_queue, notifications, the quota
-- tables, register_pages, and job_locks. The last one is fatal rather than degrading: the lock is
-- taken on every publish and on every job tick, so the release that added it takes publishing and
-- all background work down together on exactly the deployments that followed the hardening.
--
-- 0002 is not edited — its checksum is applied on every deployment in existence — so the corrected
-- text lives here, and this file is where the template's readers are now sent.
--
-- ---------------------------------------------------------------- the corrected template
--
-- Still deliberately unexecuted, for 0002's reason: roles are cluster-global and
-- environment-specific, so role management happens at deploy time. `:app_password` is the
-- application role's password; <migration_role> is the role the migrations run as — the role
-- `database.url` names, which owns every table in this schema.
--
--   CREATE ROLE pub_app LOGIN PASSWORD :'app_password';
--   GRANT CONNECT ON DATABASE pub TO pub_app;
--   GRANT USAGE ON SCHEMA public TO pub_app;
--
--   -- (1) The objects that exist now. This is also the one-time repair for a deployment
--   -- provisioned before this migration: default privileges are not retroactive, so (2) alone
--   -- leaves every table added between provisioning and today still unreachable.
--   GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO pub_app;
--   GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO pub_app;
--
--   -- (2) And the objects that do not exist yet. Default privileges are keyed on the role that
--   -- CREATEs the object, never on the role being granted to, so <migration_role> has to be the
--   -- role that runs the migrations: naming the wrong one leaves this line silently doing nothing,
--   -- which is the same failure in a new place.
--   ALTER DEFAULT PRIVILEGES FOR ROLE <migration_role> IN SCHEMA public
--       GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO pub_app;
--   ALTER DEFAULT PRIVILEGES FOR ROLE <migration_role> IN SCHEMA public
--       GRANT USAGE, SELECT ON SEQUENCES TO pub_app;
--
--   -- (3) The exceptions, last because (1) hands back what they take away. audit_log stays
--   -- INSERT-only for the application (S-22), and retention still spends the capability rather
--   -- than the privilege (decision 30).
--   REVOKE UPDATE, DELETE, TRUNCATE ON audit_log FROM pub_app;
--   GRANT EXECUTE ON FUNCTION pub_audit_prune(TIMESTAMPTZ, INT) TO pub_app;
--
-- Three things this deliberately does not do.
--
-- **No default privileges on FUNCTIONS.** 0012 revoked EXECUTE on pub_audit_prune from PUBLIC on
-- purpose: a SECURITY DEFINER function is a capability, and capabilities are granted one at a time
-- by an operator who read what they do. A blanket default privilege over future functions would
-- hand the application every such capability this schema ever grows — the exact trade 0012 refused.
--
-- **No automatic repair.** This migration could find the roles that look provisioned and re-grant
-- to them. It does not: inferring which role is meant to be the application from the privileges it
-- happens to hold is a guess, and a wrong guess widens somebody's access without being asked. It
-- reports instead, which is the function below.
--
-- **No pretence that (2) is free.** It hands the application SELECT/INSERT/UPDATE/DELETE on every
-- table this schema will ever gain, so a future table that must be restricted the way audit_log is
-- needs its own REVOKE in the template — and, unlike today's, one that existing deployments have to
-- be told to run. The alternative is a re-grant on every upgrade, which makes every upgrade a
-- privilege operation and fails silently when it is skipped. That is the defect being fixed here.

-- ------------------------------------------------------------------- pub_role_grant_gaps
-- Which roles were granted this schema's tables at some point and have been left behind by one
-- since. INSERT is the probe because it is the one privilege the template grants on every table
-- and revokes on none: a role that can append to audit_log was provisioned against this schema,
-- and a table it cannot append to is a table it was never granted.
--
-- Owners and superusers hold their privileges implicitly, so they never appear here; neither does
-- a role that was never granted anything. A read-only reporting role that happens to hold INSERT
-- on audit_log and nothing else would be listed, which is a false positive an operator can read
-- and dismiss — the direction that costs a sentence rather than an outage.
--
-- Plain SECURITY INVOKER, and EXECUTE stays with PUBLIC: every catalog this reads is
-- world-readable already, so the function exposes nothing a caller could not assemble by hand.
CREATE FUNCTION pub_role_grant_gaps()
RETURNS TABLE (role_name TEXT, missing_tables TEXT[])
LANGUAGE sql
STABLE
SET search_path = pg_catalog, public, pg_temp
AS $$
    WITH schema_tables AS (
        SELECT c.oid, c.relname::TEXT AS name
        FROM pg_catalog.pg_class c
        JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
        WHERE n.nspname = 'public' AND c.relkind IN ('r', 'p')
    ),
    provisioned AS (
        SELECT r.oid, r.rolname::TEXT AS name
        FROM pg_catalog.pg_roles r
        WHERE NOT r.rolsuper
          AND r.rolname NOT LIKE 'pg\_%'
          AND pg_catalog.has_table_privilege(r.oid, 'public.audit_log', 'INSERT')
    )
    SELECT p.name, array_agg(t.name ORDER BY t.name)
    FROM provisioned p
    JOIN schema_tables t ON NOT pg_catalog.has_table_privilege(p.oid, t.oid, 'INSERT')
    GROUP BY p.name;
$$;

COMMENT ON FUNCTION pub_role_grant_gaps() IS
    'Roles provisioned against this schema that hold no INSERT on one or more of its tables — the '
    'signature of an app role granted before a migration added a table (decision 37, roadmap D64).';

-- The upgrade says it out loud. A migration run is the exact moment the gap opens, and a WARNING
-- here reaches both the operator running psql and the server log (sqlx logs server notices), which
-- is the difference between reading one line during an upgrade and reading `permission denied for
-- table job_locks` under the next publish.
DO $$
DECLARE
    gap RECORD;
BEGIN
    FOR gap IN SELECT * FROM pub_role_grant_gaps() LOOP
        RAISE WARNING
            'pub: role "%" can write audit_log but holds no INSERT on % other table(s) in this schema: %. '
            'The S-22 provisioning template grants ON ALL TABLES, which covers only the tables that existed '
            'when it ran. See the corrected template at the top of migration 0017_role_grants.sql; '
            'SELECT * FROM pub_role_grant_gaps() re-checks at any time.',
            gap.role_name, cardinality(gap.missing_tables), array_to_string(gap.missing_tables, ', ');
    END LOOP;
END $$;
