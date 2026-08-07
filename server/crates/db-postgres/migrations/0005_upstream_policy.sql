-- 0005_upstream_policy (postgres): the per-org upstream resolution policy (decision 01, S-16).
--
-- Decision 01 gives every org a virtual registry that resolves org-owned -> instance-public ->
-- upstream, and makes that last step *policy*: `allow` (the default) now, `delay` and
-- `allowlist` later. The column lands with the read-through proxy rather than with the later
-- modes because retrofitting a resolution policy onto orgs once the proxy is serving traffic
-- means a migration plus a behaviour change on a live path — and because `block` is the one
-- answer an air-gapped or strict-supply-chain deployment needs on day one.
--
-- A CHECK constraint rather than a native ENUM type: adding `delay`/`allowlist` later is then
-- an ALTER of the constraint instead of an ALTER TYPE that cannot run inside a transaction on
-- older servers, and the storage form stays identical to the SQLite backend's TEXT.
ALTER TABLE orgs ADD COLUMN upstream_policy TEXT NOT NULL DEFAULT 'allow'
    CHECK (upstream_policy IN ('allow', 'block'));
