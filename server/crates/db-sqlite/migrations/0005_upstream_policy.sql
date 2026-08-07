-- 0005_upstream_policy (sqlite): the per-org upstream resolution policy (decision 01, S-16).
--
-- Decision 01 gives every org a virtual registry that resolves org-owned -> instance-public ->
-- upstream, and makes that last step *policy*: `allow` (the default) now, `delay` and
-- `allowlist` later. The column lands with the read-through proxy rather than with the later
-- modes because retrofitting a resolution policy onto orgs once the proxy is serving traffic
-- means a migration plus a behaviour change on a live path — and because `block` is the one
-- answer an air-gapped or strict-supply-chain deployment needs on day one.
--
-- Existing rows default to 'allow': the proxy is off instance-wide unless `[upstream].enabled`
-- says otherwise, so this default cannot start proxying for anybody by itself.
ALTER TABLE orgs ADD COLUMN upstream_policy TEXT NOT NULL DEFAULT 'allow'
    CHECK (upstream_policy IN ('allow', 'block'));
