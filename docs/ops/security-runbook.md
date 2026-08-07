# Security runbook

The pages [S-04.c](../security.md#1-authentication), [S-24.b](../security.md#5-audit--abuse), and [S-27](../security.md#6-secrets--configuration) each name "the deployment runbook". This is it.

## Should reads require a token? (S-04.c)

`registry.require_auth_for_read` (default `false`) decides whether public and proxied packages resolve anonymously. The security consideration is subtler than "private packages are private" — those are protected either way. It is about the **names**.

The 404 ladder makes a private-and-unreadable name byte-identical to an unknown one ([decision 05](../decisions.md#05--anonymous-read-configurable-default-allowed)). But [S-04.c](../security.md#1-authentication) measured the residue: a name **claimed on the instance** answers its 404 from two indexed reads (~0.34 ms median), while an **unclaimed** name is probed against upstream first (~219 ms median) — a ~640× separation. An unauthenticated prober can therefore decide "is this name claimed here?" for any org's private packages **by response time alone**, without a credential. The statuses already match; latency is the leak, and every uniform-latency alternative was judged worse than the leak itself (the analysis is in S-04.c).

What closes it is `registry.require_auth_for_read = true`: with nothing anonymous-readable there is no anonymous prober, and the differential is visible only to principals who already hold a credential on the instance. So:

- **If your private package *names* are sensitive** (product codenames, unannounced projects), set `registry.require_auth_for_read = true`. This is the concrete reason the flag exists.
- An org with `upstream_policy = block` has no expensive branch at all and is uniform (~0.6–0.7 ms) across claimed, unknown, and upstream-only names — but note that `block` binds to the org's *base URL*, not its members, who can still reach upstream through the public root `/pub` ([S-16.b](../security.md#4-supply-chain--registry-integrity)). The only instance-wide upstream cutoff is `upstream.enabled = false`.
- The cost of `require_auth_for_read`: anonymous consumption stops entirely, and a teammate without a configured token gets the spec-mandated 401 with the token-onboarding message instead of anonymous resolution.

## Proxy-header trust (S-24.b)

Covered in operational detail in [reverse-proxy.md](reverse-proxy.md#trust_proxy_headers-s-24ab); the requirement itself: deployments terminating TLS at a proxy **MUST** set `server.trust_proxy_headers = true` **and** ensure the proxy overwrites or appends to `X-Forwarded-For` — the server reads the **rightmost** entry, and a pass-through proxy makes trusted mode strictly worse than untrusted. Audit any proxy config change against this; it silently decides what "per-IP" means for every rate limit and every audit row.

## Rotation runbook (S-27)

### Rotating the JWT signing key

Fully supported, zero-downtime for users, via `kid` overlap ([S-07](../security.md#2-sessions--web-plane)). Verification resolves keys strictly by `kid` with the algorithm pinned to EdDSA, and the config validator refuses duplicate kids across signing and verify keys.

1. Move the current pair into the verify set and install a fresh one (`pubd generate-secrets` mints a new seed with a date-prefixed kid, so kids sort chronologically):

   ```toml
   [auth.jwt]
   kid = "20260901-3f9a1c22"            # new
   signing_key = "<new base64 seed>"

   [[auth.jwt.verify_keys]]             # previous generation, still verifying
   kid = "20260807-ab12cd34"
   key = "<old base64 seed>"
   ```

   The verify-keys array cannot be expressed through env vars — this step needs the TOML file ([install.md](install.md#configuration-where-values-come-from)).
2. Restart. New tokens are signed with the new kid; outstanding ones still verify. The startup summary prints the signing kid and every verify kid unmasked — read it and confirm both generations are listed.
3. Wait at least `auth.access_ttl_minutes` (≤ 15 by S-07). Every token signed with the old key has now expired.
4. Delete the `[[auth.jwt.verify_keys]]` entry and restart again. A token presenting the retired kid is now rejected.

Rotate on a schedule you can live with, and immediately on any suspicion the seed leaked — in the leak case, **skip the overlap** (install the new key with no verify entry): every session dies at once, which is the point.

### Rotating the OTP pepper

Supported, with a small blast radius and **no overlap slot**: the moment the new pepper is live, every outstanding OTP code is invalid (codes are HMACs under the pepper, [S-03](../security.md#1-authentication)). Codes live 10 minutes and are re-requestable, so the damage is "whoever was mid-sign-in requests a new code". Change the value, restart, done. Prefer a quiet hour anyway.

One hazard worth naming: nothing ever *errors* on a wrong pepper — sign-in just stops working, because every code verifies against material nobody holds. The `_FILE` loader trims trailing newlines precisely so `echo secret > file` cannot cause this ([S-25.a](../security.md#6-secrets--configuration)); if the pepper travels any other way (CI templating, copy-paste into TOML), make sure no stray whitespace rides along.

### The KEK cannot be rotated, today

Honestly: **KEK rotation is structurally impossible in the current build** (roadmap D27). There is one `auth.kek`, no previous-KEK slot, and no DEK layer between it and the data — S-27's "KEK rotation = DEK rewrap" describes the *intended* design, not the implemented one. The KEK seals every TOTP seed ([S-05](../security.md#1-authentication)) and the SMTP password stored via runtime settings ([S-26](../security.md#6-secrets--configuration)).

Changing the KEK therefore means: every TOTP enrollment is bricked (users fall back to recovery codes or re-enroll after an admin resets their factor), and the stored SMTP password must be re-entered. If the KEK is *known compromised*, that price is worth paying — the sealed material must be considered exposed anyway, so rotate it, force TOTP re-enrollment, and rotate the SMTP credential at the provider too. For routine hygiene, wait for the DEK layer; do not "rotate" a KEK casually. And never lose it: a restore under a different KEK has the same effect as a hostile rotation ([backup-restore.md](backup-restore.md#back-up-the-secrets-too)).

### OIDC client secrets

Boot-only config ([S-25](../security.md#6-secrets--configuration)). Create the new secret at the IdP (most support two active secrets, which is your overlap window), update `[[auth.oidc]] client_secret`, restart, then retire the old secret at the IdP. Signed-in users are unaffected; the secret is only used during code exchange.

### Infrastructure credentials

Database URL, S3 keys, Redis URL, SMTP password, upstream bearer token: all boot-only ([S-25](../security.md#6-secrets--configuration)) and held by the server for the process lifetime. Rotation is: rotate at the source (database, IAM, Redis, mail provider), update config, restart. There is no online re-read (S-25 is explicit that these never live in runtime settings); with credential systems that support dual-active credentials, create-new → restart → retire-old gives a zero-downtime rotation.

### The token prefix is not a rotation lever

Changing `auth.token_prefix` does **not** rotate anything — it *revokes everything*, unintentionally: validation strips the **configured** prefix before the checksum runs ([decision 13](../decisions.md#13--cliapi-token-format)), so every already-minted token stops validating the moment the config changes, with no grace period and no error other than 401s in every CI pipeline at once. It also forfeits the published secret-scanner regex ([decision 17](../decisions.md#17--branding-default-pub-white-label-token-prefix-pub_), [token-scanning.md](token-scanning.md)). Treat a prefix change as "revoke and re-mint every token on the instance", scheduled and announced — or better, pick the prefix once and never touch it.

## Break-glass

The controls sit on **two separate authority ladders** — the instance admin on one, org roles on the other ([decision 19](../decisions.md#19--rbac-cumulative-role-levels-with-a-single-authorize-chokepoint): an org Owner administers their org, not the instance, and the reverse holds too). Since 2026-08-07 ([S-13.a](../security.md#3-cliapi-tokens)) a single instance-admin action neutralizes a compromised account **on both planes at once** — read this section before you need it.

- **A user's own credentials**: `POST /api/v1/sessions/revoke-all` (step-up-gated) kills every session; `DELETE /api/v1/tokens/{id}` revokes a CLI token, effective everywhere within ≤ 60 s ([S-13](../security.md#3-cliapi-tokens)). Only the token's owner can revoke the token row directly.
- **Instance admin, against a compromised account — the primary lever now**: `POST /api/v1/admin/users/{id}/suspend` blocks sign-in, revokes **every session** immediately ([S-09](../security.md#2-sessions--web-plane)), **and gates the account's CLI tokens** — a suspended user's tokens stop authenticating within ≤ 60 s ([S-13.a](../security.md#3-cliapi-tokens)), because `find_active_by_hash` now answers only tokens of active users. Suspension is **reversible**: unsuspending restores the tokens (no re-mint), so it doubles as a safe "freeze while we investigate". This one action, available to any instance admin regardless of org role, is the break-glass answer for a compromised account — including a sole Owner, which is what used to have no answer.
- **In-org Admin+, role hygiene**: demoting the account (`PATCH …/members/{user_id}`) revokes its sessions *and* sweeps its org tokens whose scopes exceed the new role ([S-13.a](../security.md#3-cliapi-tokens)); removing it (`DELETE …/members/{user_id}`) revokes its sessions and **all** its tokens for that org. These are the durable follow-ups once the account is frozen — e.g. to permanently drop a departed maintainer without keeping them suspended forever.
- **Org-wide**: archiving an org (forced deletion, `DELETE /api/v1/orgs/{slug}` with `force`, Owner-only) revokes every org-bound token and every removed member's sessions, and flips every package private+unlisted — the nuclear option, and packages' claims survive it by design ([decision 06 addendum](../decisions.md#06--retract--admin-only-hard-delete-with-tombstone)).

**Recommended sequence for a confirmed compromise:** suspend the account first (instant, reversible, cuts both planes), then decide the durable disposition — reinstate after credential reset, or have an org Admin+ demote/remove the membership, or (last resort) archive the org. Suspension alone holds the line while you decide, which is the property the earlier two-ladder workaround lacked. Prefer two Owners per org anyway, so an org is never one account away from needing an instance admin.

## Responding to a shadowing alarm (S-17)

**What it means**: a package name claimed on your instance has appeared on upstream pub.dev. Your instance keeps serving the local package — "local always wins" is structural, the proxy is unreachable for claimed names ([S-16](../security.md#4-supply-chain--registry-integrity)) — so nothing is broken *yet*. The alarm exists because the situation is exactly what a dependency-confusion attack looks like from your side.

**How you learn of it**: an `upstream.shadowing` audit row, a row in the `shadowing_alarms` register, and a `security`-category notification to the claiming org's Admin+ members (emailed by default, `realtime.notification_email`). There are no admin screens over the register yet (roadmap D26) — the operator-visible trail is the audit log (`GET /api/v1/admin/audit`, or the org's notification feed). Detection needs the mirror worker for one of the two arrival orders: upstream *starting* to carry a name you already claim is only visible to a periodic sweep, because the read path never asks upstream about claimed names ([S-17.a](../security.md#4-supply-chain--registry-integrity)) — an instance that wants this signal runs `[upstream.mirror]` in `recent` or `full` mode.

**Triage**: (1) Is the upstream package yours — an intentional open-source release of the same name? Then it is expected; acknowledge and move on. (2) Is it a squat or a confusion attempt? Check its upstream publisher, versions, and contents. Your builds are structurally unaffected, but developers *outside* your registry (`PUB_HOSTED_URL` unset, a misconfigured laptop) would resolve the upstream package — that is the actual exposure. Respond by reporting the package to pub.dev if malicious, and auditing CI and dev-machine configuration for resolution paths that bypass the instance. An alarm is raised once per incident and re-raised if the condition returns after acknowledgement, so a re-fired alarm is news, not noise.

## Responding to quarantine and byte-drift (S-19)

Both come from the upstream proxy's integrity pipeline ([S-19.a](../security.md#4-supply-chain--registry-integrity)); both are containment reports, not requests for action to un-break serving — containment already happened.

- **Quarantine** (`upstream.quarantine` audit row, `upstream_quarantine` register row with an occurrence counter): upstream delivered archive bytes whose sha256 did not match what its own listing advertised. The bytes were refused *before* storage, the client got a 404, and the version remains ingestible the next time upstream answers honestly. One-off occurrences on residential-grade networks happen; a **corporate TLS-intercepting middlebox that rewrites bodies is the most common benign cause** — check whether the egress path decrypts traffic. A *climbing occurrence counter on one package* is the signal of active tampering: capture the audit rows (they carry both hashes), verify what the real pub.dev serves from an independent network, and consider `upstream.enabled = false` while investigating.
- **Byte-drift** (`upstream.drift` audit row): upstream's listing now advertises a *different* hash for a version you already cached. Your instance keeps serving the cached bytes forever — somebody's `pubspec.lock` pins that hash — and discards the new claim. Drift on a real registry should essentially never happen (published versions are immutable); it means upstream re-tarred history, or something between you and upstream is rewriting listings. Same investigation as quarantine; no local action can or should change what is served.

Like the shadowing register, these have no admin UI yet (D26): read them through the audit log.
