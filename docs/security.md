# Security Requirements

Corporate-grade posture. Self-assessment framework: **OWASP ASVS L2**; authenticator policy aligned with **NIST SP 800-63B rev4**; OAuth per **RFC 9700** (OAuth 2.0 Security BCP). This document is normative for implementation and review; requirement IDs (S-xx) are referenced from tests.

## 1. Authentication

**S-01 OIDC** (Google preset or any configured issuer; confidential client, code exchange server-side only): `state` ≥128-bit single-use, bound to the initiating browser via a short-lived `__Host-` pre-auth cookie (the redirect traverses full-page navigation; this cookie is a flow binder, never an API credential); PKCE S256; `nonce` verified in `id_token`; exact-match redirect URI; `id_token` validation — signature against Google JWKS by `kid` (alg pinned to RS256), `iss`/`aud`/`exp`/`iat` with small skew. Identity key is `(iss, sub)`, never email. Trust email only when `email_verified=true`.

**S-02 Account linking**: auto-link OIDC identity to an existing account only if both sides have verified the same email; an unverified identity can never claim an existing account; linking writes an audit event and notifies the user by email.

**S-03 Email OTP** (primary single factor — it is *not* MFA and is never presented as such): 8-digit CSPRNG code; stored as HMAC-SHA-256 with server pepper; expiry 10 min; single-use; invalidated by successful use *and* by issuing a replacement; ≤5 wrong attempts per code then the code dies (never the account); resend ≥60 s apart, ≤5/hour per email, per-IP caps; verification bound to the server-side pending-auth record created at request time (opaque one-time id held by the client), so a phished code cannot be redeemed from elsewhere.

**S-04 Anti-enumeration** (login, OTP request, signup, invitations, password-reset-like flows): uniform responses and near-identical timing whether or not the account exists. On the pub protocol the ladder is visibility-first: any package the principal cannot read (another org's private, unknown name) returns **404 — for anonymous and authenticated principals alike**; a 403-vs-404 differential would let account holders enumerate private names. 401/403 semantics per S-14; the full normative ladder incl. `require_auth_for_read` mode lives in [decision 05](decisions.md#05--anonymous-read-configurable-default-allowed).

**S-05 TOTP second factor**: RFC 6238, 160-bit seed, ±1 step skew, last-accepted-counter stored to reject replays; seed encrypted at rest (AES-GCM with env KEK); 8–10 single-use recovery codes hashed with argon2id, shown once. ≤5 failed TOTP/recovery-code/step-up verifications per pending attempt, then exponential backoff on the MFA step only — audit-logged as throttle trips (see S-24).

**S-06 Step-up ("sudo mode")**: fresh second-factor (or re-auth) within a short window required for: disabling 2FA, changing email, creating `publish`/`admin` tokens, sending invitations, granting or changing member roles at Write level or above, version retraction, hard delete, org deletion, transferring ownership. (Without gating invitations/role grants, a stolen admin session could invite an attacker account and escalate around the CLI-token publish boundary.) Invitations default to the `Read` role — least privilege.

## 2. Sessions & web plane

**S-07** Access JWT: TTL ≤15 min; Ed25519 with `kid`; claims limited to `sub`, `sid`, org role levels, timestamps. No other PII in claims. Verification pins the algorithm to EdDSA, resolves keys strictly by `kid` from the boot keyring, rejects `none`/unknown algorithms and retired kids, and enforces `exp`/`iat` with small skew.
**S-08** Refresh token: opaque ≥128-bit CSPRNG, stored hashed (SHA-256), rotated on every refresh; reuse of a rotated-out token revokes the session family. The refresh endpoint validates the durable session row in the DB on **every** call: not revoked (`revoked_at`), within idle timeout (default 30 d sliding) and absolute cap (default 90 d). Client-side the refresh token lives in localStorage; its theft-bound is rotation + reuse detection + these caps (decision 03 consequences).
**S-09** Revocation: durable truth is `sessions.revoked_at` in the DB. The revoked-`sid` set (TTL = access TTL) in KV is only the fast path for access-JWT checks on every authenticated request; its keyspace must not evict early (`noeviction` or a dedicated non-evicting store), and when the KV check is unavailable it **fails closed** (reject or force refresh, which hits the DB). Logout revokes the current session (`sid`); the explicit revoke-all action and **any permission or role change** revoke all the user's sessions. Multi-instance coherence is guaranteed by the Redis requirement ([decision 03](decisions.md#03--sessions-jwt-access--refresh-sessions-kv-backed-revocation)); with the in-memory KV a restart clears the blocklist for up to one access TTL — accepted, documented single-node risk.
**S-10** Session hygiene: session list UI (created, last-seen throttled, IP, coarse UA, current flag, revoke one/all); idle timeout and absolute cap configurable per instance.
**S-11** XSS compensation for localStorage tokens: strict CSP (`script-src 'self'` + nonce for the single inline theme script, no `unsafe-inline`), backend-sanitized README HTML (ammonia whitelist; links `rel="nofollow ugc noopener"`; `img-src` restricted), publishing rights reserved to CLI tokens so a stolen web session cannot publish.
**S-12** CORS locked to the instance origin; state-changing JSON endpoints require a custom header and reject non-JSON content types; `Origin`/`Sec-Fetch-Site` verified server-side.

## 3. CLI/API tokens

**S-13** Format `<prefix>_<base62×30><crc32-base62×6>` (default prefix `pub_`, instance-configurable per decision 17); SHA-256 at rest + first-8 display hint; show-once. Scopes `read`/`publish`/`retract`/`admin`, org-bound, optional package patterns; default expiry 90 days (unlimited allowed only for `read`); last-used/last-IP write-throttled tracking; revocation effective within ≤60 s (no server-side token caching beyond that); per-token rate limits.
**S-14** 401 vs 403 discipline on pub routes: **both** statuses carry `WWW-Authenticate: Bearer realm="pub", message="<actionable text>"` — the client surfaces the message in the CLI on 401 *and* 403, and it is our only messaging channel there (how to get a token / how to request access). 401 **only** for absent/invalid tokens (the client deletes its stored token on 401); 403 only for valid-but-insufficient scope/role on a resource the principal can see; unreadable resources are 404 per S-04.
**S-15** Secret-scanning support: published token regex + checksum algorithm in docs; gitleaks rule shipped; GitHub Secret Scanning partner registration later.

## 4. Supply chain & registry integrity

**S-16** Deterministic resolution: local (claimed) names always win over upstream; resolution never chooses by version across sources; per-org upstream policy (`allow` now, `delay`/`allowlist` later).
**S-17** Shadowing alarm: if a locally-claimed name appears upstream, keep serving local and alert org admins + audit.
**S-18** Immutability: versions immutable, numbers never reused (tombstones survive hard delete); archives byte-stable forever; blob store is content-addressed by sha256.
**S-19** Proxy integrity: verify upstream `archive_sha256` at ingest; re-verify from own store on serve; upstream byte-drift for a known version ⇒ serve cached, alert, quarantine the discrepancy.
**S-20** Ingest hardening: archive size cap (100 MB default, configurable), safe tar extraction (reject path escapes, duplicate entries; skip external symlink/hardlink targets), pubspec must parse and match name/version; configurable per-org storage quota enforced at publish.
**S-21** Provenance-lite: record publisher identity, token id, and CI metadata per version; surfaced in UI and audit. (Sigstore/SLSA attestations: later.)

## 5. Audit & abuse

**S-22** Append-only audit log: INSERT-only DB role; events — auth success/failure per method, MFA enroll/disable, throttle trips (incl. invitation throttles), session/token lifecycle, publish/retract/hard-delete, package settings, org/membership/invitation changes, admin settings changes, proxy policy changes, shadowing alarms, data-export requests, account-deletion requests/completions. Record: ULID, ts, actor (user|token|system), IP, UA, org, dot-namespaced action, target, result, metadata (before/after). Never log secrets, full tokens, or OTP codes.
**S-23** Retention: auth events 12 mo, admin/role changes 24 mo, publish events = package lifetime; cursor-paginated JSON export.
**S-24** Rate limiting (KV-backed, per-IP / per-account / per-token / per-org): OTP request 5/h/email + 20/h/IP; OTP verify 5/code; TOTP/recovery/step-up verify ≤5 failures then exponential backoff (per S-05); login 10/min/IP; token-auth failures 30/min/IP then tarpit; publish 30/h/org; invitations ≤20/day/org with per-actor caps; 429 + `Retry-After`; health checks exempt. KV-outage semantics: auth-abuse limiting fails **closed** via a per-instance in-process fallback; read-path limiting fails **open**. Anti-lockout: exponential backoff + device-cookie style trust, never account hard-lock from IP-driven failures; notify users on failure bursts.

## 6. Secrets & configuration

**S-25** Boot-only via env/CLI/mounted files (never DB, never admin-editable): DB URL, blob credentials, Redis URL, JWT signing keyring, OTP/HMAC pepper, KEK, OIDC client secret, public base URL. `_FILE`-suffixed env supported; secrets masked in the startup config summary and never logged.
**S-26** Runtime settings in DB with sensitive values (SMTP password) envelope-encrypted with the env KEK.
**S-27** Rotation: signing keyring rotates via `kid` overlap; KEK rotation = DEK rewrap; documented rotation runbook; admin break-glass "revoke all tokens/sessions for user/org".

## 7. Platform

**S-28** Transport & headers: HSTS, strict CSP, `X-Content-Type-Options`, frame-ancestors none (except docs if embedded), cookieless API responses marked no-store where sensitive.
**S-29** Compliance surface: account deletion erases profile, keeps anonymized publish-history tombstone (supply-chain integrity, same stance as npm/crates.io); data export endpoint; `/.well-known/security.txt` + disclosure page.
**S-30** Dependencies: `cargo audit` in CI with documented ignore justifications; `default-features = false` discipline with inline rationale (foxic convention); frontend lockfile audit.
**S-31** Sign-in domain policy: an instance-level allowlist of email domains (e.g. `corp.com`) enforced uniformly across every auth path — OIDC (verified email), email OTP, invitations — evaluated server-side at sign-in, registration, and invite time; changes are admin-only and audited; rejection responses stay anti-enumeration-uniform (S-04).
**S-32** SSE event stream: authenticated with the same access-JWT validation as REST (including the revoked-`sid` fast path); streams re-check revocation on heartbeat and terminate within one access TTL of session revocation; per-user concurrent-connection cap; events are authorization-filtered — a principal receives only events for orgs/resources they can read.
**S-33** Outbound webhooks: URLs validated against SSRF — public DNS/IP only (block loopback, RFC-1918, link-local, cloud-metadata ranges), re-checked after DNS resolution at delivery time; HTTPS required by default; payloads signed HMAC-SHA256 with a per-endpoint secret (encrypted at rest with the env KEK, shown once) and carry event data only, never credentials; capped exponential-backoff retries with a dead-letter state; delivery attempts logged (endpoint, status, duration) without response bodies.
