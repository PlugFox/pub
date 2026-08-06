# Architecture Decision Log

Status values: **accepted** (discussed and locked), **proposed** (recommended, not yet confirmed), **tbd**.
Decisions were made on 2026-08-06 based on the research summarized in [product.md](product.md) and the discussion with the project owner.

| #  | Decision                                                                 | Status   |
|----|--------------------------------------------------------------------------|----------|
| 01 | Per-org virtual registry URLs                                            | accepted |
| 02 | sqlx repository traits with per-backend implementation crates            | accepted |
| 03 | JWT access + refresh sessions, KV-backed revocation, Redis gates scaling | accepted |
| 04 | Single binary with embedded frontend; optional split serving later      | accepted |
| 05 | Anonymous read configurable, default allowed; 404 for private names     | accepted |
| 06 | Version immutability: retract + admin-only hard delete with tombstone   | accepted |
| 07 | Upstream proxy: read-through cache AND full-mirror sync mode            | accepted |
| 08 | 10 UI locales from day one                                              | accepted |
| 09 | Always-compiled backends, runtime config selection                      | accepted |
| 10 | Blob storage via `object_store` (fs / in-memory / S3)                   | accepted |
| 11 | Search behind a trait: PG tsvector+pg_trgm / SQLite FTS5                | accepted |
| 12 | Auth: email OTP + optional multi-provider OIDC, TOTP 2FA, domain policy | accepted |
| 13 | CLI tokens: opaque `<prefix>_<base62x30><crc32x6>`, SHA-256 at rest     | accepted |
| 14 | Frontend: Astro SSG + single Solid app island, Kobalte, hand-rolled SW  | accepted |
| 15 | i18n: YAML + codegen (foxic-style), no i18n framework dependency        | accepted |
| 16 | Errors: `thiserror` domain enums, RFC-ish envelope; no anyhow matching  | proposed |
| 17 | Branding: default name "Pub", token prefix `pub_`, white-label          | accepted |
| 18 | Ops: release model, image registry, reference orchestrator             | tbd      |
| 19 | RBAC: cumulative role levels (0/50/100/200/250), one authorize() gate   | accepted |
| 20 | Realtime: SSE event stream + notification center                        | accepted |
| 21 | Multi-format artifact space: pub first; npm, cargo later                | accepted |
| 22 | Domain event bus; webhooks + integrations on top                        | accepted |
| 23 | Monitoring exports optional (Prometheus/OTLP off by default)            | accepted |

---

## 01 — Per-org virtual registry URLs

**Context.** Pub has no npm-style scopes; package names are flat. The registry both hosts private/public packages and proxies pub.dev. Dependency confusion (private name shadowed by a public upstream package) is the primary attack class against this architecture, and the URL/namespace model cannot be changed cheaply later.

**Decision.** Each organization gets a virtual registry endpoint: `PUB_HOSTED_URL = https://<host>/o/<org>/pub`. The trailing `/pub` is the **format segment** — it reserves sibling URL space for future artifact formats (`/o/<org>/npm`, `/o/<org>/cargo`; decision 21) and cannot be retrofitted cheaply, so it exists from day one. That endpoint resolves, in deterministic priority order:

1. Packages owned by the org (private or public).
2. Public packages owned by other orgs on this instance.
3. pub.dev via the proxy pipeline — only if the name is not claimed on the instance (**local always wins**, never version-based races).

Package names are **globally unique per instance per format**: a name is claimed for an org at first publish and recorded in a claim table keyed by `(format, name)`. If a claimed name later appears upstream, the local package keeps winning and org admins are alerted (shadowing alarm). A public root endpoint per format (`https://<host>/pub`) serves only public + proxied packages for anonymous/simple use.

**Consequences.** One URL per org covers private deps, instance-public deps, and pub.dev simultaneously — no `hosted:` boilerplate per dependency. Resolution policy is enforceable per org: upstream `allow` (default) now, `delay` quarantine and `allowlist` later. Cross-org name contention exists by design (flat pub ecosystem semantics); squatting inside an instance is an admin-policy matter, with org name-prefix reservations (e.g. `acme_*` reserved at claim time, never proxied) as the planned enforcement mechanism (later tier).

**Implementation addendum (2026-08-07, pub protocol HTTP surface).** Three things the "resolution order" sentence left implicit, decided while wiring it:

- **The base is the namespace, not the principal.** Inside `/o/{org}/pub` a package owned by *another* org resolves only if it is **public** — another org's private package stays invisible **even to a principal who is a member of that other org**. Without this rule the same `PUB_HOSTED_URL` would mean a different package set per user, and a `pubspec.lock` written by one developer would stop resolving for their colleague. The public root `/pub` likewise resolves nothing private, not even the caller's own. The rule lives in `PackageRepo::resolve_in_base` (a *provided* method, like `resolve` — one policy above two SQL dialects) and is asserted by a contract function on both backends.
- **"Local always wins" is structural.** `Resolution::Unclaimed` is the only value that may ever authorize an upstream lookup, and it is produced on exactly one code path: after `lookup_claim` returned `None`. A locally claimed name therefore cannot reach the proxy no matter what a caller does with the result, and the pub-protocol handlers never call `get_by_name` on a read path at all.
- **Publishing a name another org holds answers 403, not 404** — a narrow, deliberate exception to the visibility-first ladder ([decision 05](#05--anonymous-read-configurable-default-allowed)), scoped to the *publish* verb. The caller has already proven publish authority in its own org, cross-org name contention is accepted by this decision as a design property, and the alternative — "package not found" in response to an attempt to *create* one — is actively misleading on the CLI's one messaging channel. The message names the package (which the caller supplied) and never the holding org. **Ownership is decided before existence** (corrected 2026-08-07 during the conformance review): the publish pipeline checks the claim before the duplicate-version pre-check, because answering "version 1.0.0 already exists" to a caller who does not hold the name is a version-existence oracle for somebody else's private package, spendable one publish attempt at a time. Both routes to the denial emit the same sentence, so an existing version is indistinguishable from a new one.

Publishing is refused at the public root with a 403 pointing at the org URL: a publish needs an owning org, and the root has none.

## 02 — sqlx repository traits with per-backend implementation crates

**Context.** SQLite and PostgreSQL must both be first-class (config-driven). sqlx `Any` driver loses compile-time checking and native type mapping. SeaORM 2.0 (kellnr's route) offers one migration set but is days old and takes SQL control away; the owner explicitly chose sqlx.

**Decision.** Domain repository traits (`PackageRepo`, `UserRepo`, `TokenRepo`, `SessionRepo`, `AuditRepo`, `SettingsRepo`, …) live in the `core` crate. Two implementation crates — `db-postgres` and `db-sqlite` — each with their own `migrations/` and their own SQL, compile-time checked via sqlx 0.9 (`sqlx.toml` multi-database prepare, committed `.sqlx/` for offline builds). Each backend uses its idioms: advisory locks vs single-writer locking, tsvector vs FTS5, `TIMESTAMPTZ`/`INET`/partial indexes vs SQLite equivalents. (Cross-instance signaling deliberately lives in the KV broker, not PG LISTEN/NOTIFY — see decision 03.)

**Consequences.** Some SQL is written twice; in exchange both backends are checked at compile time and free to be idiomatic. The API layer never sees sqlx types — only `core` traits and domain structs.

## 03 — Sessions: JWT access + refresh sessions, KV-backed revocation

**Context.** Web UI needs multi-instance-correct sessions. foxic's per-process moka blocklist leaks revoked sessions across instances.

**Decision.**

- **Access token**: short-lived JWT (default 10–15 min, configurable) stored in `localStorage`. Claims: `sub` (user id), `sid` (session id), org memberships as **role levels** per org (decision 19), `iat`/`exp`. Signed with **Ed25519**, keys carry `kid` for rotation.
- **Refresh token = server-side session**: opaque token, hash at rest, rotated on every refresh with **reuse detection** (presenting a rotated-out token revokes the whole session); the sessions table powers the device/session management UI. Client-side the refresh token lives in `localStorage` next to the access token. Defaults: idle timeout 30 days (sliding), absolute cap 90 days — both instance-configurable.
- **Revocation**: durable truth is `sessions.revoked_at` in the DB — the refresh endpoint always validates the session row (not revoked, within idle/absolute limits). The revoked-`sid` set with TTL (= access TTL) in the KV layer is the fast path checked on every authenticated request; its keyspace must not evict early and the check fails closed (S-09). Logout revokes the current session; the explicit revoke-all action and **any permission/role change revoke all of the user's sessions**, so stale role claims can never outlive the access TTL.
- **Scaling gate**: a Redis-compatible store **and broker** (pub/sub) is mandatory for more than one instance. With the in-memory KV backend the config validator refuses `instances > 1`. This one rule also carries rate-limit counters, publish locks, and runtime-settings invalidation — no PG LISTEN/NOTIFY needed.
- CLI/API tokens are a fully separate credential plane (see 13); cookies are not used for API auth, browser tokens are never accepted on pub endpoints.

**Alternatives considered.** The research baseline (IETF BFF guidance, OWASP) recommends server-side cookie sessions for the browser. The JWT+localStorage model was chosen deliberately by the owner: a uniform token plane across SPA/PWA, offline-friendly interceptor architecture (proven in foxic), and future split/CDN static serving without cookie-domain coupling. The rejected concerns are compensated explicitly here and in [security.md §2](security.md#2-sessions--web-plane).

**Consequences.** localStorage is XSS-readable — including the refresh token, whose theft-bound is rotation + reuse detection + idle/absolute caps rather than the 15-minute access TTL. Compensations: strict CSP (nonce for the single inline theme script, no `unsafe-inline`), backend-sanitized README HTML, and publish/retract/role-grant/token-mint actions reserved to CLI tokens or gated by step-up (S-06), so a stolen web session alone can neither publish nor silently escalate. With the in-memory KV backend (single instance) a process restart clears the blocklist for up to one access TTL — an accepted, documented single-node risk. Revocation is instance-coherent by construction otherwise.

## 04 — Single binary now, optional split later

**Decision.** The Astro build output (pre-compressed `.br`/`.gz`) and the service worker are embedded into the Rust binary (`rust-embed`); cache tiers/CSP/security headers are tower layers. `docker run` one container with SQLite + filesystem storage is a supported production minimum. The Docker image is a thin wrapper around the same binary. A split mode (static assets served by CDN/nginx separately) is planned later for large deployments; route layout must keep static assets under a clean prefix so the split stays mechanical.

## 05 — Anonymous read configurable, default allowed

**Decision.** Public and proxied packages are readable without authentication by default (pub.dev-like DX, public-instance showcase possible). An instance-level `require_auth_for_read` flag flips everything to token-only for strict corporate policies.

Status-code ladder (normative; mirrored in [S-04/S-14](security.md#1-authentication)):

1. **Visibility first**: any package the principal cannot read — another org's private package or an unknown name — returns **404, for anonymous and authenticated principals alike** (GitHub model). A 403-vs-404 differential would let any account holder enumerate other orgs' private names.
2. **401** only for missing/invalid credentials where credentials are required, always with `WWW-Authenticate: Bearer realm="pub", message="…"` — the pub client deletes its stored token on 401, and the message is our only onboarding channel into the CLI.
3. **403** (also carrying `WWW-Authenticate` with an explanatory message) only for insufficient scope/role on a resource the principal can see — e.g. publishing with a read-scoped token.

With `require_auth_for_read` enabled, anonymous requests get the spec-mandated **401** + token-onboarding message (nothing is anonymous-readable, so nothing is enumerable).

**Consequences.** Returning 404 where the spec mandates 401 for protected resources is a **deliberate, documented deviation** (anti-enumeration). Cost: a teammate without a configured token sees "package doesn't exist" instead of "add a token" — mitigated by the org UI's setup snippet (exact `dart pub token add` command) and docs.

**Implementation addendum (2026-08-07, pub protocol HTTP surface).**

- **Where the flag lives, for now.** `require_auth_for_read` ships as boot config (`registry.require_auth_for_read`, default `false`) rather than a `settings`-table row: the runtime-settings cache of [decision 09](#09--always-compiled-backends-runtime-config-selection) does not exist yet. It moves into the table when that lands; the flag's semantics do not depend on where it is read from. This is the one place where the current code reads an "instance setting" from boot config.
- **Ordering inside the ladder.** Credentials are judged **before** existence: the auth extractor runs ahead of the org lookup, so with `require_auth_for_read` on, an anonymous caller gets 401 for an unknown org slug too, instead of a 404 that would confirm which orgs exist on the instance. Org slugs get the same anti-enumeration treatment as package names — an unknown `/o/{slug}/pub` is 404 with no challenge.
- **Unrouted paths under a registry base answer the spec error shape**, not the SPA shell: a client asking for an endpoint we have not implemented (`…/advisories` today) must get parseable JSON, not an HTML page.

## 06 — Retract + admin-only hard delete with tombstone

**Decision.** Published versions are immutable; version numbers are never reusable. The normal lifecycle tool is **retraction** (version stays downloadable, excluded from new resolutions) plus package-level `discontinued`/`replaced-by` and `unlisted`. Hard delete exists for corporate reality (leaked secrets, legal takedown): requires org owner/admin role **and** step-up authentication, writes an audit event, removes bytes from blob storage, and leaves a tombstone — the name+version stays burned forever. Deviation from pub.dev's "publishing is forever" is deliberate and gated.

**Implementation addendum (2026-08-07, registry data layer + publish pipeline).** Three details the design left open, decided while building it:

- **What a tombstone is, physically.** Hard delete does not delete the row: it sets `versions.tombstone`, clears the metadata document (`pubspec` → `{}`) and the rendered README/CHANGELOG, and keeps `archive_sha256` and `archive_size`. Clearing the payload matters because the usual reason for a hard delete *is* leaked material; keeping the hash keeps blob accounting honest. The `(package_id, version)` unique index is deliberately **not** partial, so it covers tombstones and the number can never be republished. Tombstoned versions vanish from listings but remain findable by exact version, so callers can distinguish "burned" from "never existed".
- **Blob removal is conditional.** Storage is content-addressed, so several versions can share one object (byte-identical uploads; later, proxy-cached upstream archives). The service deletes the blob only when no live version still references the hash — otherwise it keeps the bytes and records `blob_removed: false` in the audit event. Deleting shared bytes would break a hash already pinned in somebody's `pubspec.lock` ([protocol.md sharp edge 3](protocol.md#sharp-edges-violate--break-clients)).
- **Un-retraction has a window; retraction does not.** Retracting is always allowed; restoring is allowed for `registry.unretract_window_days` (default **7**, pub.dev's rule) after the retraction. The flag propagates into resolvers and lockfile decisions, so flipping it back weeks later resurrects a version the ecosystem has already routed around. The window lives in the service layer — the repository only records the flag.

## 07 — Upstream proxy: read-through cache AND mirror mode

**Decision.** Both modes ship:

- **Read-through** (default): on first request, fetch listing/archive from pub.dev, verify `archive_sha256` at ingest, store bytes forever (byte-identical, never re-tar), serve from cache from then on; stale-serving when upstream is down; circuit breaker on upstream failures.
- **Mirror mode**: a periodic sync worker watches upstream for changes and pulls them proactively (full enumeration via `/api/package-names` for the initial sweep and drift repair, recent-changes polling for the fast path). Enables air-gap-adjacent and regional-mirror deployments. Same ingest pipeline as read-through — mirror mode is "read-through warmed by a worker", not a second implementation.

Retraction/discontinued/advisories metadata from upstream is refreshed on listing fetches and preserved verbatim.

## 08 — 10 UI locales from day one

**Decision.** en, ru, fr, it, de, es, pt, ja, ko, zh-Hans (the foxic pool). i18n is wired from the first component (roadmap step 5); English is the bundled fallback; other locales load lazily.

## 09 — Always-compiled backends, runtime config selection

**Decision.** No cargo feature matrix for backends. All implementations (sqlite+postgres, fs+s3+memory, moka+redis) compile into every binary; config selects at startup (kellnr's proven model). Boot config comes from layered sources: defaults → TOML file → env (`PUB_*`-style prefix, `_FILE` suffix support for secret mounts) → CLI flags; validated with fail-fast startup errors and a printed effective-config summary (secrets masked). Runtime-changeable settings (SMTP, rate limits, proxy policy, org policies, banners) live in a `settings` table, cached per instance via `ArcSwap`, invalidated across instances through the KV broker.

## 10 — Blob storage via `object_store`

**Decision.** One `BlobStore` trait in `core`, implemented over `object_store` (LocalFileSystem, InMemory, AmazonS3-compatible incl. MinIO). Downloads return `DownloadPlan::Redirect(presigned_url)` where the backend supports signing (S3) or `DownloadPlan::Stream(...)` (fs/memory) — decided per request, designed in from day one. Archives are stored content-addressed by sha256; the exact uploaded bytes are what is served forever.

## 11 — Search behind a trait

**Decision.** `PackageSearch` trait with per-database implementations: PostgreSQL `tsvector` + GIN + `pg_trgm`; SQLite FTS5 with sync triggers. No external search service; tantivy/Meilisearch possible later as a third impl. Filter vocabulary copies pub.dev's tag architecture (`sdk:`, `platform:`, `topic:`, `is:`, `license:`, `dependency:`) plus a cross-format `format:` tag (decision 21) so search, badges, and API stay consistent across the whole artifact space.

## 12 — Auth factors

**Decision.** Self-written auth, no Firebase, no auth SaaS. Sign-in paths: (a) **email OTP — the always-available baseline** — 8-digit CSPRNG code, hashed at rest, 10-minute expiry, single-use, ≤5 attempts per code, resend throttling, uniform anti-enumeration responses; (b) **OIDC — fully optional (zero or more providers configured)**: each provider is issuer + client id/secret + display label; Google is the first-class preset but any spec-compliant IdP works (the `openidconnect` crate is provider-agnostic; corporate buyers often ban consumer Google). Confidential client, authorization code + PKCE S256, `state` + `nonce`, full `id_token` validation, identity keyed by `(iss, sub)`, account linking only via verified email. An instance-level **sign-in domain policy** (email-domain allowlist, e.g. only `@corp.com`) applies uniformly to OIDC and OTP across sign-in/registration/invites ([S-31](security.md#7-platform)). Optional **TOTP authenticator app** as a second factor (email OTP is a single factor per NIST 800-63B and is never marketed as MFA), plus hashed one-time recovery codes. Step-up (fresh second factor, "sudo mode") required for the dangerous actions enumerated in [S-06](security.md#1-authentication) — the normative list lives there. WebAuthn/passkeys: schema-prepared (polymorphic `credentials` table), targeted at v1.1.

**Implementation addendum (2026-08-07, OIDC + TOTP slice).** Three choices made at build time, recorded here because they refine the letter of the design; normative detail in [S-01.a/S-02.a/S-05.a/S-06.a](security.md#1-authentication):

- The OIDC crate is hand-rolled over the same strict-verification core as the S-07 JWT plane (the `openidconnect` crate named above was not adopted — one JWS verifier style across the codebase, no unused surface). The browser↔flow binder is an opaque server-side **`flow_id`** (KV record: state/nonce/PKCE verifier), not a `__Host-` cookie — the API stays cookieless per decision 03; the binding property is preserved.
- A **never-seen OIDC identity requires a verified email** to link or register; a known `(iss, sub)` signs in without one. Unverifiable identities are refused rather than parked in half-registered accounts.
- **Step-up freshness = fresh login ∨ fresh step-up verification** within `auth.step_up_minutes` (default 15). Accounts without TOTP satisfy S-06's "or re-auth" arm by logging in again; the step-up endpoint itself demands an enrolled second factor.

## 13 — CLI/API token format

**Decision.** GitHub-style: `<prefix>_<30 base62 chars><6 base62 CRC32 checksum>` (~178 bits entropy; prefix TBD with product name, see 17). Stored as SHA-256 hash + first-8-chars display hint (argon2 deliberately not used: tokens are high-entropy and verified per request — crates.io rationale). Scopes: `read`, `publish`, `retract`, `admin`; org-bound, optional package-name patterns; default expiry 90 days; last-used tracking (write-throttled); show-once UX with the exact `dart pub token add` command; published regex for secret scanners; revocation effective within ≤60 s (no server-side token caching beyond that). The credential-type enum leaves room for short-lived exchanged CI credentials — trusted publishing via GitHub/GitLab OIDC token exchange (later tier).

**Implementation addendum (2026-08-07, pub protocol HTTP surface).**

- **The header, and nowhere else.** Tokens are accepted on `Authorization: Bearer` only. The spec defines no query-parameter credential and the client sends none, so `?token=` is not supported — a query credential lands in access logs, proxy logs, and `Referer` headers, and would reach users' `pubspec.lock` files through `archive_url`.
- **The offline checks are the plane boundary.** Prefix + length + base62 charset + CRC32 run before the hash lookup, which is what makes a browser access JWT structurally unusable on pub routes ([decision 03](#03--sessions-jwt-access--refresh-sessions-kv-backed-revocation)'s "never mixed") without a hand-written special case, and keeps fabricated strings off the database.
- **Package patterns**: a trailing `*` matches any suffix, anything else is an exact name; an empty list means no narrowing. Deliberately not a regex — this is an authorization decision, and a catastrophic-backtracking pattern would be a denial of service with extra steps. Patterns narrow reads of **private** packages only (a public package is readable with no credential at all, so hiding one would make a token worse than none) and are enforced at publish **finalize**, which is the first moment a package name exists in the flow.
- **The role is re-derived per request** from the durable membership, never cached in the token row: a token outlives role changes by design, so a user who has left the org authenticates and authorizes nothing.

## 14 — Frontend shape

**Decision.** Bun workspaces monorepo. `apps/site` — Astro 7: landing + docs as SSG with per-locale routes; `/app/[...rest]` is a prerendered shell mounting a single `client:only` SolidJS island with `@solidjs/router` (browser mode). Solid 1.9 + router 1.0 (Solid 2.0 beta excluded); data layer written exclusively with `createAsync`/`query`/`action` for a mechanical 2.0 upgrade. UI primitives: **Kobalte** — Ark UI was the research-preferred alternative (more active, broader coverage); Kobalte is chosen deliberately (owner preference, foxic-proven patterns and custom Tailwind state variants), and all primitives are wrapped in `packages/ui` so the primitive layer stays swappable — + Tailwind 4 (CSS-first, OKLCH tokens, `data-theme` + anti-FOUC inline script); own component recipes in `packages/ui` with a self-hosted ui-kit page. PWA: static manifest + **hand-rolled service worker** (~150 lines; vite-plugin-pwa currently breaks on Astro 7/Vite 8): app-shell precache, SWR for metadata, cache-first for immutable per-version artifacts, network-only for auth. CSP reality check (recorded 2026-08-06): besides our single authored inline script (anti-FOUC), Astro emits deterministic framework inline bootstraps on island-bearing pages (astro-island element, hydration directives) — the server CSP must include static sha256 hashes for these (or adopt Astro's `security.csp` emission) rather than assuming exactly one inline script. API types generated from utoipa's OpenAPI 3.1 via `openapi-typescript` + a foxic-style interceptor fetch client (mutex-deduped refresh, denial latch, network-vs-denial discrimination). TypeScript 7 native `tsc` for typechecking; lint/`astro check` toolchains stay on the TS6 engine until TS 7.1.

## 15 — i18n mechanism

**Decision.** foxic's homegrown system, ported: YAML message files per namespace with mandatory `desc` per key (context for translators and LLMs), Bun codegen to typed `as const` modules (typo-proof keys, bundled English fallback), `Intl.PluralRules` plurals, whitelist rich-text parser (no `innerHTML`), lazily fetched locale JSONs cached by the service worker. ~350 dependency-free lines beats paraglide/i18next for the "as lightweight as possible" goal. Astro static pages import generated modules per locale route; the app island shares the same runtime.

## 16 — Error handling (proposed)

`thiserror` domain error enums per module with explicit `code()`/`status()` mapping into a uniform JSON envelope; no `anyhow` string matching (foxic's weakest habit). Pub-protocol routes emit the spec error shape `{"error":{"code","message"}}`; permanent failures are always 4xx (the pub client retries 408/429/5xx up to 7 total attempts).

## 17 — Branding: default "Pub", white-label, token prefix `pub_`

**Decision.** The product's default name is **Pub**; binary `pubd`. Instances can rebrand at runtime via admin settings: instance name, logo, accent colors — all cosmetic, stored in the `settings` table. The token prefix defaults to **`pub_`** and is instance-configurable; the published secret-scanning regex targets the default prefix, so custom prefixes trade away scanner coverage (documented).

## 18 — Ops: release model, image registry, reference orchestrator (tbd)

Recorded so foxic's CI shape is not imported blindly. Leanings: releases must **not** commit version bumps to master from CI (race-prone; foxic's known weakness) — the version derives from the git tag and is injected as a build arg; a release-please-style PR flow is to be evaluated. Image registry: leaning **GHCR** over Docker Hub (auth via `GITHUB_TOKEN`, no pull rate limits for self-hosters). Reference orchestrator for the replicated tier: compose remains the documented baseline, Helm chart planned (see product.md); Docker Swarm is not a target.

## 19 — RBAC: cumulative role levels with a single authorize() chokepoint

**Context.** Org roles here are genuinely cumulative — Read ⊂ Read+Write ⊂ RW+Admin ⊂ RW+Admin+Owner. A bitmask earns its complexity only when permissions are non-linear (auditor-only, retract-only, billing-only); in this design that plane is already served by scoped CLI tokens and, later, per-package grants — so the org role can stay linear.

**Decision.** An org membership carries an **ordered role level**, stored as a small integer with gaps for future insertions: `0` none, `50` **Read** (resolve/download), `100` **Write** (publish, manage own packages), `200` **Admin** (members, tokens, package settings), `250` **Owner** (org lifecycle, danger zone). Checks are `level >= required`; an intermediate role (e.g. a future `150` Maintainer) slots in without migration. Wire protocol and UI use role *names* — numbers are a storage/comparison detail. JWT claims carry `{org_id: level}` (decision 03). Every check flows through a single `authorize(actor, action, resource)` chokepoint, so if a genuinely non-linear org permission ever appears, adding a bitmask overlay is a contained refactor, not an audit of scattered comparisons. Invariants: ≥1 Owner per org; invitations default to Read; grants at Write level or above are step-up-gated (S-06). CLI-token scopes (`read`/`publish`/`retract`/`admin`) remain the fine-grained, non-linear plane.

## 20 — Realtime: SSE event stream + notification center

**Decision.** The backend exposes a Server-Sent-Events stream (`GET /api/v1/events`) for live updates: package publishes/retractions in the principal's orgs, membership and invitation events, shadowing alarms, token-expiry warnings, admin announcements, settings changes for admin UIs. Delivery: per-instance in-process broadcast, fanned out across instances via the KV broker (Redis pub/sub) — consistent with decision 03's scaling gate; single instance needs no extra infra. Implementation notes: the browser client uses fetch-streaming rather than `EventSource` (which cannot set an `Authorization` header); keep-alive comments; best-effort `Last-Event-ID` replay from a short per-user ring buffer — the stream is a hint channel, the REST API remains the source of truth. On top of the same events sits a **notification center**: per-user persisted notifications (unread counts, mark-read, preferences per category), with email delivery for high-importance ones (invites, security events). Security constraints in [S-32](security.md#7-platform).

## 21 — Multi-format artifact space (pub first; npm, cargo, … later)

**Decision.** The registry is designed Artifactory-style as a **single artifact space over multiple package formats**. V1 ships the pub protocol only, but every shared seam is format-agnostic from day one:

- Core entities carry a `format` discriminator: packages unique per `(format, name)`; name claims, resolution policy, and shadowing alarms are per-format; version rows hold common fields (version, ordering key, sha256, retracted, timestamps) plus format-specific metadata as JSON (pubspec / package.json / Cargo index entry).
- The blob store is content-addressed and format-blind already.
- URL space reserves the format segment now: `/o/{org}/pub` (future `/o/{org}/npm`, `/o/{org}/cargo`), public roots `/pub` (future `/npm`, `/cargo`). The `api` crate hosts one protocol module per format, each implementing its wire contract against the shared core traits.
- One search across formats (`format:` filter tag), one permission model (decision 19), one token plane (scopes apply uniformly per format), one audit/notification/webhook pipeline.
- Upstream proxying generalizes: per-format upstreams (pub.dev, registry.npmjs.org, crates.io) share the ingest pipeline, integrity rules (S-19), and policy engine (S-16).

**Consequences.** Pub-specific logic (pubspec parsing, advisories mapping, README pipeline specifics) lives in the pub protocol module and format adapters — never in shared entities. npm's `@scope/name` maps naturally onto orgs; cargo needs a sparse-index endpoint — both are protocol-module work, not core rework. Non-goal for v1: shipping any second format.

**Implementation addendum (2026-08-07, registry data layer).** Two shared seams were fixed while landing the entities; both are format-agnostic by construction and neither can be retrofitted cheaply:

- **Version ordering is a stored precedence key.** `core::SemVer` implements semver.org §11 precedence (pre-release rules included, build metadata excluded), and `SemVer::sort_key()` projects a version onto a string whose *bytewise* order equals that precedence: fixed-width zero-padded core numbers, a release/pre-release marker, and one prefixed segment per pre-release identifier separated by a byte below every legal identifier character. Storing it (`versions.version_sort`) makes version listing and keyset pagination one index scan instead of an in-memory sort, and keeps ordering identical on both backends. It is **collation-sensitive**: the Postgres column carries `COLLATE "C"` because a locale/ICU collation folds punctuation and case and silently reorders pre-releases (verified: an ICU-collated column sorts `1.0.0-a-b` before `1.0.0-a.b`, which is backwards). The contract suite orders a table containing exactly those adversarial pairs on both backends. Other formats reuse the same key — npm and cargo are semver too.
- **Blob keys are `<format>/<sha256[0..2]>/<sha256>.tar.gz`.** Content addressing already makes the hash unique, so the format prefix is not for collision avoidance: it keeps per-format lifecycle operations (a bulk purge, a per-format retention policy, a bucket-level rule) expressible as a prefix, and the two-character shard keeps directory fan-out sane on the filesystem backend.

## 22 — Domain event bus; webhooks and integrations on top

**Decision.** All domain events (publish, retract, membership/invitation, shadowing alarm, token lifecycle, settings changes) flow through **one internal event bus** — the single seam that fans out to: the SSE stream (decision 20), the notification center, the audit log, and **outbound webhooks**. Webhooks (v1.1): configured per org (and instance-wide by admins) with event-type filters; deliveries signed with HMAC-SHA256 (`X-Pub-Signature` header), executed by the jobs crate with exponential-backoff retries and a dead-letter state; delivery log in the UI. Security constraints in [S-33](security.md#7-platform) (SSRF guards, encrypted secrets, TLS-by-default). Richer integrations (Slack/Telegram templates, CI triggers) build on the same bus later.

## 23 — Monitoring is optional

**Decision.** Observability exports are config-gated and **off by default**: the Prometheus `/metrics` endpoint (optionally on its own listen address), OTLP trace export, and JSON log shipping are each enabled explicitly. `tracing` instrumentation and `/healthz` are always on — near-free and needed by orchestrators. No monitoring stack is required to run the product.
