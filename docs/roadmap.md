# Roadmap

State of the project and the plan forward. Written 2026-08-07 against commit `3cbe504` on branch `foundation`, grounded in a full read-only audit of the code (not of the design docs — where the two disagree, the code is what this document reports). **Updated later the same day against `9cc1bef`** after the first execution wave: D4, D5, D6 and D24 closed (marked in place below), decisions 18/24/25 accepted and 02 amended, dependencies swept to latest stable (Rust 1.97.1, reqwest 0.13), the Patina palette with a three-theme registry and the sheen+ripple interaction layer landed, and the agent tooling (`.claude/` skills, commands, hooks) ported from foxic.

The original [10-step website roadmap](https://wiki.plugfox.dev/s/website-roadmap) is complete through step 7; this document replaces its remaining steps with a plan shaped by what actually got built.

---

## Part I — What exists

### Numbers

| | |
|---|---|
| Backend | 16 crates, ~56 400 LOC Rust, 1 176 LOC SQL across 9 migrations per dialect |
| Frontend | Bun workspace, 4 packages + 1 Astro app, 18 app screens, 3 registered themes |
| Tests | **841** server (incl. 26 backend-agnostic contract functions run on both dialects) + **350** web |
| API surface | 61 app-API routes, 7 pub-protocol routes mounted on 2 virtual bases, `/healthz` (now version-reporting) |
| Verified live | `dart pub` 3.12.2 publish/resolve/retract against the binary; an 11-package graph proxied from the real pub.dev; production `docker run` acceptance — fail-fast secrets, volume survival, OTP sign-in through a mail sink |

### The foundation that is genuinely load-bearing

**Pluggable infrastructure behind core traits.** Every backend is compiled in and chosen by config at startup: SQLite or PostgreSQL (separate implementation crates, dialect-idiomatic SQL, per-dialect migrations), filesystem/in-memory/S3 blobs via `object_store`, in-process or Redis KV. The `core` crate holds domain types and 15 traits and depends on no infrastructure; the API layer never sees a sqlx type. This is the single most valuable structural property of the codebase — it is why SQLite-on-a-laptop and Postgres-in-a-cluster are the same binary.

**A contract suite that runs against both databases.** 26 contract functions exercise every repository method — including the ordering-sensitive and concurrency-sensitive ones — on SQLite `:memory:` always and on a live Postgres when `PUB_TEST_POSTGRES_URL` is set. This has already caught real cross-dialect divergence (Postgres returning `203.0.113.9/32` where SQLite returned the address; C-collation being load-bearing for semver sort keys).

**One authorization chokepoint.** `authorize(actor, action, resource)` in `core`; cumulative role levels 0/50/100/200/250 with gaps for future roles; visibility policy expressed once as a provided trait method (`resolve`/`resolve_in_base`) rather than duplicated per dialect or per handler.

**Protocol conformance with an external arbiter.** All 12 sharp edges in `docs/protocol.md` are implemented and tested (48 conformance tests), and the behaviours that break real clients — 404-not-401 for unreadable names, `WWW-Authenticate` on both 401 and 403, 4xx-never-5xx for permanent failures, byte-stable archives, `archive_url` under our own base, case-insensitive `Bearer` — were each verified against the real Dart client, not only against our own router.

**Supply-chain integrity by construction.** Archives are content-addressed by sha256 and stored byte-identical; upstream bytes are hashed before storage and quarantined on mismatch; a version's bytes can never be overwritten (byte-drift keeps the cached copy and raises an alarm); a locally claimed name structurally cannot fall through to upstream, because upstream is reachable only from the `Unclaimed` arm of resolution. Dependency confusion was demonstrated end to end: a local `path 9.9.9` wins over pub.dev's real `path` with zero upstream traffic.

**Ingest hardening that survived an adversarial pass.** Streaming tar/gzip validation with caps on size, ratio and entry count; rejection of traversal, absolute paths, symlink escapes, duplicate entries, a smuggled second gzip member, and payload appended past the end-of-archive marker; YAML parsed at the event level with aliases rejected (no billion-laughs); markdown rendered and sanitized server-side.

**Authentication built to a written standard.** Email OTP with an atomic per-code attempt budget spent before comparison, Ed25519 JWT with strict `kid` resolution and algorithm pinning, rotating refresh sessions with reuse detection, multi-provider OIDC with PKCE/state/nonce and an offline mock issuer in tests, TOTP with KEK-sealed seeds and argon2id recovery codes, step-up gating on the full S-06 action list, and 20 dedicated attack tests (HS256-forgery with the Ed25519 public key, `alg=none`, parallel OTP guesses, concurrent refresh, spoofed forwarded headers).

**A normative security document wired into the tests.** `docs/security.md` carries S-01…S-33 plus lettered amendments added when reviews discovered something; tests are named after the requirement they prove. The audit verified every test name it cites actually exists.

### What is configured and ready to build on

- **CI**: path-filtered workflows for both sides; server runs fmt/clippy/test with a Postgres service; web runs typecheck, Biome, a WCAG-AA contrast gate over the token palette (now 69 pairs across three themes), an Astro build, and 350 tests. New since the audit: a PR Docker-build job (`docker-ci.yml`) and a tag-triggered multi-arch GHCR release workflow with a version smoke test, SBOM and GitHub release (`release.yml`) — no tag has been cut yet.
- **Docker**: a 4-stage image that builds today (web → dependency layer → binary → alpine runtime, non-root, healthchecked) now shipping **production mode + a data `VOLUME`**, failing fast with actionable errors naming `pubd generate-secrets`; compose profiles `pg`/`s3`/`redis`/`full` — the profile env names are fixed (they were silently ignored) and `full` is wired end to end with MinIO bucket init and a Mailpit sink.
- **Types**: the frontend generates its API types from the server's OpenAPI document (`bun run gen:api`); a server-side test asserts the document matches the route inventory exactly.
- **Design system**: the Patina palette (decision 24 — warm graphite neutrals, teal accent) behind a **theme registry** — light, dark and true-black AMOLED, contrast asserted per theme by the CI gate; the sheen+ripple interaction layer (decision 25); self-hosted font subsets with Cyrillic; a component kit with a showcase page. Iris/nocturne kept as validated candidate palettes.
- **i18n**: YAML with a mandatory `desc` per key, Bun codegen to typed modules, English bundled as fallback, 10 locales generated, Russian genuinely translated; verified lazy — no locale dictionary text reaches the JS chunks.
- **Governance for agent work**: `CLAUDE.md`, `AGENTS.md`, `docs/rules/*`, a decision log with 25 entries, a changelog with per-component tags, and `.claude/` — 21 repo-adapted skills, slash commands (`/server-check`, `/web-check`, `/db-up`, `/new-migration`), a Stop hook and permission settings.

---

## Part II — Tech debt

Ranked by risk to a real deployment. Each item names the file where the audit found it.

### Critical — these make a documented deployment shape unsafe or unusable

| # | Item | Why it matters |
|---|---|---|
| D1 | **Leader election is per-process.** `bin/pubd/src/main.rs:197,266` construct `InMemoryJobLock`; no Redis or advisory-lock implementation exists. Yet `config/src/validate.rs:33-44` permits `cluster.replicas > 1` whenever Redis KV is configured. | At two replicas: blob GC runs twice concurrently (a job that deletes bytes), mirror sweeps double-fetch, jobs race one durable cursor, and the per-name publish lock degrades to the DB unique index — clean 409s become raw constraint violations. The config validator's approval is the operator's only signal and it is wrong. |
| D2 | **Notification fan-out is synchronous, inside the request.** `events/src/bus.rs:218`, `events/src/notify.rs:210` — per recipient (default cap 200): one INSERT, one unread-count SELECT, optionally a **blocking SMTP transaction**, plus a follow-up event published to the broker. | Worst case for one publish finalize: ~400 queries and 200 SMTP sessions inside a request the pub client retries up to 7 times. |
| D3 | **Rate limiting is a non-atomic read-modify-write.** `auth/src/ratelimit.rs:40-57` does get → decide → set. | Every windowed S-24 bucket (OTP per email/IP, login per IP, token-auth failures, publish per org) is bypassable by concurrency. An atomic `Kv::incr` already exists and is used correctly for the per-code OTP budget — which is exactly why that test passes while the windows do not hold. |
| D4 | ~~**The default SQLite deployment has no WAL and no busy timeout**, with a hard-coded 5-connection pool~~ **Closed 2026-08-07** (`feat(server)` f786042): WAL + `synchronous=NORMAL` + 5s busy timeout, `[database.pool]` config for both dialects, concurrency tests. | ~~Two concurrent writers produce `SQLITE_BUSY` → 500.~~ |
| D5 | ~~**`docker run` produces an instance nobody can sign in to.**~~ **Closed 2026-08-07** (`feat(infra)` 31a7aaf): image ships production mode + `VOLUME`, fails fast naming missing secrets, `pubd generate-secrets` emits the env/TOML fragment; acceptance proven live (data survives container replacement, OTP sign-in through the compose mail sink). | |
| D6 | ~~**There is no way to obtain a build.**~~ **Closed 2026-08-07** (`feat(infra)` 08ac240, decision 18 accepted): tag-derived version through `/healthz`, PR docker-build CI, multi-arch GHCR release workflow with smoke, SBOM and GitHub release. First actual tag still pending. | |
| D7 | **No operator documentation exists.** No install guide, no configuration reference for ~90 keys across 13 sections, no backup/restore/upgrade procedure, no reverse-proxy example, no rotation runbook — though S-04.c, S-24.b and S-27 all reference "the runbook". | |

### High — promises in the docs that the code does not keep

| # | Item |
|---|---|
| D8 | **The strict CSP does not exist.** Live headers are `nosniff`, `frame-ancestors 'none'`, `X-Frame-Options`. S-11 names `script-src 'self'` + nonce as *the* compensating control for keeping tokens in localStorage (decision 03), and S-28 requires HSTS, `Referrer-Policy`, `Permissions-Policy` and `Cache-Control: no-store` on sensitive responses. None are emitted. There is also no `Cache-Control` on embedded static assets at all, so content-hashed bundles are re-fetched. |
| D9 | **Prometheus `/metrics` does not exist.** The recorder installs behind `telemetry.prometheus = true` and the handle is dropped (`main.rs:137`); no route renders it. The 16 domain counters that are emitted are unreachable, there are **zero HTTP metrics** (no rate, latency or status counters), and `publishes_total` is never emitted. OTLP is a `warn!`; JSON log output is unreachable (`LogFormat::Pretty` hard-coded); no `Server-Timing`. |
| D10 | **Runtime SMTP settings are inert.** The admin API accepts, seals and audits them (`admin/src/instance.rs:246`), but the mailer is built once from boot config and never rebuilt. An operator who configures SMTP only in the UI gets an instance that delivers no mail while the UI reports `password_set: true`. |
| D11 | **S3 downloads are proxied through the app process.** `blob/src/lib.rs:93` always returns `Stream`; `DownloadPlan::Redirect` is never constructed, though decision 10 says presigned redirects were "designed in from day one" and the handler implements the redirect branch as dead code. |
| D12 | **No purge, no retention, no export.** Sessions, invitations, audit rows, notifications, download stats and version tombstones grow forever. S-23's retention windows are unimplemented and there is no audit export. |
| D13 | **No HTTP timeout and no concurrency limit** anywhere in the middleware stack; the publish budget is spent only after the body is read, so a slow client can hold ~100 MB with no deadline. |
| D14 | **No read-path rate limiting.** Only the six credential endpoints are bucketed. `GET /api/v1/packages/{name}` issues 5–7 sequential queries and `/healthz` pings all three backends, both unauthenticated and unthrottled. |
| D15 | **Security tooling absent from CI**: no `cargo audit` (S-30 requires it), no gitleaks rule (S-15), no image scanning, no dependency-update automation, no `--locked`/`--frozen-lockfile`. |
| D16 | **The Postgres CI leg cannot fail.** The contract runner skips silently when the env var is unset and still reports `ok`; a Postgres service that fails to start yields a green build. All 198 HTTP integration tests are hard-wired to SQLite + memory blob + memory KV, so **the S3 and Redis code paths have never been executed against a real server in any automated test.** |
| D17 | **Frontend offline is broken.** The service worker precaches two HTML documents and intercepts navigations only; offline, `/app/` loads a document whose 14 eager chunks and stylesheet are uncached — a blank unstyled page. Decision 14's SWR/cache-first strategy and decision 15's locale caching are unimplemented. |
| D18 | **Server error messages never reach the user.** `state/api.ts:120` discards `ApiError.code` and `.message`, collapsing every refusal into one generic string — including "past the unretract window", "cannot remove the last owner" and duplicate-slug conflicts, all of which the UI elsewhere promises to explain. |

### Medium

- **D19** Token package patterns and non-expiring read tokens are fully implemented and tested server-side but unreachable from the API (`flows.rs:987` hard-codes an empty pattern list; the DTO has no field). S-13's "unlimited only for read" cannot be expressed.
- **D20** S-04 timing oracle on OTP request: uniform work is done for every address, then the SMTP hand-off branches and its error propagates — an accepted address costs a round trip and returns **500** when SMTP is down; a blocked one returns 200 instantly.
- **D21** No per-org storage quota (S-20); the only bound is 30 uploads/h × 100 MB.
- **D22** Staged uploads are never swept on a default install (blob GC ships disabled and dry-run).
- **D23** Blob GC loads the entire key space into memory and issues 2 queries per object while holding a 300 s lock; the search indexer walks every version of a package with no cap on every publish.
- **D24** ~~Connection pools hard-coded at 5 with no timeouts and no config keys~~ **Closed 2026-08-07** with D4 (f786042): `[database.pool]` — max connections and acquire/idle/lifetime timeouts, validated, per-dialect defaults.
- **D25** `/healthz` does not report migration status (architecture.md says it does); no `/readyz` distinct from liveness.
- **D26** No admin surface over the `upstream_quarantine` and `shadowing_alarms` registers — the two supply-chain signals that exist and are populated are visible only as a transient toast or an audit line.
- **D27** S-27 KEK rotation is structurally impossible: one `auth.kek` with no previous slot and no DEK layer, so rotating it bricks every TOTP seed and the stored SMTP password.
- **D28** S-21 provenance records user and token but no CI metadata.
- **D29** utoipa defects the frontend works around: `IntoParams` emits `in: path` for query parameters, and 13 duplicate `operationId`s (the generator renames them and prints warnings). Both belong upstream in the annotations.
- **D30** Nine hand-written enum vocabularies in the frontend mirror server enums typed as bare `string` in the OpenAPI document, with nothing asserting they agree. Three copies of the locale list, likewise unasserted.
- **D31** Config drift: `require_auth_for_read` is still boot-only though its addendum says otherwise; branding is runtime for `/home` but boot-only for notification email subjects, so a rename produces stale-branded mail.
- **D32** Frontend correctness: `revokeInvitation` is the one step-up-gated call not wrapped in `withStepUp` (the dialog opens with no waiter and the action silently fails); the show-once token panel builds the `dart pub token add` base from `window.location.origin` instead of the server-advertised public URL — wrong behind a reverse proxy, and unrecoverable without minting a new token; the SSE stream never restarts after a rate-limited stop; there is no `ErrorBoundary` in the shell.
- **D33** Accessibility gaps verified by reading: no focus management or announcement on route change; `EmptyState` titles are paragraphs, so the 404 and 403 screens have no heading at all; nine admin fields set `aria-invalid` with no `aria-describedby`; Suspense fallbacks are `aria-hidden` skeletons with no live region; a `Badge` `aria-label` replaces the visible role value with the word "Role".
- **D34** Bundle: the eager island is 79 KB gzip, of which Kobalte is 22.7 KB (pulled in by the shell's static imports of Menu/ThemeToggle/Toast/Dialog) and the full English message catalogue is 9.6 KB; the static landing page ships 23 KB gzip of JS to render one theme toggle.
- **D35** Astro has no per-locale routes and no docs pages — every built page is `lang="en"`, contradicting decisions 08 and 14.
- **D36** Partially closed 2026-08-07: **vitest browser mode is installed and live** (`packages/ui`, 8 real-Chromium tests over the feedback directives and ThemePicker, `*.vitest.tsx` naming isolated from `bun test`; its first run caught and fixed a real Kobalte close-on-select defect), alongside the happy-dom DOM-contract tests; `@playwright/test` is a dev dependency but the e2e suite does not exist yet. Still open: browser tests in CI, bundle budgets, Lighthouse, the real-`dart pub` CI job `docs/protocol.md` calls "the final arbiter", OpenAPI drift and codegen idempotence checks.

### Absent security requirements

Of S-01…S-33: 20 implemented and tested, 8 partial with a named gap, **5 absent** — S-15 (secret-scanning pattern published), S-23 (retention and export), S-29 (data export, account deletion, `security.txt`), S-30 (dependency audit in CI), S-33 (webhooks, v1.1 by design). The partials that matter most are S-11/S-28 (no strict CSP, no HSTS) and S-12 (no `CorsLayer` — currently locked by omission).

### Deliberate deviations to carry forward, not fix

These are documented, justified and should stay unless their exit condition is met: runtime sqlx queries instead of compile-time macros (**resolved 2026-08-07**: a spike proved the 0.9 CLI dual-backend workflow now works *and* that macro idioms conflict with the `COLS` dedup, the sqlx-free core and dialect-native binds — decision 02 amended, runtime queries are the recorded norm; new trigger: a drift escape the contract suite misses, or sqlx gaining computed SQL fragments); the pre-DNS SSRF guard (compensated by sha256 verification); 406 reserved exclusively for API-version mismatch; 404 where the pub spec mandates 401 (anti-enumeration, decision 05); the publish budget failing open while auth buckets fail closed.

---

## Part III — The plan

Five phases. Phases 1 and 2 are what stand between this codebase and someone else running it; 3 is the multi-instance promise; 4 and 5 are product growth. Each phase lists its exit criteria — a phase is done when those are demonstrable, not when the code is written.

### Phase 1 — Make it installable *(closes D4–D7, D8, D13, D15, D24, D25)*

The goal is a stranger installing this from a published artifact and running it in production without reading source code.

1. ~~**Release engineering (decision 18, finally decided).**~~ **Done 2026-08-07** (`08ac240`): tag-derived version through the `PUB_VERSION` build arg to `/healthz` and `--version`, PR docker-build CI, multi-arch GHCR release workflow with version smoke, SBOM and GitHub release. Two operational notes for the first tag: the GHCR package is born private (one manual flip to public), and free arm64 runners require a public repository.
2. ~~**A deployable default.**~~ **Done 2026-08-07** (`31a7aaf`): `VOLUME` + production mode in the image, fail-fast errors naming every missing secret, `pubd generate-secrets` (env/TOML, 0600, no silent overwrite), compose `full` wired end to end (MinIO bucket init, Mailpit sink) and the profile env-name drift fixed. Acceptance proven live, including container-replacement survival and OTP sign-in.
3. **Operator documentation** in `docs/ops/`: install (docker run, compose, binary), a **generated** configuration reference (derive it from the config structs so it cannot drift), reverse-proxy examples for nginx/Caddy/Traefik including the mandatory `trust_proxy_headers` guidance, backup/restore for both database and blob backends, upgrade procedure, and the key-rotation runbook that three security requirements already reference.
4. ~~**SQLite fit for the default deployment.**~~ **Done 2026-08-07** (`f786042`): WAL, `synchronous=NORMAL`, 5s `busy_timeout`, foreign keys explicit, `[database.pool]` with validated per-dialect defaults and acquire/idle/lifetime timeouts; concurrency pinned by tests, `:memory:` exempted from pool reaping (a latent data-loss hazard found in passing).
5. **HTTP hygiene**: request timeout, concurrency limit, global body cap, and the security headers S-11/S-28 require — HSTS, strict CSP with hashes for Astro's framework inline bootstraps, `Referrer-Policy`, `Permissions-Policy`, `Cache-Control` tiers (immutable for hashed assets, `no-store` for sensitive responses) and ETags. An explicit `CorsLayer` rather than locked-by-omission.
6. **Supply chain in CI**: `cargo audit` with justified ignores, gitleaks with our own token pattern published (S-15), image scanning, dependency update automation, `--locked` and `--frozen-lockfile`.

**Exit:** a tagged release exists; `docker run ghcr.io/…/pub` with a documented env file yields a production-mode instance that survives a container replacement, delivers mail, and passes an external header check; a reader can find every config key in the docs. **Status: the middle clause is now demonstrated (production boot, volume survival, mail sign-in); still open — the tag itself, the header check (item 5) and the config docs (item 3).**

### Phase 2 — Make the claims true *(closes D2, D3, D9–D12, D14, D19–D23, D26, D31, D18, D20)*

Everything here is a place where the product says something the code does not do.

1. **Atomic rate limiting** on every window via `Kv::incr` (the mechanism already exists), plus per-token buckets (S-13) and read-path limiting with fail-open semantics (S-24).
2. **Asynchronous fan-out**: notifications and outbound mail move onto the jobs queue; nothing does SMTP inside a request. This also removes the S-04 SMTP timing oracle and the 500-on-SMTP-down, because delivery stops being part of the response.
3. **Runtime SMTP that works** — a rebuildable mailer behind the settings cache, with a "send test mail" admin action.
4. **Observability that an operator can use**: mount `/metrics`, add HTTP RED metrics and the missing domain counters, make the log format configurable, emit `Server-Timing`, implement OTLP or remove the flag, and ship a reference dashboard and alert rules for the supply-chain signals (quarantine, drift, shadowing, sync lag).
5. **Presigned downloads** for S3 so archive bytes stop traversing the app tier.
6. **Lifecycle jobs**: session/OTP/invitation purge, audit retention per S-23 with cursor-paginated export, staged-upload sweeping on by default, and a blob GC that streams rather than materializing the key space.
7. **Quotas and limits**: per-org storage quota (S-20), configurable invitation limits with per-actor caps, and a cap on the indexer's version walk.
8. **Complete the token model**: package patterns and non-expiring read tokens in the API (the enforcement is already built and tested).
9. **Supply-chain visibility**: admin screens over the quarantine and shadowing registers, which today are populated but invisible.
10. **Error messages that reach the user** (D18), and the remaining config drift (D31).

**Exit:** every "Observability" and "Security baseline" line in `docs/product.md` is demonstrably true; a load test shows publish latency independent of recipient count; the S-xx table has no partial marked "absent mechanism".

### Phase 3 — Make multi-instance real *(closes D1, D16)*

1. **A distributed `JobLock`**: Redis and Postgres advisory-lock implementations behind the existing trait, used for both the scheduler and the per-name publish lock. The config validator must gate `replicas > 1` on a *distributed lock*, not merely on Redis KV.
2. **CI legs that exercise the real backends**: run the HTTP integration suite against Postgres as well as SQLite; add MinIO and Redis legs via testcontainers; make the Postgres contract leg fail loudly when its service is missing instead of skipping green.
3. **A two-replica acceptance test**: compose with two app instances behind a proxy, proving session revocation propagates, jobs run exactly once, publishes serialize, and SSE reaches a client connected to either replica.

**Exit:** a documented, tested two-replica deployment; the audit's sentence "multi-instance is permitted and unsafe" is false.

### Phase 4 — Finish the product surface *(closes D17, D19, D26, D32–D36 and the account gaps)*

1. **Account and privacy (S-29)**: `GET /me` (with `totp_enabled`, ending the session-local 2FA guess), profile edit, data export, account deletion with an anonymized publisher tombstone, and `/.well-known/security.txt`.
2. **Frontend correctness and completeness**: the step-up wrapper fix, the public-URL fix in the token panel, SSE restart, an error boundary in the shell, real paginators where sentences stand in today, and `has_more` respected on dependents.
3. **A real service worker** implementing decision 14 (or an amended decision, if the app-shell strategy should change) with locale caching per decision 15.
4. **Accessibility sweep**: route-change focus and announcements, headings on every screen, `aria-describedby` on invalid fields, live regions for async states, and a pass over the ui-kit as the reference surface.
5. **Bundle discipline**: lazy the Kobalte-dependent shell pieces, split the message catalogue per screen, drop the island from the static landing page, and add bundle budgets to CI.
6. **Astro per-locale routes and a docs section** (decisions 08 and 14), with runtime locale switching in the app island.
7. **Test depth**: component tests, a Playwright happy-path suite, and — the one the protocol document already calls the final arbiter — **a real `dart pub` job in CI**, plus OpenAPI drift and codegen idempotence checks.
8. **Upstream OpenAPI fixes** (D29) so the frontend's workarounds can be deleted, and a test asserting the shared enum vocabularies match.

**Exit:** every screen in `docs/product.md` is real or honestly absent; the app works offline as documented; CI proves the client contract on every push.

### Phase 5 — Growth

In the order the product document already prioritizes them:

- **v1.1**: OSV advisories endpoint plus upstream relay; webhooks (S-33) on the existing event-bus seam; WebAuthn/passkeys on the polymorphic credentials table; upstream `delay` quarantine mode; download charts; token-expiry notification emails; pub.dev-shaped `/score` and `/metrics` stubs so ecosystem tooling stops 404-ing.
- **Enterprise**: npm and cargo protocol modules — the payoff for the format discriminator carried since decision 21; dartdoc hosting and pana scoring in sandboxed workers; teams and per-package grants; SAML/OIDC SSO with SCIM; audit streaming; upstream allowlist and CVE/license intake policies; org name-prefix reservations; trusted publishing via CI OIDC token exchange; SLSA/Sigstore provenance; CycloneDX SBOM export; air-gap bundle sync; a Helm chart.

---

## Working agreements for the phases ahead

- **The decision log stays normative.** Anything in this roadmap that changes a decision gets recorded there first; decisions 16 (proposed) and 18 (tbd) are resolved in Phase 1.
- **Every phase ends with an adversarial review**, not only tests — the reviews in Phases 1–4 of the build so far found the archive-smuggling hole, the non-atomic OTP budget, the trusted `X-Forwarded-For`, the cross-org version oracle and the browser-only `Content-Type` defect, none of which the building agent's own tests caught.
- **External arbiters over self-reports**: the real `dart pub` client, the real pub.dev, a real browser, a real Postgres. Every claim in this document that says "verified" means one of those was involved.
- **Debt is written down where it lives.** A deviation with a documented reason and an exit condition is acceptable; an undocumented one is a defect.
