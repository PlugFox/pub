# Product: Self-Hosted Pub Registry

A self-hosted, open-source package registry for Dart/Flutter — a private pub.dev with corporate-grade security. One binary for a laptop, a replicated cluster for an enterprise.

## Why it should exist

The niche is genuinely empty (verified 2026-08):

- **unpub** (ByteDance) — semi-abandoned since 2024, MongoDB-only, proxy-by-redirect without caching, weak token model.
- **pub_server** (dart-lang) — archived 2020, "alpha, not for production".
- **pub.dev itself** (`dart-lang/pub-dev`) — AppEngine/Datastore-coupled, explicitly not designed for private hosting.
- **OnePub** — capable but SaaS-only, no self-hosting.
- **Artifactory / Cloudsmith / Nexus** (Cloudsmith has hosted private Dart since 2019; Nexus added pub only in 3.92, May 2026) — heavyweight generic platforms, not a product for the Dart ecosystem.
- **kellnr** (private crates.io registry in Rust) — the architecture model we follow: single binary, SQLite/Postgres, FS/S3, pull-through cache. Nothing like it exists for pub.

**Differentiators nobody self-hosted delivers today:** repository-spec-v2 conformance verified against the real `dart pub` client (`archive_sha256` and retraction in v1; OSV advisories endpoint in v1.1), dependency-confusion policy engine (local-always-wins, shadowing alerts, per-org upstream policy), an actual multi-org permission model with audit logs, and — in the enterprise tier — dartdoc hosting for private packages and pana scoring.

## Core capabilities

- **Registry**: publish/consume via the standard `dart pub` / `flutter pub` CLI (Hosted Pub Repository Specification v2). Immutable versions, retraction, discontinued/replaced-by, unlisted.
- **Multi-format ambition**: designed Artifactory-style as one artifact space — pub ships first; npm, cargo and other formats plug in later behind the same orgs, tokens, unified search (`format:` filter), proxy policy, and audit ([decision 21](decisions.md#21--multi-format-artifact-space-pub-first-npm-cargo--later)).
- **Organizations**: users belong to many orgs; cumulative role levels Read / Write / Admin / Owner (extensible, decision 19); email invitations; per-org virtual registry URL (`/o/<org>`) that serves org packages + instance-public packages + proxied pub.dev with deterministic local-always-wins resolution.
- **Visibility**: public and private packages; anonymous read of public/proxied content (configurable off).
- **Proxy & replication**: read-through pub.dev cache with sha256 verification and stale-serving, plus a mirror mode where a sync worker pulls upstream changes proactively.
- **Auth**: self-written — email OTP always available; zero or more configurable OIDC providers (Google preset, any compliant IdP); optional TOTP 2FA; instance-level sign-in domain policy (e.g. corporate accounts only); JWT access + refresh sessions; scoped CLI/API tokens (`dart pub token add`).
- **Search**: full-text package search with pub.dev-style filter tags.
- **Live events & notifications**: SSE stream from the backend (publishes, org events, shadowing alarms, announcements) feeding a per-user notification center with unread counts and per-category preferences; email for high-importance events.
- **Integrations**: one domain event bus behind SSE/notifications also powers outbound HMAC-signed webhooks per org (v1.1) and richer integrations later (Slack/Telegram templates, CI triggers).
- **Account & statistics**: account settings (profile, linked providers, 2FA, sessions, tokens, notification preferences, data export/deletion); download statistics per package/version with org and instance dashboards.
- **Admin**: runtime-changeable instance settings (SMTP, limits, proxy policy, branding — default name "Pub", white-label) via admin UI; user/org management; package moderation; audit log viewer; instance stats; rate limiting.
- **Web app**: Astro landing/docs (SSG, 10 locales, light/dark) + SolidJS PWA application; package pages with backend-rendered README/CHANGELOG.

## Screens (v1)

Home (top / popular / recently-updated packages, instance stats), login (configured OIDC providers + email OTP), search with filters, package page (readme / changelog / example / installing / versions tabs), org pages (packages, members & invitations, tokens, settings, audit), account (profile, security & 2FA, sessions, tokens, notification preferences, data export/deletion), notification center, admin panel (runtime settings incl. branding, users & orgs, package moderation, proxy policy, audit viewer, stats dashboard), plus 404 and offline PWA fallbacks.

## Feature triage

**V1 (roadmap steps 8–9):**

1. Spec-v2 endpoints + 3-step publish flow + legacy download routes; verified E2E against the real `dart pub` client.
2. CLI tokens with scopes, expiry, last-used, show-once UX.
3. Orgs, roles, invitations, per-org virtual URLs, name-claim table + shadowing alerts.
4. Read-through proxy with byte-identical caching; mirror sync worker.
5. Web UI: the full v1 screen set (see Screens) — home with tops, search, package pages, org/token/session management, account, notification center, admin panel.
6. SSE event stream + notification center; basic download statistics (daily rollups, package counters).
7. Security baseline: audit log (append-only), rate limits with anti-lockout, anti-enumeration, step-up auth, sign-in domain policy, retract + gated hard delete.
8. Observability: `/healthz` always on; Prometheus metrics and OTLP export optional, config-gated (decision 23); structured tracing.

**V1.1 (fast follow):** OSV advisories endpoint + upstream advisory relay, WebAuthn/passkeys, token expiry notification emails, upstream `delay` quarantine mode, download charts (weekly per version), outbound webhooks (HMAC-signed, per-org, delivery log), pub.dev-shaped `/score` and `/metrics` endpoints with stubbed payloads (ecosystem tooling reads them; real pana data comes later).

**Later (enterprise tier):** npm & cargo protocol modules (single artifact space, decision 21), dartdoc hosting per version, pana scoring + score API compatibility, teams within orgs + per-package grants, SAML/OIDC enterprise SSO + SCIM, audit streaming to SIEM, upstream allowlist mode, block/quarantine of upstream versions by CVE severity or license, org name-prefix reservations, trusted publishing (CI OIDC token exchange with repo/tag binding), Slack/Telegram integration templates, SLSA/Sigstore provenance, CycloneDX SBOM export, air-gap bundle sync, Helm chart.

**Deliberately not doing:** Flutter Favorites (Google program), Search-Console-style domain verification (orgs replace publishers), Google-account coupling, likes across the public internet.

## Non-functional requirements

- **Deployment gradient**: `docker run` one container (SQLite + fs + in-memory) → compose with Postgres/MinIO/Redis → replicated multi-instance (Redis mandatory, stateless app tier; Helm chart planned — see feature triage). Same binary everywhere.
- **Industrial security posture**: OWASP ASVS L2 as the self-assessment checklist; NIST 800-63B-aligned authenticator policy; see [security.md](security.md).
- **Corporate compliance surface**: append-only audit, retention policies, GDPR-ish account deletion with anonymized publish-history tombstones, data export.
- **Lightweight frontend**: SSG-first, one app island, no UI framework bloat, tight bundle budgets (roadmap step 8 wires the budgets into CI).
- **Test discipline**: everything testable is tested, corner cases first-class — protocol conformance suite, RBAC matrix, auth flows, both DB backends in CI, real-`dart pub` integration job.

## References

- Roadmap (10 steps, foundation before features): https://wiki.plugfox.dev/s/website-roadmap — step 6 "Firebase" is replaced by our self-hosted backend environment; product features start at steps 8–9.
- Idea/patterns reference: https://github.com/PlugFox/foxic (`/Users/fox/git/foxic`) — same author and stack; we lift its best patterns (docs governance, token scheme, cursor pagination, CI job shape) and fix its known weaknesses (no infra abstraction, per-process state, no integration tests, CI committing version bumps to master — we derive versions from git tags instead, see decision 18).
- Protocol: `dart-lang/pub` `doc/repository-spec-v2.md`; sharp edges catalogued in [protocol.md](protocol.md).
