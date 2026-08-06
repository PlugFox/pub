# Changelog

All notable changes to this project. Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versioning: SemVer per component — server crate and web package are versioned independently. Entries are tagged `(server)`, `(web)`, `(infra)`, `(docs)`.

## 2026-08-07 — v1 authentication complete: multi-provider OIDC, TOTP second factor, step-up

Design refinements recorded in [docs/decisions.md](docs/decisions.md) (decision 12 addendum) and as amendments S-01.a, S-02.a, S-05.a, S-06.a in [docs/security.md](docs/security.md).

### Added

- (server) **Multi-provider OIDC sign-in** (S-01/S-02, [auth/src/oidc.rs](server/crates/auth/src/oidc.rs)): zero or more providers from boot config (`[[auth.oidc]]`: id, display_name, issuer, client_id, client_secret, scopes — none configured = email OTP only); discovery + JWKS cached with bounded TTL, keys strictly by `kid` with exactly one refetch on rotation; flows bound by an opaque server-side `flow_id` (KV: 256-bit single-use `state`, `nonce`, PKCE S256 verifier, 10-min TTL, burned on first presentation); confidential-client code exchange server-side only; id_token validation with `alg` pinned to the discovery-advertised ∩ {RS256, ES256} (`none`/`HS*` structurally rejected), `iss`/`aud`+`azp`/`exp`/`iat` ±30 s, constant-time `nonce`/`state` compares. Identity keyed `(iss, sub)`; auto-link only when both the IdP email and the local account email are verified, with `credential.linked` audit + notification mail (S-02); S-31 domain gate at every OIDC sign-in; every auth failure is one uniform 401 with the reason confined to the audit log. Endpoints: `GET /api/v1/auth/providers` (public), `POST /api/v1/auth/oidc/{provider}/start`, `POST /api/v1/auth/oidc/{provider}/callback` (both on the S-24 login bucket; unknown provider → 404).
- (server) **TOTP second factor** (S-05, [auth/src/totp.rs](server/crates/auth/src/totp.rs)): RFC 6238 (SHA-1, 30 s, 6 digits, 160-bit seed, ±1 step skew; verified against the RFC test vectors), last-accepted-step replay floor enforced twice — in verification and as a single-statement compare-and-set in the credential repo (migration `0003_totp`, both backends); seed AES-256-GCM-sealed with the new boot KEK (`auth.kek`, production-required, `_FILE`-capable, masked in the summary); 10 single-use argon2id-hashed recovery codes shown once at confirm; enrollment parked in KV until a live code proves the authenticator. Logins of enrolled accounts (OTP *and* OIDC) return `mfa_required + mfa_token` instead of tokens; `POST /api/v1/auth/totp/verify` completes them. ≤5 failed TOTP/recovery/step-up attempts per scope, then exponential backoff (2 s doubling, 10-min cap, 429 + `Retry-After`, audit-logged) on the MFA step only. Endpoints: `POST /api/v1/auth/totp/{enroll,confirm,verify}`, `DELETE /api/v1/auth/totp` (step-up-gated).
- (server) **Step-up "sudo mode"** (S-06): sessions are step-up-fresh for `auth.step_up_minutes` (default 15) after login or after `POST /api/v1/auth/step-up` (TOTP or recovery code); the `StepUp` extractor + `require_step_up` helper gate `DELETE /api/v1/auth/totp`, minting `publish`/`admin` CLI tokens, and `POST /api/v1/sessions/revoke-all`, answering the distinct `step_up_required` 403 (new `Error::StepUpRequired`); accounts without a second factor re-auth by fresh login; the remaining S-06 actions are placeholder-documented to take the guard as their endpoints land.
- (server) `CredentialRepo` second-factor surface (`create_totp`, `find_totp`, atomic `commit_totp_step`, `replace_recovery_codes`, `list_recovery_codes`, atomic `consume_recovery_code`, `delete_second_factor`) implemented for SQLite and Postgres with a shared contract test; `TotpCredential`/`RecoveryCodeHash` domain structs with redacting `Debug` (S-25.a).
- (server) 45 tests: 14 OIDC integration tests against an in-process mock issuer (axum on a loopback port serving discovery/JWKS/token, signing real RS256 id_tokens; PKCE + client secret enforced at exchange) — happy path, linking matrix, state replay/tamper, nonce mismatch, `alg:none`/HS256/rogue-signature forgeries, expired/future/aud-mismatched tokens, unknown-kid refetch-once + rotation, S-31, closed registration; 10 MFA/step-up integration tests — enroll→confirm→login, encrypted-at-rest assertion, ±1/±2 skew, replay floor, recovery single-use, six-failure backoff growth, all three step-up gates incl. window expiry; plus TOTP/OIDC unit tests (RFC 6238 vectors, seal/open tamper cases, backoff curve, base32 round-trips) and config validation for `auth.kek`/`auth.oidc`/`auth.step_up_minutes`.

### Changed

- (server) `POST /api/v1/auth/otp/verify` (and the OIDC callback) now answer a discriminated login shape: `mfa_required: false` + token pair, or `mfa_required: true` + `mfa_token` — clients must branch on `mfa_required`. `POST /api/v1/sessions/revoke-all` and publish/admin-scope `POST /api/v1/tokens` now require step-up freshness (S-06).
- (server) `AuthService::new` takes the `OidcClient`; `AuthPolicy` carries the KEK, step-up window, and TOTP issuer label.

## 2026-08-06 — auth slice: adversarial security review

Findings from an attack-oriented review of the just-landed auth slice. Every fix ships with the attack that motivated it ([api/tests/attack.rs](server/crates/api/tests/attack.rs), 20 tests); the normative consequences are recorded as amendments S-03.a, S-04.a, S-12.a, S-24.a/b and S-25.a in [docs/security.md](docs/security.md).

### Security

- (server) **OTP attempt budget was not atomic.** The ≤5-wrong-attempts counter lived inside the pending-auth record and was read-modify-written per verification, so guesses fired in parallel shared a single increment and the budget bounded nothing. The counter moved to its own KV key behind a new atomic `Kv::incr` primitive (Redis `INCR`+`PEXPIRE`, moka per-key upsert), and the attempt is now spent **before** the code is compared (S-03/S-03.a).
- (server) **`X-Forwarded-For` was trusted unconditionally, leftmost hop first.** Every S-24 per-IP limit could be bypassed by rotating the header, and any address's bucket and audit trail could be poisoned by claiming to be it — including behind a correctly configured reverse proxy, where the leftmost entry is exactly the client-supplied one. New `server.trust_proxy_headers` (default **false**) ignores forwarding headers in favour of the socket peer; when enabled it reads the **rightmost** entry. `pubd` now serves with connect-info so a peer address exists (S-24.a/b).
- (server) **Credential redemption had no rate limit.** `POST /api/v1/auth/otp/verify` and `/auth/refresh` were unthrottled, so the per-code ≤5 budget was sidestepped by simply requesting fresh codes. Both now carry S-24's "login 10/min/IP" bucket (`auth.rate_limit.login_per_ip_minute`).
- (server) **Secrets were reachable through derived `Debug`.** The OTP pepper, JWT signing seeds, SMTP password, S3 keys, connection-URL passwords, minted token secrets and the access/refresh pair were all printable via a stray `{:?}`, `#[instrument]` field or panic message — S-25 masking covered only the startup summary. Configured secrets now use a `Secret` newtype (redacting `Debug`, no `Display`, explicit `.expose()`); `DatabaseConfig`/`KvConfig` mask their URLs; `AuthPolicy`, `LoginSuccess`, `MintedToken` and `SmtpSettings` hand-write redacting `Debug` (S-25.a).
- (server) **S-31 was enforced at registration but not at sign-in.** An account whose domain had since left the allowlist could still redeem a valid code; `verify_otp` now applies the domain gate to existing accounts too, with the same uniform `invalid_code` rejection (S-04).
- (server) **S-12's server-side `Origin`/`Sec-Fetch-Site` verification was missing** — only the custom header was checked, leaving CSRF defence entirely to the browser. `/api/` mutations now compare the parsed `Origin` triple against `server.public_url` and reject non-same-site `Sec-Fetch-Site`, while header-less CLI/CI clients keep working (S-12.a).
- (server) **Anti-enumeration timing.** `request_otp` no longer skips the account lookup and template render for policy-rejected addresses; all branches perform identical server-side work. The remaining SMTP-hand-off asymmetry is documented as an accepted, bounded risk with its planned mitigation (S-04.a).

### Added

- (server) `Kv::incr` — atomic counter with TTL on the KV seam, contracted as atomic because authentication budgets are decided by its return value.
- (server) `_FILE`-suffixed environment variables (S-25): secrets read from mounted files with trailing newlines trimmed; unreadable paths and the ambiguous "both `X` and `X_FILE` set" case are startup errors.
- (server) `RequestMeta` typed extractor replacing ad-hoc `HeaderMap` plumbing, so handlers cannot reach for a raw forwarding header instead of the resolved client identity.
- (server) 39 tests: the 20-test adversarial suite (JWT algorithm confusion with the Ed25519 public key as HMAC secret, `alg:none`, unknown `kid`; parallel OTP guessing; resend-rewind of the attempt budget; KV-outage fail-closed on both the access-token and OTP paths; concurrent refresh races; refresh-plaintext persistence; bundled `admin` scope escalation; forwarded-header spoofing and poisoning; cross-site mutations; post-policy domain sign-in) plus KV atomicity, config secret-redaction, `_FILE` handling, and JWT claim-set assertions.

## 2026-08-06 — auth vertical slice: email OTP, sessions/JWT, CLI tokens

### Added

- (server) `pub-auth` crate ([crates/auth](server/crates/auth/)): Ed25519 JWT keyring with strict-`kid` resolution, pinned `EdDSA`, ±30 s skew, and rotation overlap (S-07/S-27); email OTP primitives — 8-digit CSPRNG codes, peppered HMAC-SHA-256 storage form, constant-time compare, KV pending-auth records under opaque 128-bit ids with 10-min TTL, ≤5 attempts, ≥60 s resend that invalidates the prior code, single-use (S-03); CLI-token format `pub_` + 30 base62 + CRC32 checksum with offline validation, SHA-256 at rest, first-8 display hint (S-13, decisions 13/17); fixed-window KV rate counters (S-24); and the `AuthService` flow facade (request/verify OTP, refresh with reuse-revokes-family, logout/revoke with DB + KV-blocklist revocation per S-08/S-09, org-role-gated token minting through `authorize()`), all clock-injected and audit-logging (`auth.otp.requested`, `auth.login.success/failure`, `auth.throttled`, `session.revoked`, `token.created/revoked`).
- (server) `pub-mail` crate: `SmtpMailer` (lettre, rustls, tls/starttls/none) and `InMemoryMailer` test/dev double behind the core `Mailer` trait (new `send_multipart` with plain-text fallback); askama text+HTML templates for the OTP email rendering code, requester IP, and expiry minutes.
- (server) App API auth surface ([crates/api](server/crates/api/)): `POST /api/v1/auth/otp/{request,verify}` (uniform anti-enumeration responses incl. domain-allowlist rejections — S-04/S-31; every OTP failure is the same `invalid_code` 401), `POST /api/v1/auth/refresh` (`refresh_reused` 401 on reuse), `POST /api/v1/auth/logout`, session management (`GET /api/v1/sessions` with current flag, `DELETE /api/v1/sessions/{sid}`, `POST /api/v1/sessions/revoke-all` — S-09/S-10), CLI tokens (`POST/GET /api/v1/tokens`, `DELETE /api/v1/tokens/{id}` — show-once secret, S-13), and minimal orgs (`POST/GET /api/v1/orgs`); `AuthContext` extractor verifying Bearer JWTs against the keyring plus the revoked-`sid` KV fast path that fails closed with 503 on KV loss (S-09); S-12 mutation guard (`X-Pub-Request: 1` + JSON-only bodies) and a KV-backed per-IP OTP rate-limit layer with 429 + `Retry-After` (S-24); `bearer_auth` scheme registered in OpenAPI.
- (server) Config: `server.mode` (`dev`/`production`), `[auth]` section (access TTL capped at 15 min per S-07, refresh idle/absolute days, OTP pepper, token prefix, registration flag, S-31 email-domain allowlist, JWT signing/verify keys with seed validation, S-24 rate-limit numbers) and `[smtp]` section; production mode refuses to boot without pepper/signing key (S-25), dev mode falls back to loud ephemeral secrets in `pubd`; effective-config summary masks all new secrets.
- (server) 15 integration tests over the full in-memory stack with an injected clock ([api/tests/auth.rs](server/crates/api/tests/auth.rs)), security behavior named by requirement: S-03 (happy path/single-use, attempt exhaustion, resend), S-04, S-31, S-07, S-08, S-09, S-12, S-13 (×2 + scope gating), S-24, plus session and org happy paths.

### Changed

- (server) `core::Error` gained `Unauthorized`, `InvalidCode`, and `RateLimited` variants (stable codes `unauthorized`/`invalid_code`/`rate_limited`); the API error mapper turns them into 401/401/429 (+`Retry-After`) and maps KV failures to 503 (fail closed).
- (server) `AppState` now carries the `AuthService` and an injectable clock; `pubd` builds the mailer (SMTP when configured, in-memory with a warning otherwise) and the auth service at startup.

## 2026-08-06 — Postgres identity backend

### Added

- (server) Complete PostgreSQL implementations of all seven identity & access repositories ([db-postgres/src/repo/](server/crates/db-postgres/src/repo/)), replacing the live-ping stubs: native `UUID`/`TIMESTAMPTZ` binds, `INET`/`JSONB` round-tripped as text casts, and `SELECT … FOR UPDATE` row locks serializing the ≥1-Owner invariant, single-use invitation acceptance, and refresh rotation under Postgres' concurrent writers (SQLite's single writer needs none).
- (server) The shared repository contract suite now runs against Postgres ([db-tests/tests/postgres.rs](server/crates/db-tests/tests/postgres.rs)): gated at runtime by `PUB_TEST_POSTGRES_URL` (skip note on stderr when unset, no ignore attributes), one throwaway migrated database per test.
- (infra) `server-ci.yml` test job carries a health-checked `postgres:17-alpine` service container and exports `PUB_TEST_POSTGRES_URL`, so the Postgres contract suite runs on every server CI build.

## 2026-08-06 — design system & UI kit

### Added

- (web) Visual source of truth [web/DESIGN.md](web/DESIGN.md): product-SaaS mood, OKLCH token tables for light/dark, type scale (Inter + JetBrains Mono), 4px rhythm, radii/elevation rules, component specs, Do/Don't catalog, agent pre-commit checklist.
- (web) Finalized design tokens: refined neutral ramp + indigo/violet accent, status colors (success/warning/danger), radius and font-family tokens; [contrast-check script](web/packages/tokens/scripts/contrast-check.ts) asserting WCAG AA 4.5:1 for 44 ink/surface pairs in both themes, wired into `bun run check`.
- (web) Self-hosted fonts via fontsource: Inter Variable + JetBrains Mono (latin/latin-ext/cyrillic/cyrillic-ext woff2 subsets, critical subset preloaded, zero external requests in dist).
- (web) UI kit first tranche in [packages/ui](web/packages/ui/): Button, Input, Label, Card, Badge, Skeleton, Separator, Kobalte-based Dialog and Tooltip, restyled ThemeToggle; `/ui-kit` showcase page (robots-disallowed).
- (web) SaaS landing: gradient hero with CTA, 4-card feature grid, footer — fully i18n'd (new `landing` namespace with `desc` per key, real Russian translations; landing critical path ~82 KB gzip).

### Fixed

- (web) Contrast checker silently validated the light palette twice (selector lookup matched a header comment); the dark theme is now genuinely checked.

## 2026-08-06 — identity & access data layer

### Added

- (server) Identity & access data layer: full repository trait sets in `core` ([UserRepo, CredentialRepo, OrgRepo, SessionRepo, TokenRepo, AuditRepo, SettingsRepo](server/crates/core/src/traits.rs)) with domain types for users, polymorphic credentials (`oidc|email|totp|recovery|webauthn`), orgs/memberships/invitations, rotating refresh sessions with reuse detection (S-08), scoped CLI tokens (S-13), ULID-keyed append-only audit events (S-22), and versioned settings; the single [`authorize()` chokepoint](server/crates/core/src/authorize.rs) with role-ladder boundary tests (decision 19).
- (server) Migration `0002_identity` in both backends ([sqlite](server/crates/db-sqlite/migrations/0002_identity.sql), [postgres](server/crates/db-postgres/migrations/0002_identity.sql)): users, credentials, orgs, org_members, invitations, sessions, tokens, audit_log, settings — case-insensitive unique emails/slugs, partial indexes for active-token/active-session lookups, Postgres INSERT-only audit role template.
- (server) Complete SQLite implementations of all seven repositories ([db-sqlite/src/repo/](server/crates/db-sqlite/src/repo/)); Postgres ships live-ping stubs until its query implementations land.
- (server) Shared repository contract suite ([db-tests](server/crates/db-tests/)) run against SQLite `:memory:` — last-Owner invariant, invitation expiry/double-accept, refresh-reuse detection, cursor-pagination stability, and more.

### Changed

- (server) `/healthz` now live-pings the database (plus blob and KV) and reports per-backend `checks` instead of echoing only configured kinds; `AppState` carries the repository bundle.

## 2026-08-06 — design phase

### Added

- (docs) Design documentation: product vision and feature triage ([docs/product.md](docs/product.md)), architecture ([docs/architecture.md](docs/architecture.md)), decision log with 23 decisions ([docs/decisions.md](docs/decisions.md)), normative security requirements S-01…S-33 ([docs/security.md](docs/security.md)), pub protocol sharp edges ([docs/protocol.md](docs/protocol.md)).
- (docs) Contributor/agent governance: [CLAUDE.md](CLAUDE.md), [AGENTS.md](AGENTS.md), code conventions in [docs/rules/](docs/rules/).
- (infra) Repository scaffolding: `.gitignore`, `.editorconfig`, `.dockerignore`.
- (server) Cargo workspace skeleton — 13 crates per [docs/architecture.md](docs/architecture.md): `core` (domain types, `RoleLevel` 0/50/100/200/250, 12 backend traits), `config` (layered `defaults → TOML → PUB_* env → CLI` with validation incl. the replicas>1-requires-Redis rule), `db-sqlite`/`db-postgres` (pools + initial migrations), `blob` (object_store fs/memory/S3), `kv` (moka + broadcast broker; deadpool-redis skeleton), `telemetry` (tracing; config-gated Prometheus recorder), `jobs` (leader-locked interval scheduler), `api` (axum + utoipa: `/healthz`, `/api/v1/ping`, `/api/openapi.json`, embedded static with SPA fallback, security headers), `bin/pubd` (backend selection, migrations, graceful shutdown, build-info). 81 tests green; fmt/clippy clean.
- (web) Bun workspaces skeleton — `apps/site` (Astro 7.2 + Solid 1.9 island under `/app`, 10-locale i18n routing, anti-FOUC theme script, manifest + service worker), `packages/tokens` (OKLCH light/dark `@theme`), `packages/i18n` (YAML + `desc`, Bun codegen, dependency-free runtime with `Intl.PluralRules`), `packages/ui` (`cn()`, Button, ThemeToggle), `packages/api` (interceptor-chain client, `ApiError`/`NetworkError`). TypeScript 7.0.2 native; 19 tests green; Biome clean. Note: `astro check` waits for TS 7.1 API.
- (infra) CI: path-filtered `server-ci.yml` (fmt/clippy/test, rust-cache) and `web-ci.yml` (check/build/test, setup-bun) with minimal permissions and concurrency-cancel. Docker: 4-stage single-image build (web dist embedded into the Rust binary per decision 04), compose profiles `pg`/`s3`/`redis`/`full` with zero-config defaults.
