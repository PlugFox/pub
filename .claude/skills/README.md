# Pub Claude Code Skills

Auto-loaded skills for Claude Code in this repo. Claude picks a skill when the user's request matches its `description` in the frontmatter — you don't invoke them by hand (slash commands below are the exception).

This file is the index. Each row names the skill, says what it does, and cites where the content came from. The skills are **not** the source of truth: [docs/decisions.md](../../docs/decisions.md), [docs/security.md](../../docs/security.md) (S-01…S-33), [docs/protocol.md](../../docs/protocol.md), [docs/rules/](../../docs/rules/) and [web/DESIGN.md](../../web/DESIGN.md) are normative — skills summarize and link to them, never duplicate or contradict them. When a skill and a normative doc disagree, the doc wins and the skill is a bug.

## Conventions for skills in this repo

- Frontmatter has `name` + `description` only. The description is a one-line trigger hint — Claude reads it to decide relevance.
- Body starts with a **Source** line citing the origin (this batch was ported from the foxic repo's skills and re-grounded in pub's docs and code).
- Cross-references use relative markdown links.
- Each skill ends with a "Related" section linking sibling skills and in-repo docs.
- Meta and infra skills live at the top level. Server-specific skills live under `server/`, frontend-specific under `web/`.

## Slash commands

Explicitly invoked, defined in [.claude/commands/](../commands/):

| Command | Purpose |
|---|---|
| [/server-check](../commands/server-check.md) | Server pipeline: `cargo fmt --check` → `cargo clippy --all-targets -- -D warnings` → `cargo test --workspace`. |
| [/web-check](../commands/web-check.md) | Web pipeline: `bun run check` (typecheck, Biome, contrast gate) → `bun run build` → `bun test`. |
| [/db-up](../commands/db-up.md) | Start optional dev containers (Postgres/MinIO/Redis). The default dev loop needs **no** containers. |
| [/new-migration](../commands/new-migration.md) | Create a paired forward-only migration (SQLite + Postgres, same `NNNN`). |

## Index

### Meta

| Skill | Purpose | Source |
|---|---|---|
| [verify-changes](verify-changes/SKILL.md) | Picks the right validation pipeline (`/server-check`, `/web-check`) from what changed; regenerates i18n/API artifacts first. | Ported from foxic `verify-changes`. |
| [commit-message](commit-message/SKILL.md) | Writes Conventional Commit messages with pub's scopes and the CHANGELOG-in-same-commit rule. | Ported from foxic `commit-message`. |
| [release-notes](release-notes/SKILL.md) | Maintains `CHANGELOG.md`; explains why pub has no version-bump step (version derives from the git tag). | Adapted from foxic `bump-version` — the bump flow itself does not exist in pub. |
| [review-pr](review-pr/SKILL.md) | Reviews a PR / diff against the rule docs, S-01…S-33, decisions, and pub-protocol sharp edges. | Ported from foxic `review-pr`. |

### Server (Rust · axum · sqlx runtime · SQLite+Postgres)

| Skill | Purpose | Source |
|---|---|---|
| [server/add-api-route](server/add-api-route/SKILL.md) | New HTTP route: pick the API family (app envelope vs pub protocol), register via utoipa, authorize at the chokepoint, update the route-inventory test, regen frontend types. | Ported from foxic; re-grounded in [docs/rules/api.md](../../docs/rules/api.md). |
| [server/add-migration](server/add-migration/SKILL.md) | Paired forward-only migration in both `db-sqlite` and `db-postgres` (same `NNNN`), applied at startup via `sqlx::migrate!`. | Ported from foxic; rewritten for pub's dual-dialect, no-`.down.sql` model per [docs/rules/migrations.md](../../docs/rules/migrations.md). |
| [server/sqlx-query](server/sqlx-query/SKILL.md) | Runtime `sqlx::query`/`query_as` (no `query!` macros, no `.sqlx` cache), dual-dialect repos behind `core` traits, contract-tested in `db-tests`. | Ported from foxic — and **inverted**: foxic mandates compile-time macros; pub deliberately does not. |
| [server/rust-error-handling](server/rust-error-handling/SKILL.md) | `pub_core::Error` with stable codes, `ApiError` envelope mapping, `ProtocolError` spec shapes, no `anyhow` in libraries. | Ported from foxic; rewritten around pub's real error types. |
| [server/rust-async-tokio](server/rust-async-tokio/SKILL.md) | Cancel-safety, `select!`, `spawn_blocking`, timeouts at boundaries, `JobLock`-guarded background loops, graceful shutdown. | [wshobson/agents — rust-async-patterns](https://skills.sh/wshobson/agents/rust-async-patterns) + [Tokio docs](https://tokio.rs/tokio/topics), via foxic. |
| [server/rust-testing](server/rust-testing/SKILL.md) | Test taxonomy: unit, dual-backend contract suite (`db-tests`, Postgres leg via `PUB_TEST_POSTGRES_URL`), HTTP integration, protocol conformance, S-xx security, jobs. | [affaan-m/everything-claude-code — rust-testing](https://skills.sh/affaan-m/everything-claude-code/rust-testing), via foxic; rebuilt around pub's taxonomy. |
| [server/postgres-optimization](server/postgres-optimization/SKILL.md) | EXPLAIN (ANALYZE, BUFFERS), (partial) indexes, N+1, keyset pagination — without breaking the SQLite twin or the contract suite. | [github/awesome-copilot — postgresql-optimization](https://skills.sh/github/awesome-copilot/postgresql-optimization) + [Postgres performance tips](https://www.postgresql.org/docs/current/performance-tips.html), via foxic. |

### Web (SolidJS · Astro · Kobalte · Tailwind 4)

| Skill | Purpose | Source |
|---|---|---|
| [web/add-solid-component](web/add-solid-component/SKILL.md) | Components per project rules: `splitProps` (never destructure), CVA recipe, `cn()`, Kobalte subpath imports, mandatory ui-kit showcase entry. | Ported from foxic `client/add-solid-component`. |
| [web/add-app-screen](web/add-app-screen/SKILL.md) | New screen in the SolidJS island: screen file, lazy `Route` in `App.tsx`, guard class, `createAsync` + `query` (no `createResource`), i18n, prerendered shell path. | Adapted from foxic `client/add-feature-module` — pub has no `features/` layer; the unit is a screen. |
| [web/add-i18n-string](web/add-i18n-string/SKILL.md) | i18n key in YAML (en + mandatory `desc`) → `bun run i18n:gen` → typed `t()`/`tp()` descriptors. | Ported from foxic `client/add-i18n-string`; adapted to pub's codegen flow. |
| [web/tailwind-styling](web/tailwind-styling/SKILL.md) | Tailwind 4 CSS-first: semantic token utilities from `packages/tokens/theme.css`, CVA vs inline, no arbitrary values / `!important` / hex. | [Tailwind v4 docs](https://tailwindcss.com/docs/theme) + [cva.style](https://cva.style/docs), via foxic. |
| [web/typography-scale](web/typography-scale/SKILL.md) | Fixed type scale with breakpoint jumps, never `clamp()`; Inter Variable for UI, JetBrains Mono one step smaller for code. | [impeccable.style](https://impeccable.style/) (`/typeset`), via foxic; mirrors [web/DESIGN.md](../../web/DESIGN.md) §3. |
| [web/design-anti-patterns](web/design-anti-patterns/SKILL.md) | Anti-attractor catalogue, pub edition: no multi-hue gradients, no nested cards, no low contrast, no emoji-only states. | [impeccable.style](https://impeccable.style/) (Gallery of Shame), via foxic. |
| [web/ui-accessibility](web/ui-accessibility/SKILL.md) | Semantic HTML, correct ARIA, keyboard-only flows, Kobalte focus management, the machine-enforced contrast gate, reduced-motion. | [WCAG 2.2](https://www.w3.org/TR/WCAG22/) + [Kobalte a11y](https://kobalte.dev/docs/core/overview/introduction) + [WAI-ARIA APG](https://www.w3.org/WAI/ARIA/apg/patterns/), via foxic. |
| [web/ui-critique](web/ui-critique/SKILL.md) | UI review: Nielsen heuristics, cognitive load, mandatory five-state coverage, P0–P3 severity. | [impeccable.style](https://impeccable.style/) + [NN/g 10 heuristics](https://www.nngroup.com/articles/ten-usability-heuristics/), via foxic. |
| [web/seo-meta](web/seo-meta/SKILL.md) | SEO for the static Astro pages only: title/description via BaseLayout, robots scope, groundwork for OG / canonical / JSON-LD / sitemap / hreflang. | [aaron-he-zhu/seo-geo-claude-skills](https://skills.sh/aaron-he-zhu/seo-geo-claude-skills/meta-tags-optimizer) + [addyosmani — seo](https://skills.sh/addyosmani/web-quality-skills/seo) + [Google Search Central](https://developers.google.com/search/docs), via foxic. |
| [web/verify-ui-browser](web/verify-ui-browser/SKILL.md) | Walks a changed UI flow in real Chrome via the claude-in-chrome MCP: golden path + one edge case, both themes, mobile viewport. | Adapted from foxic `client/verify-ui-playwright` — pub verifies in the user's Chrome, not a Playwright-driven browser. |
| [web/playwright-patterns](web/playwright-patterns/SKILL.md) | Conventions for the `@playwright/test` suite as it lands: role-based locators, web-first assertions, fixtures, traces, bun-runner coexistence (`web/e2e/*.e2e.ts`). | [currents-dev/playwright-best-practices](https://skills.sh/currents-dev/playwright-best-practices-skill/playwright-best-practices) + [microsoft/playwright-cli](https://skills.sh/microsoft/playwright-cli/playwright-cli) + [Playwright best-practices](https://playwright.dev/docs/best-practices), via foxic. |

### Infra

| Skill | Purpose | Source |
|---|---|---|
| [docker-multi-stage](docker-multi-stage/SKILL.md) | Evolves pub's single-image build (web dist → cargo dep cache → `pubd` binary → alpine runtime): cache mounts, layer ordering, multi-arch, SBOM. | [github/awesome-copilot — multi-stage-dockerfile](https://skills.sh/github/awesome-copilot/multi-stage-dockerfile) + [sickn33 — docker-expert](https://skills.sh/sickn33/antigravity-awesome-skills/docker-expert), via foxic; refreshed against [docs.docker.com](https://docs.docker.com/build/). |

## Companion documents

Normative — skills defer to these, never restate them:

- [docs/decisions.md](../../docs/decisions.md) — 23 numbered architecture decisions; contradicting one requires discussion, never silent deviation.
- [docs/security.md](../../docs/security.md) — S-01…S-33 security requirements, referenced from test names.
- [docs/protocol.md](../../docs/protocol.md) — pub protocol sharp edges; violating one breaks real `dart pub` clients.
- [docs/rules/](../../docs/rules/) — [rust.md](../../docs/rules/rust.md), [web.md](../../docs/rules/web.md), [migrations.md](../../docs/rules/migrations.md), [api.md](../../docs/rules/api.md).
- [web/DESIGN.md](../../web/DESIGN.md) — visual source of truth (tokens, type scale, component specs, pre-commit visual checklist).
- [CLAUDE.md](../../CLAUDE.md) — project-wide engineering instructions; [AGENTS.md](../../AGENTS.md) — the deeper agent guide.

## Sources for this batch

This batch (August 2026) was ported from the foxic repo's `.claude/skills/` — same author, similar stack — with every skill re-verified against pub's code and normative docs. Where the stacks diverge, pub's reality won; the notable divergences are recorded below.

| Source | Used | Notes |
|---|---|---|
| foxic `.claude/skills/` | yes | Origin of the entire batch. Divergences from the originals: `sqlx-query` **inverted** (pub uses runtime queries — no `query!` macros, no `.sqlx` cache, no `cargo sqlx prepare`); `add-migration` rewritten for dual-dialect forward-only pairs (no `.down.sql`, no manual apply); `add-feature-module` → `add-app-screen` (no `features/` layer); `verify-ui-playwright` → `verify-ui-browser` (claude-in-chrome MCP instead of Playwright MCP); `bump-version` → `release-notes` (no version-bump flow); `client/` → `web/`. |
| [impeccable.style](https://impeccable.style/) | yes | `design-anti-patterns`, `ui-critique`, `typography-scale` (all via foxic); principles also echoed in `web/DESIGN.md`. |
| [wshobson/agents — rust-async-patterns](https://skills.sh/wshobson/agents/rust-async-patterns) + [Tokio docs](https://tokio.rs/tokio/topics) | yes | `rust-async-tokio`. |
| [affaan-m/everything-claude-code — rust-testing](https://skills.sh/affaan-m/everything-claude-code/rust-testing) | yes | `rust-testing`, rebuilt around pub's test taxonomy. |
| [github/awesome-copilot — postgresql-optimization](https://skills.sh/github/awesome-copilot/postgresql-optimization) + [Postgres performance tips](https://www.postgresql.org/docs/current/performance-tips.html) | yes | `postgres-optimization`, with pub's dual-dialect caveats added. |
| [currents-dev/playwright-best-practices](https://skills.sh/currents-dev/playwright-best-practices-skill/playwright-best-practices) + [microsoft/playwright-cli](https://skills.sh/microsoft/playwright-cli/playwright-cli) + [playwright.dev](https://playwright.dev/docs/best-practices) | yes | `playwright-patterns` — written ahead of the suite (`@playwright/test` is a dev dep; no config or specs yet). |
| [github/awesome-copilot — multi-stage-dockerfile](https://skills.sh/github/awesome-copilot/multi-stage-dockerfile) + [sickn33 — docker-expert](https://skills.sh/sickn33/antigravity-awesome-skills/docker-expert) + [docs.docker.com](https://docs.docker.com/build/) | yes | `docker-multi-stage`, retargeted at pub's existing single-image Dockerfile. |
| [aaron-he-zhu/seo-geo-claude-skills](https://skills.sh/aaron-he-zhu/seo-geo-claude-skills/meta-tags-optimizer) + [addyosmani/web-quality-skills](https://skills.sh/addyosmani/web-quality-skills) + [Google Search Central](https://developers.google.com/search/docs) | yes | `seo-meta`, rescoped to the static Astro pages (the `/app` island is not indexable by design). |
| [WCAG 2.2](https://www.w3.org/TR/WCAG22/) + [Kobalte docs](https://kobalte.dev/docs/core/overview/introduction) + [WAI-ARIA APG](https://www.w3.org/WAI/ARIA/apg/patterns/) | yes | `ui-accessibility`, wired to pub's machine-enforced contrast gate. |
| [Tailwind CSS v4 docs](https://tailwindcss.com/docs/theme) + [cva.style](https://cva.style/docs) | yes | `tailwind-styling`. |
| [NN/g — 10 Usability Heuristics](https://www.nngroup.com/articles/ten-usability-heuristics/) | yes | `ui-critique`. |
| [Conventional Commits](https://www.conventionalcommits.org/) | yes | `commit-message`. |
