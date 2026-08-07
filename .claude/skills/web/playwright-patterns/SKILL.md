---
name: playwright-patterns
description: Write robust @playwright/test specs for the Pub web app — role-based locators, web-first assertions, fixtures, traces, bun-runner coexistence, both themes via data-theme. Use when writing an E2E spec, creating the Playwright config, or when asked to "automate" a UI flow.
---

# Playwright Patterns (Pub web)

**Source:** ported from foxic `client/playwright-patterns`; originally adapted from [currents-dev/playwright-best-practices](https://skills.sh/currents-dev/playwright-best-practices-skill/playwright-best-practices), [microsoft/playwright-cli](https://skills.sh/microsoft/playwright-cli/playwright-cli), and the [Playwright best-practices docs](https://playwright.dev/docs/best-practices).

**Status:** `@playwright/test` is a dev dep in `web/package.json`; there is **no config and no suite yet**. This skill sets the conventions for when specs land — don't assume files exist; create them per the layout below.

## Pub specifics — read before writing the first spec

- **Bun runner coexistence.** `bun test` (the `web` test pipeline) discovers `*.test.*` and `*.spec.*` anywhere. Playwright specs must stay out of that glob: put them in `web/e2e/`, name them `*.e2e.ts`, and point the config at them (`testDir: "e2e"`, `testMatch: "**/*.e2e.ts"`). Never name an E2E file `*.test.ts` or `*.spec.ts` — bun would try to run it and fail on Playwright globals.
- **Target the Astro build preview.** Production is SSG output served statically ([decision 04](../../../../docs/decisions.md)), so specs run against the built site, not `astro dev`. In `web/playwright.config.ts`:

  ```ts
  webServer: {
    command: "bun run --filter @pub/site preview",  // requires a prior `bun run build`
    url: "http://localhost:4321",
    reuseExistingServer: !process.env.CI,
  },
  ```

  Preview serves **static output only** — same-origin `/api/v1` has no backend there. Against preview you can cover: static pages, `/ui-kit`, island mount, client routing, themes, and anything with `page.route()` stubs. API-backed flows need the embedded-server run (see [verify-ui-browser](../verify-ui-browser/SKILL.md), full-stack mode, port 8080) as `baseURL`.
- **Both themes.** Theme = `localStorage["pub_theme"]` → `data-theme` on `<html>` (anti-FOUC script in the base layout). Parametrize as two Playwright projects (or a fixture) using `addInitScript` to set the key before any page script runs, then assert `await expect(page.locator("html")).toHaveAttribute("data-theme", "dark")`. `emulateMedia({ colorScheme })` only affects the "system" branch — setting the key explicitly is deterministic.
- **Auth plane.** Web sessions are JWT in localStorage, never cookies (docs/security.md). `storageState` captures localStorage, so a logged-in state can be saved once in a setup project and reused — but prefer real login through the API over hand-crafting what `packages/api` storage expects.
- Browsers install with `bunx playwright install --with-deps chromium`; run with `bunx playwright test` from `web/` (add a `test:e2e` script when the suite lands — do not wire it into `bun test`).

## Locators — in priority order

1. **`page.getByRole(role, { name })`** — mirrors assistive tech, survives CSS/DOM refactors.
2. **`getByLabel`** (form fields), **`getByPlaceholder`** (last resort for inputs).
3. **`getByText`** for static, visible content.
4. **`getByTestId`** (`data-testid`) only when the above cannot disambiguate.
5. **CSS/XPath** — last resort; brittle. If you reach for `.nth(2)` or `:nth-child`, the test design is wrong.

```ts
await page.getByRole("button", { name: /create organization/i }).click();
await page.getByLabel("Name").fill("acme");
await expect(page.getByRole("heading", { name: "acme" })).toBeVisible();
```

For whole-region structure checks, `expect(locator).toMatchAriaSnapshot()` asserts the accessibility tree in one step — one snapshot beats five chained text assertions.

## Web-first assertions — never poll manually

Playwright's `expect()` auto-retries. Don't build your own wait loops.

- `await expect(locator).toBeVisible()` / `.toHaveText(...)` / `.toHaveCount(n)`
- `await expect(page).toHaveURL(...)`

**Banned:**

- `await page.waitForTimeout(2000)` — replace with a web-first assertion on the thing you're waiting for. One exception: deliberately testing a time-based delay (prefer the [clock API](https://playwright.dev/docs/clock) even then).
- Manual `while` loops polling `locator.count()`.
- `expect(await locator.isVisible()).toBe(true)` (no retry) in place of `toBeVisible()` (retries).

## Isolation

- **One test = one user journey.** Don't chain six features into one spec.
- **Fresh context per test.** The default `test` fixture isolates storage/cookies per test; don't share state via module globals.
- **Seed state through the API, not the UI.** Creating an org via UI in every test is slow and brittle. When running against the real server, set up over HTTP with the `request` fixture, then load the page to assert.
- **Unique test data** — generate names from `test.info().title` or `crypto.randomUUID()`; no ordering assumptions between tests.

## Fixtures

Use `test.extend()` for shared setup (theme, auth state, seeded data, API stubs). Put them in `web/e2e/fixtures.ts`; specs import `test`/`expect` from there, never a global singleton.

## Tracing / debugging

- `trace: "on-first-retry"` and `screenshot: "only-on-failure"` in the config; CI gets a trace artifact when a test flakes.
- `bunx playwright show-trace trace.zip` locally; `bunx playwright test --ui` for the time-travel UI mode.
- `page.pause()` drops into the inspector during development — remove before commit.
- HTML reporter in CI (`--reporter=html`) so failures come with an artifact.

## Network

- `page.route()` to stub `/api/v1/*` in a unit-y spec against preview. For integration specs, hit the real embedded server.
- `page.waitForResponse()` only when the request itself is the assertion — usually a web-first assertion on the resulting DOM is better.

## Flake-resilience

- **Handle animations.** Kobalte primitives animate open/close; web-first assertions absorb this — assert the final state (`toBeVisible()`), never mid-transition.
- `force: true` on `.click()` almost always hides a real bug (overlay, disabled, offscreen) — don't.
- Don't assert implementation details (class names, DOM structure) — couples the spec to the markup; roles and text survive refactors.

## In-conversation verification is a different tool

Claude-driven walkthroughs of a change use the **claude-in-chrome MCP**, not Playwright — see [verify-ui-browser](../verify-ui-browser/SKILL.md). This skill is for the committed, repeatable `@playwright/test` suite.

## Related

- [verify-ui-browser](../verify-ui-browser/SKILL.md) — golden-path browser walkthrough for in-conversation verification.
- [docs/rules/web.md](../../../../docs/rules/web.md) — frontend conventions, incl. the `bun test` pipeline these specs must stay out of.
- [web/DESIGN.md](../../../../web/DESIGN.md) — visual source of truth; §9 pre-commit checklist.
- [/web-check](../../../commands/web-check.md) — the gate that runs `check`/`build`/`bun test` (E2E stays separate).
