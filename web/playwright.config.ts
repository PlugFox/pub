import { defineConfig, devices } from "@playwright/test";

/*
 * End-to-end runs against a real browser (decision 41).
 *
 * OPT-IN, NOT A CI LEG — the same stance as the cluster acceptance stand
 * (decision 38): it needs browser binaries and a served production build, and
 * roadmap item 7 owns wiring the E2E suite into CI. Run it with
 * `just web-e2e`, or `bunx playwright test` from `web/`.
 *
 * THE BUILD MUST BE PRODUCTION. The service worker is registered only under
 * `import.meta.env.PROD` so the dev loop never fights a stale cache, which
 * makes `astro preview` over `dist` the only server these specs can use — and
 * `dist/sw.js` only exists after `bun run build` has run this repo's own
 * worker build step.
 *
 * NAMING CONTRACT: specs are `*.e2e.ts`, never `*.spec.ts`. `bun test`
 * auto-discovers `*.test.*` and `*.spec.*`, and a Playwright spec picked up by
 * Bun's runner fails in a way that looks like a broken test rather than a
 * misrouted file — the same trap `packages/ui/vitest.config.ts` documents for
 * its `.vitest.` suffix.
 */
export default defineConfig({
  testDir: "apps/site/test/e2e",
  testMatch: "**/*.e2e.ts",
  fullyParallel: false,
  reporter: "list",
  use: {
    baseURL: "http://localhost:4321",
    // A service worker needs a secure context; `localhost` is one.
    ...devices["Desktop Chrome"],
  },
  webServer: {
    command: "bun run --filter @pub/site preview",
    url: "http://localhost:4321/",
    // A preview server left running from a dev session is reused rather than
    // fought over. `just web-e2e` rebuilds first, and `astro preview` reads
    // `dist` per request, so a reused server still serves the fresh build.
    reuseExistingServer: true,
    timeout: 60_000,
  },
});
