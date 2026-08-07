import { playwright } from "@vitest/browser-playwright";
import solid from "vite-plugin-solid";
import { defineConfig } from "vitest/config";

/*
 * Component tests in a real browser (vitest browser mode, headless Chromium
 * via the playwright provider — the browser binaries are the ones
 * @playwright/test already caches).
 *
 * Naming contract: browser tests are `test/browser/*.vitest.{ts,tsx}`. The
 * `.vitest.` suffix keeps them OUT of `bun test`, which auto-discovers
 * `*.test.*` / `*_test.*` / `*.spec.*` / `*_spec.*` — the two runners must
 * never pick up each other's files (bun cannot execute Solid JSX or real
 * CSS animations; vitest must not re-run the happy-dom suites).
 */
export default defineConfig({
  plugins: [solid()],
  test: {
    include: ["test/browser/**/*.vitest.{ts,tsx}"],
    // Browser mode ignores `environment`, but vite-plugin-solid defaults it
    // to jsdom when unset (without checking browser.enabled), which makes
    // vitest demand the uninstalled jsdom package and exit nonzero.
    environment: "node",
    browser: {
      enabled: true,
      headless: true,
      provider: playwright(),
      instances: [{ browser: "chromium" }],
      screenshotFailures: false,
    },
  },
});
