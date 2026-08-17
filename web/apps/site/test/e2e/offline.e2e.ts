import { expect, test } from "@playwright/test";

/*
 * The claim D17 was filed against, checked in a real browser (decision 41).
 *
 * "Offline, `/app/` loads a document whose 14 eager chunks and stylesheet are
 * uncached — a blank unstyled page." Unit tests can prove the routing table and
 * the generated manifest; only a browser can prove that a worker installed from
 * that manifest actually serves the shell when the network is gone, which is
 * why this leg exists at all.
 *
 * Each test installs the worker from a live page, then cuts the network on the
 * browser context — `setOffline` fails requests at the transport, so the
 * worker's `fetch` rejects exactly as it would on a train.
 */

/** Resolves once the worker is active AND has claimed this page. */
async function serviceWorkerControls(page: import("@playwright/test").Page): Promise<void> {
  await page.evaluate(() => navigator.serviceWorker.ready.then(() => undefined));
  await page.waitForFunction(() => navigator.serviceWorker.controller !== null);
}

test.describe("offline", () => {
  test("the app shell boots from the precache with no network", async ({ page, context }) => {
    await page.goto("/app/");
    await serviceWorkerControls(page);

    await context.setOffline(true);
    await page.reload();

    // The chrome is what D17 said was missing: a `<header>` means the island
    // mounted, which means its fifteen eager modules came out of the cache.
    await expect(page.getByRole("banner")).toBeVisible();

    // And it is styled — the stylesheet is a precached entry like any other, so
    // a transparent body would mean the document was served without it.
    const background = await page.evaluate(() => getComputedStyle(document.body).backgroundColor);
    expect(background).not.toBe("rgba(0, 0, 0, 0)");
  });

  test("a deep app link offline still lands on the shell", async ({ page, context }) => {
    await page.goto("/app/");
    await serviceWorkerControls(page);

    await context.setOffline(true);
    // Never precached as a document of its own: the worker's navigation
    // fallback maps everything under /app onto the shell, and the router reads
    // the address bar from there.
    await page.goto("/app/orgs/acme");

    await expect(page.getByRole("banner")).toBeVisible();
    expect(new URL(page.url()).pathname).toBe("/app/orgs/acme");
  });

  test("a non-English reader keeps their language with the network gone", async ({ browser }) => {
    // The other half of this item (decision 15): the ten locale dictionaries
    // the codegen has written since the first slice, fetched for the first
    // time — and then served from the worker's cache.
    const context = await browser.newContext({ locale: "ru-RU", baseURL: "http://localhost:4321" });
    const page = await context.newPage();
    const fetched: string[] = [];
    page.on("request", (request) => {
      if (request.url().includes("/locales/")) fetched.push(new URL(request.url()).pathname);
    });

    await page.goto("/app/");
    await page.waitForFunction(() => document.documentElement.lang === "ru");
    expect(fetched).toContain("/locales/ru/app.json");
    await serviceWorkerControls(page);

    // One load under a controlling worker before the network goes. On the very
    // FIRST visit the island's locale fetch happens while the worker is still
    // installing, so it never passes through `fetch` and is never cached — the
    // same property a lazily-loaded screen has, and the reason this reload is
    // here rather than an oversight in the test.
    await page.reload();
    await page.waitForFunction(() => document.documentElement.lang === "ru");

    await context.setOffline(true);
    await page.reload();

    // `lang` only becomes `ru` when the dictionaries were actually registered.
    // Offline that can only have come from the cache: a failed fetch falls back
    // to the bundled English, which would leave this `en`.
    await page.waitForFunction(() => document.documentElement.lang === "ru");
    await context.close();
  });

  test("a navigation outside /app falls back to the offline document", async ({
    page,
    context,
  }) => {
    await page.goto("/");
    await serviceWorkerControls(page);

    await context.setOffline(true);
    await page.goto("/security");

    // English: the static pages are single-locale until roadmap item 6.
    await expect(page.getByRole("heading", { name: "You are offline" })).toBeVisible();
  });
});
