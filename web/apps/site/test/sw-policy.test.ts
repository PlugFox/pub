import { describe, expect, test } from "bun:test";
import type { Strategy } from "../src/sw/policy";
import { offlineDocumentFor, route, STRATEGY } from "../src/sw/policy";

/*
 * The service worker's routing table (decision 41).
 *
 * Half of these assertions are about the worker doing NOTHING, and those are
 * the ones that matter most: a rule that starts caching the API plane leaks a
 * personalized response into a cache that outlives the session, and a rule that
 * wraps the SSE stream in `respondWith` breaks realtime in a way no other test
 * in this project would see.
 */

const ORIGIN = "https://pub.example";

function strategyFor(path: string, init: { method?: string; mode?: string } = {}): Strategy {
  const { method = "GET", mode = "cors" } = init;
  return route({ url: `${ORIGIN}${path}`, method, mode }, ORIGIN);
}

describe("the planes the worker never touches", () => {
  test("every app-API path is passed through, including the bare /api", () => {
    // S-28 gives all of these `Cache-Control: no-store`, and they are
    // personalized — decision 41 withdrew decision 14's SWR clause for exactly
    // this reason.
    for (const path of ["/api", "/api/v1/home", "/api/v1/me", "/api/openapi.json"]) {
      expect(strategyFor(path)).toBe(STRATEGY.passthrough);
    }
  });

  test("the SSE stream is passed through rather than answered", () => {
    // A long-lived ReadableStream (decision 20) must never be wrapped in
    // `respondWith`.
    expect(strategyFor("/api/v1/events")).toBe(STRATEGY.passthrough);
  });

  test("the pub protocol plane is passed through, plainly and per-org", () => {
    for (const path of [
      "/pub",
      "/pub/api/packages/http",
      "/o/acme/pub/api/packages/http",
      "/o/acme/pub",
    ]) {
      expect(strategyFor(path)).toBe(STRATEGY.passthrough);
    }
  });

  test("a path that only looks like an org registry is not the pub plane", () => {
    // `/o/acme/pubx` and `/o//pub` are Family::Other on the server — an
    // ordinary document lookup — and a client that read them as the protocol
    // plane would refuse to serve the offline fallback for a page the server
    // considers a page.
    expect(strategyFor("/o/acme/pubx/thing", { mode: "navigate" })).toBe(STRATEGY.navigate);
    expect(strategyFor("/o//pub", { mode: "navigate" })).toBe(STRATEGY.navigate);
  });

  test("the health probe is never answered from a cache", () => {
    expect(strategyFor("/healthz")).toBe(STRATEGY.passthrough);
  });

  test("mutations are passed through on every plane", () => {
    for (const method of ["POST", "PUT", "PATCH", "DELETE", "HEAD"]) {
      expect(strategyFor("/_astro/App.hash.js", { method })).toBe(STRATEGY.passthrough);
      expect(strategyFor("/app/", { method, mode: "navigate" })).toBe(STRATEGY.passthrough);
    }
  });

  test("cross-origin requests are passed through", () => {
    // A presigned archive URL (decision 34) is a bearer capability, and an OIDC
    // provider is somebody else's origin.
    const presigned = "https://blobs.example/archives/http-1.0.0.tar.gz?X-Amz-Signature=abc";
    expect(route({ url: presigned, method: "GET", mode: "cors" }, ORIGIN)).toBe(
      STRATEGY.passthrough,
    );
  });

  test("an unparseable URL is passed through instead of throwing", () => {
    expect(route({ url: "not a url", method: "GET", mode: "cors" }, ORIGIN)).toBe(
      STRATEGY.passthrough,
    );
  });
});

describe("what the worker does cache", () => {
  test("hashed build output is cache-first", () => {
    expect(strategyFor("/_astro/App.B3adkQxQ.js")).toBe(STRATEGY.cacheFirst);
    expect(strategyFor("/_astro/base-layout.CvuWbbBu.css")).toBe(STRATEGY.cacheFirst);
    expect(strategyFor("/_astro/inter-latin-wght-normal.Dx4kXJAl.woff2")).toBe(STRATEGY.cacheFirst);
  });

  test("locales revalidate, because their bytes change at a stable URL", () => {
    expect(strategyFor("/locales/ru/app.json")).toBe(STRATEGY.revalidate);
    expect(strategyFor("/locales/zh-Hans/common.json")).toBe(STRATEGY.revalidate);
  });

  test("the manifest, the icons and robots.txt revalidate", () => {
    expect(strategyFor("/manifest.webmanifest")).toBe(STRATEGY.revalidate);
    expect(strategyFor("/icons/icon.svg")).toBe(STRATEGY.revalidate);
    expect(strategyFor("/robots.txt")).toBe(STRATEGY.revalidate);
  });

  test("navigations are network-first wherever they point", () => {
    for (const path of ["/", "/app/", "/app/orgs/acme", "/security", "/nope"]) {
      expect(strategyFor(path, { mode: "navigate" })).toBe(STRATEGY.navigate);
    }
  });

  test("a navigation to an API path is still an API request", () => {
    // The plane check runs before the navigation rule; the other order would
    // answer `/api/v1/me` with a cached HTML document.
    expect(strategyFor("/api/v1/me", { mode: "navigate" })).toBe(STRATEGY.passthrough);
  });

  test("anything else same-origin is left to the network", () => {
    // A worker that caches by default caches something it was not designed to
    // serve stale.
    expect(strategyFor("/.well-known/security.txt")).toBe(STRATEGY.passthrough);
    expect(strategyFor("/favicon.ico")).toBe(STRATEGY.passthrough);
  });

  test("a query string does not change the strategy", () => {
    expect(strategyFor("/locales/ru/app.json?v=2")).toBe(STRATEGY.revalidate);
    expect(strategyFor("/api/v1/packages?q=http")).toBe(STRATEGY.passthrough);
  });
});

describe("the document a failed navigation falls back to", () => {
  test("everything under /app falls back to the shell, which boots the island", () => {
    for (const path of ["/app", "/app/", "/app/search", "/app/orgs/acme"]) {
      expect(offlineDocumentFor(path)).toBe("/app/");
    }
  });

  test("everything else falls back to the offline document", () => {
    for (const path of ["/", "/security", "/ui-kit", "/apples"]) {
      expect(offlineDocumentFor(path)).toBe("/offline");
    }
  });
});
