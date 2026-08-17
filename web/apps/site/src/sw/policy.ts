/*
 * Service-worker routing policy (decision 41).
 *
 * A PURE FUNCTION, deliberately. The worker itself is a handful of event
 * listeners that cannot be run by `bun test`; the table of what is cached, what
 * is revalidated and — most importantly — what is never touched is the part
 * that must not drift, so it lives here, takes plain values, and is tested
 * exhaustively including the cases whose correct behaviour is *inaction*.
 *
 * Four rules are load-bearing and each exists for a stated reason:
 *
 *  1. **The API and pub planes are passed through untouched.** Every app-API
 *     response carries `Cache-Control: no-store` (S-28), those responses are
 *     personalized — a Cache API entry outlives the session that earned it and
 *     is readable by the next person on the profile — and `GET /api/v1/events`
 *     is a long-lived SSE stream (decision 20) that must never be wrapped in
 *     `respondWith`. This is why decision 14's "SWR for metadata" clause was
 *     withdrawn rather than implemented.
 *  2. **`_astro/*` is cache-first**, because the content hash is in the
 *     filename and the wire tier is `immutable` for a year: a hit cannot be
 *     stale, and this is what makes a lazily-loaded screen work offline once it
 *     has been opened.
 *  3. **Locales, icons and the manifest revalidate.** They are the cached
 *     resources that are NOT content-addressed — a deploy changes their bytes
 *     at a stable URL — so serving from cache while refreshing behind it is the
 *     only shape that cannot pin a stale translation.
 *  4. **Navigations are network-first.** The fallback is a document, and which
 *     document depends on the path: under `/app` the prerendered shell, which
 *     mounts the island and renders its own chrome; everywhere else `/offline`.
 *
 * The plane predicates mirror the server's `family_of` (`api/src/hygiene.rs`)
 * to the byte, including the bare `/api` and the per-org registry base
 * `/o/{org}/pub` (decision 01). A client that disagreed with the server about
 * where the pub plane starts would cache a protocol response.
 */

/** What the worker does with a request. */
export const STRATEGY = {
  /** Not intercepted at all — the worker calls no `respondWith`. */
  passthrough: "passthrough",
  /** Network first; on failure, a precached document. */
  navigate: "navigate",
  /** Cache first; only content-addressed URLs qualify. */
  cacheFirst: "cache-first",
  /** Cache first, refreshed in the background. */
  revalidate: "stale-while-revalidate",
} as const;

export type Strategy = (typeof STRATEGY)[keyof typeof STRATEGY];

/** The slice of `Request` the policy reads; keeps the tests plain objects. */
export type RoutedRequest = {
  readonly url: string;
  readonly method: string;
  /** `Request.mode`; `"navigate"` for document loads. */
  readonly mode: string;
};

/** The prerendered island shell, and the fallback for every client-routed path. */
export const APP_SHELL = "/app/";
/** The styled offline document, and the fallback for every other navigation. */
export const OFFLINE_DOCUMENT = "/offline";

/** Immutable, content-addressed build output (`_astro/App.B3adkQxQ.js`). */
const HASHED_ASSET_PREFIX = "/_astro/";

/** Non-content-addressed static files worth keeping across a lost connection. */
const REVALIDATED_PREFIXES = ["/locales/", "/icons/"];
const REVALIDATED_PATHS = ["/manifest.webmanifest", "/robots.txt"];

/** Whether `pathname` is on the pub protocol plane (mirrors the server's `family_of`). */
function isPubPlane(pathname: string): boolean {
  if (pathname === "/pub" || pathname.startsWith("/pub/")) return true;
  const rest = pathname.startsWith("/o/") ? pathname.slice(3) : null;
  if (rest === null) return false;
  const [org, base] = rest.split("/");
  return org !== undefined && org !== "" && base === "pub";
}

/** Whether `pathname` is on the app-API plane (mirrors the server's `is_app_api`). */
function isAppApi(pathname: string): boolean {
  return pathname === "/api" || pathname.startsWith("/api/");
}

/**
 * Whether the worker must keep its hands off this path entirely.
 *
 * `/healthz` joins the two request planes because it is a liveness probe: an
 * answer from a cache is the one answer it must never give.
 */
function isNeverCached(pathname: string): boolean {
  return isAppApi(pathname) || isPubPlane(pathname) || pathname === "/healthz";
}

/**
 * The strategy for one request, given the worker's own origin.
 *
 * Order matters: method and origin are checked before anything path-shaped, and
 * the never-cached planes are checked before the navigation rule — a document
 * navigation to an API path is still an API request.
 */
export function route(request: RoutedRequest, origin: string): Strategy {
  // A mutation is not cacheable, and a worker that answers one has changed what
  // the server was asked to do.
  if (request.method !== "GET") return STRATEGY.passthrough;

  let url: URL;
  try {
    url = new URL(request.url);
  } catch {
    return STRATEGY.passthrough;
  }

  // Cross-origin: an OIDC provider, or the presigned archive URL a redirect
  // hands the client (decision 34) — a bearer capability nothing may retain.
  if (url.origin !== origin) return STRATEGY.passthrough;

  if (isNeverCached(url.pathname)) return STRATEGY.passthrough;

  if (request.mode === "navigate") return STRATEGY.navigate;

  if (url.pathname.startsWith(HASHED_ASSET_PREFIX)) return STRATEGY.cacheFirst;

  if (REVALIDATED_PATHS.includes(url.pathname)) return STRATEGY.revalidate;
  if (REVALIDATED_PREFIXES.some((prefix) => url.pathname.startsWith(prefix))) {
    return STRATEGY.revalidate;
  }

  // Anything else same-origin — a document fetched by script, a file added to
  // `public/` after this was written — is left to the network. A worker that
  // caches by default caches something it was never designed to serve stale.
  return STRATEGY.passthrough;
}

/**
 * The precached document a failed navigation falls back to.
 *
 * Under `/app` the answer is the shell rather than the offline page, because
 * the shell boots the island: the reader gets the app's own chrome and its own
 * offline reporting instead of a dead end. This mirrors the server's fallback
 * ladder, which serves the same shell for every unknown `/app/*` path.
 */
export function offlineDocumentFor(pathname: string): string {
  return pathname === "/app" || pathname.startsWith("/app/") ? APP_SHELL : OFFLINE_DOCUMENT;
}
