/*
 * The service worker entry (decision 41). Hand-rolled, no workbox.
 *
 * Everything interesting about *what* is cached lives in `policy.ts`, which is
 * a pure function under `bun test`. This file is the part a test runner cannot
 * execute: the three lifecycle listeners and the four strategies they dispatch.
 *
 * ONE CACHE PER BUILD, `pub-<version>`, holding both the generated precache and
 * whatever a session picks up as it goes. Two caches — a shell one and a
 * runtime one — is the obvious shape and it is wrong: every read then has to
 * ask both in the right order, a refreshed copy written to one is shadowed by
 * the stale copy in the other, and the offline run caught precisely that (the
 * precached chunks were invisible to the cache-first read, so `/app/` offline
 * was still the blank page D17 describes). One cache means one `match` and one
 * `put`, and the whole class of bug is gone.
 *
 * A deploy produces a new cache NAME rather than mutating entries, so `activate`
 * sweeps by deleting everything that is not the current one.
 *
 * NO `skipWaiting()`, AND THAT IS THE POINT. A new worker installs, fills its
 * cache and waits for the last tab running the old one to go away. Taking over
 * immediately would delete — via that same sweep — the hashed chunks an open tab
 * has not fetched yet, so a reader who opens the admin screen minutes after a
 * deploy would get a failed dynamic import on a page that was working. The cost
 * is stated in decision 41: a deploy reaches an open tab on its next full load,
 * not the current session.
 *
 * `__PUB_PRECACHE__` and `__PUB_VERSION__` are substituted by
 * `scripts/build-sw.ts` at build time, because every asset name in the manifest
 * is a content hash and no committed file can name them.
 */
import { OFFLINE_DOCUMENT, offlineDocumentFor, route, STRATEGY } from "./policy";

declare const __PUB_PRECACHE__: readonly string[];
declare const __PUB_VERSION__: string;

/** The worker's own global, typed — `lib.webworker` declares `self` more loosely. */
const worker = self as unknown as ServiceWorkerGlobalScope;

const CACHE = `pub-${__PUB_VERSION__}`;

/**
 * Every read of our own cache ignores `Vary`, and this is load-bearing.
 *
 * `cache.addAll` issues **no-cors** requests, which carry no `Origin` header. A
 * module script and a `crossorigin` font are **cors** requests, which do. Any
 * `Vary: Origin` on the stored response — a dev server's CORS middleware, an
 * `nginx` in front of the instance, `Vary: Accept-Encoding` from a compressing
 * proxy — then makes those two requests miss an entry that is right there, and
 * offline they fall through to a network that is not answering.
 *
 * The offline run caught exactly that: the shell document and its stylesheet
 * (no-cors) were served from the cache while `App.js`, `client.js` and the
 * preloaded font (cors) failed, which is the blank page D17 describes with the
 * cache full. We control every URL we store, and none of them varies by
 * anything, so honouring `Vary` here buys nothing and costs the whole feature.
 */
const MATCH: CacheQueryOptions = { ignoreVary: true };

worker.addEventListener("install", (event) => {
  // `addAll` is atomic: one unreachable entry fails the install and the old
  // worker keeps serving, which is the right outcome — a half-filled cache is a
  // blank page waiting for the next disconnection.
  event.waitUntil(caches.open(CACHE).then((cache) => cache.addAll([...__PUB_PRECACHE__])));
});

worker.addEventListener("activate", (event) => {
  event.waitUntil(sweepOldCaches());
});

worker.addEventListener("fetch", (event) => {
  const { request } = event;
  const strategy = route(
    { url: request.url, method: request.method, mode: request.mode },
    worker.location.origin,
  );

  switch (strategy) {
    case STRATEGY.passthrough:
      return;
    case STRATEGY.navigate:
      event.respondWith(networkFirst(request));
      return;
    case STRATEGY.cacheFirst:
      event.respondWith(cacheFirst(request));
      return;
    case STRATEGY.revalidate:
      event.respondWith(staleWhileRevalidate(event, request));
      return;
  }
});

/** Drops every cache from an older build, then adopts the pages already open. */
async function sweepOldCaches(): Promise<void> {
  const names = await caches.keys();
  await Promise.all(names.filter((name) => name !== CACHE).map((name) => caches.delete(name)));
  // Only reaches an uncontrolled page — the very first load after registration.
  // Without `skipWaiting` there is no live tab here to yank a worker out from
  // under.
  await worker.clients.claim();
}

/**
 * Documents: the network decides, and a failure falls back to a precached page.
 *
 * A successful navigation is deliberately not written to the cache. The
 * precache is generated per build; a document captured at runtime would name
 * hashed assets that the sweep above may already have removed.
 */
async function networkFirst(request: Request): Promise<Response> {
  try {
    return await fetch(request);
  } catch {
    const cache = await caches.open(CACHE);
    const fallback = await cache.match(offlineDocumentFor(new URL(request.url).pathname), MATCH);
    return fallback ?? (await cache.match(OFFLINE_DOCUMENT, MATCH)) ?? Response.error();
  }
}

/**
 * Content-addressed assets: a hit can never be stale, so it is never revalidated.
 *
 * The hit may be a precached entry (the shell's eager graph) or one this session
 * put there itself (a lazily-loaded screen) — the same cache holds both, which
 * is what makes the first offline reload work at all: nothing had ever been
 * written at runtime by then.
 */
async function cacheFirst(request: Request): Promise<Response> {
  const cache = await caches.open(CACHE);
  const hit = await cache.match(request, MATCH);
  if (hit !== undefined) return hit;

  try {
    const response = await fetch(request);
    if (isStorable(response)) await cache.put(request, response.clone());
    return response;
  } catch {
    // Same outcome the page would get with no worker installed: a failed
    // subresource, reported by whatever asked for it.
    return Response.error();
  }
}

/**
 * Stable-URL statics: serve what we have, refresh behind it.
 *
 * `waitUntil` keeps the worker alive for the background request — without it a
 * worker that goes idle right after responding would cancel the refresh and the
 * cache would never move forward.
 */
async function staleWhileRevalidate(event: FetchEvent, request: Request): Promise<Response> {
  const cache = await caches.open(CACHE);
  const hit = await cache.match(request, MATCH);

  const refresh = fetch(request).then(async (response) => {
    if (isStorable(response)) await cache.put(request, response.clone());
    return response;
  });

  if (hit !== undefined) {
    event.waitUntil(refresh.then(noop, noop));
    return hit;
  }
  return refresh.catch(() => Response.error());
}

/**
 * Whether a response may be written to a cache.
 *
 * `status === 200` excludes both the error responses nobody wants pinned and
 * the `206` partials the Cache API refuses outright; `type === "basic"` keeps
 * opaque cross-origin responses out, which the policy should already have
 * prevented — this is the second lock on the thing that must not happen.
 */
function isStorable(response: Response): boolean {
  return response.status === 200 && response.type === "basic";
}

function noop(): void {}
