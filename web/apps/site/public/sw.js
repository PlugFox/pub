/*
 * Hand-rolled service worker (decision 14; no workbox). Skeleton tier:
 * precache the app shell, serve it as offline fallback for navigations.
 * Later roadmap steps add SWR for metadata APIs, cache-first for immutable
 * per-version artifacts, and network-only for auth — per the policy in
 * docs/architecture.md ("Frontend workspace").
 */
const VERSION = "v1";
const SHELL_CACHE = `pub-shell-${VERSION}`;
// Entry points precached at install: landing page and app shell.
const SHELL_URLS = ["/", "/app/"];

self.addEventListener("install", (event) => {
  event.waitUntil(
    caches
      .open(SHELL_CACHE)
      .then((cache) => cache.addAll(SHELL_URLS))
      .then(() => self.skipWaiting()),
  );
});

self.addEventListener("activate", (event) => {
  event.waitUntil(
    caches
      .keys()
      .then((keys) =>
        Promise.all(keys.filter((k) => k !== SHELL_CACHE).map((k) => caches.delete(k))),
      )
      .then(() => self.clients.claim()),
  );
});

self.addEventListener("fetch", (event) => {
  const request = event.request;
  if (request.method !== "GET") return; // never intercept mutations
  const url = new URL(request.url);
  if (url.origin !== self.location.origin) return; // same-origin only

  // Navigations: network first; offline falls back to the cached shell —
  // /app/* falls back to the app shell, everything else to the landing page.
  if (request.mode === "navigate") {
    event.respondWith(
      fetch(request).catch(async () => {
        const cache = await caches.open(SHELL_CACHE);
        const shell = url.pathname.startsWith("/app") ? "/app/" : "/";
        return (await cache.match(shell)) ?? Response.error();
      }),
    );
  }
  // Everything else passes through untouched (asset policies come later).
});
