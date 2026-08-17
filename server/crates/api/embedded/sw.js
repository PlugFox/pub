// Placeholder service worker mirroring the real build's shape (decision 41).
// The Docker build overwrites this directory with web/apps/site/dist, whose sw.js is bundled
// from web/apps/site/src/sw/ with a precache manifest generated from that build — every asset
// name in it is a content hash, so nothing committed here can name them. This file exists so
// the embedded tree has the same shape as a real one; the integration suite asserts /sw.js is
// served with a CSP whose connect-src 'self' lets the install populate its cache.
const CACHE = "pub-placeholder";

self.addEventListener("install", (event) => {
  event.waitUntil(caches.open(CACHE).then((cache) => cache.addAll(["/"])));
});

self.addEventListener("fetch", (event) => {
  // GET only, same-origin only, and never the request planes: the real worker's
  // rules, reduced to the one document this placeholder has.
  const request = event.request;
  if (request.method !== "GET" || request.mode !== "navigate") return;
  event.respondWith(
    fetch(request).catch(async () => {
      const cache = await caches.open(CACHE);
      return (await cache.match("/", { ignoreVary: true })) ?? Response.error();
    }),
  );
});
