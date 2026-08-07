// Placeholder service worker mirroring the real build's shape (decision 14 offline shell).
// The Docker build overwrites this directory with web/apps/site/dist; the integration suite
// asserts /sw.js is served with a CSP whose connect-src 'self' lets install succeed.
self.addEventListener("install", (event) => {
  event.waitUntil(caches.open("pub-shell").then((cache) => cache.addAll(["/"])));
});
self.addEventListener("fetch", (event) => {
  event.respondWith(caches.match(event.request).then((hit) => hit || fetch(event.request)));
});
