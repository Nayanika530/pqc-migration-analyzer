const CACHE_NAME = "pqc-analyzer-cache-v1";
const urlsToCache = [
    "/",
    "/analyze",
    "/manual",
    "/scan",
    "/static/style.css",
    "/static/home.css",
    "/static/analyze.css"
];

// When the service worker installs, pre-cache the core pages/assets
self.addEventListener("install", (event) => {
    event.waitUntil(
        caches.open(CACHE_NAME).then((cache) => cache.addAll(urlsToCache))
    );
});

// When a request happens, try cache first, fall back to network
self.addEventListener("fetch", (event) => {
    event.respondWith(
        caches.match(event.request).then((cachedResponse) => {
            return cachedResponse || fetch(event.request);
        })
    );
});

// Clean up old caches when a new version activates
self.addEventListener("activate", (event) => {
    event.waitUntil(
        caches.keys().then((cacheNames) => {
            return Promise.all(
                cacheNames
                    .filter((name) => name !== CACHE_NAME)
                    .map((name) => caches.delete(name))
            );
        })
    );
});