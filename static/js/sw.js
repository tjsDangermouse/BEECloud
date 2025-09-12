// Simple Service Worker: cache-first for static, stale-while-revalidate for key APIs
const VERSION = 'v2';
const STATIC_CACHE = `static-${VERSION}`;
const RUNTIME_CACHE = `runtime-${VERSION}`;

const STATIC_ASSETS = [
  '/static/css/app.css',
  '/static/css/tailwind.css',
  '/static/js/menu.js',
  '/static/js/status.js',
  '/static/js/sw-register.js',
  '/static/Beelogo.png'
];

const API_SWRE = [
  '/api/data',
  '/api/energy-stats',
  '/api/data/hourly-temperature-summary',
  '/api/data/daily-temperature-summary',
  '/api/data/weekly-temperature-summary',
  '/api/data/daily-energy-summary',
  '/api/data/monthly-energy-summary',
  '/api/connection-status',
  '/api/weather',
  '/api/devices/minimal'
];

self.addEventListener('install', (event) => {
  event.waitUntil((async () => {
    const cache = await caches.open(STATIC_CACHE);
    try { await cache.addAll(STATIC_ASSETS); } catch (e) {}
    self.skipWaiting();
  })());
});

self.addEventListener('activate', (event) => {
  event.waitUntil((async () => {
    const keys = await caches.keys();
    await Promise.all(keys.map(k => {
      if (!k.includes(VERSION)) return caches.delete(k);
    }));
    self.clients.claim();
  })());
});

function isApiSWRE(url) {
  return API_SWRE.some(path => url.pathname.startsWith(path));
}

self.addEventListener('fetch', (event) => {
  const req = event.request;
  if (req.method !== 'GET') return;
  const url = new URL(req.url);

  // Navigation requests: network-first, avoid caching redirects
  if (req.mode === 'navigate') {
    event.respondWith((async () => {
      try {
        const resp = await fetch(req);
        // Don't cache redirects or opaque redirects
        if (resp && resp.ok && !resp.redirected && resp.type !== 'opaqueredirect') {
          try {
            const cache = await caches.open(STATIC_CACHE);
            cache.put(req, resp.clone());
          } catch {}
        }
        return resp;
      } catch (e) {
        // Optional: return a cached shell or just error
        return Response.error();
      }
    })());
    return;
  }

  // Handle API SWR endpoints
  if (url.origin === location.origin && isApiSWRE(url)) {
    event.respondWith((async () => {
      const cache = await caches.open(RUNTIME_CACHE);
      const cached = await cache.match(req);
      const fetchPromise = fetch(req).then((resp) => {
        if (resp && resp.ok) cache.put(req, resp.clone());
        return resp;
      }).catch(() => cached);
      return cached || fetchPromise;
    })());
    return;
  }

  // Cache-first for static assets (excluding '/')
  if (url.origin === location.origin && url.pathname.startsWith('/static/')) {
    event.respondWith((async () => {
      const cache = await caches.open(STATIC_CACHE);
      const cached = await cache.match(req);
      if (cached) return cached;
      try {
        const resp = await fetch(req);
        if (resp && resp.ok) cache.put(req, resp.clone());
        return resp;
      } catch (e) {
        return cached || Response.error();
      }
    })());
    return;
  }
});
