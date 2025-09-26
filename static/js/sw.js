// Simple Service Worker: cache-first for static, stale-while-revalidate for key APIs
const VERSION = 'v7';

async function clearAllCaches() {
  const keys = await caches.keys();
  await Promise.all(keys.map(key => caches.delete(key)));
}

self.addEventListener('install', (event) => {
  event.waitUntil((async () => {
    await clearAllCaches();
    self.skipWaiting();
  })());
});

self.addEventListener('activate', (event) => {
  event.waitUntil((async () => {
    await clearAllCaches();
    self.clients.claim();
  })());
});

self.addEventListener('fetch', (event) => {
  if (event.request.method !== 'GET') return;
  event.respondWith((async () => {
    try {
      return await fetch(event.request, { cache: 'no-store' });
    } catch (e) {
      return Response.error();
    }
  })());
});
