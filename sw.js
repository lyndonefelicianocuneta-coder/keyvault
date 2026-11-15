/* KEYVAULT offline support.
   Caches ONLY the app's own files so it opens without internet.
   Your vault data is never touched here — it stays encrypted in IndexedDB.
   When you change any app file, bump VERSION so devices pick up the update. */
const VERSION = 'keyvault-v3';
const CORE = ['./index.html', './styles.css', './app.js'];            // must succeed
const EXTRA = ['./', './manifest.webmanifest', './icon-180.png', './icon-192.png', './icon-512.png']; // nice to have

self.addEventListener('install', (e) => {
  e.waitUntil((async () => {
    const cache = await caches.open(VERSION);
    await cache.addAll(CORE.map((u) => new Request(u, { cache: 'reload' })));
    // a missing icon or manifest must never block offline mode
    await Promise.all(EXTRA.map((u) => cache.add(new Request(u, { cache: 'reload' })).catch(() => {})));
    await self.skipWaiting();
  })());
});

self.addEventListener('activate', (e) => {
  e.waitUntil(caches.keys()
    .then((keys) => Promise.all(keys.filter((k) => k !== VERSION).map((k) => caches.delete(k))))
    .then(() => self.clients.claim()));
});

// Offline-first: serve from cache, refresh the cache in the background when online.
self.addEventListener('fetch', (e) => {
  const req = e.request;
  if (req.method !== 'GET' || new URL(req.url).origin !== self.location.origin) return;
  e.respondWith((async () => {
    const cache = await caches.open(VERSION);
    const cached = await cache.match(req, { ignoreSearch: true });
    const network = fetch(req).then((res) => {
      if (res && res.ok) cache.put(req, res.clone());
      return res;
    }).catch(() => null);
    if (cached) return cached;
    const res = await network;
    if (res) return res;
    // offline and not cached: any page navigation gets the app itself
    if (req.mode === 'navigate') return (await cache.match('./index.html')) || Response.error();
    return Response.error();
  })());
});
