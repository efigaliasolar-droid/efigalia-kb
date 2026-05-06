// Service Worker para Efigalia PWA
// Estrategia: network-first para index.html (que contiene TODA la app)
// con fallback a caché. Assets estáticos (iconos, manifest) cache-first.

const VERSION = 'v5';
const CACHE = 'efigalia-' + VERSION;
const SHELL = [
  './',
  './index.html',
  './manifest.json',
  './icon-192.png',
  './icon-512.png',
  './icon-maskable-512.png'
];

self.addEventListener('install', (e) => {
  e.waitUntil(
    caches.open(CACHE).then(c => c.addAll(SHELL)).then(() => self.skipWaiting())
  );
});

self.addEventListener('activate', (e) => {
  e.waitUntil(
    caches.keys().then(keys =>
      Promise.all(keys.filter(k => k !== CACHE).map(k => caches.delete(k)))
    ).then(() => self.clients.claim())
  );
});

self.addEventListener('fetch', (e) => {
  const req = e.request;
  if (req.method !== 'GET') return;
  const url = new URL(req.url);

  // Nunca cachear llamadas al Worker de Cloudflare (datos dinámicos + IA)
  if (url.hostname.endsWith('workers.dev')) return;
  // Nunca cachear CDNs de terceros (pdf.js, fuentes) para no quedar con versiones obsoletas
  if (url.origin !== self.location.origin) return;

  // Network-first para HTML (la app es una SPA en un único index.html)
  if (req.mode === 'navigate' || req.destination === 'document' || url.pathname.endsWith('.html')) {
    e.respondWith(
      fetch(req).then(res => {
        const copy = res.clone();
        caches.open(CACHE).then(c => c.put(req, copy));
        return res;
      }).catch(() => caches.match(req).then(r => r || caches.match('./index.html')))
    );
    return;
  }

  // Cache-first para todo lo demás (iconos, manifest...)
  e.respondWith(
    caches.match(req).then(cached => cached || fetch(req).then(res => {
      const copy = res.clone();
      if (res.ok) caches.open(CACHE).then(c => c.put(req, copy));
      return res;
    }))
  );
});
