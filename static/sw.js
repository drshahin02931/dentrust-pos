/* ═══════════════════════════════════════════════
   DenTrust POS — Service Worker
   • Network-first for API/HTML
   • Cache-first for static assets
   • Push notifications
═══════════════════════════════════════════════ */

const CACHE = 'dentrust-pos-v6';
const STATIC_ASSETS = [
  '/pos-system/',
  '/pos-system/static/manifest.json',
  '/pos-system/static/icon-192.png',
  '/pos-system/static/icon-512.png',
];

/* ── Install ── */
self.addEventListener('install', e => {
  self.skipWaiting();
  e.waitUntil(
    caches.open(CACHE).then(c => c.addAll(STATIC_ASSETS).catch(() => {}))
  );
});

/* ── Activate: clean old caches ── */
self.addEventListener('activate', e => {
  e.waitUntil(
    caches.keys().then(keys =>
      Promise.all(keys.filter(k => k !== CACHE).map(k => caches.delete(k)))
    ).then(() => self.clients.claim())
  );
});

/* ── Fetch: network-first for pages/API, cache-first for static ── */
self.addEventListener('fetch', e => {
  const url = new URL(e.request.url);

  /* Skip non-GET and cross-origin */
  if (e.request.method !== 'GET') return;
  if (url.origin !== location.origin) return;

  /* Static assets → cache first */
  if (url.pathname.includes('/static/') || url.pathname.includes('/uploads/')) {
    e.respondWith(
      caches.match(e.request).then(cached => cached || fetch(e.request).then(res => {
        if (res.ok) {
          const clone = res.clone();
          caches.open(CACHE).then(c => c.put(e.request, clone));
        }
        return res;
      }))
    );
    return;
  }

  /* Pages & API → network first, fall back to cache */
  e.respondWith(
    fetch(e.request)
      .then(res => {
        if (res.ok && e.request.mode === 'navigate') {
          const clone = res.clone();
          caches.open(CACHE).then(c => c.put(e.request, clone));
        }
        return res;
      })
      .catch(() => caches.match(e.request))
  );
});

/* ── Push Notifications ── */
self.addEventListener('push', e => {
  let data = { title: 'DenTrust POS', body: 'إشعار جديد', icon: '/pos-system/static/icon-192.png', badge: '/pos-system/static/icon-192.png', tag: 'dentrust-notif' };
  try {
    const d = e.data ? e.data.json() : {};
    data = Object.assign(data, d);
  } catch (_) {}

  e.waitUntil(
    self.registration.showNotification(data.title, {
      body:    data.body,
      icon:    data.icon    || '/pos-system/static/icon-192.png',
      badge:   data.badge   || '/pos-system/static/icon-192.png',
      tag:     data.tag     || 'dentrust-notif',
      data:    data.url ? { url: data.url } : {},
      vibrate: [200, 100, 200],
      requireInteraction: !!data.requireInteraction,
    })
  );
});

/* ── Notification click → open URL ── */
self.addEventListener('notificationclick', e => {
  e.notification.close();
  const url = (e.notification.data && e.notification.data.url) || '/pos-system/';
  e.waitUntil(
    clients.matchAll({ type: 'window', includeUncontrolled: true }).then(list => {
      for (const c of list) {
        if (c.url.includes('/pos-system') && 'focus' in c) return c.focus();
      }
      return clients.openWindow(url);
    })
  );
});
