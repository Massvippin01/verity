/**
 * sw.js — Hardened Cache-First Offline Service Worker for Verity Mobile Scanner PWA
 *
 * Pre-caches the app shell and core forensic engine.
 * Works 100% offline with zero external network dependencies, zero telemetry.
 * Hardened with:
 * 1. Strict versioned cache pruning on activation
 * 2. Origin & protocol validation (same-origin / HTTPS only)
 * 3. Content-Type verification before caching dynamic responses
 */

const CACHE_VERSION = 'v4';
const CACHE_NAME = `verity-mobile-${CACHE_VERSION}`;

const PRECACHE_ASSETS = [
  './',
  './index.html',
  './app.css',
  './app.js',
  './scanner.js',
  './manifest.webmanifest',
  './manifest.json',
  './icons/icon-192.png',
  './icons/icon-512.png',
  './core/index.js',
  './core/text-scanner.js',
  './core/citizen-messages.js',
  './core/xray-educator.js',
  './core/brands.json',
  './core/vendor/tldts.esm.js',
  './core/shared/text-scanner.js',
  './core/shared/citizen-messages.js',
  './core/shared/xray-educator.js',
  './core/shared/psl.js',
  './core/shared/legit-domains.js',
  './core/shared/messages.js',
  './core/shared/messages.en.js',
  './core/shared/apk-bytecode-analyzer.js',
  './core/shared/live-call-guardian.js',
  './core/shared/secv-intent-engine.js',
  './core/shared/recovery-advisor.js',
  './core/shared/flight-recorder.js',
  './core/shared/online-scam-verifier.js'
];

// Valid content types allowed to enter the persistent PWA cache
const ALLOWED_CONTENT_TYPES = [
  'text/html',
  'text/css',
  'application/javascript',
  'text/javascript',
  'application/json',
  'image/png',
  'image/jpeg',
  'image/svg+xml',
  'image/webp',
  'application/manifest+json'
];

self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME)
      .then((cache) => cache.addAll(PRECACHE_ASSETS))
      .then(() => self.skipWaiting())
  );
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys().then((keys) => {
      return Promise.all(
        keys.map((key) => {
          // Strict pruning: delete all stale verity caches
          if (key.startsWith('verity-mobile-') && key !== CACHE_NAME) {
            return caches.delete(key);
          }
        })
      );
    }).then(() => self.clients.claim())
  );
});

self.addEventListener('fetch', (event) => {
  // Web Share Target Level 2 multipart/form-data handler
  if (event.request.method === 'POST') {
    event.respondWith((async () => {
      try {
        const formData = await event.request.formData();
        const text = formData.get('text') || '';
        const url = formData.get('url') || '';
        const title = formData.get('title') || '';
        const combined = [title, text, url].filter(Boolean).join(' ');
        const redirectUrl = new URL('./', self.location.origin);
        if (combined) {
          redirectUrl.searchParams.set('text', combined);
        }
        return Response.redirect(redirectUrl.href, 303);
      } catch (_) {
        return Response.redirect('./', 303);
      }
    })());
    return;
  }

  if (event.request.method !== 'GET') return;

  event.respondWith(
    caches.match(event.request).then((cachedResponse) => {
      if (cachedResponse) {
        return cachedResponse;
      }

      return fetch(event.request).then((networkResponse) => {
        // Validate network response before caching
        if (!networkResponse || networkResponse.status !== 200 || networkResponse.type !== 'basic') {
          return networkResponse;
        }

        // Origin and HTTPS/localhost validation
        const reqUrl = new URL(event.request.url);
        const isSameOrigin = reqUrl.origin === self.location.origin;
        const isSecure = reqUrl.protocol === 'https:' || reqUrl.hostname === 'localhost' || reqUrl.hostname === '127.0.0.1';

        if (!isSameOrigin || !isSecure) {
          return networkResponse;
        }

        // Content-Type validation
        const contentType = networkResponse.headers.get('content-type') || '';
        const isAllowedType = ALLOWED_CONTENT_TYPES.some(t => contentType.toLowerCase().includes(t));

        if (isAllowedType) {
          const responseToCache = networkResponse.clone();
          caches.open(CACHE_NAME).then((cache) => {
            cache.put(event.request, responseToCache);
          });
        }

        return networkResponse;
      }).catch(() => {
        if (event.request.mode === 'navigate') {
          return caches.match('./index.html');
        }
      });
    })
  );
});
