/**
 * sw.js — Cache-First Offline Service Worker for Verity Mobile Scanner PWA
 *
 * Pre-caches the app shell and core engine. Works 100% offline with zero analytics
 * and zero external network calls.
 */

const CACHE_NAME = 'verity-mobile-v1';

const PRECACHE_ASSETS = [
  './',
  './index.html',
  './app.css',
  './app.js',
  './manifest.webmanifest',
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
  './core/background/rules.js',
  './core/background/risk-engine.js',
  './core/background/homograph-detector.js',
  './core/background/favicon-matcher.js',
  './core/background/enterprise-whitelist.js',
  './core/background/brand-detector.js',
  './core/content/bharat-scam-detectors.js',
  './core/config/top_domains.js'
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
          if (key !== CACHE_NAME) {
            return caches.delete(key);
          }
        })
      );
    }).then(() => self.clients.claim())
  );
});

self.addEventListener('fetch', (event) => {
  if (event.request.method !== 'GET') return;
  event.respondWith(
    caches.match(event.request).then((cachedResponse) => {
      if (cachedResponse) {
        return cachedResponse;
      }
      return fetch(event.request).catch(() => {
        if (event.request.mode === 'navigate') {
          return caches.match('./index.html');
        }
      });
    })
  );
});
