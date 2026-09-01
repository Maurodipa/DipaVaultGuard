const CACHE_NAME = 'dipavaultguard-v14';
// NOTA: percorsi RELATIVI (senza "/" iniziale). Il sito vive in un sottopercorso su GitHub
// Pages (es. https://tuonome.github.io/nome-repo/): un percorso assoluto come "/index.html"
// punterebbe alla radice del dominio invece che alla cartella del sito, e non verrebbe mai
// trovato (stesso tipo di bug già visto con manifest.json e con il popup di Google Drive).
const ASSETS_TO_CACHE = [
  './',
  './index.html',
  './css_Claude_2FA/style_Claude_2FA.css',
  './js_Claude_2FA/app_Claude_2FA.js',
  './js_Claude_2FA/ui_Claude_2FA.js',
  './js_Claude_2FA/crypto_Claude_2FA.js',
  './js_Claude_2FA/vault_Claude_2FA.js',
  './js_Claude_2FA/twofactor_Claude_2FA.js',
  './js_Claude_2FA/email-otp_Claude_2FA.js',
  './js_Claude_2FA/drive_Claude_2FA.js',
  './js_Claude_2FA/password-gen_Claude_2FA.js',
  './manifest_Claude_2FA.json',
  './icons_Claude_2FA/icon-192.png',
  './icons_Claude_2FA/icon-512.png'
];

self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME).then((cache) => {
      return cache.addAll(ASSETS_TO_CACHE);
    })
  );
  self.skipWaiting();
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys().then((cacheNames) => {
      return Promise.all(
        cacheNames.map((cacheName) => {
          if (cacheName !== CACHE_NAME) {
            return caches.delete(cacheName);
          }
        })
      );
    })
  );
  self.clients.claim();
});

self.addEventListener('fetch', (event) => {
  const url = new URL(event.request.url);
  if (url.hostname.includes('googleapis.com') || url.hostname.includes('accounts.google.com') || url.hostname.includes('api.emailjs.com')) {
    return;
  }
  event.respondWith(
    caches.match(event.request).then((response) => {
      if (response) {
        return response;
      }
      return fetch(event.request).then((networkResponse) => {
        if (!networkResponse || networkResponse.status !== 200 || networkResponse.type !== 'basic') {
          return networkResponse;
        }
        const responseToCache = networkResponse.clone();
        caches.open(CACHE_NAME).then((cache) => {
          cache.put(event.request, responseToCache);
        });
        return networkResponse;
      });
    })
  );
});
