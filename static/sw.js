// ALGI BİLİŞİM - basit Service Worker
//
// Amaç: uygulamanın tarayıcı tarafından "kurulabilir" (installable) PWA
// olarak tanınması. Sayfalar (giriş gerektiren, sürekli değişen veriler)
// KASITLI OLARAK önbelleğe alınmıyor — bayat/yanlış veri gösterme riskini
// önlemek için. Sadece statik dosyalar (logo, ikonlar, style.css) basit bir
// "cache-first" stratejisiyle önbelleklenir; böylece uygulama biraz daha
// hızlı açılır ama veriler her zaman sunucudan taze gelir.

const CACHE_ADI = "algi-statik-v1";
const ONBELLEKLENECEKLER = [
  "/static/style.css",
  "/static/logo.jpg",
  "/static/icons/icon-192.png",
  "/static/icons/icon-512.png",
];

self.addEventListener("install", (event) => {
  event.waitUntil(
    caches.open(CACHE_ADI).then((cache) => cache.addAll(ONBELLEKLENECEKLER))
  );
  self.skipWaiting();
});

self.addEventListener("activate", (event) => {
  event.waitUntil(
    caches.keys().then((isimler) =>
      Promise.all(
        isimler
          .filter((isim) => isim !== CACHE_ADI)
          .map((isim) => caches.delete(isim))
      )
    )
  );
  self.clients.claim();
});

self.addEventListener("fetch", (event) => {
  const istek = event.request;

  // Sadece GET isteklerine ve sadece statik dosyalara dokun; geri kalan her
  // şey (sayfalar, form gönderimleri, API çağrıları) doğrudan ağa gider.
  if (istek.method !== "GET" || !istek.url.includes("/static/")) {
    return;
  }

  event.respondWith(
    caches.match(istek).then((onbellekYaniti) => {
      if (onbellekYaniti) {
        return onbellekYaniti;
      }
      return fetch(istek).then((agYaniti) => {
        const kopya = agYaniti.clone();
        caches.open(CACHE_ADI).then((cache) => cache.put(istek, kopya));
        return agYaniti;
      });
    })
  );
});
