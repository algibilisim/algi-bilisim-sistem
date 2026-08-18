// ALGI BİLİŞİM - basit Service Worker
//
// Amaç: uygulamanın tarayıcı tarafından "kurulabilir" (installable) PWA
// olarak tanınması. Sayfalar (giriş gerektiren, sürekli değişen veriler)
// KASITLI OLARAK önbelleğe alınmıyor — bayat/yanlış veri gösterme riskini
// önlemek için. Statik dosyalar (ikonlar, style.css) "network-first"
// (önce ağdan, olmazsa önbellekten) stratejisiyle sunulur — bu sayede
// yeni bir güncelleme yayınlandığında (style.css, ikonlar vb. değiştiğinde)
// kullanıcılar eski/bayat sürümü görmeye devam etmez; internet yokken de
// (offline) en son önbelleğe alınmış sürüm gösterilir.
//
// ÖNEMLİ: CACHE_ADI ileride başka bir statik dosya değişikliği yapılırsa
// (ör. yeni bir ikon, yeni bir CSS değişikliği) yine artırılmalı — bu,
// eski tarayıcılardaki önbellek girdilerinin activate aşamasında temizlenip
// yeni sürümün baştan indirilmesini garanti eder.
const CACHE_ADI = "algi-statik-v2";
const ONBELLEKLENECEKLER = [
  "/static/style.css",
  "/static/manifest.json",
  "/static/icons/icon-192.png",
  "/static/icons/icon-512.png",
  "/static/icons/icon-192-maskable.png",
  "/static/icons/icon-512-maskable.png",
  "/static/icons/apple-touch-icon.png",
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
    fetch(istek)
      .then((agYaniti) => {
        const kopya = agYaniti.clone();
        caches.open(CACHE_ADI).then((cache) => cache.put(istek, kopya));
        return agYaniti;
      })
      .catch(() => {
        // Ağ isteği başarısız oldu (ör. internet yok) — elimizdeki en son
        // önbelleklenmiş sürümü göster, o da yoksa hata olduğu gibi geçsin.
        return caches.match(istek);
      })
  );
});
