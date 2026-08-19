// ALGI BİLİŞİM - basit Service Worker
//
// Amaç: uygulamanın tarayıcı tarafından "kurulabilir" (installable) PWA
// olarak tanınması. Sayfalar (giriş gerektiren, sürekli değişen veriler)
// KASITLI OLARAK önbelleğe alınmıyor — bayat/yanlış veri gösterme riskini
// önlemek için. Statik dosyalar (ikonlar, style.css) "stale-while-revalidate"
// (önce önbellekten ANINDA göster, aynı anda arka planda ağdan güncelini
// çekip bir sonraki ziyaret için önbelleğe yaz) stratejisiyle sunulur.
//
// ÖNCEKİ SÜRÜM "network-first" (önce ağ, olmazsa önbellek) kullanıyordu —
// bu, her sayfa geçişinde CSS/ikon gibi dosyaların ağdan yeniden alınmasını
// gerektiriyordu; ağda çok kısa bir aksama (anlık WiFi kesintisi, tam bir
// yeni dağıtımın yayına alındığı an gibi) olduğunda ve dosya önbellekte de
// yoksa istek tamamen başarısız oluyor, sayfa CSS'siz/"çıplak" görünüyordu.
// Yeni strateji bu riski ortadan kaldırıyor: dosya önbellekteyse sayfa HİÇBİR
// ZAMAN ağa bağımlı kalmadan anında düzgün görünür; güncel sürüm en son bir
// önceki ziyarette zaten arka planda alınmış olur.
//
// ÖNEMLİ: CACHE_ADI ileride başka bir statik dosya değişikliği yapılırsa
// (ör. yeni bir ikon, yeni bir CSS değişikliği) yine artırılmalı — bu,
// eski tarayıcılardaki önbellek girdilerinin activate aşamasında temizlenip
// yeni sürümün baştan indirilmesini garanti eder.
const CACHE_ADI = "algi-statik-v3";
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
    caches.open(CACHE_ADI).then((cache) =>
      cache.match(istek).then((onbellekYaniti) => {
        // Ağdan güncel sürümü çekip önbelleği güncelleyen istek — bu HER
        // ZAMAN başlatılır (bir sonraki ziyarette güncel dosya hazır olsun
        // diye), ama sayfanın şu anki yüklemesini bu isteğin bitmesi
        // BEKLETMEZ (önbellekte bir sürüm varsa).
        const agdanGuncelle = fetch(istek)
          .then((agYaniti) => {
            if (agYaniti && agYaniti.ok) {
              cache.put(istek, agYaniti.clone());
            }
            return agYaniti;
          })
          .catch(() => null);

        // Önbellekte bir sürüm varsa ANINDA onu döndür (sayfa hiçbir zaman
        // ağa/ağ hızına bağımlı kalmaz, kısa bir aksamada bile CSS'siz
        // görünmez). Önbellekte hiç yoksa (ör. ilk ziyaret) ağ isteğinin
        // bitmesini bekle.
        return onbellekYaniti || agdanGuncelle;
      })
    )
  );
});
