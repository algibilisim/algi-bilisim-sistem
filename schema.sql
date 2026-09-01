-- ALGI BİLİŞİM - Abone Listesi ve ilgili tablolar (PostgreSQL)

CREATE TABLE IF NOT EXISTS abone (
    id SERIAL PRIMARY KEY,
    s_no INTEGER,
    koy_adi TEXT NOT NULL,
    adi TEXT NOT NULL,
    soyadi TEXT NOT NULL,
    sayac_no TEXT,
    senet_tutari REAL DEFAULT 0,
    sayac_tutari REAL DEFAULT 0,
    alinan_tutar REAL DEFAULT 0,
    malzeme_tutari REAL DEFAULT 0,
    malzeme_alinan REAL DEFAULT 0,
    senet_no TEXT,
    senet_sahibi_adi TEXT,
    senet_sahibi_soyadi TEXT,
    telefon TEXT,
    baba_adi TEXT,
    montaj_tarihi TEXT,
    odeme_tarihi TEXT,
    odeme_sekli TEXT,
    odeme_gun_sozu TEXT,
    odemeyi_gonderen TEXT,
    aciklama TEXT,
    muhtara_odenecek REAL DEFAULT 0,
    muhtara_odenen REAL DEFAULT 0,
    fatura_no TEXT,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

ALTER TABLE abone ADD COLUMN IF NOT EXISTS odeme_gun_sozu TEXT;
ALTER TABLE abone ADD COLUMN IF NOT EXISTS telefon2 TEXT;
ALTER TABLE abone ADD COLUMN IF NOT EXISTS montaj_personeli TEXT;

CREATE INDEX IF NOT EXISTS idx_abone_koy ON abone(koy_adi);
CREATE INDEX IF NOT EXISTS idx_abone_sayac_no ON abone(sayac_no);
-- Abone Listesi sayfası her açılışta s_no'ya göre sıralıyor; kayıt sayısı
-- arttıkça bu sıralamayı hızlandırmak için.
CREATE INDEX IF NOT EXISTS idx_abone_s_no ON abone(s_no);

CREATE TABLE IF NOT EXISTS kullanici (
    id SERIAL PRIMARY KEY,
    kullanici_adi TEXT UNIQUE NOT NULL,
    sifre_hash TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS tahsilat (
    id SERIAL PRIMARY KEY,
    abone_id INTEGER NOT NULL REFERENCES abone(id) ON DELETE CASCADE,
    tarih TEXT,
    tur TEXT NOT NULL,
    tutar REAL DEFAULT 0,
    odeme_sekli TEXT,
    odemeyi_yapan TEXT,
    aciklama TEXT,
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_tahsilat_abone ON tahsilat(abone_id);

CREATE TABLE IF NOT EXISTS ariza (
    id SERIAL PRIMARY KEY,
    s_no INTEGER,
    ozel_s_no TEXT,
    koy_adi TEXT,
    yeni_seri_no TEXT,
    seri_no TEXT,
    adi TEXT,
    soyadi TEXT,
    ariza_ucret REAL DEFAULT 0,
    alinan_ucret REAL DEFAULT 0,
    gelis_tarihi TEXT,
    takilan_tarih TEXT,
    sayac_kredisi TEXT,
    tespit_edilen_ariza TEXT,
    yapilan_islemler TEXT,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

ALTER TABLE ariza ADD COLUMN IF NOT EXISTS telefon TEXT;
ALTER TABLE ariza ADD COLUMN IF NOT EXISTS telefon2 TEXT;
ALTER TABLE ariza ADD COLUMN IF NOT EXISTS tespit_aciklama TEXT;
ALTER TABLE ariza ADD COLUMN IF NOT EXISTS islem_aciklama TEXT;
-- Arızanın tespit edildiği konum (enlem/boylam) — abone kaydındaki "Konum Al" /
-- "Konuma Git" ile aynı mantık.
ALTER TABLE ariza ADD COLUMN IF NOT EXISTS konum_enlem DOUBLE PRECISION;
ALTER TABLE ariza ADD COLUMN IF NOT EXISTS konum_boylam DOUBLE PRECISION;
-- Arızanın giderilip sayacın/malzemenin aboneye ne zaman teslim edildiği.
ALTER TABLE ariza ADD COLUMN IF NOT EXISTS teslim_tarihi TEXT;

CREATE INDEX IF NOT EXISTS idx_ariza_koy ON ariza(koy_adi);
CREATE INDEX IF NOT EXISTS idx_ariza_seri_no ON ariza(seri_no);
-- Arıza Takip sayfası her açılışta s_no'ya göre sıralıyor; kayıt sayısı
-- arttıkça bu sıralamayı hızlandırmak için.
CREATE INDEX IF NOT EXISTS idx_ariza_s_no ON ariza(s_no);

CREATE TABLE IF NOT EXISTS ariza_tahsilat (
    id SERIAL PRIMARY KEY,
    ariza_id INTEGER NOT NULL REFERENCES ariza(id) ON DELETE CASCADE,
    tarih TEXT,
    tutar REAL DEFAULT 0,
    odeme_sekli TEXT,
    odemeyi_yapan TEXT,
    aciklama TEXT,
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_ariza_tahsilat_ariza ON ariza_tahsilat(ariza_id);

-- Arızalı sayaca ait fotoğraflar. Dosyalar DigitalOcean App Platform'un
-- diskine değil (o disk kalıcı değil, her deploy'da silinebilir), doğrudan
-- veritabanına (BYTEA) kaydedilir ki deploy sonrasında da kaybolmasın.
CREATE TABLE IF NOT EXISTS ariza_fotograf (
    id SERIAL PRIMARY KEY,
    ariza_id INTEGER NOT NULL REFERENCES ariza(id) ON DELETE CASCADE,
    dosya_adi TEXT,
    content_type TEXT,
    icerik BYTEA NOT NULL,
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_ariza_fotograf_ariza ON ariza_fotograf(ariza_id);

-- Abone kaydına ait fotoğraf/videolar (ör. sayaç, tesisat fotoğrafı) — aynı
-- ariza_fotograf gibi doğrudan veritabanında (BYTEA) saklanır.
CREATE TABLE IF NOT EXISTS abone_fotograf (
    id SERIAL PRIMARY KEY,
    abone_id INTEGER NOT NULL REFERENCES abone(id) ON DELETE CASCADE,
    dosya_adi TEXT,
    content_type TEXT,
    icerik BYTEA NOT NULL,
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_abone_fotograf_abone ON abone_fotograf(abone_id);

-- Montaj personelinin ve abonenin, kayıt sırasında telefon/tabletten
-- (dokunmatik ekranda parmakla/kalemle) attığı imza — canvas'tan PNG olarak
-- dışa aktarılır. BİLEREK abone tablosunun kendisine DEĞİL, ayrı bir tabloya
-- kondu: abone tablosu üzerinde "SELECT *" uygulamanın HER YERİNDE (Abone
-- Listesi, Fatura Kes, vb.) kullanılıyor — imza PNG'leri oraya BYTEA sütun
-- olarak eklenseydi, imzayla hiç ilgisi olmayan onlarca sorguda da gereksiz
-- yere yüklenip sayfaları yavaşlatırdı (tıpkı küçültülmemiş fotoğrafların
-- yavaşlattığı gibi — bkz. _fotografi_kucult). Her abone+tür (montaj/abone)
-- için en fazla bir satır olacağından (abone_id, tur) üzerinde tekil bir
-- indeks var; yeniden imzalanınca UPSERT ile üzerine yazılır.
CREATE TABLE IF NOT EXISTS abone_imza (
    id SERIAL PRIMARY KEY,
    abone_id INTEGER NOT NULL REFERENCES abone(id) ON DELETE CASCADE,
    tur TEXT NOT NULL,  -- 'montaj' (Montaj Personeli) veya 'abone' (Abone)
    icerik BYTEA NOT NULL,
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_abone_imza_abone_tur ON abone_imza(abone_id, tur);

-- Abonenin konumu (enlem/boylam) — "Konum Al" ile telefonun GPS'inden
-- alınır, "Konuma Git" ile harita uygulamasında navigasyon başlatılır.
ALTER TABLE abone ADD COLUMN IF NOT EXISTS konum_enlem DOUBLE PRECISION;
ALTER TABLE abone ADD COLUMN IF NOT EXISTS konum_boylam DOUBLE PRECISION;

-- Köylerden Excel ile gelen abone listeleri: ana "abone" tablosundan (faturalama/tahsilat)
-- tamamen ayrı, sadece köylerin kendi kayıt defterini (TEKSAN tarzı roster) tutar.
-- Arıza Takip'te seri no aramasında ana abone tablosunda bulunamayan seri no'lar için
-- yedek kaynak olarak da kullanılır.
CREATE TABLE IF NOT EXISTS koy_abone (
    id SERIAL PRIMARY KEY,
    koy_adi TEXT NOT NULL,
    sira_no TEXT,
    abonelik_tarihi TEXT,
    abone_no TEXT,
    cihaz_no TEXT,
    adi TEXT,
    soyadi TEXT,
    adres TEXT,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_koy_abone_koy ON koy_abone(koy_adi);
CREATE INDEX IF NOT EXISTS idx_koy_abone_cihaz_no ON koy_abone(cihaz_no);

-- Montaj Formu'nun program içinden sonradan tasarlanabilir (düzenlenebilir) HTML
-- şablonu. BİRDEN FAZLA isimli tasarım kaydedilebilir (ör. farklı firma/köy için
-- farklı görünüm) — "ad" hangi tasarım olduğunu gösterir. app.py içindeki
-- ensure_db() ilk çalıştırmada, hiç tasarım yoksa varsayılan tasarımı otomatik
-- ekler. "ad" sütunu sonradan eklendi; ADD COLUMN IF NOT EXISTS ile daha önce
-- kurulmuş veritabanlarında da (üzerine yazmadan) otomatik tamamlanır.
CREATE TABLE IF NOT EXISTS montaj_formu_sablon (
    id SERIAL PRIMARY KEY,
    icerik TEXT NOT NULL,
    guncelleme_tarihi TIMESTAMP DEFAULT NOW()
);
ALTER TABLE montaj_formu_sablon ADD COLUMN IF NOT EXISTS ad TEXT NOT NULL DEFAULT 'Varsayılan';

-- Arıza formundaki onay kutusu listelerinin (ör. "Tespit Edilen Arıza",
-- "Yapılan İşlemler") program içinden -kod yazmadan- yönetilebilmesi için.
-- "grup" hangi listeye ait olduğunu belirtir (app.py'deki FORM_SECENEK_GRUPLARI
-- ile eşleşir), "sira" listedeki gösterim sırasıdır. app.py içindeki ensure_db()
-- ilk çalıştırmada, bir grup için hiç satır yoksa varsayılan seçenekleri otomatik
-- ekler; bu yapı ileride başka formlara benzer yönetilebilir listeler eklemek
-- için de (yeni bir "grup" tanımlayıp aynı tabloyu kullanarak) kullanılabilir.
CREATE TABLE IF NOT EXISTS form_secenegi (
    id SERIAL PRIMARY KEY,
    grup TEXT NOT NULL,
    deger TEXT NOT NULL,
    sira INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_form_secenegi_grup ON form_secenegi(grup, sira);

-- "Özel Alan Ayarları" ekranından, kod değiştirmeden Abone veya Arıza formuna
-- yeni bir bilgi kutusu (metin/tarih/sayı) eklenebilmesi için. Her yeni özel
-- alan eklendiğinde app.py, bu tabloya bir satır ekler VE ilgili tabloya
-- (abone/ariza) gerçek bir sütun ekler (ALTER TABLE ... ADD COLUMN) — "kolon_adi"
-- o gerçek sütunun adıdır (kullanıcı görmez, program kendisi üretir: "ozel_<id>"),
-- "etiket" ise kullanıcının formda/listede gördüğü isimdir. Bir alan "silindiğinde"
-- veri kaybı olmaması için sütun gerçekten silinmez, sadece aktif=FALSE yapılır
-- (form/liste/filtrelerden gizlenir).
CREATE TABLE IF NOT EXISTS ozel_alan (
    id SERIAL PRIMARY KEY,
    tablo TEXT NOT NULL,
    kolon_adi TEXT NOT NULL,
    etiket TEXT NOT NULL,
    tur TEXT NOT NULL,
    sira INTEGER NOT NULL DEFAULT 0,
    aktif BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_ozel_alan_tablo ON ozel_alan(tablo, aktif, sira);

-- "Özel Alan Ayarları" ekranındaki sürükle-bırak önizlemesi, bir özel alanın
-- formda TAM OLARAK hangi sabit alandan (ör. "baba_adi") hemen SONRA
-- göründüğünü bu sütuna kaydeder — böylece alan, formdaki iki mevcut alanın
-- arasına yerleştirilebilir. Boş metin ('') = formun en sonundaki "Özel
-- Alanlar" kutusu (varsayılan, yeni eklenen her alan önce buraya düşer).
ALTER TABLE ozel_alan ADD COLUMN IF NOT EXISTS sonra_gelen_alan TEXT NOT NULL DEFAULT '';

-- Basit anahtar/değer ayar deposu. İlk kullanım amacı: Hesap Ayarları'ndan bir
-- kez girilen "Ofis Konumu" (ofis_enlem/ofis_boylam) — bilgisayardan (GPS'i
-- olmayan, konum tahmini güvenilmez olan cihazlardan) "Konum Al" basıldığında,
-- gerçek (ama yanlış çıkabilen) tarayıcı konumu yerine bu sabit, bilinen doğru
-- ofis konumu kullanılır; böylece "bu kayıt ofiste verildi" bilgisi güvenilir
-- şekilde işaretlenebilir. İleride başka tekil ayarlar için de kullanılabilir.
CREATE TABLE IF NOT EXISTS ayar (
    anahtar TEXT PRIMARY KEY,
    deger TEXT
);

-- Hızlı Bilişim Teknolojileri e-Connect API entegrasyonu (e-Fatura/e-Arşiv
-- Fatura kesme): fatura kesebilmek için GİB'in zorunlu tuttuğu ama daha önce
-- hiç tutulmayan alıcı kimlik/adres bilgileri — Abone ve Arıza kayıtlarına
-- ayrı ayrı eklendi (bir arıza kaydı mutlaka bir abone kaydına bağlı
-- olmayabilir, ikisi de bağımsız fatura kesebilmeli).
-- "kimlik_no": TC Kimlik No (11 haneli, bireysel abone) ya da Vergi No
-- (10 haneli, kurumsal abone) — hangisi olduğu uzunluğuna göre koddan
-- (_fatura_turu_belirle) otomatik anlaşılır.
ALTER TABLE abone ADD COLUMN IF NOT EXISTS kimlik_no TEXT;
ALTER TABLE abone ADD COLUMN IF NOT EXISTS vergi_dairesi TEXT;
ALTER TABLE abone ADD COLUMN IF NOT EXISTS adres TEXT;
ALTER TABLE abone ADD COLUMN IF NOT EXISTS eposta TEXT;

ALTER TABLE ariza ADD COLUMN IF NOT EXISTS kimlik_no TEXT;
ALTER TABLE ariza ADD COLUMN IF NOT EXISTS vergi_dairesi TEXT;
ALTER TABLE ariza ADD COLUMN IF NOT EXISTS adres TEXT;
ALTER TABLE ariza ADD COLUMN IF NOT EXISTS eposta TEXT;

-- Hızlı Bilişim üzerinden kesilen her e-Fatura/e-Arşiv Fatura'nın kaydı.
-- PDF içeriği de (ariza_fotograf/abone_fotograf ile aynı sebeple —
-- DigitalOcean App Platform'un diski kalıcı değil) doğrudan veritabanında
-- (BYTEA) saklanır, böylece "Faturalarım" sayfasından her zaman erişilebilir.
CREATE TABLE IF NOT EXISTS fatura (
    id SERIAL PRIMARY KEY,
    kaynak_tur TEXT NOT NULL,              -- 'abone' veya 'ariza'
    kaynak_id INTEGER NOT NULL,
    fatura_turu TEXT NOT NULL,             -- 'earsiv' veya 'efatura'
    yerel_id TEXT NOT NULL,                -- bizim ürettiğimiz, API'ye gönderilen benzersiz kimlik (LocalId)
    fatura_uuid TEXT,                      -- Hızlı Bilişim'in döndürdüğü belge UUID'si (başarılıysa)
    durum TEXT NOT NULL DEFAULT 'beklemede',  -- 'beklemede' / 'basarili' / 'hata'
    hata_mesaji TEXT,
    tutar_kdv_dahil REAL,
    tutar_kdv_haric REAL,
    kdv_tutari REAL,
    kalemler TEXT,                         -- fatura kalemlerinin özeti (ör. "ÖN ÖDEMELİ SU SAYACI: 1.200,00 TL")
    pdf_icerik BYTEA,
    olusturan_kullanici TEXT,
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_fatura_kaynak ON fatura(kaynak_tur, kaynak_id);

-- Faturanın kesildiği tarih olarak KULLANICININ SEÇTİĞİ tarih (varsayılan
-- bugün, ama geriye dönük tarih de seçilebiliyor) — created_at (kaydın
-- veritabanına düştüğü an) ile karıştırılmasın diye ayrı bir sütun.
ALTER TABLE fatura ADD COLUMN IF NOT EXISTS fatura_tarihi DATE;

-- ABONELERE MESAJ SİSTEMİ: Abone Listesi'nden tek tek ya da toplu (filtreye
-- uyan tüm kayıtlara) WhatsApp/SMS/E-posta mesajı gönderme geçmişi.
-- Her alıcı için ayrı bir satır oluşur (toplu gönderimde N alıcı = N satır),
-- böylece hem "Mesajlarım" genel geçmişi hem de ileride abone bazlı geçmiş
-- aynı tablodan sorgulanabilir.
CREATE TABLE IF NOT EXISTS mesaj (
    id SERIAL PRIMARY KEY,
    kaynak_tur TEXT NOT NULL,              -- şimdilik sadece 'abone'
    kaynak_id INTEGER NOT NULL,
    kanal TEXT NOT NULL,                   -- 'whatsapp' / 'sms' / 'eposta'
    alici_adi TEXT,
    alici_telefon TEXT,
    icerik TEXT NOT NULL,
    durum TEXT NOT NULL DEFAULT 'beklemede',  -- 'beklemede' / 'basarili' / 'hata'
    hata_mesaji TEXT,
    olusturan_kullanici TEXT,
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_mesaj_kaynak ON mesaj(kaynak_tur, kaynak_id);

-- E-posta kanalıyla gönderilen mesajlar için alıcı adresi (SMS/WhatsApp'ta
-- kullanılan alici_telefon'un e-posta karşılığı).
ALTER TABLE mesaj ADD COLUMN IF NOT EXISTS alici_eposta TEXT;

-- STOK MODÜLÜ: ürün/malzeme kataloğu + miktar (giriş/çıkış) takibi +
-- düşük stok uyarısı + tedarikçi/alım kaydı.
CREATE TABLE IF NOT EXISTS stok_urun (
    id SERIAL PRIMARY KEY,
    urun_adi TEXT NOT NULL,
    birim TEXT NOT NULL DEFAULT 'ADET',
    birim_fiyat REAL DEFAULT 0,        -- referans/güncel birim fiyat (KDV hariç) — fatura kalemi eklerken öneri olarak kullanılabilir
    kdv_orani REAL DEFAULT 20,
    stok_miktari REAL NOT NULL DEFAULT 0,
    min_stok_seviyesi REAL NOT NULL DEFAULT 0,  -- bunun altına düşünce "düşük stok" uyarısı gösterilir
    aciklama TEXT,
    aktif BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS stok_hareket (
    id SERIAL PRIMARY KEY,
    urun_id INTEGER NOT NULL REFERENCES stok_urun(id) ON DELETE CASCADE,
    hareket_turu TEXT NOT NULL,        -- 'giris' veya 'cikis'
    miktar REAL NOT NULL,
    tarih DATE NOT NULL,
    birim_fiyat REAL,                  -- giriş hareketlerinde alım fiyatı (tedarikçi/alım kaydı için)
    tedarikci_adi TEXT,
    aciklama TEXT,
    olusturan_kullanici TEXT,
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_stok_hareket_urun ON stok_hareket(urun_id);

-- FABRİKA / TAMİR MODÜLÜ: arızalı sayaçların üreticiye/fabrikaya tamire
-- gönderilip geri gelme sürecinin takibi. Bir kayıt oluşturulduğunda
-- 'beklemede' (henüz gönderilmedi) durumundadır; Fabrika/Tamir listesinden
-- seçilip "Gönderim Oluştur" ile bir fabrika_gonderim'e ve onun altındaki
-- (8'erli gruplar halinde otomatik oluşan) fabrika_koli'lere dahil edilince
-- durum 'gonderildi' olur.
CREATE TABLE IF NOT EXISTS fabrika_gonderim (
    id SERIAL PRIMARY KEY,
    kargo_firmasi TEXT,
    kargo_takip_no TEXT,
    urun_tanimi TEXT NOT NULL DEFAULT 'Elektronik Kartlı Ön Ödemeli Su Sayacı',
    adres TEXT,
    gonderim_tarihi DATE,
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS fabrika_koli (
    id SERIAL PRIMARY KEY,
    gonderim_id INTEGER NOT NULL REFERENCES fabrika_gonderim(id) ON DELETE CASCADE,
    koli_no INTEGER NOT NULL,
    koli_tarihi DATE,           -- genel gönderim tarihinden farklı olabilir (örn. bir koli bir gün sonra kargoya verilmiş olabilir)
    aciklama TEXT,
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_fabrika_koli_gonderim ON fabrika_koli(gonderim_id);

CREATE TABLE IF NOT EXISTS fabrika_tamir (
    id SERIAL PRIMARY KEY,
    seri_no TEXT NOT NULL,
    abone_adi TEXT,
    koy_adi TEXT,
    telefon TEXT,
    ilk_montaj_tarihi TEXT,
    uretim_yili TEXT,
    tespit_edilen_ariza TEXT,
    yerine_sayac_takildi BOOLEAN NOT NULL DEFAULT FALSE,
    takilan_sayac_serisi TEXT,
    durum TEXT NOT NULL DEFAULT 'beklemede',   -- beklemede / gonderildi / tamirde / tamir_edildi / iade_edildi
    gonderim_tarihi DATE,
    donus_tarihi DATE,
    tamir_ucreti REAL DEFAULT 0,
    parca_maliyeti REAL DEFAULT 0,
    odeyen TEXT,
    koli_id INTEGER REFERENCES fabrika_koli(id) ON DELETE SET NULL,
    olusturan_kullanici TEXT,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_fabrika_tamir_seri_no ON fabrika_tamir(seri_no);
CREATE INDEX IF NOT EXISTS idx_fabrika_tamir_durum ON fabrika_tamir(durum);
CREATE INDEX IF NOT EXISTS idx_fabrika_tamir_koli ON fabrika_tamir(koli_id);

-- Fabrika/Tamir kaydına ait fotoğraf/videolar — Arıza Takip'teki
-- ariza_fotograf ile aynı mantıkla (doğrudan veritabanında, BYTEA) saklanır.
CREATE TABLE IF NOT EXISTS fabrika_fotograf (
    id SERIAL PRIMARY KEY,
    kayit_id INTEGER NOT NULL REFERENCES fabrika_tamir(id) ON DELETE CASCADE,
    dosya_adi TEXT,
    content_type TEXT,
    icerik BYTEA NOT NULL,
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_fabrika_fotograf_kayit ON fabrika_fotograf(kayit_id);

-- Sayaç Durum Raporu'nda "YETKİLİ BAYİİ" tarafında imza atacak kişinin adı;
-- programdan (daha önce kullanılmış isimler arasından) seçilebilir olsun diye
-- serbest metin olarak tutulur.
ALTER TABLE fabrika_gonderim ADD COLUMN IF NOT EXISTS yetkili_bayii TEXT;

-- Tamir kaydına alınan sayacın abonede kayıtlı "Abone Kartı"nın da beraberinde
-- alınıp alınmadığını belirtir: alindi / alinmadi.
ALTER TABLE fabrika_tamir ADD COLUMN IF NOT EXISTS abone_karti TEXT NOT NULL DEFAULT 'alinmadi';

-- Gönderimler listesindeki '#' sırası artık kayıt eklenme sırası (id) değil,
-- Gönderim Tarihi'ne göre otomatik hesaplanan bir sıra numarasıdır — bkz.
-- app.py'deki _fabrika_gonderim_sira_numaralarini_yenile. Bir gönderim
-- sonradan (geçmiş bir tarihle) eklendiğinde ya da bir gönderim silindiğinde
-- bu sütun otomatik olarak yeniden hesaplanır.
ALTER TABLE fabrika_gonderim ADD COLUMN IF NOT EXISTS sira_no INTEGER;
CREATE INDEX IF NOT EXISTS idx_fabrika_gonderim_sira_no ON fabrika_gonderim(sira_no);

-- Bir tamir kaydı "Sil" ile silindiğinde artık veritabanından kalıcı olarak
-- kaldırılmıyor; silindi_mi=TRUE olarak işaretlenip Silinenler sayfasına
-- taşınıyor, buradan yanlışlıkla silinen bir kayıt geri yüklenebiliyor
-- (bkz. app.py'deki fabrika_sil / fabrika_silinenler / fabrika_geri_yukle /
-- fabrika_kalici_sil).
ALTER TABLE fabrika_tamir ADD COLUMN IF NOT EXISTS silindi_mi BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE fabrika_tamir ADD COLUMN IF NOT EXISTS silinme_tarihi TIMESTAMP;
CREATE INDEX IF NOT EXISTS idx_fabrika_tamir_silindi_mi ON fabrika_tamir(silindi_mi);
