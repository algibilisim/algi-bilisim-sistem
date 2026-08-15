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

CREATE INDEX IF NOT EXISTS idx_abone_koy ON abone(koy_adi);
CREATE INDEX IF NOT EXISTS idx_abone_sayac_no ON abone(sayac_no);

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

CREATE INDEX IF NOT EXISTS idx_ariza_koy ON ariza(koy_adi);
CREATE INDEX IF NOT EXISTS idx_ariza_seri_no ON ariza(seri_no);

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
-- şablonu. Her zaman tek bir satır tutulur; app.py içindeki ensure_db() ilk
-- çalıştırmada varsayılan tasarımı otomatik ekler.
CREATE TABLE IF NOT EXISTS montaj_formu_sablon (
    id SERIAL PRIMARY KEY,
    icerik TEXT NOT NULL,
    guncelleme_tarihi TIMESTAMP DEFAULT NOW()
);
