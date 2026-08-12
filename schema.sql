-- ALGI BİLİŞİM - Abone Listesi ve ilgili tablolar

CREATE TABLE IF NOT EXISTS abone (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
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
    odemeyi_gonderen TEXT,
    aciklama TEXT,
    muhtara_odenecek REAL DEFAULT 0,
    muhtara_odenen REAL DEFAULT 0,
    fatura_no TEXT,
    created_at TEXT DEFAULT (datetime('now')),
    updated_at TEXT DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_abone_koy ON abone(koy_adi);
CREATE INDEX IF NOT EXISTS idx_abone_sayac_no ON abone(sayac_no);

CREATE TABLE IF NOT EXISTS kullanici (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    kullanici_adi TEXT UNIQUE NOT NULL,
    sifre_hash TEXT NOT NULL
);
