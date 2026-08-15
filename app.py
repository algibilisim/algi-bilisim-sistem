import os
import io
import re
import csv
import gzip
import math
import base64
from datetime import datetime
from functools import wraps
from urllib.parse import quote as _url_quote

import psycopg2
import psycopg2.extras
from flask import (
    Flask, render_template, request, redirect,
    url_for, session, g, flash, jsonify, Response
)
from werkzeug.security import check_password_hash, generate_password_hash

DATABASE_URL = os.environ.get("DATABASE_URL")
SECRET_KEY = os.environ.get("SECRET_KEY", "gelistirme-icin-degistir")

app = Flask(__name__)
app.secret_key = SECRET_KEY


@app.template_filter('tl')
def tl_format(deger):
    try:
        deger = float(deger or 0)
    except (TypeError, ValueError):
        deger = 0.0
    s = f"{deger:,.2f}"
    s = s.replace(",", "X").replace(".", ",").replace("X", ".")
    return s


def _fatura_no_temizle(deger):
    s = str(deger or "").strip()
    if s.endswith(".0"):
        s = s[:-2]
    return s


def _telefon_formatla(deger):
    rakamlar = "".join(ch for ch in str(deger or "") if ch.isdigit())
    if not rakamlar:
        return ""
    if len(rakamlar) == 10:
        rakamlar = "0" + rakamlar
    if len(rakamlar) != 11:
        return str(deger).strip()
    return f"{rakamlar[0]} {rakamlar[1:4]} {rakamlar[4:7]} {rakamlar[7:9]} {rakamlar[9:11]}"


BIRLER = ["", "Bir", "İki", "Üç", "Dört", "Beş", "Altı", "Yedi", "Sekiz", "Dokuz"]
ONLAR = ["", "On", "Yirmi", "Otuz", "Kırk", "Elli", "Altmış", "Yetmiş", "Seksen", "Doksan"]
BASAMAK = ["", "Bin", "Milyon", "Milyar", "Trilyon"]


def _uc_basamak_oku(sayi):
    yuzler = sayi // 100
    kalan = sayi % 100
    onlar = kalan // 10
    birler = kalan % 10
    metin = ""
    if yuzler > 0:
        if yuzler == 1:
            metin += "Yüz "
        else:
            metin += BIRLER[yuzler] + " Yüz "
    if onlar > 0:
        metin += ONLAR[onlar] + " "
    if birler > 0:
        metin += BIRLER[birler] + " "
    return metin.strip()


def _sayi_yaziya_cevir(sayi):
    sayi = int(sayi)
    if sayi == 0:
        return "Sıfır"
    parcalar = []
    grup_no = 0
    while sayi > 0:
        grup = sayi % 1000
        if grup > 0:
            grup_metni = _uc_basamak_oku(grup)
            if grup_no == 1 and grup == 1:
                grup_metni = "Bin"
            elif grup_no > 0:
                grup_metni = (grup_metni + " " + BASAMAK[grup_no]).strip()
            parcalar.insert(0, grup_metni)
        sayi //= 1000
        grup_no += 1
    return " ".join(parcalar).strip()


def _tutar_yaziya_cevir(tutar):
    tutar = round(float(tutar or 0), 2)
    tl_kismi = int(tutar)
    kurus_kismi = int(round((tutar - tl_kismi) * 100))
    metin = _sayi_yaziya_cevir(tl_kismi) + " Türk Lirası"
    if kurus_kismi > 0:
        metin += " " + _sayi_yaziya_cevir(kurus_kismi) + " Kuruş"
    return metin


def _odeme_sekli_esle(metin):
    m = (metin or "").strip().upper()
    if any(k in m for k in ["NAKİT", "NAKIT", "ELDEN"]):
        return "nakit"
    if any(k in m for k in ["HAVALE", "BANKA", "EFT"]):
        return "havale"
    if "KART" in m:
        return "kredi_karti"
    if any(k in m for k in ["ÇEK", "CEK"]):
        return "cek"
    return None


DISPLAY_KOLONLARI = [
    ("s_no", "S.No"),
    ("koy_adi", "Köy"),
    ("adi", "Adı"),
    ("soyadi", "Soyadı"),
    ("sayac_no", "Sayaç No"),
    ("senet_tutari", "Senet Tutarı"),
    ("sayac_tutari", "Sayaç Tutarı"),
    ("alinan_tutar", "Alınan"),
    ("sayac_kalan", "Sayaç Kalan"),
    ("malzeme_tutari", "Malzeme Tutarı"),
    ("malzeme_alinan", "Malzeme Alınan"),
    ("malzeme_kalan", "Malzeme Kalan"),
    ("toplam_kalan", "Toplam Kalan"),
    ("senet_no", "Senet No"),
    ("senet_sahibi_adi", "Senet Sahibi Adı"),
    ("senet_sahibi_soyadi", "Senet Sahibi Soyadı"),
    ("telefon", "Telefon"),
    ("telefon2", "Telefon 2"),
    ("baba_adi", "Baba Adı"),
    ("montaj_tarihi", "Montaj Tarihi"),
    ("odeme_tarihi", "Ödeme Tarihi"),
    ("odeme_sekli", "Ödeme Şekli"),
    ("odeme_gun_sozu", "Ödeme Gün Sözü"),
    ("odemeyi_gonderen", "Ödemeyi Gönderen"),
    ("aciklama", "Açıklama"),
    ("muhtara_odenecek", "Muhtara Ödenecek"),
    ("muhtara_odenen", "Muhtara Ödenen"),
    ("muhtara_kalan", "Muhtara Kalan"),
    ("fatura_no", "Fatura No"),
]

KOLON_BILGI = {
    "s_no": ("s_no", "sayi"),
    "koy_adi": ("koy_adi", "metin"),
    "adi": ("adi", "metin"),
    "soyadi": ("soyadi", "metin"),
    "sayac_no": ("sayac_no", "metin"),
    "senet_tutari": ("senet_tutari", "sayi"),
    "sayac_tutari": ("sayac_tutari", "sayi"),
    "alinan_tutar": ("alinan_tutar", "sayi"),
    "sayac_kalan": ("(sayac_tutari - alinan_tutar)", "sayi"),
    "malzeme_tutari": ("malzeme_tutari", "sayi"),
    "malzeme_alinan": ("malzeme_alinan", "sayi"),
    "malzeme_kalan": ("(malzeme_tutari - malzeme_alinan)", "sayi"),
    "toplam_kalan": ("(sayac_tutari + malzeme_tutari - alinan_tutar - malzeme_alinan)", "sayi"),
    "senet_no": ("senet_no", "metin"),
    "senet_sahibi_adi": ("senet_sahibi_adi", "metin"),
    "senet_sahibi_soyadi": ("senet_sahibi_soyadi", "metin"),
    "telefon": ("telefon", "metin"),
    "telefon2": ("telefon2", "metin"),
    "baba_adi": ("baba_adi", "metin"),
    "montaj_tarihi": ("montaj_tarihi", "tarih"),
    "odeme_tarihi": ("odeme_tarihi", "tarih"),
    "odeme_sekli": ("odeme_sekli", "metin"),
    "odeme_gun_sozu": ("odeme_gun_sozu", "tarih"),
    "odemeyi_gonderen": ("odemeyi_gonderen", "metin"),
    "aciklama": ("aciklama", "metin"),
    "muhtara_odenecek": ("muhtara_odenecek", "sayi"),
    "muhtara_odenen": ("muhtara_odenen", "sayi"),
    "muhtara_kalan": ("(muhtara_odenecek - muhtara_odenen)", "sayi"),
    "fatura_no": ("fatura_no", "metin"),
}

SAYISAL_KOLONLAR = {k for k, (_, tur) in KOLON_BILGI.items() if tur == "sayi"}
RENK_KOLONLARI = {"sayac_kalan", "malzeme_kalan", "toplam_kalan", "muhtara_kalan"}

ARIZA_DISPLAY_KOLONLARI = [
    ("s_no", "S.No"),
    ("ozel_s_no", "Özel S.No"),
    ("koy_adi", "Köy Adı"),
    ("yeni_seri_no", "Yeni Seri No"),
    ("seri_no", "Seri No"),
    ("adi", "Adı"),
    ("soyadi", "Soyadı"),
    ("telefon", "Telefon"),
    ("telefon2", "Telefon 2"),
    ("ariza_ucret", "Arıza Ücret"),
    ("alinan_ucret", "Alınan Ücret"),
    ("kalan_ucret", "Kalan Ücret"),
    ("gelis_tarihi", "Geliş Tarihi"),
    ("takilan_tarih", "Takılan Tarih"),
    ("sayac_kredisi", "Sayaç Kredisi"),
    ("tespit_edilen_ariza", "Tespit Edilen Arıza"),
    ("tespit_aciklama", "Tespit Açıklama"),
    ("yapilan_islemler", "Yapılan İşlemler"),
    ("islem_aciklama", "İşlem Açıklama"),
]

ARIZA_KOLON_BILGI = {
    "s_no": ("s_no", "sayi"),
    "ozel_s_no": ("ozel_s_no", "metin"),
    "koy_adi": ("koy_adi", "metin"),
    "yeni_seri_no": ("yeni_seri_no", "metin"),
    "seri_no": ("seri_no", "metin"),
    "adi": ("adi", "metin"),
    "soyadi": ("soyadi", "metin"),
    "telefon": ("telefon", "metin"),
    "telefon2": ("telefon2", "metin"),
    "ariza_ucret": ("ariza_ucret", "sayi"),
    "alinan_ucret": ("alinan_ucret", "sayi"),
    "kalan_ucret": ("(ariza_ucret - alinan_ucret)", "sayi"),
    "gelis_tarihi": ("gelis_tarihi", "tarih"),
    "takilan_tarih": ("takilan_tarih", "tarih"),
    "sayac_kredisi": ("sayac_kredisi", "metin"),
    "tespit_edilen_ariza": ("tespit_edilen_ariza", "metin"),
    "tespit_aciklama": ("tespit_aciklama", "metin"),
    "yapilan_islemler": ("yapilan_islemler", "metin"),
    "islem_aciklama": ("islem_aciklama", "metin"),
}

ARIZA_SAYISAL_KOLONLAR = {k for k, (_, tur) in ARIZA_KOLON_BILGI.items() if tur == "sayi"}

ARIZA_ALAN_TANIMLARI = [
    ("adi", "Adı", "adi", False),
    ("alinan_ucret", "Alınan Ücret", "alinan_ucret", True),
    ("ariza_ucret", "Arıza Ücret", "ariza_ucret", True),
    ("gelis_tarihi", "Geliş Tarihi", "gelis_tarihi", False),
    ("islem_aciklama", "İşlem Açıklama", "islem_aciklama", False),
    ("kalan_ucret", "Kalan Ücret", "(ariza_ucret - alinan_ucret)", True),
    ("koy_adi", "Köy Adı", "koy_adi", False),
    ("ozel_s_no", "Özel S.No", "ozel_s_no", False),
    ("s_no", "S.No", "s_no", True),
    ("sayac_kredisi", "Sayaç Kredisi", "sayac_kredisi", False),
    ("seri_no", "Seri No", "seri_no", False),
    ("soyadi", "Soyadı", "soyadi", False),
    ("takilan_tarih", "Takılan Tarih", "takilan_tarih", False),
    ("telefon", "Telefon", "telefon", False),
    ("telefon2", "Telefon 2", "telefon2", False),
    ("tespit_aciklama", "Tespit Açıklama", "tespit_aciklama", False),
    ("tespit_edilen_ariza", "Tespit Edilen Arıza", "tespit_edilen_ariza", False),
    ("yapilan_islemler", "Yapılan İşlemler", "yapilan_islemler", False),
    ("yeni_seri_no", "Yeni Seri No", "yeni_seri_no", False),
]

# "kolon" seçim onay kutularının (Tahsilat Çıktısı / Arıza Takip Çıktısı) yukarıdan
# aşağıya alfabetik sırada gösterilebilmesi için ayrı, alfabetik sıralı listeler.
# Tablo başlıkları / CSV dışa aktarımı hâlâ DISPLAY_KOLONLARI / ARIZA_DISPLAY_KOLONLARI
# sırasını kullanır; bu listeler SADECE onay kutusu görünümü içindir.
_ABONE_ALFABETIK_SIRA = [
    "aciklama", "adi", "alinan_tutar", "baba_adi", "fatura_no", "koy_adi",
    "malzeme_alinan", "malzeme_kalan", "malzeme_tutari", "montaj_tarihi",
    "muhtara_kalan", "muhtara_odenecek", "muhtara_odenen", "odeme_gun_sozu",
    "odeme_sekli", "odeme_tarihi", "odemeyi_gonderen", "s_no", "sayac_kalan",
    "sayac_no", "sayac_tutari", "senet_no", "senet_sahibi_adi",
    "senet_sahibi_soyadi", "senet_tutari", "soyadi", "telefon", "telefon2",
    "toplam_kalan",
]
_DISPLAY_KOLON_HARITASI = dict(DISPLAY_KOLONLARI)
DISPLAY_KOLONLARI_ALFABETIK = [(k, _DISPLAY_KOLON_HARITASI[k]) for k in _ABONE_ALFABETIK_SIRA]

_ARIZA_ALFABETIK_SIRA = [
    "adi", "alinan_ucret", "ariza_ucret", "gelis_tarihi", "islem_aciklama",
    "kalan_ucret", "koy_adi", "ozel_s_no", "s_no", "sayac_kredisi", "seri_no",
    "soyadi", "takilan_tarih", "telefon", "telefon2", "tespit_aciklama",
    "tespit_edilen_ariza", "yapilan_islemler", "yeni_seri_no",
]
_ARIZA_DISPLAY_KOLON_HARITASI = dict(ARIZA_DISPLAY_KOLONLARI)
ARIZA_DISPLAY_KOLONLARI_ALFABETIK = [(k, _ARIZA_DISPLAY_KOLON_HARITASI[k]) for k in _ARIZA_ALFABETIK_SIRA]


def _izgara_satir(n, sutun=4):
    """columns x N onay kutusu ızgarasında kaç satır gerektiğini hesaplar."""
    if n <= 0:
        return 1
    return math.ceil(n / sutun)

TESPIT_EDILEN_ARIZA_SECENEKLERI = [
    "Arıza Simgesi", "Data", "Dijital Su Almış", "Ekran Yok",
    "Error 1", "Error 2", "Error 3", "Error 4", "Error 5",
    "Harcama Uyuşmuyor", "Harcama Yapmıyor",
    "Kondansatör Devre Dışı", "Kondansatör Yok",
    "Küre Dönmüyor", "Küre Paslı", "Küre Zor Dönüyor",
    "Magnet", "Mekanik Patlak", "Motor Oksitli", "Motor Switch Arızalı",
    "Pil Bitik", "Pil Zayıf", "Sıkıntı Yok",
]

YAPILAN_ISLEMLER_SECENEKLERI = [
    "Formatlandı",
    "Kart Değişti", "Kart Ekran Değişti", "Kart Okuyucu Değişti", "Kart Temizlendi",
    "Kondansatör Devreye Alındı", "Kondansatör Takıldı",
    "Küre Değişti", "Küre Temizlendi",
    "Mekanik Değişti", "Mekanik Patlak Tamir", "Mekanik Pervane Değişti",
    "Motor Değişti", "Motor Switch Değişti", "Motor Tamir Edildi",
    "Pil Takıldı", "Resetlendi", "Sayım Aparatı Değişti",
]

# Form tek sayfaya sığsın diye bu ızgaralar 4 yerine 6 sütun hedefler (daha az satır).
TESPIT_SATIR = _izgara_satir(len(TESPIT_EDILEN_ARIZA_SECENEKLERI), 6)
TESPIT_SATIR_2 = _izgara_satir(len(TESPIT_EDILEN_ARIZA_SECENEKLERI), 2)
ISLEM_SATIR = _izgara_satir(len(YAPILAN_ISLEMLER_SECENEKLERI), 6)
ISLEM_SATIR_2 = _izgara_satir(len(YAPILAN_ISLEMLER_SECENEKLERI), 2)

# Abone Listesi'ndeki "Aynı Sayaç No'lu Kayıtları Getir" penceresinde her farklı
# sayaç no grubunu ayrı bir renkle göstermek için kullanılan renk paleti.
GRUP_RENK_PALETI = [
    "#c0392b", "#1f6fb2", "#8e44ad", "#0e8a6d", "#c2740c",
    "#2c3e50", "#c2185b", "#00796b", "#8a6d00", "#5b3a29",
    "#d35400", "#1a7a3c",
]

YEDEKLENECEK_TABLOLAR = ["abone", "tahsilat", "ariza", "ariza_tahsilat", "kullanici"]


def _gg_aa_yyyy(t):
    if not t:
        return ""
    t = str(t).strip()
    if len(t) >= 10 and t[4:5] == "-" and t[7:8] == "-":
        # ISO: YYYY-MM-DD
        return t[8:10] + "." + t[5:7] + "." + t[0:4]
    if len(t) >= 10 and t[2:3] == "." and t[5:6] == ".":
        # Zaten GG.AA.YYYY formatında
        return t[0:10]
    return t


def _iso_tarih_mi(t):
    t = (t or "").strip()
    return len(t) == 10 and t[4:5] == "-" and t[7:8] == "-"


def _ddmmyyyy_to_iso(t):
    t = (t or "").strip()
    if len(t) == 10 and t[2:3] == "." and t[5:6] == ".":
        return t[6:10] + "-" + t[3:5] + "-" + t[0:2]
    return None


def _tarih_iso_hale_getir(t):
    """<input type=date> alanına doğrudan basılabilecek YYYY-AA-GG biçimini döndürür."""
    t = (t or "").strip()
    if not t:
        return ""
    if _iso_tarih_mi(t):
        return t
    return _ddmmyyyy_to_iso(t) or ""


def _kolon_secenekleri(db, anahtar, tablo, bilgi_sozlugu):
    ifade, tur = bilgi_sozlugu[anahtar]
    cur = db.cursor()
    if tur == "sayi":
        cur.execute(
            f"SELECT DISTINCT deger FROM (SELECT ROUND(CAST({ifade} AS NUMERIC), 2) AS deger FROM {tablo}) t WHERE deger IS NOT NULL ORDER BY deger"
        )
    else:
        cur.execute(
            f"SELECT DISTINCT {ifade} AS deger FROM {tablo} WHERE {ifade} IS NOT NULL AND {ifade} != '' ORDER BY deger"
        )
    satirlar = cur.fetchall()
    cur.close()
    secenekler = []
    for s in satirlar:
        ham = s["deger"]
        if ham is None:
            continue
        if tur == "sayi":
            metin = tl_format(ham)
        elif tur == "tarih":
            metin = _gg_aa_yyyy(str(ham))
        else:
            metin = str(ham)
        secenekler.append((str(ham), metin))
    return secenekler


def _kolon_kosul_coklu(anahtar, deger_listesi, bilgi_sozlugu):
    ifade, tur = bilgi_sozlugu[anahtar]
    if tur == "sayi":
        sayilar = []
        for d in deger_listesi:
            try:
                sayilar.append(round(float(str(d).replace(",", ".")), 2))
            except ValueError:
                pass
        if not sayilar:
            return None, []
        yer_tutucular = ", ".join(["%s"] * len(sayilar))
        return f"ROUND(CAST({ifade} AS NUMERIC), 2) IN ({yer_tutucular})", sayilar
    yer_tutucular = ", ".join(["%s"] * len(deger_listesi))
    return f"{ifade} IN ({yer_tutucular})", deger_listesi


def _abone_satir_sozlugu(k):
    sayac_kalan = (k["sayac_tutari"] or 0) - (k["alinan_tutar"] or 0)
    malzeme_kalan = (k["malzeme_tutari"] or 0) - (k["malzeme_alinan"] or 0)
    toplam_kalan = sayac_kalan + malzeme_kalan
    muhtara_kalan = (k["muhtara_odenecek"] or 0) - (k["muhtara_odenen"] or 0)
    renk = {anahtar: '' for anahtar, _ in DISPLAY_KOLONLARI}
    renk["sayac_kalan"] = 'kirmizi' if sayac_kalan > 0 else 'yesil'
    renk["malzeme_kalan"] = 'kirmizi' if malzeme_kalan > 0 else 'yesil'
    renk["toplam_kalan"] = 'kirmizi' if toplam_kalan > 0 else 'yesil'
    renk["muhtara_kalan"] = 'kirmizi' if muhtara_kalan > 0 else 'yesil'
    return {
        "id": k["id"],
        "s_no": k["s_no"],
        "koy_adi": k["koy_adi"],
        "adi": k["adi"],
        "soyadi": k["soyadi"],
        "sayac_no": k["sayac_no"],
        "senet_tutari": tl_format(k["senet_tutari"]),
        "sayac_tutari": tl_format(k["sayac_tutari"]),
        "alinan_tutar": tl_format(k["alinan_tutar"]),
        "sayac_kalan": tl_format(sayac_kalan),
        "malzeme_tutari": tl_format(k["malzeme_tutari"]),
        "malzeme_alinan": tl_format(k["malzeme_alinan"]),
        "malzeme_kalan": tl_format(malzeme_kalan),
        "toplam_kalan": tl_format(toplam_kalan),
        "senet_no": k["senet_no"],
        "senet_sahibi_adi": k["senet_sahibi_adi"],
        "senet_sahibi_soyadi": k["senet_sahibi_soyadi"],
        "telefon": _telefon_formatla(k["telefon"]),
        "telefon2": _telefon_formatla(k["telefon2"]),
        "baba_adi": k["baba_adi"],
        "montaj_tarihi": _gg_aa_yyyy(k["montaj_tarihi"]),
        "odeme_tarihi": _gg_aa_yyyy(k["odeme_tarihi"]),
        "odeme_sekli": k["odeme_sekli"],
        "odeme_gun_sozu": _gg_aa_yyyy(k["odeme_gun_sozu"]),
        "odemeyi_gonderen": k["odemeyi_gonderen"],
        "aciklama": k["aciklama"],
        "muhtara_odenecek": tl_format(k["muhtara_odenecek"]),
        "muhtara_odenen": tl_format(k["muhtara_odenen"]),
        "muhtara_kalan": tl_format(muhtara_kalan),
        "fatura_no": _fatura_no_temizle(k["fatura_no"]),
        "_renk": renk,
    }


def _ariza_satir_sozlugu(k):
    kalan_ucret = (k["ariza_ucret"] or 0) - (k["alinan_ucret"] or 0)
    renk = {anahtar: '' for anahtar, _ in ARIZA_DISPLAY_KOLONLARI}
    renk["kalan_ucret"] = 'kirmizi' if kalan_ucret > 0 else 'yesil'
    return {
        "id": k["id"],
        "s_no": k["s_no"],
        "ozel_s_no": k["ozel_s_no"],
        "koy_adi": k["koy_adi"],
        "yeni_seri_no": k["yeni_seri_no"],
        "seri_no": k["seri_no"],
        "adi": k["adi"],
        "soyadi": k["soyadi"],
        "telefon": _telefon_formatla(k["telefon"]),
        "telefon2": _telefon_formatla(k["telefon2"]),
        "ariza_ucret": tl_format(k["ariza_ucret"]),
        "alinan_ucret": tl_format(k["alinan_ucret"]),
        "kalan_ucret": tl_format(kalan_ucret),
        "gelis_tarihi": _gg_aa_yyyy(k["gelis_tarihi"]),
        "takilan_tarih": _gg_aa_yyyy(k["takilan_tarih"]),
        "sayac_kredisi": k["sayac_kredisi"],
        "tespit_edilen_ariza": k["tespit_edilen_ariza"],
        "tespit_aciklama": k["tespit_aciklama"],
        "yapilan_islemler": k["yapilan_islemler"],
        "islem_aciklama": k["islem_aciklama"],
        "_renk": renk,
    }


def ensure_db():
    schema_yolu = os.path.join(os.path.dirname(os.path.abspath(__file__)), "schema.sql")
    conn = psycopg2.connect(DATABASE_URL)
    cur = conn.cursor()
    with open(schema_yolu, "r", encoding="utf-8") as f:
        cur.execute(f.read())
    conn.commit()

    admin_kullanici = os.environ.get("ADMIN_KULLANICI")
    admin_sifre = os.environ.get("ADMIN_SIFRE")
    if admin_kullanici and admin_sifre:
        cur.execute(
            "SELECT id FROM kullanici WHERE kullanici_adi = %s", (admin_kullanici,)
        )
        var_mi = cur.fetchone()
        if not var_mi:
            cur.execute(
                "INSERT INTO kullanici (kullanici_adi, sifre_hash) VALUES (%s, %s)",
                (admin_kullanici, generate_password_hash(admin_sifre)),
            )
            conn.commit()
    cur.close()
    conn.close()


ensure_db()


def get_db():
    if "db" not in g:
        g.db = psycopg2.connect(DATABASE_URL, cursor_factory=psycopg2.extras.RealDictCursor)
    return g.db


@app.teardown_appcontext
def close_db(exception=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def _filtre_durumu_uygula(route_adi):
    """Liste sayfalarında uygulanan filtreleri oturumda hatırlar.

    - Sorgu dizesinde 'bos=1' varsa (temizleme butonlarından geldiyse) hatırlanan
      filtre silinir ve sayfa filtresiz haline yönlendirilir.
    - Sorgu dizesi doluysa (bir filtre uygulanmışsa) bu durum oturumda saklanır.
    - Sorgu dizesi tamamen boşsa (menüden düz tıklanmışsa) ve daha önce
      kaydedilmiş bir filtre varsa, o filtreye yönlendirilir.
    Bir yönlendirme gerekiyorsa Response, gerekmiyorsa None döner.
    """
    anahtar = f"filtre_{route_adi}"
    if request.args.get("bos") == "1":
        session.pop(anahtar, None)
        return redirect(url_for(route_adi))
    qs = request.query_string.decode()
    if qs:
        session[anahtar] = qs
        return None
    kayitli = session.get(anahtar)
    if kayitli:
        return redirect(url_for(route_adi) + "?" + kayitli)
    return None


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("user_id"):
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapped


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        kullanici_adi = request.form.get("kullanici_adi", "").strip()
        sifre = request.form.get("sifre", "")

        db = get_db()
        cur = db.cursor()
        cur.execute("SELECT * FROM kullanici WHERE kullanici_adi = %s", (kullanici_adi,))
        user = cur.fetchone()
        cur.close()

        if user and check_password_hash(user["sifre_hash"], sifre):
            session.clear()
            session["user_id"] = user["id"]
            session["kullanici_adi"] = user["kullanici_adi"]
            return redirect(url_for("abone_listesi"))

        flash("Kullanıcı adı veya şifre hatalı.")

    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/")
@login_required
def index():
    return redirect(url_for("abone_listesi"))


@app.route("/yedek-al")
@login_required
def yedek_al():
    db = get_db()
    cur = db.cursor()
    parcalar = []
    for t in YEDEKLENECEK_TABLOLAR:
        cur.execute(f"SELECT * FROM {t}")
        for row in cur.fetchall():
            parcalar.append(cur.mogrify(f"INSERT INTO {t} VALUES %s;", (tuple(row.values()),)).decode())
    cur.close()
    icerik = "\n".join(parcalar)
    tarih = datetime.now().strftime("%d_%m_%Y")
    return Response(
        icerik,
        mimetype="text/plain",
        headers={"Content-Disposition": f"attachment; filename=algi_bilisim_yedek_{tarih}.sql"},
    )


def _csv_olustur(kolon_listesi, goster_kolonlari, satirlar, dosya_adi):
    cikti = io.StringIO()
    yazici = csv.writer(cikti, delimiter=';')
    basliklar = [etiket for anahtar, etiket in kolon_listesi if anahtar in goster_kolonlari]
    yazici.writerow(basliklar)
    for s in satirlar:
        satir = [s[anahtar] for anahtar, etiket in kolon_listesi if anahtar in goster_kolonlari]
        yazici.writerow(satir)
    icerik = "\ufeff" + cikti.getvalue()
    return Response(
        icerik,
        mimetype="text/csv",
        headers={"Content-Disposition": f"attachment; filename={dosya_adi}"},
    )


def _abone_kaynak_paketle(satirlar):
    ilk = satirlar[0]
    digerleri = [
        {"id": s["id"], "adi": s["adi"] or "", "soyadi": s["soyadi"] or "", "koy_adi": s["koy_adi"] or ""}
        for s in satirlar
    ]
    return {
        "bulundu": True,
        "adi": ilk["adi"] or "", "soyadi": ilk["soyadi"] or "",
        "telefon": ilk["telefon"] or "", "telefon2": ilk["telefon2"] or "",
        "koy_adi": ilk["koy_adi"] or "",
        "montaj_tarihi": _tarih_iso_hale_getir(ilk["montaj_tarihi"]),
        "coklu": len(satirlar) > 1,
        "digerleri": digerleri,
        "kaynak": "abone",
    }


def _koy_kaynak_paketle(satirlar):
    ilk = satirlar[0]
    digerleri = [
        {"id": s["id"], "adi": s["adi"] or "", "soyadi": s["soyadi"] or "", "koy_adi": s["koy_adi"] or ""}
        for s in satirlar
    ]
    return {
        "bulundu": True,
        "adi": ilk["adi"] or "", "soyadi": ilk["soyadi"] or "",
        "telefon": "", "telefon2": "",
        "koy_adi": ilk["koy_adi"] or "",
        "montaj_tarihi": _tarih_iso_hale_getir(ilk["abonelik_tarihi"]),
        "coklu": len(satirlar) > 1,
        "digerleri": digerleri,
        "kaynak": "koy_listesi",
    }


@app.route("/api/abone-ara")
@login_required
def abone_ara():
    sayac_no = request.args.get("sayac_no", "").strip()
    if not sayac_no:
        return jsonify({"bulundu": False})
    db = get_db()
    cur = db.cursor()
    cur.execute(
        "SELECT id, adi, soyadi, telefon, telefon2, koy_adi, montaj_tarihi FROM abone WHERE sayac_no = %s ORDER BY id",
        (sayac_no,),
    )
    abone_satirlari = cur.fetchall()

    # Ana abone (faturalama) tablosunun yanı sıra, köylerden Excel ile gelen köy abone
    # listelerinde de (cihaz no üzerinden) HER ZAMAN ara — sadece bulunamayınca değil —
    # çünkü aynı seri no iki kaynakta da farklı bilgilerle kayıtlı olabilir. Bu durumda
    # kullanıcıya her iki kaynağı da gösterip seçim yaptırıyoruz (bkz. ikinci_kaynak).
    cur.execute(
        "SELECT id, adi, soyadi, koy_adi, abonelik_tarihi FROM koy_abone WHERE cihaz_no = %s ORDER BY id",
        (sayac_no,),
    )
    koy_satirlari = cur.fetchall()
    cur.close()

    abone_paket = _abone_kaynak_paketle(abone_satirlari) if abone_satirlari else None
    koy_paket = _koy_kaynak_paketle(koy_satirlari) if koy_satirlari else None

    if not abone_paket and not koy_paket:
        return jsonify({"bulundu": False, "digerleri": []})

    birincil = abone_paket or koy_paket
    ikincil = koy_paket if abone_paket else None

    def _isim_anahtari(p):
        return ((p.get("adi") or "").strip().upper(), (p.get("soyadi") or "").strip().upper())

    farkli = bool(abone_paket and koy_paket and _isim_anahtari(abone_paket) != _isim_anahtari(koy_paket))

    sonuc = dict(birincil)
    sonuc["ikinci_kaynak"] = ikincil if (farkli and ikincil) else None
    return jsonify(sonuc)


@app.route("/api/ariza-gecmisi")
@login_required
def ariza_gecmisi():
    """Yeni arıza kaydı açılırken, girilen seri no'ya ait daha önce oluşturulmuş
    arıza kayıtlarını (varsa) döndürür, böylece kullanıcı önceki kayıtları görebilir."""
    seri_no = request.args.get("seri_no", "").strip()
    if not seri_no:
        return jsonify({"bulundu": False, "kayitlar": []})
    db = get_db()
    cur = db.cursor()
    cur.execute(
        "SELECT gelis_tarihi, takilan_tarih, tespit_edilen_ariza, yapilan_islemler, "
        "ariza_ucret, alinan_ucret FROM ariza WHERE seri_no = %s ORDER BY id DESC",
        (seri_no,),
    )
    satirlar = cur.fetchall()
    cur.close()

    kayitlar = []
    for s in satirlar:
        kalan = (s["ariza_ucret"] or 0) - (s["alinan_ucret"] or 0)
        kayitlar.append({
            "gelis_tarihi": _gg_aa_yyyy(s["gelis_tarihi"]),
            "takilan_tarih": _gg_aa_yyyy(s["takilan_tarih"]),
            "tespit_edilen_ariza": s["tespit_edilen_ariza"] or "",
            "yapilan_islemler": s["yapilan_islemler"] or "",
            "kalan_ucret": tl_format(kalan),
        })
    return jsonify({"bulundu": len(kayitlar) > 0, "kayitlar": kayitlar})


@app.route("/abone")
@login_required
def abone_listesi():
    yonlendirme = _filtre_durumu_uygula("abone_listesi")
    if yonlendirme:
        return yonlendirme

    q = request.args.get("q", "").strip()
    koy = request.args.get("koy", "").strip()
    alanlar_secili = request.args.getlist("alan")
    db = get_db()

    ALAN_TANIMLARI = [
        ("aciklama", "Açıklama", "aciklama", False),
        ("adi", "Adı", "adi", False),
        ("alinan_tutar", "Alınan", "alinan_tutar", True),
        ("baba_adi", "Baba Adı", "baba_adi", False),
        ("fatura_no", "Fatura No", "fatura_no", False),
        ("koy", "Köy", "koy_adi", False),
        ("malzeme_alinan", "Malzeme Alınan", "malzeme_alinan", True),
        ("malzeme_kalan", "Malzeme Kalan", "(malzeme_tutari - malzeme_alinan)", True),
        ("malzeme_tutari", "Malzeme Tutarı", "malzeme_tutari", True),
        ("montaj_tarihi", "Montaj Tarihi", "montaj_tarihi", False),
        ("muhtara_kalan", "Muhtara Kalan", "(muhtara_odenecek - muhtara_odenen)", True),
        ("muhtara_odenecek", "Muhtara Ödenecek", "muhtara_odenecek", True),
        ("muhtara_odenen", "Muhtara Ödenen", "muhtara_odenen", True),
        ("odeme_gun_sozu", "Ödeme Gün Sözü", "odeme_gun_sozu", False),
        ("odeme_sekli", "Ödeme Şekli", "odeme_sekli", False),
        ("odeme_tarihi", "Ödeme Tarihi", "odeme_tarihi", False),
        ("odemeyi_gonderen", "Ödemeyi Gönderen", "odemeyi_gonderen", False),
        ("s_no", "S.No", "s_no", True),
        ("sayac_kalan", "Sayaç Kalan", "(sayac_tutari - alinan_tutar)", True),
        ("sayac_no", "Sayaç No", "sayac_no", False),
        ("sayac_tutari", "Sayaç Tutarı", "sayac_tutari", True),
        ("senet_no", "Senet No", "senet_no", False),
        ("senet_sahibi_adi", "Senet Sahibi Adı", "senet_sahibi_adi", False),
        ("senet_sahibi_soyadi", "Senet Sahibi Soyadı", "senet_sahibi_soyadi", False),
        ("senet_tutari", "Senet Tutarı", "senet_tutari", True),
        ("soyadi", "Soyadı", "soyadi", False),
        ("telefon", "Telefon", "telefon", False),
        ("telefon2", "Telefon 2", "telefon2", False),
        ("toplam_kalan", "Toplam Kalan", "(sayac_tutari + malzeme_tutari - alinan_tutar - malzeme_alinan)", True),
    ]
    ALAN_HARITASI = {k: (kolon, sayisal) for k, _, kolon, sayisal in ALAN_TANIMLARI}
    alan_listesi = [(k, etiket) for k, etiket, _, _ in ALAN_TANIMLARI]

    sql = "SELECT * FROM abone WHERE 1=1"
    params = []
    if q:
        secili = alanlar_secili if alanlar_secili else [k for k, *_ in ALAN_TANIMLARI]

        q_sayi = None
        q_temiz = q.replace(",", ".").strip()
        try:
            q_sayi = float(q_temiz)
        except ValueError:
            q_sayi = None

        kosul_listesi = []
        kosul_params = []
        for s in secili:
            if s in ALAN_HARITASI:
                kolon, sayisal = ALAN_HARITASI[s]
                if sayisal and q_sayi is not None:
                    kosul_listesi.append(f"ROUND(CAST({kolon} AS NUMERIC), 2) = %s")
                    kosul_params.append(round(q_sayi, 2))
                elif sayisal:
                    kosul_listesi.append(f"CAST({kolon} AS TEXT) ILIKE %s")
                    kosul_params.append(f"%{q}%")
                else:
                    kosul_listesi.append(f"{kolon} ILIKE %s")
                    kosul_params.append(f"%{q}%")
        if kosul_listesi:
            sql += " AND (" + " OR ".join(kosul_listesi) + ")"
            params += kosul_params
    if koy:
        sql += " AND koy_adi = %s"
        params.append(koy)

    deger_secili = {}
    for anahtar, _ in DISPLAY_KOLONLARI:
        secilenler = request.args.getlist(f"deger_{anahtar}")
        deger_secili[anahtar] = secilenler
        if secilenler:
            kosul, param_listesi = _kolon_kosul_coklu(anahtar, secilenler, KOLON_BILGI)
            if kosul:
                sql += f" AND {kosul}"
                params += param_listesi

    sql += " ORDER BY s_no"

    cur = db.cursor()
    cur.execute(sql, params)
    kayitlar_ham = cur.fetchall()
    cur.execute("SELECT DISTINCT koy_adi FROM abone ORDER BY koy_adi")
    koyler = cur.fetchall()
    cur.execute("SELECT COUNT(*) AS c FROM abone")
    toplam_kayit = cur.fetchone()["c"]

    satirlar = [_abone_satir_sozlugu(k) for k in kayitlar_ham]

    deger_secenekleri = {}
    for anahtar, _ in DISPLAY_KOLONLARI:
        deger_secenekleri[anahtar] = _kolon_secenekleri(db, anahtar, "abone", KOLON_BILGI)
    cur.close()

    return render_template(
        "abone_list.html", satirlar=satirlar, koyler=koyler, q=q, secili_koy=koy,
        secili_alanlar=alanlar_secili, alan_listesi=alan_listesi,
        kolon_listesi=DISPLAY_KOLONLARI, deger_secili=deger_secili,
        deger_secenekleri=deger_secenekleri, sayisal_kolonlar=SAYISAL_KOLONLAR,
        arama_satir=_izgara_satir(len(alan_listesi)),
        arama_satir_2=_izgara_satir(len(alan_listesi), 2),
        filtreli_kayit=len(satirlar), toplam_kayit=toplam_kayit,
    )


@app.route("/abone/coklu-sayac")
@login_required
def abone_coklu_sayac():
    """Aynı sayaç no'ya birden fazla abonede rastlanan kayıtları, sayaç no'ya göre
    gruplanmış ve her grup farklı bir renkle işaretlenmiş şekilde ayrı bir sayfada gösterir."""
    db = get_db()
    cur = db.cursor()
    cur.execute(
        "SELECT sayac_no FROM abone WHERE sayac_no IS NOT NULL AND sayac_no != '' "
        "GROUP BY sayac_no HAVING COUNT(*) > 1 ORDER BY sayac_no"
    )
    gruplar = [r["sayac_no"] for r in cur.fetchall()]
    renk_haritasi = {sn: GRUP_RENK_PALETI[i % len(GRUP_RENK_PALETI)] for i, sn in enumerate(gruplar)}

    kayitlar_ham = []
    if gruplar:
        cur.execute(
            "SELECT * FROM abone WHERE sayac_no = ANY(%s) ORDER BY sayac_no, s_no",
            (gruplar,),
        )
        kayitlar_ham = cur.fetchall()
    cur.close()

    satirlar = [_abone_satir_sozlugu(k) for k in kayitlar_ham]
    for s in satirlar:
        s["_grup_renk"] = renk_haritasi.get(s["sayac_no"], "#333333")

    return render_template(
        "abone_coklu_sayac.html", satirlar=satirlar, grup_sayisi=len(gruplar),
    )


# ---------------------------------------------------------------------------
# Köy Abone Listeleri: köylerden Excel ile gelen abone kayıt defterleri.
# Ana "abone" tablosundan (faturalama/tahsilat) tamamen ayrı, kendi sayfası olan
# bir liste. Arıza Takip'te seri no aramasında ana tabloda bulunamayan seri
# no'lar için yedek kaynak olarak da kullanılır (bkz. abone_ara()).
# ---------------------------------------------------------------------------

def _koy_abone_satir_sozlugu(k):
    return {
        "id": k["id"],
        "koy_adi": k["koy_adi"] or "",
        "sira_no": k["sira_no"] or "",
        "abonelik_tarihi": _gg_aa_yyyy(k["abonelik_tarihi"]),
        "abone_no": k["abone_no"] or "",
        "cihaz_no": k["cihaz_no"] or "",
        "adi": k["adi"] or "",
        "soyadi": k["soyadi"] or "",
        "adres": k["adres"] or "",
    }


def _koy_excel_hucre_metin(v):
    if v is None:
        return ""
    if isinstance(v, datetime):
        return v.strftime("%d.%m.%Y")
    if isinstance(v, float):
        if v.is_integer():
            return str(int(v))
        return str(v)
    return str(v).strip()


# Farklı köylerin TEKSAN dışa aktarımlarında bu başlıkların sütun sırası kayabiliyor
# (bkz. Kemalpaşa'da Cihaz No J sütunu, Destek'te G sütunu). Bu yüzden sütunları sabit
# numarayla değil, dosyanın kendi başlık satırındaki yazılarla buluyoruz. Başlık satırı
# tespit edilemezse (beklenmeyen bir dosya biçimi), Kemalpaşa'nın düzenine geri düşülür.
_KOY_EXCEL_BASLIK_ETIKETLERI = {
    "sira_no": ["SIRA NO", "S.NO", "S NO", "SNO"],
    "abonelik_tarihi": ["ABONELİK TARİHİ", "ABONELIK TARIHI"],
    "abone_no": ["ABONE NO"],
    "cihaz_no": ["CİHAZ NO", "CIHAZ NO"],
    "adi_soyadi": ["ADI SOYADI"],
    "adres": ["ADRES"],
}

_KOY_EXCEL_VARSAYILAN_SUTUNLAR = {
    "sira_no": 0, "abonelik_tarihi": 3, "abone_no": 5,
    "cihaz_no": 9, "adi_soyadi": 13, "adres": 15,
}


def _koy_excel_baslik_normallestir(v):
    metin = _koy_excel_hucre_metin(v)
    return re.sub(r"\s+", " ", metin).strip().upper()


def _koy_excel_sutunlarini_bul(ham_satirlar):
    """Her satırı tarayıp SIRA NO / ADI SOYADI gibi başlıkların hangi sütunda
    olduğunu bulan satırı arar. Bulunursa sütun numaralarının sözlüğünü, aksi
    halde None döner."""
    for satir in ham_satirlar:
        if not satir:
            continue
        bulunanlar = {}
        for idx, deger in enumerate(satir):
            metin = _koy_excel_baslik_normallestir(deger)
            if not metin:
                continue
            for alan, olasi_etiketler in _KOY_EXCEL_BASLIK_ETIKETLERI.items():
                if alan in bulunanlar:
                    continue
                if metin in olasi_etiketler:
                    bulunanlar[alan] = idx
        if "sira_no" in bulunanlar and "adi_soyadi" in bulunanlar:
            return bulunanlar
    return None


def _koy_excel_satirlarini_ayikla(ham_satirlar):
    """TEKSAN tarzı köy abone listesi export'undaki ham satırlardan gerçek veri
    satırlarını ayıklar: tekrar eden başlık satırlarını ve boş ara satırları atlar.
    Sütunların hangi indekste olduğunu dosyanın kendi başlık satırından bulur."""
    sutunlar = _koy_excel_sutunlarini_bul(ham_satirlar) or _KOY_EXCEL_VARSAYILAN_SUTUNLAR

    sonuc = []
    for satir in ham_satirlar:
        if not satir:
            continue
        ilk_metin = _koy_excel_hucre_metin(satir[sutunlar["sira_no"]] if sutunlar["sira_no"] < len(satir) else None)
        if not ilk_metin:
            continue
        try:
            int(float(ilk_metin.replace(",", ".")))
        except ValueError:
            continue  # başlık satırı ("SIRA NO"/"S.NO") ya da veri olmayan satır

        def al(alan):
            idx = sutunlar.get(alan)
            if idx is None or idx >= len(satir):
                return None
            return satir[idx]

        abonelik_tarihi_ham = _koy_excel_hucre_metin(al("abonelik_tarihi"))
        adi_soyadi_ham = _koy_excel_hucre_metin(al("adi_soyadi"))
        parcalar = [p for p in re.split(r"\s{2,}", adi_soyadi_ham) if p]
        if len(parcalar) >= 2:
            adi, soyadi = parcalar[0], " ".join(parcalar[1:])
        elif parcalar:
            adi, soyadi = parcalar[0], ""
        else:
            adi, soyadi = "", ""

        sonuc.append({
            "sira_no": ilk_metin,
            "abonelik_tarihi": _tarih_iso_hale_getir(abonelik_tarihi_ham) or abonelik_tarihi_ham,
            "abone_no": _koy_excel_hucre_metin(al("abone_no")),
            "cihaz_no": _koy_excel_hucre_metin(al("cihaz_no")),
            "adi": adi,
            "soyadi": soyadi,
            "adres": _koy_excel_hucre_metin(al("adres")),
        })
    return sonuc


def _koy_excel_ayikla(dosya):
    """Yüklenen .xls/.xlsx dosyasından ham satırları okuyup köy abone kayıtlarına çevirir."""
    dosya_adi = (dosya.filename or "").lower()
    icerik = dosya.read()
    ham_satirlar = []

    if dosya_adi.endswith(".xls") and not dosya_adi.endswith(".xlsx"):
        import xlrd
        kitap = xlrd.open_workbook(file_contents=icerik)
        sayfa = kitap.sheet_by_index(0)
        for r in range(sayfa.nrows):
            satir = []
            for c in range(sayfa.ncols):
                hucre = sayfa.cell(r, c)
                deger = hucre.value
                if hucre.ctype == xlrd.XL_CELL_DATE:
                    try:
                        deger = xlrd.xldate_as_datetime(deger, kitap.datemode).strftime("%d.%m.%Y")
                    except Exception:
                        pass
                satir.append(deger)
            ham_satirlar.append(satir)
    else:
        import openpyxl
        kitap = openpyxl.load_workbook(io.BytesIO(icerik), data_only=True)
        sayfa = kitap.worksheets[0]
        for row in sayfa.iter_rows(values_only=True):
            ham_satirlar.append(list(row))

    return _koy_excel_satirlarini_ayikla(ham_satirlar)


@app.route("/koy-abone-listesi")
@login_required
def koy_abone_listesi():
    q = request.args.get("q", "").strip()
    koy = request.args.get("koy", "").strip()
    db = get_db()
    cur = db.cursor()

    sql = "SELECT * FROM koy_abone WHERE 1=1"
    params = []
    if koy:
        sql += " AND koy_adi = %s"
        params.append(koy)
    if q:
        sql += (" AND (adi ILIKE %s OR soyadi ILIKE %s OR cihaz_no ILIKE %s "
                "OR abone_no ILIKE %s OR adres ILIKE %s)")
        params += [f"%{q}%"] * 5

    cur.execute(sql, params)
    kayitlar_ham = cur.fetchall()

    cur.execute("SELECT DISTINCT koy_adi FROM koy_abone ORDER BY koy_adi")
    koyler = cur.fetchall()

    cur.execute("SELECT COUNT(*) AS c FROM koy_abone")
    toplam_kayit = cur.fetchone()["c"]

    secili_koy_toplam = None
    if koy:
        cur.execute("SELECT COUNT(*) AS c FROM koy_abone WHERE koy_adi = %s", (koy,))
        secili_koy_toplam = cur.fetchone()["c"]
    cur.close()

    satirlar = [_koy_abone_satir_sozlugu(k) for k in kayitlar_ham]

    def _siralama_anahtari(s):
        try:
            return (s["koy_adi"], 0, int(s["sira_no"]))
        except (TypeError, ValueError):
            return (s["koy_adi"], 1, s["sira_no"])

    satirlar.sort(key=_siralama_anahtari)

    return render_template(
        "koy_abone_listesi.html", satirlar=satirlar, koyler=koyler,
        q=q, secili_koy=koy,
        filtreli_kayit=len(satirlar), toplam_kayit=toplam_kayit,
        secili_koy_toplam=secili_koy_toplam,
    )


@app.route("/koy-abone-listesi/koy-sil", methods=["POST"])
@login_required
def koy_abone_koy_sil():
    koy_adi = request.form.get("koy_adi", "").strip()
    if koy_adi:
        db = get_db()
        cur = db.cursor()
        cur.execute("DELETE FROM koy_abone WHERE koy_adi = %s", (koy_adi,))
        silinen = cur.rowcount
        db.commit()
        cur.close()
        flash(f"\"{koy_adi}\" köyüne ait {silinen} kayıt silindi.")
    return redirect(url_for("koy_abone_listesi"))


def _koy_abone_kaydet(kayit_id):
    f = request.form
    alanlar = dict(
        koy_adi=f.get("koy_adi", "").strip(),
        sira_no=f.get("sira_no", "").strip(),
        abonelik_tarihi=f.get("abonelik_tarihi", "").strip(),
        abone_no=f.get("abone_no", "").strip(),
        cihaz_no=f.get("cihaz_no", "").strip(),
        adi=f.get("adi", "").strip(),
        soyadi=f.get("soyadi", "").strip(),
        adres=f.get("adres", "").strip(),
    )
    db = get_db()
    cur = db.cursor()
    if kayit_id is None:
        kolonlar = ", ".join(alanlar.keys())
        yer_tutucular = ", ".join(["%s"] * len(alanlar))
        cur.execute(f"INSERT INTO koy_abone ({kolonlar}) VALUES ({yer_tutucular})", list(alanlar.values()))
    else:
        set_ifadesi = ", ".join([f"{k} = %s" for k in alanlar.keys()])
        cur.execute(f"UPDATE koy_abone SET {set_ifadesi}, updated_at = NOW() WHERE id = %s", list(alanlar.values()) + [kayit_id])
    db.commit()
    cur.close()


@app.route("/koy-abone-listesi/yeni", methods=["GET", "POST"])
@login_required
def koy_abone_yeni():
    if request.method == "POST":
        _koy_abone_kaydet(None)
        return redirect(url_for("koy_abone_listesi"))
    return render_template("koy_abone_form.html", kayit=None)


@app.route("/koy-abone-listesi/<int:kayit_id>/duzenle", methods=["GET", "POST"])
@login_required
def koy_abone_duzenle(kayit_id):
    db = get_db()
    if request.method == "POST":
        _koy_abone_kaydet(kayit_id)
        return redirect(url_for("koy_abone_listesi"))
    cur = db.cursor()
    cur.execute("SELECT * FROM koy_abone WHERE id = %s", (kayit_id,))
    kayit = cur.fetchone()
    cur.close()
    if not kayit:
        flash("Kayıt bulunamadı.")
        return redirect(url_for("koy_abone_listesi"))
    return render_template("koy_abone_form.html", kayit=kayit)


@app.route("/koy-abone-listesi/<int:kayit_id>/sil", methods=["POST"])
@login_required
def koy_abone_sil(kayit_id):
    geri = request.args.get("geri", "")
    db = get_db()
    cur = db.cursor()
    cur.execute("DELETE FROM koy_abone WHERE id = %s", (kayit_id,))
    db.commit()
    cur.close()
    hedef = url_for("koy_abone_listesi")
    if geri:
        hedef += "?" + geri
    return redirect(hedef)


@app.route("/koy-abone-listesi/yukle", methods=["GET", "POST"])
@login_required
def koy_abone_yukle():
    db = get_db()
    if request.method == "GET":
        cur = db.cursor()
        cur.execute("SELECT DISTINCT koy_adi FROM koy_abone ORDER BY koy_adi")
        koyler = cur.fetchall()
        cur.close()
        return render_template("koy_abone_yukle.html", koyler=koyler)

    koy_adi = request.form.get("koy_adi", "").strip()
    dosya = request.files.get("dosya")

    if not koy_adi:
        flash("Köy adı boş bırakılamaz.")
        return redirect(url_for("koy_abone_yukle"))
    if not dosya or not dosya.filename:
        flash("Bir Excel dosyası (.xls veya .xlsx) seçmediniz.")
        return redirect(url_for("koy_abone_yukle"))

    try:
        yeni_kayitlar = _koy_excel_ayikla(dosya)
    except Exception as e:
        flash(f"Dosya okunamadı, format desteklenmiyor olabilir: {e}")
        return redirect(url_for("koy_abone_yukle"))

    if not yeni_kayitlar:
        flash("Dosyada okunabilir abone kaydı bulunamadı. Dosya formatını kontrol edin.")
        return redirect(url_for("koy_abone_yukle"))

    cur = db.cursor()
    cur.execute("DELETE FROM koy_abone WHERE koy_adi = %s", (koy_adi,))
    kolonlar = ["koy_adi", "sira_no", "abonelik_tarihi", "abone_no", "cihaz_no", "adi", "soyadi", "adres"]
    toplu_degerler = [
        (koy_adi, k["sira_no"], k["abonelik_tarihi"], k["abone_no"], k["cihaz_no"], k["adi"], k["soyadi"], k["adres"])
        for k in yeni_kayitlar
    ]
    kolonlar_sql = ", ".join(kolonlar)
    yer_tutucular = ", ".join(["%s"] * len(kolonlar))
    cur.executemany(f"INSERT INTO koy_abone ({kolonlar_sql}) VALUES ({yer_tutucular})", toplu_degerler)
    db.commit()
    cur.close()

    flash(f"\"{koy_adi}\" köyü için {len(yeni_kayitlar)} kayıt yüklendi (önceki liste silinip yenisiyle değiştirildi).")
    return redirect(url_for("koy_abone_listesi", koy=koy_adi))


def _sayilastir(deger):
    try:
        return float(str(deger).replace(",", ".").strip() or 0)
    except ValueError:
        return 0.0


def _sonraki_s_no(db):
    cur = db.cursor()
    cur.execute("SELECT MAX(s_no) AS m FROM abone")
    satir = cur.fetchone()
    cur.close()
    return (satir["m"] or 0) + 1


def _sonraki_senet_no(db):
    cur = db.cursor()
    cur.execute("SELECT senet_no FROM abone WHERE senet_no IS NOT NULL AND senet_no != ''")
    satirlar = cur.fetchall()
    cur.close()
    en_buyuk = 0
    for s in satirlar:
        try:
            deger = int(s["senet_no"])
            if deger > en_buyuk:
                en_buyuk = deger
        except (ValueError, TypeError):
            pass
    return str(en_buyuk + 1)


@app.route("/abone/yeni", methods=["GET", "POST"])
@login_required
def abone_yeni():
    if request.method == "POST":
        _abone_kaydet(None)
        return redirect(url_for("abone_listesi"))
    db = get_db()
    return render_template(
        "abone_form.html", kayit=None,
        sonraki_s_no=_sonraki_s_no(db),
        sonraki_senet_no=_sonraki_senet_no(db),
    )


@app.route("/abone/<int:abone_id>/duzenle", methods=["GET", "POST"])
@login_required
def abone_duzenle(abone_id):
    db = get_db()
    geri = request.args.get("geri", "") or request.form.get("geri", "")
    if request.method == "POST":
        _abone_kaydet(abone_id)
        hedef = url_for("abone_listesi")
        if geri:
            hedef += "?" + geri
        return redirect(hedef)
    cur = db.cursor()
    cur.execute("SELECT * FROM abone WHERE id = %s", (abone_id,))
    kayit = cur.fetchone()
    cur.close()
    if kayit is None:
        flash("Kayıt bulunamadı.")
        return redirect(url_for("abone_listesi"))
    return render_template("abone_form.html", kayit=kayit, geri=geri)


@app.route("/abone/<int:abone_id>/sil", methods=["POST"])
@login_required
def abone_sil(abone_id):
    geri = request.args.get("geri", "")
    db = get_db()
    cur = db.cursor()
    cur.execute("DELETE FROM abone WHERE id = %s", (abone_id,))
    db.commit()
    cur.close()
    hedef = url_for("abone_listesi")
    if geri:
        hedef += "?" + geri
    return redirect(hedef)


def _abone_kaydet(abone_id):
    f = request.form
    sayac_tutari = _sayilastir(f.get("sayac_tutari"))
    malzeme_tutari = _sayilastir(f.get("malzeme_tutari"))

    db = get_db()
    cur = db.cursor()

    if abone_id is None:
        alinan_tutar = 0.0
        malzeme_alinan = 0.0
    else:
        cur.execute("SELECT alinan_tutar, malzeme_alinan FROM abone WHERE id = %s", (abone_id,))
        mevcut = cur.fetchone()
        alinan_tutar = (mevcut["alinan_tutar"] or 0) if mevcut else 0.0
        malzeme_alinan = (mevcut["malzeme_alinan"] or 0) if mevcut else 0.0

    senet_tutari_hesap = sayac_tutari + malzeme_tutari - alinan_tutar - malzeme_alinan

    if senet_tutari_hesap == 0:
        senet_no_final = ""
    else:
        mevcut_senet_no = ""
        if abone_id is not None:
            cur.execute("SELECT senet_no FROM abone WHERE id = %s", (abone_id,))
            satir = cur.fetchone()
            if satir and satir["senet_no"]:
                mevcut_senet_no = satir["senet_no"]
        senet_no_final = mevcut_senet_no if mevcut_senet_no else _sonraki_senet_no(db)

    alanlar = dict(
        s_no=f.get("s_no") or None,
        koy_adi=f.get("koy_adi", "").strip(),
        adi=f.get("adi", "").strip(),
        soyadi=f.get("soyadi", "").strip(),
        sayac_no=f.get("sayac_no", "").strip(),
        senet_tutari=senet_tutari_hesap,
        sayac_tutari=sayac_tutari,
        alinan_tutar=alinan_tutar,
        malzeme_tutari=malzeme_tutari,
        malzeme_alinan=malzeme_alinan,
        senet_no=senet_no_final,
        senet_sahibi_adi=f.get("senet_sahibi_adi", "").strip(),
        senet_sahibi_soyadi=f.get("senet_sahibi_soyadi", "").strip(),
        telefon=_telefon_formatla(f.get("telefon", "")),
        telefon2=_telefon_formatla(f.get("telefon2", "")),
        baba_adi=f.get("baba_adi", "").strip(),
        montaj_tarihi=f.get("montaj_tarihi", "").strip(),
        odeme_tarihi=f.get("odeme_tarihi", "").strip(),
        odeme_sekli=f.get("odeme_sekli", "").strip(),
        odeme_gun_sozu=f.get("odeme_gun_sozu", "").strip(),
        odemeyi_gonderen=f.get("odemeyi_gonderen", "").strip(),
        aciklama=f.get("aciklama", "").strip(),
        muhtara_odenecek=_sayilastir(f.get("muhtara_odenecek")),
        muhtara_odenen=_sayilastir(f.get("muhtara_odenen")),
        fatura_no=f.get("fatura_no", "").strip(),
    )

    if abone_id is None:
        kolonlar = ", ".join(alanlar.keys())
        yer_tutucular = ", ".join(["%s"] * len(alanlar))
        cur.execute(
            f"INSERT INTO abone ({kolonlar}) VALUES ({yer_tutucular})",
            list(alanlar.values()),
        )
    else:
        set_ifadesi = ", ".join([f"{k} = %s" for k in alanlar.keys()])
        cur.execute(
            f"UPDATE abone SET {set_ifadesi}, updated_at = NOW() WHERE id = %s",
            list(alanlar.values()) + [abone_id],
        )
    db.commit()
    cur.close()


@app.route("/abone/<int:abone_id>/tahsilat", methods=["GET", "POST"])
@login_required
def abone_tahsilat(abone_id):
    db = get_db()
    cur = db.cursor()
    geri = request.args.get("geri", "") or request.form.get("geri", "")

    if request.method == "POST":
        tur = request.form.get("tur")
        tutar = _sayilastir(request.form.get("tutar"))
        tarih = request.form.get("tarih", "").strip()
        odeme_sekli = request.form.get("odeme_sekli", "").strip()
        odemeyi_yapan = request.form.get("odemeyi_yapan", "").strip()
        aciklama = request.form.get("aciklama", "").strip()

        if tur in ("sayac", "malzeme") and tutar:
            cur.execute(
                "INSERT INTO tahsilat (abone_id, tarih, tur, tutar, odeme_sekli, odemeyi_yapan, aciklama) VALUES (%s, %s, %s, %s, %s, %s, %s)",
                (abone_id, tarih, tur, tutar, odeme_sekli, odemeyi_yapan, aciklama),
            )
            kolon = "alinan_tutar" if tur == "sayac" else "malzeme_alinan"
            cur.execute(f"UPDATE abone SET {kolon} = {kolon} + %s WHERE id = %s", (tutar, abone_id))
            db.commit()

        cur.close()
        hedef = url_for("abone_tahsilat", abone_id=abone_id)
        if geri:
            hedef += "?geri=" + _url_quote(geri, safe="")
        return redirect(hedef)

    cur.execute("SELECT * FROM abone WHERE id = %s", (abone_id,))
    abone = cur.fetchone()
    if abone is None:
        cur.close()
        flash("Kayıt bulunamadı.")
        return redirect(url_for("abone_listesi"))

    cur.execute("SELECT * FROM tahsilat WHERE abone_id = %s ORDER BY tarih DESC, id DESC", (abone_id,))
    tahsilatlar = cur.fetchall()
    cur.close()

    return render_template(
        "abone_tahsilat.html", abone=abone, tahsilatlar=tahsilatlar, geri=geri,
        bugun=datetime.now().strftime("%Y-%m-%d"),
    )


@app.route("/tahsilat/<int:tahsilat_id>/sil", methods=["POST"])
@login_required
def tahsilat_sil(tahsilat_id):
    db = get_db()
    cur = db.cursor()
    cur.execute("SELECT abone_id, tur, tutar FROM tahsilat WHERE id = %s", (tahsilat_id,))
    kayit = cur.fetchone()
    abone_id = None
    if kayit:
        abone_id = kayit["abone_id"]
        kolon = "alinan_tutar" if kayit["tur"] == "sayac" else "malzeme_alinan"
        cur.execute(f"UPDATE abone SET {kolon} = {kolon} - %s WHERE id = %s", (kayit["tutar"], abone_id))
        cur.execute("DELETE FROM tahsilat WHERE id = %s", (tahsilat_id,))
        db.commit()
    cur.close()
    if abone_id:
        return redirect(url_for("abone_tahsilat", abone_id=abone_id))
    return redirect(url_for("abone_listesi"))


@app.route("/tahsilat/<int:tahsilat_id>/makbuz")
@login_required
def tahsilat_makbuz(tahsilat_id):
    db = get_db()
    cur = db.cursor()
    cur.execute(
        "SELECT t.*, a.adi AS abone_adi, a.soyadi AS abone_soyadi, a.sayac_no AS abone_sayac_no "
        "FROM tahsilat t JOIN abone a ON a.id = t.abone_id WHERE t.id = %s",
        (tahsilat_id,),
    )
    kayit = cur.fetchone()
    cur.close()
    if kayit is None:
        flash("Kayıt bulunamadı.")
        return redirect(url_for("abone_listesi"))

    ad_soyad = f"{kayit['abone_adi']} {kayit['abone_soyadi']}"
    aciklama_basligi = "Sayaç Ücreti Ödemesi" if kayit["tur"] == "sayac" else "Malzeme Ücreti Ödemesi"
    odemeyi_yapan = kayit["odemeyi_yapan"] or ad_soyad
    not_goster = bool(kayit["odemeyi_yapan"]) and kayit["odemeyi_yapan"].strip().upper() != ad_soyad.strip().upper()

    return render_template(
        "makbuz.html",
        sira_no=str(kayit["id"]).zfill(6),
        tarih=_gg_aa_yyyy(kayit["tarih"]),
        sayin=ad_soyad,
        tutar=kayit["tutar"],
        tutar_yazi=_tutar_yaziya_cevir(kayit["tutar"]),
        odeme_esles=_odeme_sekli_esle(kayit["odeme_sekli"]),
        odeme_sekli_metin=kayit["odeme_sekli"],
        aciklama_basligi=aciklama_basligi,
        seri_no=kayit["abone_sayac_no"],
        odemeyi_yapan=odemeyi_yapan,
        ad_soyad=ad_soyad,
        not_goster=not_goster,
        geri_url=url_for("abone_tahsilat", abone_id=kayit["abone_id"]),
    )


KOY_KOLONLARI = [
    ("koy_adi", "Köy Adı", "metin"),
    ("sayac_tutari_toplami", "Sayaç Tutarı", "sayi"),
    ("malzeme_tutari_toplami", "Malzeme Tutarı", "sayi"),
    ("genel_satis_tutari", "Genel Satış", "sayi"),
    ("tahsil_edilen_tutar", "Tahsil Edilen", "sayi"),
    ("kalan_tutar", "Kalan Tutar", "sayi"),
    ("muhtara_odenecek", "Muhtara Ödenecek", "sayi"),
    ("muhtara_odenen", "Muhtara Ödenen", "sayi"),
    ("muhtara_kalan", "Muhtar Kalan", "sayi"),
]


@app.route("/tahsilat")
@login_required
def tahsilat():
    yonlendirme = _filtre_durumu_uygula("tahsilat")
    if yonlendirme:
        return yonlendirme

    db = get_db()
    cur = db.cursor()
    cur.execute(
        "SELECT koy_adi, SUM(sayac_tutari) AS sayac_tutari_toplami, SUM(malzeme_tutari) AS malzeme_tutari_toplami, SUM(sayac_tutari + malzeme_tutari) AS genel_satis_tutari, SUM(alinan_tutar + malzeme_alinan) AS tahsil_edilen_tutar, SUM(sayac_tutari + malzeme_tutari - alinan_tutar - malzeme_alinan) AS kalan_tutar, SUM(muhtara_odenecek) AS muhtara_odenecek, SUM(muhtara_odenen) AS muhtara_odenen, SUM(muhtara_odenecek - muhtara_odenen) AS muhtara_kalan FROM abone GROUP BY koy_adi ORDER BY koy_adi"
    )
    satirlar_tum = cur.fetchall()
    cur.close()

    deger_secenekleri = {}
    for anahtar, etiket, tur in KOY_KOLONLARI:
        secenekler = []
        gorulen = set()
        for s in satirlar_tum:
            ham = s[anahtar]
            if ham is None:
                continue
            if tur == "sayi":
                ham_yuvarlanmis = round(float(ham), 2)
                anahtar_kelime = str(ham_yuvarlanmis)
                metin = tl_format(ham_yuvarlanmis)
            else:
                anahtar_kelime = str(ham)
                metin = str(ham)
            if anahtar_kelime not in gorulen:
                gorulen.add(anahtar_kelime)
                secenekler.append((anahtar_kelime, metin))
        secenekler.sort(key=lambda x: x[1])
        deger_secenekleri[anahtar] = secenekler

    deger_secili = {}
    for anahtar, etiket, tur in KOY_KOLONLARI:
        deger_secili[anahtar] = request.args.getlist(f"deger_{anahtar}")

    def _satir_uyumlu(s):
        for anahtar, etiket, tur in KOY_KOLONLARI:
            secilenler = deger_secili[anahtar]
            if not secilenler:
                continue
            ham = s[anahtar]
            if tur == "sayi":
                deger_kelime = str(round(float(ham or 0), 2))
            else:
                deger_kelime = str(ham)
            if deger_kelime not in secilenler:
                return False
        return True

    satirlar = [s for s in satirlar_tum if _satir_uyumlu(s)]

    genel = {
        "sayac_tutari_toplami": sum(s["sayac_tutari_toplami"] or 0 for s in satirlar),
        "malzeme_tutari_toplami": sum(s["malzeme_tutari_toplami"] or 0 for s in satirlar),
        "genel_satis_tutari": sum(s["genel_satis_tutari"] or 0 for s in satirlar),
        "tahsil_edilen_tutar": sum(s["tahsil_edilen_tutar"] or 0 for s in satirlar),
        "kalan_tutar": sum(s["kalan_tutar"] or 0 for s in satirlar),
        "muhtara_odenecek": sum(s["muhtara_odenecek"] or 0 for s in satirlar),
        "muhtara_odenen": sum(s["muhtara_odenen"] or 0 for s in satirlar),
        "muhtara_kalan": sum(s["muhtara_kalan"] or 0 for s in satirlar),
    }
    genel["firma_asil_alacagi"] = genel["kalan_tutar"] - genel["muhtara_kalan"]

    return render_template(
        "tahsilat.html", satirlar=satirlar, genel=genel,
        kolon_listesi=KOY_KOLONLARI, deger_secili=deger_secili,
        deger_secenekleri=deger_secenekleri,
        filtreli_kayit=len(satirlar), toplam_kayit=len(satirlar_tum),
    )


def _tahsilat_ciktisi_satirlar():
    kolonlar_secili = request.args.getlist("kolon")
    goster_kolonlari = kolonlar_secili if kolonlar_secili else [k for k, _ in DISPLAY_KOLONLARI]
    db = get_db()
    sql = "SELECT * FROM abone WHERE 1=1"
    params = []
    for anahtar in goster_kolonlari:
        secilenler = request.args.getlist(f"deger_{anahtar}")
        if secilenler:
            kosul, param_listesi = _kolon_kosul_coklu(anahtar, secilenler, KOLON_BILGI)
            if kosul:
                sql += f" AND {kosul}"
                params += param_listesi
    sql += " ORDER BY s_no"
    cur = db.cursor()
    cur.execute(sql, params)
    kayitlar_ham = cur.fetchall()
    cur.close()
    satirlar = [_abone_satir_sozlugu(k) for k in kayitlar_ham]
    return satirlar, goster_kolonlari


@app.route("/tahsilat-ciktisi")
@login_required
def tahsilat_ciktisi():
    yonlendirme = _filtre_durumu_uygula("tahsilat_ciktisi")
    if yonlendirme:
        return yonlendirme

    satirlar, goster_kolonlari = _tahsilat_ciktisi_satirlar()
    kolonlar_secili = request.args.getlist("kolon")
    db = get_db()

    deger_secili = {}
    for anahtar in goster_kolonlari:
        deger_secili[anahtar] = request.args.getlist(f"deger_{anahtar}")

    deger_secenekleri = {}
    for anahtar in goster_kolonlari:
        deger_secenekleri[anahtar] = _kolon_secenekleri(db, anahtar, "abone", KOLON_BILGI)

    cur = db.cursor()
    cur.execute("SELECT COUNT(*) AS c FROM abone")
    toplam_kayit = cur.fetchone()["c"]
    cur.close()

    return render_template(
        "tahsilat_ciktisi.html",
        satirlar=satirlar,
        kolon_listesi=DISPLAY_KOLONLARI, goster_kolonlari=goster_kolonlari,
        kolon_secim_listesi=DISPLAY_KOLONLARI_ALFABETIK,
        secili_kolonlar=kolonlar_secili,
        deger_secili=deger_secili, deger_secenekleri=deger_secenekleri,
        sayisal_kolonlar=SAYISAL_KOLONLAR,
        kolon_satir=_izgara_satir(len(DISPLAY_KOLONLARI_ALFABETIK)),
        kolon_satir_2=_izgara_satir(len(DISPLAY_KOLONLARI_ALFABETIK), 2),
        filtreli_kayit=len(satirlar), toplam_kayit=toplam_kayit,
    )


@app.route("/tahsilat-ciktisi-excel")
@login_required
def tahsilat_ciktisi_excel():
    satirlar, goster_kolonlari = _tahsilat_ciktisi_satirlar()
    tarih = datetime.now().strftime("%d_%m_%Y")
    return _csv_olustur(DISPLAY_KOLONLARI, goster_kolonlari, satirlar, f"tahsilat_ciktisi_{tarih}.csv")


def _ariza_sonraki_s_no(db):
    cur = db.cursor()
    cur.execute("SELECT MAX(s_no) AS m FROM ariza")
    satir = cur.fetchone()
    cur.close()
    return (satir["m"] or 0) + 1


def _ariza_kaydet(ariza_id):
    f = request.form
    ariza_ucret = _sayilastir(f.get("ariza_ucret"))
    alinan_ucret = _sayilastir(f.get("alinan_ucret"))
    tespit_metni = ", ".join(f.getlist("tespit_edilen_ariza"))
    islem_metni = ", ".join(f.getlist("yapilan_islemler"))

    alanlar = dict(
        s_no=f.get("s_no") or None,
        ozel_s_no=f.get("ozel_s_no", "").strip(),
        koy_adi=f.get("koy_adi", "").strip(),
        yeni_seri_no=f.get("yeni_seri_no", "").strip(),
        seri_no=f.get("seri_no", "").strip(),
        adi=f.get("adi", "").strip(),
        soyadi=f.get("soyadi", "").strip(),
        telefon=_telefon_formatla(f.get("telefon", "")),
        telefon2=_telefon_formatla(f.get("telefon2", "")),
        ariza_ucret=ariza_ucret,
        alinan_ucret=alinan_ucret,
        gelis_tarihi=f.get("gelis_tarihi", "").strip(),
        takilan_tarih=f.get("takilan_tarih", "").strip(),
        sayac_kredisi=f.get("sayac_kredisi", "").strip(),
        tespit_edilen_ariza=tespit_metni,
        tespit_aciklama=f.get("tespit_aciklama", "").strip(),
        yapilan_islemler=islem_metni,
        islem_aciklama=f.get("islem_aciklama", "").strip(),
    )

    db = get_db()
    cur = db.cursor()
    if ariza_id is None:
        kolonlar = ", ".join(alanlar.keys())
        yer_tutucular = ", ".join(["%s"] * len(alanlar))
        cur.execute(f"INSERT INTO ariza ({kolonlar}) VALUES ({yer_tutucular})", list(alanlar.values()))
    else:
        set_ifadesi = ", ".join([f"{k} = %s" for k in alanlar.keys()])
        cur.execute(f"UPDATE ariza SET {set_ifadesi}, updated_at = NOW() WHERE id = %s", list(alanlar.values()) + [ariza_id])
    db.commit()
    cur.close()


@app.route("/ariza/yeni", methods=["GET", "POST"])
@login_required
def ariza_yeni():
    if request.method == "POST":
        _ariza_kaydet(None)
        return redirect(url_for("ariza_listesi"))
    db = get_db()
    return render_template(
        "ariza_form.html", kayit=None,
        sonraki_s_no=_ariza_sonraki_s_no(db),
        tespit_secenekleri=TESPIT_EDILEN_ARIZA_SECENEKLERI,
        islem_secenekleri=YAPILAN_ISLEMLER_SECENEKLERI,
        secili_tespit=set(), secili_islem=set(),
        tespit_satir=TESPIT_SATIR, tespit_satir_2=TESPIT_SATIR_2,
        islem_satir=ISLEM_SATIR, islem_satir_2=ISLEM_SATIR_2,
        ilk_montaj_tarihi="",
        bugun=datetime.now().strftime("%Y-%m-%d"),
    )


@app.route("/ariza/<int:ariza_id>/duzenle", methods=["GET", "POST"])
@login_required
def ariza_duzenle(ariza_id):
    db = get_db()
    if request.method == "POST":
        _ariza_kaydet(ariza_id)
        return redirect(url_for("ariza_listesi"))
    cur = db.cursor()
    cur.execute("SELECT * FROM ariza WHERE id = %s", (ariza_id,))
    kayit = cur.fetchone()
    cur.close()
    if kayit is None:
        flash("Kayıt bulunamadı.")
        return redirect(url_for("ariza_listesi"))
    secili_tespit = set((kayit["tespit_edilen_ariza"] or "").split(", ")) if kayit["tespit_edilen_ariza"] else set()
    secili_islem = set((kayit["yapilan_islemler"] or "").split(", ")) if kayit["yapilan_islemler"] else set()

    ilk_montaj_tarihi = ""
    if kayit["seri_no"]:
        cur = db.cursor()
        cur.execute(
            "SELECT montaj_tarihi FROM abone WHERE sayac_no = %s ORDER BY id LIMIT 1",
            (kayit["seri_no"],),
        )
        abone_satir = cur.fetchone()
        cur.close()
        if abone_satir:
            ilk_montaj_tarihi = _tarih_iso_hale_getir(abone_satir["montaj_tarihi"])

    return render_template(
        "ariza_form.html", kayit=kayit,
        tespit_secenekleri=TESPIT_EDILEN_ARIZA_SECENEKLERI,
        islem_secenekleri=YAPILAN_ISLEMLER_SECENEKLERI,
        secili_tespit=secili_tespit, secili_islem=secili_islem,
        tespit_satir=TESPIT_SATIR, tespit_satir_2=TESPIT_SATIR_2,
        islem_satir=ISLEM_SATIR, islem_satir_2=ISLEM_SATIR_2,
        ilk_montaj_tarihi=ilk_montaj_tarihi,
        bugun=datetime.now().strftime("%Y-%m-%d"),
    )


@app.route("/ariza/<int:ariza_id>/sil", methods=["POST"])
@login_required
def ariza_sil(ariza_id):
    db = get_db()
    cur = db.cursor()
    cur.execute("DELETE FROM ariza WHERE id = %s", (ariza_id,))
    db.commit()
    cur.close()
    return redirect(url_for("ariza_listesi"))


@app.route("/ariza")
@login_required
def ariza_listesi():
    yonlendirme = _filtre_durumu_uygula("ariza_listesi")
    if yonlendirme:
        return yonlendirme

    db = get_db()
    q = request.args.get("q", "").strip()
    alanlar_secili = request.args.getlist("alan")
    ARIZA_ALAN_HARITASI = {k: (kolon, sayisal) for k, _, kolon, sayisal in ARIZA_ALAN_TANIMLARI}
    alan_listesi = [(k, etiket) for k, etiket, _, _ in ARIZA_ALAN_TANIMLARI]

    sql = "SELECT * FROM ariza WHERE 1=1"
    params = []

    if q:
        secili = alanlar_secili if alanlar_secili else [k for k, *_ in ARIZA_ALAN_TANIMLARI]

        q_sayi = None
        q_temiz = q.replace(",", ".").strip()
        try:
            q_sayi = float(q_temiz)
        except ValueError:
            q_sayi = None

        kosul_listesi = []
        kosul_params = []
        for s in secili:
            if s in ARIZA_ALAN_HARITASI:
                kolon, sayisal = ARIZA_ALAN_HARITASI[s]
                if sayisal and q_sayi is not None:
                    kosul_listesi.append(f"ROUND(CAST({kolon} AS NUMERIC), 2) = %s")
                    kosul_params.append(round(q_sayi, 2))
                elif sayisal:
                    kosul_listesi.append(f"CAST({kolon} AS TEXT) ILIKE %s")
                    kosul_params.append(f"%{q}%")
                else:
                    kosul_listesi.append(f"{kolon} ILIKE %s")
                    kosul_params.append(f"%{q}%")
        if kosul_listesi:
            sql += " AND (" + " OR ".join(kosul_listesi) + ")"
            params += kosul_params

    deger_secili = {}
    for anahtar, _ in ARIZA_DISPLAY_KOLONLARI:
        secilenler = request.args.getlist(f"deger_{anahtar}")
        deger_secili[anahtar] = secilenler
        if secilenler:
            kosul, param_listesi = _kolon_kosul_coklu(anahtar, secilenler, ARIZA_KOLON_BILGI)
            if kosul:
                sql += f" AND {kosul}"
                params += param_listesi
    sql += " ORDER BY s_no"

    cur = db.cursor()
    cur.execute(sql, params)
    kayitlar_ham = cur.fetchall()
    cur.execute("SELECT COUNT(*) AS c FROM ariza")
    toplam_kayit = cur.fetchone()["c"]
    cur.close()

    satirlar = [_ariza_satir_sozlugu(k) for k in kayitlar_ham]

    toplam_ariza_ucreti = sum(float(k["ariza_ucret"] or 0) for k in kayitlar_ham)
    tahsil_edilen_ucret = sum(float(k["alinan_ucret"] or 0) for k in kayitlar_ham)
    kalan_bakiye = toplam_ariza_ucreti - tahsil_edilen_ucret

    deger_secenekleri = {}
    for anahtar, _ in ARIZA_DISPLAY_KOLONLARI:
        deger_secenekleri[anahtar] = _kolon_secenekleri(db, anahtar, "ariza", ARIZA_KOLON_BILGI)

    return render_template(
        "ariza_listesi.html", satirlar=satirlar,
        kolon_listesi=ARIZA_DISPLAY_KOLONLARI,
        q=q, secili_alanlar=alanlar_secili, alan_listesi=alan_listesi,
        deger_secili=deger_secili, deger_secenekleri=deger_secenekleri,
        sayisal_kolonlar=ARIZA_SAYISAL_KOLONLAR,
        arama_satir=_izgara_satir(len(alan_listesi)),
        arama_satir_2=_izgara_satir(len(alan_listesi), 2),
        filtreli_kayit=len(satirlar), toplam_kayit=toplam_kayit,
        toplam_ariza_ucreti=toplam_ariza_ucreti,
        tahsil_edilen_ucret=tahsil_edilen_ucret,
        kalan_bakiye=kalan_bakiye,
    )


def _ariza_ciktisi_satirlar():
    kolonlar_secili = request.args.getlist("kolon")
    goster_kolonlari = kolonlar_secili if kolonlar_secili else [k for k, _ in ARIZA_DISPLAY_KOLONLARI]
    db = get_db()
    sql = "SELECT * FROM ariza WHERE 1=1"
    params = []
    for anahtar in goster_kolonlari:
        secilenler = request.args.getlist(f"deger_{anahtar}")
        if secilenler:
            kosul, param_listesi = _kolon_kosul_coklu(anahtar, secilenler, ARIZA_KOLON_BILGI)
            if kosul:
                sql += f" AND {kosul}"
                params += param_listesi
    sql += " ORDER BY s_no"
    cur = db.cursor()
    cur.execute(sql, params)
    kayitlar_ham = cur.fetchall()
    cur.close()
    satirlar = [_ariza_satir_sozlugu(k) for k in kayitlar_ham]
    return satirlar, goster_kolonlari


@app.route("/ariza-ciktisi")
@login_required
def ariza_ciktisi():
    yonlendirme = _filtre_durumu_uygula("ariza_ciktisi")
    if yonlendirme:
        return yonlendirme

    satirlar, goster_kolonlari = _ariza_ciktisi_satirlar()
    kolonlar_secili = request.args.getlist("kolon")
    db = get_db()

    deger_secili = {}
    for anahtar in goster_kolonlari:
        deger_secili[anahtar] = request.args.getlist(f"deger_{anahtar}")

    deger_secenekleri = {}
    for anahtar in goster_kolonlari:
        deger_secenekleri[anahtar] = _kolon_secenekleri(db, anahtar, "ariza", ARIZA_KOLON_BILGI)

    cur = db.cursor()
    cur.execute("SELECT COUNT(*) AS c FROM ariza")
    toplam_kayit = cur.fetchone()["c"]
    cur.close()

    return render_template(
        "ariza_ciktisi.html",
        satirlar=satirlar,
        kolon_listesi=ARIZA_DISPLAY_KOLONLARI, goster_kolonlari=goster_kolonlari,
        kolon_secim_listesi=ARIZA_DISPLAY_KOLONLARI_ALFABETIK,
        secili_kolonlar=kolonlar_secili,
        deger_secili=deger_secili, deger_secenekleri=deger_secenekleri,
        sayisal_kolonlar=ARIZA_SAYISAL_KOLONLAR,
        kolon_satir=_izgara_satir(len(ARIZA_DISPLAY_KOLONLARI_ALFABETIK)),
        kolon_satir_2=_izgara_satir(len(ARIZA_DISPLAY_KOLONLARI_ALFABETIK), 2),
        filtreli_kayit=len(satirlar), toplam_kayit=toplam_kayit,
    )


@app.route("/ariza-ciktisi-excel")
@login_required
def ariza_ciktisi_excel():
    satirlar, goster_kolonlari = _ariza_ciktisi_satirlar()
    tarih = datetime.now().strftime("%d_%m_%Y")
    return _csv_olustur(ARIZA_DISPLAY_KOLONLARI, goster_kolonlari, satirlar, f"ariza_ciktisi_{tarih}.csv")


@app.route("/ariza/<int:ariza_id>/tahsilat", methods=["GET", "POST"])
@login_required
def ariza_tahsilat(ariza_id):
    db = get_db()
    cur = db.cursor()

    if request.method == "POST":
        tutar = _sayilastir(request.form.get("tutar"))
        tarih = request.form.get("tarih", "").strip()
        odeme_sekli = request.form.get("odeme_sekli", "").strip()
        odemeyi_yapan = request.form.get("odemeyi_yapan", "").strip()
        aciklama = request.form.get("aciklama", "").strip()

        if tutar:
            cur.execute(
                "INSERT INTO ariza_tahsilat (ariza_id, tarih, tutar, odeme_sekli, odemeyi_yapan, aciklama) VALUES (%s, %s, %s, %s, %s, %s)",
                (ariza_id, tarih, tutar, odeme_sekli, odemeyi_yapan, aciklama),
            )
            cur.execute("UPDATE ariza SET alinan_ucret = alinan_ucret + %s WHERE id = %s", (tutar, ariza_id))
            db.commit()

        cur.close()
        return redirect(url_for("ariza_tahsilat", ariza_id=ariza_id))

    cur.execute("SELECT * FROM ariza WHERE id = %s", (ariza_id,))
    kayit = cur.fetchone()
    if kayit is None:
        cur.close()
        flash("Kayıt bulunamadı.")
        return redirect(url_for("ariza_listesi"))

    cur.execute("SELECT * FROM ariza_tahsilat WHERE ariza_id = %s ORDER BY tarih DESC, id DESC", (ariza_id,))
    tahsilatlar = cur.fetchall()
    cur.close()

    return render_template(
        "ariza_tahsilat.html", kayit=kayit, tahsilatlar=tahsilatlar,
        bugun=datetime.now().strftime("%Y-%m-%d"),
    )


@app.route("/ariza-tahsilat/<int:tahsilat_id>/sil", methods=["POST"])
@login_required
def ariza_tahsilat_sil(tahsilat_id):
    db = get_db()
    cur = db.cursor()
    cur.execute("SELECT ariza_id, tutar FROM ariza_tahsilat WHERE id = %s", (tahsilat_id,))
    kayit = cur.fetchone()
    ariza_id = None
    if kayit:
        ariza_id = kayit["ariza_id"]
        cur.execute("UPDATE ariza SET alinan_ucret = alinan_ucret - %s WHERE id = %s", (kayit["tutar"], ariza_id))
        cur.execute("DELETE FROM ariza_tahsilat WHERE id = %s", (tahsilat_id,))
        db.commit()
    cur.close()
    if ariza_id:
        return redirect(url_for("ariza_tahsilat", ariza_id=ariza_id))
    return redirect(url_for("ariza_listesi"))


@app.route("/ariza-tahsilat/<int:tahsilat_id>/makbuz")
@login_required
def ariza_tahsilat_makbuz(tahsilat_id):
    db = get_db()
    cur = db.cursor()
    cur.execute(
        "SELECT t.*, a.adi AS ariza_adi, a.soyadi AS ariza_soyadi, a.seri_no AS ariza_seri_no "
        "FROM ariza_tahsilat t JOIN ariza a ON a.id = t.ariza_id WHERE t.id = %s",
        (tahsilat_id,),
    )
    kayit = cur.fetchone()
    cur.close()
    if kayit is None:
        flash("Kayıt bulunamadı.")
        return redirect(url_for("ariza_listesi"))

    ad_soyad = f"{kayit['ariza_adi']} {kayit['ariza_soyadi']}"
    odemeyi_yapan = kayit["odemeyi_yapan"] or ad_soyad
    not_goster = bool(kayit["odemeyi_yapan"]) and kayit["odemeyi_yapan"].strip().upper() != ad_soyad.strip().upper()

    return render_template(
        "makbuz.html",
        sira_no=str(kayit["id"]).zfill(6),
        tarih=_gg_aa_yyyy(kayit["tarih"]),
        sayin=ad_soyad,
        tutar=kayit["tutar"],
        tutar_yazi=_tutar_yaziya_cevir(kayit["tutar"]),
        odeme_esles=_odeme_sekli_esle(kayit["odeme_sekli"]),
        odeme_sekli_metin=kayit["odeme_sekli"],
        aciklama_basligi="Arıza Ücreti Ödemesi",
        seri_no=kayit["ariza_seri_no"],
        odemeyi_yapan=odemeyi_yapan,
        ad_soyad=ad_soyad,
        not_goster=not_goster,
        geri_url=url_for("ariza_tahsilat", ariza_id=kayit["ariza_id"]),
    )


@app.route("/admin/toplu-abone-yukle")
@login_required
def toplu_abone_yukle():
    veri_dosyasi = os.path.join(os.path.dirname(os.path.abspath(__file__)), "abone_toplu_veri.b64")
    if not os.path.exists(veri_dosyasi):
        return (
            "Veri dosyası (abone_toplu_veri.b64) bulunamadı. "
            "Bu dosyanın app.py ile aynı klasörde (repo kök dizininde) olduğundan emin olun.",
            404,
        )

    with open(veri_dosyasi, "rb") as f:
        b64_veri = f.read()
    csv_metin = gzip.decompress(base64.b64decode(b64_veri)).decode("utf-8-sig")
    satirlar = list(csv.DictReader(io.StringIO(csv_metin)))

    db = get_db()
    cur = db.cursor()
    cur.execute("SELECT COUNT(*) AS c FROM abone")
    mevcut_sayi = cur.fetchone()["c"]

    onay = request.args.get("onayla") == "1"
    zorla = request.args.get("zorla") == "1"

    if not onay:
        if mevcut_sayi > 50:
            aksiyon = (
                f"<p style='color:#b00;font-weight:bold'>Dikkat: tabloda hâlihazırda {mevcut_sayi} kayıt var. "
                f"Bu işlem mevcut kayıtları SİLMEZ, üzerine {len(satirlar)} yeni kayıt EKLER. "
                f"Bu veriyi daha önce yüklediyseniz tekrar yüklemeyin, kayıtlar çiftlenir.</p>"
                f"<p><a href='?onayla=1&zorla=1' style='font-size:20px;color:#b00'>"
                f"Yine de devam et ve {len(satirlar)} kaydı ekle</a></p>"
            )
        else:
            aksiyon = (
                f"<p><a href='?onayla=1' style='font-size:20px'>"
                f"Evet, {len(satirlar)} kaydı içe aktar</a></p>"
            )
        cur.close()
        return f"""
        <html><body style="font-family:sans-serif;max-width:640px;margin:40px auto;line-height:1.5">
        <h2>Toplu Abone Yükleme</h2>
        <p>Excel dosyasından hazırlanan <b>{len(satirlar)}</b> abone kaydı,
        veritabanındaki <b>abone</b> tablosuna eklenmeye hazır.</p>
        <p>Şu anda tabloda <b>{mevcut_sayi}</b> kayıt bulunuyor.</p>
        {aksiyon}
        </body></html>
        """

    if mevcut_sayi > 50 and not zorla:
        cur.close()
        return "Güvenlik nedeniyle işlem durduruldu. Lütfen onay sayfasındaki linke tekrar tıklayın.", 400

    kolonlar = [
        "s_no", "koy_adi", "adi", "soyadi", "sayac_no", "senet_tutari", "sayac_tutari",
        "alinan_tutar", "malzeme_tutari", "malzeme_alinan", "senet_no",
        "senet_sahibi_adi", "senet_sahibi_soyadi", "telefon", "baba_adi",
        "montaj_tarihi", "odeme_tarihi", "odeme_sekli", "odemeyi_gonderen",
        "aciklama", "muhtara_odenecek", "muhtara_odenen", "fatura_no",
    ]
    sayisal_alanlar = {
        "senet_tutari", "sayac_tutari", "alinan_tutar", "malzeme_tutari",
        "malzeme_alinan", "muhtara_odenecek", "muhtara_odenen",
    }

    def _sayi(v):
        try:
            return float(v) if v not in (None, "") else 0.0
        except ValueError:
            return 0.0

    def _metin(v):
        return (v or "").strip()

    toplu_degerler = []
    for satir in satirlar:
        degerler = []
        for kolon in kolonlar:
            deger_ham = satir.get(kolon, "")
            if kolon == "s_no":
                degerler.append(deger_ham if deger_ham not in (None, "") else None)
            elif kolon in sayisal_alanlar:
                degerler.append(_sayi(deger_ham))
            else:
                degerler.append(_metin(deger_ham))
        toplu_degerler.append(tuple(degerler))

    kolonlar_sql = ", ".join(kolonlar)
    yer_tutucular = ", ".join(["%s"] * len(kolonlar))
    cur.executemany(
        f"INSERT INTO abone ({kolonlar_sql}) VALUES ({yer_tutucular})",
        toplu_degerler,
    )
    db.commit()
    eklenen = len(toplu_degerler)
    cur.close()

    return f"""
    <html><body style="font-family:sans-serif;max-width:640px;margin:40px auto;line-height:1.5">
    <h2 style="color:#0a0">Başarılı</h2>
    <p><b>{eklenen}</b> abone kaydı başarıyla eklendi.</p>
    <p><a href="/abone">Abone listesine git</a></p>
    </body></html>
    """


@app.route("/admin/toplu-ariza-yukle")
@login_required
def toplu_ariza_yukle():
    veri_dosyasi = os.path.join(os.path.dirname(os.path.abspath(__file__)), "ariza_toplu_veri.b64")
    if not os.path.exists(veri_dosyasi):
        return (
            "Veri dosyası (ariza_toplu_veri.b64) bulunamadı. "
            "Bu dosyanın app.py ile aynı klasörde (repo kök dizininde) olduğundan emin olun.",
            404,
        )

    with open(veri_dosyasi, "rb") as f:
        b64_veri = f.read()
    csv_metin = gzip.decompress(base64.b64decode(b64_veri)).decode("utf-8-sig")
    satirlar = list(csv.DictReader(io.StringIO(csv_metin)))

    db = get_db()
    cur = db.cursor()
    cur.execute("SELECT COUNT(*) AS c FROM ariza")
    mevcut_sayi = cur.fetchone()["c"]

    onay = request.args.get("onayla") == "1"
    zorla = request.args.get("zorla") == "1"

    if not onay:
        if mevcut_sayi > 50:
            aksiyon = (
                f"<p style='color:#b00;font-weight:bold'>Dikkat: tabloda hâlihazırda {mevcut_sayi} kayıt var. "
                f"Bu işlem mevcut kayıtları SİLMEZ, üzerine {len(satirlar)} yeni kayıt EKLER. "
                f"Bu veriyi daha önce yüklediyseniz tekrar yüklemeyin, kayıtlar çiftlenir.</p>"
                f"<p><a href='?onayla=1&zorla=1' style='font-size:20px;color:#b00'>"
                f"Yine de devam et ve {len(satirlar)} kaydı ekle</a></p>"
            )
        else:
            aksiyon = (
                f"<p><a href='?onayla=1' style='font-size:20px'>"
                f"Evet, {len(satirlar)} kaydı içe aktar</a></p>"
            )
        cur.close()
        return f"""
        <html><body style="font-family:sans-serif;max-width:640px;margin:40px auto;line-height:1.5">
        <h2>Toplu Arıza Yükleme</h2>
        <p>Excel dosyasından hazırlanan <b>{len(satirlar)}</b> arıza kaydı,
        veritabanındaki <b>ariza</b> tablosuna eklenmeye hazır.</p>
        <p>Şu anda tabloda <b>{mevcut_sayi}</b> kayıt bulunuyor.</p>
        {aksiyon}
        </body></html>
        """

    if mevcut_sayi > 50 and not zorla:
        cur.close()
        return "Güvenlik nedeniyle işlem durduruldu. Lütfen onay sayfasındaki linke tekrar tıklayın.", 400

    kolonlar = [
        "s_no", "ozel_s_no", "koy_adi", "yeni_seri_no", "seri_no", "adi", "soyadi",
        "ariza_ucret", "alinan_ucret", "gelis_tarihi", "takilan_tarih",
        "sayac_kredisi", "islem_aciklama",
    ]
    sayisal_alanlar = {"ariza_ucret", "alinan_ucret"}

    def _sayi(v):
        try:
            return float(v) if v not in (None, "") else 0.0
        except ValueError:
            return 0.0

    def _metin(v):
        return (v or "").strip()

    toplu_degerler = []
    for satir in satirlar:
        degerler = []
        for kolon in kolonlar:
            deger_ham = satir.get(kolon, "")
            if kolon == "s_no":
                degerler.append(deger_ham if deger_ham not in (None, "") else None)
            elif kolon in sayisal_alanlar:
                degerler.append(_sayi(deger_ham))
            else:
                degerler.append(_metin(deger_ham))
        toplu_degerler.append(tuple(degerler))

    kolonlar_sql = ", ".join(kolonlar)
    yer_tutucular = ", ".join(["%s"] * len(kolonlar))
    cur.executemany(
        f"INSERT INTO ariza ({kolonlar_sql}) VALUES ({yer_tutucular})",
        toplu_degerler,
    )
    db.commit()
    eklenen = len(toplu_degerler)
    cur.close()

    return f"""
    <html><body style="font-family:sans-serif;max-width:640px;margin:40px auto;line-height:1.5">
    <h2 style="color:#0a0">Başarılı</h2>
    <p><b>{eklenen}</b> arıza kaydı başarıyla eklendi.</p>
    <p><a href="/ariza">Arıza listesine git</a></p>
    </body></html>
    """


@app.route("/admin/tarih-formati-duzelt")
@login_required
def tarih_formati_duzelt():
    onay = request.args.get("onayla") == "1"
    db = get_db()
    cur = db.cursor()

    hedefler = [
        ("abone", ["montaj_tarihi", "odeme_tarihi", "odeme_gun_sozu"]),
        ("ariza", ["gelis_tarihi", "takilan_tarih"]),
    ]

    bulunanlar = []
    for tablo, kolonlar in hedefler:
        for kolon in kolonlar:
            cur.execute(f"SELECT id, {kolon} FROM {tablo} WHERE {kolon} IS NOT NULL AND {kolon} != ''")
            for satir in cur.fetchall():
                iso = _ddmmyyyy_to_iso(satir[kolon])
                if iso:
                    bulunanlar.append((tablo, kolon, satir["id"], satir[kolon], iso))

    if not onay:
        cur.close()
        if not bulunanlar:
            return """
            <html><body style="font-family:sans-serif;max-width:640px;margin:40px auto;line-height:1.5">
            <h2>Tarih Formatı Düzeltme</h2>
            <p>Düzeltilmesi gereken GG.AA.YYYY formatında kayıt bulunamadı. Tüm tarihler zaten doğru formatta.</p>
            <p><a href="/abone">Abone listesine git</a></p>
            </body></html>
            """
        return f"""
        <html><body style="font-family:sans-serif;max-width:640px;margin:40px auto;line-height:1.5">
        <h2>Tarih Formatı Düzeltme</h2>
        <p><b>{len(bulunanlar)}</b> tarih alanı, aktarım sırasında GG.AA.YYYY metin formatında kaydedilmiş.
        Bu işlem bunları veritabanının beklediği YYYY-AA-GG formatına çevirecek. Görünen tarihler
        (GG.AA.YYYY) değişmeyecek, sadece arka plandaki kayıt biçimi düzelecek.</p>
        <p><a href="?onayla=1" style="font-size:20px">Evet, {len(bulunanlar)} tarihi düzelt</a></p>
        </body></html>
        """

    for tablo, kolon, kayit_id, eski, iso in bulunanlar:
        cur.execute(f"UPDATE {tablo} SET {kolon} = %s WHERE id = %s", (iso, kayit_id))
    db.commit()
    duzeltilen = len(bulunanlar)
    cur.close()

    return f"""
    <html><body style="font-family:sans-serif;max-width:640px;margin:40px auto;line-height:1.5">
    <h2 style="color:#0a0">Başarılı</h2>
    <p><b>{duzeltilen}</b> tarih alanı düzeltildi.</p>
    <p><a href="/abone">Abone listesine git</a></p>
    </body></html>
    """


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=True)
