import os
import io
import re
import csv
import gzip
import math
import time
import base64
import hmac
import secrets
import threading
from datetime import datetime
from functools import wraps
from urllib.parse import quote as _url_quote, urlencode as _urlencode

import psycopg2
import psycopg2.extras
import psycopg2.pool
from jinja2.sandbox import SandboxedEnvironment
from flask import (
    Flask, render_template, request, redirect,
    url_for, session, g, flash, jsonify, Response, send_from_directory
)
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.middleware.proxy_fix import ProxyFix

try:
    import mammoth
except Exception:
    # mammoth kurulu değilse (ör. requirements.txt henüz güncellenmediyse) uygulamanın
    # tamamı çökmesin diye — sadece Word'den tasarım yükleme özelliği devre dışı kalır,
    # geri kalan her şey normal çalışmaya devam eder.
    mammoth = None

try:
    from bs4 import BeautifulSoup
except Exception:
    # aynı mantık: kurulu değilse sadece kenarlık onarma adımı atlanır, uygulama çökmez.
    BeautifulSoup = None

DATABASE_URL = os.environ.get("DATABASE_URL")
SECRET_KEY = os.environ.get("SECRET_KEY")
if not SECRET_KEY:
    # ESKİDEN burada GitHub'da herkese açık, sabit bir "yedek" anahtar vardı
    # ("gelistirme-icin-degistir"). SECRET_KEY oturum çerezlerini imzalamak için
    # kullanılıyor — bilinen/sabit bir değerle çalışırsa, bu değeri bilen biri
    # sahte bir oturum çerezi üretip HERHANGİ bir kullanıcı olarak giriş
    # yapabilirdi. Bu yüzden artık ortam değişkeni tanımlı değilse uygulama
    # sessizce zayıf bir anahtara düşmek yerine hiç başlamıyor.
    raise RuntimeError(
        "SECRET_KEY ortam değişkeni tanımlı değil. Güvenlik nedeniyle uygulama "
        "bilinen/sabit bir yedek anahtarla çalışmayı reddediyor. DigitalOcean "
        "panelinde bileşen ayarlarına rastgele, uzun bir SECRET_KEY ortam "
        "değişkeni ekleyip yeniden deploy edin."
    )

app = Flask(__name__)
app.secret_key = SECRET_KEY

# DigitalOcean App Platform, uygulamanın önünde kendi ters vekil (reverse
# proxy) sunucusunu çalıştırıyor — yani gerçek ziyaretçi IP'si doğrudan
# request.remote_addr'da değil, proxy'nin eklediği X-Forwarded-For başlığında
# gelir. ProxyFix, Werkzeug'a TEK bir güvenilir vekil katmanının arkasında
# olduğumuzu (x_for=1) söyleyip request.remote_addr'ı bu başlıktan doğru
# şekilde dolduruyor — aksi halde aşağıdaki giriş deneme sınırlaması (IP'ye
# göre) herkesi aynı (proxy'nin) IP'siymiş gibi görüp ya hep birlikte kilitler
# ya da hiç işe yaramaz.
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1)

# Oturum çerezi (session cookie) güvenlik ayarları — önceden hiç ayarlanmamıştı,
# yani Flask'ın varsayılanları geçerliydi (SESSION_COOKIE_SECURE=False). Bunları
# açıkça ayarlıyoruz:
#   - HTTPONLY: JavaScript'in çerezi okumasını engeller (zaten Flask varsayılanı
#     True'dur, ama açıkça belirtmek daha güvenli/okunaklı).
#   - SAMESITE=Lax: çerezin başka sitelerden yapılan (form gönderimi gibi)
#     isteklerle otomatik gönderilmesini engeller — CSRF riskini azaltır.
#   - SECURE: çerezin sadece HTTPS üzerinden gönderilmesini zorunlu kılar.
#     Geliştirme (FLASK_DEBUG=1, yerel http://localhost) sırasında kapalı
#     kalır, aksi halde yerel testte oturum hiç açılmaz; DigitalOcean'daki
#     canlı ortam zaten HTTPS olduğu için üretimde bu her zaman True olur.
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = os.environ.get("FLASK_DEBUG", "0") != "1"

# --- CSRF (siteler arası istek sahteciliği) koruması ------------------------
# Üçüncü parti bir pakete bağımlı olmadan, oturuma (session) bağlı bir "eşleşen
# token" deseni kullanılıyor: her oturum için rastgele, tahmin edilemez bir
# token üretilip session'da saklanır (generate_csrf/csrf_token). Veri
# değiştiren (POST/PUT/PATCH/DELETE) her istekte, formdan (ya da JSON
# isteklerde X-CSRFToken başlığından) gelen token bununla karşılaştırılır;
# eşleşmezse istek reddedilir. Bu, başka bir sitedeki kötü niyetli bir sayfanın
# ya da bir bağlantının, oturumu açık bir kullanıcının tarayıcısını kullanarak
# onun adına habersizce POST isteği göndermesini (CSRF) engeller — ör. giriş
# yapmış birine gönderilen sahte bir linke tıklanması sonucu istemeden veri
# silinmesi/değiştirilmesi gibi.


def generate_csrf():
    """Oturum için CSRF token'ı döner; oturumda henüz yoksa yeni, rastgele bir
    tane üretip session'a kaydeder. Şablonlarda {{ csrf_token() }} olarak
    çağrılabilmesi için aşağıda Jinja global'i olarak da kaydediliyor."""
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_hex(32)
    return session["csrf_token"]


app.jinja_env.globals["csrf_token"] = generate_csrf


@app.before_request
def _csrf_dogrula():
    if request.method not in ("POST", "PUT", "PATCH", "DELETE"):
        return None
    beklenen = session.get("csrf_token")
    gelen = (
        request.form.get("csrf_token")
        or request.headers.get("X-CSRFToken")
        or request.headers.get("X-CSRF-Token")
    )
    if not beklenen or not gelen or not hmac.compare_digest(beklenen, gelen):
        return (
            "Güvenlik doğrulaması başarısız oldu (sayfa çok uzun süre açık "
            "kalmış ya da oturum yenilenmiş olabilir). Lütfen sayfayı "
            "yenileyip işlemi tekrar deneyin.",
            400,
        )
    return None


# Yanlışlıkla (veya kötü niyetle) çok büyük dosya yüklenip sunucunun
# yorulmasını önlemek için tüm istekler için üst sınır (fotoğraf/video
# yükleme özelliği eklenince gerekli oldu). Birden fazla video aynı anda
# yüklenebildiği için tekil dosya sınırından (60 MB) daha geniş tutuluyor.
app.config["MAX_CONTENT_LENGTH"] = 200 * 1024 * 1024


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


_TURKCE_KUCUK_HARF_TABLOSU = str.maketrans({
    "İ": "i", "I": "i", "ı": "i", "i": "i",
    "Ç": "c", "ç": "c",
    "Ğ": "g", "ğ": "g",
    "Ö": "o", "ö": "o",
    "Ş": "s", "ş": "s",
    "Ü": "u", "ü": "u",
})


def _turkce_normallestir(deger):
    """Arama kutusuna büyük/küçük harf ya da Türkçe'ye özgü İ/I/ı/i, Ç/Ş/Ğ/Ö/Ü
    farkı gözetmeden yazılabilmesi için kullanılıyor. Postgres'in kendi
    LOWER()/ILIKE'ı veritabanının "locale" ayarına bağlı çalışıyor — birçok
    yönetilen (managed) Postgres kurulumu varsayılan olarak "C"/"C.UTF-8"
    locale kullanıyor, bu da Türkçe'ye özgü harfleri (özellikle İ/ı ve
    Ç/Ş/Ğ/Ö/Ü) tanımadığı için küçük harfe çevirmiyor — sonuçta "İBRAHİM"
    yazılı bir kayıt "ibrahim" ile aranınca bulunamıyor. Bunun yerine hem
    aranan kelimeyi (burada) hem veritabanı tarafındaki kolonu (bkz.
    _turkce_esle_kosul) SABİT, locale'den bağımsız bir çeviriyle küçük harfe
    çeviriyoruz ki ikisi her zaman aynı şekilde eşleşsin."""
    return (deger or "").translate(_TURKCE_KUCUK_HARF_TABLOSU).lower()


def _turkce_esle_kosul(kolon_ifadesi):
    """`_turkce_normallestir` ile birebir aynı çeviriyi SQL tarafında (bir
    kolon/ifade için) uygulayan, `LIKE %s` ile birlikte kullanılacak ifadeyi
    döndürür. `kolon_ifadesi` her zaman kod içinde sabit (kullanıcıdan
    gelmiyor), bu yüzden doğrudan string birleştirme güvenlidir."""
    return (
        f"LOWER(TRANSLATE({kolon_ifadesi}, "
        "'İIıiÇĞÖŞÜçğöşü', 'iiiicgosucgosu'))"
    )


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
    ("montaj_personeli", "Montaj Personeli"),
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
    "montaj_personeli": ("montaj_personeli", "metin"),
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
    ("teslim_tarihi", "Teslim Edilen Tarih"),
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
    "teslim_tarihi": ("teslim_tarihi", "tarih"),
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
    ("teslim_tarihi", "Teslim Edilen Tarih", "teslim_tarihi", False),
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
    "malzeme_alinan", "malzeme_kalan", "malzeme_tutari", "montaj_personeli",
    "montaj_tarihi",
    "muhtara_kalan", "muhtara_odenecek", "muhtara_odenen", "odeme_gun_sozu",
    "odeme_sekli", "odeme_tarihi", "odemeyi_gonderen", "s_no", "sayac_kalan",
    "sayac_no", "sayac_tutari", "senet_no", "senet_sahibi_adi",
    "senet_sahibi_soyadi", "senet_tutari", "soyadi", "telefon", "telefon2",
    "toplam_kalan",
]
_DISPLAY_KOLON_HARITASI = dict(DISPLAY_KOLONLARI)
DISPLAY_KOLONLARI_ALFABETIK = [(k, _DISPLAY_KOLON_HARITASI[k]) for k in _ABONE_ALFABETIK_SIRA]

# "Özel Alan Ayarları" ekranından kullanıcının koda dokunmadan eklediği alanlar
# (bkz. schema.sql'deki ozel_alan tablosu). Bu alanlar gerçek veritabanı
# sütunlarıdır (ALTER TABLE ile eklenir) — bu yüzden mevcut sıralama/filtreleme/
# CSV dışa aktarma mekanizmasına, sadece DISPLAY_KOLONLARI/KOLON_BILGI gibi
# sabit listelere bu fonksiyonlarla üretilen ek satırları katarak sorunsuzca
# dahil olurlar.
_OZEL_ALAN_TUR_PG = {"metin": "TEXT", "tarih": "TEXT", "sayi": "REAL"}
_OZEL_ALAN_TUR_ETIKETLERI = {"metin": "Metin", "tarih": "Tarih", "sayi": "Sayı"}

# "Özel Alan Ayarları" ekranındaki sürükle-bırak önizlemesinin ve abone_form.html/
# ariza_form.html şablonlarının, formdaki SABİT (koddan gelen) alanların TAM
# OLARAK hangi sırada göründüğünü bilmesi gerekiyor — bir özel alan, buradaki
# iki anahtarın arasına yerleştirilebiliyor. Bu liste, ilgili şablondaki
# <div>...<label>...<input name="..."> bloklarının GERÇEK sırasıyla birebir
# aynı olmalı; şablonda alan sırası değişirse burası da güncellenmeli.
ABONE_FORM_ALAN_SIRASI = [
    ("koy_adi", "Köy Adı"), ("adi", "Adı"), ("soyadi", "Soyadı"), ("sayac_no", "Sayaç No"),
    ("baba_adi", "Baba Adı"), ("telefon", "Telefon"), ("telefon2", "Telefon 2"),
    ("sayac_tutari", "Sayaç Tutarı"), ("alinan_tutar", "Alınan Tutar"),
    ("senet_sahibi_adi", "Senet Sahibi Adı"), ("senet_sahibi_soyadi", "Senet Sahibi Soyadı"),
    ("malzeme_tutari", "Malzeme Tutarı"), ("malzeme_alinan", "Malzeme Alınan"),
    ("montaj_tarihi", "Montaj Tarihi"), ("montaj_personeli", "Montaj Personeli"),
    ("odeme_tarihi", "Ödeme Tarihi"), ("odeme_sekli", "Ödeme Şekli"),
    ("odemeyi_gonderen", "Ödemeyi Gönderen"), ("odeme_gun_sozu", "Ödeme Gün Sözü"),
    ("fatura_no", "Fatura No"), ("muhtara_odenecek", "Muhtara Ödenecek"),
    ("muhtara_odenen", "Muhtara Ödenen"), ("aciklama", "Açıklama"),
]
ARIZA_FORM_ALAN_SIRASI = [
    ("ozel_s_no", "Özel S.No"), ("seri_no", "Seri No"), ("koy_adi", "Köy Adı"),
    ("yeni_seri_no", "Yeni Seri No"), ("adi", "Adı"), ("soyadi", "Soyadı"),
    ("telefon", "Telefon"), ("telefon2", "Telefon 2"),
    ("ariza_ucret", "Arıza Ücret"), ("alinan_ucret", "Alınan Ücret"),
    ("gelis_tarihi", "Geliş Tarihi"), ("takilan_tarih", "Takılan Tarih"),
    ("teslim_tarihi", "Teslim Edilen Tarih"), ("sayac_kredisi", "Sayaç Kredisi"),
    ("tespit_aciklama", "Tespit Edilen Arıza - Açıklama"),
    ("islem_aciklama", "Yapılan İşlemler - Açıklama"),
]


def _ozel_alanlari_getir(db, tablo):
    """Bir tablonun ('abone' ya da 'ariza') aktif özel alanlarını, gösterim
    sırasına göre döndürür (id, kolon_adi, etiket, tur, sonra_gelen_alan
    alanlarını içeren sözlük listesi)."""
    cur = db.cursor()
    cur.execute(
        "SELECT id, kolon_adi, etiket, tur, sonra_gelen_alan FROM ozel_alan "
        "WHERE tablo = %s AND aktif = TRUE ORDER BY sira, id",
        (tablo,),
    )
    satirlar = cur.fetchall()
    cur.close()
    return satirlar


def _ozel_alan_harita(ozel_alanlar):
    """Özel alanları, formda hangi sabit alandan HEMEN SONRA görüneceklerine
    göre gruplar (sonra_gelen_alan -> o alana bağlı özel alanlar listesi,
    kendi aralarında sira/id sırasıyla). '' anahtarı, formun en sonundaki
    "Özel Alanlar" kutusuna düşen (henüz özel olarak yerleştirilmemiş)
    alanları tutar."""
    harita = {}
    for oa in ozel_alanlar:
        anahtar = oa["sonra_gelen_alan"] or ""
        harita.setdefault(anahtar, []).append(oa)
    return harita


def _form_onizleme_sirasi(sabit_alan_sirasi, ozel_alanlar):
    """Özel Alan Ayarları sayfasındaki sürükle-bırak önizlemesi için, sabit
    (koddan gelen) alanlarla özel alanları TEK bir listede, formda göründükleri
    gerçek sırayla birleştirir."""
    harita = _ozel_alan_harita(ozel_alanlar)
    sonuc = []
    for anahtar, etiket in sabit_alan_sirasi:
        sonuc.append({"tip": "sabit", "anahtar": anahtar, "etiket": etiket})
        for oa in harita.get(anahtar, []):
            sonuc.append({
                "tip": "ozel", "anahtar": oa["kolon_adi"], "etiket": oa["etiket"],
                "tur": oa["tur"], "id": oa["id"],
            })
    for oa in harita.get("", []):
        sonuc.append({
            "tip": "ozel", "anahtar": oa["kolon_adi"], "etiket": oa["etiket"],
            "tur": oa["tur"], "id": oa["id"],
        })
    return sonuc


def _abone_kolon_takimi(db):
    """DISPLAY_KOLONLARI/KOLON_BILGI/SAYISAL_KOLONLAR'ı, kullanıcının Özel Alan
    Ayarları'ndan eklediği abone alanlarıyla birleştirip döndürür:
    (kolon_listesi, kolon_bilgi, sayisal_kolonlar, ozel_alanlar)."""
    ozel = _ozel_alanlari_getir(db, "abone")
    kolon_listesi = DISPLAY_KOLONLARI + [(o["kolon_adi"], o["etiket"]) for o in ozel]
    kolon_bilgi = dict(KOLON_BILGI)
    for o in ozel:
        kolon_bilgi[o["kolon_adi"]] = (o["kolon_adi"], o["tur"])
    sayisal = SAYISAL_KOLONLAR | {o["kolon_adi"] for o in ozel if o["tur"] == "sayi"}
    return kolon_listesi, kolon_bilgi, sayisal, ozel


def _ariza_kolon_takimi(db):
    """ARIZA_DISPLAY_KOLONLARI/ARIZA_KOLON_BILGI/ARIZA_SAYISAL_KOLONLAR'ı,
    kullanıcının Özel Alan Ayarları'ndan eklediği arıza alanlarıyla birleştirip
    döndürür: (kolon_listesi, kolon_bilgi, sayisal_kolonlar, ozel_alanlar)."""
    ozel = _ozel_alanlari_getir(db, "ariza")
    kolon_listesi = ARIZA_DISPLAY_KOLONLARI + [(o["kolon_adi"], o["etiket"]) for o in ozel]
    kolon_bilgi = dict(ARIZA_KOLON_BILGI)
    for o in ozel:
        kolon_bilgi[o["kolon_adi"]] = (o["kolon_adi"], o["tur"])
    sayisal = ARIZA_SAYISAL_KOLONLAR | {o["kolon_adi"] for o in ozel if o["tur"] == "sayi"}
    return kolon_listesi, kolon_bilgi, sayisal, ozel


def _ozel_alan_deger_formatla(deger, tur):
    """Bir özel alan değerini, listede gösterilirken diğer alanlarla aynı
    bicimde (para/tarih/metin) göstermek için biçimlendirir."""
    if deger is None:
        return ""
    if tur == "sayi":
        return tl_format(deger)
    if tur == "tarih":
        return _gg_aa_yyyy(str(deger))
    return deger


def _ozel_alan_ekle(db, tablo, etiket, tur):
    """Yeni bir özel alan tanımlar VE ilgili tabloya gerçek bir sütun ekler."""
    if tablo not in ("abone", "ariza"):
        raise ValueError("geçersiz tablo")
    if tur not in _OZEL_ALAN_TUR_PG:
        raise ValueError("geçersiz tür")
    cur = db.cursor()
    cur.execute("SELECT nextval(pg_get_serial_sequence('ozel_alan', 'id')) AS id")
    yeni_id = cur.fetchone()["id"]
    kolon_adi = f"ozel_{yeni_id}"
    cur.execute(
        "INSERT INTO ozel_alan (id, tablo, kolon_adi, etiket, tur, sira) VALUES "
        "(%s, %s, %s, %s, %s, (SELECT COALESCE(MAX(sira), -1) + 1 FROM ozel_alan WHERE tablo = %s))",
        (yeni_id, tablo, kolon_adi, etiket, tur, tablo),
    )
    # kolon_adi programın kendisi ürettiği (kullanıcıdan gelmeyen) güvenli bir
    # isim olduğu için burada f-string ile SQL'e eklenmesi güvenlidir.
    pg_tur = _OZEL_ALAN_TUR_PG[tur]
    cur.execute(f"ALTER TABLE {tablo} ADD COLUMN {kolon_adi} {pg_tur}")
    db.commit()
    cur.close()


def _ozel_alan_sil(db, ozel_alan_id):
    """Özel alanı formdan/listeden gizler (aktif=FALSE). Veri kaybı olmaması
    için ilgili veritabanı sütunu SİLİNMEZ, sadece pasif hale getirilir."""
    cur = db.cursor()
    cur.execute("UPDATE ozel_alan SET aktif = FALSE WHERE id = %s", (ozel_alan_id,))
    db.commit()
    cur.close()


def _ozel_alan_sirala(db, tablo, sira_listesi):
    """Özel Alan Ayarları sayfasındaki sürükle-bırak önizlemesinden gelen YENİ
    tam sırayı (sabit alan anahtarları + özel alanların kolon_adi'leri, formda
    göründükleri sırayla karışık) kaydeder. Liste baştan sona gezilirken en son
    görülen SABİT alan anahtarı hatırlanır; her özel alana rastlandığında onun
    "sonra_gelen_alan"ı o anahtar olur (henüz hiç sabit alan görülmediyse '' —
    yani ilk sabit alandan önce bırakılmış demektir, bu da formun en sonundaki
    "Özel Alanlar" kutusuyla aynı '' değerini kullanır; pratikte kullanıcı
    alanları her zaman iki sabit alanın arasına bıraktığı için bu durum
    oluşmaz). Bilinmeyen (artık geçerli olmayan) anahtarlar sessizce yok
    sayılır — sira_listesi tamamen istemciden geldiği için güvenli tarafta
    kalınır."""
    if tablo not in ("abone", "ariza"):
        raise ValueError("geçersiz tablo")
    sabit_anahtarlar = {k for k, _ in (ABONE_FORM_ALAN_SIRASI if tablo == "abone" else ARIZA_FORM_ALAN_SIRASI)}
    ozel_kolon_id = {oa["kolon_adi"]: oa["id"] for oa in _ozel_alanlari_getir(db, tablo)}

    cur = db.cursor()
    son_sabit = ""
    sira_sayaci = 0
    for anahtar in sira_listesi:
        if anahtar in sabit_anahtarlar:
            son_sabit = anahtar
            continue
        if anahtar not in ozel_kolon_id:
            continue
        cur.execute(
            "UPDATE ozel_alan SET sonra_gelen_alan = %s, sira = %s WHERE id = %s AND tablo = %s",
            (son_sabit, sira_sayaci, ozel_kolon_id[anahtar], tablo),
        )
        sira_sayaci += 1
    db.commit()
    cur.close()


# abone_listesi() sayfasındaki serbest metin araması hangi alanlarda yapılabilir
# tanımı. Hem abone_listesi() route'u hem de Montaj Formu'nun toplu oluşturma
# özelliği aynı filtreleme mantığını (_abone_filtreli_kayitlari_getir) kullanır.
_ABONE_ALAN_TANIMLARI = [
    ("aciklama", "Açıklama", "aciklama", False),
    ("adi", "Adı", "adi", False),
    ("alinan_tutar", "Alınan", "alinan_tutar", True),
    ("baba_adi", "Baba Adı", "baba_adi", False),
    ("fatura_no", "Fatura No", "fatura_no", False),
    ("koy", "Köy", "koy_adi", False),
    ("malzeme_alinan", "Malzeme Alınan", "malzeme_alinan", True),
    ("malzeme_kalan", "Malzeme Kalan", "(malzeme_tutari - malzeme_alinan)", True),
    ("malzeme_tutari", "Malzeme Tutarı", "malzeme_tutari", True),
    ("montaj_personeli", "Montaj Personeli", "montaj_personeli", False),
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
_ABONE_ALAN_HARITASI = {k: (kolon, sayisal) for k, _, kolon, sayisal in _ABONE_ALAN_TANIMLARI}


def _abone_filtreli_kayitlari_getir(db):
    """Abone Listesi sayfasındaki (q / koy / alan / deger_*) filtrelerinin aynısını
    mevcut request.args'a göre uygulayarak, filtrelenmiş ham abone satırlarını döndürür.
    Montaj Formu'nun toplu oluşturma özelliği, Abone Listesi'nde o an görülen
    filtrelenmiş kayıt kümesiyle birebir aynı sonucu almak için bunu kullanır."""
    q = request.args.get("q", "").strip()
    koy = request.args.get("koy", "").strip()
    alanlar_secili = request.args.getlist("alan")

    sql = "SELECT * FROM abone WHERE 1=1"
    params = []
    if q:
        secili = alanlar_secili if alanlar_secili else [k for k, *_ in _ABONE_ALAN_TANIMLARI]
        q_sayi = None
        q_temiz = q.replace(",", ".").strip()
        try:
            q_sayi = float(q_temiz)
        except ValueError:
            q_sayi = None
        kosul_listesi = []
        kosul_params = []
        for s in secili:
            if s in _ABONE_ALAN_HARITASI:
                kolon, sayisal = _ABONE_ALAN_HARITASI[s]
                if sayisal and q_sayi is not None:
                    kosul_listesi.append(f"ROUND(CAST({kolon} AS NUMERIC), 2) = %s")
                    kosul_params.append(round(q_sayi, 2))
                elif sayisal:
                    kosul_listesi.append(f"{_turkce_esle_kosul(f'CAST({kolon} AS TEXT)')} LIKE %s")
                    kosul_params.append(_turkce_normallestir(f"%{q}%"))
                else:
                    kosul_listesi.append(f"{_turkce_esle_kosul(kolon)} LIKE %s")
                    kosul_params.append(_turkce_normallestir(f"%{q}%"))
        if kosul_listesi:
            sql += " AND (" + " OR ".join(kosul_listesi) + ")"
            params += kosul_params
    if koy:
        sql += " AND koy_adi = %s"
        params.append(koy)

    kolon_listesi, kolon_bilgi, _sayisal, _ozel = _abone_kolon_takimi(db)
    deger_secili = {}
    for anahtar, _ in kolon_listesi:
        secilenler = request.args.getlist(f"deger_{anahtar}")
        deger_secili[anahtar] = secilenler
        if secilenler:
            kosul, param_listesi = _kolon_kosul_coklu(anahtar, secilenler, kolon_bilgi)
            if kosul:
                sql += f" AND {kosul}"
                params += param_listesi

    sql += f" ORDER BY s_no {'DESC' if _sira_yonu_al() == 'desc' else 'ASC'}"
    cur = db.cursor()
    cur.execute(sql, params)
    kayitlar_ham = cur.fetchall()
    cur.close()
    return kayitlar_ham

_ARIZA_ALFABETIK_SIRA = [
    "adi", "alinan_ucret", "ariza_ucret", "gelis_tarihi", "islem_aciklama",
    "kalan_ucret", "koy_adi", "ozel_s_no", "s_no", "sayac_kredisi", "seri_no",
    "soyadi", "takilan_tarih", "telefon", "telefon2", "teslim_tarihi", "tespit_aciklama",
    "tespit_edilen_ariza", "yapilan_islemler", "yeni_seri_no",
]
_ARIZA_DISPLAY_KOLON_HARITASI = dict(ARIZA_DISPLAY_KOLONLARI)
ARIZA_DISPLAY_KOLONLARI_ALFABETIK = [(k, _ARIZA_DISPLAY_KOLON_HARITASI[k]) for k in _ARIZA_ALFABETIK_SIRA]


def _izgara_satir(n, sutun=4):
    """columns x N onay kutusu ızgarasında kaç satır gerektiğini hesaplar."""
    if n <= 0:
        return 1
    return math.ceil(n / sutun)


def _sira_yonu_al():
    """Şu anki istekten (?sira=asc|desc) sıralama yönünü okur. Varsayılan 'asc'
    (küçükten büyüğe / eskiden yeniye) — mevcut davranışla aynı, geriye dönük
    uyumlu. Sadece 'desc' değeri özel olarak tersine sıralama yapar."""
    return "desc" if request.args.get("sira") == "desc" else "asc"


def _sira_toggle_qs():
    """Şu anki tüm filtre/arama parametrelerini (çoklu seçim kutuları dahil)
    koruyarak sadece 'sira' parametresini ters çevrilmiş haliyle döndürür.
    Liste sayfalarındaki "S.No: Küçükten Büyüğe / Büyükten Küçüğe" bağlantısı
    bunu kullanır."""
    args = request.args.to_dict(flat=False)
    yeni = "asc" if _sira_yonu_al() == "desc" else "desc"
    args["sira"] = [yeni]
    ciftler = []
    for anahtar, degerler in args.items():
        for deger in degerler:
            ciftler.append((anahtar, deger))
    return _urlencode(ciftler)


# Büyük listelerin (Abone Listesi, Arıza Takip, Tahsilat Çıktısı, Arıza Takip
# Çıktısı, Köy Abone Listeleri) tek seferde binlerce kaydı tek sayfada
# göndermesi, sayfaların çok ağır/yavaş açılmasına sebep oluyordu (ölçümlerle
# doğrulandı). Bu sayfalar artık burada tanımlı sabit boyutta ("sayfa" başına
# kayıt) parçalara bölünüp gösteriliyor; arama/filtreler ve toplamlar yine TÜM
# eşleşen kayıtlar üzerinden hesaplanıyor, sadece EKRANA BASILAN satır sayısı
# sınırlanıyor. Excel/CSV dışa aktarma bundan etkilenmiyor, o hep tam veriyi
# içerir.
SAYFA_BOYUTU = 100


def _sayfa_no_al():
    """Şu anki istekten (?sayfa=N) sayfa numarasını okur. Geçersiz/eksikse 1
    döner; asla 1'den küçük olmaz (üst sınır, çağıran yerde toplam sayfa
    sayısına göre ayrıca sınırlanır)."""
    try:
        sayfa = int(request.args.get("sayfa", "1"))
    except (TypeError, ValueError):
        sayfa = 1
    return max(1, sayfa)


def _sayfalama_qs(sayfa):
    """Şu anki tüm filtre/arama/sıralama parametrelerini koruyarak sadece
    'sayfa' parametresini verilen değere ayarlanmış haliyle döndürür.
    Sayfalama bağlantıları (İlk/Önceki/Sonraki/Son, sayfa numaraları) bunu
    kullanır."""
    args = request.args.to_dict(flat=False)
    args["sayfa"] = [str(sayfa)]
    ciftler = []
    for anahtar, degerler in args.items():
        for deger in degerler:
            ciftler.append((anahtar, deger))
    return _urlencode(ciftler)


def _sayfala(satirlar):
    """Zaten filtrelenip sıralanmış TAM satır listesini alır; şu anki istekten
    okunan sayfa numarasına göre sadece o sayfaya denk gelen dilimi döndürür.
    Dönen değer: (o_sayfanin_satirlari, toplam_bulunan, sayfa, toplam_sayfa).
    toplam_bulunan HER ZAMAN sayfalama öncesi TÜM eşleşen kayıt sayısıdır —
    "FİLTRELİ KAYIT" gibi toplamlar hep bunu kullanmalı, dilimlenmiş listenin
    uzunluğunu değil.

    ?tumu=1 parametresi sayfalamayı tamamen atlar — Tahsilat Çıktısı / Arıza
    Takip Çıktısı gibi "Yazdır" butonu olan sayfalarda, filtrelenmiş TÜM
    kayıtları tek seferde yazdırabilmek için gerekli (aksi halde sadece o an
    ekranda görünen sayfa yazdırılırdı)."""
    toplam_bulunan = len(satirlar)
    if request.args.get("tumu") == "1":
        return satirlar, toplam_bulunan, 1, 1
    toplam_sayfa = max(1, math.ceil(toplam_bulunan / SAYFA_BOYUTU))
    sayfa = min(_sayfa_no_al(), toplam_sayfa)
    baslangic = (sayfa - 1) * SAYFA_BOYUTU
    return satirlar[baslangic:baslangic + SAYFA_BOYUTU], toplam_bulunan, sayfa, toplam_sayfa


def _tumunu_goster_qs():
    """Şu anki tüm filtre/arama parametrelerini koruyarak 'tumu=1' ekler (ve
    anlamsız kalacağı için 'sayfa' parametresini kaldırır). Tahsilat Çıktısı /
    Arıza Takip Çıktısı gibi "Yazdır" butonu olan sayfalardaki "Tümünü Göster
    (Yazdır İçin)" bağlantısı bunu kullanır — aksi halde yazdırma sadece o an
    ekranda görünen tek sayfayı kapsardı."""
    args = request.args.to_dict(flat=False)
    args.pop("sayfa", None)
    args["tumu"] = ["1"]
    ciftler = []
    for anahtar, degerler in args.items():
        for deger in degerler:
            ciftler.append((anahtar, deger))
    return _urlencode(ciftler)


# Arıza formundaki onay kutusu listeleri artık koddan değil, "form_secenegi"
# tablosundan (bkz. schema.sql) okunuyor — bu sayede Ayarlar > Onay Kutusu
# Ayarları ekranından, koda dokunmadan yeni seçenek eklenip çıkarılabiliyor.
# Aşağıdaki iki liste sadece veritabanı ilk kurulurken (tablo boşken) o grup
# için otomatik eklenecek VARSAYILAN seçenekleri tutar; program çalışırken
# artık bu listeler değil, veritabanındaki güncel liste kullanılır.
FORM_SECENEK_GRUPLARI = {
    "tespit_edilen_ariza": "Tespit Edilen Arıza",
    "yapilan_islemler": "Yapılan İşlemler",
}

_TESPIT_EDILEN_ARIZA_VARSAYILAN = [
    "Arıza Simgesi", "Data", "Dijital Su Almış", "Ekran Yok",
    "Error 1", "Error 2", "Error 3", "Error 4", "Error 5",
    "Harcama Uyuşmuyor", "Harcama Yapmıyor",
    "Kondansatör Devre Dışı", "Kondansatör Yok",
    "Küre Dönmüyor", "Küre Paslı", "Küre Zor Dönüyor",
    "Magnet", "Mekanik Patlak", "Motor Oksitli", "Motor Switch Arızalı",
    "Pil Bitik", "Pil Zayıf", "Sıkıntı Yok",
]

_YAPILAN_ISLEMLER_VARSAYILAN = [
    "Formatlandı",
    "Kart Değişti", "Kart Ekran Değişti", "Kart Okuyucu Değişti", "Kart Temizlendi",
    "Kondansatör Devreye Alındı", "Kondansatör Takıldı",
    "Küre Değişti", "Küre Temizlendi",
    "Mekanik Değişti", "Mekanik Patlak Tamir", "Mekanik Pervane Değişti",
    "Motor Değişti", "Motor Switch Değişti", "Motor Tamir Edildi",
    "Pil Takıldı", "Resetlendi", "Sayım Aparatı Değişti",
]

FORM_SECENEK_VARSAYILANLARI = {
    "tespit_edilen_ariza": _TESPIT_EDILEN_ARIZA_VARSAYILAN,
    "yapilan_islemler": _YAPILAN_ISLEMLER_VARSAYILAN,
}


def _form_secenekleri_getir(db, grup):
    """Bir seçenek grubunun (ör. 'tespit_edilen_ariza') güncel listesini,
    kayıtlı gösterim sırasına göre veritabanından okur."""
    cur = db.cursor()
    cur.execute("SELECT deger FROM form_secenegi WHERE grup = %s ORDER BY sira, id", (grup,))
    satirlar = cur.fetchall()
    cur.close()
    return [s["deger"] for s in satirlar]

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


def _abone_satir_sozlugu(k, ozel_alanlar=None):
    sayac_kalan = (k["sayac_tutari"] or 0) - (k["alinan_tutar"] or 0)
    malzeme_kalan = (k["malzeme_tutari"] or 0) - (k["malzeme_alinan"] or 0)
    toplam_kalan = sayac_kalan + malzeme_kalan
    muhtara_kalan = (k["muhtara_odenecek"] or 0) - (k["muhtara_odenen"] or 0)
    ozel_alanlar = ozel_alanlar or []
    renk = {anahtar: '' for anahtar, _ in DISPLAY_KOLONLARI}
    for oa in ozel_alanlar:
        renk[oa["kolon_adi"]] = ''
    renk["sayac_kalan"] = 'kirmizi' if sayac_kalan > 0 else 'yesil'
    renk["malzeme_kalan"] = 'kirmizi' if malzeme_kalan > 0 else 'yesil'
    renk["toplam_kalan"] = 'kirmizi' if toplam_kalan > 0 else 'yesil'
    renk["muhtara_kalan"] = 'kirmizi' if muhtara_kalan > 0 else 'yesil'
    satir = {
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
        "montaj_personeli": k["montaj_personeli"],
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
    for oa in ozel_alanlar:
        satir[oa["kolon_adi"]] = _ozel_alan_deger_formatla(k[oa["kolon_adi"]], oa["tur"])
    return satir


def _ariza_satir_sozlugu(k, ozel_alanlar=None):
    kalan_ucret = (k["ariza_ucret"] or 0) - (k["alinan_ucret"] or 0)
    ozel_alanlar = ozel_alanlar or []
    renk = {anahtar: '' for anahtar, _ in ARIZA_DISPLAY_KOLONLARI}
    for oa in ozel_alanlar:
        renk[oa["kolon_adi"]] = ''
    renk["kalan_ucret"] = 'kirmizi' if kalan_ucret > 0 else 'yesil'
    satir = {
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
        "teslim_tarihi": _gg_aa_yyyy(k["teslim_tarihi"]),
        "sayac_kredisi": k["sayac_kredisi"],
        "tespit_edilen_ariza": k["tespit_edilen_ariza"],
        "tespit_aciklama": k["tespit_aciklama"],
        "yapilan_islemler": k["yapilan_islemler"],
        "islem_aciklama": k["islem_aciklama"],
        "_renk": renk,
    }
    for oa in ozel_alanlar:
        satir[oa["kolon_adi"]] = _ozel_alan_deger_formatla(k[oa["kolon_adi"]], oa["tur"])
    return satir


# Montaj Formu'nun varsayılan tasarımı. Bu, sadece TEK bir kopyayı tanımlar —
# A4 kağıda basıldığında sayfanın üstünde ve altında aynı abonenin bilgileriyle
# İKİ KEZ basılması, şablonun kendisinde değil montaj_formu.html sayfasında
# (aynı render'ı iki kez yazdırarak) sağlanır. Böylece kullanıcı Montaj Formu
# Tasarımı ekranından sadece TEK kopyayı düzenler, iki kopyanın birbirinden
# farklılaşma riski olmaz. Alanlar arasında {{ adi }}, {{ soyadi }}, {{ koy_adi }},
# {{ sayac_no }}, {{ telefon }}, {{ telefon2 }}, {{ montaj_tarihi }} kullanılabilir.
_MONTAJ_FORMU_VARSAYILAN_SABLON = """<div class="montaj-formu-kopya" style="border:1px solid #999; border-radius:6px; padding:14px 18px; margin-bottom:14px; font-size:12.5px; line-height:1.5; color:#1f2a24;">
    <img src="{{ url_for('static', filename='montaj_formu_header.png') }}" alt="ALGI - ELEKTROMED" style="max-width:560px; width:100%; display:block; margin-bottom:8px;">

    <div style="display:flex; justify-content:space-between; margin-bottom:8px; font-weight:700;">
        <div>KÖY ADI&nbsp;&nbsp;:&nbsp;&nbsp;{{ koy_adi }}</div>
        <div>{{ montaj_tarihi }}</div>
    </div>

    <table style="width:100%; border-collapse:collapse; margin-bottom:6px;">
        <tr><td colspan="4" style="border:1px solid #333; background:#eee; text-align:center; font-weight:700; padding:4px;">GARANTİ BELGESİ - ABONE BİLGİLERİ</td></tr>
        <tr>
            <td style="border:1px solid #333; padding:5px; width:18%; font-weight:700; background:#f7f7f7;">Adı Soyadı</td>
            <td style="border:1px solid #333; padding:5px; width:32%;">{{ adi }} {{ soyadi }}</td>
            <td style="border:1px solid #333; padding:5px; width:18%; font-weight:700; background:#f7f7f7;">Sayaç No</td>
            <td style="border:1px solid #333; padding:5px; width:32%;">{{ sayac_no }}</td>
        </tr>
        <tr>
            <td style="border:1px solid #333; padding:5px; font-weight:700; background:#f7f7f7;">İletişim</td>
            <td style="border:1px solid #333; padding:5px;">{{ telefon }}{% if telefon2 %} / {{ telefon2 }}{% endif %}</td>
            <td style="border:1px solid #333; padding:5px; font-weight:700; background:#f7f7f7;">Mekanik Sayaç Alındı</td>
            <td style="border:1px solid #333; padding:5px;">&nbsp;</td>
        </tr>
        <tr>
            <td style="border:1px solid #333; padding:5px; font-weight:700; background:#f7f7f7;">Sayaç Ücreti</td>
            <td style="border:1px solid #333; padding:5px;">{{ sayac_ucreti }}</td>
            <td style="border:1px solid #333; padding:5px; font-weight:700; background:#f7f7f7;">Tesisat Ücreti</td>
            <td style="border:1px solid #333; padding:5px;">{{ tesisat_ucreti }}</td>
        </tr>
        <tr>
            <td style="border:1px solid #333; padding:5px; font-weight:700; background:#f7f7f7;">Alınan</td>
            <td style="border:1px solid #333; padding:5px;">{{ sayac_ucreti_alinan }}</td>
            <td style="border:1px solid #333; padding:5px; font-weight:700; background:#f7f7f7;">Alınan</td>
            <td style="border:1px solid #333; padding:5px;">{{ tesisat_ucreti_alinan }}</td>
        </tr>
    </table>

    <table style="width:100%; border-collapse:collapse; margin-bottom:6px; font-size:11px;">
        <tr><td colspan="6" style="border:1px solid #333; background:#eee; text-align:center; font-weight:700; padding:3px;">MONTAJDA KULLANILAN MALZEMELER</td></tr>
        <tr style="font-weight:700; background:#f7f7f7;">
            <td style="border:1px solid #333; padding:3px;">MALZEME</td><td style="border:1px solid #333; padding:3px; width:8%;">ADET</td>
            <td style="border:1px solid #333; padding:3px;">MALZEME</td><td style="border:1px solid #333; padding:3px; width:8%;">ADET</td>
            <td style="border:1px solid #333; padding:3px;">MALZEME</td><td style="border:1px solid #333; padding:3px; width:8%;">ADET</td>
        </tr>
        <tr>
            <td style="border:1px solid #333; padding:3px;">REKOR 20x20 İÇ DİŞLİ OYNAR BAŞLI</td><td style="border:1px solid #333;">&nbsp;</td>
            <td style="border:1px solid #333; padding:3px;">MAŞON 32x32 PPRC</td><td style="border:1px solid #333;">&nbsp;</td>
            <td style="border:1px solid #333; padding:3px;">MAŞON 20x20 KAPLİN</td><td style="border:1px solid #333;">&nbsp;</td>
        </tr>
        <tr>
            <td style="border:1px solid #333; padding:3px;">VANA 20x20 PPRC</td><td style="border:1px solid #333;">&nbsp;</td>
            <td style="border:1px solid #333; padding:3px;">TE 20x20x20 PPRC</td><td style="border:1px solid #333;">&nbsp;</td>
            <td style="border:1px solid #333; padding:3px;">REDÜKSİYON 25x20 KAPLİN</td><td style="border:1px solid #333;">&nbsp;</td>
        </tr>
        <tr>
            <td style="border:1px solid #333; padding:3px;">DİRSEK 20x20 PPRC</td><td style="border:1px solid #333;">&nbsp;</td>
            <td style="border:1px solid #333; padding:3px;">REDÜKSİYON 25x20 PPRC</td><td style="border:1px solid #333;">&nbsp;</td>
            <td style="border:1px solid #333; padding:3px;">REDÜKSİYON 32x20 KAPLİN</td><td style="border:1px solid #333;">&nbsp;</td>
        </tr>
        <tr>
            <td style="border:1px solid #333; padding:3px;">MAŞON 20x20 PPRC</td><td style="border:1px solid #333;">&nbsp;</td>
            <td style="border:1px solid #333; padding:3px;">REDÜKSİYON 32x20 PPRC</td><td style="border:1px solid #333;">&nbsp;</td>
            <td style="border:1px solid #333; padding:3px;">DİRSEK 20x20 KAPLİN</td><td style="border:1px solid #333;">&nbsp;</td>
        </tr>
        <tr>
            <td style="border:1px solid #333; padding:3px;">MAŞON 25x25 PPRC</td><td style="border:1px solid #333;">&nbsp;</td>
            <td style="border:1px solid #333; padding:3px;">KORUMA KABI</td><td style="border:1px solid #333;">&nbsp;</td>
            <td style="border:1px solid #333; padding:3px;">&nbsp;</td><td style="border:1px solid #333;">&nbsp;</td>
        </tr>
    </table>

    <div style="margin:6px 0;">
        <strong style="color:#c0392b;">ÖDEME BİLGİLERİ</strong><br>
        HESAP SAHİBİ : SEVDİYE ÇOBAN<br>
        HALK BANKASI IBAN: TR95 0001 2009 6680 0009 0053 87
    </div>

    <div style="margin:6px 0; font-size:11.5px;">
        {{ montaj_tarihi }} Tarihinde sayacım firma tarafından bilgim dahilinde değiştirildi. Sayacın garanti şartları aşağıda belirtilmiştir.
    </div>

    <div style="font-size:11px;">
        <strong>Garanti Şartları</strong><br>
        1 - Yüklenici sayaçları 10 (On) yıl boyunca garanti kapsamı dışında bedeli karşılığı teknik servis hizmeti sağlayacaktır.<br>
        2 - Üretici tarafından üretimi yapılan sayaçlar TSE standartlarında olup, garanti süresi 2 (iki) yıl olacaktır.<br>
        3 - Su gibi etkenlere direkt ve devamlı maruz kaldığında garanti dışı işlem yapılacaktır.<br>
        4 - Montajı yapılan sayaçlar abone tarafından belirlenmiştir. Montaj yerinde sonradan doğabilecek sorunlar aboneye aittir.
    </div>

    <div style="display:flex; justify-content:space-between; margin-top:22px; font-size:11.5px; text-align:center;">
        <div style="flex:1;">Kurum Personeli</div>
        <div style="flex:1;">{{ montaj_personeli }}<br>ELEKTROMED Yetkili Personeli</div>
        <div style="flex:1;">{{ adi }} {{ soyadi }}<br>Abone Veya Vekili</div>
    </div>
</div>"""


def _word_tasarimini_onar(html):
    """Word'den (.docx) mammoth ile HTML'e çevrilen bir tasarımda, mammoth'un
    KASITLI olarak atladığı/eklemediği bazı şeyleri onarır — çünkü mammoth "sadece
    içerik" felsefesiyle çalışır, sayfa üzerindeki GÖRSEL sonucu önemsemez:

    1) Tablo kenarlığı/gölge: Word'deki tablo kenarlıkları direkt biçimlendirme
       sayıldığı için hiç aktarılmaz — dönüşüm sonrası tablolar kenarlıksız çıkar.
       Sadece BİRDEN FAZLA satırlı tabloları "gerçek veri tablosu" sayıp kenarlık
       ekliyoruz; Word'de sayfa düzeni için kullanılan (ör. "köy adı solda, tarih
       sağda" gibi metinleri hizalamak amaçlı) tek satırlık tablolar kenarlıksız
       bırakılıyor.
    2) Sütun genişliği: aynı sebeple Word'deki sütun genişlikleri de aktarılmaz.
       Burada her sütuna, içindeki en uzun metne göre ORANTILI bir genişlik
       veriliyor (<colgroup> ile) — eşit genişlik vermek "MALZEME" gibi uzun
       metinlerin dar bir sütuna sığmayıp alt satıra taşmasına ve tablonun
       gereksiz uzamasına yol açtığı için tercih edilmedi.
    3) Paragraf boşluğu: mammoth her metin bloğunu (tablo hücresi içindekiler dahil)
       bir <p> etiketine sarar; tarayıcının bu etikete uyguladığı varsayılan üst/alt
       boşluk (margin), özellikle çok hücreli tablolarda ve alt alta birçok satırda
       toplanınca tasarımı ÇOK şişirir (ör. Montaj Formu iki kopya halinde tek A4
       sayfasına sığacak şekilde tasarlanmışken, bu boşluklar yüzünden tek kopya
       bile sayfaya sığmayabilir). Bu yüzden hücre içindeki <p>'lerin boşluğu tümüyle
       sıfırlanıyor, hücre dışındakilerin ise küçük, sabit bir alt boşlukla
       sınırlandırılıyor.

    bs4 kurulu değilse HTML'e dokunulmadan olduğu gibi döner (onarım sessizce
    atlanır, uygulama çökmez)."""
    if BeautifulSoup is None or not html:
        return html

    soup = BeautifulSoup(html, "html.parser")

    for p in soup.find_all("p"):
        hucre_icinde = p.find_parent(["td", "th"]) is not None
        p["style"] = "margin:0;" if hucre_icinde else "margin:0 0 2px 0;"

    # 4) Resim genişliği: Word'de bir resmi (ör. üstteki logo/TEKSAN şeridi) sayfa
    # genişliğine yayacak şekilde boyutlandırmış olsanız bile, mammoth bu boyut
    # bilgisini (Word'ün "bu resmi şu genişlikte göster" verisini) HTML'e aktarmaz —
    # resim, dosyanın kendi ham piksel boyutunda (genelde OLMASI GEREKENDEN dar)
    # çıkar ve sayfanın sol tarafında küçük/sıkışık görünür. Bunu, TEK BAŞINA bir
    # paragrafı kaplayan (yanında başka metin olmayan) resimleri sayfa genişliğine
    # yayarak (width:100%) telafi ediyoruz — bu genelde üst logo/başlık şeridi gibi
    # tam genişlikte tasarlanmış resimler için doğru varsayım.
    for p in soup.find_all("p"):
        icerik_cocuklari = [c for c in p.contents if not (isinstance(c, str) and not c.strip())]
        if len(icerik_cocuklari) == 1 and getattr(icerik_cocuklari[0], "name", None) == "img":
            icerik_cocuklari[0]["style"] = "width:100%; height:auto; display:block;"

    if "<table" not in html:
        return str(soup)

    for tablo in soup.find_all("table"):
        satirlar = tablo.find_all("tr")
        if len(satirlar) < 2:
            # Muhtemelen sayfa düzeni amaçlı tek satırlık tablo (ör. "köy adı solda,
            # tarih sağda" gibi metinleri hizalamak için, ya da logo/adres başlığı,
            # ya da "Kurum Personeli / Montaj Personeli / Abone Veya Vekili" imza
            # satırı için kullanılmış) — kenarlık/gölge eklenmiyor, ama mammoth hücre
            # genişliklerini de attığı için tablo daraltılmış görünmesin diye en
            # azından tam genişlik veriliyor.
            #
            # Hizalama SADECE hücreler resim İÇERMİYORSA zorlanıyor: resim içeren
            # satırlar genelde logo/başlık düzeni içindir ve hücrelerin içindeki
            # metin/resim zaten Word'de kendi konumuna (sola/sağa) yaslanmış olarak
            # gelir — hepsini ortaya zorlamak (ör. TEKSAN adres bloğunu) yerinden
            # oynatıp sayfanın ortasına kaydırıyordu. Resim yoksa (imza satırı gibi
            # salt metin içeren 3 hücreli satırlarda) hücreler ortaya yaslanıyor.
            tek_satir = satirlar[0] if satirlar else None
            if tek_satir is not None:
                tablo["style"] = "width:100%; border-collapse:collapse;"
                hucreler = tek_satir.find_all(["td", "th"], recursive=False)
                resimli = tek_satir.find("img") is not None
                if not resimli:
                    if len(hucreler) == 2:
                        hucreler[-1]["style"] = "text-align:right;"
                    elif len(hucreler) == 3:
                        for h in hucreler:
                            h["style"] = "text-align:center;"
            continue

        tablo["style"] = "width:100%; border-collapse:collapse; table-layout:fixed; margin-bottom:3px;"

        # Sütun genişliklerini içerik uzunluğuna GÖRE ORANTILI hesaplayıp <colgroup>
        # ile veriyoruz — hepsine eşit genişlik vermek (ör. 6 eşit sütun), "MALZEME"
        # gibi uzun metinlerin dar bir sütuna sığmayıp alt satıra taşmasına ve
        # tablonun boyunun gereksiz şişmesine yol açıyordu. colspan İÇERMEYEN
        # satırlardan (başlık çubuğu hariç, gerçek veri satırlarından) her sütunun
        # en uzun metnini bulup ona göre pay veriyoruz; çok kısa sütunlar (ör.
        # "ADET") aşırı daralmasın diye bir taban genişlik (%8) uygulanıyor.
        kolon_sayisi = 0
        kolon_uzunluklari = []
        for satir in satirlar:
            hucreler = satir.find_all(["td", "th"], recursive=False)
            if not hucreler or any(h.get("colspan") for h in hucreler):
                continue
            if kolon_sayisi == 0:
                kolon_sayisi = len(hucreler)
                kolon_uzunluklari = [0] * kolon_sayisi
            if len(hucreler) != kolon_sayisi:
                continue  # tutarsız satır — sütun hizası bozulmasın diye atla
            for i, h in enumerate(hucreler):
                uzunluk = len(h.get_text(strip=True))
                if uzunluk > kolon_uzunluklari[i]:
                    kolon_uzunluklari[i] = uzunluk

        if kolon_sayisi:
            mevcut_colgroup = tablo.find("colgroup")
            if mevcut_colgroup:
                mevcut_colgroup.decompose()
            TABAN_YUZDE = 8
            toplam_uzunluk = sum(kolon_uzunluklari) or kolon_sayisi
            kalan_yuzde = 100 - TABAN_YUZDE * kolon_sayisi
            colgroup = soup.new_tag("colgroup")
            genislikler = []
            for uzunluk in kolon_uzunluklari:
                pay = TABAN_YUZDE + (kalan_yuzde * uzunluk / toplam_uzunluk if kalan_yuzde > 0 else 0)
                genislikler.append(pay)
            # yuvarlama farkını son sütuna ekleyip toplamın tam %100 olmasını sağla
            fark = 100 - sum(genislikler)
            genislikler[-1] += fark
            for genislik in genislikler:
                col = soup.new_tag("col")
                col["style"] = f"width:{round(genislik, 4)}%;"
                colgroup.append(col)
            tablo.insert(0, colgroup)

        for hucre in tablo.find_all(["td", "th"]):
            # white-space:normal AÇIKÇA belirtiliyor — sitenin genel stil dosyasında
            # tüm <table> öğeleri için "white-space: nowrap" tanımlı (başka sayfalardaki
            # listeler için); bu, miras yoluyla buradaki hücrelere de bulaşıp satırların
            # hiç kaydırılmamasına (dolayısıyla tablonun yana taşmasına) yol açabilirdi.
            stil = ("border:1px solid #333; padding:2px 4px; overflow-wrap:break-word; "
                    "white-space:normal;")
            if hucre.get("colspan"):
                # tüm satırı kaplayan tek hücre — başlık çubuğu (ör. "GARANTİ BELGESİ...")
                stil += " background:#eee; text-align:center;"
            else:
                icerik_cocuklari = [c for c in hucre.contents if not (isinstance(c, str) and not c.strip())]
                tek_strong = (
                    len(icerik_cocuklari) == 1
                    and getattr(icerik_cocuklari[0], "name", None) == "strong"
                ) or (
                    len(icerik_cocuklari) == 1
                    and getattr(icerik_cocuklari[0], "name", None) == "p"
                    and len(icerik_cocuklari[0].contents) == 1
                    and getattr(icerik_cocuklari[0].contents[0], "name", None) == "strong"
                )
                if tek_strong:
                    # hücrenin tamamı tek bir kalın etiket — alan adı (ör. "Sayaç No") gibi görünüyor
                    stil += " background:#f7f7f7;"
            hucre["style"] = stil
    return str(soup)


def _montaj_formu_veri(satir):
    """`_abone_satir_sozlugu()` çıktısından Montaj Formu şablonu için birleştirme
    (mail-merge) verisi hazırlar. montaj_tarihi burada GG/AA/YYYY biçimine çevrilir
    (satırdaki değer zaten GG.AA.YYYY biçiminde geliyor)."""
    return {
        "adi": satir.get("adi") or "",
        "soyadi": satir.get("soyadi") or "",
        "koy_adi": satir.get("koy_adi") or "",
        "sayac_no": satir.get("sayac_no") or "",
        "telefon": satir.get("telefon") or "",
        "telefon2": satir.get("telefon2") or "",
        "montaj_tarihi": (satir.get("montaj_tarihi") or "").replace(".", "/"),
        "sayac_ucreti": satir.get("sayac_tutari") or "0,00",
        "sayac_ucreti_alinan": satir.get("alinan_tutar") or "0,00",
        "tesisat_ucreti": satir.get("malzeme_tutari") or "0,00",
        "tesisat_ucreti_alinan": satir.get("malzeme_alinan") or "0,00",
        "montaj_personeli": satir.get("montaj_personeli") or "",
    }


_MONTAJ_FORMU_SANDBOX = SandboxedEnvironment()


def _montaj_formu_render_tek(sablon_icerik, satir):
    """Şablonu tek bir abone verisiyle render eder. Hata olursa (bozuk Jinja/HTML)
    (None, hata_metni) döner; başarılıysa (render_edilmis_html, None) döner.

    Kullanıcının kendi yapıştırdığı/yüklediği (Word dahil) tasarım içeriği burada
    render ediliyor — yani bu içerik GÜVENİLMEZ (kullanıcı girdisi). Uygulamanın
    normal app.jinja_env'i yerine bilerek AYRI, kum havuzlu (sandboxed) bir Jinja
    ortamı (_MONTAJ_FORMU_SANDBOX) kullanılıyor: bu, "{{ ''.__class__.__mro__[1]
    .__subclasses__() }}" tarzı gadget zincirleriyle sunucuda kod çalıştırmayı
    (RCE) engeller, ama {{ adi }} / {% if telefon2 %} gibi normal şablon
    kullanımını olduğu gibi çalışır bırakır."""
    veri = _montaj_formu_veri(satir)
    try:
        return _MONTAJ_FORMU_SANDBOX.from_string(sablon_icerik).render(**veri), None
    except Exception as e:
        return None, str(e)


# Yeni yüklenen (.html veya .docx) bir Montaj Formu tasarımının kaydedilmeden önce
# güvenli şekilde render edilip edilemediğini sınamak için kullanılan sabit test verisi.
_MONTAJ_FORMU_TEST_VERISI = {
    "adi": "TEST", "soyadi": "TEST", "koy_adi": "TEST", "sayac_no": "0",
    "telefon": "", "telefon2": "", "montaj_tarihi": "01.01.2026",
    "sayac_tutari": "0,00", "alinan_tutar": "0,00",
    "malzeme_tutari": "0,00", "malzeme_alinan": "0,00", "montaj_personeli": "",
}


def _montaj_formu_sablonlar_listele(db):
    """Kayıtlı TÜM Montaj Formu tasarımlarının (id, ad) listesini döner — hem
    Tasarım sayfasındaki seçici sekmeler, hem de M.Form penceresindeki "hangi
    tasarımla açmak istersin" listesi için kullanılır."""
    cur = db.cursor()
    cur.execute("SELECT id, ad FROM montaj_formu_sablon ORDER BY id")
    satirlar = cur.fetchall()
    cur.close()
    return satirlar


def _montaj_formu_sablon_getir(db, sablon_id=None):
    """Belirli bir tasarımı (sablon_id verilmişse) ya da hiç verilmemişse kayıtlı
    İLK tasarımı döner. Hiç tasarım yoksa (ör. veritabanı henüz kurulmadıysa)
    koddaki sabit varsayılan tasarım kullanılır."""
    cur = db.cursor()
    if sablon_id:
        cur.execute("SELECT id, ad, icerik FROM montaj_formu_sablon WHERE id = %s", (sablon_id,))
    else:
        cur.execute("SELECT id, ad, icerik FROM montaj_formu_sablon ORDER BY id LIMIT 1")
    satir = cur.fetchone()
    cur.close()
    if satir:
        return satir
    return {"id": None, "ad": "Varsayılan", "icerik": _MONTAJ_FORMU_VARSAYILAN_SABLON}


def _montaj_formu_sablon_kaydet(db, sablon_id, yeni_icerik):
    """Var olan (id'si bilinen) bir Montaj Formu tasarımının içeriğini günceller —
    tasarım kutusundan Kaydet'e basıldığında, Varsayılana Döndür'de, ve dosyadan/
    Word'den tasarım yükleme akışlarında kullanılan ortak yardımcı fonksiyon."""
    cur = db.cursor()
    cur.execute(
        "UPDATE montaj_formu_sablon SET icerik = %s, guncelleme_tarihi = NOW() WHERE id = %s",
        (yeni_icerik, sablon_id),
    )
    db.commit()
    cur.close()


def _montaj_formu_sablon_olustur(db, ad, icerik):
    """Yeni, isimli bir Montaj Formu tasarımı oluşturur ve yeni kaydın id'sini döner."""
    cur = db.cursor()
    cur.execute(
        "INSERT INTO montaj_formu_sablon (ad, icerik) VALUES (%s, %s) RETURNING id",
        (ad or "Yeni Tasarım", icerik),
    )
    yeni_id = cur.fetchone()["id"]
    db.commit()
    cur.close()
    return yeni_id


def _montaj_formu_sablon_yeniden_adlandir(db, sablon_id, yeni_ad):
    cur = db.cursor()
    cur.execute("UPDATE montaj_formu_sablon SET ad = %s WHERE id = %s", (yeni_ad, sablon_id))
    db.commit()
    cur.close()


def _montaj_formu_sablon_sil(db, sablon_id):
    """Bir tasarımı siler. En az bir tasarım her zaman kalmalı — bunun kontrolü
    (tek tasarım kaldıysa silmeyi engelleme) çağıran route'ta yapılıyor."""
    cur = db.cursor()
    cur.execute("DELETE FROM montaj_formu_sablon WHERE id = %s", (sablon_id,))
    db.commit()
    cur.close()


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

    cur.execute("SELECT COUNT(*) FROM montaj_formu_sablon")
    if cur.fetchone()[0] == 0:
        cur.execute(
            "INSERT INTO montaj_formu_sablon (icerik) VALUES (%s)",
            (_MONTAJ_FORMU_VARSAYILAN_SABLON,),
        )
        conn.commit()

    # Arıza formu onay kutusu listeleri: bir grup için tabloda hiç satır yoksa
    # (ör. ilk kurulum, ya da biri "hepsini sil" yapmışsa) o grubun varsayılan
    # seçenekleri otomatik eklenir — böylece form hiçbir zaman bomboş kalmaz.
    for grup, varsayilan_liste in FORM_SECENEK_VARSAYILANLARI.items():
        cur.execute("SELECT COUNT(*) FROM form_secenegi WHERE grup = %s", (grup,))
        if cur.fetchone()[0] == 0:
            for sira, deger in enumerate(varsayilan_liste):
                cur.execute(
                    "INSERT INTO form_secenegi (grup, deger, sira) VALUES (%s, %s, %s)",
                    (grup, deger, sira),
                )
            conn.commit()

    cur.close()
    conn.close()


ensure_db()

# Her sayfa isteğinde veritabanına sıfırdan yeni bir bağlantı açıp kapatmak
# (özellikle uzak/şifreli bağlantılarda) küçük ama gerçek bir gecikme
# ekliyordu — her tıklama, bağlantı kurma maliyetini baştan ödüyordu.
# Bunun yerine uygulama başlarken birkaç bağlantı önceden açılıp bir havuzda
# hazır tutulur; her istek bu havuzdan bir bağlantı ödünç alır, işi bitince
# geri verir. Böylece bağlantı kurma maliyeti neredeyse tamamen ortadan kalkar.
_DB_HAVUZU = psycopg2.pool.ThreadedConnectionPool(
    1, 8, DATABASE_URL, cursor_factory=psycopg2.extras.RealDictCursor
)


def get_db():
    if "db" not in g:
        g.db = _DB_HAVUZU.getconn()
    return g.db


@app.teardown_appcontext
def close_db(exception=None):
    db = g.pop("db", None)
    if db is not None:
        try:
            # Önceki istekten kalan yarım bir işlem (transaction) varsa temizle
            # — yoksa havuzdan bu bağlantıyı bir sonraki ödünç alan istek onu
            # miras alır ve garip/anlaşılmaz hatalara yol açabilir.
            db.rollback()
        except Exception:
            pass
        _DB_HAVUZU.putconn(db)


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


# --- Giriş denemesi sınırlaması (brute-force / şifre tahmin saldırılarına
# karşı) --------------------------------------------------------------------
# Şifreyi otomatik olarak defalarca deneyen bir betiğin (script) hesabı ele
# geçirmesini zorlaştırmak için IP başına başarısız giriş denemesi sayılıyor;
# üst üste çok fazla başarısız denemeden sonra o IP birkaç dakikalığına
# kilitleniyor. Uygulama gunicorn'da TEK worker (--workers 1, --worker-class
# gthread ile çoklu thread) olarak çalıştığı için, bellek-içi (in-memory) bu
# basit sözlük tüm istekler arasında güvenle paylaşılabiliyor — ayrı bir
# Redis/veritabanı gerekmiyor. (İleride worker sayısı 1'in üzerine çıkarılırsa
# bu sayaç worker'lar arasında paylaşılmaz, o durumda paylaşılan bir depoya
# taşınması gerekir.)
_GIRIS_DENEME_KILIDI = threading.Lock()
_GIRIS_BASARISIZ_DENEMELER = {}  # ip -> (basarisiz_sayisi, son_deneme_zamani)
_GIRIS_MAKS_DENEME = 5
_GIRIS_KILIT_SURESI_SN = 5 * 60  # 5 dakika


def _giris_kilitli_mi(ip):
    with _GIRIS_DENEME_KILIDI:
        kayit = _GIRIS_BASARISIZ_DENEMELER.get(ip)
        if not kayit:
            return False, 0
        sayi, son_zaman = kayit
        if sayi < _GIRIS_MAKS_DENEME:
            return False, 0
        kalan = _GIRIS_KILIT_SURESI_SN - (time.time() - son_zaman)
        if kalan <= 0:
            del _GIRIS_BASARISIZ_DENEMELER[ip]
            return False, 0
        return True, kalan


def _giris_basarisiz_kaydet(ip):
    with _GIRIS_DENEME_KILIDI:
        sayi, _ = _GIRIS_BASARISIZ_DENEMELER.get(ip, (0, 0))
        _GIRIS_BASARISIZ_DENEMELER[ip] = (sayi + 1, time.time())


def _giris_basarili_temizle(ip):
    with _GIRIS_DENEME_KILIDI:
        _GIRIS_BASARISIZ_DENEMELER.pop(ip, None)


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        istemci_ip = request.remote_addr or "bilinmiyor"
        kilitli, kalan_sn = _giris_kilitli_mi(istemci_ip)
        if kilitli:
            flash(
                f"Çok fazla başarısız giriş denemesi yapıldı. Lütfen "
                f"{math.ceil(kalan_sn / 60)} dakika sonra tekrar deneyin."
            )
            return render_template("login.html")

        kullanici_adi = request.form.get("kullanici_adi", "").strip()
        sifre = request.form.get("sifre", "")

        db = get_db()
        cur = db.cursor()
        cur.execute("SELECT * FROM kullanici WHERE kullanici_adi = %s", (kullanici_adi,))
        user = cur.fetchone()
        cur.close()

        if user and check_password_hash(user["sifre_hash"], sifre):
            _giris_basarili_temizle(istemci_ip)
            session.clear()
            session["user_id"] = user["id"]
            session["kullanici_adi"] = user["kullanici_adi"]
            return redirect(url_for("abone_listesi"))

        _giris_basarisiz_kaydet(istemci_ip)
        flash("Kullanıcı adı veya şifre hatalı.")

    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/hesap-ayarlari", methods=["GET", "POST"])
@login_required
def hesap_ayarlari():
    db = get_db()
    cur = db.cursor()
    cur.execute("SELECT * FROM kullanici WHERE id = %s", (session["user_id"],))
    kullanici = cur.fetchone()

    if request.method == "POST":
        mevcut_sifre = request.form.get("mevcut_sifre", "")
        yeni_kullanici_adi = request.form.get("yeni_kullanici_adi", "").strip()
        yeni_sifre = request.form.get("yeni_sifre", "")
        yeni_sifre_tekrar = request.form.get("yeni_sifre_tekrar", "")

        if not kullanici or not check_password_hash(kullanici["sifre_hash"], mevcut_sifre):
            flash("Mevcut şifre yanlış, değişiklik yapılmadı.")
        elif not yeni_kullanici_adi:
            flash("Kullanıcı adı boş olamaz.")
        elif yeni_sifre and yeni_sifre != yeni_sifre_tekrar:
            flash("Yeni şifre ile tekrarı birbirini tutmuyor.")
        elif yeni_sifre and len(yeni_sifre) < 8:
            flash("Yeni şifre en az 8 karakter olmalı.")
        else:
            cur.execute(
                "SELECT id FROM kullanici WHERE kullanici_adi = %s AND id != %s",
                (yeni_kullanici_adi, kullanici["id"]),
            )
            cakisma = cur.fetchone()
            if cakisma:
                flash("Bu kullanıcı adı zaten başka bir hesapta kullanılıyor.")
            else:
                if yeni_sifre:
                    cur.execute(
                        "UPDATE kullanici SET kullanici_adi = %s, sifre_hash = %s WHERE id = %s",
                        (yeni_kullanici_adi, generate_password_hash(yeni_sifre), kullanici["id"]),
                    )
                else:
                    cur.execute(
                        "UPDATE kullanici SET kullanici_adi = %s WHERE id = %s",
                        (yeni_kullanici_adi, kullanici["id"]),
                    )
                db.commit()
                session["kullanici_adi"] = yeni_kullanici_adi
                cur.close()
                flash("Hesap bilgileriniz güncellendi.")
                return redirect(url_for("hesap_ayarlari"))

    cur.close()
    return render_template(
        "hesap_ayarlari.html", kullanici=kullanici,
        ofis_enlem=_ayar_getir(db, "ofis_enlem"),
        ofis_boylam=_ayar_getir(db, "ofis_boylam"),
    )


@app.route("/hesap-ayarlari/ofis-konumu", methods=["POST"])
@login_required
def hesap_ayarlari_ofis_konumu():
    """Hesap Ayarları'ndaki 'Ofis Konumu' kutusunun kaydet düğmesi. Buradaki
    değer, bilgisayardan (GPS'siz, konum tahmini güvenilmez) "Konum Al"
    basıldığında kullanılır — bkz. /api/ofis-konumu."""
    enlem = _konum_sayilastir(request.form.get("ofis_enlem"))
    boylam = _konum_sayilastir(request.form.get("ofis_boylam"))
    if enlem is None or boylam is None or not (-90 <= enlem <= 90) or not (-180 <= boylam <= 180):
        flash("Geçersiz koordinat — enlem -90 ile 90, boylam -180 ile 180 arasında bir sayı olmalı.")
        return redirect(url_for("hesap_ayarlari"))
    db = get_db()
    _ayar_kaydet(db, "ofis_enlem", str(enlem))
    _ayar_kaydet(db, "ofis_boylam", str(boylam))
    flash("Ofis konumu kaydedildi.")
    return redirect(url_for("hesap_ayarlari"))


@app.route("/api/ofis-konumu")
@login_required
def ofis_konumu_api():
    """abone_form.html / ariza_form.html'deki "Konum Al" butonu, bilgisayardan
    (dokunmatik olmayan bir cihazdan) basıldığında GPS denemek yerine bu uçtan
    kayıtlı ofis konumunu okur."""
    db = get_db()
    enlem = _ayar_getir(db, "ofis_enlem")
    boylam = _ayar_getir(db, "ofis_boylam")
    return jsonify({
        "enlem": float(enlem) if enlem else None,
        "boylam": float(boylam) if boylam else None,
    })


@app.route("/")
@login_required
def index():
    return redirect(url_for("abone_listesi"))


@app.route("/sw.js")
def service_worker():
    # PWA Service Worker dosyası, tüm siteyi (/) kapsayabilmesi için kök
    # dizinden (/sw.js) sunulur — static/ altından sunulsaydı varsayılan
    # kapsamı sadece /static/ olurdu ve uygulama "kurulabilir" (installable)
    # sayılmazdı. Giriş gerektirmez, çünkü tarayıcı bunu oturum açılmadan
    # önce de indirebilmeli.
    yanit = send_from_directory(app.static_folder, "sw.js")
    yanit.headers["Service-Worker-Allowed"] = "/"
    yanit.headers["Content-Type"] = "application/javascript"
    return yanit


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


def _isim_anahtari(adi, soyadi):
    return ((adi or "").strip().upper(), (soyadi or "").strip().upper())


def _tum_adaylari_olustur(abone_satirlari, koy_satirlari):
    """Hem 'abone' tablosundaki (mükerrer olabilen) tüm satırları, hem de
    'koy_abone' tablosundaki tüm satırları tarayıp, isme göre tekilleştirilmiş
    TÜM farklı kişi adaylarının listesini döndürür. Böylece aynı seri no
    'abone' tablosunda 2, 'koy_abone' tablosunda 1 farklı isimle kayıtlıysa
    (toplam 3 farklı kişi), üçü de listelenir — sadece kaynak başına bir
    temsilci değil."""
    adaylar = []
    gorulenler = set()
    for s in abone_satirlari:
        anahtar = _isim_anahtari(s["adi"], s["soyadi"])
        if anahtar in gorulenler:
            continue
        gorulenler.add(anahtar)
        adaylar.append({
            "kaynak": "abone",
            "adi": s["adi"] or "", "soyadi": s["soyadi"] or "",
            "telefon": s["telefon"] or "", "telefon2": s["telefon2"] or "",
            "koy_adi": s["koy_adi"] or "",
            "montaj_tarihi": _tarih_iso_hale_getir(s["montaj_tarihi"]),
        })
    for s in koy_satirlari:
        anahtar = _isim_anahtari(s["adi"], s["soyadi"])
        if anahtar in gorulenler:
            continue
        gorulenler.add(anahtar)
        adaylar.append({
            "kaynak": "koy_listesi",
            "adi": s["adi"] or "", "soyadi": s["soyadi"] or "",
            "telefon": "", "telefon2": "",
            "koy_adi": s["koy_adi"] or "",
            "montaj_tarihi": _tarih_iso_hale_getir(s["abonelik_tarihi"]),
        })
    return adaylar


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
    # çünkü aynı seri no iki kaynakta da (hatta bir kaynağın kendi içinde mükerrer
    # satırlarla) farklı bilgilerle kayıtlı olabilir. Bu durumda kullanıcıya TÜM
    # farklı adayları gösterip seçim yaptırıyoruz (bkz. secenekler / detaylı arama).
    cur.execute(
        "SELECT id, adi, soyadi, koy_adi, abonelik_tarihi FROM koy_abone WHERE cihaz_no = %s ORDER BY id",
        (sayac_no,),
    )
    koy_satirlari = cur.fetchall()
    cur.close()

    if not abone_satirlari and not koy_satirlari:
        return jsonify({"bulundu": False, "digerleri": []})

    abone_paket = _abone_kaynak_paketle(abone_satirlari) if abone_satirlari else None
    koy_paket = _koy_kaynak_paketle(koy_satirlari) if koy_satirlari else None
    birincil = abone_paket or koy_paket

    adaylar = _tum_adaylari_olustur(abone_satirlari, koy_satirlari)

    sonuc = dict(birincil)
    sonuc["secenekler"] = adaylar if len(adaylar) > 1 else []
    return jsonify(sonuc)


@app.route("/api/kolon-secenekleri")
@login_required
def kolon_secenekleri_api():
    """Liste sayfalarındaki (Abone Listesi, Arıza Takip vb.) sütun filtre
    kutuları artık sayfa ilk açıldığında TÜM sütunlar için seçenekleri
    hesaplamıyor (bu, 30 sütunlu bir sayfada 30 ayrı sorgu demekti ve asıl
    yavaşlığın kaynağıydı) — bunun yerine kullanıcı bir sütunun filtre
    kutusunu AÇTIĞINDA, sadece o tek sütun için bu uç nokta üzerinden
    (JavaScript ile) seçenekler istenir."""
    tablo = request.args.get("tablo", "").strip()
    anahtar = request.args.get("anahtar", "").strip()
    if tablo not in ("abone", "ariza"):
        return jsonify({"hata": "geçersiz tablo"}), 400
    db = get_db()
    if tablo == "abone":
        _kolon_listesi, bilgi_sozlugu, _sayisal, _ozel = _abone_kolon_takimi(db)
    else:
        _kolon_listesi, bilgi_sozlugu, _sayisal, _ozel = _ariza_kolon_takimi(db)
    if anahtar not in bilgi_sozlugu:
        return jsonify({"hata": "geçersiz sütun"}), 400
    secenekler = _kolon_secenekleri(db, anahtar, tablo, bilgi_sozlugu)
    return jsonify({"secenekler": secenekler})


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
        "SELECT id, gelis_tarihi, takilan_tarih, tespit_edilen_ariza, yapilan_islemler, "
        "ariza_ucret, alinan_ucret FROM ariza WHERE seri_no = %s ORDER BY id DESC",
        (seri_no,),
    )
    satirlar = cur.fetchall()
    cur.close()

    kayitlar = []
    for s in satirlar:
        kalan = (s["ariza_ucret"] or 0) - (s["alinan_ucret"] or 0)
        kayitlar.append({
            "id": s["id"],
            "duzenle_url": url_for("ariza_duzenle", ariza_id=s["id"]),
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

    ALAN_TANIMLARI = _ABONE_ALAN_TANIMLARI
    ALAN_HARITASI = _ABONE_ALAN_HARITASI
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
                    kosul_listesi.append(f"{_turkce_esle_kosul(f'CAST({kolon} AS TEXT)')} LIKE %s")
                    kosul_params.append(_turkce_normallestir(f"%{q}%"))
                else:
                    kosul_listesi.append(f"{_turkce_esle_kosul(kolon)} LIKE %s")
                    kosul_params.append(_turkce_normallestir(f"%{q}%"))
        if kosul_listesi:
            sql += " AND (" + " OR ".join(kosul_listesi) + ")"
            params += kosul_params
    if koy:
        sql += " AND koy_adi = %s"
        params.append(koy)

    kolon_listesi, kolon_bilgi, sayisal_kolonlar, ozel_alanlar = _abone_kolon_takimi(db)
    deger_secili = {}
    for anahtar, _ in kolon_listesi:
        secilenler = request.args.getlist(f"deger_{anahtar}")
        deger_secili[anahtar] = secilenler
        if secilenler:
            kosul, param_listesi = _kolon_kosul_coklu(anahtar, secilenler, kolon_bilgi)
            if kosul:
                sql += f" AND {kosul}"
                params += param_listesi

    sql += f" ORDER BY s_no {'DESC' if _sira_yonu_al() == 'desc' else 'ASC'}"

    cur = db.cursor()
    cur.execute(sql, params)
    kayitlar_ham = cur.fetchall()
    cur.execute("SELECT DISTINCT koy_adi FROM abone ORDER BY koy_adi")
    koyler = cur.fetchall()
    cur.execute("SELECT COUNT(*) AS c FROM abone")
    toplam_kayit = cur.fetchone()["c"]

    # Ödeme Gün Sözü hatırlatması: sözü verilen tarih bugüne gelmiş/geçmiş VE
    # hâlâ ödenmemiş (toplam kalan borç > 0) olan abonelerin uyarı listesi.
    bugun_iso = datetime.now().strftime("%Y-%m-%d")
    cur.execute(
        """
        SELECT id, koy_adi, adi, soyadi, odeme_gun_sozu,
               (sayac_tutari + malzeme_tutari - alinan_tutar - malzeme_alinan) AS toplam_kalan
        FROM abone
        WHERE odeme_gun_sozu IS NOT NULL AND odeme_gun_sozu <> ''
          AND odeme_gun_sozu <= %s
          AND (sayac_tutari + malzeme_tutari - alinan_tutar - malzeme_alinan) > 0
        ORDER BY odeme_gun_sozu ASC
        """,
        (bugun_iso,),
    )
    odeme_hatirlatmalari = [
        {
            "id": r["id"],
            "koy_adi": r["koy_adi"],
            "adi": r["adi"],
            "soyadi": r["soyadi"],
            "odeme_gun_sozu": _gg_aa_yyyy(r["odeme_gun_sozu"]),
            "toplam_kalan": tl_format(r["toplam_kalan"]),
        }
        for r in cur.fetchall()
    ]

    satirlar = [_abone_satir_sozlugu(k, ozel_alanlar) for k in kayitlar_ham]

    # Sütun filtre kutularının seçenekleri artık burada TÜM sütunlar için
    # tek tek sorgulanmıyor (30 ayrı SELECT DISTINCT — sayfanın yavaş
    # açılmasının asıl sebebiydi). Kullanıcı bir sütunun filtre kutusunu
    # açtığında /api/kolon-secenekleri ile JavaScript üzerinden anlık istenir.
    cur.close()

    # Sayfalama: ekrana basılan satır sayısı sınırlanıyor (bkz. _sayfala
    # tanımı) — arama/filtre sonucundaki TÜM kayıt sayısı filtreli_kayit'te
    # korunuyor, sadece görüntülenen satırlar bir sayfaya (SAYFA_BOYUTU)
    # bölünüyor.
    satirlar, filtreli_kayit, sayfa, toplam_sayfa = _sayfala(satirlar)

    return render_template(
        "abone_list.html", satirlar=satirlar, koyler=koyler, q=q, secili_koy=koy,
        secili_alanlar=alanlar_secili, alan_listesi=alan_listesi,
        kolon_listesi=kolon_listesi, deger_secili=deger_secili,
        sayisal_kolonlar=sayisal_kolonlar,
        arama_satir=_izgara_satir(len(alan_listesi)),
        arama_satir_2=_izgara_satir(len(alan_listesi), 2),
        filtreli_kayit=filtreli_kayit, toplam_kayit=toplam_kayit,
        odeme_hatirlatmalari=odeme_hatirlatmalari,
        sira=_sira_yonu_al(), sira_toggle_qs=_sira_toggle_qs(),
        sayfa=sayfa, toplam_sayfa=toplam_sayfa, sayfalama_qs=_sayfalama_qs,
    )


def _montaj_formu_secili_id(db, istenen_id):
    """İstenen sablon_id gerçekten var mı diye kontrol eder; yoksa (ör. silinmiş
    ya da hiç verilmemişse) kayıtlı ilk tasarımın id'sine döner."""
    sablonlar = _montaj_formu_sablonlar_listele(db)
    if not sablonlar:
        return None
    if istenen_id:
        for s in sablonlar:
            if s["id"] == istenen_id:
                return istenen_id
    return sablonlar[0]["id"]


@app.route("/montaj-formu/tasarim", methods=["GET", "POST"])
@login_required
def montaj_formu_tasarim():
    db = get_db()

    if request.method == "POST":
        sablon_id = request.form.get("sablon_id", type=int)
        yeni_icerik = request.form.get("icerik", "")
        _montaj_formu_sablon_kaydet(db, sablon_id, yeni_icerik)
        flash("Montaj Formu tasarımı kaydedildi.")
        return redirect(url_for("montaj_formu_tasarim", sablon_id=sablon_id))

    secili_id = _montaj_formu_secili_id(db, request.args.get("sablon_id", type=int))
    sablon = _montaj_formu_sablon_getir(db, secili_id)
    sablonlar = _montaj_formu_sablonlar_listele(db)

    ornek_satir = {
        "adi": "AHMET", "soyadi": "YILMAZ", "koy_adi": "ÖRNEK KÖYÜ",
        "sayac_no": "12345678", "telefon": "0555 555 55 55", "telefon2": "",
        "montaj_tarihi": datetime.now().strftime("%d.%m.%Y"),
        "sayac_tutari": "1.500,00", "alinan_tutar": "1.500,00",
        "malzeme_tutari": "750,00", "malzeme_alinan": "750,00",
        "montaj_personeli": "ÖRNEK PERSONEL",
    }
    onizleme_html, onizleme_hata = _montaj_formu_render_tek(sablon["icerik"], ornek_satir)

    return render_template(
        "montaj_formu_tasarim.html",
        sablon=sablon, sablonlar=sablonlar,
        icerik=sablon["icerik"], onizleme_html=onizleme_html, onizleme_hata=onizleme_hata,
    )


@app.route("/montaj-formu/tasarim/yeni", methods=["POST"])
@login_required
def montaj_formu_tasarim_yeni():
    """Boş/varsayılan içerikle yeni, isimli bir Montaj Formu tasarımı oluşturur —
    ör. birden fazla köy/firma için farklı görünümde form hazırlamak isteyenler için."""
    db = get_db()
    ad = (request.form.get("ad") or "").strip() or "Yeni Tasarım"
    yeni_id = _montaj_formu_sablon_olustur(db, ad, _MONTAJ_FORMU_VARSAYILAN_SABLON)
    flash(f'"{ad}" adında yeni bir Montaj Formu tasarımı oluşturuldu.')
    return redirect(url_for("montaj_formu_tasarim", sablon_id=yeni_id))


@app.route("/montaj-formu/tasarim/yeniden-adlandir", methods=["POST"])
@login_required
def montaj_formu_tasarim_yeniden_adlandir():
    db = get_db()
    sablon_id = request.form.get("sablon_id", type=int)
    yeni_ad = (request.form.get("ad") or "").strip()
    if sablon_id and yeni_ad:
        _montaj_formu_sablon_yeniden_adlandir(db, sablon_id, yeni_ad)
        flash("Tasarımın adı güncellendi.")
    return redirect(url_for("montaj_formu_tasarim", sablon_id=sablon_id))


@app.route("/montaj-formu/tasarim/sil", methods=["POST"])
@login_required
def montaj_formu_tasarim_sil():
    """Bir tasarımı siler. Kayıtlı TEK tasarım buysa (en az bir tasarım her zaman
    kalmalı, aksi halde Montaj Formu hiç oluşturulamaz) silme işlemi reddedilir."""
    db = get_db()
    sablon_id = request.form.get("sablon_id", type=int)
    sablonlar = _montaj_formu_sablonlar_listele(db)
    if len(sablonlar) <= 1:
        flash("Son kalan Montaj Formu tasarımı silinemez — en az bir tasarım kayıtlı olmalı.")
        return redirect(url_for("montaj_formu_tasarim", sablon_id=sablon_id))
    if sablon_id:
        _montaj_formu_sablon_sil(db, sablon_id)
        flash("Tasarım silindi.")
    return redirect(url_for("montaj_formu_tasarim"))


@app.route("/montaj-formu/sablonlar.json")
@login_required
def montaj_formu_sablonlar_json():
    """M.Form penceresinde 'hangi tasarımla açmak istiyorsun' listesini doldurmak
    için kullanılan küçük JSON uç noktası."""
    db = get_db()
    sablonlar = _montaj_formu_sablonlar_listele(db)
    return jsonify([{"id": s["id"], "ad": s["ad"]} for s in sablonlar])


@app.route("/montaj-formu/tasarim/sifirla", methods=["POST"])
@login_required
def montaj_formu_tasarim_sifirla():
    """Seçili Montaj Formu tasarımını, koddaki güncel varsayılan tasarıma sıfırlar."""
    db = get_db()
    sablon_id = request.form.get("sablon_id", type=int)
    _montaj_formu_sablon_kaydet(db, sablon_id, _MONTAJ_FORMU_VARSAYILAN_SABLON)
    flash("Montaj Formu tasarımı, programın güncel varsayılan tasarımına sıfırlandı.")
    return redirect(url_for("montaj_formu_tasarim", sablon_id=sablon_id))


@app.route("/montaj-formu/tasarim/dosya-yukle", methods=["POST"])
@login_required
def montaj_formu_tasarim_dosya_yukle():
    """Montaj Formu tasarımını, kullanıcının bilgisayarından seçtiği bir .html
    dosyasını yükleyerek değiştirir — kutuya elle yazma/yapıştırma yapmadan,
    tek bir dosya seçme + Yükle butonuyla yeni tasarımın devreye girmesini sağlar."""
    sablon_id = request.form.get("sablon_id", type=int)
    dosya = request.files.get("sablon_dosyasi")
    if dosya is None or not dosya.filename:
        flash("Lütfen yüklemek için bir tasarım dosyası (.html) seçin.")
        return redirect(url_for("montaj_formu_tasarim", sablon_id=sablon_id))

    try:
        yeni_icerik = dosya.read().decode("utf-8")
    except UnicodeDecodeError:
        flash("Dosya okunamadı — lütfen UTF-8 kodlamalı bir .html dosyası yükleyin.")
        return redirect(url_for("montaj_formu_tasarim", sablon_id=sablon_id))

    _, hata = _montaj_formu_render_tek(yeni_icerik, _MONTAJ_FORMU_TEST_VERISI)
    if hata:
        flash(f"Yüklenen dosyada bir hata var, tasarım kaydedilmedi: {hata}")
        return redirect(url_for("montaj_formu_tasarim", sablon_id=sablon_id))
    db = get_db()
    _montaj_formu_sablon_kaydet(db, sablon_id, yeni_icerik)
    flash("Montaj Formu tasarımı, yüklediğiniz dosyadan güncellendi.")
    return redirect(url_for("montaj_formu_tasarim", sablon_id=sablon_id))


@app.route("/montaj-formu/tasarim/word-yukle", methods=["POST"])
@login_required
def montaj_formu_tasarim_word_yukle():
    """Montaj Formu tasarımını, kullanıcının Word'de (.docx) hazırladığı bir belgeyi
    yükleyerek değiştirir. Belge, mammoth kütüphanesiyle HTML'e çevrilir — Word'deki
    tablo/kalın yazı gibi yapı korunur, ancak renk/piksel düzeyinde birebir görsel
    eşleşme garanti edilmez. Kullanıcı Word içinde {{ adi }} gibi alan adlarını TEK
    bir biçimlendirmeyle (araya kalın/italik geçişi koymadan) yazmalıdır; aksi halde
    dönüşüm sırasında alan adı ikiye bölünüp çalışmayabilir.

    Not: mammoth, Word'deki tablo kenarlığı/gölge/sütun genişliği gibi DİREKT
    biçimlendirmeyi HTML'e taşımaz ve her metni fazladan boşluklu bir <p> içine
    sarar — bu yüzden dönüşümden hemen sonra _word_tasarimini_onar() ile bunlar
    otomatik olarak onarılıyor (bkz. o fonksiyonun docstring'i)."""
    sablon_id = request.form.get("sablon_id", type=int)
    if mammoth is None:
        flash("Word'den tasarım yükleme özelliği şu anda kullanılamıyor (sunucu tarafında "
              "'mammoth' kütüphanesi kurulu değil). Lütfen bizimle iletişime geçin.")
        return redirect(url_for("montaj_formu_tasarim", sablon_id=sablon_id))

    dosya = request.files.get("sablon_word")
    if dosya is None or not dosya.filename:
        flash("Lütfen yüklemek için bir Word belgesi (.docx) seçin.")
        return redirect(url_for("montaj_formu_tasarim", sablon_id=sablon_id))

    try:
        sonuc = mammoth.convert_to_html(dosya)
        yeni_icerik = _word_tasarimini_onar(sonuc.value)
    except Exception as e:
        flash(f"Word belgesi okunamadı: {e}")
        return redirect(url_for("montaj_formu_tasarim", sablon_id=sablon_id))

    if not yeni_icerik.strip():
        flash("Word belgesinden hiçbir içerik okunamadı — lütfen dosyayı kontrol edin.")
        return redirect(url_for("montaj_formu_tasarim", sablon_id=sablon_id))

    _, hata = _montaj_formu_render_tek(yeni_icerik, _MONTAJ_FORMU_TEST_VERISI)
    if hata:
        flash(f"Word belgesinden dönüştürülen tasarımda bir hata var, tasarım "
              f"kaydedilmedi: {hata}")
        return redirect(url_for("montaj_formu_tasarim", sablon_id=sablon_id))

    db = get_db()
    _montaj_formu_sablon_kaydet(db, sablon_id, yeni_icerik)
    uyari_sayisi = len(getattr(sonuc, "messages", []) or [])
    if uyari_sayisi:
        flash(f"Montaj Formu tasarımı, Word belgesinden güncellendi ({uyari_sayisi} "
              f"küçük dönüşüm notu var — önizlemeyi kontrol edin).")
    else:
        flash("Montaj Formu tasarımı, Word belgesinden güncellendi.")
    return redirect(url_for("montaj_formu_tasarim", sablon_id=sablon_id))


@app.route("/abone/<int:abone_id>/montaj-formu")
@login_required
def abone_montaj_formu(abone_id):
    db = get_db()
    cur = db.cursor()
    cur.execute("SELECT * FROM abone WHERE id = %s", (abone_id,))
    kayit = cur.fetchone()
    cur.close()
    if kayit is None:
        flash("Abone bulunamadı.")
        return redirect(url_for("abone_listesi"))

    sablon_id = _montaj_formu_secili_id(db, request.args.get("sablon_id", type=int))
    sablon = _montaj_formu_sablon_getir(db, sablon_id)
    satir = _abone_satir_sozlugu(kayit)
    render_edilmis, hata = _montaj_formu_render_tek(sablon["icerik"], satir)
    if hata:
        flash(f"Montaj Formu tasarımında hata var, lütfen tasarımı kontrol edin: {hata}")
        return redirect(url_for("montaj_formu_tasarim", sablon_id=sablon["id"]))

    return render_template(
        "montaj_formu.html",
        sayfalar=[render_edilmis],
        baslik=f"{satir['adi'] or ''} {satir['soyadi'] or ''}".strip(),
        geri_url=url_for("abone_listesi"),
    )


@app.route("/abone/<int:abone_id>/montaj-formu/onizle/<int:sablon_id>")
@login_required
def abone_montaj_formu_onizle(abone_id, sablon_id):
    """M.Form penceresinde, formu tam açmadan ÖNCE hangi tasarım olduğunu
    görebilmek için kullanılan küçük önizleme. Gerçek abone verisiyle, TEK
    kopya, yazdırma çerçevesi (Geri Dön/Yazdır butonları, iki kopya vb.)
    OLMADAN, pencere içindeki bir <iframe>'e gömülmek üzere bağımsız/tam bir
    HTML sayfası döner."""
    db = get_db()
    cur = db.cursor()
    cur.execute("SELECT * FROM abone WHERE id = %s", (abone_id,))
    kayit = cur.fetchone()
    cur.close()
    if kayit is None:
        return "<p>Abone bulunamadı.</p>", 404

    sablon = _montaj_formu_sablon_getir(db, sablon_id)
    satir = _abone_satir_sozlugu(kayit)
    render_edilmis, hata = _montaj_formu_render_tek(sablon["icerik"], satir)
    if hata:
        return f"<p>Bu tasarımda bir hata var: {hata}</p>"

    return render_template("montaj_formu_onizle_parca.html", icerik=render_edilmis)


@app.route("/abone/montaj-formu/toplu")
@login_required
def abone_montaj_formu_toplu():
    db = get_db()
    kayitlar_ham = _abone_filtreli_kayitlari_getir(db)
    if not kayitlar_ham:
        flash("Filtreye uyan abone bulunamadı.")
        return redirect(url_for("abone_listesi"))

    sablon_id = _montaj_formu_secili_id(db, request.args.get("sablon_id", type=int))
    sablon = _montaj_formu_sablon_getir(db, sablon_id)

    sayfalar = []
    for kayit in kayitlar_ham:
        satir = _abone_satir_sozlugu(kayit)
        render_edilmis, hata = _montaj_formu_render_tek(sablon["icerik"], satir)
        if hata:
            flash(f"Montaj Formu tasarımında hata var, lütfen tasarımı kontrol edin: {hata}")
            return redirect(url_for("montaj_formu_tasarim", sablon_id=sablon["id"]))
        sayfalar.append(render_edilmis)

    return render_template(
        "montaj_formu.html",
        sayfalar=sayfalar,
        baslik=f"Toplu ({len(sayfalar)} kayıt)",
        geri_url=url_for("abone_listesi") + "?" + request.query_string.decode(),
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
        _kk = _turkce_esle_kosul
        sql += (f" AND ({_kk('adi')} LIKE %s OR {_kk('soyadi')} LIKE %s OR {_kk('cihaz_no')} LIKE %s "
                f"OR {_kk('abone_no')} LIKE %s OR {_kk('adres')} LIKE %s)")
        params += [_turkce_normallestir(f"%{q}%")] * 5

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

    sira = _sira_yonu_al()
    satirlar.sort(key=_siralama_anahtari, reverse=(sira == "desc"))

    satirlar, filtreli_kayit, sayfa, toplam_sayfa = _sayfala(satirlar)

    return render_template(
        "koy_abone_listesi.html", satirlar=satirlar, koyler=koyler,
        q=q, secili_koy=koy,
        filtreli_kayit=filtreli_kayit, toplam_kayit=toplam_kayit,
        secili_koy_toplam=secili_koy_toplam,
        sira=sira, sira_toggle_qs=_sira_toggle_qs(),
        sayfa=sayfa, toplam_sayfa=toplam_sayfa, sayfalama_qs=_sayfalama_qs,
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


def _konum_sayilastir(deger):
    """Konum (enlem/boylam) alanları için: boşsa/hatalıysa None döner —
    _sayilastir'den farklı olarak 0.0'a düşürmüyoruz, çünkü konum
    alınmamışsa veritabanında boş (NULL) kalması gerekiyor, 0,0 koordinatı
    (gerçekte Afrika açıklarında bir nokta) yanlış anlaşılmasın diye."""
    try:
        deger = str(deger).strip()
        return float(deger) if deger else None
    except (ValueError, TypeError):
        return None


def _ayar_getir(db, anahtar):
    """Basit anahtar/değer ayar deposundan ('ayar' tablosu) bir değeri okur;
    hiç ayarlanmamışsa None döner."""
    cur = db.cursor()
    cur.execute("SELECT deger FROM ayar WHERE anahtar = %s", (anahtar,))
    satir = cur.fetchone()
    cur.close()
    return satir["deger"] if satir else None


def _ayar_kaydet(db, anahtar, deger):
    """Basit anahtar/değer ayar deposuna ('ayar' tablosu) bir değer yazar
    (varsa günceller, yoksa ekler)."""
    cur = db.cursor()
    cur.execute(
        "INSERT INTO ayar (anahtar, deger) VALUES (%s, %s) "
        "ON CONFLICT (anahtar) DO UPDATE SET deger = EXCLUDED.deger",
        (anahtar, deger),
    )
    db.commit()
    cur.close()


def _sonraki_s_no(db):
    """Yeni Abone formunda gösterilen, KABACA bir öngörü — kesin sıra numarası
    kayıt kaydedildikten sonra _abone_sira_numaralarini_yenile ile (montaj
    tarihine göre) yeniden hesaplanır."""
    cur = db.cursor()
    cur.execute("SELECT COUNT(*) AS c FROM abone")
    satir = cur.fetchone()
    cur.close()
    return (satir["c"] or 0) + 1


def _abone_sira_numaralarini_yenile(db):
    """S.No artık elle girilen bir değer değil — abone kayıtları HER ZAMAN
    montaj tarihine göre (eskiden yeniye) sıralı tutuluyor ve S.No bu sıraya
    göre 1'den başlayarak boşluksuz yeniden numaralandırılıyor (arıza
    kayıtlarındaki geliş tarihi mantığıyla birebir aynı — bkz.
    _ariza_sira_numaralarini_yenile). Bir kayıt silindiğinde arada boşluk
    kalmaması, yeni bir kayıt geçmiş bir montaj tarihiyle girildiğinde de
    sıraya doğru yerine oturması için bu fonksiyon her ekleme/güncelleme/
    silme sonrasında çağrılıyor."""
    cur = db.cursor()
    cur.execute(
        """
        UPDATE abone a
        SET s_no = t.yeni_sira
        FROM (
            SELECT id, ROW_NUMBER() OVER (ORDER BY montaj_tarihi ASC NULLS LAST, id ASC) AS yeni_sira
            FROM abone
        ) t
        WHERE a.id = t.id AND a.s_no IS DISTINCT FROM t.yeni_sira
        """
    )
    db.commit()
    cur.close()


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
        yeni_id = _abone_kaydet(None)
        db = get_db()
        _abone_fotograflarini_kaydet(db, yeni_id, request.files.getlist("fotograflar"))
        return redirect(url_for("abone_listesi"))
    db = get_db()
    return render_template(
        "abone_form.html", kayit=None,
        sonraki_s_no=_sonraki_s_no(db),
        sonraki_senet_no=_sonraki_senet_no(db),
        fotograflar=[],
        ozel_alan_harita=_ozel_alan_harita(_ozel_alanlari_getir(db, "abone")),
    )


@app.route("/abone/<int:abone_id>/duzenle", methods=["GET", "POST"])
@login_required
def abone_duzenle(abone_id):
    db = get_db()
    geri = request.args.get("geri", "") or request.form.get("geri", "")
    if request.method == "POST":
        _abone_kaydet(abone_id)
        _abone_fotograflarini_kaydet(db, abone_id, request.files.getlist("fotograflar"))
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
    cur = db.cursor()
    cur.execute(
        "SELECT id, dosya_adi, content_type FROM abone_fotograf WHERE abone_id = %s ORDER BY id",
        (abone_id,),
    )
    fotograflar = cur.fetchall()
    cur.close()
    return render_template(
        "abone_form.html", kayit=kayit, geri=geri, fotograflar=fotograflar,
        ozel_alan_harita=_ozel_alan_harita(_ozel_alanlari_getir(db, "abone")),
    )


@app.route("/abone/<int:abone_id>/sil", methods=["POST"])
@login_required
def abone_sil(abone_id):
    geri = request.args.get("geri", "")
    db = get_db()
    cur = db.cursor()
    cur.execute("DELETE FROM abone WHERE id = %s", (abone_id,))
    db.commit()
    cur.close()
    _abone_sira_numaralarini_yenile(db)
    hedef = url_for("abone_listesi")
    if geri:
        hedef += "?" + geri
    return redirect(hedef)


@app.route("/abone-fotograf/<int:foto_id>")
@login_required
def abone_fotograf_goster(foto_id):
    db = get_db()
    cur = db.cursor()
    cur.execute("SELECT content_type, icerik FROM abone_fotograf WHERE id = %s", (foto_id,))
    foto = cur.fetchone()
    cur.close()
    if foto is None:
        return "Fotoğraf bulunamadı.", 404
    yanit = Response(bytes(foto["icerik"]), mimetype=foto["content_type"] or "application/octet-stream")
    # Tarayıcının, gerçek içerik resim/video olmadığı halde (ör. eski kayıtlarda)
    # dosyayı "koklayıp" (MIME sniffing) HTML/script olarak yorumlamasını engeller —
    # depolanan (stored) XSS riskine karşı ek bir savunma katmanı.
    yanit.headers["X-Content-Type-Options"] = "nosniff"
    return yanit


@app.route("/abone-fotograf/<int:foto_id>/sil", methods=["POST"])
@login_required
def abone_fotograf_sil(foto_id):
    db = get_db()
    cur = db.cursor()
    cur.execute("SELECT abone_id FROM abone_fotograf WHERE id = %s", (foto_id,))
    foto = cur.fetchone()
    if foto:
        cur.execute("DELETE FROM abone_fotograf WHERE id = %s", (foto_id,))
        db.commit()
    cur.close()
    if foto:
        return redirect(url_for("abone_duzenle", abone_id=foto["abone_id"]))
    return redirect(url_for("abone_listesi"))


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
        montaj_personeli=f.get("montaj_personeli", "").strip(),
        odeme_tarihi=f.get("odeme_tarihi", "").strip(),
        odeme_sekli=f.get("odeme_sekli", "").strip(),
        odeme_gun_sozu=f.get("odeme_gun_sozu", "").strip(),
        odemeyi_gonderen=f.get("odemeyi_gonderen", "").strip(),
        aciklama=f.get("aciklama", "").strip(),
        muhtara_odenecek=_sayilastir(f.get("muhtara_odenecek")),
        muhtara_odenen=_sayilastir(f.get("muhtara_odenen")),
        fatura_no=f.get("fatura_no", "").strip(),
        konum_enlem=_konum_sayilastir(f.get("konum_enlem")),
        konum_boylam=_konum_sayilastir(f.get("konum_boylam")),
    )

    for oa in _ozel_alanlari_getir(db, "abone"):
        if oa["tur"] == "sayi":
            alanlar[oa["kolon_adi"]] = _sayilastir(f.get(oa["kolon_adi"]))
        else:
            alanlar[oa["kolon_adi"]] = f.get(oa["kolon_adi"], "").strip()

    if abone_id is None:
        kolonlar = ", ".join(alanlar.keys())
        yer_tutucular = ", ".join(["%s"] * len(alanlar))
        cur.execute(
            f"INSERT INTO abone ({kolonlar}) VALUES ({yer_tutucular}) RETURNING id",
            list(alanlar.values()),
        )
        abone_id = cur.fetchone()["id"]
    else:
        set_ifadesi = ", ".join([f"{k} = %s" for k in alanlar.keys()])
        cur.execute(
            f"UPDATE abone SET {set_ifadesi}, updated_at = NOW() WHERE id = %s",
            list(alanlar.values()) + [abone_id],
        )
    db.commit()
    cur.close()
    _abone_sira_numaralarini_yenile(db)
    return abone_id


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
    db = get_db()
    kolon_listesi, kolon_bilgi, _sayisal, ozel_alanlar = _abone_kolon_takimi(db)
    kolonlar_secili = request.args.getlist("kolon")
    goster_kolonlari = kolonlar_secili if kolonlar_secili else [k for k, _ in kolon_listesi]
    sql = "SELECT * FROM abone WHERE 1=1"
    params = []
    for anahtar in goster_kolonlari:
        secilenler = request.args.getlist(f"deger_{anahtar}")
        if secilenler:
            kosul, param_listesi = _kolon_kosul_coklu(anahtar, secilenler, kolon_bilgi)
            if kosul:
                sql += f" AND {kosul}"
                params += param_listesi
    sql += f" ORDER BY s_no {'DESC' if _sira_yonu_al() == 'desc' else 'ASC'}"
    cur = db.cursor()
    cur.execute(sql, params)
    kayitlar_ham = cur.fetchall()
    cur.close()
    satirlar = [_abone_satir_sozlugu(k, ozel_alanlar) for k in kayitlar_ham]
    return satirlar, goster_kolonlari, kolon_listesi


@app.route("/tahsilat-ciktisi")
@login_required
def tahsilat_ciktisi():
    yonlendirme = _filtre_durumu_uygula("tahsilat_ciktisi")
    if yonlendirme:
        return yonlendirme

    satirlar, goster_kolonlari, kolon_listesi = _tahsilat_ciktisi_satirlar()
    kolonlar_secili = request.args.getlist("kolon")
    db = get_db()
    _kl, _kb, sayisal_kolonlar, _ozel = _abone_kolon_takimi(db)
    kolon_secim_listesi = DISPLAY_KOLONLARI_ALFABETIK + [
        (k, e) for k, e in kolon_listesi if k not in _DISPLAY_KOLON_HARITASI
    ]

    deger_secili = {}
    for anahtar in goster_kolonlari:
        deger_secili[anahtar] = request.args.getlist(f"deger_{anahtar}")

    # Sütun filtre seçenekleri artık tembel yükleniyor, bkz. abone_listesi().
    cur = db.cursor()
    cur.execute("SELECT COUNT(*) AS c FROM abone")
    toplam_kayit = cur.fetchone()["c"]
    cur.close()

    # Excel çıktısı (tahsilat_ciktisi_excel) TÜM satırları kullanmaya devam
    # ediyor — sadece bu HTML görünümü sayfalanıyor.
    satirlar, filtreli_kayit, sayfa, toplam_sayfa = _sayfala(satirlar)

    return render_template(
        "tahsilat_ciktisi.html",
        satirlar=satirlar,
        kolon_listesi=kolon_listesi, goster_kolonlari=goster_kolonlari,
        kolon_secim_listesi=kolon_secim_listesi,
        secili_kolonlar=kolonlar_secili,
        deger_secili=deger_secili,
        sayisal_kolonlar=sayisal_kolonlar,
        kolon_satir=_izgara_satir(len(kolon_secim_listesi)),
        kolon_satir_2=_izgara_satir(len(kolon_secim_listesi), 2),
        filtreli_kayit=filtreli_kayit, toplam_kayit=toplam_kayit,
        sira=_sira_yonu_al(), sira_toggle_qs=_sira_toggle_qs(),
        sayfa=sayfa, toplam_sayfa=toplam_sayfa, sayfalama_qs=_sayfalama_qs,
        tumunu_goster_qs=_tumunu_goster_qs(),
    )


@app.route("/tahsilat-ciktisi-excel")
@login_required
def tahsilat_ciktisi_excel():
    satirlar, goster_kolonlari, kolon_listesi = _tahsilat_ciktisi_satirlar()
    tarih = datetime.now().strftime("%d_%m_%Y")
    return _csv_olustur(kolon_listesi, goster_kolonlari, satirlar, f"tahsilat_ciktisi_{tarih}.csv")


def _ariza_secenek_baglami(db):
    """Arıza formundaki iki onay kutusu listesini (güncel veritabanı sırasıyla)
    ve ızgara satır sayılarını, render_template'e doğrudan **ile geçirilecek
    şekilde hazırlar."""
    tespit = _form_secenekleri_getir(db, "tespit_edilen_ariza")
    islem = _form_secenekleri_getir(db, "yapilan_islemler")
    return dict(
        tespit_secenekleri=tespit,
        islem_secenekleri=islem,
        # Form tek sayfaya sığsın diye bu ızgaralar 4 yerine 6 sütun hedefler (daha az satır).
        tespit_satir=_izgara_satir(len(tespit), 6),
        tespit_satir_2=_izgara_satir(len(tespit), 2),
        islem_satir=_izgara_satir(len(islem), 6),
        islem_satir_2=_izgara_satir(len(islem), 2),
    )


def _ariza_sonraki_s_no(db):
    """Yeni Arıza formunda gösterilen, KABACA bir öngörü — kesin sıra numarası
    kayıt kaydedildikten sonra _ariza_sira_numaralarini_yenile ile (geliş
    tarihine göre) yeniden hesaplanır."""
    cur = db.cursor()
    cur.execute("SELECT COUNT(*) AS c FROM ariza")
    satir = cur.fetchone()
    cur.close()
    return (satir["c"] or 0) + 1


def _ariza_sira_numaralarini_yenile(db):
    """S.No artık elle girilen bir değer değil — arıza kayıtları HER ZAMAN
    geliş tarihine göre (eskiden yeniye) sıralı tutuluyor ve S.No bu sıraya
    göre 1'den başlayarak boşluksuz yeniden numaralandırılıyor. Bir kayıt
    silindiğinde arada boşluk kalmaması, yeni bir kayıt geçmiş bir tarihle
    girildiğinde de sıraya doğru yerine oturması için bu fonksiyon her
    ekleme/güncelleme/silme sonrasında çağrılıyor."""
    cur = db.cursor()
    cur.execute(
        """
        UPDATE ariza a
        SET s_no = t.yeni_sira
        FROM (
            SELECT id, ROW_NUMBER() OVER (ORDER BY gelis_tarihi ASC NULLS LAST, id ASC) AS yeni_sira
            FROM ariza
        ) t
        WHERE a.id = t.id AND a.s_no IS DISTINCT FROM t.yeni_sira
        """
    )
    db.commit()
    cur.close()


def _ariza_kaydet(ariza_id):
    f = request.form
    ariza_ucret = _sayilastir(f.get("ariza_ucret"))
    alinan_ucret = _sayilastir(f.get("alinan_ucret"))
    tespit_metni = ", ".join(f.getlist("tespit_edilen_ariza"))
    islem_metni = ", ".join(f.getlist("yapilan_islemler"))

    alanlar = dict(
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
        teslim_tarihi=f.get("teslim_tarihi", "").strip(),
        sayac_kredisi=f.get("sayac_kredisi", "").strip(),
        tespit_edilen_ariza=tespit_metni,
        tespit_aciklama=f.get("tespit_aciklama", "").strip(),
        yapilan_islemler=islem_metni,
        islem_aciklama=f.get("islem_aciklama", "").strip(),
        konum_enlem=_konum_sayilastir(f.get("konum_enlem")),
        konum_boylam=_konum_sayilastir(f.get("konum_boylam")),
    )

    db = get_db()
    for oa in _ozel_alanlari_getir(db, "ariza"):
        if oa["tur"] == "sayi":
            alanlar[oa["kolon_adi"]] = _sayilastir(f.get(oa["kolon_adi"]))
        else:
            alanlar[oa["kolon_adi"]] = f.get(oa["kolon_adi"], "").strip()

    cur = db.cursor()
    if ariza_id is None:
        kolonlar = ", ".join(alanlar.keys())
        yer_tutucular = ", ".join(["%s"] * len(alanlar))
        cur.execute(
            f"INSERT INTO ariza ({kolonlar}) VALUES ({yer_tutucular}) RETURNING id",
            list(alanlar.values()),
        )
        ariza_id = cur.fetchone()["id"]
    else:
        set_ifadesi = ", ".join([f"{k} = %s" for k in alanlar.keys()])
        cur.execute(f"UPDATE ariza SET {set_ifadesi}, updated_at = NOW() WHERE id = %s", list(alanlar.values()) + [ariza_id])
    db.commit()
    cur.close()
    _ariza_sira_numaralarini_yenile(db)
    return ariza_id


# Fotoğraf/video yüklerken izin verilen dosya türleri ve üst boyut sınırı
# (kötüye kullanımı / veritabanının aşırı şişmesini önlemek için). Video
# dosyaları fotoğraftan çok daha büyük olabildiği için sınır video'yu da
# rahatça kapsayacak şekilde yükseltildi — ama unutulmamalı: videolar da
# tıpkı fotoğraflar gibi doğrudan veritabanında saklanıyor, bu yüzden çok
# sayıda/uzun video biriktirmek veritabanı boyutunu belirgin şekilde büyütür.
_FOTOGRAF_MAKS_BOYUT = 60 * 1024 * 1024  # 60 MB (tek dosya)

# Yüklenen dosyanın "video" olduğunu, dosyanın kendi baytlarındaki (tarayıcının
# gönderdiği Content-Type başlığına değil) bilinen konteyner imzalarına bakarak
# doğrulamak için kullanılıyor. (offset, imza_baytlari) çiftleri.
_VIDEO_IMZALARI = (
    (4, b"ftyp"),              # MP4 / MOV / M4V / 3GP (ISO base media)
    (0, b"\x1A\x45\xDF\xA3"),  # WebM / MKV (EBML)
    (0, b"RIFF"),              # AVI (RIFF....AVI  — AVI etiketi ayrıca kontrol ediliyor)
    (0, b"\x00\x00\x00\x0C\x6A\x50"),  # bazı eski/mobil MOV varyantları
)

_RESIM_FORMAT_MIME_HARITASI = {
    "JPEG": "image/jpeg", "PNG": "image/png", "GIF": "image/gif",
    "WEBP": "image/webp", "BMP": "image/bmp", "HEIF": "image/heif", "TIFF": "image/tiff",
}


def _dosya_gercek_turu_dogrula(icerik, beyan_edilen_tur):
    """Yüklenen dosyanın GERÇEKTEN bir resim/video olup olmadığını dosyanın kendi
    baytlarına bakarak doğrular. Tarayıcının form ile birlikte gönderdiği
    Content-Type başlığı (beyan_edilen_tur) istemci tarafından kolayca
    sahtelenebilir — ör. içine <script> gömülü bir SVG dosyası "image/jpeg" diye
    işaretlenip yüklenebilir, sonra "fotoğrafı görüntüle" linkiyle açıldığında
    tarayıcıda çalışıp oturum çalabilirdi (depolanan/stored XSS). Bu yüzden
    depolamadan önce gerçek türü burada bağımsızca tespit ediyoruz; doğrulanmış,
    güvenli bir MIME türü döner, dosya resim/video olarak doğrulanamazsa None
    döner (ör. SVG, HTML, veya bozuk/tanınmayan dosyalar burada elenir)."""
    if beyan_edilen_tur.startswith("image/"):
        try:
            from PIL import Image
            with Image.open(io.BytesIO(icerik)) as img:
                img.verify()
            # verify() sonrası aynı akışı tekrar açmak gerekiyor (verify tek kullanımlık)
            with Image.open(io.BytesIO(icerik)) as img2:
                return _RESIM_FORMAT_MIME_HARITASI.get(img2.format)
        except Exception:
            return None
    if beyan_edilen_tur.startswith("video/"):
        for konum, imza in _VIDEO_IMZALARI:
            if icerik[konum:konum + len(imza)] == imza:
                if imza == b"RIFF" and icerik[8:12] != b"AVI ":
                    continue
                return beyan_edilen_tur if beyan_edilen_tur.startswith("video/") else "video/mp4"
        return None
    return None


def _medya_kaydet(db, tablo, sahip_kolonu, sahip_id, dosyalar):
    """Arıza ve abone kayıtlarındaki fotoğraf/video yükleme kutuları aynı mantığı
    paylaşıyor — bu yüzden ortak bir yerde tutuluyor. `tablo` ve `sahip_kolonu`
    her zaman kod içinde sabit (kullanıcıdan gelmiyor), bu yüzden f-string ile
    kullanılmaları güvenli."""
    cur = db.cursor()
    for dosya in dosyalar:
        if not dosya or not dosya.filename:
            continue
        icerik = dosya.read()
        if not icerik:
            continue
        if len(icerik) > _FOTOGRAF_MAKS_BOYUT:
            flash(f'"{dosya.filename}" dosyası çok büyük (60 MB üstü), yüklenmedi.')
            continue
        tur = dosya.mimetype or ""
        if not (tur.startswith("image/") or tur.startswith("video/")):
            flash(f'"{dosya.filename}" bir resim/video dosyası gibi görünmüyor, yüklenmedi.')
            continue
        dogrulanmis_tur = _dosya_gercek_turu_dogrula(icerik, tur)
        if not dogrulanmis_tur:
            flash(f'"{dosya.filename}" dosyasının içeriği bir resim/video ile eşleşmiyor, yüklenmedi.')
            continue
        cur.execute(
            f"INSERT INTO {tablo} ({sahip_kolonu}, dosya_adi, content_type, icerik) VALUES (%s, %s, %s, %s)",
            (sahip_id, dosya.filename, dogrulanmis_tur, psycopg2.Binary(icerik)),
        )
    db.commit()
    cur.close()


def _ariza_fotograflarini_kaydet(db, ariza_id, dosyalar):
    _medya_kaydet(db, "ariza_fotograf", "ariza_id", ariza_id, dosyalar)


def _abone_fotograflarini_kaydet(db, abone_id, dosyalar):
    _medya_kaydet(db, "abone_fotograf", "abone_id", abone_id, dosyalar)


@app.route("/admin/secenek-yonetimi")
@login_required
def secenek_yonetimi():
    db = get_db()
    cur = db.cursor()
    gruplar = {}
    for anahtar, baslik in FORM_SECENEK_GRUPLARI.items():
        cur.execute(
            "SELECT id, deger, sira FROM form_secenegi WHERE grup = %s ORDER BY sira, id",
            (anahtar,),
        )
        gruplar[anahtar] = {"baslik": baslik, "secenekler": cur.fetchall()}
    cur.close()
    return render_template(
        "secenek_yonetimi.html",
        gruplar=gruplar, grup_sirasi=list(FORM_SECENEK_GRUPLARI.keys()),
    )


@app.route("/admin/secenek-yonetimi/ekle", methods=["POST"])
@login_required
def secenek_yonetimi_ekle():
    grup = request.form.get("grup", "")
    deger = request.form.get("deger", "").strip()
    if grup not in FORM_SECENEK_GRUPLARI:
        flash("Geçersiz seçenek grubu.")
        return redirect(url_for("secenek_yonetimi"))
    if not deger:
        flash("Boş seçenek eklenemez.")
        return redirect(url_for("secenek_yonetimi"))

    db = get_db()
    cur = db.cursor()
    cur.execute(
        "SELECT id FROM form_secenegi WHERE grup = %s AND LOWER(deger) = LOWER(%s)",
        (grup, deger),
    )
    if cur.fetchone():
        flash(f'"{deger}" zaten bu listede var.')
        cur.close()
        return redirect(url_for("secenek_yonetimi"))

    cur.execute("SELECT COALESCE(MAX(sira), -1) AS m FROM form_secenegi WHERE grup = %s", (grup,))
    sonraki_sira = cur.fetchone()["m"] + 1
    cur.execute(
        "INSERT INTO form_secenegi (grup, deger, sira) VALUES (%s, %s, %s)",
        (grup, deger, sonraki_sira),
    )
    db.commit()
    cur.close()
    flash(f'"{deger}" eklendi.')
    return redirect(url_for("secenek_yonetimi"))


@app.route("/admin/secenek-yonetimi/duzenle/<int:secenek_id>", methods=["POST"])
@login_required
def secenek_yonetimi_duzenle(secenek_id):
    yeni_deger = request.form.get("deger", "").strip()
    if not yeni_deger:
        flash("Boş değer kaydedilemez.")
        return redirect(url_for("secenek_yonetimi"))
    db = get_db()
    cur = db.cursor()
    cur.execute("UPDATE form_secenegi SET deger = %s WHERE id = %s", (yeni_deger, secenek_id))
    db.commit()
    cur.close()
    flash("Seçenek güncellendi. (Daha önce kaydedilmiş arıza kayıtlarındaki eski metin değişmeden kalır.)")
    return redirect(url_for("secenek_yonetimi"))


@app.route("/admin/secenek-yonetimi/sil/<int:secenek_id>", methods=["POST"])
@login_required
def secenek_yonetimi_sil(secenek_id):
    db = get_db()
    cur = db.cursor()
    cur.execute("DELETE FROM form_secenegi WHERE id = %s", (secenek_id,))
    db.commit()
    cur.close()
    flash("Seçenek silindi.")
    return redirect(url_for("secenek_yonetimi"))


@app.route("/admin/secenek-yonetimi/sirala", methods=["POST"])
@login_required
def secenek_yonetimi_sirala():
    """Onay Kutusu Ayarları'ndaki sürükle-bırak listesi, bir seçenek
    bırakıldığında bu uca JSON gövde ile {"grup": "...", "sira": [id, id, ...]}
    gönderir — "sira" o grubun TÜM seçeneklerinin yeni (yukarıdan aşağıya)
    id sırasıdır."""
    veri = request.get_json(silent=True) or {}
    grup = veri.get("grup", "")
    sira_listesi = veri.get("sira", [])
    if grup not in FORM_SECENEK_GRUPLARI or not isinstance(sira_listesi, list):
        return jsonify({"hata": "geçersiz istek"}), 400
    db = get_db()
    cur = db.cursor()
    for i, secenek_id in enumerate(sira_listesi):
        try:
            secenek_id = int(secenek_id)
        except (TypeError, ValueError):
            continue
        cur.execute(
            "UPDATE form_secenegi SET sira = %s WHERE id = %s AND grup = %s",
            (i, secenek_id, grup),
        )
    db.commit()
    cur.close()
    return jsonify({"tamam": True})


@app.route("/admin/ozel-alan-ayarlari")
@login_required
def ozel_alan_ayarlari():
    """Abone/Arıza formuna kod yazmadan yeni bir bilgi kutusu (metin/tarih/sayı)
    eklenebildiği ayarlar ekranı — bkz. app.py başındaki _ozel_alan_ekle() ve
    schema.sql'deki ozel_alan tablosu üzerindeki açıklama."""
    db = get_db()
    abone_alanlari = _ozel_alanlari_getir(db, "abone")
    ariza_alanlari = _ozel_alanlari_getir(db, "ariza")
    return render_template(
        "ozel_alan_ayarlari.html",
        abone_sirasi=_form_onizleme_sirasi(ABONE_FORM_ALAN_SIRASI, abone_alanlari),
        ariza_sirasi=_form_onizleme_sirasi(ARIZA_FORM_ALAN_SIRASI, ariza_alanlari),
        tur_etiketleri=_OZEL_ALAN_TUR_ETIKETLERI,
    )


@app.route("/admin/ozel-alan-ayarlari/ekle", methods=["POST"])
@login_required
def ozel_alan_ayarlari_ekle():
    tablo = request.form.get("tablo", "")
    etiket = request.form.get("etiket", "").strip()
    tur = request.form.get("tur", "")
    if tablo not in ("abone", "ariza"):
        flash("Geçersiz tablo.")
        return redirect(url_for("ozel_alan_ayarlari"))
    if not etiket:
        flash("Boş alan adı eklenemez.")
        return redirect(url_for("ozel_alan_ayarlari"))
    if tur not in _OZEL_ALAN_TUR_PG:
        flash("Geçersiz alan türü.")
        return redirect(url_for("ozel_alan_ayarlari"))

    db = get_db()
    _ozel_alan_ekle(db, tablo, etiket, tur)
    flash(f'"{etiket}" alanı eklendi.')
    return redirect(url_for("ozel_alan_ayarlari"))


@app.route("/admin/ozel-alan-ayarlari/sil/<int:ozel_alan_id>", methods=["POST"])
@login_required
def ozel_alan_ayarlari_sil(ozel_alan_id):
    db = get_db()
    _ozel_alan_sil(db, ozel_alan_id)
    flash("Alan kaldırıldı. (Daha önce bu alana girilmiş veriler kaybolmadı, sadece form/listeden gizlendi.)")
    return redirect(url_for("ozel_alan_ayarlari"))


@app.route("/admin/ozel-alan-ayarlari/sirala", methods=["POST"])
@login_required
def ozel_alan_ayarlari_sirala():
    """Özel Alan Ayarları'ndaki sürükle-bırak önizlemesi, bir alan bırakıldığında
    bu uca JSON gövde ile {"tablo": "abone"|"ariza", "sira": [...]} gönderir —
    "sira" o an ekranda görünen TÜM alanların (sabit + özel, karışık) yukarıdan
    aşağıya anahtarlarının listesidir."""
    veri = request.get_json(silent=True) or {}
    tablo = veri.get("tablo", "")
    sira_listesi = veri.get("sira", [])
    if tablo not in ("abone", "ariza") or not isinstance(sira_listesi, list):
        return jsonify({"hata": "geçersiz istek"}), 400
    db = get_db()
    _ozel_alan_sirala(db, tablo, [str(a) for a in sira_listesi])
    return jsonify({"tamam": True})


@app.route("/ariza/yeni", methods=["GET", "POST"])
@login_required
def ariza_yeni():
    if request.method == "POST":
        yeni_id = _ariza_kaydet(None)
        db = get_db()
        _ariza_fotograflarini_kaydet(db, yeni_id, request.files.getlist("fotograflar"))
        return redirect(url_for("ariza_listesi"))
    db = get_db()
    return render_template(
        "ariza_form.html", kayit=None,
        sonraki_s_no=_ariza_sonraki_s_no(db),
        **_ariza_secenek_baglami(db),
        secili_tespit=set(), secili_islem=set(),
        ilk_montaj_tarihi="",
        bugun=datetime.now().strftime("%Y-%m-%d"),
        fotograflar=[],
        ozel_alan_harita=_ozel_alan_harita(_ozel_alanlari_getir(db, "ariza")),
    )


@app.route("/ariza/<int:ariza_id>/duzenle", methods=["GET", "POST"])
@login_required
def ariza_duzenle(ariza_id):
    db = get_db()
    if request.method == "POST":
        _ariza_kaydet(ariza_id)
        _ariza_fotograflarini_kaydet(db, ariza_id, request.files.getlist("fotograflar"))
        flash("Kayıt kaydedildi.")
        return redirect(url_for("ariza_duzenle", ariza_id=ariza_id))
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

    cur = db.cursor()
    cur.execute(
        "SELECT id, dosya_adi, content_type FROM ariza_fotograf WHERE ariza_id = %s ORDER BY id",
        (ariza_id,),
    )
    fotograflar = cur.fetchall()
    cur.close()

    return render_template(
        "ariza_form.html", kayit=kayit,
        **_ariza_secenek_baglami(db),
        secili_tespit=secili_tespit, secili_islem=secili_islem,
        ilk_montaj_tarihi=ilk_montaj_tarihi,
        bugun=datetime.now().strftime("%Y-%m-%d"),
        fotograflar=fotograflar,
        ozel_alan_harita=_ozel_alan_harita(_ozel_alanlari_getir(db, "ariza")),
    )


@app.route("/ariza/<int:ariza_id>/sil", methods=["POST"])
@login_required
def ariza_sil(ariza_id):
    db = get_db()
    cur = db.cursor()
    cur.execute("DELETE FROM ariza WHERE id = %s", (ariza_id,))
    db.commit()
    cur.close()
    _ariza_sira_numaralarini_yenile(db)
    return redirect(url_for("ariza_listesi"))


@app.route("/ariza-fotograf/<int:foto_id>")
@login_required
def ariza_fotograf_goster(foto_id):
    db = get_db()
    cur = db.cursor()
    cur.execute("SELECT content_type, icerik FROM ariza_fotograf WHERE id = %s", (foto_id,))
    foto = cur.fetchone()
    cur.close()
    if foto is None:
        return "Fotoğraf bulunamadı.", 404
    yanit = Response(bytes(foto["icerik"]), mimetype=foto["content_type"] or "application/octet-stream")
    # Tarayıcının, gerçek içerik resim/video olmadığı halde (ör. eski kayıtlarda)
    # dosyayı "koklayıp" (MIME sniffing) HTML/script olarak yorumlamasını engeller —
    # depolanan (stored) XSS riskine karşı ek bir savunma katmanı.
    yanit.headers["X-Content-Type-Options"] = "nosniff"
    return yanit


@app.route("/ariza-fotograf/<int:foto_id>/sil", methods=["POST"])
@login_required
def ariza_fotograf_sil(foto_id):
    db = get_db()
    cur = db.cursor()
    cur.execute("SELECT ariza_id FROM ariza_fotograf WHERE id = %s", (foto_id,))
    foto = cur.fetchone()
    if foto:
        cur.execute("DELETE FROM ariza_fotograf WHERE id = %s", (foto_id,))
        db.commit()
    cur.close()
    if foto:
        return redirect(url_for("ariza_duzenle", ariza_id=foto["ariza_id"]))
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
                    kosul_listesi.append(f"{_turkce_esle_kosul(f'CAST({kolon} AS TEXT)')} LIKE %s")
                    kosul_params.append(_turkce_normallestir(f"%{q}%"))
                else:
                    kosul_listesi.append(f"{_turkce_esle_kosul(kolon)} LIKE %s")
                    kosul_params.append(_turkce_normallestir(f"%{q}%"))
        if kosul_listesi:
            sql += " AND (" + " OR ".join(kosul_listesi) + ")"
            params += kosul_params

    kolon_listesi, kolon_bilgi, sayisal_kolonlar, ozel_alanlar = _ariza_kolon_takimi(db)
    deger_secili = {}
    for anahtar, _ in kolon_listesi:
        secilenler = request.args.getlist(f"deger_{anahtar}")
        deger_secili[anahtar] = secilenler
        if secilenler:
            kosul, param_listesi = _kolon_kosul_coklu(anahtar, secilenler, kolon_bilgi)
            if kosul:
                sql += f" AND {kosul}"
                params += param_listesi
    sql += f" ORDER BY s_no {'DESC' if _sira_yonu_al() == 'desc' else 'ASC'}"

    cur = db.cursor()
    cur.execute(sql, params)
    kayitlar_ham = cur.fetchall()
    cur.execute("SELECT COUNT(*) AS c FROM ariza")
    toplam_kayit = cur.fetchone()["c"]
    cur.close()

    satirlar = [_ariza_satir_sozlugu(k, ozel_alanlar) for k in kayitlar_ham]

    # NOT: bu toplamlar (ücret vb.) her zaman TÜM filtrelenmiş kayıtlar
    # üzerinden hesaplanır — aşağıdaki sayfalama sadece EKRANA basılan satır
    # sayısını sınırlar, bu toplamları etkilemez.
    toplam_ariza_ucreti = sum(float(k["ariza_ucret"] or 0) for k in kayitlar_ham)
    tahsil_edilen_ucret = sum(float(k["alinan_ucret"] or 0) for k in kayitlar_ham)
    kalan_bakiye = toplam_ariza_ucreti - tahsil_edilen_ucret

    # Sütun filtre seçenekleri artık tembel yükleniyor, bkz. abone_listesi().

    satirlar, filtreli_kayit, sayfa, toplam_sayfa = _sayfala(satirlar)

    return render_template(
        "ariza_listesi.html", satirlar=satirlar,
        kolon_listesi=kolon_listesi,
        q=q, secili_alanlar=alanlar_secili, alan_listesi=alan_listesi,
        deger_secili=deger_secili,
        sayisal_kolonlar=sayisal_kolonlar,
        arama_satir=_izgara_satir(len(alan_listesi)),
        arama_satir_2=_izgara_satir(len(alan_listesi), 2),
        filtreli_kayit=filtreli_kayit, toplam_kayit=toplam_kayit,
        toplam_ariza_ucreti=toplam_ariza_ucreti,
        tahsil_edilen_ucret=tahsil_edilen_ucret,
        kalan_bakiye=kalan_bakiye,
        sira=_sira_yonu_al(), sira_toggle_qs=_sira_toggle_qs(),
        sayfa=sayfa, toplam_sayfa=toplam_sayfa, sayfalama_qs=_sayfalama_qs,
    )


def _ariza_ciktisi_satirlar():
    db = get_db()
    kolon_listesi, kolon_bilgi, _sayisal, ozel_alanlar = _ariza_kolon_takimi(db)
    kolonlar_secili = request.args.getlist("kolon")
    goster_kolonlari = kolonlar_secili if kolonlar_secili else [k for k, _ in kolon_listesi]
    sql = "SELECT * FROM ariza WHERE 1=1"
    params = []
    for anahtar in goster_kolonlari:
        secilenler = request.args.getlist(f"deger_{anahtar}")
        if secilenler:
            kosul, param_listesi = _kolon_kosul_coklu(anahtar, secilenler, kolon_bilgi)
            if kosul:
                sql += f" AND {kosul}"
                params += param_listesi
    sql += f" ORDER BY s_no {'DESC' if _sira_yonu_al() == 'desc' else 'ASC'}"
    cur = db.cursor()
    cur.execute(sql, params)
    kayitlar_ham = cur.fetchall()
    cur.close()
    satirlar = [_ariza_satir_sozlugu(k, ozel_alanlar) for k in kayitlar_ham]
    return satirlar, goster_kolonlari, kolon_listesi


@app.route("/ariza-ciktisi")
@login_required
def ariza_ciktisi():
    yonlendirme = _filtre_durumu_uygula("ariza_ciktisi")
    if yonlendirme:
        return yonlendirme

    satirlar, goster_kolonlari, kolon_listesi = _ariza_ciktisi_satirlar()
    kolonlar_secili = request.args.getlist("kolon")
    db = get_db()

    kolon_secim_listesi = ARIZA_DISPLAY_KOLONLARI_ALFABETIK + [
        (k, e) for k, e in kolon_listesi if k not in _ARIZA_DISPLAY_KOLON_HARITASI
    ]
    _kl, _kb, sayisal_kolonlar, _ozel = _ariza_kolon_takimi(db)

    deger_secili = {}
    for anahtar in goster_kolonlari:
        deger_secili[anahtar] = request.args.getlist(f"deger_{anahtar}")

    # Sütun filtre seçenekleri artık tembel yükleniyor, bkz. abone_listesi().
    cur = db.cursor()
    cur.execute("SELECT COUNT(*) AS c FROM ariza")
    toplam_kayit = cur.fetchone()["c"]
    cur.close()

    # Excel çıktısı (ariza_ciktisi_excel) TÜM satırları kullanmaya devam
    # ediyor — sadece bu HTML görünümü sayfalanıyor.
    satirlar, filtreli_kayit, sayfa, toplam_sayfa = _sayfala(satirlar)

    return render_template(
        "ariza_ciktisi.html",
        satirlar=satirlar,
        kolon_listesi=kolon_listesi, goster_kolonlari=goster_kolonlari,
        kolon_secim_listesi=kolon_secim_listesi,
        secili_kolonlar=kolonlar_secili,
        deger_secili=deger_secili,
        sayisal_kolonlar=sayisal_kolonlar,
        kolon_satir=_izgara_satir(len(kolon_secim_listesi)),
        kolon_satir_2=_izgara_satir(len(kolon_secim_listesi), 2),
        filtreli_kayit=filtreli_kayit, toplam_kayit=toplam_kayit,
        sira=_sira_yonu_al(), sira_toggle_qs=_sira_toggle_qs(),
        sayfa=sayfa, toplam_sayfa=toplam_sayfa, sayfalama_qs=_sayfalama_qs,
        tumunu_goster_qs=_tumunu_goster_qs(),
    )


@app.route("/ariza-ciktisi-excel")
@login_required
def ariza_ciktisi_excel():
    satirlar, goster_kolonlari, kolon_listesi = _ariza_ciktisi_satirlar()
    tarih = datetime.now().strftime("%d_%m_%Y")
    return _csv_olustur(kolon_listesi, goster_kolonlari, satirlar, f"ariza_ciktisi_{tarih}.csv")


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


@app.route("/admin/toplu-abone-yukle", methods=["GET", "POST"])
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

    # Bu işlem veritabanına toplu kayıt ekliyor — bu yüzden SADECE POST (gerçek
    # bir <form> gönderimiyle, CSRF token doğrulamasından geçerek) tetiklenebilir.
    # Eskiden bir GET linkine (?onayla=1) tıklamak yeterliydi; bu, oturumu açık
    # birine gönderilen sahte bir linkin (ör. e-postadaki gizli bir <img>) fark
    # ettirmeden binlerce kaydı tekrar eklemesine (CSRF) izin verebilirdi.
    onay = request.method == "POST" and request.form.get("onayla") == "1"
    zorla = request.method == "POST" and request.form.get("zorla") == "1"
    _csrf_gizli_alan = f'<input type="hidden" name="csrf_token" value="{generate_csrf()}">'

    if not onay:
        if mevcut_sayi > 50:
            aksiyon = (
                f"<p style='color:#b00;font-weight:bold'>Dikkat: tabloda hâlihazırda {mevcut_sayi} kayıt var. "
                f"Bu işlem mevcut kayıtları SİLMEZ, üzerine {len(satirlar)} yeni kayıt EKLER. "
                f"Bu veriyi daha önce yüklediyseniz tekrar yüklemeyin, kayıtlar çiftlenir.</p>"
                f"<form method='post'>{_csrf_gizli_alan}"
                f"<input type='hidden' name='onayla' value='1'><input type='hidden' name='zorla' value='1'>"
                f"<button type='submit' style='font-size:20px;color:#b00;background:none;border:none;"
                f"text-decoration:underline;cursor:pointer;padding:0;'>"
                f"Yine de devam et ve {len(satirlar)} kaydı ekle</button></form>"
            )
        else:
            aksiyon = (
                f"<form method='post'>{_csrf_gizli_alan}"
                f"<input type='hidden' name='onayla' value='1'>"
                f"<button type='submit' style='font-size:20px;background:none;border:none;"
                f"text-decoration:underline;cursor:pointer;padding:0;'>"
                f"Evet, {len(satirlar)} kaydı içe aktar</button></form>"
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


@app.route("/admin/toplu-ariza-yukle", methods=["GET", "POST"])
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

    # bkz. toplu_abone_yukle() içindeki aynı konudaki not — SADECE POST (CSRF
    # token doğrulamasıyla) tetiklenebilir, artık bir GET linkine tıklamak
    # yeterli değil.
    onay = request.method == "POST" and request.form.get("onayla") == "1"
    zorla = request.method == "POST" and request.form.get("zorla") == "1"
    _csrf_gizli_alan = f'<input type="hidden" name="csrf_token" value="{generate_csrf()}">'

    if not onay:
        if mevcut_sayi > 50:
            aksiyon = (
                f"<p style='color:#b00;font-weight:bold'>Dikkat: tabloda hâlihazırda {mevcut_sayi} kayıt var. "
                f"Bu işlem mevcut kayıtları SİLMEZ, üzerine {len(satirlar)} yeni kayıt EKLER. "
                f"Bu veriyi daha önce yüklediyseniz tekrar yüklemeyin, kayıtlar çiftlenir.</p>"
                f"<form method='post'>{_csrf_gizli_alan}"
                f"<input type='hidden' name='onayla' value='1'><input type='hidden' name='zorla' value='1'>"
                f"<button type='submit' style='font-size:20px;color:#b00;background:none;border:none;"
                f"text-decoration:underline;cursor:pointer;padding:0;'>"
                f"Yine de devam et ve {len(satirlar)} kaydı ekle</button></form>"
            )
        else:
            aksiyon = (
                f"<form method='post'>{_csrf_gizli_alan}"
                f"<input type='hidden' name='onayla' value='1'>"
                f"<button type='submit' style='font-size:20px;background:none;border:none;"
                f"text-decoration:underline;cursor:pointer;padding:0;'>"
                f"Evet, {len(satirlar)} kaydı içe aktar</button></form>"
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


@app.route("/admin/tarih-formati-duzelt", methods=["GET", "POST"])
@login_required
def tarih_formati_duzelt():
    # bkz. toplu_abone_yukle() içindeki aynı konudaki not — SADECE POST (CSRF
    # token doğrulamasıyla) tetiklenebilir.
    onay = request.method == "POST" and request.form.get("onayla") == "1"
    db = get_db()
    cur = db.cursor()

    hedefler = [
        ("abone", ["montaj_tarihi", "odeme_tarihi", "odeme_gun_sozu"]),
        ("ariza", ["gelis_tarihi", "takilan_tarih", "teslim_tarihi"]),
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
        <form method="post">
        <input type="hidden" name="csrf_token" value="{generate_csrf()}">
        <input type="hidden" name="onayla" value="1">
        <button type="submit" style="font-size:20px;background:none;border:none;text-decoration:underline;cursor:pointer;padding:0;">
        Evet, {len(bulunanlar)} tarihi düzelt</button>
        </form>
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
    # ÖNEMLİ: debug=True asla canlı ortamda (production) kullanılmamalı — hem
    # güvenlik açığıdır (herkese açık, kod çalıştırabilen Werkzeug hata ayıklayıcısı)
    # hem de Flask'ın tek-iş-parçacıklı (single-threaded) geliştirme sunucusunu
    # zorunlu kılar, bu da aynı anda birden fazla kullanıcı/sekme kullanıldığında
    # sayfalar arası geçişin gittikçe yavaşlamasına yol açar. FLASK_DEBUG ortam
    # değişkeni ayarlanmadığı sürece (yani normal/canlı çalıştırmada) artık
    # False'tur; sadece yerelde bilerek FLASK_DEBUG=1 verilirse eski davranış
    # (otomatik yeniden yükleme + hata ayıklayıcı) geri gelir.
    debug_modu = os.environ.get("FLASK_DEBUG", "0") == "1"
    app.run(host="0.0.0.0", port=port, debug=debug_modu)
