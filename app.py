import os
from functools import wraps

import psycopg2
import psycopg2.extras
from flask import (
    Flask, render_template, request, redirect,
    url_for, session, g, flash, jsonify
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


DISPLAY_KOLONLARI = [
    ("s_no", "S.No"),
    ("koy_adi", "Köy"),
    ("ad_soyad", "Adı Soyadı"),
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
    "ad_soyad": ("(adi || ' ' || soyadi)", "metin"),
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
    ("ariza_ucret", "Arıza Ücret"),
    ("alinan_ucret", "Alınan Ücret"),
    ("kalan_ucret", "Kalan Ücret"),
    ("gelis_tarihi", "Geliş Tarihi"),
    ("takilan_tarih", "Takılan Tarih"),
    ("sayac_kredisi", "Sayaç Kredisi"),
    ("tespit_edilen_ariza", "Tespit Edilen Arıza"),
    ("yapilan_islemler", "Yapılan İşlemler"),
]

ARIZA_KOLON_BILGI = {
    "s_no": ("s_no", "sayi"),
    "ozel_s_no": ("ozel_s_no", "metin"),
    "koy_adi": ("koy_adi", "metin"),
    "yeni_seri_no": ("yeni_seri_no", "metin"),
    "seri_no": ("seri_no", "metin"),
    "adi": ("adi", "metin"),
    "soyadi": ("soyadi", "metin"),
    "ariza_ucret": ("ariza_ucret", "sayi"),
    "alinan_ucret": ("alinan_ucret", "sayi"),
    "kalan_ucret": ("(ariza_ucret - alinan_ucret)", "sayi"),
    "gelis_tarihi": ("gelis_tarihi", "tarih"),
    "takilan_tarih": ("takilan_tarih", "tarih"),
    "sayac_kredisi": ("sayac_kredisi", "metin"),
    "tespit_edilen_ariza": ("tespit_edilen_ariza", "metin"),
    "yapilan_islemler": ("yapilan_islemler", "metin"),
}

ARIZA_SAYISAL_KOLONLAR = {k for k, (_, tur) in ARIZA_KOLON_BILGI.items() if tur == "sayi"}

TESPIT_EDILEN_ARIZA_SECENEKLERI = [
    "Ekran Yok", "Mekanik Patlak", "Dijital Su Almış", "Pil Bitik", "Pil Zayıf",
    "Motor Oksitli", "Sıkıntı Yok", "Motor Switch Arızalı", "Error 1", "Error 2",
    "Error 3", "Error 4", "Error 5", "Arıza Simgesi", "Harcama Uyuşmuyor",
    "Magnet", "Data", "Küre Dönmüyor", "Küre Zor Dönüyor", "Küre Paslı",
    "Harcama Yapmıyor", "Kondansatör Yok", "Kondansatör Devre Dışı",
]

YAPILAN_ISLEMLER_SECENEKLERI = [
    "Pil Takıldı", "Motor Değişti", "Kart Değişti", "Kart Ekran Değişti",
    "Kart Okuyucu Değişti", "Mekanik Değişti", "Mekanik Patlak Tamir",
    "Sayım Aparatı Değişti", "Motor Switch Değişti", "Formatlandı", "Resetlendi",
    "Mekanik Pervane Değişti", "Küre Değişti", "Küre Temizlendi",
    "Kondansatör Takıldı", "Kondansatör Devreye Alındı", "Kart Temizlendi",
    "Motor Tamir Edildi",
]


def _gg_aa_yyyy(t):
    if t and len(t) >= 10:
        return t[8:10] + "." + t[5:7] + "." + t[0:4]
    return t or ""


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
        "ad_soyad": f"{k['adi']} {k['soyadi']}",
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
        "telefon": k["telefon"],
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
        "fatura_no": k["fatura_no"],
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
        "ariza_ucret": tl_format(k["ariza_ucret"]),
        "alinan_ucret": tl_format(k["alinan_ucret"]),
        "kalan_ucret": tl_format(kalan_ucret),
        "gelis_tarihi": _gg_aa_yyyy(k["gelis_tarihi"]),
        "takilan_tarih": _gg_aa_yyyy(k["takilan_tarih"]),
        "sayac_kredisi": k["sayac_kredisi"],
        "tespit_edilen_ariza": k["tespit_edilen_ariza"],
        "yapilan_islemler": k["yapilan_islemler"],
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


@app.route("/api/abone-ara")
@login_required
def abone_ara():
    sayac_no = request.args.get("sayac_no", "").strip()
    if not sayac_no:
        return jsonify({"bulundu": False})
    db = get_db()
    cur = db.cursor()
    cur.execute("SELECT adi, soyadi FROM abone WHERE sayac_no = %s LIMIT 1", (sayac_no,))
    satir = cur.fetchone()
    cur.close()
    if satir:
        return jsonify({"bulundu": True, "adi": satir["adi"], "soyadi": satir["soyadi"]})
    return jsonify({"bulundu": False})


@app.route("/abone")
@login_required
def abone_listesi():
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
                    kosul_listesi.append(f"CAST({kolon} AS TEXT) LIKE %s")
                    kosul_params.append(f"%{q}%")
                else:
                    kosul_listesi.append(f"{kolon} LIKE %s")
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

    satirlar = [_abone_satir_sozlugu(k) for k in kayitlar_ham]

    deger_secenekleri = {}
    for anahtar, _ in DISPLAY_KOLONLARI:
        deger_secenekleri[anahtar] = _kolon_secenekleri(db, anahtar, "abone", KOLON_BILGI)
    cur.close()

    return render_template(
        "abone_list.html", satirlar=satirlar, koyler=koyler, q=q, secili_koy=koy,
        secili_alanlar=alanlar_secili, alan_listesi=alan_listesi,
        kolon_listesi=DISPLAY_KOLONLARI, deger_secili=deger_secili,
        deger_secenekleri=deger_secenekleri, sayisal_kolonlar=SAYISAL_KOLONLAR
    )


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
    if request.method == "POST":
        _abone_kaydet(abone_id)
        return redirect(url_for("abone_listesi"))
    cur = db.cursor()
    cur.execute("SELECT * FROM abone WHERE id = %s", (abone_id,))
    kayit = cur.fetchone()
    cur.close()
    if kayit is None:
        flash("Kayıt bulunamadı.")
        return redirect(url_for("abone_listesi"))
    return render_template("abone_form.html", kayit=kayit)


@app.route("/abone/<int:abone_id>/sil", methods=["POST"])
@login_required
def abone_sil(abone_id):
    db = get_db()
    cur = db.cursor()
    cur.execute("DELETE FROM abone WHERE id = %s", (abone_id,))
    db.commit()
    cur.close()
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
        telefon=f.get("telefon", "").strip(),
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
        return redirect(url_for("abone_tahsilat", abone_id=abone_id))

    cur.execute("SELECT * FROM abone WHERE id = %s", (abone_id,))
    abone = cur.fetchone()
    if abone is None:
        cur.close()
        flash("Kayıt bulunamadı.")
        return redirect(url_for("abone_listesi"))

    cur.execute("SELECT * FROM tahsilat WHERE abone_id = %s ORDER BY tarih DESC, id DESC", (abone_id,))
    tahsilatlar = cur.fetchall()
    cur.close()

    return render_template("abone_tahsilat.html", abone=abone, tahsilatlar=tahsilatlar)


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
    genel["firma_asil_alacagi"] = genel["kalan_tutar"] - genel["muhtara_odenecek"]

    return render_template(
        "tahsilat.html", satirlar=satirlar, genel=genel,
        kolon_listesi=KOY_KOLONLARI, deger_secili=deger_secili,
        deger_secenekleri=deger_secenekleri,
    )


@app.route("/tahsilat-ciktisi")
@login_required
def tahsilat_ciktisi():
    kolonlar_secili = request.args.getlist("kolon")
    goster_kolonlari = kolonlar_secili if kolonlar_secili else [k for k, _ in DISPLAY_KOLONLARI]

    db = get_db()

    deger_secili = {}
    sql = "SELECT * FROM abone WHERE 1=1"
    params = []
    for anahtar in goster_kolonlari:
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
    cur.close()

    satirlar = [_abone_satir_sozlugu(k) for k in kayitlar_ham]

    deger_secenekleri = {}
    for anahtar in goster_kolonlari:
        deger_secenekleri[anahtar] = _kolon_secenekleri(db, anahtar, "abone", KOLON_BILGI)

    return render_template(
        "tahsilat_ciktisi.html",
        satirlar=satirlar,
        kolon_listesi=DISPLAY_KOLONLARI, goster_kolonlari=goster_kolonlari,
        secili_kolonlar=kolonlar_secili,
        deger_secili=deger_secili, deger_secenekleri=deger_secenekleri,
        sayisal_kolonlar=SAYISAL_KOLONLAR,
    )


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
        ariza_ucret=ariza_ucret,
        alinan_ucret=alinan_ucret,
        gelis_tarihi=f.get("gelis_tarihi", "").strip(),
        takilan_tarih=f.get("takilan_tarih", "").strip(),
        sayac_kredisi=f.get("sayac_kredisi", "").strip(),
        tespit_edilen_ariza=tespit_metni,
        yapilan_islemler=islem_metni,
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
    return render_template(
        "ariza_form.html", kayit=kayit,
        tespit_secenekleri=TESPIT_EDILEN_ARIZA_SECENEKLERI,
        islem_secenekleri=YAPILAN_ISLEMLER_SECENEKLERI,
        secili_tespit=secili_tespit, secili_islem=secili_islem,
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
    db = get_db()
    sql = "SELECT * FROM ariza WHERE 1=1"
    params = []
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
    cur.close()

    satirlar = [_ariza_satir_sozlugu(k) for k in kayitlar_ham]

    deger_secenekleri = {}
    for anahtar, _ in ARIZA_DISPLAY_KOLONLARI:
        deger_secenekleri[anahtar] = _kolon_secenekleri(db, anahtar, "ariza", ARIZA_KOLON_BILGI)

    return render_template(
        "ariza_listesi.html", satirlar=satirlar,
        kolon_listesi=ARIZA_DISPLAY_KOLONLARI,
        deger_secili=deger_secili, deger_secenekleri=deger_secenekleri,
        sayisal_kolonlar=ARIZA_SAYISAL_KOLONLAR,
    )


@app.route("/ariza-ciktisi")
@login_required
def ariza_ciktisi():
    kolonlar_secili = request.args.getlist("kolon")
    goster_kolonlari = kolonlar_secili if kolonlar_secili else [k for k, _ in ARIZA_DISPLAY_KOLONLARI]

    db = get_db()

    deger_secili = {}
    sql = "SELECT * FROM ariza WHERE 1=1"
    params = []
    for anahtar in goster_kolonlari:
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
    cur.close()

    satirlar = [_ariza_satir_sozlugu(k) for k in kayitlar_ham]

    deger_secenekleri = {}
    for anahtar in goster_kolonlari:
        deger_secenekleri[anahtar] = _kolon_secenekleri(db, anahtar, "ariza", ARIZA_KOLON_BILGI)

    return render_template(
        "ariza_ciktisi.html",
        satirlar=satirlar,
        kolon_listesi=ARIZA_DISPLAY_KOLONLARI, goster_kolonlari=goster_kolonlari,
        secili_kolonlar=kolonlar_secili,
        deger_secili=deger_secili, deger_secenekleri=deger_secenekleri,
        sayisal_kolonlar=ARIZA_SAYISAL_KOLONLAR,
    )


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=True)
