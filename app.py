import os
from functools import wraps

import psycopg2
import psycopg2.extras
from flask import (
    Flask, render_template, request, redirect,
    url_for, session, g, flash
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


# ---------- Veritabanı yardımcıları ----------

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


# ---------- Giriş / Çıkış ----------

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        kullanici_adi = request.form.get("kullanici_adi", "").strip()
        sifre = request.form.get("sifre", "")

        db = get_db()
        cur = db.cursor()
        cur.execute(
            "SELECT * FROM kullanici WHERE kullanici_adi = %s", (kullanici_adi,)
        )
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


# ---------- Abone Listesi ----------

@app.route("/")
@login_required
def index():
    return redirect(url_for("abone_listesi"))


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
    sql += " ORDER BY s_no"

    cur = db.cursor()
    cur.execute(sql, params)
    kayitlar = cur.fetchall()
    cur.execute("SELECT DISTINCT koy_adi FROM abone ORDER BY koy_adi")
    koyler = cur.fetchall()
    cur.close()

    return render_template(
        "abone_list.html", kayitlar=kayitlar, koyler=koyler, q=q, secili_koy=koy,
        secili_alanlar=alanlar_secili, alan_listesi=alan_listesi
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
    cur.execute(
        "SELECT senet_no FROM abone WHERE senet_no IS NOT NULL AND senet_no != ''"
    )
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


# ---------- Tahsilat (sonradan / farklı tarihli tahsilatlar) ----------

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
            cur.execute(
                f"UPDATE abone SET {kolon} = {kolon} + %s WHERE id = %s",
                (tutar, abone_id),
            )
            db.commit()

        cur.close()
        return redirect(url_for("abone_tahsilat", abone_id=abone_id))

    cur.execute("SELECT * FROM abone WHERE id = %s", (abone_id,))
    abone = cur.fetchone()
    if abone is None:
        cur.close()
        flash("Kayıt bulunamadı.")
        return redirect(url_for("abone_listesi"))

    cur.execute(
        "SELECT * FROM tahsilat WHERE abone_id = %s ORDER BY tarih DESC, id DESC",
        (abone_id,),
    )
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
        cur.execute(
            f"UPDATE abone SET {kolon} = {kolon} - %s WHERE id = %s",
            (kayit["tutar"], abone_id),
        )
        cur.execute("DELETE FROM tahsilat WHERE id = %s", (tahsilat_id,))
        db.commit()
    cur.close()
    if abone_id:
        return redirect(url_for("abone_tahsilat", abone_id=abone_id))
    return redirect(url_for("abone_listesi"))


# ---------- Tahsilat (köy bazlı özet) ----------

@app.route("/tahsilat")
@login_required
def tahsilat():
    db = get_db()
    cur = db.cursor()
    cur.execute(
        "SELECT koy_adi, SUM(sayac_tutari) AS sayac_tutari_toplami, SUM(malzeme_tutari) AS malzeme_tutari_toplami, SUM(sayac_tutari + malzeme_tutari) AS genel_satis_tutari, SUM(alinan_tutar + malzeme_alinan) AS tahsil_edilen_tutar, SUM(sayac_tutari + malzeme_tutari - alinan_tutar - malzeme_alinan) AS kalan_tutar, SUM(muhtara_odenecek) AS muhtara_odenecek, SUM(muhtara_odenen) AS muhtara_odenen, SUM(muhtara_odenecek - muhtara_odenen) AS muhtara_kalan FROM abone GROUP BY koy_adi ORDER BY koy_adi"
    )
    satirlar = cur.fetchall()
    cur.close()

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

    return render_template("tahsilat.html", satirlar=satirlar, genel=genel)


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=True)
