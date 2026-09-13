"""ALGI BİLİŞİM — Masaüstü (Windows) sürümü için YEREL VERİTABANI katmanı.

Sunucu sürümü PostgreSQL kullanır. Masaüstü sürümünün internetsiz çalışması
gerektiği için burada, bilgisayarda tek bir dosyada duran SQLite veritabanı
kullanılır.

Bu modül, app.py'nin PostgreSQL'e göre yazılmış kodunu DEĞİŞTİRMEDEN
çalıştırabilmek için psycopg2 kütüphanesinin kullanılan kısımlarını taklit
eder (connect, cursor, extras.RealDictCursor, pool.ThreadedConnectionPool,
Binary). Böylece program mantığı tek bir yerde kalır: sunucuda da masaüstünde
de aynı app.py çalışır.

Yapılan çeviriler:
  * Sorgu yer tutucuları:  %s          -> ?
  * ILIKE                              -> LIKE   (SQLite'ta LIKE zaten
                                          büyük/küçük harf ayırmaz)
  * TRANSLATE(...)                     -> Python'da tanımlanan aynı isimli
                                          fonksiyon (Türkçe harf eşleme için)
  * NOW() / CURRENT_TIMESTAMP          -> SQLite'ın kendi zaman damgası
  * Şema tipleri: SERIAL -> INTEGER PRIMARY KEY AUTOINCREMENT,
    BYTEA -> BLOB, DOUBLE PRECISION -> REAL, TIMESTAMP DEFAULT NOW() -> ...
  * ALTER TABLE ... ADD COLUMN IF NOT EXISTS  -> SQLite'ta karşılığı olmadığı
    için kolon zaten varsa sessizce atlanır.
"""

import datetime
import os
import re
import sqlite3
import threading

# psycopg2 ile aynı isimde hata sınıfları (app.py bunları yakalıyor).
Error = sqlite3.Error
DatabaseError = sqlite3.DatabaseError
IntegrityError = sqlite3.IntegrityError
OperationalError = sqlite3.OperationalError
ProgrammingError = sqlite3.ProgrammingError
DataError = sqlite3.DataError
InternalError = sqlite3.InternalError
NotSupportedError = sqlite3.NotSupportedError


def _zaman_cozumle(ham):
    """TIMESTAMP sütunlarını datetime'a çevirir. PostgreSQL yedeğinden gelen
    "2026-09-11T20:54:49.337611" ve SQLite'ın kendi yazdığı
    "2026-09-11 20:54:49" biçimlerinin ikisini de anlar."""
    metin = ham.decode("utf-8", "replace").strip() if isinstance(ham, bytes) else str(ham).strip()
    if not metin:
        return None
    try:
        return datetime.datetime.fromisoformat(metin.replace(" ", "T", 1))
    except ValueError:
        return metin


def _tarih_cozumle(ham):
    metin = ham.decode("utf-8", "replace").strip() if isinstance(ham, bytes) else str(ham).strip()
    if not metin:
        return None
    try:
        return datetime.date.fromisoformat(metin[:10])
    except ValueError:
        return metin


sqlite3.register_converter("TIMESTAMP", _zaman_cozumle)
sqlite3.register_converter("DATE", _tarih_cozumle)
sqlite3.register_adapter(datetime.datetime, lambda d: d.isoformat(sep=" "))
sqlite3.register_adapter(datetime.date, lambda d: d.isoformat())


def Binary(deger):
    """psycopg2.Binary karşılığı — SQLite baytları olduğu gibi saklar."""
    if deger is None:
        return None
    return sqlite3.Binary(deger)


# --------------------------------------------------------------------------
# Satır nesnesi
# --------------------------------------------------------------------------
class Satir(dict):
    """Sorgu sonucundaki bir satır.

    app.py satırlara hem isimle (satir["adi"]), hem sırayla (satir[0]), hem de
    satir.get("adi") şeklinde eriştiği için üçünü de destekler.
    """

    __slots__ = ("_sutunlar",)

    def __init__(self, sutunlar, degerler):
        super().__init__(zip(sutunlar, degerler))
        self._sutunlar = sutunlar

    def __getitem__(self, anahtar):
        if isinstance(anahtar, int):
            return super().__getitem__(self._sutunlar[anahtar])
        if isinstance(anahtar, slice):
            return [super(Satir, self).__getitem__(s) for s in self._sutunlar[anahtar]]
        return super().__getitem__(anahtar)


# --------------------------------------------------------------------------
# SQL çevirisi
# --------------------------------------------------------------------------
# Sorgu içindeki tek tırnaklı metinleri koruyup geri kalanı çevirmek için.
_METIN_KALIBI = re.compile(r"'(?:[^']|'')*'")


def _metin_disini_degistir(sql, degistirici):
    """Sorgudaki tırnak içi metinlere DOKUNMADAN, geri kalanına `degistirici`
    fonksiyonunu uygular (örn. 'Ali %s' gibi bir metin bozulmasın diye)."""
    parcalar = []
    son = 0
    for m in _METIN_KALIBI.finditer(sql):
        parcalar.append(degistirici(sql[son:m.start()]))
        parcalar.append(m.group(0))
        son = m.end()
    parcalar.append(degistirici(sql[son:]))
    return "".join(parcalar)


_ILIKE = re.compile(r"\bILIKE\b", re.IGNORECASE)
_NOW = re.compile(r"\bNOW\s*\(\s*\)", re.IGNORECASE)

# PostgreSQL "UPDATE tablo t SET ..." yazımına izin verir; SQLite takma ad
# için "AS" ister: "UPDATE tablo AS t SET ...". Aynı şekilde UPDATE ... FROM
# içindeki alt sorgu takma adı da "AS" ile yazılır.
_UPDATE_TAKMA_AD = re.compile(
    r"\bUPDATE\s+(\w+)\s+(?!SET\b|AS\b)(\w+)\s+SET\b", re.IGNORECASE)
_ALT_SORGU_TAKMA_AD = re.compile(
    r"\)\s+(?!AS\b|WHERE\b|ON\b|AND\b|OR\b|GROUP\b|ORDER\b|LIMIT\b|"
    r"UNION\b|HAVING\b|SET\b|FROM\b|JOIN\b|WHEN\b|THEN\b|ELSE\b|END\b)"
    r"([a-zA-Z_]\w*)\s+WHERE\b", re.IGNORECASE)


# PostgreSQL tip dönüşümleri: '...'::timestamp, '\x41'::bytea gibi. SQLite'ta
# karşılığı yok; yedek dosyasından veri aktarırken bunlarla karşılaşılır.
_BYTEA_CAST = re.compile(r"'\\\\x([0-9a-fA-F]*)'::bytea", re.IGNORECASE)
_TIP_CAST = re.compile(r"::\s*\w+(\s*\[\s*\])?")


def _sorgu_cevir(sql):
    """Tek bir sorguyu PostgreSQL yazımından SQLite yazımına çevirir."""
    if "::" in sql:
        sql = _BYTEA_CAST.sub(lambda m: "X'" + m.group(1) + "'", sql)
        sql = _metin_disini_degistir(sql, lambda p: _TIP_CAST.sub("", p))

    def duzelt(parca):
        parca = parca.replace("%s", "?")
        parca = _ILIKE.sub("LIKE", parca)
        parca = _NOW.sub("CURRENT_TIMESTAMP", parca)
        return parca

    cevrilmis = _metin_disini_degistir(sql, duzelt)
    if _UPDATE_TAKMA_AD.search(cevrilmis):
        cevrilmis = _UPDATE_TAKMA_AD.sub(r"UPDATE \1 AS \2 SET", cevrilmis)
        cevrilmis = _ALT_SORGU_TAKMA_AD.sub(r") AS \1 WHERE", cevrilmis)
    return cevrilmis


# Şema (CREATE TABLE) çevirileri
_SEMA_CEVIRILERI = [
    (re.compile(r"\bBIGSERIAL\s+PRIMARY\s+KEY\b", re.I), "INTEGER PRIMARY KEY AUTOINCREMENT"),
    (re.compile(r"\bSERIAL\s+PRIMARY\s+KEY\b", re.I), "INTEGER PRIMARY KEY AUTOINCREMENT"),
    (re.compile(r"\bBIGSERIAL\b", re.I), "INTEGER"),
    (re.compile(r"\bSERIAL\b", re.I), "INTEGER"),
    (re.compile(r"\bBYTEA\b", re.I), "BLOB"),
    (re.compile(r"\bDOUBLE\s+PRECISION\b", re.I), "REAL"),
    (re.compile(r"\bTIMESTAMPTZ\b", re.I), "TIMESTAMP"),
    (re.compile(r"\bTIMESTAMP\s+WITH\s+TIME\s+ZONE\b", re.I), "TIMESTAMP"),
]


def _sema_cevir(sql):
    """CREATE TABLE / ALTER TABLE gibi şema ifadelerini SQLite'a çevirir."""
    def duzelt(parca):
        for kalip, yeni in _SEMA_CEVIRILERI:
            parca = kalip.sub(yeni, parca)
        parca = _NOW.sub("CURRENT_TIMESTAMP", parca)
        return parca

    return _metin_disini_degistir(sql, duzelt)


def _ifadelere_ayir(betik):
    """Bir SQL betiğini, tırnak içi noktalı virgülleri atlayarak ifadelere
    böler (schema.sql tek seferde çalıştırılamaz, çünkü SQLite'ta
    ADD COLUMN IF NOT EXISTS gibi ifadeleri tek tek ele almamız gerekiyor)."""
    ifadeler = []
    tampon = []
    tirnak = False
    i = 0
    while i < len(betik):
        ch = betik[i]
        if ch == "'":
            # '' (kaçışlı tırnak) tek bir karakter gibi ele alınır
            if tirnak and i + 1 < len(betik) and betik[i + 1] == "'":
                tampon.append("''")
                i += 2
                continue
            tirnak = not tirnak
            tampon.append(ch)
        elif ch == "-" and not tirnak and betik[i:i + 2] == "--":
            # satır sonuna kadar yorum
            son = betik.find("\n", i)
            i = len(betik) if son == -1 else son
            continue
        elif ch == ";" and not tirnak:
            ifade = "".join(tampon).strip()
            if ifade:
                ifadeler.append(ifade)
            tampon = []
        else:
            tampon.append(ch)
        i += 1
    kalan = "".join(tampon).strip()
    if kalan:
        ifadeler.append(kalan)
    return ifadeler


_ADD_COLUMN = re.compile(
    r"ALTER\s+TABLE\s+(\w+)\s+ADD\s+COLUMN\s+(?:IF\s+NOT\s+EXISTS\s+)?(\w+)\s+(.+)",
    re.IGNORECASE | re.DOTALL,
)

# PostgreSQL'de sonradan gevşetilen kısıtlar:
#   ALTER TABLE t ALTER COLUMN c DROP NOT NULL / DROP DEFAULT
# SQLite'ta böyle bir komut yok. Bunun yerine betik önce baştan sona okunur,
# bu kısıtları kaldırılan sütunlar tespit edilir ve o sütunlar ZATEN
# oluşturulurken kısıtsız oluşturulur — sonuç aynı olur.
_ALTER_COLUMN = re.compile(
    r"ALTER\s+TABLE\s+(\w+)\s+ALTER\s+(?:COLUMN\s+)?(\w+)\s+DROP\s+(NOT\s+NULL|DEFAULT)",
    re.IGNORECASE,
)
_CREATE_TABLE = re.compile(r"CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?(\w+)", re.IGNORECASE)
_NOT_NULL = re.compile(r"\s+NOT\s+NULL\b", re.IGNORECASE)
_DEFAULT = re.compile(r"\s+DEFAULT\s+(?:'(?:[^']|'')*'|[\w.()]+)", re.IGNORECASE)


def _kisit_kaldir(tanim, not_null, varsayilan):
    """Bir sütun tanımından NOT NULL ve/veya DEFAULT kısmını siler."""
    if not_null:
        tanim = _NOT_NULL.sub("", tanim)
    if varsayilan:
        tanim = _DEFAULT.sub("", tanim)
    return tanim.strip()


def _create_table_gevset(ifade, tablo, gevsetilecek):
    """CREATE TABLE ifadesindeki belirli sütunların kısıtlarını kaldırır."""
    satirlar = ifade.split("\n")
    for i, satir in enumerate(satirlar):
        m = re.match(r"(\s*)(\w+)(\s+.*)", satir)
        if not m:
            continue
        anahtar = (tablo.lower(), m.group(2).lower())
        if anahtar not in gevsetilecek:
            continue
        not_null, varsayilan = gevsetilecek[anahtar]
        sonda_virgul = satir.rstrip().endswith(",")
        govde = _kisit_kaldir(m.group(3).rstrip().rstrip(","), not_null, varsayilan)
        satirlar[i] = m.group(1) + m.group(2) + " " + govde + ("," if sonda_virgul else "")
    return "\n".join(satirlar)


# --------------------------------------------------------------------------
# Türkçe harf eşlemesi (PostgreSQL'in TRANSLATE fonksiyonunun karşılığı)
# --------------------------------------------------------------------------
def _translate(metin, kaynak, hedef):
    if metin is None:
        return None
    metin = str(metin)
    esleme = {}
    for i, ch in enumerate(str(kaynak)):
        esleme[ch] = str(hedef)[i] if i < len(str(hedef)) else ""
    return "".join(esleme.get(ch, ch) for ch in metin)


def _lower_tr(metin):
    """SQLite'ın kendi LOWER'ı yalnızca ASCII harfleri küçültür; Türkçe
    harfler için Python'un küçültmesi kullanılır."""
    return None if metin is None else str(metin).lower()


def _upper_tr(metin):
    return None if metin is None else str(metin).upper()


def _sql_degeri(deger):
    """Bir Python değerini SQL metnine çevirir (yedek dosyası üretmek için)."""
    if deger is None:
        return "NULL"
    if isinstance(deger, bool):
        return "TRUE" if deger else "FALSE"
    if isinstance(deger, (int, float)):
        return repr(deger)
    if isinstance(deger, (bytes, bytearray, memoryview)):
        return "'\\x" + bytes(deger).hex() + "'"
    if isinstance(deger, (tuple, list)):
        return "(" + ", ".join(_sql_degeri(d) for d in deger) + ")"
    return "'" + str(deger).replace("'", "''") + "'"


# --------------------------------------------------------------------------
# İmleç (cursor)
# --------------------------------------------------------------------------
class Imlec:
    def __init__(self, baglanti):
        self._baglanti = baglanti
        self._imlec = baglanti._ham.cursor()
        self._kapali = False

    # -- psycopg2 uyumlu özellikler --
    @property
    def rowcount(self):
        return self._imlec.rowcount

    @property
    def lastrowid(self):
        return self._imlec.lastrowid

    @property
    def description(self):
        return self._imlec.description

    def execute(self, sql, params=None):
        cevrilmis = _sorgu_cevir(sql)
        if params is None:
            self._imlec.execute(cevrilmis)
        else:
            self._imlec.execute(cevrilmis, tuple(params))
        return self

    def executemany(self, sql, params_listesi):
        self._imlec.executemany(_sorgu_cevir(sql), [tuple(p) for p in params_listesi])
        return self

    def _satir(self, ham):
        if ham is None:
            return None
        sutunlar = [s[0] for s in self._imlec.description]
        return Satir(sutunlar, ham)

    def fetchone(self):
        return self._satir(self._imlec.fetchone())

    def fetchall(self):
        hamlar = self._imlec.fetchall()
        if not hamlar:
            return []
        sutunlar = [s[0] for s in self._imlec.description]
        return [Satir(sutunlar, h) for h in hamlar]

    def fetchmany(self, size=1):
        hamlar = self._imlec.fetchmany(size)
        if not hamlar:
            return []
        sutunlar = [s[0] for s in self._imlec.description]
        return [Satir(sutunlar, h) for h in hamlar]

    def mogrify(self, sql, params=None):
        """psycopg2.mogrify karşılığı: sorguyu, parametreleri yerine
        yerleştirilmiş hâliyle (bayt dizisi olarak) döndürür. "Yedek Al"
        özelliği bunu kullanarak INSERT satırları üretir."""
        cevrilmis = _sorgu_cevir(sql)
        if params:
            for p in params:
                cevrilmis = cevrilmis.replace("?", _sql_degeri(p), 1)
        return cevrilmis.encode("utf-8")

    def close(self):
        if not self._kapali:
            self._kapali = True
            try:
                self._imlec.close()
            except Exception:
                pass

    def __iter__(self):
        return iter(self.fetchall())

    def __enter__(self):
        return self

    def __exit__(self, *a):
        self.close()


# --------------------------------------------------------------------------
# Bağlantı
# --------------------------------------------------------------------------
class Baglanti:
    def __init__(self, dosya_yolu):
        self.dosya_yolu = dosya_yolu
        self._ham = sqlite3.connect(
            dosya_yolu, check_same_thread=False, timeout=30,
            detect_types=sqlite3.PARSE_DECLTYPES,
        )
        self._ham.execute("PRAGMA journal_mode=WAL")
        self._ham.execute("PRAGMA foreign_keys=ON")
        self._ham.execute("PRAGMA busy_timeout=30000")
        self._ham.create_function("TRANSLATE", 3, _translate)
        self._ham.create_function("LOWER", 1, _lower_tr)
        self._ham.create_function("UPPER", 1, _upper_tr)
        self._kilit = threading.RLock()
        self.closed = 0

    def cursor(self, *a, **kw):
        return Imlec(self)

    def commit(self):
        self._ham.commit()

    def rollback(self):
        try:
            self._ham.rollback()
        except Exception:
            pass

    def close(self):
        self.closed = 1
        try:
            self._ham.close()
        except Exception:
            pass

    # schema.sql gibi çok ifadeli betikleri çalıştırmak için
    def betik_calistir(self, betik):
        ifadeler = _ifadelere_ayir(betik)

        # 1. geçiş: sonradan kısıtı kaldırılan sütunları tespit et.
        gevsetilecek = {}
        for ifade in ifadeler:
            m = _ALTER_COLUMN.match(ifade.strip())
            if not m:
                continue
            anahtar = (m.group(1).lower(), m.group(2).lower())
            not_null, varsayilan = gevsetilecek.get(anahtar, (False, False))
            if m.group(3).upper().replace(" ", "").startswith("NOT"):
                not_null = True
            else:
                varsayilan = True
            gevsetilecek[anahtar] = (not_null, varsayilan)

        # 2. geçiş: ifadeleri çalıştır.
        imlec = self._ham.cursor()
        for ifade in ifadeler:
            duz = ifade.strip()
            if _ALTER_COLUMN.match(duz):
                # Karşılığı 1. geçişte uygulandı, ifadenin kendisi atlanır.
                continue

            m = _ADD_COLUMN.match(duz)
            if m:
                # SQLite'ta "ADD COLUMN IF NOT EXISTS" yok: kolon zaten varsa atla.
                tablo, kolon, tanim = m.group(1), m.group(2), m.group(3)
                imlec.execute(f"PRAGMA table_info({tablo})")
                mevcut = {s[1].lower() for s in imlec.fetchall()}
                if kolon.lower() in mevcut:
                    continue
                kisit = gevsetilecek.get((tablo.lower(), kolon.lower()))
                if kisit:
                    tanim = _kisit_kaldir(tanim, kisit[0], kisit[1])
                duz = f"ALTER TABLE {tablo} ADD COLUMN {kolon} {tanim}"
            else:
                mt = _CREATE_TABLE.match(duz)
                if mt and gevsetilecek:
                    duz = _create_table_gevset(duz, mt.group(1), gevsetilecek)

            try:
                imlec.execute(_sema_cevir(duz))
            except sqlite3.OperationalError as hata:
                mesaj = str(hata).lower()
                # Zaten var olan kolon/tablo/indeks hataları görmezden gelinir
                # (schema.sql her açılışta yeniden çalıştırılıyor).
                if "duplicate column" in mesaj or "already exists" in mesaj:
                    continue
                raise
        self._ham.commit()
        imlec.close()


def connect(dsn=None, **kw):
    """psycopg2.connect karşılığı. `dsn` bir dosya yolu ya da sqlite:///yol
    biçiminde olabilir; verilmezse ALGI_VERI_DOSYASI ortam değişkeni
    kullanılır."""
    yol = dsn or os.environ.get("ALGI_VERI_DOSYASI") or "algi_bilisim.db"
    if yol.startswith("sqlite:///"):
        yol = yol[len("sqlite:///"):]
    elif yol.startswith("sqlite://"):
        yol = yol[len("sqlite://"):]
    klasor = os.path.dirname(os.path.abspath(yol))
    if klasor:
        os.makedirs(klasor, exist_ok=True)
    return Baglanti(yol)


# --------------------------------------------------------------------------
# psycopg2.extras ve psycopg2.pool taklitleri
# --------------------------------------------------------------------------
class _Extras:
    """app.py `cursor_factory=psycopg2.extras.RealDictCursor` geçiyor; bizim
    imlecimiz zaten sözlük benzeri satır döndürdüğü için bunlar sadece birer
    işaret."""
    RealDictCursor = "RealDictCursor"
    DictCursor = "DictCursor"

    @staticmethod
    def register_default_jsonb(*a, **kw):
        return None


class _Havuz:
    """Tek kullanıcılı masaüstü sürümünde gerçek bir bağlantı havuzuna gerek
    yok; aynı dosyaya birden çok bağlantı açmak yerine tek bağlantı paylaşılır
    (SQLite'ta yazma kilidi tek olduğu için en güvenlisi budur)."""

    def __init__(self, minconn, maxconn, dsn=None, **kw):
        self._dsn = dsn
        self._baglanti = connect(dsn)
        self._kilit = threading.RLock()

    def getconn(self, key=None):
        with self._kilit:
            if self._baglanti is None or self._baglanti.closed:
                self._baglanti = connect(self._dsn)
            return self._baglanti

    def putconn(self, conn, key=None, close=False):
        return None

    def closeall(self):
        with self._kilit:
            if self._baglanti is not None:
                self._baglanti.close()
                self._baglanti = None


class _Pool:
    ThreadedConnectionPool = _Havuz
    SimpleConnectionPool = _Havuz


extras = _Extras()
pool = _Pool()
