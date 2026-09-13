# -*- mode: python ; coding: utf-8 -*-
"""ALGI BİLİŞİM — Windows masaüstü paketi tarifi (PyInstaller 6).

Bu dosya, programın Windows'ta çalışan bir uygulamaya dönüştürülmesini
tarif eder. GitHub'daki derleme sistemi (bkz. .github/workflows/windows.yml)
bunu kullanarak "dist\\ALGI BILISIM" klasörünü üretir.
"""

import os

# Şablonlar, stil dosyaları ve veritabanı şeması programın yanında taşınır.
veri_dosyalari = [
    ("templates", "templates"),
    ("static", "static"),
    ("schema.sql", "."),
]

# PyInstaller'ın kod içinden bulamadığı, çalışma anında gereken paketler.
gizli_ice_aktarmalar = [
    "yerel_veritabani",
    "app",
    "waitress",
    "webview",
    "webview.platforms.winforms",
    "clr_loader",
    "openpyxl",
    "xlrd",
    "mammoth",
    "bs4",
    "PIL",
    "PIL.Image",
    "reportlab",
    "reportlab.pdfgen",
    "reportlab.lib",
    "reportlab.platypus",
    "jinja2",
    "sqlite3",
]

def _simge_bul():
    """Masaüstü sürümünün simgesi. Dosya yanlış klasöre yüklenmiş olabilir
    diye birkaç olası yer sırayla denenir; hiçbiri yoksa PyInstaller'ın
    varsayılan simgesi kullanılır (program yine de çalışır)."""
    adaylar = [
        os.path.join("static", "icons", "algi-masaustu.ico"),
        os.path.join("static", "algi-masaustu.ico"),
        "algi-masaustu.ico",
        os.path.join("static", "icons", "algi.ico"),
        os.path.join("static", "algi.ico"),
        "algi.ico",
    ]
    for yol in adaylar:
        if os.path.exists(yol):
            print(f"[ALGI] Program simgesi: {yol}")
            return yol
    print("[ALGI] UYARI: simge dosyası bulunamadı, varsayılan simge kullanılacak.")
    return None


_simge = _simge_bul()

a = Analysis(
    ["masaustu.py"],
    pathex=[],
    binaries=[],
    datas=veri_dosyalari,
    hiddenimports=gizli_ice_aktarmalar,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    # Masaüstü sürümü PostgreSQL kullanmadığı için psycopg2 pakete alınmaz.
    excludes=["psycopg2", "psycopg2-binary", "gunicorn"],
    noarchive=False,
    optimize=0,
)

pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="ALGI BILISIM",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=False,  # siyah komut penceresi açılmasın
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=_simge,
)

coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=False,
    upx_exclude=[],
    name="ALGI BILISIM",
)
