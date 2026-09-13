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

_simge = os.path.join("static", "icons", "algi.ico")

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
    icon=_simge if os.path.exists(_simge) else None,
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
