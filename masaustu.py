"""ALGI BİLİŞİM — Masaüstü (Windows) başlatıcısı.

Bu dosya çalıştırıldığında:
  1. Programın verilerini kullanıcının bilgisayarındaki kalıcı bir klasöre
     yerleştirir (Belgeler\\ALGI BILISIM). Program güncellense bile veriler
     burada kalır.
  2. Web sunucusunu yalnızca bu bilgisayarda dinleyecek şekilde (127.0.0.1)
     arka planda başlatır — dışarıdan kimse bağlanamaz.
  3. Kendi penceresinde (adres çubuğu olmayan bir pencere) programı açar.

Sunucu sürümünden tek farkı budur; ekranların ve iş mantığının tamamı aynı
app.py dosyasından gelir.
"""

import os
import socket
import sys
import threading
import time


UYGULAMA_ADI = "ALGI BILISIM"


def _veri_klasoru():
    """Verilerin saklanacağı kalıcı klasör. Windows'ta Belgeler altında,
    diğer sistemlerde kullanıcı klasöründe açılır."""
    ozel = os.environ.get("ALGI_VERI_KLASORU")
    if ozel:
        klasor = ozel
    elif os.name == "nt":
        belgeler = os.path.join(os.path.expanduser("~"), "Documents")
        if not os.path.isdir(belgeler):
            belgeler = os.path.expanduser("~")
        klasor = os.path.join(belgeler, UYGULAMA_ADI)
    else:
        klasor = os.path.join(os.path.expanduser("~"), ".algi-bilisim")
    os.makedirs(klasor, exist_ok=True)
    return klasor


def _program_klasoru():
    """Program dosyalarının (templates, static, schema.sql) bulunduğu klasör.
    PyInstaller ile paketlendiğinde bunlar geçici bir klasöre açılır."""
    if getattr(sys, "frozen", False):
        return getattr(sys, "_MEIPASS", os.path.dirname(sys.executable))
    return os.path.dirname(os.path.abspath(__file__))


def _bos_port_bul():
    # Sorun giderirken sabit bir port kullanilabilsin diye (ALGI_PORT=8800).
    ozel = os.environ.get("ALGI_PORT")
    if ozel and ozel.isdigit():
        return int(ozel)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _gizli_anahtar(veri_klasoru):
    """Oturum çerezlerini imzalayan anahtar. İlk açılışta rastgele üretilip
    veri klasöründe saklanır, sonraki açılışlarda aynısı kullanılır (yoksa
    her açılışta oturum düşerdi)."""
    yol = os.path.join(veri_klasoru, "gizli_anahtar.txt")
    if os.path.exists(yol):
        try:
            with open(yol, "r", encoding="utf-8") as f:
                anahtar = f.read().strip()
            if anahtar:
                return anahtar
        except OSError:
            pass
    import secrets
    anahtar = secrets.token_hex(32)
    try:
        with open(yol, "w", encoding="utf-8") as f:
            f.write(anahtar)
        if os.name != "nt":
            os.chmod(yol, 0o600)
    except OSError:
        pass
    return anahtar


def _ortami_hazirla():
    veri_klasoru = _veri_klasoru()
    program_klasoru = _program_klasoru()

    os.environ["ALGI_MASAUSTU"] = "1"
    os.environ["ALGI_VERI_DOSYASI"] = os.path.join(veri_klasoru, "algi_bilisim.db")
    os.environ.setdefault("SECRET_KEY", _gizli_anahtar(veri_klasoru))
    # İlk açılışta giriş yapılabilsin diye varsayılan kullanıcı. Program
    # içinden "Kullanıcı Ayarları" ekranından değiştirilebilir.
    os.environ.setdefault("ADMIN_KULLANICI", "admin")
    os.environ.setdefault("ADMIN_SIFRE", "admin")
    # Yüklenen fotoğraf vb. dosyalar için çalışma klasörü
    os.chdir(program_klasoru)
    return veri_klasoru


# Başlatma sırasında oluşan hatalar buraya yazılır. Program penceresiz
# çalıştığı için ekranda hata görünmez; sorun olursa bu dosyaya bakılır.
_HATA_DOSYASI = None
_SUNUCU_HATASI = []


def _kayit_yaz(metin):
    print(metin, flush=True)
    if not _HATA_DOSYASI:
        return
    try:
        with open(_HATA_DOSYASI, "a", encoding="utf-8") as f:
            f.write(f"[{time.strftime('%d.%m.%Y %H:%M:%S')}] {metin}\n")
    except OSError:
        pass


def _sunucuyu_baslat(port):
    """Flask uygulamasını arka planda, yalnızca bu bilgisayarda dinleyecek
    şekilde çalıştırır."""
    try:
        from waitress import serve
        import app as algi_app

        _kayit_yaz(f"Sunucu başlatılıyor: 127.0.0.1:{port}")
        serve(algi_app.app, host="127.0.0.1", port=port, threads=4, _quiet=True)
    except BaseException as hata:
        import traceback
        _SUNUCU_HATASI.append(traceback.format_exc())
        _kayit_yaz("SUNUCU BAŞLATILAMADI:\n" + traceback.format_exc())


def _sunucu_hazir_mi(port, saniye=40):
    baslangic = time.time()
    while time.time() - baslangic < saniye:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=1):
                return True
        except OSError:
            time.sleep(0.2)
    return False


def main():
    global _HATA_DOSYASI
    veri_klasoru = _ortami_hazirla()
    _HATA_DOSYASI = os.path.join(veri_klasoru, "calisma_kaydi.txt")
    _kayit_yaz("ALGI BİLİŞİM başlatılıyor — veri klasörü: " + veri_klasoru)
    port = _bos_port_bul()
    adres = f"http://127.0.0.1:{port}/"

    sunucu = threading.Thread(target=_sunucuyu_baslat, args=(port,), daemon=True)
    sunucu.start()

    if not _sunucu_hazir_mi(port):
        ayrinti = _SUNUCU_HATASI[0] if _SUNUCU_HATASI else "(ayrıntı yok)"
        _kayit_yaz("Sunucu hazır olmadı.\n" + ayrinti)
        _hata_goster(
            "Program başlatılamadı",
            "Program açılırken bir sorun oluştu.\n\n"
            f"Ayrıntılar şu dosyada: {_HATA_DOSYASI}\n\n"
            + ayrinti[-600:],
        )
        return 1
    _kayit_yaz("Sunucu hazır.")

    try:
        import webview
        pencere = webview.create_window(
            "ALGI BİLİŞİM",
            adres,
            width=1280,
            height=860,
            min_size=(900, 600),
            confirm_close=False,
        )
        webview.start()
        # Pencere kapatıldığında program da kapanır.
        del pencere
    except Exception as hata:
        # Pencere açılamazsa (örn. sistem bileşeni eksik) varsayılan
        # tarayıcıda açıp programı ayakta tutarız — kullanıcı programsız
        # kalmasın.
        _kayit_yaz(f"Program penceresi açılamadı ({hata}); tarayıcıda açılıyor.")
        import webbrowser
        webbrowser.open(adres)
        print(f"ALGI BİLİŞİM çalışıyor: {adres}")
        print("Kapatmak için bu pencereyi kapatın.")
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            pass
    return 0


def _hata_goster(baslik, mesaj):
    try:
        import tkinter
        from tkinter import messagebox
        kok = tkinter.Tk()
        kok.withdraw()
        messagebox.showerror(baslik, mesaj)
        kok.destroy()
    except Exception:
        print(f"{baslik}: {mesaj}")


if __name__ == "__main__":
    sys.exit(main())
