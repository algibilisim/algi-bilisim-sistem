# ALGI BİLİŞİM - Malzeme Alacak Takip Sistemi (Çekirdek Sürüm)

Bu sürüm şunları içerir:
- Giriş (kullanıcı adı / şifre)
- Abone Listesi (ekle, düzenle, sil, ara, köye göre filtrele)
- Tahsilat (köy bazlı otomatik özet - Excel'deki gibi canlı hesaplanır)

## Bilgisayarınızda deneme (yerel test)

1. Python 3.10+ kurulu olmalı.
2. Terminal / komut satırında bu klasöre girin:
   ```
   cd algi_bilisim
   pip install -r requirements.txt
   python init_db.py     # kullanıcı adı ve şifre soracak
   python app.py
   ```
3. Tarayıcıda `http://127.0.0.1:5000` adresini açın.

## DigitalOcean üzerine kurulum (Claude Code ile birlikte yapılacak)

Bu adımları Claude Code'da birlikte tamamlayacağız:
1. DigitalOcean hesabı açma
2. App Platform üzerinde yeni bir uygulama oluşturma (bu proje klasörünü GitHub'a yükleyip bağlayacağız)
3. Ortam değişkenlerini ayarlama: `SECRET_KEY`, `DB_PATH`
4. `gunicorn app:app` komutuyla üretim (production) modunda çalıştırma
5. Kendi alan adınızı (isteğe bağlı) bağlama

## Sıradaki adımlar (henüz eklenmedi)

- Tahsilat Çıktısı (borç raporu / filtreleme)
- Malzeme Maliyet Listesi
- Donanım ve Malzeme Satışı
- Kar Listesi
- Malzeme Harcama Dağılımı (abone başına malzeme kullanımı)
- Arıza Takip
- PostgreSQL'e geçiş (DigitalOcean'da SQLite yerine kalıcı veritabanı için önerilir)
