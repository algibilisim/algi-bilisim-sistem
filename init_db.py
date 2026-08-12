"""
Veritabanını ve ilk yönetici kullanıcısını oluşturur.
Çalıştırma:  python init_db.py
"""
import sqlite3
import os
from werkzeug.security import generate_password_hash

DB_PATH = os.environ.get("DB_PATH", "algibilisim.db")

def main():
    conn = sqlite3.connect(DB_PATH)
    with open("schema.sql", "r", encoding="utf-8") as f:
        conn.executescript(f.read())

    kullanici_adi = input("Yönetici kullanıcı adı: ").strip()
    sifre = input("Yönetici şifresi: ").strip()

    conn.execute(
        "INSERT OR REPLACE INTO kullanici (kullanici_adi, sifre_hash) VALUES (?, ?)",
        (kullanici_adi, generate_password_hash(sifre)),
    )
    conn.commit()
    conn.close()
    print(f"Veritabanı hazır: {DB_PATH}")
    print(f"Kullanıcı '{kullanici_adi}' oluşturuldu.")

if __name__ == "__main__":
    main()
