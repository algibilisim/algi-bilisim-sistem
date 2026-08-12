"""
Var olan veritabanına 'odeme_gun_sozu' sütununu ekler.
Mevcut verileriniz SİLİNMEZ, sadece yeni bir sütun eklenir.

Çalıştırma:  python migrate_db.py
"""
import sqlite3
import os

DB_PATH = os.environ.get("DB_PATH", "algibilisim.db")

def main():
    conn = sqlite3.connect(DB_PATH)
    try:
        conn.execute("ALTER TABLE abone ADD COLUMN odeme_gun_sozu TEXT")
        conn.commit()
        print("Sütun eklendi: odeme_gun_sozu")
    except sqlite3.OperationalError as e:
        print("Sütun zaten var veya bir hata oluştu:", e)
    conn.close()

if __name__ == "__main__":
    main()