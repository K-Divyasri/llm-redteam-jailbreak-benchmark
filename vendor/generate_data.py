"""Build the bundled data the tools use: a small SQLite company database.

The `query_database` tool reads this file. We generate it deterministically (no
randomness) so the database is identical on every machine and every run — which
keeps the notebooks, labs, and tests reproducible.

    python generate_data.py     # writes data/company.db

The web_search corpus is tiny and lives inline in tools.py, so there's nothing to
generate for it.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

DATA_DIR = Path(__file__).resolve().parent / "data"
DB_PATH = DATA_DIR / "company.db"

EMPLOYEES = [
    ("Ada Lovelace", "Engineering", "London", 95000),
    ("Grace Hopper", "Engineering", "Austin", 98000),
    ("Alan Turing", "Engineering", "London", 102000),
    ("Katherine Johnson", "Finance", "Toronto", 91000),
    ("Radia Perlman", "Engineering", "Berlin", 99000),
    ("Hedy Lamarr", "Marketing", "Paris", 78000),
    ("Claude Shannon", "Engineering", "Austin", 105000),
    ("Margaret Hamilton", "Engineering", "London", 101000),
    ("Marie Curie", "Support", "Paris", 72000),
    ("Rosalind Franklin", "Sales", "Berlin", 84000),
    ("Tim Berners-Lee", "Engineering", "London", 110000),
    ("Barbara Liskov", "Engineering", "Toronto", 103000),
    ("Sundar Iyer", "Sales", "Austin", 82000),
    ("Nadia Comaneci", "Marketing", "Toronto", 76000),
    ("Yuki Tanaka", "Support", "Tokyo", 69000),
]

PRODUCTS = [
    ("Mechanical Keyboard", "Hardware", 89, 1),
    ("Wireless Mouse", "Accessories", 35, 1),
    ("USB-C Hub", "Accessories", 45, 0),
    ("Noise-Cancelling Headphones", "Hardware", 199, 1),
    ("Code Editor Pro (license)", "Software", 60, 1),
    ("Standing Desk", "Hardware", 320, 0),
    ("Webcam 1080p", "Hardware", 55, 1),
    ("Password Manager (1yr)", "Software", 24, 1),
    ("Laptop Stand", "Accessories", 28, 1),
    ("Cloud Backup (1yr)", "Software", 90, 1),
]


def main() -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    if DB_PATH.exists():
        DB_PATH.unlink()

    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("CREATE TABLE employees (name TEXT, department TEXT, city TEXT, salary INTEGER)")
        conn.executemany("INSERT INTO employees VALUES (?, ?, ?, ?)", EMPLOYEES)
        conn.execute("CREATE TABLE products (name TEXT, category TEXT, price INTEGER, in_stock INTEGER)")
        conn.executemany("INSERT INTO products VALUES (?, ?, ?, ?)", PRODUCTS)
        conn.commit()

    print(f"Wrote {DB_PATH}")
    print(f"  employees: {len(EMPLOYEES)} rows")
    print(f"  products:  {len(PRODUCTS)} rows")


if __name__ == "__main__":
    main()
