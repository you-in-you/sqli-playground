#!/usr/bin/env python3
"""
SQLi CTF — Database Setup
Creates 60 isolated databases + meta DB with random unique flags.
Safe to re-run (idempotent for structure; flags only generated once).
"""

import os
import json
import secrets
import time
from pathlib import Path
import pymysql

ROOT = Path(__file__).resolve().parent.parent
_cfg_path = Path(os.getenv("SQLI_CTF_CONFIG", str(ROOT / "config.json")))
_cfg = {}
if _cfg_path.is_file():
    try:
        _cfg = json.loads(_cfg_path.read_text(encoding="utf-8"))
    except Exception:
        _cfg = {}

def _get(key, default):
    if key in os.environ:
        return os.environ[key]
    if key in _cfg:
        return _cfg[key]
    return default

DB_HOST = str(_get("DB_HOST", "127.0.0.1"))
DB_PORT = int(_get("DB_PORT", 3306))
DB_USER = str(_get("DB_USER", "ctf"))
DB_PASS = str(_get("DB_PASS", "ctfpass"))
FLAGS_FILE = str(_get("FLAGS_FILE", str(ROOT / "flags.json")))

TOTAL_LEVELS = 60


def wait_for_db(retries=30, delay=2):
    for i in range(retries):
        try:
            conn = pymysql.connect(
                host=DB_HOST, port=DB_PORT,
                user=DB_USER, password=DB_PASS,
                charset="utf8mb4"
            )
            conn.close()
            print("[+] Database is ready")
            return
        except Exception as e:
            print(f"[.] Waiting for DB... ({i+1}/{retries}) {e}")
            time.sleep(delay)
    raise RuntimeError("Database not available")


def gen_flag(level_id: int) -> str:
    token = secrets.token_hex(4)
    return f"CTF{{sql1_l{level_id:02d}_{token}}}"


def get_connection(database=None):
    kwargs = dict(
        host=DB_HOST, port=DB_PORT,
        user=DB_USER, password=DB_PASS,
        charset="utf8mb4",
        autocommit=True,
    )
    if database:
        kwargs["database"] = database
    return pymysql.connect(**kwargs)


def load_or_create_flags():
    """Load existing flags or generate new ones (persist across restarts)."""
    if os.path.exists(FLAGS_FILE):
        with open(FLAGS_FILE, "r") as f:
            raw = json.load(f)
        flags = {int(k): v for k, v in raw.items() if str(k).isdigit()}
        if len(flags) >= TOTAL_LEVELS:
            print(f"[+] Loaded existing flags from {FLAGS_FILE}")
            return flags
        print("[.] flags.json incomplete — regenerating")

    flags = {i: gen_flag(i) for i in range(1, TOTAL_LEVELS + 1)}
    parent = os.path.dirname(FLAGS_FILE)
    if parent:
        os.makedirs(parent, exist_ok=True)
    with open(FLAGS_FILE, "w") as f:
        json.dump({str(k): v for k, v in flags.items()}, f, indent=2)
    print(f"[+] Generated {TOTAL_LEVELS} unique flags → {FLAGS_FILE}")
    return flags


def create_meta_db():
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("CREATE DATABASE IF NOT EXISTS sqli_ctf_meta")
    cur.execute("USE sqli_ctf_meta")
    cur.execute("""
        CREATE TABLE IF NOT EXISTS progress (
            id INT PRIMARY KEY DEFAULT 1,
            current_level INT NOT NULL DEFAULT 1,
            solved TEXT NOT NULL DEFAULT ''
        )
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS attack_history (
            id INT AUTO_INCREMENT PRIMARY KEY,
            level_id INT NOT NULL,
            username_payload TEXT NOT NULL,
            password_payload TEXT NOT NULL,
            response_message TEXT,
            response_raw TEXT,
            ok TINYINT NOT NULL DEFAULT 0,
            is_winning TINYINT NOT NULL DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            INDEX (level_id)
        )
    """)
    cur.execute("SELECT COUNT(*) FROM progress")
    if cur.fetchone()[0] == 0:
        cur.execute("INSERT INTO progress (id, current_level, solved) VALUES (1, 1, '')")
    cur.close()
    conn.close()
    print("[+] Meta database ready")


def create_level_db(level_id: int, flag: str):
    db_name = f"sqli_level_{level_id:02d}"
    conn = get_connection()
    cur = conn.cursor()
    cur.execute(f"CREATE DATABASE IF NOT EXISTS `{db_name}`")
    cur.execute(f"USE `{db_name}`")

    # Common tables for most levels
    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INT AUTO_INCREMENT PRIMARY KEY,
            username VARCHAR(64) NOT NULL,
            password VARCHAR(128) NOT NULL,
            email VARCHAR(128) DEFAULT NULL,
            role VARCHAR(32) DEFAULT 'user'
        )
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS secrets (
            id INT AUTO_INCREMENT PRIMARY KEY,
            name VARCHAR(64) NOT NULL,
            flag VARCHAR(128) NOT NULL
        )
    """)

    # Seed data only if empty
    cur.execute("SELECT COUNT(*) FROM users")
    if cur.fetchone()[0] == 0:
        cur.execute(
            "INSERT INTO users (username, password, email, role) VALUES "
            "('admin', 'admin123', 'admin@local', 'admin'),"
            "('alice', 'alicepass', 'alice@local', 'user'),"
            "('bob', 'bobpass', 'bob@local', 'user'),"
            "('guest', 'guest', 'guest@local', 'user')"
        )

    cur.execute("SELECT COUNT(*) FROM secrets")
    if cur.fetchone()[0] == 0:
        cur.execute(
            "INSERT INTO secrets (name, flag) VALUES (%s, %s)",
            ("level_flag", flag)
        )

    # Level-specific extra tables / data can be added here later
    cur.close()
    conn.close()


def main():
    print("=" * 50)
    print("  SQLi CTF — Database Setup")
    print("=" * 50)

    wait_for_db()
    flags = load_or_create_flags()
    create_meta_db()

    for i in range(1, TOTAL_LEVELS + 1):
        create_level_db(i, flags[i])
        if i % 10 == 0:
            print(f"[+] Levels 1–{i} ready")

    print("[+] All 60 level databases ready")
    print("[+] Setup complete")
    print("=" * 50)


if __name__ == "__main__":
    main()
