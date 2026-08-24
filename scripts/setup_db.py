#!/usr/bin/env python3
"""
SQLi CTF — Database Setup
Creates 60 isolated databases + meta DB with random unique flags.
Safe to re-run (idempotent for structure; flags only generated once).

When APP_VERSION changes (bump the constant below after an update),
setup detects the mismatch, asks the user, then regenerates all flags,
resets progress/history, updates flags.json, and stores the new version.
"""

import os
import sys
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

# Bump this string whenever you ship an update that should invalidate
# existing flags / progress. Must match what is stored in sqli_ctf_meta.app_version.
APP_VERSION = "1.0.0"


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


def save_flags(flags: dict) -> None:
    parent = os.path.dirname(FLAGS_FILE)
    if parent:
        os.makedirs(parent, exist_ok=True)
    with open(FLAGS_FILE, "w") as f:
        json.dump({str(k): v for k, v in sorted(flags.items())}, f, indent=2)
    print(f"[+] Wrote {len(flags)} flags → {FLAGS_FILE}")


def generate_flags() -> dict:
    flags = {i: gen_flag(i) for i in range(1, TOTAL_LEVELS + 1)}
    save_flags(flags)
    print(f"[+] Generated {TOTAL_LEVELS} unique flags")
    return flags


def load_or_create_flags(force_new: bool = False) -> dict:
    """Load existing flags or generate new ones (persist across restarts)."""
    if force_new:
        return generate_flags()

    if os.path.exists(FLAGS_FILE):
        with open(FLAGS_FILE, "r") as f:
            raw = json.load(f)
        flags = {int(k): v for k, v in raw.items() if str(k).isdigit()}
        if len(flags) >= TOTAL_LEVELS:
            print(f"[+] Loaded existing flags from {FLAGS_FILE}")
            return flags
        print("[.] flags.json incomplete — regenerating")

    return generate_flags()


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
    # Single-row table holding the schema/app version for migration detection
    cur.execute("""
        CREATE TABLE IF NOT EXISTS app_version (
            id INT PRIMARY KEY DEFAULT 1,
            version VARCHAR(32) NOT NULL
        )
    """)
    cur.execute("SELECT COUNT(*) FROM progress")
    if cur.fetchone()[0] == 0:
        cur.execute("INSERT INTO progress (id, current_level, solved) VALUES (1, 1, '')")
    cur.close()
    conn.close()
    print("[+] Meta database ready")


def get_stored_version() -> str | None:
    """Return stored version string, or None if missing / table empty."""
    try:
        conn = get_connection("sqli_ctf_meta")
        cur = conn.cursor()
        cur.execute(
            "SELECT COUNT(*) FROM information_schema.tables "
            "WHERE table_schema = 'sqli_ctf_meta' AND table_name = 'app_version'"
        )
        if cur.fetchone()[0] == 0:
            cur.close()
            conn.close()
            return None
        cur.execute("SELECT version FROM app_version WHERE id = 1")
        row = cur.fetchone()
        cur.close()
        conn.close()
        if not row:
            return None
        return row[0]
    except Exception:
        return None


def set_stored_version(version: str) -> None:
    conn = get_connection("sqli_ctf_meta")
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS app_version (
            id INT PRIMARY KEY DEFAULT 1,
            version VARCHAR(32) NOT NULL
        )
    """)
    cur.execute(
        "INSERT INTO app_version (id, version) VALUES (1, %s) "
        "ON DUPLICATE KEY UPDATE version = VALUES(version)",
        (version,),
    )
    cur.close()
    conn.close()
    print(f"[+] Stored app version: {version}")


def reset_progress_and_history() -> None:
    conn = get_connection("sqli_ctf_meta")
    cur = conn.cursor()
    cur.execute(
        "UPDATE progress SET current_level = 1, solved = '' WHERE id = 1"
    )
    cur.execute("TRUNCATE TABLE attack_history")
    cur.close()
    conn.close()
    print("[+] Progress and attack history reset")


def update_level_flag(level_id: int, flag: str) -> None:
    """Ensure level DB exists and secrets.flag matches the given flag."""
    db_name = f"sqli_level_{level_id:02d}"
    conn = get_connection()
    cur = conn.cursor()
    cur.execute(f"CREATE DATABASE IF NOT EXISTS `{db_name}`")
    cur.execute(f"USE `{db_name}`")
    cur.execute("""
        CREATE TABLE IF NOT EXISTS secrets (
            id INT AUTO_INCREMENT PRIMARY KEY,
            name VARCHAR(64) NOT NULL,
            flag VARCHAR(128) NOT NULL
        )
    """)
    cur.execute("SELECT id FROM secrets WHERE name = %s LIMIT 1", ("level_flag",))
    row = cur.fetchone()
    if row:
        cur.execute(
            "UPDATE secrets SET flag = %s WHERE name = %s",
            (flag, "level_flag"),
        )
    else:
        cur.execute(
            "INSERT INTO secrets (name, flag) VALUES (%s, %s)",
            ("level_flag", flag),
        )
    cur.close()
    conn.close()


def create_level_db(level_id: int, flag: str):
    db_name = f"sqli_level_{level_id:02d}"
    conn = get_connection()
    cur = conn.cursor()
    cur.execute(f"CREATE DATABASE IF NOT EXISTS `{db_name}`")
    cur.execute(f"USE `{db_name}`")

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
            ("level_flag", flag),
        )
    else:
        # Keep secrets.flag in sync with flags.json on normal runs too
        cur.execute(
            "UPDATE secrets SET flag = %s WHERE name = %s",
            (flag, "level_flag"),
        )

    cur.close()
    conn.close()


def ask_user_confirm_reset(stored: str | None, current: str) -> bool:
    """
    Ask whether to apply version migration (new flags + progress reset).
    Interactive terminal → prompt. Non-interactive (Docker) → auto-yes with warning.
    Env SQLI_CTF_SKIP_RESET=1 forces skip; SQLI_CTF_FORCE_RESET=1 forces yes.
    """
    if os.getenv("SQLI_CTF_FORCE_RESET", "").strip() in ("1", "true", "yes"):
        print("[!] SQLI_CTF_FORCE_RESET=1 → applying reset")
        return True
    if os.getenv("SQLI_CTF_SKIP_RESET", "").strip() in ("1", "true", "yes"):
        print("[!] SQLI_CTF_SKIP_RESET=1 → keeping old data")
        return False

    stored_label = stored if stored is not None else "(none)"
    print()
    print("!" * 50)
    print("  GAME UPDATE DETECTED")
    print(f"  Database version : {stored_label}")
    print(f"  App version      : {current}")
    print()
    print("  Applying this update will:")
    print("    • Generate new random flags for all 60 levels")
    print("    • Update flags.json")
    print("    • Reset your progress (current level & solved)")
    print("    • Clear attack history")
    print("!" * 50)

    interactive = sys.stdin.isatty()
    if not interactive:
        print("[!] Non-interactive session — applying reset automatically.")
        print("    Set SQLI_CTF_SKIP_RESET=1 to keep old data.")
        return True

    while True:
        ans = input("Continue and reset progress? [y/N]: ").strip().lower()
        if ans in ("y", "yes"):
            return True
        if ans in ("n", "no", ""):
            return False
        print("Please answer y or n.")


def apply_version_reset() -> dict:
    """Regenerate flags, rewrite flags.json, update all secrets, reset meta."""
    print("[*] Applying version migration / full reset...")
    flags = generate_flags()
    for i in range(1, TOTAL_LEVELS + 1):
        update_level_flag(i, flags[i])
        if i % 10 == 0:
            print(f"[+] Flags updated for levels 1–{i}")
    reset_progress_and_history()
    set_stored_version(APP_VERSION)
    print("[+] Version migration complete")
    return flags


def check_and_handle_version() -> bool:
    """
    Returns True if a full flag reset was performed (caller should still
    ensure level structure exists). Returns False if versions already match.
    """
    stored = get_stored_version()
    if stored == APP_VERSION:
        print(f"[+] App version OK ({APP_VERSION})")
        return False

    # First install (no version row yet) and no progress worth keeping:
    # if progress is still default empty, just set version without scary prompt.
    if stored is None:
        try:
            conn = get_connection("sqli_ctf_meta")
            cur = conn.cursor()
            cur.execute("SELECT current_level, solved FROM progress WHERE id = 1")
            row = cur.fetchone()
            cur.close()
            conn.close()
            is_fresh = (
                row is None
                or (row[0] <= 1 and (not row[1] or row[1].strip() == ""))
            )
        except Exception:
            is_fresh = True

        if is_fresh:
            print(f"[+] First setup — setting version to {APP_VERSION}")
            set_stored_version(APP_VERSION)
            return False

    if not ask_user_confirm_reset(stored, APP_VERSION):
        print("[!] Skipping reset. Old flags and progress kept.")
        print("    (Version in DB still differs from APP_VERSION.)")
        return False

    apply_version_reset()
    return True


def main():
    print("=" * 50)
    print("  SQLi CTF — Database Setup")
    print(f"  Version: {APP_VERSION}")
    print("=" * 50)

    wait_for_db()
    create_meta_db()

    did_reset = check_and_handle_version()
    flags = load_or_create_flags(force_new=False)

    # If user skipped reset but flags.json was missing, we still generated
    # flags above via load_or_create_flags — ensure DB secrets match file.
    for i in range(1, TOTAL_LEVELS + 1):
        create_level_db(i, flags[i])
        if i % 10 == 0:
            print(f"[+] Levels 1–{i} ready")

    # Ensure version is set even on clean first run path
    if get_stored_version() is None:
        set_stored_version(APP_VERSION)

    print("[+] All 60 level databases ready")
    if did_reset:
        print("[+] Setup complete (flags & progress reset due to version change)")
    else:
        print("[+] Setup complete")
    print("=" * 50)


if __name__ == "__main__":
    main()
