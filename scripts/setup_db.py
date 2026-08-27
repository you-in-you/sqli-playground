#!/usr/bin/env python3
"""
SQLi CTF — Database Setup
Creates 60 isolated databases + meta DB with random unique flags.
Safe to re-run (idempotent for structure; flags only generated once).

Version manager
---------------
Bump APP_VERSION when you ship an update. Register which levels changed
in MIGRATIONS for that version. On startup, if the DB is behind, only
those levels (union of all pending migrations) get new flags and are
un-solved — the rest of the player's progress is kept.

Example: DB at 1.0.1, app at 1.0.9 → applies migrations 1.0.2 … 1.0.9
and refreshes only the levels listed in those entries.
"""

from __future__ import annotations

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

APP_VERSION = "1.0.1"

MIGRATIONS: list[dict] = [
    {
        "version": "1.0.1",
        "levels": [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11],
        "note": "Redesigned early SQLi levels",
    }
]

# ---------------------------------------------------------------------------
# Semver helpers
# ---------------------------------------------------------------------------
def parse_version(v: str) -> tuple[int, ...]:
    """Parse '1.0.9' / '1.0' / '2' → comparable tuple. Non-numeric → (0,)."""
    if not v or not str(v).strip():
        return (0,)
    parts: list[int] = []
    for p in str(v).strip().split("."):
        digits = "".join(c for c in p if c.isdigit())
        parts.append(int(digits) if digits else 0)
    return tuple(parts) if parts else (0,)


def version_lt(a: str, b: str) -> bool:
    return parse_version(a) < parse_version(b)


def version_le(a: str, b: str) -> bool:
    return parse_version(a) <= parse_version(b)


def version_eq(a: str, b: str) -> bool:
    return parse_version(a) == parse_version(b)


def pending_migrations(from_version: str | None, to_version: str) -> list[dict]:
    """
    Migrations strictly after from_version and up to to_version (inclusive).
    If from_version is None (legacy DB with no row), treat as 0.0.0 so ALL
    registered migrations apply — or full reset if MIGRATIONS is empty.
    """
    start = from_version if from_version is not None else "0.0.0"
    pending = []
    for m in MIGRATIONS:
        mv = str(m.get("version", "")).strip()
        if not mv:
            continue
        # start < migration_version <= to_version
        if version_lt(start, mv) and version_le(mv, to_version):
            pending.append(m)
    pending.sort(key=lambda m: parse_version(str(m["version"])))
    return pending


def levels_from_migrations(migs: list[dict]) -> set[int]:
    """Union of all level ids touched by the given migrations."""
    out: set[int] = set()
    for m in migs:
        levels = m.get("levels", [])
        if levels == "*" or levels == ["*"]:
            return set(range(1, TOTAL_LEVELS + 1))
        for lv in levels:
            try:
                n = int(lv)
            except (TypeError, ValueError):
                continue
            if n == 0:
                # convention: 0 means all levels
                return set(range(1, TOTAL_LEVELS + 1))
            if 1 <= n <= TOTAL_LEVELS:
                out.add(n)
    return out


# ---------------------------------------------------------------------------
# DB helpers
# ---------------------------------------------------------------------------
def wait_for_db(retries=30, delay=2):
    for i in range(retries):
        try:
            conn = pymysql.connect(
                host=DB_HOST, port=DB_PORT,
                user=DB_USER, password=DB_PASS,
                charset="utf8mb4",
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


def patch_flags(level_ids: set[int], existing: dict | None = None) -> dict:
    """Regenerate flags only for level_ids; keep the rest; write flags.json."""
    flags = dict(existing) if existing else {}
    if not flags and os.path.exists(FLAGS_FILE):
        try:
            with open(FLAGS_FILE, "r") as f:
                raw = json.load(f)
            flags = {int(k): v for k, v in raw.items() if str(k).isdigit()}
        except Exception:
            flags = {}

    for i in range(1, TOTAL_LEVELS + 1):
        if i not in flags:
            flags[i] = gen_flag(i)

    for i in sorted(level_ids):
        flags[i] = gen_flag(i)
        print(f"[+] New flag for level {i:02d}")

    save_flags(flags)
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
    cur.execute("""
        CREATE TABLE IF NOT EXISTS app_version (
            id INT PRIMARY KEY DEFAULT 1,
            version VARCHAR(32) NOT NULL
        )
    """)
    cur.execute("SELECT COUNT(*) FROM progress")
    if cur.fetchone()[0] == 0:
        cur.execute(
            "INSERT INTO progress (id, current_level, solved) VALUES (1, 1, '')"
        )
    cur.close()
    conn.close()
    print("[+] Meta database ready")


def get_stored_version() -> str | None:
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
    print("[+] Progress and attack history fully reset")


def unsolve_levels(level_ids: set[int]) -> None:
    """Remove specific levels from solved list; fix current_level; clear their history."""
    if not level_ids:
        return
    conn = get_connection("sqli_ctf_meta")
    cur = conn.cursor()
    cur.execute("SELECT current_level, solved FROM progress WHERE id = 1")
    row = cur.fetchone()
    solved: list[int] = []
    current = 1
    if row:
        current = int(row[0] or 1)
        if row[1]:
            solved = [int(x) for x in str(row[1]).split(",") if x.strip()]

    solved = [x for x in solved if x not in level_ids]
    # current_level = first unsolved (sequential unlock model)
    new_current = 1
    for i in range(1, TOTAL_LEVELS + 1):
        if i not in solved:
            new_current = i
            break
    else:
        new_current = TOTAL_LEVELS

    solved_str = ",".join(str(x) for x in sorted(solved))
    cur.execute(
        "UPDATE progress SET current_level = %s, solved = %s WHERE id = 1",
        (new_current, solved_str),
    )
    # history only for affected levels
    placeholders = ",".join(["%s"] * len(level_ids))
    cur.execute(
        f"DELETE FROM attack_history WHERE level_id IN ({placeholders})",
        tuple(sorted(level_ids)),
    )
    cur.close()
    conn.close()
    print(
        f"[+] Unsolved levels {sorted(level_ids)}; "
        f"current_level → {new_current}; history cleared for those levels"
    )


def update_level_flag(level_id: int, flag: str) -> None:
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
        cur.execute(
            "UPDATE secrets SET flag = %s WHERE name = %s",
            (flag, "level_flag"),
        )

    cur.close()
    conn.close()


# ---------------------------------------------------------------------------
# Version migration flow
# ---------------------------------------------------------------------------
def _is_fresh_install() -> bool:
    try:
        conn = get_connection("sqli_ctf_meta")
        cur = conn.cursor()
        cur.execute("SELECT current_level, solved FROM progress WHERE id = 1")
        row = cur.fetchone()
        cur.close()
        conn.close()
        return (
            row is None
            or (int(row[0] or 1) <= 1 and (not row[1] or str(row[1]).strip() == ""))
        )
    except Exception:
        return True


def ask_user_confirm_migration(
    stored: str | None,
    current: str,
    migs: list[dict],
    affected: set[int],
    full_reset: bool,
) -> bool:
    if os.getenv("SQLI_CTF_FORCE_RESET", "").strip() in ("1", "true", "yes"):
        print("[!] SQLI_CTF_FORCE_RESET=1 → applying migration")
        return True
    if os.getenv("SQLI_CTF_SKIP_RESET", "").strip() in ("1", "true", "yes"):
        print("[!] SQLI_CTF_SKIP_RESET=1 → skipping migration")
        return False

    stored_label = stored if stored is not None else "(none)"
    print()
    print("!" * 56)
    print("  GAME UPDATE DETECTED")
    print(f"  Database version : {stored_label}")
    print(f"  App version      : {current}")
    print()
    if full_reset:
        print("  No selective migrations registered for this jump.")
        print("  Applying FULL reset:")
        print("    • New flags for all 60 levels")
        print("    • flags.json rewritten")
        print("    • All progress + attack history cleared")
    else:
        print("  Pending migrations:")
        for m in migs:
            note = m.get("note") or ""
            lv = m.get("levels")
            print(f"    • v{m['version']}: levels {lv}" + (f" — {note}" if note else ""))
        print()
        print(f"  Affected levels ({len(affected)}): {sorted(affected)}")
        print("  Will:")
        print("    • Generate new flags only for those levels")
        print("    • Update flags.json")
        print("    • Mark those levels unsolved (other progress kept)")
        print("    • Clear attack history for those levels")
    print("!" * 56)

    if not sys.stdin.isatty():
        print("[!] Non-interactive session — applying migration automatically.")
        print("    Set SQLI_CTF_SKIP_RESET=1 to skip.")
        return True

    while True:
        ans = input("Apply this update? [y/N]: ").strip().lower()
        if ans in ("y", "yes"):
            return True
        if ans in ("n", "no", ""):
            return False
        print("Please answer y or n.")


def apply_full_reset() -> dict:
    print("[*] Full reset …")
    flags = generate_flags()
    for i in range(1, TOTAL_LEVELS + 1):
        update_level_flag(i, flags[i])
        if i % 10 == 0:
            print(f"[+] Flags updated for levels 1–{i}")
    reset_progress_and_history()
    set_stored_version(APP_VERSION)
    print("[+] Full reset complete")
    return flags


def apply_selective_migration(affected: set[int], existing_flags: dict | None = None) -> dict:
    print(f"[*] Selective migration for levels: {sorted(affected)}")
    flags = patch_flags(affected, existing_flags)
    for i in sorted(affected):
        update_level_flag(i, flags[i])
    unsolve_levels(affected)
    set_stored_version(APP_VERSION)
    print("[+] Selective migration complete")
    return flags


def check_and_handle_version() -> dict | None:
    """
    Returns updated flags dict if migration ran, else None.
    Caller should still ensure all level DB structures exist.
    """
    stored = get_stored_version()

    if stored is not None and version_eq(stored, APP_VERSION):
        print(f"[+] App version OK ({APP_VERSION})")
        return None

    # Brand-new install: no progress → just stamp version, no scary prompt
    if stored is None and _is_fresh_install():
        print(f"[+] First setup — setting version to {APP_VERSION}")
        set_stored_version(APP_VERSION)
        return None

    # App older than DB (downgrade) — do nothing destructive
    if stored is not None and version_lt(APP_VERSION, stored):
        print(
            f"[!] App version {APP_VERSION} is older than DB {stored}. "
            "No migration applied."
        )
        return None

    migs = pending_migrations(stored, APP_VERSION)
    affected = levels_from_migrations(migs)

    # Version changed but nothing listed in MIGRATIONS for this jump
    # → safe default: full reset (so a forgotten migration entry still
    #   invalidates old flags). Set MIGRATIONS properly to avoid this.
    full_reset = not affected

    if not ask_user_confirm_migration(stored, APP_VERSION, migs, affected, full_reset):
        print("[!] Migration skipped. DB version left unchanged.")
        return None

    if full_reset:
        return apply_full_reset()

    existing = None
    if os.path.exists(FLAGS_FILE):
        try:
            with open(FLAGS_FILE, "r") as f:
                raw = json.load(f)
            existing = {int(k): v for k, v in raw.items() if str(k).isdigit()}
        except Exception:
            existing = None
    return apply_selective_migration(affected, existing)


def main():
    print("=" * 50)
    print("  SQLi CTF — Database Setup")
    print(f"  Version: {APP_VERSION}")
    print("=" * 50)

    wait_for_db()
    create_meta_db()

    migrated_flags = check_and_handle_version()
    flags = migrated_flags if migrated_flags is not None else load_or_create_flags()

    for i in range(1, TOTAL_LEVELS + 1):
        create_level_db(i, flags[i])
        if i % 10 == 0:
            print(f"[+] Levels 1–{i} ready")

    if get_stored_version() is None:
        set_stored_version(APP_VERSION)

    print("[+] All 60 level databases ready")
    if migrated_flags is not None:
        print("[+] Setup complete (version migration applied)")
    else:
        print("[+] Setup complete")
    print("=" * 50)


if __name__ == "__main__":
    main()
