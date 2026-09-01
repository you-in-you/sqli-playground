#!/usr/bin/env python3
"""
SQLi CTF — Database Setup / Installer

Creates 60 isolated databases + meta DB with random unique flags.

Usage
-----
  python3 scripts/setup_db.py              # ensure (default, used by run.sh)
  python3 scripts/setup_db.py ensure       # same as default
  python3 scripts/setup_db.py install      # wipe lab DBs, recreate, new flags
  python3 scripts/setup_db.py reinstall    # same as install (explicit rebuild)
  python3 scripts/setup_db.py status       # show version / DB / progress
  python3 scripts/setup_db.py --help

Environment
-----------
  SQLI_CTF_FORCE_RESET=1   auto-confirm migrations / destructive ops
  SQLI_CTF_SKIP_RESET=1    skip migrations
  SQLI_CTF_CONFIG=path     override config.json
"""

from __future__ import annotations

import argparse
import json
import os
import secrets
import sys
import time
from pathlib import Path
from urllib.error import URLError, HTTPError
from urllib.request import Request, urlopen

try:
    import pymysql
except ImportError:  # allow --help without deps installed
    pymysql = None  # type: ignore

ROOT = Path(__file__).resolve().parent.parent
_cfg_path = Path(os.getenv("SQLI_CTF_CONFIG", str(ROOT / "config.json")))
_cfg: dict = {}
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

# Bump when shipping breaking level/handler changes and list them in MIGRATIONS.
APP_VERSION = "1.0.0"
REPO_URL = "https://github.com/you-in-you/sqli-playground"

# Remote version manifest (branch: main). Override with SQLI_CTF_VERSION_URL.
VERSION_CHECK_URL = str(
    _get(
        "VERSION_CHECK_URL",
        ""
        # "https://raw.githubusercontent.com/you-in-you/sqli-playground/main/version/version.json",
    )
)
VERSION_CHECK_TIMEOUT = float(_get("VERSION_CHECK_TIMEOUT", 5))

MIGRATIONS: list[dict] = [
    # Example:
    # {
    #     "version": "1.0.1",
    #     "levels": [16, 17, 18],
    #     "note": "Reworked medium levels",
    # },
]


# ─────────────────────────────────────────────────────────────────────────────
# Terminal UI helpers
# ─────────────────────────────────────────────────────────────────────────────
class UI:
    """Minimal ANSI UI (disables color when not a TTY)."""

    def __init__(self) -> None:
        self.color = sys.stdout.isatty() and os.getenv("NO_COLOR") is None

    def _c(self, code: str, text: str) -> str:
        if not self.color:
            return text
        return f"\033[{code}m{text}\033[0m"

    def bold(self, t: str) -> str:
        return self._c("1", t)

    def dim(self, t: str) -> str:
        return self._c("2", t)

    def green(self, t: str) -> str:
        return self._c("32", t)

    def yellow(self, t: str) -> str:
        return self._c("33", t)

    def red(self, t: str) -> str:
        return self._c("31", t)

    def cyan(self, t: str) -> str:
        return self._c("36", t)

    def magenta(self, t: str) -> str:
        return self._c("35", t)

    def banner(self, subtitle: str = "") -> None:
        line = "─" * 56
        print()
        print(self.cyan(line))
        print(self.bold(self.cyan("  SQLi Playground")) + self.dim(f"  v{APP_VERSION}"))
        print(self.dim("  Local SQL Injection CTF lab — database toolkit"))
        if subtitle:
            print(self.yellow(f"  › {subtitle}"))
        print(self.cyan(line))
        print()

    def section(self, title: str) -> None:
        print(self.bold(f"  ▸ {title}"))

    def ok(self, msg: str) -> None:
        print(f"  {self.green('✔')}  {msg}")

    def info(self, msg: str) -> None:
        print(f"  {self.cyan('•')}  {msg}")

    def warn(self, msg: str) -> None:
        print(f"  {self.yellow('!')}  {msg}")

    def err(self, msg: str) -> None:
        print(f"  {self.red('✖')}  {msg}")

    def step(self, msg: str) -> None:
        print(f"  {self.dim('…')}  {msg}")

    def kv(self, key: str, value: str) -> None:
        print(f"     {self.dim(key.ljust(16))} {value}")

    def footer(self, msg: str = "Done.") -> None:
        print()
        print(self.green(f"  {msg}"))
        print()


ui = UI()


# ─────────────────────────────────────────────────────────────────────────────
# Semver helpers
# ─────────────────────────────────────────────────────────────────────────────
def parse_version(v: str) -> tuple[int, ...]:
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
    start = from_version if from_version is not None else "0.0.0"
    pending = []
    for m in MIGRATIONS:
        mv = str(m.get("version", "")).strip()
        if not mv:
            continue
        if version_lt(start, mv) and version_le(mv, to_version):
            pending.append(m)
    pending.sort(key=lambda m: parse_version(str(m["version"])))
    return pending


def levels_from_migrations(migs: list[dict]) -> set[int]:
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
                return set(range(1, TOTAL_LEVELS + 1))
            if 1 <= n <= TOTAL_LEVELS:
                out.add(n)
    return out


# ─────────────────────────────────────────────────────────────────────────────
# DB helpers
# ─────────────────────────────────────────────────────────────────────────────
def wait_for_db(retries: int = 30, delay: float = 2.0) -> None:
    ui.section("Database connection")
    for i in range(retries):
        try:
            conn = pymysql.connect(
                host=DB_HOST,
                port=DB_PORT,
                user=DB_USER,
                password=DB_PASS,
                charset="utf8mb4",
            )
            conn.close()
            ui.ok(f"Connected to {DB_HOST}:{DB_PORT} as {DB_USER}")
            return
        except Exception as e:
            ui.step(f"Waiting ({i + 1}/{retries}) — {e}")
            time.sleep(delay)
    ui.err("Database not available")
    raise RuntimeError("Database not available")


def gen_flag(level_id: int) -> str:
    token = secrets.token_hex(4)
    return f"CTF{{sql1_l{level_id:02d}_{token}}}"


def get_connection(database: str | None = None):
    kwargs = dict(
        host=DB_HOST,
        port=DB_PORT,
        user=DB_USER,
        password=DB_PASS,
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
    with open(FLAGS_FILE, "w", encoding="utf-8") as f:
        json.dump({str(k): v for k, v in sorted(flags.items())}, f, indent=2)
    ui.ok(f"Wrote {len(flags)} flags → {FLAGS_FILE}")


def generate_flags() -> dict:
    flags = {i: gen_flag(i) for i in range(1, TOTAL_LEVELS + 1)}
    save_flags(flags)
    ui.ok(f"Generated {TOTAL_LEVELS} unique flags")
    return flags


def load_or_create_flags(force_new: bool = False) -> dict:
    if force_new:
        return generate_flags()

    if os.path.exists(FLAGS_FILE):
        with open(FLAGS_FILE, "r", encoding="utf-8") as f:
            raw = json.load(f)
        flags = {int(k): v for k, v in raw.items() if str(k).isdigit()}
        if len(flags) >= TOTAL_LEVELS:
            ui.ok(f"Loaded existing flags from {FLAGS_FILE}")
            return flags
        ui.warn("flags.json incomplete — regenerating")

    return generate_flags()


def patch_flags(level_ids: set[int], existing: dict | None = None) -> dict:
    flags = dict(existing) if existing else {}
    if not flags and os.path.exists(FLAGS_FILE):
        try:
            with open(FLAGS_FILE, "r", encoding="utf-8") as f:
                raw = json.load(f)
            flags = {int(k): v for k, v in raw.items() if str(k).isdigit()}
        except Exception:
            flags = {}

    for i in range(1, TOTAL_LEVELS + 1):
        if i not in flags:
            flags[i] = gen_flag(i)

    for i in sorted(level_ids):
        flags[i] = gen_flag(i)
        ui.info(f"New flag for level {i:02d}")

    save_flags(flags)
    return flags


def list_lab_databases() -> list[str]:
    """Return names of sqli_level_* and sqli_ctf_meta databases."""
    conn = get_connection()
    cur = conn.cursor()
    cur.execute(
        "SELECT schema_name FROM information_schema.schemata "
        "WHERE schema_name = 'sqli_ctf_meta' OR schema_name LIKE 'sqli_level_%' "
        "ORDER BY schema_name"
    )
    rows = [r[0] for r in cur.fetchall()]
    cur.close()
    conn.close()
    return rows


def drop_lab_databases() -> int:
    """DROP every lab database (meta + all level DBs). Returns count dropped."""
    dbs = list_lab_databases()
    if not dbs:
        ui.info("No lab databases to drop")
        return 0

    conn = get_connection()
    cur = conn.cursor()
    for name in dbs:
        cur.execute(f"DROP DATABASE IF EXISTS `{name}`")
        ui.step(f"Dropped `{name}`")
    cur.close()
    conn.close()
    ui.ok(f"Dropped {len(dbs)} database(s)")
    return len(dbs)


def create_meta_db() -> None:
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("CREATE DATABASE IF NOT EXISTS sqli_ctf_meta")
    cur.execute("USE sqli_ctf_meta")
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS progress (
            id INT PRIMARY KEY DEFAULT 1,
            current_level INT NOT NULL DEFAULT 1,
            solved TEXT NOT NULL DEFAULT ''
        )
        """
    )
    cur.execute(
        """
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
        """
    )
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS app_version (
            id INT PRIMARY KEY DEFAULT 1,
            version VARCHAR(32) NOT NULL
        )
        """
    )
    cur.execute("SELECT COUNT(*) FROM progress")
    if cur.fetchone()[0] == 0:
        cur.execute(
            "INSERT INTO progress (id, current_level, solved) VALUES (1, 1, '')"
        )
    cur.close()
    conn.close()
    ui.ok("Meta database ready (progress, history, version)")


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
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS app_version (
            id INT PRIMARY KEY DEFAULT 1,
            version VARCHAR(32) NOT NULL
        )
        """
    )
    cur.execute(
        "INSERT INTO app_version (id, version) VALUES (1, %s) "
        "ON DUPLICATE KEY UPDATE version = VALUES(version)",
        (version,),
    )
    cur.close()
    conn.close()
    ui.ok(f"Stored app version → {version}")


def reset_progress() -> None:
    conn = get_connection("sqli_ctf_meta")
    cur = conn.cursor()
    cur.execute(
        "UPDATE progress SET current_level = 1, solved = '' WHERE id = 1"
    )
    cur.execute("TRUNCATE TABLE attack_history")
    cur.close()
    conn.close()
    ui.ok("Progress reset + attack history cleared")


def unsolve_levels(level_ids: set[int]) -> None:
    if not level_ids:
        return
    conn = get_connection("sqli_ctf_meta")
    cur = conn.cursor()
    cur.execute("SELECT solved FROM progress WHERE id = 1")
    row = cur.fetchone()
    solved_raw = (row[0] or "") if row else ""
    solved = set()
    for part in solved_raw.split(","):
        part = part.strip()
        if part.isdigit():
            solved.add(int(part))
    solved -= level_ids
    new_solved = ",".join(str(x) for x in sorted(solved))
    cur.execute("UPDATE progress SET solved = %s WHERE id = 1", (new_solved,))
    for lv in level_ids:
        cur.execute("DELETE FROM attack_history WHERE level_id = %s", (lv,))
    cur.close()
    conn.close()
    ui.ok(f"Unsolved {len(level_ids)} level(s); history trimmed")


def update_level_flag(level_id: int, flag: str) -> None:
    db_name = f"sqli_level_{level_id:02d}"
    try:
        conn = get_connection(db_name)
    except Exception:
        return
    cur = conn.cursor()
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS secrets (
            id INT AUTO_INCREMENT PRIMARY KEY,
            name VARCHAR(64) NOT NULL,
            flag VARCHAR(128) NOT NULL
        )
        """
    )
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


def create_level_db(level_id: int, flag: str) -> None:
    db_name = f"sqli_level_{level_id:02d}"
    conn = get_connection()
    cur = conn.cursor()
    cur.execute(f"CREATE DATABASE IF NOT EXISTS `{db_name}`")
    cur.execute(f"USE `{db_name}`")

    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INT AUTO_INCREMENT PRIMARY KEY,
            username VARCHAR(64) NOT NULL,
            password VARCHAR(128) NOT NULL,
            email VARCHAR(128) DEFAULT NULL,
            role VARCHAR(32) DEFAULT 'user'
        )
        """
    )
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS secrets (
            id INT AUTO_INCREMENT PRIMARY KEY,
            name VARCHAR(64) NOT NULL,
            flag VARCHAR(128) NOT NULL
        )
        """
    )

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


def ensure_all_level_dbs(flags: dict) -> None:
    ui.section(f"Level databases (1–{TOTAL_LEVELS})")
    for i in range(1, TOTAL_LEVELS + 1):
        create_level_db(i, flags[i])
        if i % 10 == 0:
            ui.ok(f"Levels 1–{i} ready")
    ui.ok(f"All {TOTAL_LEVELS} level databases ready")


# ─────────────────────────────────────────────────────────────────────────────
# Version migration
# ─────────────────────────────────────────────────────────────────────────────
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


def _env_force() -> bool:
    return os.getenv("SQLI_CTF_FORCE_RESET", "").strip().lower() in ("1", "true", "yes")


def _env_skip() -> bool:
    return os.getenv("SQLI_CTF_SKIP_RESET", "").strip().lower() in ("1", "true", "yes")


def confirm(prompt: str, default_no: bool = True) -> bool:
    if _env_force():
        ui.warn("SQLI_CTF_FORCE_RESET=1 → auto-confirm")
        return True
    if _env_skip():
        ui.warn("SQLI_CTF_SKIP_RESET=1 → auto-skip")
        return False
    if not sys.stdin.isatty():
        ui.warn("Non-interactive session — confirming automatically")
        ui.info("Set SQLI_CTF_SKIP_RESET=1 to skip destructive actions")
        return True

    suffix = " [y/N]: " if default_no else " [Y/n]: "
    while True:
        ans = input(f"  {prompt}{suffix}").strip().lower()
        if ans in ("y", "yes"):
            return True
        if ans in ("n", "no"):
            return False
        if ans == "":
            return not default_no
        print("     Please answer y or n.")


def ask_user_confirm_migration(
    stored: str | None,
    current: str,
    migs: list[dict],
    affected: set[int],
    full_reset: bool,
) -> bool:
    stored_label = stored if stored is not None else "(none)"
    print()
    ui.warn("Game update detected")
    ui.kv("DB version", stored_label)
    ui.kv("App version", current)
    print()
    if full_reset:
        ui.info("No selective migrations for this jump → FULL reset:")
        ui.info("  • New flags for all 60 levels")
        ui.info("  • flags.json rewritten")
        ui.info("  • Progress + attack history cleared")
    else:
        ui.info("Pending migrations:")
        for m in migs:
            note = m.get("note") or ""
            lv = m.get("levels")
            extra = f" — {note}" if note else ""
            print(f"       • v{m['version']}: levels {lv}{extra}")
        ui.info(f"Affected levels ({len(affected)}): {sorted(affected)}")
        ui.info("Will refresh flags + unsolve only those levels")
    print()
    return confirm("Apply this update?")


def apply_full_reset() -> dict:
    ui.section("Full flag / progress reset")
    flags = generate_flags()
    for i in range(1, TOTAL_LEVELS + 1):
        update_level_flag(i, flags[i])
        if i % 10 == 0:
            ui.ok(f"Flags updated for levels 1–{i}")
    reset_progress()
    set_stored_version(APP_VERSION)
    return flags


def apply_selective_migration(affected: set[int], existing: dict | None) -> dict:
    ui.section(f"Selective migration ({len(affected)} levels)")
    flags = patch_flags(affected, existing)
    for i in sorted(affected):
        update_level_flag(i, flags[i])
    unsolve_levels(affected)
    set_stored_version(APP_VERSION)
    return flags


def check_and_handle_version() -> dict | None:
    stored = get_stored_version()

    if stored is not None and version_eq(stored, APP_VERSION):
        ui.ok(f"App version OK ({APP_VERSION})")
        return None

    if stored is None and _is_fresh_install():
        ui.info(f"First setup — stamping version {APP_VERSION}")
        set_stored_version(APP_VERSION)
        return None

    if stored is not None and version_lt(APP_VERSION, stored):
        ui.warn(
            f"App version {APP_VERSION} is older than DB {stored}. "
            "No migration applied."
        )
        return None

    migs = pending_migrations(stored, APP_VERSION)
    affected = levels_from_migrations(migs)
    full_reset = not affected

    if not ask_user_confirm_migration(stored, APP_VERSION, migs, affected, full_reset):
        ui.warn("Migration skipped. DB version left unchanged.")
        return None

    if full_reset:
        return apply_full_reset()

    existing = None
    if os.path.exists(FLAGS_FILE):
        try:
            with open(FLAGS_FILE, "r", encoding="utf-8") as f:
                raw = json.load(f)
            existing = {int(k): v for k, v in raw.items() if str(k).isdigit()}
        except Exception:
            existing = None
    return apply_selective_migration(affected, existing)


# ─────────────────────────────────────────────────────────────────────────────
# Commands
# ─────────────────────────────────────────────────────────────────────────────

def fetch_remote_version(timeout: float | None = None) -> dict | None:
    """
    Download version/version.json from GitHub.
    Returns parsed dict or None on any failure (offline / 404 / bad JSON).
    """
    if timeout is None:
        timeout = VERSION_CHECK_TIMEOUT
    url = VERSION_CHECK_URL
    # Allow disabling: SQLI_CTF_SKIP_UPDATE=1
    if os.getenv("SQLI_CTF_SKIP_UPDATE", "").strip().lower() in ("1", "true", "yes"):
        return None
    try:
        req = Request(
            url,
            headers={
                "User-Agent": f"sqli-playground-setup/{APP_VERSION}",
                "Accept": "application/json",
            },
            method="GET",
        )
        with urlopen(req, timeout=timeout) as resp:
            raw = resp.read().decode("utf-8", errors="replace")
        data = json.loads(raw)
        if not isinstance(data, dict) or "version" not in data:
            return None
        return data
    except (URLError, HTTPError, TimeoutError, json.JSONDecodeError, ValueError, OSError):
        return None


def check_remote_update(quiet: bool = False) -> bool:
    """
    Compare APP_VERSION with remote version.json.
    If remote is newer, show changelog and ask user to git pull.
    Returns True if an update is available.
    """
    if not quiet:
        ui.section("Update check")
    remote = fetch_remote_version()
    if remote is None:
        if not quiet:
            ui.info("Could not reach GitHub version file (offline or not published yet)")
        return False

    remote_ver = str(remote.get("version", "")).strip()
    if not remote_ver:
        if not quiet:
            ui.info("Remote version.json has no version field")
        return False

    local = APP_VERSION
    if version_eq(local, remote_ver):
        if not quiet:
            ui.ok(f"Up to date (local {local} = remote {remote_ver})")
        return False

    if version_lt(remote_ver, local):
        # Local is ahead of published remote (dev build)
        if not quiet:
            ui.info(f"Local {local} is newer than remote {remote_ver}")
        return False

    # remote > local → update available
    print()
    ui.warn(f"New version available: {remote_ver}  (you have {local})")
    released = remote.get("released") or remote.get("date") or ""
    if released:
        ui.kv("Released", str(released))
    repo = remote.get("url") or REPO_URL
    ui.kv("Repo", str(repo))
    print()

    changes = remote.get("changes") or remote.get("changelog") or []
    if isinstance(changes, str):
        changes = [changes]
    if changes:
        ui.section("What changed")
        for item in changes:
            print(f"       • {item}")
        print()

    notes = remote.get("notes") or remote.get("note") or ""
    if notes:
        ui.info(str(notes))
        print()

    ui.warn("Update this install with:")
    print(self_git_pull_hint())
    print()

    if sys.stdin.isatty() and not _env_skip():
        # default Yes — setup continues; user was already told to pull
        confirm("Continue setup with the current version?", default_no=False)
    else:
        ui.info("Continuing with current version (pull when you can)")
    return True


def self_git_pull_hint() -> str:
    return (
        "       cd /path/to/sqli-playground\n"
        "       git pull origin main\n"
        "       ./run.sh ensure\n"
        "       # or full wipe after a big update:\n"
        "       ./run.sh install"
    )


def cmd_status() -> int:
    ui.banner("status")
    check_remote_update()
    ui.section("Configuration")
    ui.kv("Host", f"{DB_HOST}:{DB_PORT}")
    ui.kv("User", DB_USER)
    ui.kv("Flags file", FLAGS_FILE)
    ui.kv("App version", APP_VERSION)
    print()

    try:
        wait_for_db(retries=5, delay=1)
    except RuntimeError:
        return 1

    dbs = list_lab_databases()
    level_dbs = [d for d in dbs if d.startswith("sqli_level_")]
    has_meta = "sqli_ctf_meta" in dbs

    ui.section("Databases")
    ui.kv("Meta DB", "yes" if has_meta else "no")
    ui.kv("Level DBs", f"{len(level_dbs)} / {TOTAL_LEVELS}")
    print()

    if has_meta:
        stored = get_stored_version()
        ui.section("Progress")
        ui.kv("DB version", stored or "(none)")
        try:
            conn = get_connection("sqli_ctf_meta")
            cur = conn.cursor()
            cur.execute("SELECT current_level, solved FROM progress WHERE id = 1")
            row = cur.fetchone()
            if row:
                solved = [x for x in (row[1] or "").split(",") if x.strip()]
                ui.kv("Current level", str(row[0]))
                ui.kv("Solved", f"{len(solved)} levels")
            cur.execute("SELECT COUNT(*) FROM attack_history")
            ui.kv("History rows", str(cur.fetchone()[0]))
            cur.close()
            conn.close()
        except Exception as e:
            ui.warn(f"Could not read progress: {e}")
    else:
        ui.warn("Meta DB missing — run: python3 scripts/setup_db.py install")

    if os.path.exists(FLAGS_FILE):
        try:
            raw = json.loads(Path(FLAGS_FILE).read_text(encoding="utf-8"))
            ui.kv("flags.json", f"{len(raw)} entries")
        except Exception:
            ui.kv("flags.json", "present (unreadable)")
    else:
        ui.kv("flags.json", "missing")

    ui.footer("Status complete.")
    return 0


def cmd_ensure() -> int:
    """Idempotent setup used by run.sh — no wipe."""
    ui.banner("ensure (non-destructive)")
    check_remote_update()
    wait_for_db()
    ui.section("Meta")
    create_meta_db()

    migrated = check_and_handle_version()
    flags = migrated if migrated is not None else load_or_create_flags()
    ensure_all_level_dbs(flags)

    if get_stored_version() is None:
        set_stored_version(APP_VERSION)

    if migrated is not None:
        ui.footer("Setup complete (migration applied).")
    else:
        ui.footer("Setup complete.")
    return 0


def cmd_install(force: bool = False) -> int:
    """
    Destructive install / reinstall:
      • DROP all sqli_level_* and sqli_ctf_meta
      • Remove flags.json
      • Recreate meta + 60 level DBs with fresh flags
      • Reset progress
    """
    label = "reinstall" if force else "install"
    ui.banner(f"{label} (destructive)")
    check_remote_update()
    print()
    ui.info(f"Welcome back to SQLi Playground — {REPO_URL}")
    ui.warn("This will DELETE all lab databases, tables, flags, and progress.")
    ui.info("Databases matching: sqli_ctf_meta, sqli_level_*")
    ui.info("A clean lab will be created right after the wipe.")
    print()

    if not confirm(f"Really {label} everything?", default_no=True):
        ui.warn("Aborted — nothing was changed.")
        return 2

    wait_for_db()

    ui.section("Wipe")
    drop_lab_databases()
    if os.path.exists(FLAGS_FILE):
        os.remove(FLAGS_FILE)
        ui.ok(f"Removed {FLAGS_FILE}")
    else:
        ui.info("No flags.json to remove")

    ui.section("Rebuild")
    create_meta_db()
    flags = generate_flags()
    ensure_all_level_dbs(flags)
    set_stored_version(APP_VERSION)

    print()
    ui.ok(f"{label.capitalize()} complete — fresh lab is ready.")
    ui.info("Start the lab with:  ./run.sh")
    ui.info(f"Project: {REPO_URL}")
    ui.footer("Happy hacking.")
    return 0


def cmd_uninstall() -> int:
    """
    Remove the lab completely from MySQL/MariaDB:
      • DROP sqli_ctf_meta + all sqli_level_*
      • Delete local flags.json
    Does NOT delete the git checkout / source code.
    """
    ui.banner("uninstall")
    print()
    ui.warn("This removes the lab data from your database server.")
    ui.info("Will DROP: sqli_ctf_meta, sqli_level_01 … sqli_level_60")
    ui.info(f"Will delete local flags file: {FLAGS_FILE}")
    ui.info("Source code in this folder is kept (git repo stays).")
    print()

    if not confirm("Uninstall the lab and wipe all challenge data?", default_no=True):
        ui.warn("Aborted — lab is still installed.")
        ui.info("Come back whenever you like.")
        return 2

    try:
        wait_for_db()
    except RuntimeError:
        ui.warn("Database unreachable — will still try to remove local flags.json")
    else:
        ui.section("Removing databases")
        n = drop_lab_databases()
        if n == 0:
            ui.info("No lab databases were present")

    ui.section("Local files")
    if os.path.exists(FLAGS_FILE):
        try:
            os.remove(FLAGS_FILE)
            ui.ok(f"Removed {FLAGS_FILE}")
        except OSError as e:
            ui.err(f"Could not remove flags.json: {e}")
    else:
        ui.info("No flags.json to remove")

    print()
    ui.ok("Lab data removed.")
    print()
    ui.info("Thanks for playing SQLi Playground.")
    ui.info("Come back later anytime:")
    print(f"       {REPO_URL}")
    print()
    ui.info("To reinstall from this folder:")
    print("       ./run.sh install")
    print("       ./run.sh")
    print()
    ui.footer("See you around.")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="setup_db.py",
        description="SQLi Playground database toolkit",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
commands:
  ensure      Create missing DBs/tables; keep flags & progress (default)
  install     DROP lab DBs + flags, then full rebuild
  reinstall   Alias of install
  uninstall   DROP lab DBs + flags only (no rebuild) — come back later
  status      Show version, databases, progress

examples:
  python3 scripts/setup_db.py
  python3 scripts/setup_db.py status
  python3 scripts/setup_db.py install
  python3 scripts/setup_db.py uninstall
  SQLI_CTF_FORCE_RESET=1 python3 scripts/setup_db.py reinstall
""".rstrip(),
    )
    p.add_argument(
        "command",
        nargs="?",
        default="ensure",
        choices=["ensure", "install", "reinstall", "uninstall", "status"],
        help="action to run (default: ensure)",
    )
    p.add_argument(
        "-y",
        "--yes",
        action="store_true",
        help="skip confirmation prompts (same as SQLI_CTF_FORCE_RESET=1)",
    )
    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.yes:
        os.environ["SQLI_CTF_FORCE_RESET"] = "1"

    if pymysql is None:
        print("Missing dependency: pymysql — pip install -r requirements.txt")
        return 1

    try:
        if args.command == "status":
            return cmd_status()
        if args.command == "install":
            return cmd_install(force=False)
        if args.command == "reinstall":
            return cmd_install(force=True)
        if args.command == "uninstall":
            return cmd_uninstall()
        # ensure (default)
        return cmd_ensure()
    except KeyboardInterrupt:
        print()
        ui.warn("Interrupted.")
        return 130
    except RuntimeError as e:
        ui.err(str(e))
        return 1
    except Exception as e:
        # pymysql.Error is a subclass of Exception when pymysql is available
        if pymysql is not None and isinstance(e, pymysql.Error):
            ui.err(f"MySQL error: {e}")
            return 1
        raise


if __name__ == "__main__":
    raise SystemExit(main())
