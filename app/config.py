import json
import os
from pathlib import Path

# Project root: .../sqli-ctf/
ROOT = Path(__file__).resolve().parent.parent
CONFIG_FILE = Path(os.getenv("SQLI_CTF_CONFIG", str(ROOT / "config.json")))


def _load_file_config() -> dict:
    if CONFIG_FILE.is_file():
        try:
            with open(CONFIG_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
            if isinstance(data, dict):
                return data
        except Exception:
            pass
    return {}


_file = _load_file_config()


def _get(key: str, default):
    # Environment overrides config.json
    if key in os.environ:
        return os.environ[key]
    if key in _file:
        return _file[key]
    return default


DB_HOST = str(_get("DB_HOST", "127.0.0.1"))
DB_PORT = int(_get("DB_PORT", 3306))
DB_USER = str(_get("DB_USER", "ctf"))
DB_PASS = str(_get("DB_PASS", "ctfpass"))
SECRET_KEY = str(_get("SECRET_KEY", "dev-secret-change-me"))
HOST = str(_get("HOST", "0.0.0.0"))
PORT = int(_get("PORT", 5000))

# flags.json only used by setup_db.py to seed DBs (optional path)
FLAGS_FILE = str(_get("FLAGS_FILE", str(ROOT / "flags.json")))
TOTAL_LEVELS = 60

# App release version (keep in sync with version/version.json when publishing)
APP_VERSION = str(_get("APP_VERSION", "1.0.0"))
REPO_URL = str(_get("REPO_URL", "https://github.com/you-in-you/sqli-playground"))
VERSION_CHECK_URL = str(
    _get(
        "VERSION_CHECK_URL",
        "https://raw.githubusercontent.com/you-in-you/sqli-playground/main/version/version.json",
    )
)
VERSION_CHECK_TIMEOUT = float(_get("VERSION_CHECK_TIMEOUT", 2.5))
