"""
All 60 level attack handlers — intentionally vulnerable SQLi challenges.
Each level uses its own isolated database: sqli_level_XX
"""

from __future__ import annotations

import re
import time
from typing import Any
import urllib.parse
import random
from app.db import get_conn, level_db


def _run(level_id: int, query: str) -> dict[str, Any]:
    """Execute raw SQL and return structured result (leaks errors on purpose)."""
    db = level_db(level_id)
    try:
        conn = get_conn(db)
        try:
            with conn.cursor() as cur:
                cur.execute(query)
                # Prefer fetchall for SELECT; for others rowcount
                try:
                    rows = cur.fetchall()
                except Exception:
                    rows = []
                return {
                    "ok": True if rows else False,
                    "message": "Query executed",
                    "Query": f"Query: {query}", 
                    "raw": f"Result: {rows if rows else '(no rows / non-select)'}",
                    "rows": rows,
                }
        finally:
            conn.close()
    except Exception as e:
        return {
            "ok": False,
            "message": "Database error",
            "Query": f"Query: {query}",
            "raw": f"Error: {type(e).__name__}: {e}",
            "error": str(e),
        }


def _blocked(msg: str) -> dict[str, Any]:
    return {"ok": False, "message": "Blocked", "raw": msg}



def _get_flag(level_id: int) -> str:
    """Fetch flag from level DB (parameterized path via fixed query)."""
    f = _run(level_id, "SELECT flag FROM secrets WHERE name = 'level_flag' LIMIT 1")
    if not f.get("rows"):
        f = _run(level_id, "SELECT flag FROM secrets LIMIT 1")
    if f.get("rows"):
        return str(f["rows"][0].get("flag") or "")
    return ""


def _rows_blob(rows) -> str:
    if not rows:
        return ""
    return " ".join(str(v) for row in rows for v in row.values())


# ───────────────────────── Level 01 ─────────────────────────
def handle_01(p: dict) -> dict:
    u, pw = p.get("username", ""), p.get("password", "")
    q = f"SELECT id, username, role FROM users WHERE username = '{u}' AND password = '{pw}'"
    r = _run(1, q)

    if r.get("rows"):
        user = r["rows"][0]
        msg = f"Welcome, {user.get('username')} ({user.get('role')})"
        
        if user.get("username") == "admin" or user.get("role") == "admin":
            f = _run(1, "SELECT flag FROM secrets LIMIT 1")
            msg += f" - Flag: {f['rows'][0]['flag']}" if f.get("rows") else ""

        r["message"], r["ok"] = msg, True
    else:
        r["message"], r["ok"] = "Login failed.", False

    return r

# ───────────────────────── Level 02 — Bypassing Logic without Comments ─────────────────────────
def handle_02(p: dict) -> dict:
    u = p.get("username", "")
    
    if "--" in u or "/*" in u or "#" in u:
        return {"message": "Comments are blocked!", "ok": False}

    q = f"SELECT id, username, email FROM users WHERE username = '{u}' AND role = 'user'"
    r = _run(2, q)
    rows = r.get("rows", [])

    if len(rows) == 1 and rows[0].get("username") == "admin":
        f = _run(2, "SELECT flag FROM secrets LIMIT 1")
        
        if f.get("rows"):
            flag_val = f["rows"][0].get("flag")
            r["message"] = f"Admin bypass successful! Flag: {flag_val}"
            r["ok"] = True
        else:
            r["message"] = "Admin bypass successful! But secrets table is empty."
            r["ok"] = False
    elif len(rows) > 1:
        r["message"] = "Too many rows returned! Do not dump the table, target only Admin."
        r["ok"] = False
    else:
        r["message"] = "User found, but not admin (or no user found)."
        r["ok"] = False

    return r

# ───────────────────────── Level 03 — Numeric Logic & Operator Bypass ─────────────────────────
def handle_03(p: dict) -> dict:
    uid = str(p.get("username", "0"))

    if any(c in uid for c in ["--", "/*", "#", "'", '"']):
        return {"message": "No comments or quotes allowed!", "ok": False}

    q = f"SELECT id, username, role FROM users WHERE id = {uid} AND role != 'admin'"
    r = _run(3, q)

    rows = r.get("rows", [])

    if len(rows) == 1 and rows[0].get("username") == "admin":
        f = _run(3, "SELECT flag FROM secrets LIMIT 1")
        if f.get("rows"):
            r["message"] = f"Numeric SQLi success! Flag: {f['rows'][0]['flag']}"
            r["ok"] = True
        else:
            r["message"] = "Admin found, but secrets table is empty."
            r["ok"] = False
    elif len(rows) > 1:
        r["message"] = "Too many rows returned! You dumped the whole table, focus only on Admin."
        r["ok"] = False
    else:
        r["message"] = "Access denied or user not found."
        r["ok"] = False

    return r

# ───────────────────────── Level 04 — Discovering Column Count with UNION ─────────────────────────
def handle_04(p: dict) -> dict:
    u = p.get("username", "")

    q = f"SELECT username, email FROM users WHERE username = '{u}'"
    r = _run(4, q)

    if not r.get("ok"):
        return {"message": f"Database Error: {r.get('error', 'Query failed')}", "ok": False}

    rows = r.get("rows", [])

    if rows:
        for row in rows:
            if "edis" in row.values():
                f = _run(4, "SELECT flag FROM secrets LIMIT 1")
                flag_val = f["rows"][0].get("flag") if f.get("rows") else ""
                return {"message": f"Column count matched & UNION successful! Flag: {flag_val}", "ok": True}

        return {"message": "Query executed", "ok": False}

    return {"message": "No results returned. Find the column count and inject 'edis' via UNION SELECT.", "ok": False}

# ───────────────────────── Level 05 — Matching Data Types with UNION ─────────────────────────
def handle_05(p: dict) -> dict:
    u = p.get("username", "")

    q = f"SELECT username, password, email, role, id FROM users WHERE username = '{u}'"
    r = _run(5, q)

    if not r.get("ok"):
        return {"message": f"Database Error: {r.get('error', 'Query failed')}", "ok": False}

    rows = r.get("rows", [])

    if rows:
        for row in rows:
            vals = list(row.values())

            if len(vals) == 5:
                first_four_are_str = all(isinstance(v, str) for v in vals[:4])
                fifth_is_1337 = isinstance(vals[4], (int, float)) and vals[4] == 1337

                if first_four_are_str and fifth_is_1337:
                    f = _run(5, "SELECT flag FROM secrets LIMIT 1")
                    flag_val = f["rows"][0].get("flag") if f.get("rows") else ""
                    return {"message": f"Data types strictly matched & UNION successful! Flag: {flag_val}", "ok": True}

        return {"message": "Payload layout invalid! .", "ok": False}

    return {"message": "No results returned. Match column counts and data types via UNION SELECT.", "ok": False}

# ───────────────────────── Level 06 — Extracting Table Names under Filtered Syntax ─────────────────────────

def handle_06(p: dict) -> dict:
    raw_u = p.get("username", "")

    if any(c in raw_u for c in ["--", "/*", "#"]):
        return {"message": "Standard comments are blocked!", "ok": False}

    u = urllib.parse.unquote(raw_u)

    q = f"SELECT id, username, role FROM users WHERE username = '{u}'"
    r = _run(6, q)

    if not r.get("ok"):
        return {"message": f"Database Error: {r.get('error', 'Query failed')}", "ok": False}

    rows = r.get("rows", [])
    r["result"] = rows

    if rows:
        all_vals = " ".join([str(v) for row in rows for v in row.values()]).lower()

        system_tables = ["character_sets", "collations", "engines", "routines", "tablespaces"]
        if any(sys_t in all_vals for sys_t in system_tables):
            r["message"] = "Too noisy! You dumped all system tables. Limit your query using table_schema = database()."
            r["ok"] = False
            return r

        if "secrets" in all_vals:
            f = _run(6, "SELECT flag FROM secrets LIMIT 1")
            flag_val = f["rows"][0].get("flag") if f.get("rows") else ""
            r["message"] = f"Table schema enumerated successfully! Flag: {flag_val}"
            r["ok"] = True
            return r

        r["message"] = "Query executed"
        r["ok"] = False
    else:
        r["message"] = "No rows returned."
        r["ok"] = False

    return r

# ───────────────────────── Level 07 — comment styles ─────────────────────────

def _setup_level_07_dynamic_table():
    check_db_q = (
        "SELECT schema_name FROM information_schema.schemata "
        "WHERE schema_name LIKE 'sqli_db_level7_%' LIMIT 1"
    )
    res_db = _run(7, check_db_q)

    sec = _run(7, "SELECT flag FROM sqli_level_07.secrets WHERE name = 'level_flag' LIMIT 1")
    if not sec.get("rows"):
        sec = _run(7, "SELECT flag FROM sqli_level_07.secrets LIMIT 1")

    main_flag = (
        sec["rows"][0]["flag"]
        if (sec.get("rows") and "flag" in sec["rows"][0])
        else "NOT HERE"
    )

    if res_db.get("rows"):
        existing_db = res_db["rows"][0]["schema_name"]

        if main_flag.startswith("CTF{"):
            check_tbl = (
                f"SELECT table_name FROM information_schema.tables "
                f"WHERE table_schema = '{existing_db}' "
                f"AND table_name LIKE 'CTF_level7_%' LIMIT 1"
            )
            res_tbl = _run(7, check_tbl)
            if res_tbl.get("rows"):
                tbl_name = res_tbl["rows"][0]["table_name"]
                safe_flag = main_flag.replace("\\", "\\\\").replace("'", "''")
                _run(7, f"UPDATE `{existing_db}`.`{tbl_name}` SET flag = '{safe_flag}'")

            _run(7, "UPDATE sqli_level_07.secrets SET flag = 'NOT HERE' WHERE name = 'level_flag'")
        return

    rand_db_id = random.randint(1000, 9999)
    new_db = f"sqli_db_level7_{rand_db_id}"
    _run(7, f"CREATE DATABASE IF NOT EXISTS `{new_db}`")

    rand_tbl_id = random.randint(1000, 9999)
    new_tbl = f"CTF_level7_{rand_tbl_id}"

    flag_to_insert = main_flag if main_flag.startswith("CTF{") else "CTF{dynamic_schema_bypass_7392}"
    safe_flag = flag_to_insert.replace("\\", "\\\\").replace("'", "''")

    _run(7, f"CREATE TABLE IF NOT EXISTS `{new_db}`.`{new_tbl}` (id INT, flag VARCHAR(255))")
    _run(7, f"INSERT INTO `{new_db}`.`{new_tbl}` (id, flag) VALUES (1, '{safe_flag}')")

    _run(7, "UPDATE sqli_level_07.secrets SET flag = 'NOT HERE' WHERE name = 'level_flag'")


def _restore_flag_and_drop_dynamic_db() -> str | None:

    res_db = _run(
        7,
        "SELECT schema_name FROM information_schema.schemata "
        "WHERE schema_name LIKE 'sqli_db_level7_%' LIMIT 1",
    )
    if not res_db.get("rows"):
        return None

    dyn_db = res_db["rows"][0]["schema_name"]

    res_tbl = _run(
        7,
        f"SELECT table_name FROM information_schema.tables "
        f"WHERE table_schema = '{dyn_db}' AND table_name LIKE 'CTF_level7_%' LIMIT 1",
    )
    recovered = None
    if res_tbl.get("rows"):
        tbl = res_tbl["rows"][0]["table_name"]
        flag_res = _run(7, f"SELECT flag FROM `{dyn_db}`.`{tbl}` LIMIT 1")
        if flag_res.get("rows") and "flag" in flag_res["rows"][0]:
            recovered = flag_res["rows"][0]["flag"]

    if recovered and str(recovered).startswith("CTF{"):
        safe_flag = str(recovered).replace("\\", "\\\\").replace("'", "''")
        _run(
            7,
            f"UPDATE sqli_level_07.secrets SET flag = '{safe_flag}' WHERE name = 'level_flag'",
        )
        check = _run(7, "SELECT id FROM sqli_level_07.secrets WHERE name = 'level_flag' LIMIT 1")
        if not check.get("rows"):
            _run(
                7,
                f"INSERT INTO sqli_level_07.secrets (name, flag) VALUES ('level_flag', '{safe_flag}')",
            )

    _run(7, f"DROP DATABASE IF EXISTS `{dyn_db}`")
    return recovered


def handle_07(p: dict) -> dict:
    _setup_level_07_dynamic_table()

    raw_u = p.get("username", "")

    if any(c in raw_u for c in ["--", "/*", "#"]):
        return {"message": "Standard comments are blocked!", "ok": False}

    if "(" in raw_u or ")" in raw_u:
        return {
            "message": "Parentheses '()' are strictly forbidden! No function calls allowed.",
            "ok": False,
        }

    u = urllib.parse.unquote(raw_u)

    q = f"SELECT id, username, role FROM users WHERE username = '{u}'"
    r = _run(7, q)

    if not r.get("ok"):
        return {"message": f"Database Error: {r.get('error', 'Query failed')}", "ok": False}

    rows = r.get("rows", [])

    if len(rows) > 3:
        return {
            "message": "Too many rows returned! Do not dump all schemas. Filter your query specifically.",
            "ok": False,
        }

    r["result"] = rows

    if rows:
        all_vals = " ".join([str(v) for row in rows for v in row.values()])

        if "CTF{" in all_vals:
            recovered = _restore_flag_and_drop_dynamic_db()
            r["message"] = "Full Dynamic Schema Dump Successful! Flag extracted."
            if recovered:
                r["message"] += " Submit the flag to clear the level."
            r["ok"] = True
            return r

        r["message"] = (
            f"Query executed successfully. Rows returned: {len(rows)}. Keep enumerating."
        )
        r["ok"] = False
    else:
        r["message"] = "No rows returned."
        r["ok"] = False

    return r

# ───────────────────────── Level 08 — Error-Based Only ─────────────────────────
def handle_08(p: dict) -> dict:
    u = p.get("username", "")

    # Block the easy result-set paths so the intended channel is SQL errors
    lowered = u.lower()
    if "union" in lowered:
        return {
            "message": "UNION-based extraction is blocked on this level. Use an error-based channel.",
            "ok": False,
            "raw": "",
        }

    q = f"SELECT id, username, role FROM users WHERE username = '{u}' AND role = 'user'"
    r = _run(8, q)

    # Only the real DB exception text counts (not SELECT row dumps)
    err = str(r.get("error") or "")
    raw = str(r.get("raw") or "")

    # Prefer the explicit error field; fall back to raw only if it looks like an exception
    error_text = err
    if not error_text and "Error:" in raw:
        error_text = raw

    if "CTF{" in error_text:
        f = _run(8, "SELECT flag FROM secrets WHERE name = 'level_flag' LIMIT 1")
        if not f.get("rows"):
            f = _run(8, "SELECT flag FROM secrets LIMIT 1")
        flag_val = f["rows"][0].get("flag") if f.get("rows") else ""
        return {
            "message": (
                f"Error-based extraction successful! Flag: {flag_val}"
                if flag_val
                else "Error-based extraction successful!"
            ),
            "ok": True,
            # show the error that leaked data (learning feedback)
            "raw": error_text,
            "error": err or None,
        }

    # Harden response: do not reflect SELECT rows (prevents visual dump + submit)
    if r.get("error") or "Error:" in raw:
        return {
            "message": "Query failed — read the error carefully. Data may be hiding inside it.",
            "ok": False,
            "raw": error_text or raw,
            "error": err or None,
        }

    return {
        "message": (
            "Query executed, but row output is hidden on this level. "
            "Force a SQL error that includes data from the secrets table."
        ),
        "ok": False,
        "raw": "",
    }

# ───────────────────────── Level 09 — IF logic required ─────────────────────────
def handle_09(p: dict) -> dict:
    u = p.get("username", "")
    lowered = u.lower()

    q = f"SELECT id, username, role FROM users WHERE username = '{u}'"
    r = _run(9, q)

    if r.get("error"):
        return {
            "message": f"Database Error: {r.get('error')}",
            "ok": False,
            "raw": r.get("raw", ""),
            "error": r.get("error"),
        }

    rows = r.get("rows", [])
    if not rows:
        return {
            "message": "No rows. Open the query first — then solve it with IF logic.",
            "ok": False,
            "raw": r.get("raw", ""),
        }

    all_vals = [str(v) for row in rows for v in row.values()]
    blob = " ".join(all_vals)
    has_flag = "CTF{" in blob
    used_if = "if(" in lowered

    # Plain UNION dump of secrets.flag without IF → rejected on purpose
    if has_flag and not used_if:
        return {
            "message": (
                "Flag-shaped data appeared, but this level rejects direct dumps. "
                "Rebuild the extraction using IF(condition, true_expr, false_expr)."
            ),
            "ok": False,
            "raw": "",  # hide the dumped flag so submit-from-sight is harder
        }

    if has_flag and used_if:
        flag_val = next((v for v in all_vals if "CTF{" in v), "")
        return {
            "message": f"IF logic satisfied. Secret revealed. Flag: {flag_val}",
            "ok": True,
            "raw": r.get("raw", ""),
        }

    if used_if:
        return {
            "message": (
                "IF() was detected, but the flag is not in the result yet. "
                "When the condition is true, make true_expr return secrets.flag."
            ),
            "ok": False,
            "raw": r.get("raw", ""),
        }

    return {
        "message": (
            "Rows returned, but only normal columns. "
            "Plain login / UNION SELECT flag is not enough — use IF() to pull the secret."
        ),
        "ok": False,
        "raw": r.get("raw", ""),
    }

# ───────────────────────── Level 10 — boolean blind → prove length + 6th char ─────────────────────────
def handle_10(p: dict) -> dict:
    u = p.get("username", "")

    # Server-side secret (never shown unless challenge is solved)
    f = _run(10, "SELECT flag FROM secrets WHERE name = 'level_flag' LIMIT 1")
    if not f.get("rows"):
        f = _run(10, "SELECT flag FROM secrets LIMIT 1")
    flag_val = f["rows"][0].get("flag") if f.get("rows") else ""
    need_len = len(flag_val) if flag_val else -1
    need_ch = flag_val[5] if flag_val and len(flag_val) >= 6 else ""

    # Two columns so UNION can carry: length , 6th_char
    q = f"SELECT id, username FROM users WHERE username = '{u}'"
    r = _run(10, q)

    if r.get("error"):
        return {
            "ok": False,
            "message": "Invalid request",
            "raw": "Something went wrong.",
        }

    rows = r.get("rows") or []
    blob = " ".join(str(v) for row in rows for v in row.values())

    # Block direct dump of the flag / secrets contents into the result set
    if flag_val and flag_val in blob:
        return {
            "ok": False,
            "message": "Direct dump blocked. Enumerate with boolean checks, then prove length + 6th character via UNION.",
            "raw": "",
        }
    if "CTF{" in blob:
        return {
            "ok": False,
            "message": "Direct dump blocked. Do not select the flag column — prove length and the 6th character only.",
            "raw": "",
        }

    # Proof step: a returned row whose first two values are (length, 6th_char)
    for row in rows:
        vals = list(row.values())
        if len(vals) < 2:
            continue
        got_len = str(vals[0]).strip()
        got_ch = str(vals[1]).strip()
        if got_len == str(need_len) and got_ch == need_ch:
            return {
                "ok": True,
                "message": f"Blind solved (length + 6th char verified). Flag: {flag_val}",
                "raw": "Proof accepted",
            }

    # Boolean oracle only — no row data
    if rows:
        return {
            "ok": True,
            "message": "User exists",
            "raw": "User exists",
        }
    return {
        "ok": False,
        "message": "User not found",
        "raw": "User not found",
    }

# ───────────────────────── Level 11 — limited boolean search + UNION proof ─────────────────────────

def _level11_ensure_state():
    """secrets.here + attempt counter inside sqli_level_11."""
    _run(11, """
        CREATE TABLE IF NOT EXISTS challenge_state (
            id INT PRIMARY KEY DEFAULT 1,
            attempts INT NOT NULL DEFAULT 0
        )
    """)
    _run(11, "INSERT IGNORE INTO challenge_state (id, attempts) VALUES (1, 0)")

    # add column here if missing (MySQL/MariaDB)
    col = _run(
        11,
        "SELECT COUNT(*) AS c FROM information_schema.COLUMNS "
        "WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'secrets' AND COLUMN_NAME = 'here'",
    )
    c = 0
    if col.get("rows"):
        c = int(list(col["rows"][0].values())[0])
    if c == 0:
        _run(11, "ALTER TABLE secrets ADD COLUMN here INT NULL")

    # ensure a row exists and here is seeded in [25, 275]
    sec = _run(11, "SELECT id, here FROM secrets WHERE name = 'level_flag' LIMIT 1")
    if not sec.get("rows"):
        sec = _run(11, "SELECT id, here FROM secrets LIMIT 1")
    if not sec.get("rows"):
        _run(11, "INSERT INTO secrets (name, flag, here) VALUES ('level_flag', 'CTF{missing}', 100)")
        sec = _run(11, "SELECT id, here FROM secrets LIMIT 1")

    row = sec["rows"][0]
    here_val = row.get("here")
    if here_val is None or int(here_val) < 25 or int(here_val) > 275:
        n = random.randint(25, 275)
        _run(11, f"UPDATE secrets SET here = {n} WHERE id = {int(row['id'])}")

def _level11_get_here() -> int:
    r = _run(11, "SELECT here FROM secrets WHERE name = 'level_flag' LIMIT 1")
    if not r.get("rows"):
        r = _run(11, "SELECT here FROM secrets LIMIT 1")
    return int(r["rows"][0]["here"])

def _level11_get_attempts() -> int:
    r = _run(11, "SELECT attempts FROM challenge_state WHERE id = 1")
    if not r.get("rows"):
        return 0
    return int(r["rows"][0]["attempts"])

def _level11_set_attempts(n: int) -> None:
    _run(11, f"UPDATE challenge_state SET attempts = {int(n)} WHERE id = 1")

def _level11_reroll() -> int:
    n = random.randint(25, 275)
    _run(11, f"UPDATE secrets SET here = {n} WHERE name = 'level_flag'")
    # if name filter matched nothing, update all rows
    _run(11, f"UPDATE secrets SET here = {n} WHERE here IS NULL OR here < 25 OR here > 275 OR 1=1 LIMIT 1")
    # simpler reliable update:
    _run(11, f"UPDATE secrets SET here = {n}")
    _level11_set_attempts(0)
    return n

def handle_11(p: dict) -> dict:
    u = p.get("username", "") or "1=0"
    lowered = u.lower()

    _level11_ensure_state()

    # --- budget: every request counts (boolean OR union) ---
    attempts = _level11_get_attempts() + 1
    if attempts > 25:
        _level11_reroll()
        attempts = 1
        _level11_set_attempts(attempts)
        left = 25 - attempts
        return {
            "ok": False,
            "message": (
                "Query budget exceeded (25). The secret number in secrets.here was re-randomized. "
                f"Attempts left: {left}"
            ),
            "raw": f"Attempts left: {left}",
        }

    _level11_set_attempts(attempts)
    left = 25 - attempts
    here = _level11_get_here()

    # Block dumping the column directly — must binary-search, then prove with a literal
    if re.search(r"\bhere\b", lowered) and re.search(r"\bunion\b", lowered):
        return {
            "ok": False,
            "message": (
                f"Dumping secrets.here via UNION is blocked. Compare with < > = first, "
                f"then UNION a plain number. Attempts left: {left}"
            ),
            "raw": f"Attempts left: {left}",
        }
    if re.search(r"\bunion\b", lowered) and re.search(r"\bhere\b", lowered):
            return {
                "ok": False,
                "message": (
                    f"Dumping secrets.here via UNION is blocked. "
                    f"Compare with < > = , then UNION a plain number. "
                    f"Attempts left: {left}"
                ),
                "raw": f"Attempts left: {left}",
            }

    # Injection point: boolean expression after AND (no quotes around input)
    q = f"SELECT id, username FROM users WHERE username = 'admin' AND {u}"
    r = _run(11, q)

    if r.get("error"):
        return {
            "ok": False,
            "message": f"Invalid expression. Attempts left: {left}",
            "raw": f"Attempts left: {left}",
            "error": r.get("error"),
        }

    rows = r.get("rows") or []

    # Win: UNION proof row whose first cell equals the secret number (literal, not column dump)
    for row in rows:
        vals = list(row.values())
        if not vals:
            continue
        try:
            got = int(str(vals[0]).strip())
        except ValueError:
            continue
        if got == here:
            # optional: require UNION in payload so plain true-row on id==here can't win accidentally
            if "union" not in lowered:
                continue
            f = _run(11, "SELECT flag FROM secrets WHERE name = 'level_flag' LIMIT 1")
            if not f.get("rows"):
                f = _run(11, "SELECT flag FROM secrets LIMIT 1")
            flag_val = f["rows"][0].get("flag") if f.get("rows") else ""
            _level11_set_attempts(0)  # soft reset after solve (optional)
            return {
                "ok": True,
                "message": (
                    f"Correct number ({here}). Budget used wisely. Flag: {flag_val}"
                    if flag_val
                    else f"Correct number ({here})."
                ),
                "raw": f"Attempts left: {left}",
            }

    # Boolean oracle only
    if rows:
        return {
            "ok": True,
            "message": f"TRUE. Attempts left: {left}",
            "raw": f"Attempts left: {left}",
        }
    return {
        "ok": False,
        "message": f"FALSE. Attempts left: {left}",
        "raw": f"Attempts left: {left}",
    }

# ───────────────────────── Level 12 — player must use ORD/SUBSTRING ─────────────────────────

def handle_12(p: dict) -> dict:
    expr = (p.get("username") or "0").strip()
    lowered = expr.lower()

    # Must actually use the string/char functions — not a bare number
    uses_ord = "ord(" in lowered or "ascii(" in lowered
    uses_sub = "substring(" in lowered or "substr(" in lowered or "mid(" in lowered
    if not (uses_ord and uses_sub):
        return {
            "ok": False,
            "message": (
                "Use SQL character functions in your expression. "
                "Hint shape: ORD(SUBSTRING(flag, 7, 1))=?"
            ),
            "raw": "Functions required",
        }

    if re.search(r"\bor\b\s+1\s*=\s*1", lowered) or "union" in lowered:
        return {
            "ok": False,
            "message": "OR 1=1 / UNION blocked. Solve with ORD + SUBSTRING on flag.",
            "raw": "Blocked",
        }

    q = f"SELECT id FROM secrets WHERE id = 1 AND ({expr})"
    r = _run(12, q)

    if r.get("error"):
        return {
            "ok": False,
            "message": "Invalid expression",
            "raw": str(r.get("error") or "Invalid"),
            "error": r.get("error"),
        }

    if r.get("rows"):
        f = _run(12, "SELECT flag FROM secrets WHERE name = 'level_flag' LIMIT 1")
        if not f.get("rows"):
            f = _run(12, "SELECT flag FROM secrets LIMIT 1")
        flag_val = f["rows"][0].get("flag") if f.get("rows") else ""
        return {
            "ok": True,
            "message": (
                f"MATCH — character function logic correct. Flag: {flag_val}"
                if flag_val
                else "MATCH — correct."
            ),
            "raw": "ORD matches",
        }

    return {
        "ok": False,
        "message": "NO MATCH — expression is valid but false. Adjust the number.",
        "raw": "ORD does not match",
    }

# ───────────────────────── Level 13 — time-based find 12th char, prove with UNION ─────────────────────────
def handle_13(p: dict) -> dict:
    expr = (p.get("username") or "1=0").strip()
    lowered = expr.lower()

    f = _run(13, "SELECT flag FROM secrets WHERE name = 'level_flag' LIMIT 1")
    if not f.get("rows"):
        f = _run(13, "SELECT flag FROM secrets LIMIT 1")
    flag_val = f["rows"][0].get("flag") if f.get("rows") else ""
    twelfth = flag_val[11] if flag_val and len(flag_val) >= 12 else ""

    # no outer parens — UNION must work at top level
    q = f"SELECT id, name FROM secrets WHERE {expr}"
    r = _run(13, q)

    if r.get("error"):
        return {
            "ok": False,
            "message": "Invalid expression",
            "raw": str(r.get("error") or "Invalid expression"),
            "error": r.get("error"),
        }

    rows = r.get("rows") or []
    blob = " ".join(str(v) for row in rows for v in row.values())

    # block dumping the full flag into the result
    if flag_val and flag_val in blob:
        return {
            "ok": False,
            "message": "Full flag dump blocked. Prove the 12th character with UNION SELECT 'edis', '<char>'.",
            "raw": "",
        }

    # WIN: UNION proof row contains marker 'edis' AND the correct 12th character
    if "union" in lowered and twelfth:
        for row in rows:
            vals = [str(v) for v in row.values()]
            has_marker = any(v.lower() == "edis" for v in vals)
            has_char = any(v == twelfth for v in vals)
            if has_marker and has_char:
                return {
                    "ok": True,
                    "message": (
                        f"Proof accepted (edis + 12th char). Flag: {flag_val}"
                        if flag_val
                        else "Proof accepted."
                    ),
                    "raw": "OK",
                }

    # time-based / boolean path — do not reveal flag
    if rows:
        return {
            "ok": True,
            "message": "YES",
            "raw": "YES",
        }
    return {
        "ok": False,
        "message": "NO",
        "raw": "NO",
    }


# ───────────────────────── Level 14 — time-based (flag if elapsed > 1s) ─────────────────────────
def handle_14(p: dict) -> dict:
    u = p.get("username", "")
    q = f"SELECT id FROM users WHERE username = '{u}'"

    start = time.time()
    r = _run(14, q)
    elapsed = time.time() - start

    # Always hide row dumps — this level is about time only
    if r.get("error"):
        return {
            "ok": False,
            "message": "Query error",
            "raw": f"Error after {elapsed:.2f}s\n{r.get('error')}",
            "error": r.get("error"),
        }

    if elapsed > 1.0:
        f = _run(14, "SELECT flag FROM secrets WHERE name = 'level_flag' LIMIT 1")
        if not f.get("rows"):
            f = _run(14, "SELECT flag FROM secrets LIMIT 1")
        flag_val = f["rows"][0].get("flag") if f.get("rows") else ""
        return {
            "ok": True,
            "message": (
                f"Time threshold passed ({elapsed:.2f}s). Flag: {flag_val}"
                if flag_val
                else f"Time threshold passed ({elapsed:.2f}s)."
            ),
            "raw": f"Query finished in {elapsed:.2f}s",
        }

    return {
        "ok": False,
        "message": f"Done in {elapsed:.2f}s — too fast. Force a delay > 1 second.",
        "raw": f"Query finished in {elapsed:.2f}s\n(Use SLEEP to measure true/false)",
    }


# ───────────────────────── Level 15 — simple blacklist (|| bypass) ─────────────────────────
def handle_15(p: dict) -> dict:
    u = p.get("username", "")
    blocked = [
        "union", "select", "or", "and", "sleep", "benchmark",
        "--", "#", "/*",
    ]
    low = u.lower()
    for w in blocked:
        if w in low:
            return _blocked(f"Blacklist hit: '{w}' is not allowed")

    # role='user' → plain "admin" returns nothing; comments are blacklisted
    q = f"SELECT id, username, role FROM users WHERE username = '{u}' AND role = 'user'"
    r = _run(15, q)

    if r.get("error"):
        return {
            "ok": False,
            "message": "Query error",
            "raw": r.get("raw") or str(r.get("error")),
            "error": r.get("error"),
        }

    rows = r.get("rows") or []

    # Normal single-user login (alice/bob/guest) → 1 row → not enough
    # Injection that opens the WHERE → multiple user rows → win
    if len(rows) >= 2:
        f = _run(15, "SELECT flag FROM secrets WHERE name = 'level_flag' LIMIT 1")
        if not f.get("rows"):
            f = _run(15, "SELECT flag FROM secrets LIMIT 1")
        flag_val = f["rows"][0].get("flag") if f.get("rows") else ""
        return {
            "ok": True,
            "message": (
                f"Blacklist bypassed (multiple rows). Flag: {flag_val}"
                if flag_val
                else "Blacklist bypassed."
            ),
            "raw": r.get("raw") or "",
        }

    if len(rows) == 1:
        return {
            "ok": False,
            "message": "One user row — not enough. Bypass the filter so the query matches more rows.",
            "raw": r.get("raw") or "",
        }

    return {
        "ok": False,
        "message": "No rows. Remember: or/and/comments are blocked — try another operator.",
        "raw": r.get("raw") or "",
    }



# ───────────────────────── Level 16 — Union with Types ─────────────────────────
def handle_16(p: dict) -> dict:
    """UNION must align column types (id INT, username/role strings)."""
    u = p.get("username", "")
    lowered = u.lower()

    q = f"SELECT id, username, role FROM users WHERE username = '{u}'"
    r = _run(16, q)

    if r.get("error"):
        return {
            "ok": False,
            "message": "Query error — check column count and types (use NULL/CAST).",
            "raw": r.get("raw") or str(r.get("error")),
            "error": r.get("error"),
        }

    rows = r.get("rows") or []
    blob = _rows_blob(rows)

    # Require UNION-based extraction (not plain dump of users table alone)
    if "CTF{" in blob and "union" in lowered:
        flag_val = _get_flag(16)
        # Prefer flag from result if present
        for row in rows:
            for v in row.values():
                s = str(v)
                if s.startswith("CTF{"):
                    flag_val = s
                    break
        return {
            "ok": True,
            "message": f"UNION types aligned. Flag: {flag_val}" if flag_val else "UNION types aligned.",
            "raw": r.get("raw") or "",
        }

    if len(rows) > 5:
        return {
            "ok": False,
            "message": "Too many rows — do not dump the whole table. Use a precise UNION SELECT.",
            "raw": "",
        }

    if rows:
        return {
            "ok": False,
            "message": "Rows returned, but flag not extracted via typed UNION. Match 3 columns (int, str, str).",
            "raw": r.get("raw") or "",
        }

    return {
        "ok": False,
        "message": "No rows. Try UNION SELECT with matching types (NULL/CAST help).",
        "raw": r.get("raw") or "",
    }


# ───────────────────────── Level 17 — Union + Limit ─────────────────────────
def handle_17(p: dict) -> dict:
    """LIMIT 1 is fixed after WHERE — inject before it or use subquery."""
    u = p.get("username", "")
    lowered = u.lower()

    q = f"SELECT id, username, role FROM users WHERE username = '{u}' LIMIT 1"
    r = _run(17, q)

    if r.get("error"):
        return {
            "ok": False,
            "message": "Query error",
            "raw": r.get("raw") or str(r.get("error")),
            "error": r.get("error"),
        }

    rows = r.get("rows") or []
    blob = _rows_blob(rows)

    # Win: extracted flag appears, or single admin row via injection before LIMIT
    if "CTF{" in blob:
        flag_val = next((str(v) for row in rows for v in row.values() if str(v).startswith("CTF{")), _get_flag(17))
        return {
            "ok": True,
            "message": f"Bypassed LIMIT. Flag: {flag_val}",
            "raw": r.get("raw") or "",
        }

    if rows and (rows[0].get("username") == "admin" or rows[0].get("role") == "admin"):
        # Only count as win if injection was used (not plain "admin")
        if u.strip().lower() == "admin":
            return {
                "ok": False,
                "message": "Admin row visible, but you must inject past LIMIT (not plain username).",
                "raw": r.get("raw") or "",
            }
        flag_val = _get_flag(17)
        return {
            "ok": True,
            "message": f"LIMIT bypassed — admin reached. Flag: {flag_val}",
            "raw": r.get("raw") or "",
        }

    if rows:
        return {
            "ok": False,
            "message": "One row returned (LIMIT 1). Inject before LIMIT or use a subquery/UNION trick.",
            "raw": r.get("raw") or "",
        }

    return {
        "ok": False,
        "message": "No rows. Remember: LIMIT 1 sits after the WHERE clause.",
        "raw": r.get("raw") or "",
    }


# ───────────────────────── Level 18 — Second-Order Basic ─────────────────────────
def handle_18(p: dict) -> dict:
    """password=save stores username; password=view runs vulnerable read."""
    action = (p.get("password") or "view").strip().lower()
    u = p.get("username", "")
    db = level_db(18)

    if action == "save":
        try:
            conn = get_conn(db)
            try:
                with conn.cursor() as cur:
                    cur.execute(
                        "CREATE TABLE IF NOT EXISTS profiles ("
                        "id INT PRIMARY KEY, name VARCHAR(512))"
                    )
                    cur.execute("DELETE FROM profiles WHERE id = 1")
                    # intentionally vulnerable insert
                    cur.execute(f"INSERT INTO profiles (id, name) VALUES (1, '{u}')")
                    conn.commit()
            finally:
                conn.close()
            return {
                "ok": True,
                "message": "Profile saved. Now set password=view to trigger the query.",
                "raw": f"Saved name length={len(u)}",
            }
        except Exception as e:
            return {"ok": False, "message": "Save failed", "raw": str(e), "error": str(e)}

    # view path
    q = (
        "SELECT id, username, role FROM users WHERE username = "
        "(SELECT name FROM profiles WHERE id = 1 LIMIT 1)"
    )
    r = _run(18, q)

    if r.get("error"):
        # Second-order can break syntax — surface error for learning
        err = str(r.get("error") or "")
        if "CTF{" in err:
            flag_val = _get_flag(18)
            return {
                "ok": True,
                "message": f"Second-order error channel worked. Flag: {flag_val}",
                "raw": err,
                "error": err,
            }
        return {
            "ok": False,
            "message": "Query error on view — check stored payload syntax.",
            "raw": r.get("raw") or err,
            "error": err,
        }

    rows = r.get("rows") or []
    blob = _rows_blob(rows)

    if "CTF{" in blob:
        flag_val = next((str(v) for row in rows for v in row.values() if str(v).startswith("CTF{")), _get_flag(18))
        return {
            "ok": True,
            "message": f"Second-order extraction successful. Flag: {flag_val}",
            "raw": r.get("raw") or "",
        }

    if any(row.get("username") == "admin" or row.get("role") == "admin" for row in rows):
        # Stored payload caused admin match
        if "admin" in (u or "").lower() and action != "save":
            # could be leftover store
            pass
        flag_val = _get_flag(18)
        return {
            "ok": True,
            "message": f"Second-order login as admin. Flag: {flag_val}",
            "raw": r.get("raw") or "",
        }

    if len(rows) > 3:
        return {
            "ok": False,
            "message": "Too many rows — target a precise second-order payload, do not dump.",
            "raw": "",
        }

    return {
        "ok": False,
        "message": "View executed. Save a payload that breaks out when the subquery is inlined.",
        "raw": r.get("raw") or "",
    }


# ───────────────────────── Level 19 — Cookie Injection ─────────────────────────
def handle_19(p: dict) -> dict:
    cookie = p.get("username", p.get("cookie", "guest"))
    lowered = cookie.lower()

    q = f"SELECT id, username, role FROM users WHERE username = '{cookie}'"
    r = _run(19, q)

    if r.get("error"):
        return {
            "ok": False,
            "message": "Query error",
            "raw": r.get("raw") or str(r.get("error")),
            "error": r.get("error"),
        }

    rows = r.get("rows") or []
    blob = _rows_blob(rows)

    if "CTF{" in blob:
        flag_val = next((str(v) for row in rows for v in row.values() if str(v).startswith("CTF{")), _get_flag(19))
        return {
            "ok": True,
            "message": f"Cookie injection extracted flag. Flag: {flag_val}",
            "raw": r.get("raw") or "",
        }

    if any(row.get("username") == "admin" or row.get("role") == "admin" for row in rows):
        if cookie.strip().lower() == "admin":
            return {
                "ok": False,
                "message": "Plain admin cookie is not enough — inject through the cookie value.",
                "raw": r.get("raw") or "",
            }
        flag_val = _get_flag(19)
        return {
            "ok": True,
            "message": f"Cookie forged as admin. Flag: {flag_val}",
            "raw": r.get("raw") or "",
        }

    if len(rows) >= 2:
        flag_val = _get_flag(19)
        return {
            "ok": True,
            "message": f"Cookie injection returned multiple rows. Flag: {flag_val}",
            "raw": r.get("raw") or "",
        }

    if len(rows) > 3:
        return {
            "ok": False,
            "message": "Too many rows — do not dump. Target admin or extract the flag.",
            "raw": "",
        }

    return {
        "ok": False,
        "message": "Cookie accepted but not privileged. Inject into the cookie-like field (username).",
        "raw": r.get("raw") or "",
    }


# ───────────────────────── Level 20 — Header Injection ─────────────────────────
def handle_20(p: dict) -> dict:
    ua = p.get("username", p.get("user_agent", "Mozilla"))
    lowered = ua.lower()

    q = f"SELECT id, username, role FROM users WHERE username = '{ua}' LIMIT 5"
    r = _run(20, q)

    if r.get("error"):
        return {
            "ok": False,
            "message": "Query error",
            "raw": r.get("raw") or str(r.get("error")),
            "error": r.get("error"),
        }

    rows = r.get("rows") or []
    blob = _rows_blob(rows)

    if "CTF{" in blob:
        flag_val = next((str(v) for row in rows for v in row.values() if str(v).startswith("CTF{")), _get_flag(20))
        return {
            "ok": True,
            "message": f"Header injection worked. Flag: {flag_val}",
            "raw": r.get("raw") or "",
        }

    if any(row.get("username") == "admin" or row.get("role") == "admin" for row in rows):
        if ua.strip().lower() == "admin":
            return {
                "ok": False,
                "message": "Plain admin is not the intended path — inject via User-Agent field.",
                "raw": r.get("raw") or "",
            }
        flag_val = _get_flag(20)
        return {
            "ok": True,
            "message": f"User-Agent forged. Flag: {flag_val}",
            "raw": r.get("raw") or "",
        }

    if len(rows) >= 2:
        flag_val = _get_flag(20)
        return {
            "ok": True,
            "message": f"Header injection multi-row. Flag: {flag_val}",
            "raw": r.get("raw") or "",
        }

    if len(rows) > 3:
        return {
            "ok": False,
            "message": "Too many rows — refine the payload.",
            "raw": "",
        }

    return {
        "ok": False,
        "message": "Header processed. Inject SQLi into the User-Agent-like field.",
        "raw": r.get("raw") or "",
    }


# ───────────────────────── Level 21 — JSON Body SQLi ─────────────────────────
def handle_21(p: dict) -> dict:
    u = p.get("username", "")
    q = f"SELECT id, username, role FROM users WHERE username = '{u}'"

    r = _run(21, q)
    if r.get("error"):
        return {
            "ok": False,
            "message": "Query error",
            "raw": r.get("raw") or str(r.get("error")),
            "error": r.get("error"),
        }

    rows = r.get("rows") or []
    blob = _rows_blob(rows)

    if "CTF{" in blob:
        flag_val = next((str(v) for row in rows for v in row.values() if str(v).startswith("CTF{")), _get_flag(21))
        return {
            "ok": True,
            "message": f"JSON field injection succeeded. Flag: {flag_val}",
            "raw": r.get("raw") or "",
        }

    if rows and (rows[0].get("username") == "admin" or rows[0].get("role") == "admin"):
        if u.strip().lower() == "admin":
            return {
                "ok": False,
                "message": "Need injection in the JSON user value, not a plain admin string.",
                "raw": r.get("raw") or "",
            }
        flag_val = _get_flag(21)
        return {
            "ok": True,
            "message": f"JSON user escalated. Flag: {flag_val}",
            "raw": r.get("raw") or "",
        }

    if len(rows) > 3:
        return {
            "ok": False,
            "message": "Too many rows — do not dump the table.",
            "raw": "",
        }

    return {
        "ok": False,
        "message": "JSON value concatenated into query. Extract flag or become admin.",
        "raw": r.get("raw") or "",
    }


# ───────────────────────── Level 22 — Blind Time + Filter ─────────────────────────
def handle_22(p: dict) -> dict:
    u = p.get("username", "")
    lowered = u.lower()

    if re.search(r"(?i)\bsleep\s*\(|\bbenchmark\s*\(", u):
        return _blocked("SLEEP/BENCHMARK are filtered. Obfuscate or use another delay.")

    q = f"SELECT id FROM users WHERE username = '{u}'"
    start = time.time()
    r = _run(22, q)
    elapsed = time.time() - start

    if r.get("error"):
        return {
            "ok": False,
            "message": "Query error",
            "raw": f"{r.get('raw')}\n[elapsed: {elapsed:.2f}s]",
            "error": r.get("error"),
        }

    # Win on deliberate delay > 1.5s (obfuscated sleep / heavy query)
    if elapsed > 1.5:
        flag_val = _get_flag(22)
        return {
            "ok": True,
            "message": f"Time channel confirmed ({elapsed:.2f}s). Flag: {flag_val}",
            "raw": f"elapsed={elapsed:.2f}s",
        }

    # Hide row dumps — this is a time-oriented level
    return {
        "ok": False,
        "message": f"Done in {elapsed:.2f}s — need a measurable delay (>1.5s) despite the filter.",
        "raw": f"elapsed={elapsed:.2f}s",
    }


# ───────────────────────── Level 23 — Order By Injection ─────────────────────────
def handle_23(p: dict) -> dict:
    order = p.get("username", "id")
    lowered = order.lower()

    # Block obvious full dumps via ORDER BY subquery that returns many rows elsewhere
    q = f"SELECT id, username, role FROM users ORDER BY {order}"
    r = _run(23, q)

    if r.get("error"):
        err = str(r.get("error") or "")
        if "CTF{" in err:
            flag_val = _get_flag(23)
            return {
                "ok": True,
                "message": f"ORDER BY error-based extraction. Flag: {flag_val}",
                "raw": err,
                "error": err,
            }
        return {
            "ok": False,
            "message": "ORDER BY error — useful for enumeration.",
            "raw": r.get("raw") or err,
            "error": err,
        }

    rows = r.get("rows") or []
    blob = _rows_blob(rows)

    if "CTF{" in blob:
        flag_val = next((str(v) for row in rows for v in row.values() if str(v).startswith("CTF{")), _get_flag(23))
        return {
            "ok": True,
            "message": f"ORDER BY injection extracted data. Flag: {flag_val}",
            "raw": r.get("raw") or "",
        }

    # Boolean-style: CASE WHEN forces different order; detect marker technique
    if "case" in lowered and "when" in lowered and rows:
        # soft success path: player demonstrated CASE control — still need flag
        return {
            "ok": False,
            "message": "CASE/WHEN observed in ORDER BY. Use it to extract secrets.flag (error or subquery).",
            "raw": f"Rows: {len(rows)}",
        }

    if len(rows) > 10:
        return {
            "ok": False,
            "message": "Result set too large — keep ORDER BY extraction focused.",
            "raw": "",
        }

    return {
        "ok": False,
        "message": "ORDER BY is injectable. Try CASE, errors, or subqueries to reach secrets.",
        "raw": r.get("raw") or "",
    }


# ───────────────────────── Level 24 — Group By / Having ─────────────────────────
def handle_24(p: dict) -> dict:
    having = p.get("username", "1=1")
    lowered = having.lower()

    q = f"SELECT role, COUNT(*) AS c FROM users GROUP BY role HAVING {having}"
    r = _run(24, q)

    if r.get("error"):
        err = str(r.get("error") or "")
        if "CTF{" in err:
            flag_val = _get_flag(24)
            return {
                "ok": True,
                "message": f"HAVING error-based extraction. Flag: {flag_val}",
                "raw": err,
                "error": err,
            }
        return {
            "ok": False,
            "message": "HAVING clause error",
            "raw": r.get("raw") or err,
            "error": err,
        }

    rows = r.get("rows") or []
    blob = _rows_blob(rows)

    if "CTF{" in blob:
        flag_val = next((str(v) for row in rows for v in row.values() if str(v).startswith("CTF{")), _get_flag(24))
        return {
            "ok": True,
            "message": f"HAVING injection succeeded. Flag: {flag_val}",
            "raw": r.get("raw") or "",
        }

    # Win if player forces a true condition that proves subquery on secrets
    if "secrets" in lowered and rows:
        flag_val = _get_flag(24)
        return {
            "ok": True,
            "message": f"HAVING touched secrets. Flag: {flag_val}",
            "raw": r.get("raw") or "",
        }

    return {
        "ok": False,
        "message": "HAVING is injectable. Boolean/subquery against secrets to extract the flag.",
        "raw": r.get("raw") or "",
    }


# ───────────────────────── Level 25 — Stacked Queries ─────────────────────────
def handle_25(p: dict) -> dict:
    u = p.get("username", "")
    q = f"SELECT id, username, role FROM users WHERE username = '{u}'"

    # Allow stacked statements (pymysql multi)
    db = level_db(25)
    try:
        conn = get_conn(db)
        try:
            with conn.cursor() as cur:
                parts = [x.strip() for x in q.split(";") if x.strip()]
                if len(parts) > 4:
                    return {
                        "ok": False,
                        "message": "Too many stacked statements (max 4).",
                        "raw": "",
                    }
                results = []
                last_rows = []
                for part in parts:
                    cur.execute(part)
                    try:
                        rows = cur.fetchall()
                        results.append(rows)
                        last_rows = rows
                    except Exception:
                        results.append("(ok non-select)")
                        last_rows = []
                conn.commit()
                blob = _rows_blob(last_rows) if last_rows else ""
                # Also scan all result sets
                all_blob = " ".join(_rows_blob(r) if isinstance(r, list) else "" for r in results)

                if "CTF{" in all_blob or "CTF{" in blob:
                    flag_val = _get_flag(25)
                    for rset in results:
                        if isinstance(rset, list):
                            for row in rset:
                                for v in row.values():
                                    if str(v).startswith("CTF{"):
                                        flag_val = str(v)
                    return {
                        "ok": True,
                        "message": f"Stacked query extracted flag. Flag: {flag_val}",
                        "raw": f"Results: {results}",
                    }

                # Detect that a second statement ran successfully
                if len(parts) >= 2:
                    return {
                        "ok": False,
                        "message": "Stacked statements ran. Use a second SELECT against secrets for the flag.",
                        "raw": f"Statements: {len(parts)}; last={last_rows}",
                    }

                if len(last_rows) > 3:
                    return {
                        "ok": False,
                        "message": "Too many rows — stack a precise SELECT, do not dump users.",
                        "raw": "",
                    }

                return {
                    "ok": False,
                    "message": "Single statement only. Terminate with ; and append another query.",
                    "raw": f"Result: {last_rows}",
                }
        finally:
            conn.close()
    except Exception as e:
        return {
            "ok": False,
            "message": "Database error",
            "raw": f"Query: {q}\nError: {e}",
            "error": str(e),
        }


# ───────────────────────── Level 26 — Out-of-Band Surface ─────────────────────────
def handle_26(p: dict) -> dict:
    """OOB simulated: prefer error-based extraction; classic SELECT still works but limited."""
    u = p.get("username", "")
    lowered = u.lower()

    if re.search(r"(?i)into\s+outfile|load_file\s*\(", u):
        return _blocked("OUTFILE / LOAD_FILE are disabled in this lab.")

    q = f"SELECT id, username, role FROM users WHERE username = '{u}'"
    r = _run(26, q)

    err = str(r.get("error") or "")
    if "CTF{" in err:
        flag_val = _get_flag(26)
        return {
            "ok": True,
            "message": f"Error-channel extraction (OOB-style). Flag: {flag_val}",
            "raw": err,
            "error": err,
        }

    if r.get("error"):
        return {
            "ok": False,
            "message": "Error surfaced — dig for data inside it.",
            "raw": r.get("raw") or err,
            "error": err,
        }

    rows = r.get("rows") or []
    blob = _rows_blob(rows)
    if "CTF{" in blob:
        flag_val = next((str(v) for row in rows for v in row.values() if str(v).startswith("CTF{")), _get_flag(26))
        return {
            "ok": True,
            "message": f"Extracted via query channel. Flag: {flag_val}",
            "raw": r.get("raw") or "",
        }

    if len(rows) > 3:
        return {
            "ok": False,
            "message": "Too many rows. Prefer error-based / precise extraction over dumps.",
            "raw": "",
        }

    return {
        "ok": False,
        "message": "OOB sinks are blocked; use error-based or tight UNION instead.",
        "raw": r.get("raw") or "",
    }


# ───────────────────────── Level 27 — WAF Simple Keywords ─────────────────────────
def handle_27(p: dict) -> dict:
    u = p.get("username", "")
    # Keyword WAF on contiguous words — UN/**/ION bypasses because comments break the token
    banned = ["union", "select", "from", "where", "or", "and", "information_schema"]
    low = u.lower()
    for w in banned:
        if re.search(rf"(?<![a-z_]){re.escape(w)}(?![a-z_])", low):
            return _blocked(f"WAF: keyword '{w}' denied — try obfuscation (comments/case).")

    q = f"SELECT id, username, role FROM users WHERE username = '{u}'"
    r = _run(27, q)

    if r.get("error"):
        return {
            "ok": False,
            "message": "Query error after WAF",
            "raw": r.get("raw") or str(r.get("error")),
            "error": r.get("error"),
        }

    rows = r.get("rows") or []
    blob = _rows_blob(rows)
    if "CTF{" in blob:
        flag_val = next((str(v) for row in rows for v in row.values() if str(v).startswith("CTF{")), _get_flag(27))
        return {
            "ok": True,
            "message": f"WAF bypassed. Flag: {flag_val}",
            "raw": r.get("raw") or "",
        }

    if rows and (rows[0].get("username") == "admin" or rows[0].get("role") == "admin"):
        if u.strip().lower() == "admin":
            return {
                "ok": False,
                "message": "Plain admin does not teach WAF bypass.",
                "raw": r.get("raw") or "",
            }
        flag_val = _get_flag(27)
        return {
            "ok": True,
            "message": f"WAF bypassed (admin). Flag: {flag_val}",
            "raw": r.get("raw") or "",
        }

    if len(rows) > 3:
        return {
            "ok": False,
            "message": "Too many rows — targeted extraction only.",
            "raw": "",
        }

    return {
        "ok": False,
        "message": "WAF is active on common keywords. Obfuscate (e.g. UN/**/ION).",
        "raw": r.get("raw") or "",
    }


# ───────────────────────── Level 28 — Double Encoding ─────────────────────────
def handle_28(p: dict) -> dict:
    raw_u = p.get("username", "")
    # App decodes exactly once
    try:
        u = urllib.parse.unquote(raw_u)
    except Exception:
        u = raw_u

    q = f"SELECT id, username, role FROM users WHERE username = '{u}'"
    r = _run(28, q)

    if r.get("error"):
        return {
            "ok": False,
            "message": "Query error",
            "raw": r.get("raw") or str(r.get("error")),
            "error": r.get("error"),
        }

    rows = r.get("rows") or []
    blob = _rows_blob(rows)

    if "CTF{" in blob:
        flag_val = next((str(v) for row in rows for v in row.values() if str(v).startswith("CTF{")), _get_flag(28))
        return {
            "ok": True,
            "message": f"Encoding bypass worked. Flag: {flag_val}",
            "raw": r.get("raw") or "",
        }

    if rows and (rows[0].get("username") == "admin" or rows[0].get("role") == "admin"):
        if u.strip().lower() == "admin" and "%" not in raw_u:
            return {
                "ok": False,
                "message": "Use encoding so the injection appears only after one URL-decode.",
                "raw": r.get("raw") or "",
            }
        flag_val = _get_flag(28)
        return {
            "ok": True,
            "message": f"Decoded injection succeeded. Flag: {flag_val}",
            "raw": r.get("raw") or "",
        }

    if len(rows) > 3:
        return {
            "ok": False,
            "message": "Too many rows — refine the encoded payload.",
            "raw": "",
        }

    return {
        "ok": False,
        "message": "Input is URL-decoded once before the query. Double-encode special characters.",
        "raw": r.get("raw") or "",
    }


# ───────────────────────── Level 29 — Scientific Notation / numeric tricks ─────────────────────────
def handle_29(p: dict) -> dict:
    uid = p.get("username", "1")
    if "'" in uid or " " in uid or ";" in uid or '"' in uid:
        return _blocked("Invalid characters in id (no spaces/quotes/semicolon)")

    q = f"SELECT id, username, role FROM users WHERE id = {uid}"
    r = _run(29, q)

    if r.get("error"):
        return {
            "ok": False,
            "message": "Query error",
            "raw": r.get("raw") or str(r.get("error")),
            "error": r.get("error"),
        }

    rows = r.get("rows") or []
    blob = _rows_blob(rows)

    if "CTF{" in blob:
        flag_val = next((str(v) for row in rows for v in row.values() if str(v).startswith("CTF{")), _get_flag(29))
        return {
            "ok": True,
            "message": f"Numeric injection worked. Flag: {flag_val}",
            "raw": r.get("raw") or "",
        }

    # OR-style without spaces: 1OR1=1 / 1||1=1 / 1oRtrue
    if len(rows) >= 2:
        flag_val = _get_flag(29)
        return {
            "ok": True,
            "message": f"Numeric logic bypass (multi-row). Flag: {flag_val}",
            "raw": r.get("raw") or "",
        }

    if rows and (rows[0].get("username") == "admin" or rows[0].get("role") == "admin"):
        flag_val = _get_flag(29)
        return {
            "ok": True,
            "message": f"Targeted numeric bypass. Flag: {flag_val}",
            "raw": r.get("raw") or "",
        }

    return {
        "ok": False,
        "message": "Numeric context only — no spaces/quotes. Try operators without spaces (OR, ||, scientific notation).",
        "raw": r.get("raw") or "",
    }


# ───────────────────────── Level 30 — Inline Comments Bypass ─────────────────────────
def handle_30(p: dict) -> dict:
    u = p.get("username", "")
    # Blacklist whole words only — inline comments can split them
    if re.search(r"(?i)\bunion\b|\bselect\b|\bor\b|\band\b", u):
        # Allow if comments break the word in the raw payload for execution,
        # but the regex above already sees comments as non-word... actually
        # UN/**/ION does NOT match \bunion\b — good.
        return _blocked("Bare keyword blocked — split with inline comments /* */")

    q = f"SELECT id, username, role FROM users WHERE username = '{u}'"
    r = _run(30, q)

    if r.get("error"):
        return {
            "ok": False,
            "message": "Query error",
            "raw": r.get("raw") or str(r.get("error")),
            "error": r.get("error"),
        }

    rows = r.get("rows") or []
    blob = _rows_blob(rows)

    if "CTF{" in blob:
        flag_val = next((str(v) for row in rows for v in row.values() if str(v).startswith("CTF{")), _get_flag(30))
        return {
            "ok": True,
            "message": f"Inline-comment bypass worked. Flag: {flag_val}",
            "raw": r.get("raw") or "",
        }

    if rows and (rows[0].get("username") == "admin" or rows[0].get("role") == "admin"):
        if u.strip().lower() == "admin":
            return {
                "ok": False,
                "message": "Demonstrate keyword obfuscation with /* */, not plain admin.",
                "raw": r.get("raw") or "",
            }
        flag_val = _get_flag(30)
        return {
            "ok": True,
            "message": f"Comment-obfuscated injection succeeded. Flag: {flag_val}",
            "raw": r.get("raw") or "",
        }

    if len(rows) > 3:
        return {
            "ok": False,
            "message": "Too many rows — precise extraction only.",
            "raw": "",
        }

    return {
        "ok": False,
        "message": "Whole-word blacklist is active. Use inline comments inside keywords.",
        "raw": r.get("raw") or "",
    }


# ───────────────────────── Level 31 — Advanced Boolean ─────────────────────────
def handle_31(p: dict) -> dict:
    expr = p.get("username", "0")
    # Expression against secrets — boolean only
    q = f"SELECT id FROM secrets WHERE IF(({expr}), 1, 0) = 1 LIMIT 1"
    r = _run(31, q)

    if r.get("error"):
        return {"ok": False, "message": "0", "raw": "0", "error": r.get("error")}

    bit = "1" if r.get("rows") else "0"

    # Win when player proves knowledge of full flag via exact match expression
    lowered = expr.lower().replace(" ", "")
    if "flag=" in lowered or "flaglike" in lowered:
        # If condition true and references flag equality — accept
        if bit == "1" and "ctf{" in lowered:
            flag_val = _get_flag(31)
            return {
                "ok": True,
                "message": f"Boolean proof accepted. Flag: {flag_val}",
                "raw": "1",
            }

    return {
        "ok": True if bit == "1" else False,
        "message": bit,
        "raw": bit,
    }


# ───────────────────────── Level 32 — Time-Based Heavy Filter ─────────────────────────
def handle_32(p: dict) -> dict:
    u = p.get("username", "")
    if re.search(r"(?i)sleep|benchmark|get_lock|wait_for|pg_sleep", u):
        return _blocked("Common delay functions are blocked")

    q = f"SELECT id FROM users WHERE username = '{u}'"
    start = time.time()
    r = _run(32, q)
    elapsed = time.time() - start

    if r.get("error"):
        return {
            "ok": False,
            "message": "Query error",
            "raw": f"{r.get('raw')}\n[elapsed: {elapsed:.2f}s]",
            "error": r.get("error"),
        }

    if elapsed > 1.5:
        flag_val = _get_flag(32)
        return {
            "ok": True,
            "message": f"Alternative delay worked ({elapsed:.2f}s). Flag: {flag_val}",
            "raw": f"elapsed={elapsed:.2f}s",
        }

    return {
        "ok": False,
        "message": f"Finished in {elapsed:.2f}s. Delay functions blocked — find another slow path.",
        "raw": f"elapsed={elapsed:.2f}s",
    }


# ───────────────────────── Level 33 — Second-Order Advanced ─────────────────────────
def handle_33(p: dict) -> dict:
    """Same two-step pattern as 18, isolated DB, slightly stricter win."""
    action = (p.get("password") or "view").strip().lower()
    u = p.get("username", "")
    db = level_db(33)

    if action == "save":
        try:
            conn = get_conn(db)
            try:
                with conn.cursor() as cur:
                    cur.execute(
                        "CREATE TABLE IF NOT EXISTS profiles ("
                        "id INT PRIMARY KEY, name VARCHAR(512))"
                    )
                    cur.execute("DELETE FROM profiles WHERE id = 1")
                    cur.execute(f"INSERT INTO profiles (id, name) VALUES (1, '{u}')")
                    conn.commit()
            finally:
                conn.close()
            return {
                "ok": True,
                "message": "Stored. Use password=view to execute the second-order query.",
                "raw": f"saved_len={len(u)}",
            }
        except Exception as e:
            return {"ok": False, "message": "Save failed", "raw": str(e), "error": str(e)}

    q = (
        "SELECT id, username, role FROM users WHERE username = "
        "(SELECT name FROM profiles WHERE id = 1 LIMIT 1)"
    )
    r = _run(33, q)

    if r.get("error"):
        err = str(r.get("error") or "")
        if "CTF{" in err:
            return {
                "ok": True,
                "message": f"Second-order error extraction. Flag: {_get_flag(33)}",
                "raw": err,
                "error": err,
            }
        return {
            "ok": False,
            "message": "View error — adjust stored payload.",
            "raw": r.get("raw") or err,
            "error": err,
        }

    rows = r.get("rows") or []
    blob = _rows_blob(rows)
    if "CTF{" in blob:
        flag_val = next((str(v) for row in rows for v in row.values() if str(v).startswith("CTF{")), _get_flag(33))
        return {
            "ok": True,
            "message": f"Advanced second-order win. Flag: {flag_val}",
            "raw": r.get("raw") or "",
        }

    if any(row.get("role") == "admin" for row in rows):
        flag_val = _get_flag(33)
        return {
            "ok": True,
            "message": f"Second-order admin. Flag: {flag_val}",
            "raw": r.get("raw") or "",
        }

    if len(rows) > 3:
        return {
            "ok": False,
            "message": "Too many rows — keep the second-order payload precise.",
            "raw": "",
        }

    return {
        "ok": False,
        "message": "View ran. Store a payload that extracts secrets on the second step.",
        "raw": r.get("raw") or "",
    }


# ───────────────────────── Level 34 — WAF Regex Bypass ─────────────────────────
def handle_34(p: dict) -> dict:
    u = p.get("username", "")
    if re.search(r"(?i)(union\s+select|or\s+1\s*=\s*1|'?\s*or\s*')", u):
        return _blocked("WAF regex blocked classic patterns")

    q = f"SELECT id, username, role FROM users WHERE username = '{u}'"
    r = _run(34, q)

    if r.get("error"):
        return {
            "ok": False,
            "message": "Query error",
            "raw": r.get("raw") or str(r.get("error")),
            "error": r.get("error"),
        }

    rows = r.get("rows") or []
    blob = _rows_blob(rows)
    if "CTF{" in blob:
        flag_val = next((str(v) for row in rows for v in row.values() if str(v).startswith("CTF{")), _get_flag(34))
        return {
            "ok": True,
            "message": f"Regex WAF bypassed. Flag: {flag_val}",
            "raw": r.get("raw") or "",
        }

    if rows and (rows[0].get("username") == "admin" or rows[0].get("role") == "admin"):
        if u.strip().lower() == "admin":
            return {
                "ok": False,
                "message": "Bypass the regex with alternative syntax, not plain admin.",
                "raw": r.get("raw") or "",
            }
        flag_val = _get_flag(34)
        return {
            "ok": True,
            "message": f"Regex bypass succeeded. Flag: {flag_val}",
            "raw": r.get("raw") or "",
        }

    if len(rows) > 3:
        return {
            "ok": False,
            "message": "Too many rows — targeted bypass only.",
            "raw": "",
        }

    return {
        "ok": False,
        "message": "Classic union select / or 1=1 shapes are blocked. Use alternatives.",
        "raw": r.get("raw") or "",
    }


# ───────────────────────── Level 35 — No Error, No Time ─────────────────────────
def handle_35(p: dict) -> dict:
    """Always OK feedback — win via stacked side-effect writing a marker, or second statement."""
    u = p.get("username", "")
    db = level_db(35)

    # Ensure marker table
    try:
        conn = get_conn(db)
        try:
            with conn.cursor() as cur:
                cur.execute(
                    "CREATE TABLE IF NOT EXISTS sidechannel ("
                    "id INT PRIMARY KEY, note VARCHAR(255))"
                )
                conn.commit()
        finally:
            conn.close()
    except Exception:
        pass

    q = f"SELECT id FROM users WHERE username = '{u}'"
    # Support stacked to allow INSERT into sidechannel
    try:
        conn = get_conn(db)
        try:
            with conn.cursor() as cur:
                parts = [x.strip() for x in q.split(";") if x.strip()]
                for part in parts[:3]:
                    cur.execute(part)
                conn.commit()
                # Check sidechannel marker
                cur.execute("SELECT note FROM sidechannel WHERE id = 1")
                marker = cur.fetchone()
        finally:
            conn.close()
    except Exception as e:
        # Still return OK (no error feedback)
        return {"ok": True, "message": "OK", "raw": "OK"}

    if marker and marker.get("note"):
        note = str(marker.get("note"))
        if "CTF{" in note or note.lower() == "pwned":
            flag_val = _get_flag(35)
            return {
                "ok": True,
                "message": f"Side-effect confirmed. Flag: {flag_val}",
                "raw": "OK",
            }

    return {"ok": True, "message": "OK", "raw": "OK"}


# ───────────────────────── Level 36 — INSERT Injection ─────────────────────────
def handle_36(p: dict) -> dict:
    u = p.get("username", "")
    email = p.get("password", "x@x.com")
    lowered = (u + " " + email).lower()

    q = (
        f"INSERT INTO users (username, password, email, role) "
        f"VALUES ('{u}', 'pass', '{email}', 'user')"
    )
    r = _run(36, q)

    # After insert, check if role was escalated or secrets leaked via injection
    check = _run(36, "SELECT id, username, role FROM users WHERE role = 'admin' ORDER BY id DESC LIMIT 3")
    rows = check.get("rows") or []

    # Also allow extracting flag if injection did a subquery into a visible place —
    # detect CTF in error
    err = str(r.get("error") or "")
    if "CTF{" in err:
        return {
            "ok": True,
            "message": f"INSERT error-channel. Flag: {_get_flag(36)}",
            "raw": err,
            "error": err,
        }

    # Win if a new admin appeared that is not the original seed admin alone with injection evidence
    if "role" in lowered and "admin" in lowered and any(row.get("role") == "admin" for row in rows):
        # Require injection characters
        if "'" in u or "'" in email or ";" in u or ";" in email:
            flag_val = _get_flag(36)
            return {
                "ok": True,
                "message": f"INSERT injection escalated role. Flag: {flag_val}",
                "raw": r.get("raw") or "",
            }

    if r.get("error"):
        return {
            "ok": False,
            "message": "INSERT failed — break out of VALUES carefully.",
            "raw": r.get("raw") or err,
            "error": err,
        }

    return {
        "ok": False,
        "message": "Row inserted as user. Inject into VALUES to change role or extract secrets.",
        "raw": r.get("raw") or "",
    }


# ───────────────────────── Level 37 — UPDATE Injection ─────────────────────────
def handle_37(p: dict) -> dict:
    u = p.get("username", "")
    newmail = p.get("password", "a@b.c")
    lowered = (u + " " + newmail).lower()

    q = f"UPDATE users SET email = '{newmail}' WHERE username = '{u}'"
    r = _run(37, q)

    err = str(r.get("error") or "")
    if "CTF{" in err:
        return {
            "ok": True,
            "message": f"UPDATE error-channel. Flag: {_get_flag(37)}",
            "raw": err,
            "error": err,
        }

    # Check if admin email was changed via injection in WHERE
    check = _run(37, "SELECT username, email, role FROM users WHERE role = 'admin' LIMIT 1")
    admin_rows = check.get("rows") or []
    if admin_rows:
        admin_email = str(admin_rows[0].get("email") or "")
        if admin_email == newmail and ("'" in u or "or" in u.lower() or "or" in newmail.lower()):
            flag_val = _get_flag(37)
            return {
                "ok": True,
                "message": f"UPDATE injection hit admin. Flag: {flag_val}",
                "raw": r.get("raw") or "",
            }

    # role escalation via SET injection
    if "role" in lowered and "admin" in lowered and ("'" in newmail or "'" in u):
        check2 = _run(37, f"SELECT username, role FROM users WHERE username = '{u.split(chr(39))[0]}' LIMIT 1")
        # simpler: any user now admin beyond seed
        flag_val = _get_flag(37)
        # Verify at least one injection-looking success
        if re.search(r"(?i)role\s*=", newmail) or re.search(r"(?i)role\s*=", u):
            return {
                "ok": True,
                "message": f"UPDATE SET injection likely succeeded. Flag: {flag_val}",
                "raw": r.get("raw") or "",
            }

    if r.get("error"):
        return {
            "ok": False,
            "message": "UPDATE error",
            "raw": r.get("raw") or err,
            "error": err,
        }

    return {
        "ok": False,
        "message": "UPDATE ran. Inject in SET or WHERE (username / password fields).",
        "raw": r.get("raw") or "",
    }


# ───────────────────────── Level 38 — Limit & Offset Abuse ─────────────────────────
def handle_38(p: dict) -> dict:
    lim = p.get("username", "1")
    lowered = lim.lower()

    # Only allow relatively safe characters for LIMIT expression, but still injectable
    if re.search(r"[;]", lim):
        return _blocked("Semicolon not allowed in LIMIT")

    q = f"SELECT id, username, role FROM users ORDER BY id LIMIT {lim}"
    r = _run(38, q)

    if r.get("error"):
        err = str(r.get("error") or "")
        if "CTF{" in err:
            return {
                "ok": True,
                "message": f"LIMIT error-channel. Flag: {_get_flag(38)}",
                "raw": err,
                "error": err,
            }
        return {
            "ok": False,
            "message": "LIMIT expression error",
            "raw": r.get("raw") or err,
            "error": err,
        }

    rows = r.get("rows") or []
    blob = _rows_blob(rows)
    if "CTF{" in blob:
        flag_val = next((str(v) for row in rows for v in row.values() if str(v).startswith("CTF{")), _get_flag(38))
        return {
            "ok": True,
            "message": f"LIMIT injection extracted data. Flag: {flag_val}",
            "raw": r.get("raw") or "",
        }

    # PROCEDURE ANALYSE / subquery tricks may not return CTF in rows —
    # accept subquery mention with successful exec and secrets reference
    if "secrets" in lowered and not r.get("error"):
        flag_val = _get_flag(38)
        return {
            "ok": True,
            "message": f"LIMIT subquery touched secrets. Flag: {flag_val}",
            "raw": r.get("raw") or "",
        }

    if len(rows) > 5:
        return {
            "ok": False,
            "message": "Too many rows from LIMIT — be precise.",
            "raw": "",
        }

    return {
        "ok": False,
        "message": "LIMIT is injectable (expression). Subquery / nested SELECT for secrets.",
        "raw": r.get("raw") or "",
    }


# ───────────────────────── Level 39 — Prepared Statement Bypass ─────────────────────────
def handle_39(p: dict) -> dict:
    uid = p.get("password", "1")
    name = p.get("username", "")
    try:
        int(uid)
    except ValueError:
        return _blocked("id must be integer (prepared-style)")

    q = f"SELECT id, username, role FROM users WHERE id = {int(uid)} AND username = '{name}'"
    r = _run(39, q)

    if r.get("error"):
        return {
            "ok": False,
            "message": "Query error",
            "raw": r.get("raw") or str(r.get("error")),
            "error": r.get("error"),
        }

    rows = r.get("rows") or []
    blob = _rows_blob(rows)
    if "CTF{" in blob:
        flag_val = next((str(v) for row in rows for v in row.values() if str(v).startswith("CTF{")), _get_flag(39))
        return {
            "ok": True,
            "message": f"Partial prepared bypass. Flag: {flag_val}",
            "raw": r.get("raw") or "",
        }

    if rows and (rows[0].get("username") == "admin" or rows[0].get("role") == "admin"):
        if name.strip().lower() == "admin":
            return {
                "ok": False,
                "message": "Inject via username; id is validated as int.",
                "raw": r.get("raw") or "",
            }
        flag_val = _get_flag(39)
        return {
            "ok": True,
            "message": f"Username field injection worked. Flag: {flag_val}",
            "raw": r.get("raw") or "",
        }

    if len(rows) > 3:
        return {
            "ok": False,
            "message": "Too many rows — inject precisely on the username parameter.",
            "raw": "",
        }

    return {
        "ok": False,
        "message": "id is constrained; username is still concatenated. Attack the string side.",
        "raw": r.get("raw") or "",
    }


# ───────────────────────── Level 40 — Quote Stripping ─────────────────────────
def handle_40(p: dict) -> dict:
    raw = p.get("username", "")
    u = raw.replace("'", "").replace('"', "")
    # Quotes stripped — must use no-quote techniques; but query still uses quotes around value
    # So classic ' or 1=1 -- becomes  or 1=1 -- which can still work if spaces ok

    q = f"SELECT id, username, role FROM users WHERE username = '{u}'"
    r = _run(40, q)

    if r.get("error"):
        return {
            "ok": False,
            "message": "Query error",
            "raw": r.get("raw") or str(r.get("error")),
            "error": r.get("error"),
        }

    rows = r.get("rows") or []
    blob = _rows_blob(rows)
    if "CTF{" in blob:
        flag_val = next((str(v) for row in rows for v in row.values() if str(v).startswith("CTF{")), _get_flag(40))
        return {
            "ok": True,
            "message": f"Quote-less technique worked. Flag: {flag_val}",
            "raw": r.get("raw") or "",
        }

    if len(rows) >= 2:
        flag_val = _get_flag(40)
        return {
            "ok": True,
            "message": f"Bypassed without quotes. Flag: {flag_val}",
            "raw": r.get("raw") or "",
        }

    if rows and (rows[0].get("role") == "admin" or rows[0].get("username") == "admin"):
        if raw.strip().lower() == "admin":
            return {
                "ok": False,
                "message": "Quotes are stripped — craft a no-quote injection.",
                "raw": r.get("raw") or "",
            }
        flag_val = _get_flag(40)
        return {
            "ok": True,
            "message": f"No-quote admin path. Flag: {flag_val}",
            "raw": r.get("raw") or "",
        }

    return {
        "ok": False,
        "message": "Quotes are stripped from input. Try OR/UNION without relying on quote breaks, or CHAR/hex.",
        "raw": r.get("raw") or "",
    }


# ───────────────────────── Level 41 — JSON + Dual Fields ─────────────────────────
def handle_41(p: dict) -> dict:
    u, pw = p.get("username", ""), p.get("password", "")
    q = f"SELECT id, username, role FROM users WHERE username = '{u}' AND email = '{pw}'"
    r = _run(41, q)

    if r.get("error"):
        return {
            "ok": False,
            "message": "Query error",
            "raw": r.get("raw") or str(r.get("error")),
            "error": r.get("error"),
        }

    rows = r.get("rows") or []
    blob = _rows_blob(rows)
    if "CTF{" in blob:
        flag_val = next((str(v) for row in rows for v in row.values() if str(v).startswith("CTF{")), _get_flag(41))
        return {
            "ok": True,
            "message": f"Dual-field injection worked. Flag: {flag_val}",
            "raw": r.get("raw") or "",
        }

    if rows and (rows[0].get("username") == "admin" or rows[0].get("role") == "admin"):
        if u.strip().lower() == "admin" and "'" not in u and "'" not in pw:
            return {
                "ok": False,
                "message": "Inject into username and/or password (email) fields.",
                "raw": r.get("raw") or "",
            }
        flag_val = _get_flag(41)
        return {
            "ok": True,
            "message": f"Dual-field bypass. Flag: {flag_val}",
            "raw": r.get("raw") or "",
        }

    if len(rows) > 3:
        return {
            "ok": False,
            "message": "Too many rows — do not dump.",
            "raw": "",
        }

    return {
        "ok": False,
        "message": "Both fields are injectable. Attack either side of the AND.",
        "raw": r.get("raw") or "",
    }


# ───────────────────────── Level 42 — Header + Cookie Chain ─────────────────────────
def handle_42(p: dict) -> dict:
    u, pw = p.get("username", ""), p.get("password", "")
    q = f"SELECT id, username, role FROM users WHERE username = '{u}' OR password = '{pw}'"
    r = _run(42, q)

    if r.get("error"):
        return {
            "ok": False,
            "message": "Query error",
            "raw": r.get("raw") or str(r.get("error")),
            "error": r.get("error"),
        }

    rows = r.get("rows") or []
    blob = _rows_blob(rows)
    if "CTF{" in blob:
        flag_val = next((str(v) for row in rows for v in row.values() if str(v).startswith("CTF{")), _get_flag(42))
        return {
            "ok": True,
            "message": f"Chained field injection. Flag: {flag_val}",
            "raw": r.get("raw") or "",
        }

    if any(row.get("username") == "admin" or row.get("role") == "admin" for row in rows):
        if u.strip().lower() in ("admin", "") and pw.strip().lower() in ("admin", "") and "'" not in u + pw:
            return {
                "ok": False,
                "message": "Either field can carry the payload — inject, do not guess passwords.",
                "raw": r.get("raw") or "",
            }
        flag_val = _get_flag(42)
        return {
            "ok": True,
            "message": f"OR-chain reached admin. Flag: {flag_val}",
            "raw": r.get("raw") or "",
        }

    if len(rows) > 3:
        return {
            "ok": False,
            "message": "Too many rows — precise injection on one field is enough.",
            "raw": "",
        }

    return {
        "ok": False,
        "message": "username OR password — inject in either simulated header/cookie field.",
        "raw": r.get("raw") or "",
    }


# ───────────────────────── Level 43 — Blind Extraction ─────────────────────────
def handle_43(p: dict) -> dict:
    expr = p.get("username", "0")
    q = f"SELECT 1 FROM secrets WHERE ({expr}) LIMIT 1"
    r = _run(43, q)

    if r.get("error"):
        return {"ok": False, "message": "no", "raw": "no"}

    yes = bool(r.get("rows"))
    lowered = expr.lower().replace(" ", "")

    # Accept full-flag equality proof
    if yes and "ctf{" in lowered and ("flag=" in lowered or "flaglike" in lowered):
        return {
            "ok": True,
            "message": f"yes — Flag: {_get_flag(43)}",
            "raw": "yes",
        }

    return {
        "ok": yes,
        "message": "yes" if yes else "no",
        "raw": "yes" if yes else "no",
    }


# ───────────────────────── Level 44 — Filter + Encoding Maze ─────────────────────────
def handle_44(p: dict) -> dict:
    u = p.get("username", "")
    # Layer 1: strip spaces and --
    u2 = u.replace(" ", "").replace("--", "")
    # Layer 2: keywords on stripped text
    if re.search(r"(?i)union|select|or|and", u2):
        return _blocked("Layered filter blocked request")

    # Note: comments can restore keywords in real SQL (/**/) — if player used comments,
    # stripped keyword check may still catch 'union' inside unless broken: UN/**/ION
    # UN/**/ION after removing spaces is still UN/**/ION — regex union won't match. Good.

    q = f"SELECT id, username, role FROM users WHERE username = '{u}'"
    r = _run(44, q)

    if r.get("error"):
        return {
            "ok": False,
            "message": "Query error",
            "raw": r.get("raw") or str(r.get("error")),
            "error": r.get("error"),
        }

    rows = r.get("rows") or []
    blob = _rows_blob(rows)
    if "CTF{" in blob:
        flag_val = next((str(v) for row in rows for v in row.values() if str(v).startswith("CTF{")), _get_flag(44))
        return {
            "ok": True,
            "message": f"Layered filters bypassed. Flag: {flag_val}",
            "raw": r.get("raw") or "",
        }

    if rows and (rows[0].get("username") == "admin" or rows[0].get("role") == "admin"):
        if u.strip().lower() == "admin":
            return {
                "ok": False,
                "message": "Bypass the layered filters with comments/encoding.",
                "raw": r.get("raw") or "",
            }
        flag_val = _get_flag(44)
        return {
            "ok": True,
            "message": f"Filter maze cleared. Flag: {flag_val}",
            "raw": r.get("raw") or "",
        }

    if len(rows) > 3:
        return {
            "ok": False,
            "message": "Too many rows.",
            "raw": "",
        }

    return {
        "ok": False,
        "message": "Spaces stripped and keywords blocked. Use /**/ and encoding tricks.",
        "raw": r.get("raw") or "",
    }


# ───────────────────────── Level 45 — Conditional Error Blind ─────────────────────────
def handle_45(p: dict) -> dict:
    expr = p.get("username", "0")
    # Error only when condition true — player controls condition
    q = (
        f"SELECT IF(({expr}), "
        f"(SELECT 1/0 FROM secrets WHERE flag IS NOT NULL LIMIT 1), 0)"
    )
    r = _run(45, q)

    err = str(r.get("error") or "")
    raw = str(r.get("raw") or "")

    # Division by zero or similar indicates true condition
    if r.get("error") and re.search(r"(?i)division|error|truncated", err):
        lowered = expr.lower().replace(" ", "")
        if "flag" in lowered and "ctf{" in lowered:
            return {
                "ok": True,
                "message": f"Conditional error confirmed knowledge. Flag: {_get_flag(45)}",
                "raw": err,
                "error": err,
            }
        # Still useful feedback for binary search
        return {
            "ok": False,
            "message": "Condition TRUE (error triggered). Narrow the flag guess.",
            "raw": err,
            "error": err,
        }

    if "CTF{" in err or "CTF{" in raw:
        return {
            "ok": True,
            "message": f"Error leaked flag. Flag: {_get_flag(45)}",
            "raw": err or raw,
        }

    return {
        "ok": False,
        "message": "Condition FALSE or no error. Use IF(condition, error-expr, 0).",
        "raw": r.get("raw") or "",
    }



# ───────────────────────── Level 46 — WAF + Obfuscation ─────────────────────────
def handle_46(p: dict) -> dict:
    """Classic patterns blocked — obfuscate past the regex."""
    u = p.get("username", "")
    if re.search(r"(?i)union\s+select|or\s+1\s*=\s*1", u):
        return _blocked("WAF blocked classic patterns — obfuscate")

    q = f"SELECT id, username, role FROM users WHERE username = '{u}'"
    r = _run(46, q)

    if r.get("error"):
        err = str(r.get("error") or "")
        if "CTF{" in err:
            return {
                "ok": True,
                "message": f"Error extraction after WAF. Flag: {_get_flag(46)}",
                "raw": err,
                "error": err,
            }
        return {
            "ok": False,
            "message": "Query error",
            "raw": r.get("raw") or err,
            "error": err,
        }

    rows = r.get("rows") or []
    blob = _rows_blob(rows)
    if "CTF{" in blob:
        flag_val = next((str(v) for row in rows for v in row.values() if str(v).startswith("CTF{")), _get_flag(46))
        return {
            "ok": True,
            "message": f"WAF bypassed. Flag: {flag_val}",
            "raw": r.get("raw") or "",
        }

    if any(row.get("username") == "admin" or row.get("role") == "admin" for row in rows):
        if u.strip().lower() == "admin":
            return {
                "ok": False,
                "message": "Plain admin is not enough — demonstrate obfuscation.",
                "raw": r.get("raw") or "",
            }
        flag_val = _get_flag(46)
        return {
            "ok": True,
            "message": f"Obfuscated bypass reached admin. Flag: {flag_val}",
            "raw": r.get("raw") or "",
        }

    if len(rows) >= 2:
        flag_val = _get_flag(46)
        return {
            "ok": True,
            "message": f"Logic bypass after WAF. Flag: {flag_val}",
            "raw": r.get("raw") or "",
        }

    if len(rows) > 5:
        return {
            "ok": False,
            "message": "Too many rows — targeted extraction only.",
            "raw": "",
        }

    return {
        "ok": False,
        "message": "WAF blocks 'union select' and 'or 1=1'. Use /**/, case tricks, or ||.",
        "raw": r.get("raw") or "",
    }


# ───────────────────────── Level 47 — Stacked + Filter ─────────────────────────
def handle_47(p: dict) -> dict:
    """Stacked allowed; DROP/DELETE/UPDATE/INSERT words blocked."""
    u = p.get("username", "")
    if re.search(r"(?i)\b(drop|delete|update|insert|alter|truncate)\b", u):
        return _blocked("Dangerous DML/DDL keyword blocked")

    q = f"SELECT id, username, role FROM users WHERE username = '{u}'"
    db = level_db(47)
    try:
        conn = get_conn(db)
        try:
            with conn.cursor() as cur:
                parts = [x.strip() for x in q.split(";") if x.strip()]
                if len(parts) > 4:
                    return {"ok": False, "message": "Too many stacked statements (max 4).", "raw": ""}
                results = []
                for part in parts:
                    # re-check each part for banned keywords
                    if re.search(r"(?i)\b(drop|delete|update|insert|alter|truncate)\b", part):
                        return _blocked("Dangerous keyword in stacked part")
                    cur.execute(part)
                    try:
                        results.append(cur.fetchall())
                    except Exception:
                        results.append("(ok non-select)")
                conn.commit()
                all_blob = " ".join(_rows_blob(r) if isinstance(r, list) else "" for r in results)
                if "CTF{" in all_blob:
                    flag_val = _get_flag(47)
                    for rset in results:
                        if isinstance(rset, list):
                            for row in rset:
                                for v in row.values():
                                    if str(v).startswith("CTF{"):
                                        flag_val = str(v)
                    return {
                        "ok": True,
                        "message": f"Stacked (filtered) extraction. Flag: {flag_val}",
                        "raw": f"Results: {results}",
                    }
                if len(parts) >= 2:
                    return {
                        "ok": False,
                        "message": "Stacked statements ran. SELECT the flag without DML keywords.",
                        "raw": f"Statements: {len(parts)}",
                    }
                rows = results[0] if results and isinstance(results[0], list) else []
                if len(rows) > 3:
                    return {
                        "ok": False,
                        "message": "Too many rows — stack a precise SELECT on secrets.",
                        "raw": "",
                    }
                return {
                    "ok": False,
                    "message": "Use ';' to stack a SELECT (no INSERT/UPDATE/DELETE/DROP).",
                    "raw": f"Result: {rows}",
                }
        finally:
            conn.close()
    except Exception as e:
        return {
            "ok": False,
            "message": "Database error",
            "raw": f"Query: {q}\nError: {e}",
            "error": str(e),
        }


# ───────────────────────── Level 48 — No UNION Keyword ─────────────────────────
def handle_48(p: dict) -> dict:
    """UNION word blocked — error / blind / stacked instead."""
    u = p.get("username", "")
    if re.search(r"(?i)union", u):
        return _blocked("UNION is blocked on this level")

    q = f"SELECT id, username, role FROM users WHERE username = '{u}'"
    r = _run(48, q)

    err = str(r.get("error") or "")
    if "CTF{" in err:
        return {
            "ok": True,
            "message": f"Error-based extraction (no UNION). Flag: {_get_flag(48)}",
            "raw": err,
            "error": err,
        }

    if r.get("error"):
        return {
            "ok": False,
            "message": "Error surfaced — extract data without UNION.",
            "raw": r.get("raw") or err,
            "error": err,
        }

    rows = r.get("rows") or []
    blob = _rows_blob(rows)
    if "CTF{" in blob:
        # stacked or subquery without the word union
        flag_val = next((str(v) for row in rows for v in row.values() if str(v).startswith("CTF{")), _get_flag(48))
        return {
            "ok": True,
            "message": f"Extracted without UNION. Flag: {flag_val}",
            "raw": r.get("raw") or "",
        }

    if any(row.get("username") == "admin" or row.get("role") == "admin" for row in rows):
        if u.strip().lower() == "admin":
            return {
                "ok": False,
                "message": "Need extraction without the UNION keyword.",
                "raw": r.get("raw") or "",
            }
        flag_val = _get_flag(48)
        return {
            "ok": True,
            "message": f"Logic bypass without UNION. Flag: {flag_val}",
            "raw": r.get("raw") or "",
        }

    if len(rows) > 3:
        return {
            "ok": False,
            "message": "Too many rows — use error-based or precise subquery.",
            "raw": "",
        }

    return {
        "ok": False,
        "message": "UNION is forbidden. Try error-based, boolean, or stacked SELECT.",
        "raw": r.get("raw") or "",
    }


# ───────────────────────── Level 49 — No Spaces ─────────────────────────
def handle_49(p: dict) -> dict:
    """All spaces stripped from input before query."""
    raw = p.get("username", "")
    u = raw.replace(" ", "")

    q = f"SELECT id, username, role FROM users WHERE username = '{u}'"
    r = _run(49, q)

    if r.get("error"):
        err = str(r.get("error") or "")
        if "CTF{" in err:
            return {
                "ok": True,
                "message": f"No-space error extraction. Flag: {_get_flag(49)}",
                "raw": err,
                "error": err,
            }
        return {
            "ok": False,
            "message": "Query error",
            "raw": r.get("raw") or err,
            "error": err,
        }

    rows = r.get("rows") or []
    blob = _rows_blob(rows)
    if "CTF{" in blob:
        flag_val = next((str(v) for row in rows for v in row.values() if str(v).startswith("CTF{")), _get_flag(49))
        return {
            "ok": True,
            "message": f"No-space payload worked. Flag: {flag_val}",
            "raw": r.get("raw") or "",
        }

    if any(row.get("username") == "admin" or row.get("role") == "admin" for row in rows):
        if raw.strip().lower() == "admin":
            return {
                "ok": False,
                "message": "Spaces are stripped — craft injection without relying on spaces.",
                "raw": r.get("raw") or "",
            }
        flag_val = _get_flag(49)
        return {
            "ok": True,
            "message": f"No-space bypass. Flag: {flag_val}",
            "raw": r.get("raw") or "",
        }

    if len(rows) >= 2:
        flag_val = _get_flag(49)
        return {
            "ok": True,
            "message": f"No-space logic bypass. Flag: {flag_val}",
            "raw": r.get("raw") or "",
        }

    return {
        "ok": False,
        "message": "Spaces are removed. Use /**/ or tabs/parentheses instead of spaces.",
        "raw": r.get("raw") or "",
    }


# ───────────────────────── Level 50 — No Comments ─────────────────────────
def handle_50(p: dict) -> dict:
    """SQL comments forbidden — balance quotes naturally."""
    u = p.get("username", "")
    if "--" in u or "/*" in u or "*/" in u or "#" in u:
        return _blocked("Comments are not allowed")

    q = f"SELECT id, username, role FROM users WHERE username = '{u}' AND role = 'user'"
    r = _run(50, q)

    if r.get("error"):
        return {
            "ok": False,
            "message": "Query error — balance quotes without comments.",
            "raw": r.get("raw") or str(r.get("error")),
            "error": r.get("error"),
        }

    rows = r.get("rows") or []
    blob = _rows_blob(rows)
    if "CTF{" in blob:
        flag_val = next((str(v) for row in rows for v in row.values() if str(v).startswith("CTF{")), _get_flag(50))
        return {
            "ok": True,
            "message": f"No-comment injection worked. Flag: {flag_val}",
            "raw": r.get("raw") or "",
        }

    if any(row.get("username") == "admin" or row.get("role") == "admin" for row in rows):
        flag_val = _get_flag(50)
        return {
            "ok": True,
            "message": f"Logic balanced without comments. Flag: {flag_val}",
            "raw": r.get("raw") or "",
        }

    if len(rows) >= 2:
        flag_val = _get_flag(50)
        return {
            "ok": True,
            "message": f"Multi-row without comments. Flag: {flag_val}",
            "raw": r.get("raw") or "",
        }

    return {
        "ok": False,
        "message": "Comments blocked and role='user' is appended. Close quotes and balance AND.",
        "raw": r.get("raw") or "",
    }


# ───────────────────────── Level 51 — Blind + Heavy WAF ─────────────────────────
def handle_51(p: dict) -> dict:
    """Strong keyword block + boolean channel on secrets."""
    expr = p.get("username", "0")
    if re.search(r"(?i)union|sleep|benchmark|information_schema|select|from", expr):
        # allow comment-broken tokens
        stripped = re.sub(r"/\*.*?\*/", "", expr.lower())
        if re.search(r"(?i)union|sleep|benchmark|information_schema|\bselect\b|\bfrom\b", stripped):
            return _blocked("Heavy WAF blocked keyword")

    q = f"SELECT id FROM secrets WHERE ({expr}) LIMIT 1"
    r = _run(51, q)

    if r.get("error"):
        return {"ok": False, "message": "0", "raw": "0"}

    bit = "1" if r.get("rows") else "0"
    lowered = expr.lower().replace(" ", "")
    if bit == "1" and "ctf{" in lowered and ("flag=" in lowered or "flaglike" in lowered):
        return {
            "ok": True,
            "message": f"1 — Flag: {_get_flag(51)}",
            "raw": "1",
        }

    return {
        "ok": bit == "1",
        "message": bit,
        "raw": bit,
    }


# ───────────────────────── Level 52 — Polyglot Payload ─────────────────────────
def handle_52(p: dict) -> dict:
    """Classic string context — clean extraction, no dump."""
    u = p.get("username", "")
    q = f"SELECT id, username, role FROM users WHERE username = '{u}'"
    r = _run(52, q)

    if r.get("error"):
        err = str(r.get("error") or "")
        if "CTF{" in err:
            return {
                "ok": True,
                "message": f"Polyglot error path. Flag: {_get_flag(52)}",
                "raw": err,
                "error": err,
            }
        return {
            "ok": False,
            "message": "Query error",
            "raw": r.get("raw") or err,
            "error": err,
        }

    rows = r.get("rows") or []
    blob = _rows_blob(rows)
    if "CTF{" in blob:
        flag_val = next((str(v) for row in rows for v in row.values() if str(v).startswith("CTF{")), _get_flag(52))
        return {
            "ok": True,
            "message": f"Clean extraction. Flag: {flag_val}",
            "raw": r.get("raw") or "",
        }

    if any(row.get("username") == "admin" or row.get("role") == "admin" for row in rows):
        if u.strip().lower() == "admin":
            return {
                "ok": False,
                "message": "Extract the flag with a precise polyglot payload.",
                "raw": r.get("raw") or "",
            }
        flag_val = _get_flag(52)
        return {
            "ok": True,
            "message": f"Admin via polyglot. Flag: {flag_val}",
            "raw": r.get("raw") or "",
        }

    if len(rows) > 3:
        return {
            "ok": False,
            "message": "Too many rows — one clean payload to the flag.",
            "raw": "",
        }

    return {
        "ok": False,
        "message": "Classic string SQLi. Craft one clean payload that extracts secrets.flag.",
        "raw": r.get("raw") or "",
    }


# ───────────────────────── Level 53 — No Quotes Allowed ─────────────────────────
def handle_53(p: dict) -> dict:
    """Quotes rejected — numeric id context only."""
    u = p.get("username", "")
    if "'" in u or '"' in u:
        return _blocked("Quotes are forbidden")

    q = f"SELECT id, username, role FROM users WHERE id = {u or 0}"
    r = _run(53, q)

    if r.get("error"):
        err = str(r.get("error") or "")
        if "CTF{" in err:
            return {
                "ok": True,
                "message": f"Numeric error extraction. Flag: {_get_flag(53)}",
                "raw": err,
                "error": err,
            }
        return {
            "ok": False,
            "message": "Query error",
            "raw": r.get("raw") or err,
            "error": err,
        }

    rows = r.get("rows") or []
    blob = _rows_blob(rows)
    if "CTF{" in blob:
        flag_val = next((str(v) for row in rows for v in row.values() if str(v).startswith("CTF{")), _get_flag(53))
        return {
            "ok": True,
            "message": f"Numeric injection worked. Flag: {flag_val}",
            "raw": r.get("raw") or "",
        }

    if len(rows) >= 2:
        flag_val = _get_flag(53)
        return {
            "ok": True,
            "message": f"Numeric logic bypass. Flag: {flag_val}",
            "raw": r.get("raw") or "",
        }

    if any(row.get("username") == "admin" or row.get("role") == "admin" for row in rows):
        flag_val = _get_flag(53)
        return {
            "ok": True,
            "message": f"Numeric path to admin. Flag: {flag_val}",
            "raw": r.get("raw") or "",
        }

    return {
        "ok": False,
        "message": "No quotes. Inject into numeric id (OR, UNION without quotes via hex/CHAR).",
        "raw": r.get("raw") or "",
    }


# ───────────────────────── Level 54 — Bit-by-Bit Advanced ─────────────────────────
def handle_54(p: dict) -> dict:
    """Y/N channel for bit / ASCII extraction on secrets."""
    expr = p.get("username", "0")
    q = f"SELECT id FROM secrets WHERE ({expr}) LIMIT 1"
    r = _run(54, q)

    if r.get("error"):
        return {"ok": False, "message": "N", "raw": "N"}

    yes = bool(r.get("rows"))
    lowered = expr.lower().replace(" ", "")

    if yes and "ctf{" in lowered and ("flag=" in lowered or "flaglike" in lowered):
        return {
            "ok": True,
            "message": f"Y — Flag: {_get_flag(54)}",
            "raw": "Y",
        }

    return {
        "ok": yes,
        "message": "Y" if yes else "N",
        "raw": "Y" if yes else "N",
    }


# ───────────────────────── Level 55 — Chained Contexts (second-order) ─────────────────────────
def handle_55(p: dict) -> dict:
    """password=save stores; password=view executes second-order query."""
    action = (p.get("password") or "view").strip().lower()
    u = p.get("username", "")
    db = level_db(55)

    if action == "save":
        try:
            conn = get_conn(db)
            try:
                with conn.cursor() as cur:
                    cur.execute(
                        "CREATE TABLE IF NOT EXISTS profiles ("
                        "id INT PRIMARY KEY, name VARCHAR(512))"
                    )
                    cur.execute("DELETE FROM profiles WHERE id = 1")
                    cur.execute(f"INSERT INTO profiles (id, name) VALUES (1, '{u}')")
                    conn.commit()
            finally:
                conn.close()
            return {
                "ok": True,
                "message": "Stored. Set password=view to trigger second-order execution.",
                "raw": f"saved_len={len(u)}",
            }
        except Exception as e:
            return {"ok": False, "message": "Save failed", "raw": str(e), "error": str(e)}

    q = (
        "SELECT id, username, role FROM users WHERE username = "
        "(SELECT name FROM profiles WHERE id = 1 LIMIT 1)"
    )
    r = _run(55, q)

    if r.get("error"):
        err = str(r.get("error") or "")
        if "CTF{" in err:
            return {
                "ok": True,
                "message": f"Second-order error path. Flag: {_get_flag(55)}",
                "raw": err,
                "error": err,
            }
        return {
            "ok": False,
            "message": "View error — adjust stored payload.",
            "raw": r.get("raw") or err,
            "error": err,
        }

    rows = r.get("rows") or []
    blob = _rows_blob(rows)
    if "CTF{" in blob:
        flag_val = next((str(v) for row in rows for v in row.values() if str(v).startswith("CTF{")), _get_flag(55))
        return {
            "ok": True,
            "message": f"Chained second-order win. Flag: {flag_val}",
            "raw": r.get("raw") or "",
        }

    if any(row.get("username") == "admin" or row.get("role") == "admin" for row in rows):
        flag_val = _get_flag(55)
        return {
            "ok": True,
            "message": f"Second-order admin. Flag: {flag_val}",
            "raw": r.get("raw") or "",
        }

    if len(rows) > 3:
        return {
            "ok": False,
            "message": "Too many rows — precise second-order payload only.",
            "raw": "",
        }

    return {
        "ok": False,
        "message": "save then view. Store a payload that extracts secrets on view.",
        "raw": r.get("raw") or "",
    }


# ───────────────────────── Level 56 — Full Chain Expert ─────────────────────────
def handle_56(p: dict) -> dict:
    """Keywords blocked unless split with inline comments."""
    u = p.get("username", "")
    # Bare keywords blocked; UN/**/ION allowed
    low = u.lower()
    for kw in ("union", "select", "or"):
        if re.search(rf"(?<![a-z_/*]){kw}(?![a-z_/*])", low):
            if not re.search(r"/\*.*?\*/", u):
                return _blocked(f"Direct keyword '{kw}' blocked — use inline comments")
            # if comments present but keyword still contiguous, still block
            stripped = re.sub(r"/\*.*?\*/", "", low)
            if re.search(rf"(?<![a-z_]){kw}(?![a-z_])", stripped):
                return _blocked(f"Keyword '{kw}' still contiguous — split it with /* */")

    q = f"SELECT id, username, role FROM users WHERE username = '{u}'"
    r = _run(56, q)

    if r.get("error"):
        err = str(r.get("error") or "")
        if "CTF{" in err:
            return {
                "ok": True,
                "message": f"Expert chain error path. Flag: {_get_flag(56)}",
                "raw": err,
                "error": err,
            }
        return {
            "ok": False,
            "message": "Query error",
            "raw": r.get("raw") or err,
            "error": err,
        }

    rows = r.get("rows") or []
    blob = _rows_blob(rows)
    if "CTF{" in blob:
        flag_val = next((str(v) for row in rows for v in row.values() if str(v).startswith("CTF{")), _get_flag(56))
        return {
            "ok": True,
            "message": f"Expert obfuscation worked. Flag: {flag_val}",
            "raw": r.get("raw") or "",
        }

    if any(row.get("username") == "admin" or row.get("role") == "admin" for row in rows):
        if u.strip().lower() == "admin":
            return {
                "ok": False,
                "message": "Demonstrate comment-obfuscated keywords.",
                "raw": r.get("raw") or "",
            }
        flag_val = _get_flag(56)
        return {
            "ok": True,
            "message": f"Obfuscated admin path. Flag: {flag_val}",
            "raw": r.get("raw") or "",
        }

    if len(rows) > 3:
        return {
            "ok": False,
            "message": "Too many rows.",
            "raw": "",
        }

    return {
        "ok": False,
        "message": "Keywords must be split with /* */ (e.g. UN/**/ION SE/**/LECT).",
        "raw": r.get("raw") or "",
    }


# ───────────────────────── Level 57 — Protocol Surface ─────────────────────────
def handle_57(p: dict) -> dict:
    """Any classic path to secrets.flag; OUTFILE blocked."""
    u = p.get("username", "")
    if re.search(r"(?i)into\s+outfile|load_file\s*\(", u):
        return _blocked("OUTFILE / LOAD_FILE disabled")

    q = f"SELECT id, username, role FROM users WHERE username = '{u}'"
    r = _run(57, q)

    err = str(r.get("error") or "")
    if "CTF{" in err:
        return {
            "ok": True,
            "message": f"Error-channel extraction. Flag: {_get_flag(57)}",
            "raw": err,
            "error": err,
        }

    if r.get("error"):
        return {
            "ok": False,
            "message": "Error surfaced — dig for the flag.",
            "raw": r.get("raw") or err,
            "error": err,
        }

    rows = r.get("rows") or []
    blob = _rows_blob(rows)
    if "CTF{" in blob:
        flag_val = next((str(v) for row in rows for v in row.values() if str(v).startswith("CTF{")), _get_flag(57))
        return {
            "ok": True,
            "message": f"Extracted secrets.flag. Flag: {flag_val}",
            "raw": r.get("raw") or "",
        }

    if any(row.get("username") == "admin" or row.get("role") == "admin" for row in rows):
        if u.strip().lower() == "admin":
            return {
                "ok": False,
                "message": "Reach secrets.flag via union/error/blind — not plain admin.",
                "raw": r.get("raw") or "",
            }
        flag_val = _get_flag(57)
        return {
            "ok": True,
            "message": f"Privileged path. Flag: {flag_val}",
            "raw": r.get("raw") or "",
        }

    if len(rows) > 3:
        return {
            "ok": False,
            "message": "Too many rows — extract the flag precisely.",
            "raw": "",
        }

    return {
        "ok": False,
        "message": "Open surface. Error, UNION, or blind — any path to secrets.flag.",
        "raw": r.get("raw") or "",
    }


# ───────────────────────── Level 58 — Race Surface ─────────────────────────
def handle_58(p: dict) -> dict:
    """Same vulnerable login surface — standard extraction wins."""
    u = p.get("username", "")
    pw = p.get("password", "")

    q = f"SELECT id, username, role FROM users WHERE username = '{u}' AND password = '{pw}'"
    r = _run(58, q)

    if r.get("error"):
        err = str(r.get("error") or "")
        if "CTF{" in err:
            return {
                "ok": True,
                "message": f"Race-surface error path. Flag: {_get_flag(58)}",
                "raw": err,
                "error": err,
            }
        return {
            "ok": False,
            "message": "Query error",
            "raw": r.get("raw") or err,
            "error": err,
        }

    rows = r.get("rows") or []
    blob = _rows_blob(rows)
    if "CTF{" in blob:
        flag_val = next((str(v) for row in rows for v in row.values() if str(v).startswith("CTF{")), _get_flag(58))
        return {
            "ok": True,
            "message": f"Extracted on race surface. Flag: {flag_val}",
            "raw": r.get("raw") or "",
        }

    if any(row.get("username") == "admin" or row.get("role") == "admin" for row in rows):
        if u.strip().lower() == "admin" and "'" not in u and "'" not in pw:
            return {
                "ok": False,
                "message": "Inject — do not guess the admin password.",
                "raw": r.get("raw") or "",
            }
        flag_val = _get_flag(58)
        return {
            "ok": True,
            "message": f"Auth bypass. Flag: {flag_val}",
            "raw": r.get("raw") or "",
        }

    if len(rows) >= 2:
        flag_val = _get_flag(58)
        return {
            "ok": True,
            "message": f"Logic bypass. Flag: {flag_val}",
            "raw": r.get("raw") or "",
        }

    return {
        "ok": False,
        "message": "Login surface is injectable on username/password.",
        "raw": r.get("raw") or "",
    }


# ───────────────────────── Level 59 — Almost Impossible Filter ─────────────────────────
def handle_59(p: dict) -> dict:
    """Very limited charset: letters, digits, _, space, quotes, -|=<> """
    u = p.get("username", "")
    if re.search(r"[^a-zA-Z0-9_\s'\-\|=<>]", u):
        return _blocked("Illegal character — charset is restricted")

    q = f"SELECT id, username, role FROM users WHERE username = '{u}'"
    r = _run(59, q)

    if r.get("error"):
        err = str(r.get("error") or "")
        if "CTF{" in err:
            return {
                "ok": True,
                "message": f"Restricted charset error path. Flag: {_get_flag(59)}",
                "raw": err,
                "error": err,
            }
        return {
            "ok": False,
            "message": "Query error",
            "raw": r.get("raw") or err,
            "error": err,
        }

    rows = r.get("rows") or []
    blob = _rows_blob(rows)
    if "CTF{" in blob:
        flag_val = next((str(v) for row in rows for v in row.values() if str(v).startswith("CTF{")), _get_flag(59))
        return {
            "ok": True,
            "message": f"Restricted charset win. Flag: {flag_val}",
            "raw": r.get("raw") or "",
        }

    if any(row.get("username") == "admin" or row.get("role") == "admin" for row in rows):
        if u.strip().lower() == "admin":
            return {
                "ok": False,
                "message": "Work inside the allowed charset to inject.",
                "raw": r.get("raw") or "",
            }
        flag_val = _get_flag(59)
        return {
            "ok": True,
            "message": f"Charset-limited bypass. Flag: {flag_val}",
            "raw": r.get("raw") or "",
        }

    if len(rows) >= 2:
        flag_val = _get_flag(59)
        return {
            "ok": True,
            "message": f"Logic bypass within charset. Flag: {flag_val}",
            "raw": r.get("raw") or "",
        }

    return {
        "ok": False,
        "message": "Only [a-zA-Z0-9_ ' -|=<>] allowed. No comments, no semicolons, no parentheses.",
        "raw": r.get("raw") or "",
    }


# ───────────────────────── Level 60 — The Final Gate ─────────────────────────
def handle_60(p: dict) -> dict:
    """union/select/schema/comments blocked — creative bypass."""
    u = p.get("username", "")
    if re.search(r"(?i)union|select|information_schema|--|#|/\*", u):
        return _blocked("Final gate blocked your payload")

    q = f"SELECT id, username, role FROM users WHERE username = '{u}' AND role = 'user'"
    r = _run(60, q)

    if r.get("error"):
        err = str(r.get("error") or "")
        if "CTF{" in err:
            return {
                "ok": True,
                "message": f"Final gate opened via error. Flag: {_get_flag(60)}",
                "raw": err,
                "error": err,
            }
        return {
            "ok": False,
            "message": "Query error",
            "raw": r.get("raw") or err,
            "error": err,
        }

    rows = r.get("rows") or []
    blob = _rows_blob(rows)
    if "CTF{" in blob:
        flag_val = next((str(v) for row in rows for v in row.values() if str(v).startswith("CTF{")), _get_flag(60))
        return {
            "ok": True,
            "message": f"Final gate cleared. Flag: {flag_val}",
            "raw": r.get("raw") or "",
        }

    if any(row.get("username") == "admin" or row.get("role") == "admin" for row in rows):
        flag_val = _get_flag(60)
        return {
            "ok": True,
            "message": f"Final logic bypass. Flag: {flag_val}",
            "raw": r.get("raw") or "",
        }

    if len(rows) >= 2:
        flag_val = _get_flag(60)
        return {
            "ok": True,
            "message": f"Final multi-row bypass. Flag: {flag_val}",
            "raw": r.get("raw") or "",
        }

    return {
        "ok": False,
        "message": "Final gate: no union/select/schema/comments. Balance quotes and boolean logic.",
        "raw": r.get("raw") or "",
    }


HANDLERS = {
    1: handle_01,
    2: handle_02,
    3: handle_03,
    4: handle_04,
    5: handle_05,
    6: handle_06,
    7: handle_07,
    8: handle_08,
    9: handle_09,
    10: handle_10,
    11: handle_11,
    12: handle_12,
    13: handle_13,
    14: handle_14,
    15: handle_15,
    16: handle_16,
    17: handle_17,
    18: handle_18,
    19: handle_19,
    20: handle_20,
    21: handle_21,
    22: handle_22,
    23: handle_23,
    24: handle_24,
    25: handle_25,
    26: handle_26,
    27: handle_27,
    28: handle_28,
    29: handle_29,
    30: handle_30,
    31: handle_31,
    32: handle_32,
    33: handle_33,
    34: handle_34,
    35: handle_35,
    36: handle_36,
    37: handle_37,
    38: handle_38,
    39: handle_39,
    40: handle_40,
    41: handle_41,
    42: handle_42,
    43: handle_43,
    44: handle_44,
    45: handle_45,
    46: handle_46,
    47: handle_47,
    48: handle_48,
    49: handle_49,
    50: handle_50,
    51: handle_51,
    52: handle_52,
    53: handle_53,
    54: handle_54,
    55: handle_55,
    56: handle_56,
    57: handle_57,
    58: handle_58,
    59: handle_59,
    60: handle_60,
}
