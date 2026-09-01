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


# ───────────────────────── Level 16 — type casting / column types ─────────────────────────
def handle_16(p: dict) -> dict:
    u = p.get("username", "")
    q = f"SELECT id, username, role FROM users WHERE username = '{u}'"
    return _run(16, q)


# ───────────────────────── Level 17 — LIMIT only one row ─────────────────────────
def handle_17(p: dict) -> dict:
    u = p.get("username", "")
    q = f"SELECT id, username, role FROM users WHERE username = '{u}' OR 1=1 LIMIT 1"
    # Actually injectable before limit
    q = f"SELECT id, username, role FROM users WHERE username = '{u}' LIMIT 1"
    return _run(17, q)


# ───────────────────────── Level 18 — second-order (store then use) ─────────────────────────
def handle_18(p: dict) -> dict:
    """Register-like: store username, then profile query uses it unsafely."""
    action = p.get("password", "view")  # 'save' or 'view'
    u = p.get("username", "")
    db = level_db(18)
    if action == "save":
        # Store without sanitizing (second-order seed)
        try:
            conn = get_conn(db)
            with conn.cursor() as cur:
                cur.execute("CREATE TABLE IF NOT EXISTS profiles (id INT PRIMARY KEY, name VARCHAR(256))")
                cur.execute("DELETE FROM profiles WHERE id = 1")
                cur.execute(f"INSERT INTO profiles (id, name) VALUES (1, '{u}')")
            conn.close()
            return {"ok": True, "message": "Profile saved", "raw": f"Saved name={u}"}
        except Exception as e:
            return {"ok": False, "message": "Save failed", "raw": str(e), "error": str(e)}
    # view — vulnerable read of stored value
    q = "SELECT id, username, role FROM users WHERE username = (SELECT name FROM profiles WHERE id = 1)"
    return _run(18, q)


# ───────────────────────── Level 19 — cookie injection ─────────────────────────
def handle_19(p: dict) -> dict:
    # cookie value passed as username field from frontend (or cookie key)
    cookie = p.get("username", p.get("cookie", "guest"))
    q = f"SELECT id, username, role FROM users WHERE username = '{cookie}'"
    return _run(19, q)


# ───────────────────────── Level 20 — header / user-agent ─────────────────────────
def handle_20(p: dict) -> dict:
    ua = p.get("username", p.get("user_agent", "Mozilla"))
    q = f"SELECT id, username FROM users WHERE username = '{ua}' LIMIT 1"
    return _run(20, q)


# ───────────────────────── Level 21 — JSON-like value ─────────────────────────
def handle_21(p: dict) -> dict:
    # Simulate JSON body field "user"
    u = p.get("username", "")
    q = f"SELECT id, username, role FROM users WHERE username = '{u}'"
    return _run(21, q)


# ───────────────────────── Level 22 — time + filter ─────────────────────────
def handle_22(p: dict) -> dict:
    u = p.get("username", "")
    if re.search(r"(?i)\bsleep\b|\bbenchmark\b", u):
        return _blocked("Time functions blocked by filter")
    q = f"SELECT id FROM users WHERE username = '{u}'"
    start = time.time()
    r = _run(22, q)
    r["raw"] = (r.get("raw") or "") + f"\n[elapsed: {time.time()-start:.2f}s]"
    return r


# ───────────────────────── Level 23 — ORDER BY injection ─────────────────────────
def handle_23(p: dict) -> dict:
    order = p.get("username", "id")
    q = f"SELECT id, username, role FROM users ORDER BY {order}"
    return _run(23, q)


# ───────────────────────── Level 24 — HAVING ─────────────────────────
def handle_24(p: dict) -> dict:
    having = p.get("username", "1=1")
    q = f"SELECT role, COUNT(*) AS c FROM users GROUP BY role HAVING {having}"
    return _run(24, q)


# ───────────────────────── Level 25 — stacked queries ─────────────────────────
def handle_25(p: dict) -> dict:
    u = p.get("username", "")
    q = f"SELECT id, username FROM users WHERE username = '{u}'"
    # pymysql may allow multi if configured — try execute with multi
    db = level_db(25)
    try:
        conn = get_conn(db)
        try:
            with conn.cursor() as cur:
                # Enable multi statements via client flag simulation: split on ;
                parts = [x.strip() for x in q.split(";") if x.strip()]
                results = []
                for part in parts:
                    cur.execute(part)
                    try:
                        results.append(cur.fetchall())
                    except Exception:
                        results.append(f"(affected ok)")
                return {
                    "ok": True,
                    "message": "Executed",
                    "raw": f"Query: {q}\n\nResults: {results}",
                }
        finally:
            conn.close()
    except Exception as e:
        return {
            "ok": False,
            "message": "Database error",
            "raw": f"Query: {q}\n\nError: {e}",
            "error": str(e),
        }


# ───────────────────────── Level 26 — OOB simulated (extract via error / into outfile blocked) ─────────────────────────
def handle_26(p: dict) -> dict:
    u = p.get("username", "")
    q = f"SELECT id, username FROM users WHERE username = '{u}'"
    return _run(26, q)


# ───────────────────────── Level 27 — WAF keywords ─────────────────────────
def handle_27(p: dict) -> dict:
    u = p.get("username", "")
    banned = ["union", "select", "from", "where", "or", "and", "information_schema"]
    low = u.lower()
    for w in banned:
        if w in low:
            return _blocked(f"WAF: keyword '{w}' denied")
    q = f"SELECT id, username, role FROM users WHERE username = '{u}'"
    return _run(27, q)


# ───────────────────────── Level 28 — app decodes once; double encoding needed conceptually ─────────────────────────
def handle_28(p: dict) -> dict:
    import urllib.parse
    u = p.get("username", "")
    # Decode once (simulate)
    try:
        u = urllib.parse.unquote(u)
    except Exception:
        pass
    q = f"SELECT id, username, role FROM users WHERE username = '{u}'"
    return _run(28, q)


# ───────────────────────── Level 29 — numeric tricks ─────────────────────────
def handle_29(p: dict) -> dict:
    uid = p.get("username", "1")
    # weak filter: block if contains space or quote
    if "'" in uid or " " in uid or ";" in uid:
        return _blocked("Invalid characters in id")
    q = f"SELECT id, username, role FROM users WHERE id = {uid}"
    return _run(29, q)


# ───────────────────────── Level 30 — inline comments bypass ─────────────────────────
def handle_30(p: dict) -> dict:
    u = p.get("username", "")
    # blacklist whole words only
    if re.search(r"(?i)\bunion\b|\bselect\b", u):
        return _blocked("Keywords union/select blocked")
    q = f"SELECT id, username, role FROM users WHERE username = '{u}'"
    return _run(30, q)


# ───────────────────────── Level 31 — advanced boolean (content-length style minimal) ─────────────────────────
def handle_31(p: dict) -> dict:
    expr = p.get("username", "0")
    q = f"SELECT id FROM secrets WHERE IF(({expr}), 1, 0) = 1"
    r = _run(31, q)
    if r.get("error"):
        return {"ok": False, "message": "err", "raw": "."}
    return {
        "ok": bool(r.get("rows")),
        "message": "1" if r.get("rows") else "0",
        "raw": "1" if r.get("rows") else "0",
    }


# ───────────────────────── Level 32 — time filter strong ─────────────────────────
def handle_32(p: dict) -> dict:
    u = p.get("username", "")
    if re.search(r"(?i)sleep|benchmark|get_lock|wait", u):
        return _blocked("Delay functions are blocked")
    q = f"SELECT id FROM users WHERE username = '{u}'"
    start = time.time()
    r = _run(32, q)
    r["raw"] = (r.get("raw") or "") + f"\n[elapsed: {time.time()-start:.2f}s]"
    return r


# ───────────────────────── Level 33 — second-order advanced ─────────────────────────
def handle_33(p: dict) -> dict:
    return handle_18(p)  # same pattern, different DB isolation


# ───────────────────────── Level 34 — regex WAF ─────────────────────────
def handle_34(p: dict) -> dict:
    u = p.get("username", "")
    if re.search(r"(?i)(union\s+select|or\s+1\s*=\s*1|'?\s*or\s*')", u):
        return _blocked("WAF regex blocked payload")
    q = f"SELECT id, username, role FROM users WHERE username = '{u}'"
    return _run(34, q)


# ───────────────────────── Level 35 — almost no feedback ─────────────────────────
def handle_35(p: dict) -> dict:
    u = p.get("username", "")
    q = f"SELECT id FROM users WHERE username = '{u}'"
    r = _run(35, q)
    # Always same message
    return {"ok": True, "message": "OK", "raw": "OK"}


# ───────────────────────── Level 36 — INSERT injection ─────────────────────────
def handle_36(p: dict) -> dict:
    u = p.get("username", "")
    email = p.get("password", "x@x.com")
    q = f"INSERT INTO users (username, password, email, role) VALUES ('{u}', 'pass', '{email}', 'user')"
    return _run(36, q)


# ───────────────────────── Level 37 — UPDATE injection ─────────────────────────
def handle_37(p: dict) -> dict:
    u = p.get("username", "")
    newmail = p.get("password", "a@b.c")
    q = f"UPDATE users SET email = '{newmail}' WHERE username = '{u}'"
    return _run(37, q)


# ───────────────────────── Level 38 — LIMIT/OFFSET ─────────────────────────
def handle_38(p: dict) -> dict:
    lim = p.get("username", "1")
    q = f"SELECT id, username, role FROM users ORDER BY id LIMIT {lim}"
    return _run(38, q)


# ───────────────────────── Level 39 — partial prepared (id safe, name not) ─────────────────────────
def handle_39(p: dict) -> dict:
    uid = p.get("password", "1")
    name = p.get("username", "")
    # id uses parameter style check; name concatenated
    try:
        int(uid)
    except ValueError:
        return _blocked("id must be integer")
    q = f"SELECT id, username, role FROM users WHERE id = {int(uid)} AND username = '{name}'"
    return _run(39, q)


# ───────────────────────── Level 40 — strip quotes only ─────────────────────────
def handle_40(p: dict) -> dict:
    u = p.get("username", "").replace("'", "").replace('"', "")
    q = f"SELECT id, username, role FROM users WHERE username = '{u}'"
    return _run(40, q)


# ───────────────────────── Level 41 — nested / two params ─────────────────────────
def handle_41(p: dict) -> dict:
    u, pw = p.get("username", ""), p.get("password", "")
    q = f"SELECT id, username FROM users WHERE username = '{u}' AND email = '{pw}'"
    return _run(41, q)


# ───────────────────────── Level 42 — both fields matter ─────────────────────────
def handle_42(p: dict) -> dict:
    u, pw = p.get("username", ""), p.get("password", "")
    q = f"SELECT id FROM users WHERE username = '{u}' OR password = '{pw}'"
    return _run(42, q)


# ───────────────────────── Level 43 — blind heavy ─────────────────────────
def handle_43(p: dict) -> dict:
    expr = p.get("username", "0")
    q = f"SELECT 1 FROM secrets WHERE ({expr})"
    r = _run(43, q)
    if r.get("error"):
        return {"ok": False, "message": "no", "raw": "no"}
    return {"ok": True, "message": "yes" if r.get("rows") else "no", "raw": "yes" if r.get("rows") else "no"}


# ───────────────────────── Level 44 — multi filter layers ─────────────────────────
def handle_44(p: dict) -> dict:
    u = p.get("username", "")
    u2 = u.replace(" ", "").replace("--", "")
    if re.search(r"(?i)union|select|or|and", u2):
        return _blocked("Layered filter blocked request")
    q = f"SELECT id, username, role FROM users WHERE username = '{u}'"
    return _run(44, q)


# ───────────────────────── Level 45 — conditional error ─────────────────────────
def handle_45(p: dict) -> dict:
    expr = p.get("username", "0")
    # Extract via dual error
    q = f"SELECT IF(({expr}), (SELECT table_name FROM information_schema.tables), 0)"
    return _run(45, q)


# ───────────────────────── Level 46 — WAF + need obfuscation ─────────────────────────
def handle_46(p: dict) -> dict:
    u = p.get("username", "")
    if re.search(r"(?i)union\s+select|or\s+1=1", u):
        return _blocked("WAF blocked")
    q = f"SELECT id, username, role FROM users WHERE username = '{u}'"
    return _run(46, q)


# ───────────────────────── Level 47 — stacked + filter ─────────────────────────
def handle_47(p: dict) -> dict:
    u = p.get("username", "")
    if re.search(r"(?i)\b(drop|delete|update|insert)\b", u):
        return _blocked("Dangerous keyword blocked")
    return handle_25({**p, "username": u})


# ───────────────────────── Level 48 — extract without union keyword ─────────────────────────
def handle_48(p: dict) -> dict:
    u = p.get("username", "")
    if "union" in u.lower():
        return _blocked("UNION is blocked")
    q = f"SELECT id, username, role FROM users WHERE username = '{u}'"
    return _run(48, q)


# ───────────────────────── Level 49 — remove spaces ─────────────────────────
def handle_49(p: dict) -> dict:
    u = p.get("username", "").replace(" ", "")
    q = f"SELECT id, username, role FROM users WHERE username = '{u}'"
    return _run(49, q)


# ───────────────────────── Level 50 — filter comments ─────────────────────────
def handle_50(p: dict) -> dict:
    u = p.get("username", "")
    if "--" in u or "/*" in u or "#" in u:
        return _blocked("Comments not allowed")
    q = f"SELECT id, username, role FROM users WHERE username = '{u}' AND role = 'user'"
    return _run(50, q)


# ───────────────────────── Level 51 — blind + waf ─────────────────────────
def handle_51(p: dict) -> dict:
    u = p.get("username", "")
    if re.search(r"(?i)union|sleep|benchmark|information_schema", u):
        return _blocked("WAF")
    q = f"SELECT id FROM secrets WHERE username = '{u}' OR ({u})" if False else f"SELECT id FROM secrets WHERE ({u or '0'})"
    r = _run(51, q)
    if r.get("error"):
        return {"ok": False, "message": "0", "raw": "0"}
    return {"ok": True, "message": "1" if r.get("rows") else "0", "raw": "1" if r.get("rows") else "0"}


# ───────────────────────── Level 52 — polyglot friendly (same as basic but strict output) ─────────────────────────
def handle_52(p: dict) -> dict:
    u = p.get("username", "")
    q = f"SELECT id, username, role FROM users WHERE username = '{u}'"
    return _run(52, q)


# ───────────────────────── Level 53 — no quotes allowed ─────────────────────────
def handle_53(p: dict) -> dict:
    u = p.get("username", "")
    if "'" in u or '"' in u:
        return _blocked("Quotes are forbidden")
    q = f"SELECT id, username, role FROM users WHERE id = {u or 0}"
    return _run(53, q)


# ───────────────────────── Level 54 — bit extraction channel ─────────────────────────
def handle_54(p: dict) -> dict:
    expr = p.get("username", "0")
    q = f"SELECT id FROM secrets WHERE ({expr})"
    r = _run(54, q)
    if r.get("error"):
        return {"ok": False, "message": "x", "raw": "x"}
    return {"ok": True, "message": "Y" if r.get("rows") else "N", "raw": "Y" if r.get("rows") else "N"}


# ───────────────────────── Level 55 — two-step context ─────────────────────────
def handle_55(p: dict) -> dict:
    return handle_18(p)


# ───────────────────────── Level 56 — full chain lite (filter + string) ─────────────────────────
def handle_56(p: dict) -> dict:
    u = p.get("username", "")
    if re.search(r"(?i)\bunion\b|\bselect\b|\bor\b", u):
        # allow obfuscation with comments
        if not re.search(r"/\*.*\*/", u):
            return _blocked("Direct keywords blocked — be creative")
    q = f"SELECT id, username, role FROM users WHERE username = '{u}'"
    return _run(56, q)


# ───────────────────────── Level 57 — into outfile / load_file style attempt surface ─────────────────────────
def handle_57(p: dict) -> dict:
    u = p.get("username", "")
    q = f"SELECT id, username FROM users WHERE username = '{u}'"
    return _run(57, q)


# ───────────────────────── Level 58 — slow / heavy query allowed ─────────────────────────
def handle_58(p: dict) -> dict:
    u = p.get("username", "")
    q = f"SELECT id, username, role FROM users WHERE username = '{u}'"
    return _run(58, q)


# ───────────────────────── Level 59 — very strict charset ─────────────────────────
def handle_59(p: dict) -> dict:
    u = p.get("username", "")
    if re.search(r"[^a-zA-Z0-9_\s'\-\|=<>]", u):
        return _blocked("Illegal character")
    q = f"SELECT id, username, role FROM users WHERE username = '{u}'"
    return _run(59, q)


# ───────────────────────── Level 60 — final: filter + string + no comments ─────────────────────────
def handle_60(p: dict) -> dict:
    u = p.get("username", "")
    if re.search(r"(?i)union|select|information_schema|--|#|/\*", u):
        return _blocked("Final gate blocked your payload")
    q = f"SELECT id, username, role FROM users WHERE username = '{u}'"
    return _run(60, q)


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
