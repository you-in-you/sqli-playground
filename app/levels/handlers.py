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

# ───────────────────────── Level 08 — auth bypass ─────────────────────────
def handle_08(p: dict) -> dict:
    u, pw = p.get("username", ""), p.get("password", "")
    q = f"SELECT id, username, role FROM users WHERE username = '{u}' AND password = '{pw}'"
    r = _run(8, q)
    if r.get("rows"):
        r["message"] = f"Logged in as {r['rows'][0].get('username')}"
        r["ok"] = True
    return r


# ───────────────────────── Level 09 — verbose errors (already default) ─────────────────────────
def handle_09(p: dict) -> dict:
    u = p.get("username", "")
    q = f"SELECT * FROM users WHERE username = '{u}'"
    return _run(9, q)


# ───────────────────────── Level 10 — boolean blind (no data in response) ─────────────────────────
def handle_10(p: dict) -> dict:
    u = p.get("username", "")
    q = f"SELECT id FROM users WHERE username = '{u}'"
    r = _run(10, q)
    # Hide rows — only true/false style message
    if r.get("error"):
        return {"ok": False, "message": "Invalid request", "raw": "Something went wrong."}
    if r.get("rows"):
        return {"ok": True, "message": "User exists", "raw": "User exists"}
    return {"ok": False, "message": "User not found", "raw": "User not found"}


# ───────────────────────── Level 11 — boolean AND ─────────────────────────
def handle_11(p: dict) -> dict:
    u = p.get("username", "")
    q = f"SELECT id FROM users WHERE username = 'admin' AND ({u})"
    # username field is injected as boolean expression after AND
    # Actually make it: search param
    q = f"SELECT id FROM users WHERE username = 'admin' AND {u or '1=0'}"
    r = _run(11, q)
    if r.get("error"):
        return {"ok": False, "message": "Error", "raw": "Invalid"}
    if r.get("rows"):
        return {"ok": True, "message": "TRUE", "raw": "Condition is TRUE"}
    return {"ok": False, "message": "FALSE", "raw": "Condition is FALSE"}


# ───────────────────────── Level 12 — length extraction channel ─────────────────────────
def handle_12(p: dict) -> dict:
    expr = p.get("username", "0")
    q = f"SELECT id FROM secrets WHERE LENGTH(flag) = {expr}"
    r = _run(12, q)
    if r.get("error"):
        return {"ok": False, "message": "Invalid", "raw": "Invalid"}
    if r.get("rows"):
        return {"ok": True, "message": "MATCH", "raw": "Length matches"}
    return {"ok": False, "message": "NO MATCH", "raw": "Length does not match"}


# ───────────────────────── Level 13 — char extraction ─────────────────────────
def handle_13(p: dict) -> dict:
    # username = position, password = ascii guess  OR combined expression
    expr = p.get("username", "1=0")
    q = f"SELECT id FROM secrets WHERE {expr}"
    r = _run(13, q)
    if r.get("error"):
        return {"ok": False, "message": "Invalid", "raw": "Invalid expression"}
    if r.get("rows"):
        return {"ok": True, "message": "YES", "raw": "YES"}
    return {"ok": False, "message": "NO", "raw": "NO"}


# ───────────────────────── Level 14 — time-based ─────────────────────────
def handle_14(p: dict) -> dict:
    u = p.get("username", "")
    q = f"SELECT id FROM users WHERE username = '{u}'"
    start = time.time()
    r = _run(14, q)
    elapsed = time.time() - start
    r["raw"] = (r.get("raw") or "") + f"\n\n[elapsed: {elapsed:.2f}s]"
    # Don't leak row content for pure time practice — still show errors
    if not r.get("error") and r.get("rows") is not None:
        r["message"] = "Done"
        r["raw"] = f"Query finished in {elapsed:.2f}s\n(Use SLEEP to measure true/false)"
    return r


# ───────────────────────── Level 15 — simple blacklist ─────────────────────────
def handle_15(p: dict) -> dict:
    u = p.get("username", "")
    blocked = ["union", "select", "or", "and", "sleep", "benchmark"]
    low = u.lower()
    for w in blocked:
        if w in low:
            return _blocked(f"Blacklist hit: '{w}' is not allowed")
    q = f"SELECT id, username, role FROM users WHERE username = '{u}'"
    return _run(15, q)


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
