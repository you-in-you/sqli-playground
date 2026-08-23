"""
Level 01 — Error-Based Basic
Classic login form with string concatenation SQLi.
Goal: extract flag from secrets table via error or auth bypass + query.
"""

from app.db import get_conn, level_db

META = {
    "id": 1,
    "name": "Error-Based Basic",
    "diff": "easy",
    "desc": "A simple login form is vulnerable to SQL injection. Extract the flag from the database.",
    "hint_i": "No soldiers guard the castle gates.",
    "hint_t": "The application does not sanitize input. Try triggering a database error to reveal information. The flag lives in the secrets table.",
    "implemented": True,
}


def handle(payload: dict) -> dict:
    """
    Vulnerable login endpoint.
    Intentionally concatenates user input into SQL — classic SQLi.
    """
    username = payload.get("username", "")
    password = payload.get("password", "")

    db = level_db(1)
    # VULNERABLE QUERY — do not fix
    query = (
        f"SELECT id, username, role FROM users "
        f"WHERE username = '{username}' AND password = '{password}'"
    )

    try:
        conn = get_conn(db)
        try:
            with conn.cursor() as cur:
                cur.execute(query)
                rows = cur.fetchall()
        finally:
            conn.close()

        if rows:
            user = rows[0]
            return {
                "ok": True,
                "message": f"Welcome, {user['username']} ({user['role']})",
                "raw": f"Query: {query}\n\nResult: {rows}",
            }
        return {
            "ok": False,
            "message": "Login failed. Invalid username or password.",
            "raw": f"Query: {query}\n\nNo matching rows.",
        }

    except Exception as e:
        # Error-based: leak the exception (includes SQL error details)
        return {
            "ok": False,
            "message": "Database error",
            "raw": f"Query: {query}\n\nError: {type(e).__name__}: {e}",
            "error": str(e),
        }
