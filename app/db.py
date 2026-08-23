import json
import pymysql
from app.config import DB_HOST, DB_PORT, DB_USER, DB_PASS, TOTAL_LEVELS


def get_conn(database: str | None = None):
    kwargs = dict(
        host=DB_HOST,
        port=DB_PORT,
        user=DB_USER,
        password=DB_PASS,
        charset="utf8mb4",
        cursorclass=pymysql.cursors.DictCursor,
        autocommit=True,
    )
    if database:
        kwargs["database"] = database
    return pymysql.connect(**kwargs)


def level_db(level_id: int) -> str:
    return f"sqli_level_{level_id:02d}"


def get_flag_from_db(level_id: int) -> str | None:
    """Read correct flag only from that level's isolated database (parameterized)."""
    if level_id < 1 or level_id > TOTAL_LEVELS:
        return None
    db = level_db(level_id)
    conn = get_conn(db)
    try:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT flag FROM secrets WHERE name = %s LIMIT 1",
                ("level_flag",),
            )
            row = cur.fetchone()
            return row["flag"] if row else None
    finally:
        conn.close()


def get_progress() -> dict:
    conn = get_conn("sqli_ctf_meta")
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT current_level, solved FROM progress WHERE id = 1")
            row = cur.fetchone()
            solved = []
            if row and row["solved"]:
                solved = [int(x) for x in row["solved"].split(",") if x.strip()]
            return {
                "current_level": row["current_level"] if row else 1,
                "solved": solved,
            }
    finally:
        conn.close()


def mark_solved(level_id: int, winning_history_id: int | None = None) -> None:
    conn = get_conn("sqli_ctf_meta")
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT current_level, solved FROM progress WHERE id = 1")
            row = cur.fetchone()
            solved = set()
            if row and row["solved"]:
                solved = {int(x) for x in row["solved"].split(",") if x.strip()}
            solved.add(level_id)
            solved_str = ",".join(str(x) for x in sorted(solved))
            new_current = max(row["current_level"] if row else 1, level_id + 1)
            cur.execute(
                "UPDATE progress SET current_level = %s, solved = %s WHERE id = 1",
                (new_current, solved_str),
            )
            if winning_history_id is not None:
                cur.execute(
                    "UPDATE attack_history SET is_winning = 1 WHERE id = %s AND level_id = %s",
                    (winning_history_id, level_id),
                )
    finally:
        conn.close()


def is_level_unlocked(level_id: int) -> bool:
    if level_id <= 1:
        return True
    progress = get_progress()
    return (level_id - 1) in progress["solved"]


def log_attack(
    level_id: int,
    username: str,
    password: str,
    response_message: str,
    response_raw: str,
    ok: bool,
) -> int | None:
    """
    Store attack attempt in meta DB using ONLY parameterized queries.
    User payloads are stored as data, never concatenated into SQL.
    """
    conn = get_conn("sqli_ctf_meta")
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO attack_history
                    (level_id, username_payload, password_payload, response_message, response_raw, ok)
                VALUES (%s, %s, %s, %s, %s, %s)
                """,
                (
                    level_id,
                    (username or "")[:4000],
                    (password or "")[:4000],
                    (response_message or "")[:2000],
                    (response_raw or "")[:8000],
                    1 if ok else 0,
                ),
            )
            return cur.lastrowid
    except Exception:
        return None
    finally:
        conn.close()


def get_level_history(level_id: int) -> list[dict]:
    conn = get_conn("sqli_ctf_meta")
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT id, level_id, username_payload, password_payload,
                       response_message, response_raw, ok, is_winning, created_at
                FROM attack_history
                WHERE level_id = %s
                ORDER BY id ASC
                """,
                (level_id,),
            )
            rows = cur.fetchall()
            # serialize datetime
            for r in rows:
                if r.get("created_at") is not None:
                    r["created_at"] = str(r["created_at"])
            return rows
    finally:
        conn.close()


def mark_winning_payload(level_id: int, history_id: int) -> None:
    conn = get_conn("sqli_ctf_meta")
    try:
        with conn.cursor() as cur:
            cur.execute(
                "UPDATE attack_history SET is_winning = 0 WHERE level_id = %s",
                (level_id,),
            )
            cur.execute(
                "UPDATE attack_history SET is_winning = 1 WHERE id = %s AND level_id = %s",
                (history_id, level_id),
            )
    finally:
        conn.close()
