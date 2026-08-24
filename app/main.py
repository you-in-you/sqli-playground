from flask import Flask, render_template, request, jsonify
from app.config import SECRET_KEY, TOTAL_LEVELS
from app.db import (
    get_progress,
    mark_solved,
    is_level_unlocked,
    get_flag_from_db,
    log_attack,
    get_level_history,
)
from app.levels import get_meta, handle_level, LEVEL_NAMES

app = Flask(
    __name__,
    template_folder="templates",
    static_folder="static",
)
app.secret_key = SECRET_KEY


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/levels")
def api_levels():
    progress = get_progress()
    solved = set(progress["solved"])
    levels = []
    for i in range(1, TOTAL_LEVELS + 1):
        unlocked = is_level_unlocked(i)
        meta = get_meta(i)
        item = {
            "id": i,
            "unlocked": unlocked,
            "solved": i in solved,
            "diff": meta["diff"],
        }
        if unlocked or i in solved:
            item["name"] = meta["name"]
        levels.append(item)
    return jsonify({
        "levels": levels,
        "progress": {
            "solved_count": len(solved),
            "current_level": progress["current_level"],
            "solved": progress["solved"],
        },
    })


@app.route("/api/level/<int:level_id>")
def api_level(level_id: int):
    if level_id < 1 or level_id > TOTAL_LEVELS:
        return jsonify({"error": "Invalid level"}), 404
    if not is_level_unlocked(level_id):
        return jsonify({"error": "403 Access Denied", "code": 403}), 403

    meta = get_meta(level_id)
    progress = get_progress()
    return jsonify({
        "id": meta["id"],
        "name": meta["name"],
        "diff": meta["diff"],
        "desc": meta["desc"],
        "hint_i": meta["hint_i"],
        "hint_t": meta["hint_t"],
        "implemented": meta.get("implemented", False),
        "solved": level_id in progress["solved"],
    })


@app.route("/api/level/<int:level_id>/attack", methods=["POST"])
def api_attack(level_id: int):
    if level_id < 1 or level_id > TOTAL_LEVELS:
        return jsonify({"error": "Invalid level"}), 404
    if not is_level_unlocked(level_id):
        return jsonify({"error": "403 Access Denied"}), 403

    data = request.get_json(silent=True) or {}
    username = data.get("username", "")
    password = data.get("password", "")

    result = handle_level(level_id, data)

    # Safe parameterized history log (payloads stored as bound parameters)
    history_id = log_attack(
        level_id=level_id,
        username=str(username),
        password=str(password),
        response_message=str(result.get("message") or ""),
        response_raw=str(result.get("raw") or result.get("error") or ""),
        ok=bool(result.get("ok")),
    )
    if history_id is not None:
        result["history_id"] = history_id

    return jsonify(result)


@app.route("/api/level/<int:level_id>/submit", methods=["POST"])
def api_submit(level_id: int):
    if level_id < 1 or level_id > TOTAL_LEVELS:
        return jsonify({"error": "Invalid level"}), 404
    if not is_level_unlocked(level_id):
        return jsonify({"error": "403 Access Denied"}), 403

    data = request.get_json(silent=True) or {}
    flag = (data.get("flag") or "").strip()
    history_id = data.get("history_id")  # optional: which attempt found the flag

    correct = get_flag_from_db(level_id)
    if not correct:
        return jsonify({"ok": False, "message": "Flag not configured in database"}), 500

    if flag == correct:
        mark_solved(level_id)
        # mark winning attempt if client sends history_id, else last matching response
        if history_id is not None:
            try:
                from app.db import mark_winning_payload
                mark_winning_payload(level_id, int(history_id))
            except Exception:
                pass
        return jsonify({
            "ok": True,
            "message": "Correct! Flag accepted.",
            "flag": correct,
            "next_level": level_id + 1 if level_id < TOTAL_LEVELS else None,
        })

    return jsonify({"ok": False, "message": "Wrong flag. Try again."})


@app.route("/api/solved")
def api_solved():
    progress = get_progress()
    items = []
    for lid in progress["solved"]:
        flag = get_flag_from_db(lid) or ""
        items.append({
            "id": lid,
            "name": LEVEL_NAMES.get(lid, f"Level {lid}"),
            "flag": flag,
        })
    return jsonify({"solved": items})


@app.route("/api/level/<int:level_id>/history")
def api_history(level_id: int):
    if level_id < 1 or level_id > TOTAL_LEVELS:
        return jsonify({"error": "Invalid level"}), 404
    # Only allow history for unlocked/solved levels
    progress = get_progress()
    if not is_level_unlocked(level_id) and level_id not in progress["solved"]:
        return jsonify({"error": "403 Access Denied"}), 403
    rows = get_level_history(level_id)
    return jsonify({
        "level_id": level_id,
        "name": LEVEL_NAMES.get(level_id, f"Level {level_id}"),
        "history": rows,
    })


if __name__ == "__main__":
    from app.config import HOST, PORT
    app.run(host=HOST, port=PORT, debug=True)
