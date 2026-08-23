# SQLi Playground

Local, offline **SQL Injection CTF lab** with **60 progressive levels** on **MariaDB / MySQL**.

Each level uses an **isolated database**. Flags are **random per installation**. Progress is sequential — you cannot skip levels.

> Educational lab only. Run on your own machine. Do not expose it to the internet.

---


## Live demo

Static UI preview (no database required):

[Live Demo](https://you-in-you.github.io/sqli-playground/demo/)

- Level **01** is interactive (mock SQLi in the browser)
- Levels **02–60** are visual demo only
- Full real lab: clone and run locally

## Features

- 60 levels from basic error-based SQLi to advanced filter / WAF / blind techniques
- Real vulnerable queries (not regex “fake” checks)
- One database per level — dumping level 1 does not reveal later flags
- Random flags generated at setup (`CTF{sql1_lXX_........}`)
- Flag verification reads **only from that level’s database**
- Attack history stored safely (parameterized queries) — click a solved flag to review payloads and responses
- Dark minimal CTF UI (difficulty-colored)
- Config via `config.json` (no need to export env vars every time)

---

## Requirements

- Python **3.10+**
- MariaDB **10.5+** or MySQL **8+**
- `pip` / venv

---

## Quick start

### 1. Clone

```bash
git clone https://github.com/you-in-you/sqli-playground.git
cd sqli-playground
```

### 2. Python environment

```bash
python3 -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

### 3. Database user

On many Linux distros (Fedora, Ubuntu, …) `root` uses **socket auth** and cannot connect via TCP without a password. Create a dedicated user:

```bash
sudo mariadb -u root
```

```sql
CREATE USER IF NOT EXISTS 'ctf'@'localhost' IDENTIFIED BY 'ctfpass';
GRANT ALL PRIVILEGES ON *.* TO 'ctf'@'localhost' WITH GRANT OPTION;
FLUSH PRIVILEGES;
EXIT;
```

### 4. Configure

Edit `config.json`:

```json
{
  "DB_HOST": "127.0.0.1",
  "DB_PORT": 3306,
  "DB_USER": "ctf",
  "DB_PASS": "ctfpass",
  "SECRET_KEY": "change-this-to-a-long-random-string",
  "HOST": "0.0.0.0",
  "PORT": 5000
}
```

### 5. Initialize databases & flags

```bash
python3 scripts/setup_db.py
```

This creates:

- `sqli_level_01` … `sqli_level_60` (each with `users` + `secrets`)
- `sqli_ctf_meta` (progress + attack history)
- `flags.json` (seed only; not required at runtime for verification)

### 6. Run

```bash
export PYTHONPATH="$(pwd)"
python3 -m flask --app app.main run
```

Or:

```bash
chmod +x run.sh
./run.sh
```

Open: **http://127.0.0.1:5000**

---

## How to play

1. Open level 1 (others stay `403` until unlocked).
2. Inject into the form fields and read the **RESPONSE** panel.
3. Extract the flag from the `secrets` table of that level.
4. Submit the flag (`CTF{...}`).
5. Next level unlocks.
6. Click a row under **Solved Flags** to see your attack history and the winning payload.

### Level 1 example

```text
' UNION SELECT 1,flag,3 FROM secrets -- 
```

(Column counts differ by level — read the error messages and hints.)

---

## Project layout

```text
sqli-playground/
├── app/
│   ├── main.py           # Flask API + pages
│   ├── config.py         # loads config.json (+ env overrides)
│   ├── db.py             # DB helpers, progress, safe history
│   ├── levels/
│   │   ├── handlers.py   # 60 intentionally vulnerable handlers
│   │   └── __init__.py   # metadata + registry
│   ├── static/           # CSS / JS
│   └── templates/
├── scripts/setup_db.py   # create DBs + random flags
├── config.json           # local settings (edit this)
├── requirements.txt
├── run.sh
└── README.md
```

---

## Reset / maintenance

**Reset progress only:**

```sql
UPDATE sqli_ctf_meta.progress SET current_level = 1, solved = '';
TRUNCATE TABLE sqli_ctf_meta.attack_history;
```

**New random flags (re-seed):**

```bash
rm -f flags.json
python3 scripts/setup_db.py
```

Note: existing level DBs keep old flag rows until re-created. For a full wipe, drop `sqli_ctf_meta` and `sqli_level_*` databases, then run setup again.

---

## Common errors

### `Access denied for user 'root'@'localhost'`

Root is using unix_socket auth. Use a dedicated user (`ctf` / `ctfpass`) as in the install steps, or enable password auth for root.

### `Can't connect to MySQL server on '127.0.0.1'`

MariaDB/MySQL is not running:

```bash
# Fedora / Ubuntu
sudo systemctl start mariadb
```

### `ModuleNotFoundError: flask` / `pymysql`

Activate the venv and install requirements:

```bash
source .venv/bin/activate
pip install -r requirements.txt
```

### `flags.json incomplete` / setup regenerates flags

Normal on first run. Setup generates 60 unique flags and writes them into each level DB.

### Port already in use

Change `"PORT"` in `config.json`, or:

```bash
python3 -m flask --app app.main run --port 8080
```

### History modal empty for an old solved level

History is recorded after this feature was added. New attacks are logged; the attempt used right before a successful submit can be marked as the winning payload.

### Docker

`Dockerfile` and `docker-compose.yml` are optional. On Fedora/workstations with local MariaDB, venv + `config.json` is simpler.

---

## Security notes

- **Local lab only.** Set `"HOST": "127.0.0.1"` in `config.json` for stricter local binding.
- Challenge endpoints are **intentionally vulnerable**.
- Meta DB operations (progress, history, flag check) use **parameterized queries** so stored payloads cannot SQLi the lab control plane.
- Do not commit `flags.json` (see `.gitignore`).
- Change `SECRET_KEY` in `config.json` for your install.

---

## License

Educational use. Use responsibly.

---

## Author

[you-in-you](https://github.com/you-in-you)
