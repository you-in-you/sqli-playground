# SQLi Playground — CTF Lab

Local offline SQL Injection CTF with 60 progressive levels on MariaDB.

## Quick Start

```bash
cd sqli-ctf
docker compose up --build
```

Open: **http://localhost:5000**

## What gets created

- 60 isolated databases: `sqli_level_01` … `sqli_level_60`
- Meta DB: `sqli_ctf_meta` (progress)
- Unique random flags per install → `flags.json`
- Flask web app on port 5000

## Level 01 (live)

Classic error-based / string SQLi on login:

```sql
SELECT ... WHERE username = '{input}' AND password = '{input}'
```

Extract the flag from table `secrets`.

Example payloads to explore:

```
admin' OR '1'='1' --
' UNION SELECT 1,flag,3,4 FROM secrets --
```

## Architecture

| Component | Role |
|-----------|------|
| Each level DB | Isolated data + flag (no cross-dump) |
| `sqli_ctf_meta` | Solved levels / unlock gate |
| `/api/level/N/attack` | Vulnerable endpoint |
| `/api/level/N/submit` | Flag check + unlock next |

## Reset progress

```bash
docker compose exec db mariadb -uroot -prootpass -e \
  "UPDATE sqli_ctf_meta.progress SET current_level=1, solved=''"
```

## Reset all flags (new random set)

```bash
rm flags.json
docker compose down -v
docker compose up --build
```

## Status

- UI: complete
- Progress / lock / random flags: complete
- Level 01 backend: fully vulnerable & working
- Levels 02–60: DBs + flags + meta ready; attack handlers to be added per level
