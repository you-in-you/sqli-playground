#!/bin/bash
set -e
cd "$(dirname "$0")"
if [ -f .venv/bin/activate ]; then
  source .venv/bin/activate
fi
export PYTHONPATH="$(pwd)"
python3 scripts/setup_db.py
python3 -m flask --app app.main run --host="$(python3 -c 'from app.config import HOST; print(HOST)')" --port="$(python3 -c 'from app.config import PORT; print(PORT)')"
