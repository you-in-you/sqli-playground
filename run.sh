#!/bin/bash
# SQLi Playground — launcher & DB toolkit
# Usage:
#   ./run.sh                 ensure DB, then start the lab server
#   ./run.sh start           same as above
#   ./run.sh ensure          create missing DBs/tables (keep flags & progress)
#   ./run.sh install         wipe lab DBs + flags, full rebuild
#   ./run.sh reinstall       same as install
#   ./run.sh uninstall       remove lab DBs + flags only (no rebuild)
#   ./run.sh status          show version / databases / progress
#   ./run.sh -y install      skip confirmation prompts
#   ./run.sh help            show this help

set -e
cd "$(dirname "$0")"

if [ -f .venv/bin/activate ]; then
  # shellcheck source=/dev/null
  source .venv/bin/activate
fi

export PYTHONPATH="$(pwd)"

SETUP=(python3 scripts/setup_db.py)
YES_ARGS=()
CMD=""

print_help() {
  cat <<'HELP'

  SQLi Playground  —  ./run.sh
  https://github.com/you-in-you/sqli-playground

  Commands:
    start        Ensure databases, then start the Flask lab server (default)
    ensure       Create missing DBs/tables; keep flags & progress
    install      DROP all lab databases + flags, then rebuild from scratch
    reinstall    Same as install
    uninstall    DROP lab databases + flags only (no rebuild) — come back later
    status       Show app version, databases, and progress
    help         Show this help

  Options:
    -y, --yes    Skip confirmation prompts (install / reinstall / uninstall)

  Examples:
    ./run.sh
    ./run.sh status
    ./run.sh install
    ./run.sh -y reinstall
    ./run.sh uninstall
    ./run.sh ensure

HELP
}

while [ $# -gt 0 ]; do
  case "$1" in
    -y|--yes)
      YES_ARGS+=(-y)
      shift
      ;;
    -h|--help|help)
      print_help
      exit 0
      ;;
    start|ensure|install|reinstall|uninstall|status)
      CMD="$1"
      shift
      break
      ;;
    -*)
      echo "Unknown option: $1" >&2
      echo "Try: ./run.sh help" >&2
      exit 2
      ;;
    *)
      echo "Unknown command: $1" >&2
      echo "Try: ./run.sh help" >&2
      exit 2
      ;;
  esac
done

if [ -z "$CMD" ]; then
  CMD="start"
fi

case "$CMD" in
  start)
    "${SETUP[@]}" "${YES_ARGS[@]}" ensure
    HOST="$(python3 -c 'from app.config import HOST; print(HOST)')"
    PORT="$(python3 -c 'from app.config import PORT; print(PORT)')"
    echo ""
    echo "  Starting Flask on http://${HOST}:${PORT}"
    echo "  Project: https://github.com/you-in-you/sqli-playground"
    echo "  Stop with Ctrl+C"
    echo ""
    exec python3 -m flask --app app.main run --host="$HOST" --port="$PORT"
    ;;
  ensure|install|reinstall|uninstall|status)
    exec "${SETUP[@]}" "${YES_ARGS[@]}" "$CMD" "$@"
    ;;
  *)
    print_help
    exit 2
    ;;
esac
