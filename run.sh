#!/bin/bash
# SQLi Playground — launcher & DB toolkit (local + Docker)
#
# Local:
#   ./run.sh                 ensure DB, start Flask
#   ./run.sh status|install|reinstall|uninstall|ensure
#   ./run.sh -y install
#
# Docker (same verbs, prefixed with docker):
#   ./run.sh docker up       build + start stack
#   ./run.sh docker down     stop stack
#   ./run.sh docker logs     follow web logs
#   ./run.sh docker status|ensure|install|reinstall|uninstall
#   ./run.sh docker -y install
#   ./run.sh docker shell    shell inside web container

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
DOCKER_MODE=0

print_banner() {
  # SQLi playground ASCII — green / red / purple (ANSI)
  local G=$'\033[38;2;0;255;136m'
  local R=$'\033[38;2;255;0;85m'
  local P=$'\033[38;2;213;0;249m'
  local D=$'\033[38;2;107;107;128m'
  local N=$'\033[0m'
  printf '%s\n' \
"${D}·······················································································${N}" \
"${R}:${G} ____   ___  _     _                 _                                             _ ${R}:${N}" \
"${R}:${G}/ ___| / _ \\| |   (_)          _ __ | | __ _ _   _  __ _ _ __ ___  _   _ _ __   __| |${R}:${N}" \
"${R}:${G}\\___ \\| | | | |   | |  _____  | '_ \\| |/ _\` | | | |/ _\` | '__/ _ \\| | | | '_ \\ / _\` |${R}:${N}" \
"${R}:${P} ___) | |_| | |___| | |_____| | |_) | | (_| | |_| | (_| | | | (_) | |_| | | | | (_| |${R}:${N}" \
"${R}:${P}|____/ \\__\\_\\_____|_|         | .__/|_|\\__,_|\\__, |\\__, |_|  \\___/ \\__,_|_| |_|\\__,_|${R}:${N}" \
"${R}:${P}                              |_|            |___/ |___/                             ${R}:${N}" \
"${D}·······················································································${N}"
  printf '%s\n' "${D}  local SQLi CTF lab  ·  60 levels  ·  ${N}${R}no mercy${N}"
  printf '\n'
}


need_compose() {
  if command -v docker >/dev/null 2>&1 && docker compose version >/dev/null 2>&1; then
    return 0
  fi
  echo "  Docker Compose not found. Install Docker Engine + Compose v2." >&2
  exit 1
}

compose() {
  docker compose "$@"
}

web_exec() {
  # Prefer exec on running container; fall back to one-off run
  if compose ps --status running 2>/dev/null | grep -q sqli-ctf-web; then
    compose exec -T web "$@"
  else
    echo "  web is not running — using a one-off container…"
    compose run --rm web "$@"
  fi
}

print_help() {
  print_banner
  cat <<'HELP'

  SQLi Playground  —  ./run.sh
  https://github.com/you-in-you/sqli-playground

  Local commands:
    start        Ensure databases, then start Flask (default)
    ensure       Create missing DBs/tables; keep flags & progress
    install      DROP lab DBs + flags, full rebuild
    reinstall    Same as install
    uninstall    DROP lab DBs + flags only — come back later
    status       Show version / databases / progress
    help         Show this help

  Docker commands:
    docker up         Build images and start db + web
    docker down       Stop containers
    docker down -v    Stop and delete DB volume (full wipe)
    docker logs       Tail web container logs
    docker ps         Show compose services
    docker shell      Open a shell in the web container
    docker ensure     setup_db ensure inside web
    docker install    setup_db install inside web
    docker reinstall  setup_db reinstall inside web
    docker uninstall  setup_db uninstall inside web
    docker status     setup_db status inside web

  Options:
    -y, --yes    Skip confirmation prompts (works with local and docker *)

  Examples:
    ./run.sh
    ./run.sh status
    ./run.sh -y install

    ./run.sh docker up
    ./run.sh docker status
    ./run.sh docker -y install
    ./run.sh docker logs
    ./run.sh docker down

HELP
}

# ── parse global -y and first command ───────────────────────────────────────
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
    docker)
      DOCKER_MODE=1
      shift
      break
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

# ── Docker branch ───────────────────────────────────────────────────────────
if [ "$DOCKER_MODE" -eq 1 ]; then
  need_compose

  # docker-level -y (e.g. ./run.sh docker -y install)
  while [ $# -gt 0 ]; do
    case "$1" in
      -y|--yes)
        YES_ARGS+=(-y)
        shift
        ;;
      *)
        break
        ;;
    esac
  done

  DCMD="${1:-up}"
  shift || true

  case "$DCMD" in
    up|start)
      print_banner
      echo "  Building & starting Docker stack…"
      compose up --build -d
      echo ""
      echo "  Lab:  http://127.0.0.1:5000"
      echo "  Logs: ./run.sh docker logs"
      echo "  Stop: ./run.sh docker down"
      echo ""
      ;;
    down|stop)
      # pass through extra args (e.g. -v)
      compose down "$@"
      echo "  Stack stopped."
      ;;
    logs)
      compose logs -f web "$@"
      ;;
    ps)
      compose ps "$@"
      ;;
    shell|sh|bash)
      if compose ps --status running 2>/dev/null | grep -q sqli-ctf-web; then
        compose exec web bash -c 'command -v bash >/dev/null && exec bash || exec sh'
      else
        compose run --rm web bash -c 'command -v bash >/dev/null && exec bash || exec sh'
      fi
      ;;
    ensure|install|reinstall|uninstall|status)
      echo "  → docker: setup_db.py $DCMD"
      web_exec python scripts/setup_db.py "${YES_ARGS[@]}" "$DCMD" "$@"
      ;;
    help|-h|--help)
      print_help
      ;;
    *)
      echo "Unknown docker command: $DCMD" >&2
      echo "Try: ./run.sh help" >&2
      exit 2
      ;;
  esac
  exit 0
fi

# ── Local branch ────────────────────────────────────────────────────────────
if [ -z "$CMD" ]; then
  CMD="start"
fi

case "$CMD" in
  start)
    print_banner
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
