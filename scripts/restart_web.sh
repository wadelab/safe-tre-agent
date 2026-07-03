#!/usr/bin/env bash
# Restart the local safe-tre web interface in the background.
set -euo pipefail
cd "$(dirname "$0")/.."

HOST="${HOST:-127.0.0.1}"
PORT="${PORT:-8800}"
ENV_FILE="${SAFETRE_WEB_ENV_FILE:-.env.local}"
LOG_FILE="${SAFETRE_WEB_LOG:-/tmp/safetre-web-${PORT}.log}"
PID_FILE="${SAFETRE_WEB_PID:-/tmp/safetre-web-${PORT}.pid}"

if [[ -f "$ENV_FILE" ]]; then
  set -a
  # shellcheck disable=SC1090
  source "$ENV_FILE"
  set +a
fi

is_safetre_web_pid() {
  local pid="$1"
  [[ -r "/proc/${pid}/cmdline" ]] || return 1
  tr '\0' ' ' <"/proc/${pid}/cmdline" | grep -q "safetre_web.app:app"
}

candidate_pids() {
  if [[ -f "$PID_FILE" ]]; then
    sed -nE '/^[0-9]+$/p' "$PID_FILE"
  fi
  ss -ltnp "sport = :${PORT}" 2>/dev/null \
    | sed -nE 's/.*pid=([0-9]+).*/\1/p'
  pgrep -f "safetre_web\\.app:app.*--port ${PORT}" 2>/dev/null || true
}

mapfile -t pids < <(candidate_pids | sort -nu)
stopped=0
for pid in "${pids[@]}"; do
  if is_safetre_web_pid "$pid"; then
    echo "stopping safetre web pid ${pid}"
    kill -TERM "$pid" 2>/dev/null || true
    stopped=1
  fi
done

if [[ "$stopped" -eq 1 ]]; then
  for _ in {1..30}; do
    alive=0
    for pid in "${pids[@]}"; do
      if is_safetre_web_pid "$pid" && kill -0 "$pid" 2>/dev/null; then
        alive=1
      fi
    done
    [[ "$alive" -eq 0 ]] && break
    sleep 0.2
  done
fi

mapfile -t pids < <(candidate_pids | sort -nu)
for pid in "${pids[@]}"; do
  if is_safetre_web_pid "$pid" && kill -0 "$pid" 2>/dev/null; then
    echo "force stopping safetre web pid ${pid}"
    kill -KILL "$pid" 2>/dev/null || true
  fi
done

mkdir -p "$(dirname "$LOG_FILE")" "$(dirname "$PID_FILE")"
: >"$LOG_FILE"
cmd=(uv run uvicorn safetre_web.app:app --host "$HOST" --port "$PORT")
if command -v setsid >/dev/null 2>&1; then
  nohup setsid "${cmd[@]}" >>"$LOG_FILE" 2>&1 &
else
  nohup "${cmd[@]}" >>"$LOG_FILE" 2>&1 &
fi
pid="$!"
echo "$pid" >"$PID_FILE"
echo "started safetre web pid ${pid} on http://${HOST}:${PORT}"

for _ in {1..50}; do
  if curl -fsS "http://${HOST}:${PORT}/healthz" >/dev/null 2>&1; then
    echo "healthz ok"
    echo "log: ${LOG_FILE}"
    exit 0
  fi
  if ! kill -0 "$pid" 2>/dev/null; then
    echo "web process exited during startup; log follows:" >&2
    tail -n 80 "$LOG_FILE" >&2 || true
    exit 1
  fi
  sleep 0.2
done

echo "web did not pass health check; log follows:" >&2
tail -n 80 "$LOG_FILE" >&2 || true
exit 1
