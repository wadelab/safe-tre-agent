#!/usr/bin/env bash
# Run the web interface bound to localhost only, then expose to the tailnet.
set -euo pipefail
cd "$(dirname "$0")/.."

# Load local config (SAFETRE_LLM=exampleprovider/real, API key, model, etc.) so the app
# uses the configured online planner. Without this, SAFETRE_LLM is unset and the
# app can only use it if it is already exported in the ambient environment.
ENV_FILE="${SAFETRE_WEB_ENV_FILE:-.env.local}"
if [[ -f "$ENV_FILE" ]]; then
  set -a
  # shellcheck disable=SC1090
  source "$ENV_FILE"
  set +a
fi

PORT="${PORT:-8800}"

# localhost bind is deliberate: only the local tailscale proxy can reach it,
# so the identity header cannot be forged by a remote client.
echo "serving on http://127.0.0.1:${PORT}  (expose with: tailscale serve --bg ${PORT})"
exec uv run uvicorn safetre_web.app:app --host 127.0.0.1 --port "${PORT}"

# On d2-1, in another shell:
#   tailscale serve --bg 8800
# -> https://d2-1.<tailnet>.ts.net   (TLS + tailnet identity headers)
