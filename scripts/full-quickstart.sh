#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PYTHON_BIN=${PYTHON_BIN:-python3}
DASHBOARD_VENV_DIR=${DASHBOARD_VENV_DIR:-"$REPO_ROOT/.dashboard-service-venv"}
NODE_BIN_DIR=${NODE_BIN_DIR:-"$HOME/.local/node/bin"}
SYSTEM_NODE_BIN=${SYSTEM_NODE_BIN:-"/usr/local/node/bin"}
DEFAULT_SERVICE_HOST=${DASHBOARD_SERVICE_HOST:-127.0.0.1}
DEFAULT_SERVICE_PORT=${DASHBOARD_SERVICE_PORT:-8001}
DEFAULT_UI_HOST=${DASHBOARD_UI_HOST:-127.0.0.1}
DEFAULT_UI_PORT=${DASHBOARD_UI_PORT:-5173}
DASHBOARD_AUTOSTART_NODE=${DASHBOARD_AUTOSTART_NODE:-1}
DASHBOARD_NODE_HOST=${DASHBOARD_NODE_HOST:-127.0.0.1}
DEFAULT_NODE_PORT=${DASHBOARD_NODE_PORT:-8080}
DASHBOARD_NODE_DB_PATH=${DASHBOARD_NODE_DB_PATH:-"$REPO_ROOT/state/dashboard-node.$(date +%s).db"}
DASHBOARD_NODE_TOKEN=${DASHBOARD_NODE_TOKEN:-devnet-token}
WALLET_STORE_PATH=${WALLET_STORE_PATH:-}
WALLET_PASSPHRASE_FILE=${WALLET_PASSPHRASE_FILE:-}
WALLET_API_URL=${WALLET_API_URL:-}
export WALLET_API_URL

find_open_port() {
    local preferred="${1:-}"
    local host="${2:-127.0.0.1}"
    "$PYTHON_BIN" - "$preferred" "$host" <<'PY'
import socket
import sys

preferred = sys.argv[1]
host = sys.argv[2]


def port_free(port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(0.5)
        return sock.connect_ex((host, port)) != 0


if preferred:
    try:
        candidate = int(preferred)
    except ValueError:
        candidate = None
    else:
        if candidate > 0 and port_free(candidate):
            print(candidate)
            sys.exit(0)

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
    sock.bind((host, 0))
    print(sock.getsockname()[1])
PY
}

cleanup() {
    local exit_code=$?
    trap - EXIT INT TERM
    if [[ -n "${WALLET_DAEMON_PID:-}" ]]; then
        if kill -0 "${WALLET_DAEMON_PID}" 2>/dev/null; then
            echo "Shutting down wallet daemon (pid ${WALLET_DAEMON_PID})"
            kill "${WALLET_DAEMON_PID}" 2>/dev/null || true
        fi
        wait "${WALLET_DAEMON_PID}" 2>/dev/null || true
    fi
    if [[ -n "${DASHBOARD_SERVICE_PID:-}" ]]; then
        if kill -0 "${DASHBOARD_SERVICE_PID}" 2>/dev/null; then
            printf "\nShutting down dashboard service (pid %s)\n" "${DASHBOARD_SERVICE_PID}"
            kill "${DASHBOARD_SERVICE_PID}" 2>/dev/null || true
        fi
        wait "${DASHBOARD_SERVICE_PID}" 2>/dev/null || true
    fi
    if [[ -n "${DASHBOARD_UI_PID:-}" ]]; then
        if kill -0 "${DASHBOARD_UI_PID}" 2>/dev/null; then
            echo "Stopping dashboard UI (pid ${DASHBOARD_UI_PID})"
            kill "${DASHBOARD_UI_PID}" 2>/dev/null || true
        fi
        wait "${DASHBOARD_UI_PID}" 2>/dev/null || true
    fi
    exit "$exit_code"
}
trap cleanup EXIT INT TERM

cd "$REPO_ROOT"

if [[ -d "$SYSTEM_NODE_BIN" ]]; then
    export PATH="$SYSTEM_NODE_BIN:$PATH"
fi
if [[ -d "$NODE_BIN_DIR" ]]; then
    export PATH="$NODE_BIN_DIR:$PATH"
fi

DASHBOARD_SERVICE_HOST="$DEFAULT_SERVICE_HOST"
DASHBOARD_SERVICE_PORT=$(find_open_port "$DEFAULT_SERVICE_PORT" "$DASHBOARD_SERVICE_HOST")
DASHBOARD_UI_HOST="$DEFAULT_UI_HOST"
DASHBOARD_UI_PORT=$(find_open_port "$DEFAULT_UI_PORT" "$DASHBOARD_UI_HOST")
DASHBOARD_NODE_PORT=$(find_open_port "$DEFAULT_NODE_PORT" "$DASHBOARD_NODE_HOST")
NODE_RPC_URL=${NODE_RPC_URL:-"http://${DASHBOARD_NODE_HOST}:${DASHBOARD_NODE_PORT}"}
NODE_RPC_TOKEN=${NODE_RPC_TOKEN:-$DASHBOARD_NODE_TOKEN}
VITE_DASHBOARD_SERVICE_URL=${VITE_DASHBOARD_SERVICE_URL:-"http://${DASHBOARD_SERVICE_HOST}:${DASHBOARD_SERVICE_PORT}"}

export DASHBOARD_AUTOSTART_NODE
export DASHBOARD_NODE_HOST DASHBOARD_NODE_PORT DASHBOARD_NODE_DB_PATH DASHBOARD_NODE_TOKEN
export NODE_RPC_URL NODE_RPC_TOKEN VITE_DASHBOARD_SERVICE_URL
export DASHBOARD_SERVICE_PORT DASHBOARD_SERVICE_HOST

echo "Running workstation quickstart (CLI flow)..."
./scripts/dashboard.py --run quickstart

if [[ -n "$WALLET_STORE_PATH" && -f "$WALLET_PASSPHRASE_FILE" && -n "${NODE_RPC_URL:-}" && -n "$WALLET_API_URL" ]]; then
    WALLET_HTTP_BIND=${WALLET_API_URL#http://}
    WALLET_HTTP_BIND=${WALLET_HTTP_BIND#https://}
    WALLET_HTTP_BIND=${WALLET_HTTP_BIND%%/*}
    WALLET_PASSPHRASE=$(tr -d '\n' <"$WALLET_PASSPHRASE_FILE")
    echo "Launching wallet daemon with HTTP API on ${WALLET_HTTP_BIND}"
    cargo run -p wallet --bin wallet -- daemon \
        --store "$WALLET_STORE_PATH" \
        --passphrase "$WALLET_PASSPHRASE" \
        --rpc-url "$NODE_RPC_URL" \
        --auth-token "${NODE_RPC_TOKEN:-}" \
        --interval-secs 5 \
        --http-listen "$WALLET_HTTP_BIND" &
    WALLET_DAEMON_PID=$!
else
    echo "Skipping wallet daemon launch. Set WALLET_STORE_PATH, WALLET_PASSPHRASE_FILE, WALLET_API_URL, and NODE_RPC_URL to enable it."
fi

if [[ ! -d "$DASHBOARD_VENV_DIR" ]]; then
    echo "Creating dashboard service virtual environment at ${DASHBOARD_VENV_DIR}"
    "$PYTHON_BIN" -m venv "$DASHBOARD_VENV_DIR"
fi

DASHBOARD_PIP="${DASHBOARD_VENV_DIR}/bin/pip"
DASHBOARD_PYTHON="${DASHBOARD_VENV_DIR}/bin/python"

echo "Installing dashboard service dependencies into ${DASHBOARD_VENV_DIR}..."
"$DASHBOARD_PIP" install --upgrade pip
"$DASHBOARD_PIP" install -r scripts/dashboard_requirements.txt

echo "Launching dashboard service on ${DASHBOARD_SERVICE_HOST}:${DASHBOARD_SERVICE_PORT}"
"$DASHBOARD_PYTHON" -m uvicorn scripts.dashboard_service:app --host "$DASHBOARD_SERVICE_HOST" --port "$DASHBOARD_SERVICE_PORT" &
DASHBOARD_SERVICE_PID=$!

pushd dashboard-ui >/dev/null
echo "Installing dashboard UI dependencies (npm ci)"
npm run clean --if-present >/dev/null 2>&1 || true
if [[ -d node_modules ]]; then
    if ! rm -rf node_modules 2>/dev/null; then
        echo "rm -rf node_modules failed; retrying with safe Python fallback"
        "$PYTHON_BIN" - <<'PY'
import shutil
import sys
from pathlib import Path
path = Path("node_modules")
try:
    shutil.rmtree(path, ignore_errors=False)
except Exception as exc:  # noqa: BLE001
    print(f"Warning: could not fully remove {path}: {exc}", file=sys.stderr)
    # best-effort cleanup so npm ci can proceed
    shutil.rmtree(path, ignore_errors=True)
PY
    fi
fi
npm ci --no-progress

echo "Starting dashboard UI with Vite (bound to http://${DASHBOARD_UI_HOST}:${DASHBOARD_UI_PORT})"
VITE_DASHBOARD_SERVICE_URL="$VITE_DASHBOARD_SERVICE_URL" npm run dev -- --host "$DASHBOARD_UI_HOST" --port "$DASHBOARD_UI_PORT" &
DASHBOARD_UI_PID=$!
popd >/dev/null

echo
echo "Dashboard UI is running at http://${DASHBOARD_UI_HOST}:${DASHBOARD_UI_PORT}"
echo "Streaming service API: http://${DASHBOARD_SERVICE_HOST}:${DASHBOARD_SERVICE_PORT}"
if [[ "${DASHBOARD_AUTOSTART_NODE}" == "1" || "${DASHBOARD_AUTOSTART_NODE,,}" == "true" ]]; then
    echo "Autostarted node target: ${NODE_RPC_URL} (token ${NODE_RPC_TOKEN})"
fi
echo "Press Ctrl+C when you are done to stop both processes."

wait
