#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DASHBOARD_SERVICE_PORT=${DASHBOARD_SERVICE_PORT:-8001}
DASHBOARD_SERVICE_HOST=${DASHBOARD_SERVICE_HOST:-127.0.0.1}
VITE_DASHBOARD_SERVICE_URL=${VITE_DASHBOARD_SERVICE_URL:-"http://127.0.0.1:${DASHBOARD_SERVICE_PORT}"}
PYTHON_BIN=${PYTHON_BIN:-python3}
DASHBOARD_VENV_DIR=${DASHBOARD_VENV_DIR:-"$REPO_ROOT/.dashboard-service-venv"}
NODE_BIN_DIR=${NODE_BIN_DIR:-"$HOME/.local/node/bin"}
SYSTEM_NODE_BIN=${SYSTEM_NODE_BIN:-"/usr/local/node/bin"}

cleanup() {
    local exit_code=$?
    trap - EXIT INT TERM
    if [[ -n "${DASHBOARD_SERVICE_PID:-}" ]]; then
        if kill -0 "${DASHBOARD_SERVICE_PID}" 2>/dev/null; then
            echo "\nShutting down dashboard service (pid ${DASHBOARD_SERVICE_PID})"
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

echo "Running workstation quickstart (CLI flow)..."
./scripts/dashboard.py --run quickstart

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
npm ci --no-progress

echo "Starting dashboard UI with Vite (bound to http://localhost:5173)"
VITE_DASHBOARD_SERVICE_URL="$VITE_DASHBOARD_SERVICE_URL" npm run dev &
DASHBOARD_UI_PID=$!
popd >/dev/null

echo "\nDashboard UI is running at http://localhost:5173"
echo "Streaming service API: http://${DASHBOARD_SERVICE_HOST}:${DASHBOARD_SERVICE_PORT}"
echo "Press Ctrl+C when you are done to stop both processes."

wait
