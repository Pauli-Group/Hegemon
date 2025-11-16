#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DASHBOARD_SERVICE_PORT=${DASHBOARD_SERVICE_PORT:-8001}
DASHBOARD_SERVICE_HOST=${DASHBOARD_SERVICE_HOST:-127.0.0.1}
VITE_DASHBOARD_SERVICE_URL=${VITE_DASHBOARD_SERVICE_URL:-"http://127.0.0.1:${DASHBOARD_SERVICE_PORT}"}

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

echo "Running workstation quickstart (CLI flow)..."
./scripts/dashboard.py --run quickstart

echo "Installing dashboard service dependencies..."
python3 -m pip install -r scripts/dashboard_requirements.txt

echo "Launching dashboard service on ${DASHBOARD_SERVICE_HOST}:${DASHBOARD_SERVICE_PORT}"
uvicorn scripts.dashboard_service:app --host "$DASHBOARD_SERVICE_HOST" --port "$DASHBOARD_SERVICE_PORT" &
DASHBOARD_SERVICE_PID=$!

pushd dashboard-ui >/dev/null
echo "Installing dashboard UI dependencies (npm install)"
npm install

echo "Starting dashboard UI with Vite (bound to http://localhost:5173)"
VITE_DASHBOARD_SERVICE_URL="$VITE_DASHBOARD_SERVICE_URL" npm run dev &
DASHBOARD_UI_PID=$!
popd >/dev/null

echo "\nDashboard UI is running at http://localhost:5173"
echo "Streaming service API: http://${DASHBOARD_SERVICE_HOST}:${DASHBOARD_SERVICE_PORT}"
echo "Press Ctrl+C when you are done to stop both processes."

wait
