#!/bin/bash
# scripts/dependency-audit.sh
#
# Dependency advisory tracker (cargo audit). This is advisory-only; it does not
# gate builds unless wired into CI. Use --record to append output to the log.
#
# Usage:
#   ./scripts/dependency-audit.sh
#   ./scripts/dependency-audit.sh --record
#   ./scripts/dependency-audit.sh --offline --record
#
# Exit codes:
#   0 - No known advisories (or cargo audit returned success)
#   1 - Advisories found (cargo audit non-zero)
#   2 - cargo-audit not installed or invalid usage

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
LOG_PATH="$PROJECT_ROOT/docs/DEPENDENCY_AUDITS.md"

RECORD=false
OFFLINE=false
USE_JSON=false

usage() {
    echo "Usage: $0 [--record] [--offline] [--json]"
}

for arg in "$@"; do
    case "$arg" in
        --record)
            RECORD=true
            ;;
        --offline)
            OFFLINE=true
            ;;
        --json)
            USE_JSON=true
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "Unknown argument: $arg"
            usage
            exit 2
            ;;
    esac
done

if ! command -v cargo-audit >/dev/null 2>&1; then
    echo "cargo-audit is not installed."
    echo "Install with: cargo install cargo-audit"
    exit 2
fi

cd "$PROJECT_ROOT"

CMD_TEXT=(cargo audit --color never)
CMD_JSON=(cargo audit --color never --json --no-fetch --stale)
if [ "$OFFLINE" = true ]; then
    CMD_TEXT+=(--no-fetch --stale)
fi

status=0
status_text=0
status_json=0
output=""
json_output=""
json_err=""
summary=""

run_json_clean() {
    status_json=0
    json_err_file="$(mktemp)"
    json_output="$("${CMD_JSON[@]}" 2> "$json_err_file")" || status_json=$?
    json_err="$(cat "$json_err_file")"
    rm -f "$json_err_file"
}

prefetch_db() {
    if [ "$OFFLINE" = true ]; then
        return 0
    fi
    "${CMD_TEXT[@]}" >/dev/null 2>&1 || true
}

if [ "$RECORD" = true ]; then
    if [ "$USE_JSON" = true ]; then
        prefetch_db
        run_json_clean
        printf '%s\n' "$json_output"
    else
        output="$("${CMD_TEXT[@]}" 2>&1)" || status_text=$?
        printf '%s\n' "$output"
        run_json_clean
    fi
    status=$status_json
    json_tmp="$(mktemp)"
    printf '%s' "$json_output" > "$json_tmp"
    summary="$(CARGO_AUDIT_STDERR="$json_err" python3 - "$json_tmp" <<'PY'
import json
import sys
import os

def safe(text: str) -> str:
    return text.encode('ascii', 'replace').decode('ascii')

def norm(value: object, default: str = "") -> str:
    if value is None:
        return default
    text = str(value)
    return text if text else default

path = sys.argv[1]
with open(path, "r", encoding="utf-8") as handle:
    raw = handle.read()
try:
    data = json.loads(raw)
except Exception:
    print(safe("Unable to parse cargo audit JSON output"))
    stderr = os.environ.get("CARGO_AUDIT_STDERR", "")
    for line in stderr.splitlines():
        print(safe(line))
    sys.exit(0)

db = data.get("database", {})
print(safe(f"Database: last-commit={norm(db.get('last-commit'), 'unknown')} last-updated={norm(db.get('last-updated'), 'unknown')} advisories={norm(db.get('advisory-count'), 'unknown')}"))

vuln = data.get("vulnerabilities", {})
print(safe(f"Vulnerabilities: {vuln.get('count', 0)}"))
for item in vuln.get("list", []):
    adv = item.get("advisory") or {}
    pkg = item.get("package") or {}
    line = f"- {norm(adv.get('id'), 'unknown')} {norm(pkg.get('name'), 'unknown')} {norm(pkg.get('version'), 'unknown')} {norm(adv.get('url'))}".rstrip()
    print(safe(line))

warnings = data.get("warnings", {})
for key in ("unmaintained", "unsound", "yanked"):
    items = warnings.get(key) or []
    print(safe(f"{key}: {len(items)}"))
    for item in items:
        adv = item.get("advisory") or {}
        pkg = item.get("package") or {}
        line = f"- {norm(adv.get('id'), 'unknown')} {norm(pkg.get('name'), 'unknown')} {norm(pkg.get('version'), 'unknown')} {norm(adv.get('url'))}".rstrip()
        print(safe(line))
PY
)"
    rm -f "$json_tmp"
else
    if [ "$USE_JSON" = true ]; then
        prefetch_db
        run_json_clean
        status=$status_json
        printf '%s\n' "$json_output"
    else
        output="$("${CMD_TEXT[@]}" 2>&1)" || status=$?
        printf '%s\n' "$output"
    fi
fi

if [ "$RECORD" = true ]; then
    timestamp="$(date -u '+%Y-%m-%d %H:%MZ')"

    if [ ! -f "$LOG_PATH" ]; then
        cat > "$LOG_PATH" <<'EOF'
# Dependency Audit Log

This log tracks `cargo audit` runs for the workspace. It is advisory only and
does not gate builds unless explicitly wired into CI.

Run:

    ./scripts/dependency-audit.sh --record

Each entry records the exit status and summary output so changes can be reviewed
over time.
EOF
    fi

    {
        echo ""
        echo "## $timestamp"
        echo ""
        echo "Command: ${CMD_JSON[*]}"
        echo "Exit status: $status"
        echo ""
        echo "Summary:"
        echo ""
        printf '%s\n' "$summary" | sed 's/^/    /'
        echo ""
    } >> "$LOG_PATH"
fi

exit "$status"
