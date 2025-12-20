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
CMD_JSON=(cargo audit --color never --json)
if [ "$OFFLINE" = true ]; then
    CMD_TEXT+=(--no-fetch --stale)
    CMD_JSON+=(--no-fetch --stale)
fi

status=0
output=""
json_output=""
summary=""

if [ "$RECORD" = true ]; then
    json_output="$("${CMD_JSON[@]}" 2>&1)" || status=$?
    summary="$(printf '%s' "$json_output" | python3 - <<'PY'\nimport json\nimport sys\n\ndef safe(text: str) -> str:\n    return text.encode('ascii', 'replace').decode('ascii')\n\nraw = sys.stdin.read()\ntry:\n    data = json.loads(raw)\nexcept Exception:\n    print(safe(\"Unable to parse cargo audit JSON output\"))\n    for line in raw.splitlines():\n        print(safe(line))\n    sys.exit(0)\n\ndb = data.get(\"database\", {})\nprint(safe(f\"Database: last-commit={db.get('last-commit','')} last-updated={db.get('last-updated','')} advisories={db.get('advisory-count','')}\"))\n\nvuln = data.get(\"vulnerabilities\", {})\nprint(safe(f\"Vulnerabilities: {vuln.get('count', 0)}\"))\nfor item in vuln.get(\"list\", []):\n    adv = item.get(\"advisory\", {})\n    pkg = item.get(\"package\", {})\n    print(safe(f\"- {adv.get('id','')} {pkg.get('name','')} {pkg.get('version','')} {adv.get('url','')}\"))\n\nwarnings = data.get(\"warnings\", {})\nfor key in (\"unmaintained\", \"unsound\", \"yanked\"):\n    items = warnings.get(key) or []\n    print(safe(f\"{key}: {len(items)}\"))\n    for item in items:\n        adv = item.get(\"advisory\", {})\n        pkg = item.get(\"package\", {})\n        print(safe(f\"- {adv.get('id','')} {pkg.get('name','')} {pkg.get('version','')} {adv.get('url','')}\"))\nPY")"

    if [ "$USE_JSON" = true ]; then
        printf '%s\n' "$json_output"
    else
        output="$("${CMD_TEXT[@]}" 2>&1)" || true
        printf '%s\n' "$output"
    fi
else
    if [ "$USE_JSON" = true ]; then
        output="$("${CMD_JSON[@]}" 2>&1)" || status=$?
    else
        output="$("${CMD_TEXT[@]}" 2>&1)" || status=$?
    fi
    printf '%s\n' "$output"
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

Each entry records the exit status and raw output so changes can be reviewed
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
