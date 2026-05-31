#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
POLICY="$ROOT/config/dependency-audit-waivers.json"
AUDIT_JSON=""
AUDIT_ARGS=(cargo audit --color never --json)

usage() {
  cat <<'EOF'
Usage: scripts/dependency-audit-gate.sh [--policy path] [--audit-json path] [--offline]

Runs cargo audit and fails on every unwaived advisory or yanked crate. Waivers
must name the advisory id, package, version, reason, tracking id, and expiry.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --policy)
      POLICY="$2"
      shift 2
      ;;
    --audit-json)
      AUDIT_JSON="$2"
      shift 2
      ;;
    --offline|--no-fetch)
      AUDIT_ARGS+=(--no-fetch --stale)
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "unknown argument: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

if [[ ! -f "$POLICY" ]]; then
  echo "dependency audit waiver policy not found: $POLICY" >&2
  exit 2
fi

if [[ -z "$AUDIT_JSON" ]]; then
  if ! command -v cargo-audit >/dev/null 2>&1; then
    echo "cargo-audit is not installed. Install with: cargo install cargo-audit --locked" >&2
    exit 2
  fi
  cd "$ROOT"
  AUDIT_JSON="$(mktemp)"
  trap 'rm -f "$AUDIT_JSON"' EXIT
  set +e
  "${AUDIT_ARGS[@]}" > "$AUDIT_JSON"
  AUDIT_STATUS=$?
  set -e
else
  AUDIT_STATUS=0
fi

python3 - "$AUDIT_JSON" "$POLICY" "$AUDIT_STATUS" <<'PY'
import json
import sys
from datetime import date
from pathlib import Path

audit_path = Path(sys.argv[1])
policy_path = Path(sys.argv[2])
audit_status = int(sys.argv[3])

try:
    audit = json.loads(audit_path.read_text(encoding="utf-8"))
except Exception as exc:
    raise SystemExit(f"failed to parse cargo audit JSON: {exc}")

try:
    policy = json.loads(policy_path.read_text(encoding="utf-8"))
except Exception as exc:
    raise SystemExit(f"failed to parse dependency audit policy: {exc}")

today = date.today()
waivers = policy.get("waivers", [])
if not isinstance(waivers, list):
    raise SystemExit("policy waivers must be a list")

def advisory_id(kind, item):
    advisory = item.get("advisory") or {}
    package = item.get("package") or {}
    if advisory.get("id"):
        return advisory["id"]
    if kind == "yanked":
        return f"yanked:{package.get('name', 'unknown')}:{package.get('version', 'unknown')}"
    return f"{kind}:{package.get('name', 'unknown')}:{package.get('version', 'unknown')}"

def package_name(item):
    return (item.get("package") or {}).get("name", "unknown")

def package_version(item):
    return (item.get("package") or {}).get("version", "unknown")

def title(item):
    advisory = item.get("advisory") or {}
    return advisory.get("title") or advisory.get("url") or ""

findings = []
for item in audit.get("vulnerabilities", {}).get("list", []):
    findings.append({
        "kind": "vulnerability",
        "id": advisory_id("vulnerability", item),
        "package": package_name(item),
        "version": package_version(item),
        "title": title(item),
    })

for kind, items in (audit.get("warnings") or {}).items():
    if not isinstance(items, list):
        continue
    for item in items:
        findings.append({
            "kind": kind,
            "id": advisory_id(kind, item),
            "package": package_name(item),
            "version": package_version(item),
            "title": title(item),
        })

validated_waivers = []
for index, waiver in enumerate(waivers):
    missing = [
        key
        for key in ("id", "package", "version", "kind", "expires", "tracking", "reason")
        if not waiver.get(key)
    ]
    if missing:
        raise SystemExit(f"waiver #{index} is missing required fields: {', '.join(missing)}")
    try:
        expiry = date.fromisoformat(waiver["expires"])
    except ValueError as exc:
        raise SystemExit(f"waiver {waiver['id']} has invalid expires date: {exc}")
    if expiry < today:
        raise SystemExit(
            f"waiver {waiver['id']} for {waiver['package']} {waiver['version']} expired on {expiry}"
        )
    validated_waivers.append(waiver)

def matching_waiver(finding):
    for waiver in validated_waivers:
        if waiver["id"] != finding["id"]:
            continue
        if waiver["package"] != finding["package"]:
            continue
        if waiver["version"] != finding["version"]:
            continue
        if waiver["kind"] != finding["kind"]:
            continue
        return waiver
    return None

unwaived = []
waived = []
for finding in findings:
    waiver = matching_waiver(finding)
    if waiver is None:
        unwaived.append(finding)
    else:
        waived.append((finding, waiver))

print(f"dependency audit findings: {len(findings)} total, {len(waived)} waived, {len(unwaived)} unwaived")
for finding, waiver in waived:
    print(
        f"waived {finding['kind']} {finding['id']} "
        f"{finding['package']} {finding['version']} until {waiver['expires']} "
        f"({waiver['tracking']})"
    )

if unwaived:
    print("unwaived dependency advisories:")
    for finding in unwaived:
        detail = f" - {finding['kind']} {finding['id']} {finding['package']} {finding['version']}"
        if finding["title"]:
            detail += f": {finding['title']}"
        print(detail)
    raise SystemExit(1)

if audit_status not in (0, 1):
    raise SystemExit(f"cargo audit exited with unexpected status {audit_status}")
PY
