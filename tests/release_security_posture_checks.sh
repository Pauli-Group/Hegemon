#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

fail() {
  printf 'release security posture check failed: %s\n' "$1" >&2
  exit 1
}

sha256_file() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  else
    shasum -a 256 "$1" | awk '{print $1}'
  fi
}

grep -q 'app.isPackaged' "$ROOT/hegemon-app/electron/main.ts" \
  || fail "Electron main must branch on app.isPackaged"
grep -q '!app.isPackaged && process.env.VITE_DEV_SERVER_URL' "$ROOT/hegemon-app/electron/main.ts" \
  || fail "packaged app must not honor VITE_DEV_SERVER_URL"
grep -q '!app.isPackaged && process.env.ELECTRON_RENDERER_URL' "$ROOT/hegemon-app/electron/main.ts" \
  || fail "packaged app must not honor ELECTRON_RENDERER_URL"
grep -q 'if (app.isPackaged)' "$ROOT/hegemon-app/electron/binPaths.ts" \
  || fail "packaged app must not honor HEGEMON_BIN_DIR"

python3 - "$ROOT/hegemon-app/electron/nodeManager.ts" <<'PY'
import re
import sys
from pathlib import Path

source = Path(sys.argv[1]).read_text(encoding="utf-8")
match = re.search(
    r"async setMiningEnabled\(.*?\n  \}",
    source,
    flags=re.S,
)
if not match:
    raise SystemExit("setMiningEnabled body not found")
body = match.group(0)
if "this.resolveMiningRpcEndpoint" not in body:
    raise SystemExit("setMiningEnabled must resolve a trusted mining RPC endpoint")
if "this.rpcCall('hegemon_startMining', [params], endpoint)" not in body:
    raise SystemExit("startMining must use the resolved endpoint")
if "this.rpcCall('hegemon_stopMining', params, endpoint)" not in body:
    raise SystemExit("stopMining must use the resolved endpoint")
if "this.rpcCall('hegemon_startMining', [params], httpUrl)" in body:
    raise SystemExit("startMining still uses renderer-selected httpUrl")
if "Refusing to send mining RPC token to a renderer-selected RPC URL" not in source:
    raise SystemExit("missing mining-token exfiltration guard")
PY

python3 - "$ROOT/.github/workflows/release.yml" <<'PY'
import re
import sys
from pathlib import Path

workflow = Path(sys.argv[1]).read_text(encoding="utf-8")
for job in ("build-linux", "build-macos-intel", "build-macos-arm", "build-windows"):
    match = re.search(rf"(?ms)^  {job}:\n(?P<body>.*?)(?=^  [A-Za-z0-9_-]+:\n|\Z)", workflow)
    if not match:
        raise SystemExit(f"missing release job {job}")
    body = match.group("body")
    build_index = body.find("Build wallet binaries")
    audit_index = body.find("Release PQ binary audit")
    if build_index < 0 or audit_index < 0 or build_index > audit_index:
        raise SystemExit(f"{job}: wallet/walletd must build before release audit")
    audit_line = next(
        (line for line in body.splitlines() if "./scripts/security-audit.sh" in line),
        "",
    )
    if "--require-binary" not in audit_line or "--node-bin" not in audit_line:
        raise SystemExit(f"{job}: release audit must require node binary")
    if "--binary" not in audit_line or "wallet" not in audit_line or "walletd" not in audit_line:
        raise SystemExit(f"{job}: release audit must include wallet and walletd binaries")
PY

grep -q 'BINARY_BINS' "$ROOT/scripts/security-audit.sh" \
  || fail "security-audit.sh must track additional release binaries"
grep -q 'Required release binary not found' "$ROOT/scripts/security-audit.sh" \
  || fail "security-audit.sh must fail closed for each missing required binary"
grep -q 'for release_bin in' "$ROOT/scripts/security-audit.sh" \
  || fail "security-audit.sh must scan every listed release binary"

grep -q 'HEGEMON_TLC_BIN' "$ROOT/scripts/check_formal_core.sh" \
  || fail "formal-core model checker gate must require pinned TLC path"
grep -q 'HEGEMON_TLC_SHA256' "$ROOT/scripts/check_formal_core.sh" \
  || fail "formal-core model checker gate must require pinned TLC hash"
grep -q 'HEGEMON_APALACHE_BIN' "$ROOT/scripts/check_formal_core.sh" \
  || fail "formal-core model checker gate must require pinned Apalache path"
grep -q 'HEGEMON_APALACHE_SHA256' "$ROOT/scripts/check_formal_core.sh" \
  || fail "formal-core model checker gate must require pinned Apalache hash"
if grep -q 'skipping TLC\|skipping Apalache' "$ROOT/scripts/check_formal_core.sh"; then
  fail "requested model checker execution must not silently skip missing binaries"
fi

TMPDIR="$(mktemp -d)"
cleanup() {
  rm -rf "$TMPDIR"
}
trap cleanup EXIT

cat > "$TMPDIR/current_claim.json" <<'JSON'
{
  "native_security_claim": {
    "review_state": "accepted"
  },
  "native_backend_params": {
    "maturity_label": "reviewed"
  }
}
JSON
cat > "$TMPDIR/review_manifest.json" <<'JSON'
{
  "guarantee_summary": {
    "external_cryptanalysis_completed": true
  }
}
JSON
printf 'accepted external\n' > "$TMPDIR/acceptance.txt"
if "$ROOT/scripts/check_native_backend_release_posture.sh" \
  --claim-json "$TMPDIR/current_claim.json" \
  --review-manifest "$TMPDIR/review_manifest.json" \
  --require-accepted \
  --acceptance-artifact "$TMPDIR/acceptance.txt" >"$TMPDIR/malformed-acceptance.out" 2>&1; then
  fail "plain-text accepted external artifact must not satisfy accepted mode"
fi

claim_hash="$(sha256_file "$TMPDIR/current_claim.json")"
manifest_hash="$(sha256_file "$TMPDIR/review_manifest.json")"
cat > "$TMPDIR/acceptance.json" <<JSON
{
  "schema_version": 1,
  "artifact_type": "hegemon_native_backend_external_acceptance",
  "review_state": "accepted",
  "external_review_completed": true,
  "reviewer": "fixture",
  "reviewed_at": "2026-06-23T00:00:00Z",
  "current_claim_sha256": "$claim_hash",
  "review_manifest_sha256": "$manifest_hash"
}
JSON
"$ROOT/scripts/check_native_backend_release_posture.sh" \
  --claim-json "$TMPDIR/current_claim.json" \
  --review-manifest "$TMPDIR/review_manifest.json" \
  --require-accepted \
  --acceptance-artifact "$TMPDIR/acceptance.json" >"$TMPDIR/structured-acceptance.out"

printf 'release security posture checks passed\n'
