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

python3 - \
  "$ROOT/hegemon-app/electron/walletdClient.ts" \
  "$ROOT/hegemon-app/electron/walletdProtocol.ts" \
  "$ROOT/hegemon-app/package-lock.json" <<'PY'
import json
import re
import sys
from pathlib import Path

walletd_client = Path(sys.argv[1]).read_text(encoding="utf-8")
walletd_protocol = Path(sys.argv[2]).read_text(encoding="utf-8")
if "rejectLineDelimitedPassphrase(passphrase);" not in walletd_client:
    raise SystemExit("walletd client must reject line-delimited passphrases")
if "export function rejectLineDelimitedPassphrase" not in walletd_protocol:
    raise SystemExit("walletd protocol must define line-delimited passphrase rejection")
if "passphrase.includes('\\n')" not in walletd_protocol or "passphrase.includes('\\r')" not in walletd_protocol:
    raise SystemExit("walletd client must reject both LF and CR in passphrases")

lock = json.loads(Path(sys.argv[3]).read_text(encoding="utf-8"))
electron = lock.get("packages", {}).get("node_modules/electron", {}).get("version")
if not isinstance(electron, str):
    raise SystemExit("package-lock must pin electron")
match = re.fullmatch(r"(\d+)\.(\d+)\.(\d+)", electron)
if not match:
    raise SystemExit(f"electron version is not semver: {electron}")
major, minor, patch = map(int, match.groups())
if (major, minor, patch) < (39, 8, 5):
    raise SystemExit(f"electron runtime must be at least 39.8.5, got {electron}")
PY

python3 - "$ROOT/state.sh" "$ROOT/send.sh" "$ROOT/Dockerfile" "$ROOT/wallet/src/bin/wallet.rs" "$ROOT/docker-compose.testnet.yml" <<'PY'
import re
import sys
from pathlib import Path

state_sh = Path(sys.argv[1]).read_text(encoding="utf-8")
send_sh = Path(sys.argv[2]).read_text(encoding="utf-8")
dockerfile = Path(sys.argv[3]).read_text(encoding="utf-8")
wallet_cli = Path(sys.argv[4]).read_text(encoding="utf-8")
compose = Path(sys.argv[5]).read_text(encoding="utf-8")

for name, source in (("state.sh", state_sh), ("send.sh", send_sh)):
    if "wallet-passphrase" in source:
        raise SystemExit(f"{name}: helper usage must not ask for passphrase argv")
    if "--passphrase" in source:
        raise SystemExit(f"{name}: helper must let wallet prompt instead of passing --passphrase")
    if "HEGEMON_WALLET_PASSPHRASE" in source:
        raise SystemExit(f"{name}: helper must not move passphrase exposure into env")

from_lines = re.findall(r"(?m)^FROM\s+\S+", dockerfile)
if len(from_lines) < 2:
    raise SystemExit("Dockerfile must have builder and runtime FROM lines")
for line in from_lines:
    if "@sha256:" not in line:
        raise SystemExit(f"Dockerfile base image must be digest-pinned: {line}")
if "cargo build --locked --release" not in dockerfile:
    raise SystemExit("Dockerfile cargo build must use --locked")
if "--rpc-external" in dockerfile or "--rpc-cors=all" in dockerfile:
    raise SystemExit("Dockerfile default command must not expose dev RPC externally")
if 'env = "HEGEMON_WALLET_PASSPHRASE"' in wallet_cli:
    raise SystemExit("wallet CLI must not accept passphrases through environment variables")
if re.search(r"#\s*\[\s*arg\s*\([^]]*long[^]]*\)\s*\]\s*\n\s*passphrase\s*:", wallet_cli):
    raise SystemExit("wallet CLI must not accept passphrases through --passphrase")
if "--rpc-external" in compose or "--rpc-cors=all" in compose:
    raise SystemExit("docker-compose.testnet.yml must not expose RPC externally or use wildcard CORS")
for match in re.finditer(r'(?m)^\s*-\s+"([^"]*):9944(?::9944)?"', compose):
    mapping = match.group(1)
    if not mapping.startswith("127.0.0.1:"):
        raise SystemExit(f"compose RPC port mapping must bind loopback: {mapping}")
PY

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
if re.search(r"(?m)^permissions:\n\s+contents:\s+write\b", workflow):
    raise SystemExit("release workflow must not grant workflow-wide contents: write")
if not re.search(r"(?m)^permissions:\n\s+contents:\s+read\b", workflow):
    raise SystemExit("release workflow must default to workflow-wide contents: read")
create_release = re.search(
    r"(?ms)^  create-release:\n(?P<body>.*?)(?=^  [A-Za-z0-9_-]+:\n|\Z)",
    workflow,
)
if not create_release:
    raise SystemExit("missing create-release job")
if not re.search(r"(?m)^    permissions:\n\s+contents:\s+write\b", create_release.group("body")):
    raise SystemExit("create-release job must be the only job with contents: write")
for job_match in re.finditer(r"(?m)^  ([A-Za-z0-9_-]+):\n", workflow):
    job_name = job_match.group(1)
    if job_name == "create-release":
        continue
    job_body_match = re.search(
        rf"(?ms)^  {re.escape(job_name)}:\n(?P<body>.*?)(?=^  [A-Za-z0-9_-]+:\n|\Z)",
        workflow,
    )
    if job_body_match and re.search(
        r"(?m)^    permissions:\n(?:      .*\n)*?      contents:\s+write\b",
        job_body_match.group("body"),
    ):
        raise SystemExit(f"{job_name}: only create-release may request contents: write")
for match in re.finditer(r"(?m)^\s*uses:\s*([^\s#]+)", workflow):
    value = match.group(1)
    if "@" not in value:
        raise SystemExit(f"action reference must include an immutable ref: {value}")
    _, ref = value.rsplit("@", 1)
    if not re.fullmatch(r"[0-9a-f]{40}", ref):
        raise SystemExit(f"action reference must be pinned to a full commit SHA: {value}")
for match in re.finditer(r"(?m)^(\s*)-\s+uses:\s+actions/checkout@[0-9a-f]{40}\s*$", workflow):
    start = match.end()
    following = workflow[start : workflow.find("\n      - ", start) if "\n      - " in workflow[start:] else len(workflow)]
    if "persist-credentials: false" not in following:
        raise SystemExit("actions/checkout steps must disable persist-credentials")
for job in ("build-linux", "build-macos-intel", "build-macos-arm", "build-windows"):
    match = re.search(rf"(?ms)^  {job}:\n(?P<body>.*?)(?=^  [A-Za-z0-9_-]+:\n|\Z)", workflow)
    if not match:
        raise SystemExit(f"missing release job {job}")
    body = match.group("body")
    build_index = body.find("Build attested release artifacts")
    audit_index = body.find("Release PQ binary audit")
    if build_index < 0 or audit_index < 0 or build_index > audit_index:
        raise SystemExit(f"{job}: attested artifacts must build before release audit")
    audit_line = next(
        (line for line in body.splitlines() if "./scripts/security-audit.sh" in line),
        "",
    )
    if "--require-binary" not in audit_line or "--node-bin" not in audit_line:
        raise SystemExit(f"{job}: release audit must require node binary")
    if "--binary-manifest" not in audit_line:
        raise SystemExit(f"{job}: release audit must require an artifact manifest")
    if "--binary" not in audit_line or "wallet" not in audit_line or "walletd" not in audit_line:
        raise SystemExit(f"{job}: release audit must include wallet and walletd binaries")
if "cargo install cargo-audit --version 0.22.2 --locked" not in workflow:
    raise SystemExit("release workflow must pin cargo-audit version")
if "ELAN_INIT_SHA256:" not in workflow or "sha256sum -c -" not in workflow:
    raise SystemExit("release workflow must verify elan installer hash before execution")
PY

grep -q 'BINARY_BINS' "$ROOT/scripts/security-audit.sh" \
  || fail "security-audit.sh must track additional release binaries"
grep -q 'Required release binary not found' "$ROOT/scripts/security-audit.sh" \
  || fail "security-audit.sh must fail closed for each missing required binary"
grep -q 'for release_bin in' "$ROOT/scripts/security-audit.sh" \
  || fail "security-audit.sh must scan every listed release binary"
grep -q 'release_artifact_manifest.py' "$ROOT/scripts/security-audit.sh" \
  || fail "security-audit.sh must verify release artifact provenance"
grep -q 'check_release_crypto_profile.py' "$ROOT/scripts/security-audit.sh" \
  || fail "security-audit.sh must attest the compiled SmallWood profile"

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
