#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CLAIM_JSON=""
REVIEW_MANIFEST=""
PACKAGE_TAR=""
REQUIRE_ACCEPTED=false
ACCEPTANCE_ARTIFACT=""

usage() {
  cat <<'EOF'
Usage: scripts/check_native_backend_release_posture.sh [options]

Options:
  --claim-json path           Read current_claim.json instead of running superneo-bench.
  --review-manifest path      Optional review_manifest.json for external-review checks.
  --package path              Extract current_claim.json and review_manifest.json from a review package tarball.
  --require-accepted          Fail unless the native backend is externally accepted.
  --acceptance-artifact path  Required with --require-accepted; must be structured JSON
                              binding the accepted review to claim/manifest hashes.

Default mode is the CI posture gate: the active native backend must remain
candidate_under_review / structural_candidate and must not look externally
accepted.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --claim-json)
      CLAIM_JSON="$2"
      shift 2
      ;;
    --review-manifest)
      REVIEW_MANIFEST="$2"
      shift 2
      ;;
    --package)
      PACKAGE_TAR="$2"
      shift 2
      ;;
    --require-accepted)
      REQUIRE_ACCEPTED=true
      shift
      ;;
    --acceptance-artifact)
      ACCEPTANCE_ARTIFACT="$2"
      shift 2
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

WORKDIR=""
cleanup() {
  if [[ -n "$WORKDIR" ]]; then
    rm -rf "$WORKDIR"
  fi
}
trap cleanup EXIT

if [[ -n "$PACKAGE_TAR" ]]; then
  WORKDIR="$(mktemp -d)"
  PACKAGE_SHA="$(dirname "$PACKAGE_TAR")/package.sha256"
  python3 -I "$ROOT/scripts/native_backend_review_package.py" extract \
    --archive "$PACKAGE_TAR" \
    --sha "$PACKAGE_SHA" \
    --destination "$WORKDIR" >/dev/null
  CLAIM_JSON="$WORKDIR/native-backend-128b-review-package/current_claim.json"
  REVIEW_MANIFEST="$WORKDIR/native-backend-128b-review-package/review_manifest.json"
fi

if [[ -z "$CLAIM_JSON" ]]; then
  WORKDIR="$(mktemp -d)"
  CLAIM_JSON="$WORKDIR/current_claim.json"
  cd "$ROOT"
  cargo run -p superneo-bench -- --print-native-security-claim > "$CLAIM_JSON"
fi

if [[ "$REQUIRE_ACCEPTED" == true && -z "$ACCEPTANCE_ARTIFACT" ]]; then
  echo "--require-accepted requires --acceptance-artifact" >&2
  exit 2
fi

python3 - "$CLAIM_JSON" "$REVIEW_MANIFEST" "$REQUIRE_ACCEPTED" "$ACCEPTANCE_ARTIFACT" "$PACKAGE_TAR" <<'PY'
import hashlib
import json
import sys
from pathlib import Path

claim_path = Path(sys.argv[1])
manifest_path = Path(sys.argv[2]) if sys.argv[2] else None
require_accepted = sys.argv[3] == "true"
acceptance_artifact = Path(sys.argv[4]) if sys.argv[4] else None
package_path = Path(sys.argv[5]) if sys.argv[5] else None

def sha256_file(path):
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()

def require_nonempty_string(artifact, field):
    value = artifact.get(field)
    if not isinstance(value, str) or not value.strip():
        raise SystemExit(
            f"native backend release blocked: acceptance artifact missing {field}"
        )
    return value.strip()

def load_acceptance_artifact(path):
    if path is None or not path.is_file():
        raise SystemExit("native backend release blocked: missing checked-in external acceptance artifact")
    try:
        artifact = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise SystemExit(
            f"native backend release blocked: acceptance artifact is not JSON: {exc}"
        ) from exc
    if not isinstance(artifact, dict):
        raise SystemExit("native backend release blocked: acceptance artifact must be a JSON object")
    if artifact.get("schema_version") != 1:
        raise SystemExit("native backend release blocked: unsupported acceptance artifact schema")
    if artifact.get("artifact_type") != "hegemon_native_backend_external_acceptance":
        raise SystemExit("native backend release blocked: malformed acceptance artifact type")
    if artifact.get("review_state") != "accepted":
        raise SystemExit("native backend release blocked: acceptance artifact does not mark review_state accepted")
    if artifact.get("external_review_completed") is not True:
        raise SystemExit("native backend release blocked: acceptance artifact does not mark external review completed")
    require_nonempty_string(artifact, "reviewer")
    require_nonempty_string(artifact, "reviewed_at")
    claim_hash = require_nonempty_string(artifact, "current_claim_sha256")
    if claim_hash != sha256_file(claim_path):
        raise SystemExit("native backend release blocked: acceptance artifact current_claim_sha256 mismatch")
    if manifest_path is None or not manifest_path.is_file():
        raise SystemExit("native backend release blocked: accepted mode requires review_manifest.json")
    manifest_hash = require_nonempty_string(artifact, "review_manifest_sha256")
    if manifest_hash != sha256_file(manifest_path):
        raise SystemExit("native backend release blocked: acceptance artifact review_manifest_sha256 mismatch")
    if package_path is not None:
        package_hash = require_nonempty_string(artifact, "package_sha256")
        if package_hash != sha256_file(package_path):
            raise SystemExit("native backend release blocked: acceptance artifact package_sha256 mismatch")
    return artifact

claim = json.loads(claim_path.read_text(encoding="utf-8"))
claim_body = claim.get("native_security_claim") or {}
params = claim.get("native_backend_params") or {}
review_state = claim_body.get("review_state")
maturity = params.get("maturity_label")

manifest = None
if manifest_path is not None:
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    guarantees = manifest.get("guarantee_summary") or {}
    external_done = guarantees.get("external_cryptanalysis_completed")
else:
    guarantees = {}
    external_done = None

if require_accepted:
    if review_state != "accepted":
        raise SystemExit(
            f"native backend release blocked: review_state={review_state!r}, expected 'accepted'"
        )
    if external_done is not True:
        raise SystemExit("native backend release blocked: review manifest must mark external cryptanalysis complete")
    load_acceptance_artifact(acceptance_artifact)
    print("native backend release posture: externally accepted")
else:
    if review_state != "candidate_under_review":
        raise SystemExit(
            f"native backend posture mismatch: review_state={review_state!r}, expected 'candidate_under_review'"
        )
    if maturity != "structural_candidate":
        raise SystemExit(
            f"native backend posture mismatch: maturity_label={maturity!r}, expected 'structural_candidate'"
        )
    if external_done not in (None, False):
        raise SystemExit("native backend posture mismatch: external cryptanalysis is marked complete but review_state is still candidate")
    print("native backend release posture: candidate_under_review / structural_candidate")
PY
