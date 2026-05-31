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
  --acceptance-artifact path  Required with --require-accepted; must be a checked-in external acceptance note.

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

TMPDIR=""
cleanup() {
  if [[ -n "$TMPDIR" ]]; then
    rm -rf "$TMPDIR"
  fi
}
trap cleanup EXIT

if [[ -n "$PACKAGE_TAR" ]]; then
  TMPDIR="$(mktemp -d)"
  tar -xzf "$PACKAGE_TAR" -C "$TMPDIR"
  CLAIM_JSON="$TMPDIR/native-backend-128b-review-package/current_claim.json"
  REVIEW_MANIFEST="$TMPDIR/native-backend-128b-review-package/review_manifest.json"
fi

if [[ -z "$CLAIM_JSON" ]]; then
  TMPDIR="$(mktemp -d)"
  CLAIM_JSON="$TMPDIR/current_claim.json"
  cd "$ROOT"
  cargo run -p superneo-bench -- --print-native-security-claim > "$CLAIM_JSON"
fi

if [[ "$REQUIRE_ACCEPTED" == true && -z "$ACCEPTANCE_ARTIFACT" ]]; then
  echo "--require-accepted requires --acceptance-artifact" >&2
  exit 2
fi

python3 - "$CLAIM_JSON" "$REVIEW_MANIFEST" "$REQUIRE_ACCEPTED" "$ACCEPTANCE_ARTIFACT" <<'PY'
import json
import sys
from pathlib import Path

claim_path = Path(sys.argv[1])
manifest_path = Path(sys.argv[2]) if sys.argv[2] else None
require_accepted = sys.argv[3] == "true"
acceptance_artifact = Path(sys.argv[4]) if sys.argv[4] else None

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
    if external_done is False:
        raise SystemExit("native backend release blocked: review manifest says external cryptanalysis is incomplete")
    if acceptance_artifact is None or not acceptance_artifact.is_file():
        raise SystemExit("native backend release blocked: missing checked-in external acceptance artifact")
    acceptance_text = acceptance_artifact.read_text(encoding="utf-8").lower()
    if "accepted" not in acceptance_text or "external" not in acceptance_text:
        raise SystemExit("native backend release blocked: acceptance artifact does not state external acceptance")
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
