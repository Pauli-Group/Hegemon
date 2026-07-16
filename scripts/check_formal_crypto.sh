#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CRYPTO_ROOT="$ROOT/formal/crypto"
MODE="${1:-full}"

if [ "$MODE" != "full" ] && [ "$MODE" != "--isolation-only" ]; then
  printf 'usage: %s [--isolation-only]\n' "$0" >&2
  exit 2
fi

TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/hegemon-formal-crypto.XXXXXX")"
trap 'rm -rf "$TMP_DIR"' EXIT

isolation_report="$TMP_DIR/isolation.txt"
: > "$isolation_report"

while IFS= read -r -d '' manifest; do
  if grep -niE 'formal/crypto|HegemonCrypto|ArkLib|Arklib' "$manifest" \
      >> "$isolation_report" 2>/dev/null; then
    printf 'source: %s\n' "$manifest" >> "$isolation_report"
  fi
done < <(find "$ROOT" -name Cargo.toml -not -path '*/.lake/*' -print0)

while IFS= read -r -d '' source; do
  if grep -niE 'formal/crypto|HegemonCrypto|ArkLib|Arklib' "$source" \
      >> "$isolation_report" 2>/dev/null; then
    printf 'source: %s\n' "$source" >> "$isolation_report"
  fi
done < <(find "$ROOT/formal/lean" \
  \( -name '*.lean' -o -name 'lakefile.lean' -o -name 'lake-manifest.json' \) -print0)

for release_surface in \
    "$ROOT/.github/workflows/release.yml" \
    "$ROOT/config/formal-security-claims.json" \
    "$ROOT/config/formal-security-blueprint.json"; do
  if [ -f "$release_surface" ] && \
      grep -niE 'formal/crypto|HegemonCrypto|ArkLib|Arklib' "$release_surface" \
        >> "$isolation_report" 2>/dev/null; then
    printf 'source: %s\n' "$release_surface" >> "$isolation_report"
  fi
done

if [ -s "$isolation_report" ]; then
  printf 'research-only formal cryptography leaked into a production authority surface:\n' >&2
  cat "$isolation_report" >&2
  exit 1
fi

if find "$CRYPTO_ROOT" -path "$CRYPTO_ROOT/.lake" -prune -o -type l -print -quit \
    | grep -q .; then
  printf 'formal/crypto must not contain source symlinks\n' >&2
  exit 1
fi

if [ "$MODE" = "--isolation-only" ]; then
  printf 'formal-crypto isolation passed: no production authority imports research definitions\n'
  exit 0
fi

if [ -d "${HOME:-}/.elan/bin" ]; then
  export PATH="${HOME}/.elan/bin:$PATH"
fi

for command in lake python3; do
  if ! command -v "$command" >/dev/null 2>&1; then
    printf '%s is required for the formal cryptography gate\n' "$command" >&2
    exit 2
  fi
done

expected_toolchain='leanprover/lean4:v4.30.0'
actual_toolchain="$(tr -d '\r\n' < "$CRYPTO_ROOT/lean-toolchain")"
if [ "$actual_toolchain" != "$expected_toolchain" ]; then
  printf 'unexpected formal/crypto toolchain: %s\n' "$actual_toolchain" >&2
  exit 1
fi

python3 - "$CRYPTO_ROOT/lake-manifest.json" "$CRYPTO_ROOT/lakefile.toml" <<'PY'
import json
import re
import sys
import tomllib

manifest = json.load(open(sys.argv[1], encoding="utf-8"))
with open(sys.argv[2], "rb") as lakefile:
    lake_config = tomllib.load(lakefile)
packages = {package["name"]: package for package in manifest["packages"]}
required = {
    "Arklib": (
        "https://github.com/Verified-zkEVM/ArkLib",
        "e6d77b18ca1334a91faf4d1ccf9f96d854d58ba4",
    ),
    "VCVio": (
        "https://github.com/Verified-zkEVM/VCV-io",
        "5f7707fbeb0c53754580b0a506af8952f75e9019",
    ),
}
for name, (url, revision) in required.items():
    package = packages.get(name)
    if package is None or package.get("url") != url or package.get("rev") != revision:
        raise SystemExit(f"dependency pin mismatch for {name}")
for package in manifest["packages"]:
    if package.get("type") == "git":
        if not re.fullmatch(r"[0-9a-f]{40}", package.get("rev", "")):
            raise SystemExit(f"non-immutable git revision for {package['name']}")
        if not package.get("url", "").startswith("https://github.com/"):
            raise SystemExit(f"non-GitHub dependency URL for {package['name']}")
formal = packages.get("hegemon_formal")
if formal is None or formal.get("type") != "path" or formal.get("dir") != "../lean":
    raise SystemExit("formal/crypto must depend on formal/lean through ../lean")
path_packages = [package["name"] for package in manifest["packages"] if package.get("type") == "path"]
if path_packages != ["hegemon_formal"]:
    raise SystemExit(f"unexpected local path dependencies: {path_packages}")
expected_requirements = [
    {"name": "hegemon_formal", "path": "../lean"},
    {
        "name": "Arklib",
        "git": "https://github.com/Verified-zkEVM/ArkLib",
        "rev": "e6d77b18ca1334a91faf4d1ccf9f96d854d58ba4",
    },
]
if lake_config.get("require") != expected_requirements:
    raise SystemExit("lakefile.toml direct requirements differ from the reviewed dependency set")
PY

if [ ! -d "$CRYPTO_ROOT/.lake/packages" ]; then
  minimum_free_gib="${HEGEMON_FORMAL_CRYPTO_MIN_FREE_GIB:-40}"
  python3 - "$CRYPTO_ROOT" "$minimum_free_gib" <<'PY'
import shutil
import sys

free = shutil.disk_usage(sys.argv[1]).free
minimum = int(sys.argv[2]) * 1024 ** 3
if free < minimum:
    raise SystemExit(
        f"cold formal/crypto build refused: {free / 1024 ** 3:.1f} GiB free, "
        f"{int(sys.argv[2])} GiB required"
    )
PY
fi

forbidden_report="$TMP_DIR/forbidden.txt"
if find "$CRYPTO_ROOT" -path "$CRYPTO_ROOT/.lake" -prune -o -type f -name '*.lean' -print0 \
    | xargs -0 grep -nE \
      '\b(sorry|admit|unsafe|partial|opaque|extern|implemented_by|native_decide)\b|^[[:space:]]*((private|protected|noncomputable)[[:space:]]+)*axiom[[:space:]]' \
      > "$forbidden_report" 2>/dev/null; then
  printf 'formal cryptography sources contain forbidden trust bypasses:\n' >&2
  cat "$forbidden_report" >&2
  exit 1
fi

cat > "$TMP_DIR/expected-sources.txt" <<'EOF'
HegemonCrypto.lean
HegemonCrypto/AssuranceBoundary.lean
HegemonCrypto/CCS.lean
HegemonCrypto/CCSExamples.lean
HegemonCrypto/KnowledgeSoundnessTarget.lean
HegemonCrypto/SmallWoodRelation.lean
EOF
find "$CRYPTO_ROOT" -path "$CRYPTO_ROOT/.lake" -prune -o -type f -name '*.lean' -print \
  | sed "s#^$CRYPTO_ROOT/##" | sort > "$TMP_DIR/actual-sources.txt"
if ! diff -u "$TMP_DIR/expected-sources.txt" "$TMP_DIR/actual-sources.txt"; then
  printf 'formal cryptography source inventory differs from the reviewed set\n' >&2
  exit 1
fi

theorem_count="$(find "$CRYPTO_ROOT" -path "$CRYPTO_ROOT/.lake" -prune -o \
  -type f -name '*.lean' -exec grep -hE '^[[:space:]]*(theorem|lemma)[[:space:]]' {} + \
  | wc -l | tr -d '[:space:]')"
if [ "$theorem_count" != "10" ]; then
  printf 'formal cryptography theorem inventory changed: expected 10, found %s\n' \
    "$theorem_count" >&2
  exit 1
fi

if grep -nE '^[[:space:]]*(theorem|lemma|instance)[[:space:]]' \
    "$CRYPTO_ROOT/HegemonCrypto/KnowledgeSoundnessTarget.lean" > "$forbidden_report"; then
  printf 'the sanity package may state, but not prove, knowledge soundness:\n' >&2
  cat "$forbidden_report" >&2
  exit 1
fi

(
  cd "$CRYPTO_ROOT"
  lake build HegemonCrypto
  lake env lean --run "$ROOT/scripts/lean_axiom_audit.lean" \
    "$CRYPTO_ROOT/credited-declarations.txt" HegemonCrypto > "$TMP_DIR/axioms.json"
)

python3 - "$TMP_DIR/axioms.json" "$CRYPTO_ROOT/credited-declarations.txt" <<'PY'
import json
import sys

records = json.load(open(sys.argv[1], encoding="utf-8"))
expected = [
    "HegemonCrypto.CCS.System.rowSatisfiedB_iff",
    "HegemonCrypto.CCS.System.satisfiesB_iff",
    "HegemonCrypto.CCSExamples.product_system_accepts_exact_assignment",
    "HegemonCrypto.CCSExamples.changed_coefficient_rejects",
    "HegemonCrypto.CCSExamples.omitted_factor_rejects",
    "HegemonCrypto.CCSExamples.duplicated_factor_rejects",
    "HegemonCrypto.CCSExamples.changed_witness_rejects",
    "HegemonCrypto.SmallWood.Relation",
    "HegemonCrypto.SmallWood.relationB_iff",
    "HegemonCrypto.SmallWood.ExactCCSRefinement",
    "HegemonCrypto.SmallWood.KnowledgeSoundnessTarget",
    "HegemonCrypto.AssuranceBoundary.every_cryptographic_obligation_remains_open",
    "HegemonCrypto.AssuranceBoundary.open_research_posture_cannot_authorize_production_security_claim",
]
listed = [line.strip() for line in open(sys.argv[2], encoding="utf-8") if line.strip()]
if listed != expected:
    raise SystemExit("credited declaration inventory differs from the reviewed fixed list")
observed = [record["theorem"] for record in records]
if observed != expected:
    raise SystemExit("axiom audit did not return the exact credited declaration list")
allowed = {"propext", "Classical.choice", "Quot.sound"}
violations = {
    record["theorem"]: sorted(set(record["axioms"]) - allowed)
    for record in records
    if set(record["axioms"]) - allowed
}
if violations:
    raise SystemExit(f"unapproved transitive axioms: {violations}")
print(f"audited {len(records)} formal-crypto declarations against the kernel axiom allowlist")
PY

printf 'formal-crypto sanity passed: ArkLib e6d77b18; 13 declarations; production claim remains unauthorized\n'
