#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CRYPTO_ROOT="$ROOT/formal/crypto"
if [ "$#" -gt 1 ]; then
  printf 'usage: %s [full|--isolation-only]\n' "$0" >&2
  exit 2
fi
MODE="${1:-full}"

if [ "$MODE" != "full" ] && [ "$MODE" != "--isolation-only" ]; then
  printf 'usage: %s [full|--isolation-only]\n' "$0" >&2
  exit 2
fi

WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/hegemon-formal-crypto.XXXXXX")"
trap 'rm -rf "$WORK_DIR"' EXIT

isolation_report="$WORK_DIR/isolation.txt"
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

expected_toolchain='leanprover/lean4:v4.32.2'
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
        "name": "mathlib",
        "git": "https://github.com/leanprover-community/mathlib4",
        "rev": "905b95818eb32af7874a58b427f50c1711a5e96c",
    },
]
if lake_config.get("require") != expected_requirements:
    raise SystemExit("lakefile.toml direct requirements differ from the reviewed dependency set")
PY

if [ ! -d "$CRYPTO_ROOT/.lake/packages" ]; then
  minimum_free_gib="${HEGEMON_FORMAL_CRYPTO_MIN_FREE_GIB:-8}"
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

bash "$ROOT/scripts/check_poseidon2_v8_relation_program_components_lean.sh"

forbidden_report="$WORK_DIR/forbidden.txt"
if find "$CRYPTO_ROOT" -path "$CRYPTO_ROOT/.lake" -prune -o -type f -name '*.lean' -print0 \
    | xargs -0 grep -nE \
      '\b(sorry|admit|unsafe|partial|opaque|extern|implemented_by|native_decide)\b|^[[:space:]]*((private|protected|noncomputable)[[:space:]]+)*axiom[[:space:]]' \
      > "$forbidden_report" 2>/dev/null; then
  printf 'formal cryptography sources contain forbidden trust bypasses:\n' >&2
  cat "$forbidden_report" >&2
  exit 1
fi

python3 - "$CRYPTO_ROOT/credited-declarations.txt" <<'PY'
import sys

declarations = [
    line.strip()
    for line in open(sys.argv[1], encoding="utf-8")
    if line.strip() and not line.lstrip().startswith("#")
]
if not declarations:
    raise SystemExit("credited declaration inventory is empty")
if len(declarations) != len(set(declarations)):
    raise SystemExit("credited declaration inventory contains duplicates")
PY

(
  cd "$CRYPTO_ROOT"
  manifest_sha256_before="$(python3 - "$CRYPTO_ROOT/lake-manifest.json" <<'PY'
import hashlib
import pathlib
import sys

print(hashlib.sha256(pathlib.Path(sys.argv[1]).read_bytes()).hexdigest())
PY
)"
  # Mathlib's pinned cache client is inherited by downstream Lake projects.
  # Use only the official upstream repo and its documented master,legacy chain;
  # the legacy container supplies master-built artifacts predating the write cutover.
  # Hard transfer/decompression failures must not fall through into a build.
  cache_status=0
  lake exe cache get --repo=leanprover-community/mathlib4 \
    --cache-from=master,legacy || cache_status=$?
  manifest_sha256_after="$(python3 - "$CRYPTO_ROOT/lake-manifest.json" <<'PY'
import hashlib
import pathlib
import sys

print(hashlib.sha256(pathlib.Path(sys.argv[1]).read_bytes()).hexdigest())
PY
)"
  if [ "$manifest_sha256_before" != "$manifest_sha256_after" ]; then
    printf 'Mathlib cache bootstrap changed the validated lake-manifest.json\n' >&2
    exit 1
  fi
  if [ "$cache_status" -ne 0 ]; then
    printf 'Mathlib precompiled cache fetch failed (exit %s); refusing HegemonCrypto build\n' \
      "$cache_status" >&2
    exit "$cache_status"
  fi
  python3 - "$CRYPTO_ROOT/.lake/packages/mathlib" <<'PY'
import pathlib
import sys

mathlib = pathlib.Path(sys.argv[1])
source_root = mathlib / "Mathlib"
olean_root = mathlib / ".lake/build/lib/lean/Mathlib"
sources = sorted(source_root.rglob("*.lean"))
if not sources:
    raise SystemExit(f"Mathlib source tree is empty: {source_root}")
missing = [
    str(source.relative_to(source_root))
    for source in sources
    if not (olean_root / source.relative_to(source_root).with_suffix(".olean")).is_file()
]
root_source = mathlib / "Mathlib.lean"
if root_source.is_file() and not (olean_root.parent / "Mathlib.olean").is_file():
    missing.append(root_source.name)
if missing:
    sample = ", ".join(missing[:10])
    raise SystemExit(
        f"Mathlib cache incomplete: {len(missing)} of {len(sources)} modules lack "
        f"compiled artifacts (for example: {sample}); refusing cold Mathlib build"
    )
compiled_count = len(sources) + int(root_source.is_file())
print(f"Mathlib cache ready: all {compiled_count} pinned modules are compiled")
PY
  lake build HegemonCrypto
  lake env lean --run HegemonCrypto/GenerateSmallWoodProofWireVectors.lean \
    > "$WORK_DIR/smallwood-proof-wire.json"
  lake env lean --run HegemonCrypto/GenerateSmallWoodSmz8ProofWireVectors.lean \
    > "$WORK_DIR/smallwood-smz8-proof-wire.json"
  lake env lean --run HegemonCrypto/GenerateSmallWoodSmz9ProofWireVectors.lean \
    > "$WORK_DIR/smallwood-smz9-proof-wire.json"
  lake env lean --run "$ROOT/scripts/lean_axiom_audit.lean" \
    "$CRYPTO_ROOT/credited-declarations.txt" HegemonCrypto > "$WORK_DIR/axioms.json"
)

if ! diff -u \
    "$ROOT/testdata/formal_crypto_vectors/smallwood_proof_wire.json" \
    "$WORK_DIR/smallwood-proof-wire.json"; then
  printf 'Lean-generated SmallWood proof-wire vectors are stale\n' >&2
  exit 1
fi

if ! diff -u \
    "$ROOT/testdata/formal_crypto_vectors/smallwood_smz8_proof_wire.json" \
    "$WORK_DIR/smallwood-smz8-proof-wire.json"; then
  printf 'Lean-generated SmallWood SMZ8 proof-wire vectors are stale\n' >&2
  exit 1
fi

if ! diff -u \
    "$ROOT/testdata/formal_crypto_vectors/smallwood_smz9_proof_wire.json" \
    "$WORK_DIR/smallwood-smz9-proof-wire.json"; then
  printf 'Lean-generated SmallWood SMZ9 proof-wire vectors are stale\n' >&2
  exit 1
fi

python3 - "$WORK_DIR/axioms.json" "$CRYPTO_ROOT/credited-declarations.txt" <<'PY'
import json
import sys

records = json.load(open(sys.argv[1], encoding="utf-8"))
expected = [
    line.strip()
    for line in open(sys.argv[2], encoding="utf-8")
    if line.strip() and not line.lstrip().startswith("#")
]
observed = [record["theorem"] for record in records]
if observed != expected:
    raise SystemExit("axiom audit did not return the credited declaration list in order")
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

printf 'formal-crypto sanity passed: selected CCS, canonical wire, extraction interfaces, finite-QRO semantics, BCS/QROM boundaries, masking proofs, native parser refinement, and compressed-relation lemmas checked; production security remains unauthorized\n'
