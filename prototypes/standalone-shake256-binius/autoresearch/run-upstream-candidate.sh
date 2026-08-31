#!/bin/sh
set -eu

if [ "$#" -lt 2 ] || [ "$#" -gt 3 ]; then
  echo "usage: $0 /path/to/binius64-at-3f961630 candidate.patch|- [orchestrate|prepare]" >&2
  exit 2
fi

if [ -z "${HEGEMON_AUTORESEARCH_RUN_DIR:-}" ]; then
  echo "HEGEMON_AUTORESEARCH_RUN_DIR must be set by autoresearch.py" >&2
  exit 2
fi

SOURCE_BINIUS=$1
CANDIDATE_PATCH=$2
PHASE=${3:-orchestrate}
REVISION=3f96163049f680b2909f6545690bd929f1b48c44
SCRIPT_DIR=${HEGEMON_AUTORESEARCH_EVALUATOR_DIR:-$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)}
HEGEMON_ROOT=${HEGEMON_AUTORESEARCH_ROOT:-$(CDPATH= cd -- "$SCRIPT_DIR/../../.." && pwd)}
BASELINE_DIR="$SCRIPT_DIR/../all-private-patch"
RUN_DIR=$HEGEMON_AUTORESEARCH_RUN_DIR
WORK_DIR="$RUN_DIR/src"
TARGET_DIR="$RUN_DIR/target"
TMP_DIR="$RUN_DIR/tmp"

umask 077
# The controller applies non-raiseable core, file-size, process, and CPU limits
# before this orchestrator starts. Reapplying setrlimit from inside Seatbelt is
# redundant and is denied on macOS.

guard_sha256() {
  expected=$1
  path=$2
  actual=$(shasum -a 256 "$path" | awk '{print $1}')
  if [ "$actual" != "$expected" ]; then
    echo "immutable evaluator source hash mismatch: $path" >&2
    exit 1
  fi
}

require_hard_reserve() {
  free_kib=$(df -Pk "$RUN_DIR" | awk 'NR == 2 { print $4 }')
  if [ "$free_kib" -lt 20971520 ]; then
    echo "refusing to continue below the non-lowerable 20 GiB reserve" >&2
    exit 1
  fi
}

copy_crate() {
  source_dir=$1
  destination_dir=$2
  mkdir -p "$destination_dir"
  cp "$source_dir/Cargo.toml" "$destination_dir/Cargo.toml"
  if [ -f "$source_dir/Cargo.lock" ]; then
    cp "$source_dir/Cargo.lock" "$destination_dir/Cargo.lock"
  fi
  cp -R "$source_dir/src" "$destination_dir/src"
  if [ -d "$source_dir/tests" ]; then
    cp -R "$source_dir/tests" "$destination_dir/tests"
  fi
}

PAY1X2_SOURCE="$HEGEMON_ROOT/prototypes/standalone-shake256-binius/pay1x2-backend"
PROTOTYPES="$WORK_DIR/hegemon/prototypes/standalone-shake256-binius"
CIRCUITS="$WORK_DIR/hegemon/circuits"

if [ "$PHASE" = prepare ]; then
mkdir -p "$WORK_DIR" "$TARGET_DIR" "$TMP_DIR"

# This closure is outside candidate control. Candidate patches apply only to
# the disposable pinned Binius source after the baseline private-input patch.
guard_sha256 5a16d82ab9b4092356a5a255f31e108639e21524beb368c76977be7b48230804 "$PAY1X2_SOURCE/Cargo.toml"
guard_sha256 f580927ac4ef7222569b883f6d001382791bb2d1db8461fd73044680ac6eb1f5 "$PAY1X2_SOURCE/Cargo.lock"
guard_sha256 a8fcd0193698f37bea4a297750f66bc9f862f132bbabaf58107f2893a6315d5d "$PAY1X2_SOURCE/src/lib.rs"
guard_sha256 873dc3ea57c6517da262a4032194a6d0a66357bcce930d881425596d70039366 "$PAY1X2_SOURCE/src/main.rs"
guard_sha256 d5a5901d7a10b4416965ad98c30ba1611b687066b4586af81513880fbdc8fbc2 "$HEGEMON_ROOT/prototypes/standalone-shake256-binius/backend/Cargo.toml"
guard_sha256 f675fe956858e55ad16b059f72e336727e717e03a322c32ecfccc6c156b7fa1e "$HEGEMON_ROOT/prototypes/standalone-shake256-binius/backend/src/lib.rs"
guard_sha256 0d80ea3bbd81783e92b8e00268b6ff5fc5c93aec7388d43dcd77eec3a2533f69 "$HEGEMON_ROOT/circuits/standalone-pay1x2-relation-prototype/Cargo.toml"
guard_sha256 5185ab77a94f48932b53665cdeb7e956f1f8c5dae19470336c18543261f0d6f5 "$HEGEMON_ROOT/circuits/standalone-pay1x2-relation-prototype/src/lib.rs"
guard_sha256 8032a14f95fa96fd73741dc4b33abe6d1076cb71f56b7aeb7d14c35e7361b215 "$HEGEMON_ROOT/circuits/standalone-pay1x2-statement-prototype/Cargo.toml"
guard_sha256 c4663e965128019591730068c369e301f578815d11295cad46cc389e9d1d2001 "$HEGEMON_ROOT/circuits/standalone-pay1x2-statement-prototype/src/lib.rs"
guard_sha256 9cbdb905cbd63d4fdb84d11ff7765bd84a1c13b5cc0b930ab196299cb8c0c522 "$HEGEMON_ROOT/circuits/standalone-pay1x2-statement-prototype/src/action.rs"
guard_sha256 7a5833deb0316b57a48a037851b6d4f2409db5968b43335b49c119c19335e1e0 "$HEGEMON_ROOT/circuits/standalone-shake256-prototype/Cargo.toml"
guard_sha256 83daaf05bd08d2de1b499fd12ac719c97d509479ef6db4c4abc782552ba48f75 "$HEGEMON_ROOT/circuits/standalone-shake256-prototype/src/lib.rs"
guard_sha256 43f46fc090ef042adeb0321e3772dd1e4c3c00a7cc2d40df451647430e42cdf3 "$HEGEMON_ROOT/circuits/standalone-proof-envelope-prototype/Cargo.toml"
guard_sha256 16521454025761e60b40eb5e5a6b0d6c584665bd8b8007f5b4f40a68e81bcbe4 "$HEGEMON_ROOT/circuits/standalone-proof-envelope-prototype/src/lib.rs"
guard_sha256 016ec679b3bdb80f03156471a83ce098375afad1bf605adb9893151faa510d82 "$HEGEMON_ROOT/scripts/measure_standalone_shake256_prototype.py"
guard_sha256 13eb638f0dcd5264d12ac83ca30efc49e0ed994066c6bd7dc94f6c389041e05d "$BASELINE_DIR/binius64-all-private-inputs.patch"
guard_sha256 621b56131c17c48b8d301d8725c882620474ba786dce6f10f397baa7d968b83e "$BASELINE_DIR/pay1x2-all-private-layout.patch"

test "$(git -C "$SOURCE_BINIUS" rev-parse HEAD)" = "$REVISION"
test -z "$(git -C "$SOURCE_BINIUS" status --porcelain)"
require_hard_reserve

mkdir -p "$PROTOTYPES/binius64" "$CIRCUITS"
copy_crate "$PAY1X2_SOURCE" "$PROTOTYPES/pay1x2-backend"
copy_crate "$HEGEMON_ROOT/prototypes/standalone-shake256-binius/backend" "$PROTOTYPES/backend"
copy_crate "$HEGEMON_ROOT/circuits/standalone-pay1x2-relation-prototype" "$CIRCUITS/standalone-pay1x2-relation-prototype"
copy_crate "$HEGEMON_ROOT/circuits/standalone-pay1x2-statement-prototype" "$CIRCUITS/standalone-pay1x2-statement-prototype"
copy_crate "$HEGEMON_ROOT/circuits/standalone-shake256-prototype" "$CIRCUITS/standalone-shake256-prototype"
copy_crate "$HEGEMON_ROOT/circuits/standalone-proof-envelope-prototype" "$CIRCUITS/standalone-proof-envelope-prototype"
git -C "$SOURCE_BINIUS" archive "$REVISION" | tar -x -C "$PROTOTYPES/binius64"
git -C "$PROTOTYPES/binius64" apply --check --whitespace=error "$BASELINE_DIR/binius64-all-private-inputs.patch"
git -C "$PROTOTYPES/binius64" apply --whitespace=error "$BASELINE_DIR/binius64-all-private-inputs.patch"

# Establish a disposable baseline index after the fixed private-input patch.
# Staging is sufficient: the candidate remains an unstaged worktree delta from
# this index. Avoiding a synthetic commit also avoids Git's session-management
# path inside the preparation sandbox.
git -C "$PROTOTYPES/binius64" init -q
git -C "$PROTOTYPES/binius64" add -A

if [ "$CANDIDATE_PATCH" != "-" ]; then
  git -C "$PROTOTYPES/binius64" apply --check --whitespace=error "$CANDIDATE_PATCH"
  git -C "$PROTOTYPES/binius64" apply --whitespace=error "$CANDIDATE_PATCH"
  changed_count=0
  tab=$(printf '\t')
  changed_list="$TMP_DIR/candidate-changes.tsv"
  git -C "$PROTOTYPES/binius64" diff --name-status --no-renames > "$changed_list"
  while IFS="$tab" read -r change_status changed_path; do
    [ -n "$changed_path" ] || continue
    changed_count=$((changed_count + 1))
    if [ "$change_status" != "M" ]; then
      echo "candidate produced a non-modification tree change: $change_status $changed_path" >&2
      exit 1
    fi
    case "$changed_path" in
      crates/*/src/*.rs) ;;
      *)
        echo "candidate changed a path outside existing crate Rust sources: $changed_path" >&2
        exit 1
        ;;
    esac
    case "$changed_path" in
      */tests/*|*/tests.rs|*_test.rs)
        echo "candidate changed a test source: $changed_path" >&2
        exit 1
        ;;
    esac
    if [ ! -f "$PROTOTYPES/binius64/$changed_path" ] || [ -L "$PROTOTYPES/binius64/$changed_path" ]; then
      echo "candidate changed a non-regular source: $changed_path" >&2
      exit 1
    fi
  done < "$changed_list"
  if [ "$changed_count" -eq 0 ]; then
    echo "candidate patch produced no source changes" >&2
    exit 1
  fi
  if [ -n "$(git -C "$PROTOTYPES/binius64" ls-files --others --exclude-standard)" ]; then
    echo "candidate created untracked files" >&2
    exit 1
  fi
  git -C "$PROTOTYPES/binius64" diff --check
fi

git -C "$PROTOTYPES/pay1x2-backend" apply --check --whitespace=error "$BASELINE_DIR/pay1x2-all-private-layout.patch"
git -C "$PROTOTYPES/pay1x2-backend" apply --whitespace=error "$BASELINE_DIR/pay1x2-all-private-layout.patch"

# The fixed local-source patch intentionally changes Cargo's source graph.
# Resolve that graph once, offline, before the source closure becomes
# read-only. All compilation below then uses --locked against this exact file.
CARGO_NET_OFFLINE=true cargo +1.97.1 generate-lockfile --offline \
  --manifest-path "$PROTOTYPES/pay1x2-backend/Cargo.toml"

# Candidate code is not executed during preparation. Before any Cargo command,
# remove discretionary write bits from the complete source closure. The trusted
# orchestrator launches the compile phase as a sibling Seatbelt job after this
# preparation process exits, avoiding nested-profile fork failures.
chmod -R a-w "$WORK_DIR"
exit 0
fi

if [ "$PHASE" != orchestrate ]; then
  echo "unknown autoresearch runner phase: $PHASE" >&2
  exit 2
fi

# Keep the trusted orchestrator outside every Seatbelt profile. Preparation,
# each compile command, and each candidate-linked runtime are direct sibling
# jobs. This avoids profile intersection and lets the controller's single PGID
# supervise every phase.
export HEGEMON_AUTORESEARCH_EVALUATOR_DIR=$SCRIPT_DIR
export HEGEMON_AUTORESEARCH_ROOT=$HEGEMON_ROOT
/usr/bin/sandbox-exec \
  -D "WRITE_A=$WORK_DIR" \
  -D "WRITE_B=$TARGET_DIR" \
  -D "WRITE_C=$TMP_DIR" \
  -D "WRITE_D=$RUN_DIR/outputs" \
  -D "WRITE_E=$RUN_DIR/home" \
  -D "WRITE_F=$RUN_DIR/cargo-home" \
  -D "MARKER=$RUN_DIR/.hegemon-proof-autoresearch-owner.json" \
  -f "$SCRIPT_DIR/sandbox.sb" \
  /bin/sh "$0" "$SOURCE_BINIUS" "$CANDIDATE_PATCH" prepare

test -d "$WORK_DIR"
test -d "$PROTOTYPES/binius64"
if [ -w "$WORK_DIR" ]; then
  echo "prepared source closure unexpectedly remains writable" >&2
  exit 1
fi

export CARGO_TARGET_DIR="$TARGET_DIR"
export TMPDIR="$TMP_DIR"
export CARGO_NET_OFFLINE=true
export CARGO_INCREMENTAL=0
export CARGO_PROFILE_DEV_DEBUG=0
export CARGO_PROFILE_TEST_DEBUG=0
export CARGO_PROFILE_RELEASE_DEBUG=0
export CARGO_BUILD_JOBS=${CARGO_BUILD_JOBS:-4}
export RUSTFLAGS=${RUSTFLAGS:--Ctarget-cpu=native}
export SDKROOT=/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk
MANIFEST="$PROTOTYPES/pay1x2-backend/Cargo.toml"
RUNTIME_PROFILE="$SCRIPT_DIR/runtime.sb"
TEST_ARTIFACTS="$RUN_DIR/outputs/test-artifacts.jsonl"
HOST_USER_ROOT=$(dirname "$(dirname "${HEGEMON_AUTORESEARCH_HOST_CARGO_BIN:?}")")

compile_sandbox() {
  /usr/bin/sandbox-exec \
    -D "RUN_DIR=$RUN_DIR" \
    -D "RUN_PARENT=$(dirname "$RUN_DIR")" \
    -D "USER_ROOT=$HOST_USER_ROOT" \
    -D "CARGO_PARENT=$(dirname "${HEGEMON_AUTORESEARCH_HOST_CARGO_BIN:?}")" \
    -D "EVALUATOR_DIR=$SCRIPT_DIR" \
    -D "MEASURE_SCRIPT=$HEGEMON_ROOT/scripts/measure_standalone_shake256_prototype.py" \
    -D "CARGO_BIN=${HEGEMON_AUTORESEARCH_HOST_CARGO_BIN:?}" \
    -D "CARGO_REGISTRY=${HEGEMON_AUTORESEARCH_HOST_CARGO_REGISTRY:?}" \
    -D "CARGO_GIT=${HEGEMON_AUTORESEARCH_HOST_CARGO_GIT:?}" \
    -D "RUSTUP_ROOT=${RUSTUP_HOME:?}" \
    -D "TARGET_DIR=$TARGET_DIR" \
    -D "TMP_DIR=$TMP_DIR" \
    -D "HOME_DIR=$RUN_DIR/home" \
    -D "CARGO_HOME=$RUN_DIR/cargo-home" \
    -D "LOGS_DIR=$RUN_DIR/logs" \
    -D "MARKER=$RUN_DIR/.hegemon-proof-autoresearch-owner.json" \
    -f "$SCRIPT_DIR/compile.sb" \
    "$@"
}

assert_phase_quiescent() {
  python3 -c '
import os, subprocess, sys
pgid = os.getpgrp()
probe = subprocess.Popen(["/bin/ps", "-axo", "pid=,pgid=,command="], stdout=subprocess.PIPE, text=True)
stdout, _ = probe.communicate(timeout=5)
allowed = {os.getpid(), os.getppid(), probe.pid}
unexpected = []
for line in stdout.splitlines():
    fields = line.strip().split(None, 2)
    if len(fields) >= 2 and fields[0].isdigit() and fields[1].isdigit():
        pid, row_pgid = map(int, fields[:2])
        if row_pgid == pgid and pid not in allowed:
            unexpected.append(line.strip())
if probe.returncode != 0 or unexpected:
    print("compile phase left a live process in the candidate PGID: " + repr(unexpected), file=sys.stderr)
    raise SystemExit(1)
'
}

run_candidate_binary() {
  candidate_executable=$1
  shift
  cd "$TMP_DIR"
  /usr/bin/sandbox-exec \
    -D "TMP_DIR=$TMP_DIR" \
    -D "TARGET_DIR=$TARGET_DIR" \
    -D "EXECUTABLE=$candidate_executable" \
    -D "MARKER=$RUN_DIR/.hegemon-proof-autoresearch-owner.json" \
    -f "$RUNTIME_PROFILE" \
    "$candidate_executable" "$@"
  cd "$RUN_DIR"
}

compile_sandbox cargo +1.97.1 test --release --locked --offline --no-run \
  --lib --bins --tests --message-format=json-render-diagnostics \
  --manifest-path "$MANIFEST" > "$TEST_ARTIFACTS"
assert_phase_quiescent

if ! TEST_BINARIES=$(python3 -c '
import json, pathlib, sys
report = pathlib.Path(sys.argv[1])
target = pathlib.Path(sys.argv[2]).resolve()
seen = set()
for raw in report.read_text(encoding="utf-8").splitlines():
    row = json.loads(raw)
    executable = row.get("executable")
    profile = row.get("profile") or {}
    if not executable or profile.get("test") is not True:
        continue
    path = pathlib.Path(executable).resolve()
    if target not in path.parents or not path.is_file() or path.is_symlink():
        raise SystemExit("test executable escaped the owned target")
    if not path.name.startswith("hegemon_standalone_shake256_pay1x2_binius_backend-"):
        raise SystemExit("unexpected test executable name")
    seen.add(str(path))
if len(seen) != 2:
    raise SystemExit(f"Cargo emitted {len(seen)} test executables; expected exactly 2")
print("\n".join(sorted(seen)))
' "$TEST_ARTIFACTS" "$TARGET_DIR"); then
  echo "failed to enumerate the exact fixed test executables" >&2
  exit 1
fi
[ -n "$TEST_BINARIES" ] || { echo "empty test executable set" >&2; exit 1; }
printf '%s\n' "$TEST_BINARIES" |
while IFS= read -r test_binary; do
  run_candidate_binary "$test_binary" --test-threads=1
done
compile_sandbox cargo +1.97.1 build --release --locked --offline --manifest-path "$MANIFEST"
assert_phase_quiescent
require_hard_reserve

BACKEND="$TARGET_DIR/release/hegemon-standalone-shake256-pay1x2-binius-backend"
if [ ! -f "$BACKEND" ] || [ -L "$BACKEND" ] || [ ! -x "$BACKEND" ]; then
  echo "compiled backend is not an owned regular executable" >&2
  exit 1
fi
SWEEP_JSON="$RUN_DIR/outputs/full-pay1x2-candidate-sweep.json"
mkdir -p "$RUN_DIR/outputs"
run_candidate_binary "$BACKEND" --rate 1 --rate 2 --rate 3 --rate 4 --deterministic-test > "$SWEEP_JSON"
python3 -m json.tool "$SWEEP_JSON" >/dev/null
BEST_RATE=$(python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); print(min(d["rate_sweep"], key=lambda r: (r["canonical_proof_bytes"], r["verify_ms"], r["prove_ms"]))["log_inverse_rate"])' "$SWEEP_JSON")

require_hard_reserve
BEST_JSON="$RUN_DIR/outputs/full-pay1x2-candidate-best.json"
run_candidate_binary "$BACKEND" --rate "$BEST_RATE" --deterministic-test > "$BEST_JSON"
python3 -m json.tool "$BEST_JSON" >/dev/null
python3 "$HEGEMON_ROOT/scripts/measure_standalone_shake256_prototype.py" \
  --min-free-gib 20 --allow-unsupported-prototype --backend-json "$BEST_JSON"
require_hard_reserve
