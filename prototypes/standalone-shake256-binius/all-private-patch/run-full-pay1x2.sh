#!/bin/sh
set -eu

if [ "$#" -ne 1 ]; then
  echo "usage: $0 /path/to/binius64-at-3f961630" >&2
  exit 2
fi

SOURCE_BINIUS=$1
REVISION=3f96163049f680b2909f6545690bd929f1b48c44
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
HEGEMON_ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/../../.." && pwd)
WORK_DIR=$(mktemp -d /private/tmp/hegemon-full-all-private-src.XXXXXX)
TARGET_DIR=$(mktemp -d /private/tmp/hegemon-full-all-private-target.XXXXXX)

cleanup() {
  rm -rf "$WORK_DIR" "$TARGET_DIR"
}
trap cleanup EXIT INT TERM

guard_sha256() {
  expected=$1
  path=$2
  actual=$(shasum -a 256 "$path" | awk '{print $1}')
  if [ "$actual" != "$expected" ]; then
    echo "source hash mismatch: $path" >&2
    exit 1
  fi
}

require_reserve() {
  free_kib=$(df -Pk /private/tmp | awk 'NR == 2 { print $4 }')
  if [ "$free_kib" -lt 16777216 ]; then
    echo "refusing to continue below the 16 GiB free-space reserve" >&2
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
}

PAY1X2_SOURCE="$HEGEMON_ROOT/prototypes/standalone-shake256-binius/pay1x2-backend"
guard_sha256 5a16d82ab9b4092356a5a255f31e108639e21524beb368c76977be7b48230804 "$PAY1X2_SOURCE/Cargo.toml"
guard_sha256 f580927ac4ef7222569b883f6d001382791bb2d1db8461fd73044680ac6eb1f5 "$PAY1X2_SOURCE/Cargo.lock"
guard_sha256 a8fcd0193698f37bea4a297750f66bc9f862f132bbabaf58107f2893a6315d5d "$PAY1X2_SOURCE/src/lib.rs"
guard_sha256 873dc3ea57c6517da262a4032194a6d0a66357bcce930d881425596d70039366 "$PAY1X2_SOURCE/src/main.rs"

# Guard the source-bearing local dependency closure used by the frozen crate.
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
guard_sha256 13eb638f0dcd5264d12ac83ca30efc49e0ed994066c6bd7dc94f6c389041e05d "$SCRIPT_DIR/binius64-all-private-inputs.patch"
guard_sha256 621b56131c17c48b8d301d8725c882620474ba786dce6f10f397baa7d968b83e "$SCRIPT_DIR/pay1x2-all-private-layout.patch"

test "$(git -C "$SOURCE_BINIUS" rev-parse HEAD)" = "$REVISION"
test -z "$(git -C "$SOURCE_BINIUS" status --porcelain)"
require_reserve

PROTOTYPES="$WORK_DIR/hegemon/prototypes/standalone-shake256-binius"
CIRCUITS="$WORK_DIR/hegemon/circuits"
mkdir -p "$PROTOTYPES/binius64" "$CIRCUITS"
copy_crate "$PAY1X2_SOURCE" "$PROTOTYPES/pay1x2-backend"
copy_crate "$HEGEMON_ROOT/prototypes/standalone-shake256-binius/backend" "$PROTOTYPES/backend"
copy_crate "$HEGEMON_ROOT/circuits/standalone-pay1x2-relation-prototype" "$CIRCUITS/standalone-pay1x2-relation-prototype"
copy_crate "$HEGEMON_ROOT/circuits/standalone-pay1x2-statement-prototype" "$CIRCUITS/standalone-pay1x2-statement-prototype"
copy_crate "$HEGEMON_ROOT/circuits/standalone-shake256-prototype" "$CIRCUITS/standalone-shake256-prototype"
copy_crate "$HEGEMON_ROOT/circuits/standalone-proof-envelope-prototype" "$CIRCUITS/standalone-proof-envelope-prototype"
git -C "$SOURCE_BINIUS" archive "$REVISION" | tar -x -C "$PROTOTYPES/binius64"
git -C "$PROTOTYPES/binius64" apply "$SCRIPT_DIR/binius64-all-private-inputs.patch"
git -C "$PROTOTYPES/pay1x2-backend" apply "$SCRIPT_DIR/pay1x2-all-private-layout.patch"

export CARGO_TARGET_DIR="$TARGET_DIR"
export CARGO_INCREMENTAL=0
export CARGO_PROFILE_DEV_DEBUG=0
export CARGO_PROFILE_TEST_DEBUG=0
export CARGO_PROFILE_RELEASE_DEBUG=0
MANIFEST="$PROTOTYPES/pay1x2-backend/Cargo.toml"
cargo +1.97.1 test --release --offline --manifest-path "$MANIFEST"
cargo +1.97.1 build --release --offline --manifest-path "$MANIFEST"
require_reserve

BACKEND="$TARGET_DIR/release/hegemon-standalone-shake256-pay1x2-binius-backend"
SWEEP_JSON="$WORK_DIR/full-pay1x2-all-private-sweep.json"
"$BACKEND" --rate 2 --rate 3 --rate 4 --deterministic-test > "$SWEEP_JSON"
python3 -m json.tool "$SWEEP_JSON" >/dev/null
cat "$SWEEP_JSON"

require_reserve
python3 "$HEGEMON_ROOT/scripts/measure_standalone_shake256_prototype.py" \
  --min-free-gib 16 --allow-unsupported-prototype -- \
  "$BACKEND" --rate 3 --deterministic-test
require_reserve
