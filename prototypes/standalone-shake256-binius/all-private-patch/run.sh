#!/bin/sh
set -eu

if [ "$#" -ne 1 ]; then
  echo "usage: $0 /path/to/binius64-at-3f961630" >&2
  exit 2
fi

SOURCE=$1
REVISION=3f96163049f680b2909f6545690bd929f1b48c44
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
WORK_DIR=$(mktemp -d /private/tmp/hegemon-all-private.XXXXXX)
TARGET_DIR=$(mktemp -d /private/tmp/hegemon-all-private-target.XXXXXX)

cleanup() {
  rm -rf "$WORK_DIR" "$TARGET_DIR"
}
trap cleanup EXIT INT TERM

test "$(git -C "$SOURCE" rev-parse HEAD)" = "$REVISION"
test -z "$(git -C "$SOURCE" status --porcelain)"
mkdir -p "$WORK_DIR/binius64"
git -C "$SOURCE" archive "$REVISION" | tar -x -C "$WORK_DIR/binius64"
git -C "$WORK_DIR/binius64" apply "$SCRIPT_DIR/binius64-all-private-inputs.patch"
cp -R "$SCRIPT_DIR/harness" "$WORK_DIR/binius64/hegemon-all-private-prototype"
cp -R "$SCRIPT_DIR/../../../circuits/standalone-shake256-prototype" \
  "$WORK_DIR/binius64/hegemon-standalone-shake256-prototype"
cp "$SCRIPT_DIR/../backend/src/lib.rs" \
  "$WORK_DIR/binius64/hegemon-all-private-prototype/src/relation.rs"

export CARGO_TARGET_DIR="$TARGET_DIR"
export CARGO_INCREMENTAL=0
export CARGO_PROFILE_DEV_DEBUG=0
export CARGO_PROFILE_TEST_DEBUG=0
export CARGO_PROFILE_RELEASE_DEBUG=0

df -h /private/tmp
cargo +1.97.1 test --release --manifest-path \
  "$WORK_DIR/binius64/hegemon-all-private-prototype/Cargo.toml"
cargo +1.97.1 run --release --quiet --manifest-path \
  "$WORK_DIR/binius64/hegemon-all-private-prototype/Cargo.toml" -- 1 3 chain
cargo +1.97.1 run --release --quiet --manifest-path \
  "$WORK_DIR/binius64/hegemon-all-private-prototype/Cargo.toml" -- 40 2 chain
cargo +1.97.1 run --release --quiet --manifest-path \
  "$WORK_DIR/binius64/hegemon-all-private-prototype/Cargo.toml" -- 40 3 chain
cargo +1.97.1 run --release --quiet --manifest-path \
  "$WORK_DIR/binius64/hegemon-all-private-prototype/Cargo.toml" -- 40 4 chain
cargo +1.97.1 run --release --quiet --manifest-path \
  "$WORK_DIR/binius64/hegemon-all-private-prototype/Cargo.toml" -- 40 3 independent
