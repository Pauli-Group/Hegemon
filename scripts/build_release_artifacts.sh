#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TARGET_TRIPLE=""
MANIFEST=""

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --target)
      TARGET_TRIPLE="${2:?--target requires a Rust target triple}"
      shift 2
      ;;
    --manifest)
      MANIFEST="${2:?--manifest requires a path}"
      shift 2
      ;;
    -h|--help)
      echo "usage: scripts/build_release_artifacts.sh [--target TRIPLE] [--manifest PATH]"
      exit 0
      ;;
    *)
      echo "unknown option: $1" >&2
      exit 2
      ;;
  esac
done

HOST_TRIPLE="$(rustc -vV | sed -n 's/^host: //p')"
if [[ -z "$HOST_TRIPLE" ]]; then
  echo "could not determine rustc host triple" >&2
  exit 1
fi

RELEASE_DIR="$ROOT/target/release"
MANIFEST_TARGET="$HOST_TRIPLE"
if [[ -n "$TARGET_TRIPLE" ]]; then
  RELEASE_DIR="$ROOT/target/$TARGET_TRIPLE/release"
  MANIFEST_TARGET="$TARGET_TRIPLE"
fi

EXE_SUFFIX=""
if [[ "$MANIFEST_TARGET" == *windows* ]]; then
  EXE_SUFFIX=".exe"
fi
if [[ -z "$MANIFEST" ]]; then
  MANIFEST="$RELEASE_DIR/hegemon-release-artifacts.json"
elif [[ "$MANIFEST" != /* ]]; then
  MANIFEST="$ROOT/$MANIFEST"
fi

cd "$ROOT"
build_release() {
  if [[ -n "$TARGET_TRIPLE" ]]; then
    CARGO_INCREMENTAL=0 cargo build --locked --release "$@" --target "$TARGET_TRIPLE"
  else
    CARGO_INCREMENTAL=0 cargo build --locked --release "$@"
  fi
}

build_release -p hegemon-node --bin hegemon-node --no-default-features
build_release -p wallet --bin wallet
build_release -p walletd --bin walletd

NODE_BIN="$RELEASE_DIR/hegemon-node$EXE_SUFFIX"
WALLET_BIN="$RELEASE_DIR/wallet$EXE_SUFFIX"
WALLETD_BIN="$RELEASE_DIR/walletd$EXE_SUFFIX"

python3 "$ROOT/scripts/release_artifact_manifest.py" create \
  --output "$MANIFEST" \
  --target-triple "$MANIFEST_TARGET" \
  --artifact "hegemon-node:hegemon-node:$NODE_BIN" \
  --artifact "wallet:wallet:$WALLET_BIN" \
  --artifact "walletd:walletd:$WALLETD_BIN" \
  >/dev/null
python3 "$ROOT/scripts/release_artifact_manifest.py" verify \
  --manifest "$MANIFEST" \
  --expect "hegemon-node:hegemon-node:$NODE_BIN" \
  --expect "wallet:wallet:$WALLET_BIN" \
  --expect "walletd:walletd:$WALLETD_BIN" \
  >/dev/null

printf '%s\n' "$MANIFEST"
