#!/usr/bin/env bash
set -e

echo "build dashboard"
./scripts/build_dashboard.sh

echo "build substrate node"
cargo build -p hegemon-node --features substrate --release

echo "binary ready at: target/release/hegemon-node"
