#!/usr/bin/env bash
set -e

echo "build native node"
cargo build -p hegemon-node --release

echo "binary ready at: target/release/hegemon-node"
