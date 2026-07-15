#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

for package in hegemon-node wallet walletd; do
  tree="$(cd "$ROOT" && cargo tree --locked -p "$package" --target all --edges normal,build --prefix none)"
  if grep -Eiq '(^|[[:space:]])p3-|plonky3' <<<"$tree"; then
    printf '%s normal/build dependency graph contains a retired proof package:\n' "$package" >&2
    grep -Ein '(^|[[:space:]])p3-|plonky3' <<<"$tree" >&2
    exit 1
  fi
done

printf 'native runtime dependency gate passed: no Plonky3 package in hegemon-node, wallet, or walletd normal/build graphs for any target\n'
