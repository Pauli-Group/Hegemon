#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: ./scripts/check-core.sh [lint|test|build|all]

lint   Run the default formatting and lint gate.
test   Run the default fast Rust test gate.
build  Build the release node binary.
all    Run lint, test, and build gates.
EOF
}

run_lint() {
  cargo fmt --all -- --check
  cargo clippy \
    -p hegemon-node \
    -p protocol-kernel \
    -p protocol-shielded-pool \
    -p wallet \
    -p network \
    -p consensus \
    -p consensus-light-client \
    -p synthetic-crypto \
    -p transaction-circuit \
    -p block-circuit \
    -p disclosure-circuit \
    -p cashvm-bridge \
    --all-targets -- -D warnings
  cargo clippy \
    -p superneo-backend-lattice \
    -p superneo-hegemon \
    -p superneo-bench \
    -p native-backend-ref \
    -p native-backend-timing \
    --all-targets -- -D warnings
}

run_test() {
  export PROPTEST_MAX_CASES="${PROPTEST_MAX_CASES:-64}"

  cargo test -p synthetic-crypto
  cargo test -p consensus-light-client
  cargo test -p consensus
  cargo test -p transaction-circuit
  cargo test -p block-circuit
  cargo test -p disclosure-circuit
  cargo test -p network
  cargo test -p protocol-kernel
  cargo test -p protocol-shielded-pool
  cargo test -p wallet
  cargo test -p cashvm-bridge
  cargo test -p hegemon-node --lib
  cargo test -p hegemon-node --lib --no-default-features
  cargo test --test security_pipeline -- --nocapture
}

run_build() {
  cargo build -p hegemon-node --bin hegemon-node --no-default-features --release
}

case "${1:-all}" in
  lint)
    run_lint
    ;;
  test)
    run_test
    ;;
  build)
    run_build
    ;;
  all)
    run_lint
    run_test
    run_build
    ;;
  *)
    usage >&2
    exit 1
    ;;
esac
