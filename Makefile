SHELL := /bin/bash
.PHONY: setup fmt lint test check bench wallet-demo quickstart node app-no-ssh-e2e htlc-swap-e2e

setup:
	./scripts/dev-setup.sh

fmt:
	cargo fmt --all

lint:
	./scripts/check-core.sh lint

test:
	./scripts/check-core.sh test

check:
	./scripts/check-core.sh all

bench:
	cargo test -p transaction-circuit compressed_level5_radix2_roundtrip_benchmark --release -- --ignored --nocapture
	cargo run -p wallet-bench -- --smoke --json
	( cd consensus/bench && go run ./cmd/netbench --smoke --json )

wallet-demo:
	./scripts/wallet-demo.sh --out wallet-demo-artifacts

# Build the native operator node binary.
node:
	cargo build -p hegemon-node --bin hegemon-node --no-default-features --release

app-no-ssh-e2e:
	./scripts/check-app-no-ssh-e2e.sh

# Fresh local Development chain and Bitcoin Core regtest HTLC scenarios.
# This grants no production authority. The node uses an empty seed list.
htlc-swap-e2e:
	python3 scripts/local_htlc_swap_e2e.py --scenario all
