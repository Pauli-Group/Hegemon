SHELL := /bin/bash
.PHONY: setup fmt lint test check bench wallet-demo quickstart node app-no-ssh-e2e swap-test swap-integration swap-hegemon-local

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

# Swap series test tiers (details and tool versions: docs/SWAP_TOOLCHAIN.md).
# Fast tier: Node 24 and the Python packages only. No network, chain tools or browser.
swap-test:
	./scripts/swap-tiers.sh fast

# Local chains and browsers. Prints SKIPPED for anything the host cannot run; SWAP_INTEGRATION_STRICT=1 fails on skips.
swap-integration:
	./scripts/swap-tiers.sh integration

# Opt in: engine swaps on a real local Hegemon chain (needs the development node and wallet binaries).
swap-hegemon-local:
	./scripts/swap-tiers.sh hegemon-local
