SHELL := /bin/bash
.PHONY: setup fmt lint test check bench wallet-demo quickstart node

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
	cargo run -p circuits-bench -- --smoke --prove --json
	cargo run -p wallet-bench -- --smoke --json
	( cd consensus/bench && go run ./cmd/netbench --smoke --json )

wallet-demo:
	./scripts/wallet-demo.sh --out wallet-demo-artifacts

# Build the native operator node binary.
node:
	cargo build -p hegemon-node --bin hegemon-node --no-default-features --release
