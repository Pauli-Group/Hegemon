SHELL := /bin/bash
.PHONY: setup fmt lint test check bench wallet-demo dashboard quickstart

setup:
	./scripts/dev-setup.sh

fmt:
	cargo fmt --all

lint:
	cargo clippy --workspace --all-targets --all-features -D warnings

test:
	cargo test --workspace

check: fmt lint test

bench:
	cargo run -p circuits-bench -- --smoke --prove --json
	cargo run -p wallet-bench -- --smoke --json
	( cd consensus/bench && go run ./cmd/netbench --smoke --json )

wallet-demo:
        ./scripts/wallet-demo.sh --out wallet-demo-artifacts

dashboard:
./scripts/dashboard.py

quickstart:
./scripts/dashboard.py --run quickstart
