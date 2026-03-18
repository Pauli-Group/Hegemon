SHELL := /bin/bash
.PHONY: setup fmt lint test check bench wallet-demo quickstart node node-fast check-deps

# macOS: librocksdb-sys requires libclang.dylib at runtime during build
# Set these environment variables for the build to find clang libraries
UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Darwin)
  # Check for Command Line Tools first, then Xcode.app
  ifneq ($(wildcard /Library/Developer/CommandLineTools/usr/lib/libclang.dylib),)
    export LIBCLANG_PATH := /Library/Developer/CommandLineTools/usr/lib
    export DYLD_LIBRARY_PATH := /Library/Developer/CommandLineTools/usr/lib:$(DYLD_LIBRARY_PATH)
  else ifneq ($(wildcard /Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/lib/libclang.dylib),)
    export LIBCLANG_PATH := /Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/lib
    export DYLD_LIBRARY_PATH := /Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/lib:$(DYLD_LIBRARY_PATH)
  endif
endif

setup:
	./scripts/dev-setup.sh

fmt:
	cargo fmt --all

lint:
	cargo clippy --workspace --all-targets --all-features -- -D warnings

test:
	cargo test --workspace

check: fmt lint test

bench:
	cargo run -p circuits-bench -- --smoke --prove --json
	cargo run -p wallet-bench -- --smoke --json
	( cd consensus/bench && go run ./cmd/netbench --smoke --json )

wallet-demo:
	./scripts/wallet-demo.sh --out wallet-demo-artifacts

# Verify all required build tools are available before compiling.
# Source cargo env and add common tool paths so check works in non-interactive shells.
check-deps:
	@export PATH="$$HOME/.cargo/bin:$$HOME/.local/go/bin:$$HOME/.local/node/bin:$$PATH"; \
	[ -f "$$HOME/.cargo/env" ] && . "$$HOME/.cargo/env"; \
	missing=""; \
	for cmd in cargo rustup go node protoc; do \
		command -v $$cmd >/dev/null 2>&1 || missing="$$missing $$cmd"; \
	done; \
	if [ -n "$$missing" ]; then \
		echo "error: missing required tools:$$missing" >&2; \
		echo "Run 'make setup' to install them." >&2; \
		exit 1; \
	fi; \
	if ! rustup target list --installed 2>/dev/null | grep -q wasm32-unknown-unknown; then \
		echo "error: missing rustup target wasm32-unknown-unknown" >&2; \
		echo "Run 'make setup' to install it." >&2; \
		exit 1; \
	fi; \
	echo "All build dependencies present."

# Build the Substrate-based node binary
node: check-deps
	cargo build -p hegemon-node --features substrate --release

# Build the Substrate-based node binary with dev-fast proof acceptance enabled.
# This is for development only; do not ship production binaries with fast proofs enabled.
node-fast: check-deps
	cargo build -p hegemon-node --features substrate,fast-proofs --release
