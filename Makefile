SHELL := /bin/bash
.PHONY: setup fmt lint test check bench wallet-demo quickstart node node-fast

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

# Build the Substrate-based node binary
node:
	cargo build -p hegemon-node --features substrate --release

# Build the Substrate-based node binary with dev-fast proof acceptance enabled.
# This is for development only; do not ship production binaries with fast proofs enabled.
node-fast:
	cargo build -p hegemon-node --features substrate,fast-proofs --release
