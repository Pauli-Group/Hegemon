SHELL := /bin/bash
.PHONY: setup fmt lint test check bench wallet-demo quickstart node node-fast

# macOS: librocksdb-sys requires libclang.dylib at runtime during build.
# We still export the library path for make-driven builds, and the helper script
# below also installs a persistent fallback at ~/lib/libclang.dylib so later
# direct cargo invocations work without extra shell setup.
UNAME_S := $(shell uname -s)
MACOS_LIBCLANG_HELPER := ./scripts/ensure-macos-libclang.sh
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
	$(MACOS_LIBCLANG_HELPER)
	./scripts/dev-setup.sh

fmt:
	cargo fmt --all

lint:
	$(MACOS_LIBCLANG_HELPER)
	./scripts/check-core.sh lint

test:
	$(MACOS_LIBCLANG_HELPER)
	./scripts/check-core.sh test

check:
	$(MACOS_LIBCLANG_HELPER)
	./scripts/check-core.sh all

bench:
	$(MACOS_LIBCLANG_HELPER)
	cargo run -p circuits-bench -- --smoke --prove --json
	cargo run -p wallet-bench -- --smoke --json
	( cd consensus/bench && go run ./cmd/netbench --smoke --json )

wallet-demo:
	./scripts/wallet-demo.sh --out wallet-demo-artifacts

# Build the Substrate-based node binary
node:
	$(MACOS_LIBCLANG_HELPER)
	cargo build -p hegemon-node --features substrate --release

# Build the Substrate-based node binary with dev-fast proof acceptance enabled.
# This is for development only; do not ship production binaries with fast proofs enabled.
node-fast:
	$(MACOS_LIBCLANG_HELPER)
	cargo build -p hegemon-node --features substrate,fast-proofs --release
