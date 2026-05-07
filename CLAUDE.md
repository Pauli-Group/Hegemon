# Always Be Shipping

The product must be made real, not a mock up. DON'T BE A SYCOPHANT CLAUDE.

# ExecPlans

When writing complex features or significant refactors, use an ExecPlan (as described in .agent/PLANS.md) from design to implementation.

# First-Run Setup

Setup is layered. Build only what the user needs — never silently skip an optional component, since failures surface later as confusing runtime errors (e.g. clicking "create wallet" in the Electron app fails if `walletd` was never built).

**Mandatory (every fresh clone):**
1. `make setup` — installs toolchains (Rust, Go, jq, clang-format, protoc, libclang).
2. `make node` — builds `./target/release/hegemon-node`.

**Optional add-ons — ASK the user which they want before building:**
- **Desktop Electron app** → also requires `make walletd` (builds `./target/release/walletd`) plus `cd hegemon-app && npm install`. The app's `resolveBinaryPath` looks for both `hegemon-node` and `walletd` in `target/release/`. Convenience target: `make app` builds both Rust binaries.
- **Benchmarks** → `make bench` (runs prover/wallet/network smoke benches; no prebuilt binary needed).
- **Tests / contributor flow** → `make check` (fmt + lint + test).
- **Wallet demo artifacts** → `make wallet-demo`.

For an interactive walk-through that detects state, asks the right questions, and runs the right commands in order, invoke the `hegemon-setup` skill (`/hegemon-setup`) or accept a user request like "help me set up this repo" by running it.

To start a dev node after `make node`: `HEGEMON_MINE=1 ./target/release/hegemon-node --dev --tmp`.

# Design and Methods Docs

Always consult DESIGN.md and METHODS.md before making code changes to ensure the implementation aligns with the documented plans, and update those documents whenever the architecture or methods evolve.

# README Whitepaper

Maintain the opening section of `README.md` as the canonical whitepaper for the project. The whitepaper must appear before the "Monorepo layout" and "Getting started" sections and must preserve the document title and subtitle.

# Branding Guidelines

Whenever you design or adjust any visual element, interface component, or documentation mock-up, consult `BRAND.md` to ensure colors, typography, layout, and motion adhere to the shared system. Document any intentional deviations in the relevant pull request.
