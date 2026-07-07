# Always Be Shipping

## Operator runbook updates

- When documenting mining setup, always include guidance to set `HEGEMON_SEEDS` with the currently approved seed list and note that miners must share the same seeds to avoid forks.
- Remind operators to enable time sync (NTP/chrony) because PoW timestamps are rejected if they exceed the future-skew bound.

The product must be made real, not a mock up. DON'T BE A SYCOPHANT.

# ExecPlans

When writing complex features or significant refactors, use an ExecPlan (as described in .agent/PLANS.md) from design to implementation.

# First-Run Setup

Every fresh clone must begin with `make setup` followed by `make node`. The setup command installs toolchains, and `make node` builds the native `hegemon-node` binary. Run `HEGEMON_MINE=1 ./target/release/hegemon-node --dev --tmp` to start a native dev node with mining enabled.

For shared mining environments, document and use `HEGEMON_SEEDS="hegemon.pauli.group:30333"` unless the approved seed list has been deliberately rotated. All miners on the same network must share the same seed list to avoid partitions and forks, and mining hosts must keep NTP or chrony enabled because future-skewed PoW timestamps are rejected.

# Design and Methods Docs

Always consult DESIGN.md and METHODS.md before making code changes to ensure the implementation aligns with the documented plans, and update those documents whenever the architecture or methods evolve.

# README Whitepaper

Maintain the opening section of `README.md` as the canonical whitepaper for the project. The whitepaper must appear before the "Monorepo layout" and "Getting started" sections and must preserve the document title and subtitle.

# Branding Guidelines

Whenever you design or adjust any visual element, interface component, or documentation mock-up, consult `BRAND.md` to ensure colors, typography, layout, and motion adhere to the shared system. Document any intentional deviations in the relevant pull request.
