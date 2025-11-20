# Documentation Hub

![HEGEMON sovereignty emblem with a golden throne triangle, shielded rings, lattice accent, and HEGEMON wordmark](assets/hegemon-wordmark.svg)

This `docs/` tree centralizes contributor-facing material for the synthetic hegemonic currency monorepo. Everything here is considered normative alongside `DESIGN.md` and `METHODS.md`; when you change implementation code, update the relevant design/method sections *and* the docs entry that describes the behavior. The most useful entry points are:

- [`CONTRIBUTING.md`](CONTRIBUTING.md) – day-to-day workflows, required toolchains, CI entry points, and benchmarking instructions.
- [`THREAT_MODEL.md`](THREAT_MODEL.md) – explicit attacker assumptions, post-quantum (PQ) security margins, and mitigations for each subsystem.
- [`API_REFERENCE.md`](API_REFERENCE.md) – high-level overview of the Rust, Go, and (future) C++ APIs with links into `crypto/`, `circuits/`, `consensus/`, and `wallet/` implementations.
- [`USER_PRIVACY_GUIDELINES.md`](USER_PRIVACY_GUIDELINES.md) – end-user playbook for protecting wallet keys, node operations, and selective-disclosure workflows.
- [`BOUNTY_ZKSYNC_PROTOTYPE.md`](BOUNTY_ZKSYNC_PROTOTYPE.md) – prototype-level architecture for a zkSync-based bounty platform with escrow, dispute, and AA paymaster flows ready for implementation.

Each document calls out which sections of `DESIGN.md` and `METHODS.md` must be kept in sync so reviewers can verify that code, design, and docs evolve together. When adding a new crate, benchmark, or protocol feature, extend this hub and cross-reference the exact commit that introduced the change.
