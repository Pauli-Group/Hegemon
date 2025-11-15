# Version governance and activation playbook

This document supplements DESIGN.md / METHODS.md by describing how we use the new version identifiers in code (`protocol-versioning`) and the governance structures (`VersionProposal`, `VersionSchedule`, `UpgradeDirective`) to roll out or retire primitives without splitting the privacy pool.

## Terminology

- **VersionBinding** – a `(circuit_version, crypto_suite)` pair compiled into every transaction witness/proof.
- **VersionCommitment** – a SHA-256 hash of the per-block version matrix, published in every block header so peers know exactly which bindings were accepted.
- **VersionSchedule** – a consensus-side structure that records which bindings are valid at which heights. It is populated with `VersionProposal`s.
- **VersionProposal** – the ZIP-style governance artifact that specifies:
  - the `VersionBinding` being activated,
  - `activates_at` (height when miners/validators must accept the binding),
  - optional `retires_at` (height after which the binding is rejected),
  - optional `UpgradeDirective` (the binding for the migration/upgrade circuit plus the height at which that circuit becomes mandatory).

## Proposal lifecycle

1. **Draft** – Authors describe the change, security motivation, and expected activation/retirement heights. They attach new verifying/proving keys for the target binding and (if applicable) the upgrade circuit binding.
2. **Review** – Engineering / security teams run regression tests (see `tests/block_flow.rs::mixed_versions_require_declared_keys`) with the proposed bindings to ensure mixed-version blocks still verify. The `governance/VERSIONING.md` document is updated with rationale and parameters.
3. **Scheduling** – Once the proposal is ratified, operators add it to `VersionSchedule` by calling `register(VersionProposal { ... })`. The activation height is announced at least 2 epochs ahead so wallets can ship new proving keys.
4. **Activation** – At `activates_at`, validators must include the new binding in their verifying-key map (the block circuit already accepts it) and ensure `VersionSchedule::first_unsupported` no longer flags it. Blocks that contain the binding but a validator has not updated will be rejected with `ConsensusError::UnsupportedVersion`.
5. **Monitoring** – During the grace period between `activates_at` and `retires_at`, operators watch the `version_counts` reported by recursive block proofs and `version_commitment` in headers to ensure usage trends as expected.
6. **Retirement** – At `retires_at`, the binding is removed from `VersionSchedule`. Any lingering proofs with the old binding are rejected at consensus level, even if they would otherwise verify.

## Upgrade circuits and note migration

When a primitive needs to be replaced (e.g., moving from ML-KEM-768 to a post-attack variant), proposals should include an `UpgradeDirective`:

- `from` – the binding being deprecated.
- `to` – the new binding the ecosystem should move toward.
- `circuit` – the binding of the special upgrade circuit that proves "I owned a note under `from` and recreated it under `to`".
- `activation_height` – when the upgrade circuit must be accepted (usually the same as the new binding’s activation).

The upgrade circuit lives alongside normal transaction circuits. Wallets craft an "upgrade transaction" that consumes the old note, outputs an equivalent note under the new binding, and pays any mandated migration fee. Consensus treats the upgrade circuit like any other binding, so it benefits from the same `version_commitment`/`version_counts` monitoring.

## Emergency primitive swap runbook (summary)

A detailed operator checklist lives in `runbooks/emergency_version_swap.md`, but the key actions are:

1. Detect the issue and draft a VersionProposal + UpgradeDirective with aggressive activation/retirement heights.
2. Push the proposal through review/governance and merge the new bindings/keys.
3. Publish the activation plan to validators and wallet maintainers.
4. Update `VersionSchedule` on every node, redeploy verifying-key maps, and start accepting the upgrade circuit binding.
5. Track `version_counts` to ensure the old binding winds down before `retires_at`.
6. After retirement, remove the old verifying key from block producers/validators to avoid accidental acceptance.
