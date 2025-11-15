# Emergency primitive swap runbook

This runbook is the operator-facing checklist referenced by DESIGN.md, METHODS.md, and `governance/VERSIONING.md`. It assumes a binding is compromised and we need to migrate all notes to a replacement binding via the upgrade circuit.

## 1. Assess and declare

1. Confirm the break or weakness with the security team.
2. Draft a `VersionProposal` with:
   - `binding` = the safe replacement binding (new circuit + crypto suite IDs),
   - `activates_at` = soonest practical height (give wallets ≥1 epoch to ship binaries),
   - `retires_at` = the hard cutoff for the compromised binding,
   - `upgrade` = `UpgradeDirective { from: old_binding, to: new_binding, circuit: upgrade_binding, activation_height }`.
3. Publish the draft to the governance list and link to regression test results (e.g., `tests/block_flow.rs::mixed_versions_require_declared_keys`).

## 2. Prepare code + keys

1. Generate the new proving/verifying keys for the transaction circuit and for the upgrade circuit binding.
2. Merge the keys plus the updated `VersionSchedule` entry (calling `register(proposal)` in node configs) through the usual review process.
3. Ensure block producers and validators deploy builds that:
   - include the new binding in their verifying-key map,
   - expose the upgrade circuit proving key to wallets,
   - ship the new `protocol-versioning` constants if we bumped circuit/crypto IDs.

## 3. Activation window

1. **T-1 epoch:** Announce `activates_at`/`retires_at` heights to the community. Wallets should begin offering an “Upgrade my notes” action that crafts the upgrade circuit witness (consume old binding, produce new binding).
2. **At `activates_at`:**
   - Verify every validator’s `version_schedule` contains the new binding + upgrade circuit binding.
   - Monitor mempool telemetry for upgrade transactions; they should start appearing immediately.
   - Reject blocks that still omit the new binding (Consensus will raise `UnsupportedVersion`).
3. **During the grace period:**
   - Use the `version_counts` field in recursive block proofs and the header’s `version_commitment` to track migration progress.
   - Alert large custodians or exchanges that still emit old-binding proofs.

## 4. Retirement

1. At `retires_at`, remove the compromised binding from `VersionSchedule` (call `register` with `retires_at` or manually edit config).
2. Rotate block-producer verifying-key maps to drop the obsolete verifying key so a misconfigured node cannot accidentally accept it.
3. Keep the upgrade circuit binding available for at least one extra epoch in case of straggler migrations.
4. After the buffer period, prune the upgrade circuit if no longer needed and update documentation with a postmortem.

## 5. Verification & audit

1. Archive the `version_counts` timeseries and the precise block heights where the binding appeared/disappeared.
2. Record the hash of the `VersionProposal` that was executed and any deviations from the plan.
3. File a short report so future swaps can reuse the lessons learned.
