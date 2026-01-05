# Emergency primitive swap runbook

This runbook is the miner and node-operator facing checklist referenced by DESIGN.md, METHODS.md, and `governance/VERSIONING.md`. It assumes a binding is compromised and we need to migrate all notes to a replacement binding via the upgrade circuit.

## 1. Assess and declare

1. Confirm the break or weakness with the security team.
2. Draft a `VersionProposal` with:
   - `binding` = the safe replacement binding (new circuit + crypto suite IDs),
   - `activates_at` = soonest practical height (give wallets ≥1 epoch to ship binaries, but keep it aligned with `VersionSchedule` checkpoint semantics so PoW nodes can deterministically enforce it),
   - `retires_at` = the hard cutoff for the compromised binding,
   - `upgrade` = `UpgradeDirective { from: old_binding, to: new_binding, circuit: upgrade_binding, activation_height }`.
3. Publish the draft to the governance list and link to regression test results (e.g., `tests/block_flow.rs::mixed_versions_require_declared_keys`). Include a heads-up for mining pools that a mandatory template change is imminent.

## 2. Prepare code + keys

1. Generate the new proving/verifying keys for the transaction circuit and for the upgrade circuit binding.
2. Merge the keys plus the updated `VersionSchedule` entry (calling `register(proposal)` in node configs) through the usual review process.
3. Package signed verifying-key bundles and distribute them via the miner channel (pool ops mailing list, artifact registry, IPFS mirror). Document the SHA-256 digests so miners can verify downloads.
4. Ensure template-serving full nodes and mining pool infrastructure deploy builds that:
   - include the new binding in their verifying-key map,
   - expose the upgrade circuit proving key to wallets,
   - ship the new `protocol-versioning` constants if we bumped circuit/crypto IDs,
   - advertise the updated `VersionSchedule` hash so miners can confirm they are following the correct activation track.

## 3. Activation window

1. **T-1 epoch:** Announce `activates_at`/`retires_at` heights to the community, explicitly addressing miners and mining pools. Wallets should begin offering an “Upgrade my notes” action that crafts the upgrade circuit witness (consume old binding, produce new binding). Pools should stage the new verifying-key bundle on their template servers and confirm the node reports `VersionSchedule::first_unsupported(height)` = `None` at activation height.
2. **At `activates_at`:**
   - Verify every template-serving node (pool infrastructure and solo miners) loads the new binding + upgrade circuit binding via `VersionSchedule`.
   - Monitor mempool telemetry for upgrade transactions; they should start appearing immediately. Pools can expose per-miner counts in their dashboards.
   - Reject block templates that still omit the new binding; miners should treat such templates as invalid before hashing, and full nodes will enforce the rule with `ConsensusError::UnsupportedVersion`.
3. **During the grace period:**
   - Use per-block `version_counts` (derived from transaction bindings) and the header’s `version_commitment` (where surfaced) to track migration progress. Pools should alert if `version_counts[old_binding]` plateaus above 0 near `retires_at`.
   - Alert large custodians or exchanges that still emit old-binding proofs and broadcast notices to miners so they can prioritize upgrade transactions.

## 4. Retirement

1. At `retires_at`, remove the compromised binding from `VersionSchedule` (call `register` with `retires_at` or manually edit config). Publish the new schedule hash so miners can double-check their nodes.
2. Rotate miner and pool verifying-key bundles to drop the obsolete verifying key so misconfigured rigs cannot produce invalid witnesses.
3. Keep the upgrade circuit binding available for at least one extra epoch in case of straggler migrations, but flag any miner who continues to propagate old proofs after retirement.
4. After the buffer period, prune the upgrade circuit if no longer needed and update documentation with a postmortem that includes miner/pool participation stats.

## 5. Verification & audit

1. Archive the `version_counts` timeseries, pool-level adoption metrics, and the precise block heights where the binding appeared/disappeared.
2. Record the hash of the `VersionProposal` that was executed and any deviations from the plan, explicitly listing which mining organizations lagged or escalated issues.
3. File a short report so future swaps can reuse the lessons learned and include updated escalation contacts for pool operators and full node maintainers.

## Monitoring and escalation contacts

- **Mining pools:** Follow the operations mailing list + signed governance bulletins. Escalate to the security lead (`security@`) if templates fail validation or miners report conflicting `version_commitment` hashes.
- **Solo miners / full node operators:** Subscribe to the alerting feed and verify node logs for `VersionSchedule::first_unsupported`. Escalate to the protocol SRE rotation via the `#protocol-pow` channel if their node rejects templates post-activation.
- **Wallet maintainers:** Coordinate with pools to prioritize upgrade transactions and raise issues in `#wallet-upgrades` if miners fail to mine upgrade proofs.
