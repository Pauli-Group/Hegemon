```md
# Governance escalations and incentive hooks for attestations/settlement

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds. It must be maintained in accordance with `.agent/PLANS.md`.

## Purpose / Big Picture

We need governance-aware dispute flows in the attestations and settlement pallets so that disputes can escalate through council or referenda origins instead of ad-hoc signers. The oracles/settlement paths should surface treasury-funded incentives for validators and oracle operators, and pallets must expose migration guards with auditable events. The end result should let a runtime configured with council/referenda origins escalate disputes, process scheduled incentive payouts via the treasury, and emit events for migrations and governance actions.

## Progress

- [x] (2024-07-02 00:00Z) Captured requirements and current state; plan drafted.
- [x] (2024-07-02 01:00Z) Implemented governance escalation, dispute lifecycle updates, and audit events in attestations/settlement pallets.
- [x] (2024-07-02 01:10Z) Added treasury incentive hooks with scheduled payouts for oracles/settlement plus audit events.
- [x] (2024-07-02 01:20Z) Added migration guards/events across pallets and wired runtime origins/treasury constants; pending tests.

## Surprises & Discoveries

- None yet.

## Decision Log

- Decision: Use council/referenda origin parameters to gate escalations rather than fixed Root origins, allowing runtime composition.
  Rationale: Matches request for governance escalation flexibility and keeps pallets reusable.
  Date/Author: 2024-07-02 / assistant

## Outcomes & Retrospective

TBD after implementation.

## Context and Orientation

Key pallets live under `pallets/attestations`, `pallets/settlement`, and `pallets/oracles`. Runtime wiring is in `runtime/src/lib.rs`. Treasury integration uses `pallet_treasury` already present in the runtime. Storage version guards currently exist but lack audit events and governance-aware checks.

## Plan of Work

Update attestations: add governance escalation origins (council/referenda), extend dispute statuses and events, and log migrations. Settlement: add batch dispute initiation, allow governance escalation via either origin, queue incentive payouts, and emit audit events including migration runs. Oracles: add treasury-driven rewards for submitters/verifiers with scheduler-based payout queue and audit events. Introduce migration guard helpers across pallets to refuse downgrades and emit events when storage versions bump. Wire runtime to use council origins and treasury-backed incentive handler, and adjust weights/tests as needed.

## Concrete Steps

1. Modify attestations pallet Config to accept council/referenda origins; add escalate/dispute resolve extrinsics gated by those origins, update events and pending settlement hooks accordingly. Add migration guard that emits an event when upgrading and no-ops on higher versions.
2. Extend settlement pallet with batch dispute initiation, governance escalation using council/referenda origins, and a reward queue processed in `on_initialize`; add audit events for disputes, payouts, and migrations. Ensure rollback/resolution paths update flags consistently.
3. Enhance oracles pallet with treasury-backed incentive hooks (using Currency + treasury account) and scheduled payout processing; emit events for rewards and migrations.
4. Propagate migration guard/event pattern to other pallets as needed (asset-registry, identity, observability, feature-flags) to satisfy “all pallets” requirement.
5. Wire runtime origins: set council-based governance origins and referenda fallback, configure treasury incentive handler, and adjust tests to reflect new dispute behaviors and events.

## Validation and Acceptance

- Build and run unit tests for updated pallets and runtime (`cargo test -p ...` or `cargo test`).
- Demonstrate dispute start + governance escalation emits events and updates statuses. Confirm reward queue drains and transfers succeed in tests. Verify migration events emitted during on_runtime_upgrade guard tests.

## Idempotence and Recovery

On-runtime upgrade guards should no-op when versions match and refuse downgrades; scheduled payout queues clear after processing, so re-running initialization is safe. Tests construct fresh externalities per run.

## Artifacts and Notes

None yet.

## Interfaces and Dependencies

- Attestations Config gains council/referenda origins; new extrinsics `escalate_dispute`/`resolve_dispute` gated by `EnsureOrigin` combos.
- Settlement Config gains council/referenda origins and incentive treasury handle using `Currency`; new extrinsics `flag_batch_dispute`, `escalate_state_channel_dispute` uses governance origins; reward queue processed each block.
- Oracles Config gains treasury reward handler and reward constants; payout queue processed per block.
- Migration guard helper ensures `on_chain_storage_version` is not ahead of `STORAGE_VERSION` and emits events when upgraded.
```
