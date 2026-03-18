# Remove Stale External-Prover And Pooling Artifacts After The InlineTx Pivot

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds. This document follows [`.agent/PLANS.md`](/Users/pldd/Projects/Reflexivity/Hegemon/.agent/PLANS.md) and must be maintained in accordance with that file.

## Purpose / Big Picture

After the proving recovery, Hegemon ships an explicit `InlineTx` admission path: users or private wallets/provers generate canonical transaction proofs first, block authors attach the parent-bound commitment proof, and consensus verifies ordered inline tx proofs directly. The current tree still exposes an older topology in the runtime defaults, the desktop app, and operator docs. Those stale surfaces mislead operators into thinking that a private recursive prover host and pooled hash worker are still part of the current product path.

This cleanup makes the current product behavior visible and consistent. After the change, a novice should be able to start the app and see only the roles that actually exist in the current shipped architecture, inspect the runtime manifest and find `InlineRequired` as the fresh-testnet default proof-availability policy, and read the rollout docs without being told to deploy `hegemon-prover` as part of normal operation.

## Progress

- [x] (2026-03-18 08:26Z) Audited the stale surfaces and confirmed the top mismatches: desktop `pooled_hasher` / `private_prover` roles, runtime `ProofAvailabilityPolicy::SelfContained` in the protocol manifest, and rollout docs that still describe `hegemon-prover` as part of the current topology.
- [x] (2026-03-18 09:34Z) Updated the runtime protocol manifest so fresh chainspecs default to `ProofAvailabilityPolicy::InlineRequired`.
- [x] (2026-03-18 09:52Z) Removed stale pooled/private-prover participation roles from the desktop UI, deleted pool-miner IPC from the app surface, and stopped ordinary node summaries from probing prover RPC.
- [x] (2026-03-18 10:11Z) Rewrote operator/testnet docs so the current shipping topology is “authoring node + full nodes” and demoted external-prover language to explicit experimental or historical context only.
- [x] (2026-03-18 10:33Z) Validated the cleanup with `npm --prefix hegemon-app run typecheck`, `cargo check -p runtime`, and `cargo check -p hegemon-node --features substrate`.

## Surprises & Discoveries

- Observation: the strongest stale architecture bug is not in the UI but in the runtime manifest. `runtime/src/manifest.rs` still sets `proof_availability_policy` to `ProofAvailabilityPolicy::SelfContained` and comments that wallets may omit per-tx proof bytes, even though the live shipping lane is `InlineTx`.
  Evidence: `runtime/src/manifest.rs` lines 82-85 before cleanup.

- Observation: the desktop backend still probes `prover_getStageWorkPackage` and `prover_getWorkPackage` on every node summary even though the current live lane publishes no external work in `InlineTx`.
  Evidence: `hegemon-app/electron/nodeManager.ts` lines 273-279 before cleanup.

- Observation: the desktop’s participation model is still centered on the old topology. It offers `pooled_hasher` and `private_prover` as first-class roles and presents pool/prover-specific form fields and operations even when the current product path is just `full_node` vs `authoring_pool`.
  Evidence: `hegemon-app/src/types.ts` line 2 and `hegemon-app/src/App.tsx` lines 71-97 before cleanup.

## Decision Log

- Decision: fix the runtime policy default now instead of treating it as “just docs.”
  Rationale: a manifest default that still says `SelfContained` is an architecture lie. It affects chainspec generation and operator assumptions, not just prose.
  Date/Author: 2026-03-18 / Codex

- Decision: remove `pooled_hasher` and `private_prover` from the desktop participation selector instead of merely relabeling them.
  Rationale: the user-facing problem is that the interface advertises roles that are not part of the current shipped path. Hiding them behind softer copy would preserve the lie.
  Date/Author: 2026-03-18 / Codex

- Decision: keep experimental recursive/worker code in-tree for now, but demote it to non-product status in docs and app surfaces.
  Rationale: cutting all recursion code in one turn would mix product-surface cleanup with deeper experimental-code deletion. This cleanup turn is about making the shipped architecture honest first.
  Date/Author: 2026-03-18 / Codex

## Outcomes & Retrospective

The cleanup landed cleanly. Fresh protocol manifests now default to `InlineRequired`, the desktop only exposes `Full node` and `Authoring node`, normal node summaries no longer probe dead prover RPC, and the operator docs no longer instruct people to deploy `hegemon-prover` for the current release.

What intentionally remains in-tree:

- the experimental recursive worker code and `hegemon-prover-worker` binary;
- the pool miner manager implementation, now disconnected from the shipping desktop surface;
- recursive/merge-root documentation inside `DESIGN.md` and `METHODS.md`, but reworded so it is clearly experimental rather than current product topology.

The main practical gain is not cosmetic. A fresh reader can now look at the runtime manifest, the desktop app, and the rollout docs and see the same architecture: proof-ready transactions at the edge, `InlineTx` in the core, and a normal deployment built around an authoring node plus full nodes.

## Context and Orientation

The current shipping path is the `InlineTx` lane. In plain language, that means each shielded transaction must already carry canonical tx proof bytes when it reaches block assembly, and the block author only adds the parent-bound commitment proof that binds the ordered transaction set to the new state roots and nullifier data.

The runtime protocol manifest lives in `/Users/pldd/Projects/Reflexivity/Hegemon/runtime/src/manifest.rs`. That file defines the default proof-availability policy that fresh chainspecs inherit. If it says `SelfContained`, operators will believe the chain expects proofless transfers plus a same-block aggregation artifact. That is stale for the current shipping lane.

The desktop participation-role model lives in `/Users/pldd/Projects/Reflexivity/Hegemon/hegemon-app/src/types.ts` and `/Users/pldd/Projects/Reflexivity/Hegemon/hegemon-app/src/App.tsx`. Those files decide which roles the user can choose and which controls appear in the interface. The Electron backend that feeds node status is in `/Users/pldd/Projects/Reflexivity/Hegemon/hegemon-app/electron/nodeManager.ts`.

The rollout and operator docs that still describe the older topology are in:

- `/Users/pldd/Projects/Reflexivity/Hegemon/config/testnet-initialization.md`
- `/Users/pldd/Projects/Reflexivity/Hegemon/docs/SCALABILITY_PATH.md`
- `/Users/pldd/Projects/Reflexivity/Hegemon/runbooks/authoring_pool_upgrade.md`
- `/Users/pldd/Projects/Reflexivity/Hegemon/runbooks/two_person_testnet.md`
- `/Users/pldd/Projects/Reflexivity/Hegemon/config/testnet/README.md`
- `/Users/pldd/Projects/Reflexivity/Hegemon/README.md`
- `/Users/pldd/Projects/Reflexivity/Hegemon/DESIGN.md`
- `/Users/pldd/Projects/Reflexivity/Hegemon/METHODS.md`

The recursive external-worker binary still exists at `/Users/pldd/Projects/Reflexivity/Hegemon/node/src/bin/prover_worker.rs`, but this plan treats it as experimental code left in-tree, not as part of the current shipping path.

## Plan of Work

First, edit `runtime/src/manifest.rs` so the protocol manifest uses `ProofAvailabilityPolicy::InlineRequired` and the surrounding comment describes the live `InlineTx` path accurately. This aligns fresh testnets and generated chainspecs with the admission mode the node already defaults to.

Second, simplify the desktop participation model. In `hegemon-app/src/types.ts`, narrow `NodeParticipationRole` to the roles that still exist in the current product surface. In `hegemon-app/src/App.tsx`, remove the stale `pooled_hasher` and `private_prover` role metadata, remove the role-specific form fields and action panels that only serve those modes, and make the ordinary local/remote connection experience about `full_node` versus `authoring_pool`. In `hegemon-app/electron/nodeManager.ts`, stop collecting prover work-package state as part of normal node summary generation because that state is not part of current `InlineTx` operation.

Third, rewrite the operator/testnet docs so they describe the current deployment honestly. That means removing instructions that treat `hegemon-prover` as required, removing pooled/private-prover guidance as the default path, and rewriting the topology language around the current live lane. Where experimental recursion or future prover-market work remains relevant, say so explicitly as future/experimental work rather than current rollout guidance.

Finally, validate the runtime and app builds, then record what still remains intentionally experimental. The result should be a branch where the product surface matches what the code actually ships.

## Concrete Steps

Run these commands from the repository root:

    cargo check -p hegemon-runtime
    cargo check -p hegemon-node --features substrate
    npm --prefix hegemon-app run typecheck

If the app uses a different script for type checking, update this section with the exact command used during implementation.

## Validation and Acceptance

Acceptance is behavioral:

1. A fresh reader opening `runtime/src/manifest.rs` sees `ProofAvailabilityPolicy::InlineRequired`, not `SelfContained`, as the protocol-manifest default.
2. The desktop participation selector offers only the roles that still exist in the current shipped architecture.
3. The desktop no longer presents pool-worker or private-prover setup controls to ordinary users.
4. The rollout docs no longer tell operators to provision `hegemon-prover` as part of the current shipping topology.
5. The runtime and desktop type/build checks still pass.

## Idempotence and Recovery

These edits are safe to repeat. If a documentation rewrite overshoots, compare against the current shipped code path (`InlineTx` in `node/src/substrate/service.rs` and `consensus/src/proof.rs`) and reword the docs to match the implementation rather than restoring old topology guidance.

## Artifacts and Notes

Important pre-change stale references:

    runtime/src/manifest.rs
    hegemon-app/src/types.ts
    hegemon-app/src/App.tsx
    hegemon-app/electron/nodeManager.ts
    config/testnet-initialization.md
    docs/SCALABILITY_PATH.md
    runbooks/authoring_pool_upgrade.md

## Interfaces and Dependencies

At the end of this change:

- `runtime::manifest::protocol_manifest()` must return `ProofAvailabilityPolicy::InlineRequired`.
- `hegemon-app/src/types.ts` must define a `NodeParticipationRole` that reflects the current product surface.
- `hegemon-app/electron/nodeManager.ts` must not treat `prover_get*` work-package polling as part of normal node health/status collection.
- Operator docs must describe the current shipped `InlineTx` deployment honestly and reserve external-prover language for explicit experimental sections only.
