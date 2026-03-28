# Bootstrap pooled hashing and private-prover authoring for 0.9.x

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds.

This document must be maintained in accordance with [.agent/PLANS.md](./PLANS.md).

## Purpose / Big Picture

After this work lands, Hegemon will have a clear and operable first public mining experience that matches the actual hardware available today. One node will be treated as the only public authoring node, one proving machine will stay private behind an outbound-only tunnel, the first app mining UX will be pooled hashing rather than independent shielded block authorship, and new participants will have explicit criteria for joining as hashers, provers, or second pool operators. A novice operator should be able to follow the runbook, bring up the author/prover topology, and understand which role a new machine should play.

The observable result is:

1. An operator can read one runbook and configure a public author backed by a private prover machine.
2. The app/product plan explicitly steers ordinary users toward pooled hashing or full-node verification rather than limited authoring.
3. The repository records explicit admission criteria for new participants: hasher, prover, or second pool operator.

## Progress

- [x] (2026-03-09 20:40Z) Re-read `.agent/PLANS.md` and confirmed this work needs a self-contained ExecPlan.
- [x] (2026-03-09 20:46Z) Audited current architecture references in `DESIGN.md`, `METHODS.md`, `docs/SCALABILITY_PATH.md`, and the existing VPS/testnet runbooks.
- [x] (2026-03-09 20:58Z) Added `runbooks/authoring_pool_upgrade.md` to describe the immediate public-author + private-prover topology, public app miner posture, and onboarding criteria.
- [x] (2026-03-09 22:05Z) Updated `hegemon-app` so node connections carry an explicit participation role (`full node`, `pooled hasher`, `public author`, `private prover`) and the UI now defaults to pooled-hashing/full-node language instead of generic local mining language.
- [x] (2026-03-09 23:34Z) Implemented the first pooled miner UX in `hegemon-app`: pooled hash workers can now be configured and started from Electron, background hash loops submit shares through the new pool RPC, and the UI shows worker status, logs, and pool accounting.
- [x] (2026-03-10 00:22Z) Implemented the first standalone private prover worker (`hegemon-prover-worker`) and author-side `root_finalize` stage package publication for the `MergeRoot` path.
- [ ] Define the remaining network/API work needed to support pool-style workers at production quality (completed: pooled hash-worker flow, worker-level payout fractions, configurable share difficulty, author-side pool RPC, stage-package publication, and standalone private prover worker; remaining: durable payout persistence, a hardened pool share protocol beyond JSON-RPC, and broader external proving modes beyond the current `MergeRoot` root-finalize path).

## Surprises & Discoveries

- Observation: the repository already assumes a separation between authoring and proving much more strongly than the current user-facing mining story suggests.
  Evidence: `METHODS.md` describes prove-ahead bundle construction plus external proving, while `docs/SCALABILITY_PATH.md` now makes the initial topology “one public author + private prover backend + many hashers.”

- Observation: the current public mining surface does not provide a real pool work/share protocol; it mostly exposes node control and telemetry.
  Evidence: `node/src/substrate/rpc/hegemon.rs` exposes `miningStatus`, `startMining`, and `stopMining`, but no Stratum-like template/share submission interface.

- Observation: the existing runbooks already carry the approved `HEGEMON_SEEDS` list and NTP/chrony requirements, so the new runbook should repeat those values rather than invent a new bootstrap story.
  Evidence: `runbooks/miner_wallet_quickstart.md` and `runbooks/two_person_testnet.md`.

- Observation: the clean standalone prover cut is to publish `root_finalize` stage packages that already include resolved transaction proofs and commitment-proof public inputs, then let the worker generate the commitment proof and merge-root artifact offline.
  Evidence: `node/src/substrate/prover_coordinator.rs` now carries `root_finalize_payload`, and `node/src/bin/prover_worker.rs` consumes `prover_getStageWorkPackage` to build a full `BlockProofBundle`.

- Observation: the desktop app previously modeled node intent only as `local` vs `remote` plus a generic mining toggle, which implicitly suggested ordinary users should become local authors if they wanted to participate.
  Evidence: before this change, `hegemon-app/src/App.tsx` exposed `Auto-start mining`, `Miner address`, and `Mine threads` without any explicit participation-role model.

- Observation: pooled hashing and standalone private proving were both shippable once the author published the right package shapes. Hashers only need current PoW work, while the prover worker needs resolved transaction proofs plus commitment-proof public inputs.
  Evidence: the author node now exposes `hegemon_poolWork` / `hegemon_submitPoolShare` for hashers and `prover_getStageWorkPackage` root-finalize payloads for the standalone prover worker.

- Observation: a practical pooled worker can run today inside the desktop app by hashing in background Node worker threads against `hegemon_poolWork` and submitting accepted shares through `hegemon_submitPoolShare`; this does not require changing consensus.
  Evidence: `hegemon-app/electron/poolMinerManager.ts` now starts worker threads with `hash-wasm`, polls pool work over RPC, and the renderer shows accepted shares, block candidates, and per-worker payout fractions from `hegemon_poolStatus`.

## Decision Log

- Decision: treat pooled hashing, not limited authoring, as the first public miner experience.
  Rationale: with the current hardware, broad authoring would multiply proving load while ordinary users still lack proving capacity. Pooled hashing decentralizes PoW immediately without wasting the private prover.
  Date/Author: 2026-03-09 / Codex

- Decision: write a dedicated operator runbook for the immediate topology instead of folding the guidance into the generic VPS or testnet runbooks.
  Rationale: the “one public author + one private prover backend” setup is a specific operational mode with stronger boundary rules than the generic runbooks.
  Date/Author: 2026-03-09 / Codex

- Decision: sequence decentralization as hashers first, then second pools, then a broader prover market, then wider authoring.
  Rationale: this preserves throughput and aligns with the current proving implementation, which benefits from reusing parent-scoped prepared bundles.
  Date/Author: 2026-03-09 / Codex

- Decision: keep the new runbook explicit about the missing standalone prover worker and pool share protocol instead of pretending the current tree already supports the full topology end to end.
  Rationale: the user asked for an exact next work plan. Hiding the implementation gap would make the runbook operationally misleading.
  Date/Author: 2026-03-09 / Codex

- Decision: ship a role-based app model before the pool worker exists.
  Rationale: we can remove the misleading “everyone can mine locally” story now, preserve future pool/prover settings in saved connections, and keep the UI honest while the backend transport is still under construction.
  Date/Author: 2026-03-09 / Codex

- Decision: infer `public author` for existing saved connections that already have mining settings.
  Rationale: older local connections with `miningIntent` or `minerAddress` should keep working after the new role field is introduced instead of silently downgrading to full-node mode.
  Date/Author: 2026-03-09 / Codex

- Decision: build the pooled-hasher backend foundation before the standalone prover worker.
  Rationale: the authoring node already maintains live PoW work and can validate external solutions with modest changes, while the current external proving path still needs more work-package and worker plumbing to become a real standalone service.
  Date/Author: 2026-03-09 / Codex

- Decision: use Electron-side Node worker threads plus `hash-wasm` for the first pooled hash worker.
  Rationale: this ships a real background hasher immediately, keeps the renderer responsive, avoids inventing a custom native module, and reuses the new pool RPC without waiting on a separate packaged worker binary.
  Date/Author: 2026-03-09 / Codex

- Decision: publish standalone prover work only for the `MergeRoot` root-finalize stage in the first cut.
  Rationale: the root-finalize path can be reconstructed offline from resolved transaction proofs plus commitment-proof public inputs. The current leaf-batch external path still lacks the public witness/context needed for a robust standalone worker.
  Date/Author: 2026-03-10 / Codex

## Outcomes & Retrospective

The planning artifacts now state the intended topology clearly, the desktop app now reflects that topology at the UX level, the authoring node plus Electron app form a working pooled-hasher path, and the repo now ships a standalone private prover worker for the current `MergeRoot` root-finalize path. The remaining gap is operator hardening and economic durability, not basic topology enablement. Pool accounting is still in-memory rather than durable, and the standalone prover worker is narrower than the long-term prover market design. The next contributor should treat this ExecPlan as the bridge from “the topology works” to “the pool and prover economy are production-grade.”

## Context and Orientation

Hegemon currently has three relevant documentation anchors for this work.

`DESIGN.md` is the architecture document. It describes the commitment-proof and aggregation architecture, the asynchronous prover coordinator, and the long-term direction toward an open prover market. It also explains that prepared bundles are keyed by parent hash, transaction statement commitment, and transaction count, which means proving work is most efficient when it is reused across many hashers extending the same parent.

`METHODS.md` is the implementation-oriented document. It describes how the node publishes work packages (`prover_getWorkPackage`, `prover_submitWorkResult`, and related methods), how proof bundles are assembled, and how block import verifies the final commitment and aggregation artifacts. It also says operators must share the same `HEGEMON_SEEDS` list and keep NTP/chrony healthy.

`docs/SCALABILITY_PATH.md` is the topology roadmap. It states that the immediate target is one public authoring node, one private prover backend, and many pooled hashers. It also states that second pools should come before broad public authoring.

The current operator-facing runbooks (`runbooks/p2p_node_vps.md`, `runbooks/miner_wallet_quickstart.md`, and `runbooks/two_person_testnet.md`) explain how to start nodes, connect peers, and mine in a generic sense, but they do not yet serve as the canonical guide for the authoring-pool topology.

The current app is in `hegemon-app/src/App.tsx` plus the Electron entrypoints under `hegemon-app/electron/`. It can start a local node, connect to external nodes, and present wallet/node actions, but it does not yet present a clean pooled-mining role separation to users. “Pooled hashing” in this plan means a user contributes proof-of-work shares against pool-provided templates. It does not mean the user independently constructs shielded block templates or runs a proving backend. “Authoring” means the node that selects transactions, coordinates proving, assembles a ready `BlockProofBundle`, and broadcasts blocks.

## Plan of Work

First, keep the immediate operations story stable. The new runbook `runbooks/authoring_pool_upgrade.md` is the operator source of truth for the public-author + private-prover topology. Any subsequent edits to app copy, operator docs, or release notes must remain consistent with that runbook. If the topology changes, update the runbook first and then reflect the change in the higher-level docs.

Second, align the app and user-facing documentation to pooled hashing. Audit `hegemon-app/src/App.tsx` and related operator screens to find any copy or flows that imply ordinary users should become public shielded block authors. Replace those assumptions with three explicit roles: full node, pooled hasher, and operator-only author. The default public path should be pooled hashing or full-node verification. Authoring should be advanced/operator-only.

Third, harden the pooled transport work that now exists. The node exposes a pool template/share interface, the desktop app can act as a pooled hash worker, and the repo ships a standalone private prover worker for the `MergeRoot` root-finalize path. The next implementation milestone should harden those surfaces: durable payout persistence, better pool auth, and broader external proving coverage.

Fourth, document the participant-role criteria in the user/operator materials. New participants should have a crisp rule for joining as a hasher, a prover, or a second pool operator. This guidance must appear in the runbook and any relevant onboarding docs so operators do not have to reconstruct it from architecture prose.

## Concrete Steps

Work from `/Users/pldd/Projects/Reflexivity/Hegemon`.

1. Read the current topology documents before changing anything:

    sed -n '1,220p' docs/SCALABILITY_PATH.md
    sed -n '874,889p' METHODS.md
    sed -n '443,447p' DESIGN.md

2. Read the new immediate-topology runbook:

    sed -n '1,260p' runbooks/authoring_pool_upgrade.md

3. Audit user-facing app copy for mining-role assumptions:

    rg -n "mine|mining|author|pool|hash" hegemon-app/src hegemon-app/electron

4. When the pooled-miner UX work starts, record the exact files changed and update `Progress`, `Decision Log`, and `Outcomes & Retrospective` in this ExecPlan.

5. Validate documentation consistency after each change:

    git diff --check
    rg -n "public authoring node|private prover backend|pooled hashing|second pool|HEGEMON_SEEDS|chrony|NTP" \
      docs runbooks hegemon-app/src -g '!target'

Expected result today: the commands above should show the new runbook and the topology language in the docs, with no diff-check failures.

## Validation and Acceptance

This ExecPlan is accepted when all of the following are true:

1. A novice operator can follow `runbooks/authoring_pool_upgrade.md` and understand exactly which services belong on the public authoring node and which belong on the private prover backend.
2. The repository’s public mining story is internally consistent: ordinary users are guided toward pooled hashing or full-node mode, not toward unsupported limited authoring.
3. The app/product work for pooled hashing is decomposed into implementable tasks with named files, surfaces, and success criteria.
4. The repo contains explicit criteria for classifying new participants as hashers, provers, or second pool operators.

Acceptance now includes a working demonstration: start the public authoring node, fetch work through `hegemon_poolWork`, submit an accepted share through `hegemon_submitPoolShare`, connect a pooled worker end to end, and start the standalone prover worker on the private proving machine so the authoring node continues to use the private prover backend for block assembly.

## Idempotence and Recovery

Documentation edits in this plan are additive and safe to repeat. If the topology changes, update `runbooks/authoring_pool_upgrade.md` first, then reconcile the rest of the docs and this ExecPlan. If app copy changes drift from the runbook, revert the copy change or revise both together; do not leave contradictory operator guidance in the tree.

Operationally, the immediate topology should be tested on non-production hosts first. If the private tunnel or remote proving path fails, the safe fallback is to keep the public authoring node as the only public node and temporarily re-enable local proving on a controlled host rather than exposing the prover publicly.

## Artifacts and Notes

Important repository artifacts for this plan:

    docs/SCALABILITY_PATH.md
    runbooks/authoring_pool_upgrade.md
    DESIGN.md
    METHODS.md
    hegemon-app/src/App.tsx
    node/src/substrate/rpc/hegemon.rs
    node/src/substrate/rpc/prover.rs

Evidence snippet proving the immediate topology is now documented:

    rg -n "Phase 0: 0.9.1 authoring pool|public authoring node|private proving machine" \
      docs/SCALABILITY_PATH.md runbooks/authoring_pool_upgrade.md

## Interfaces and Dependencies

The next implementation milestone driven by this ExecPlan should end with the following conceptual interfaces, even if the exact transport is still to be chosen:

- A pool-facing work endpoint on the public authoring side that serves PoW templates or share work units to hashers. The initial version is `hegemon_poolWork`.
- A pool-facing share submission endpoint that accepts accepted/rejected share results and records them for payout accounting. The initial version is `hegemon_submitPoolShare`, with aggregate counters exposed by `hegemon_poolStatus`.
- A standalone prover worker executable or service that can run on the private proving machine, poll the authoring node’s `prover_*` stage work packages over a private link, and return accepted results. The current implementation is `hegemon-prover-worker` for the `MergeRoot` root-finalize path.
- A private or PQ-authenticated proving path between the authoring node and one or more prover workers. The current `prover_*` RPC methods are sufficient for the immediate private deployment, but not yet sufficient as the final public prover market transport.
- Clear role labels in the app and docs: `full node`, `pooled hasher`, `prover`, and `pool operator`.

Revision note: created on 2026-03-09 to turn the documented scaling direction into an operator runbook plus a concrete work plan for the first pooled mining UX and the immediate public-author / private-prover topology.
