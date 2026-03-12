# Permissionless PQC Scaling Redesign

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds.

This document must be maintained in accordance with [.agent/PLANS.md](./PLANS.md).

## Purpose / Big Picture

Hegemon needs a fresh-testnet architecture that can use worldwide Bitcoin-style mining infrastructure without requiring ASIC operators to run provers, full nodes, or a bespoke large-template control plane. After this redesign, a wallet still submits shielded transactions, a prover still computes public block-level proof artifacts, but any operator can run a permissionless template builder that turns public transactions plus public artifacts into compact mining jobs. ASICs and pooled hash workers only see a small Stratum-style job. They never fetch full proof bytes or reason about shielded state.

The user-visible result is simple. A wallet submits a transaction. Public provers publish reusable candidate artifacts. Template builders compete to turn those artifacts into valid block headers for the current parent. Mining farms, pools, and solo operators point their hashpower at compact jobs and keep their existing industrial operating model. The chain pays block winners and artifact claims by consensus. Pool share accounting stays off-chain and optional.

This ExecPlan deliberately targets a **fresh testnet**. It does not preserve compatibility with the current `BlockProofBundle` shape, current centralized authoring assumptions, or the current BLAKE3-based Substrate mining shortcut. If the target architecture requires a clean cut, this plan chooses the clean cut.

## Progress

- [x] (2026-03-11 17:40Z) Re-read `.agent/PLANS.md`, `DESIGN.md`, `METHODS.md`, and `docs/SCALABILITY_PATH.md` to confirm the current proving, mining, and pool architecture.
- [x] (2026-03-11 18:05Z) Audited the current pool, prover, and mining surfaces in `node/src/substrate/rpc/hegemon.rs`, `node/src/substrate/rpc/prover.rs`, `node/src/substrate/service.rs`, `consensus/src/substrate_pow.rs`, and the runbooks.
- [x] (2026-03-11 18:20Z) Re-scoped the redesign around the clarified target: fresh testnet, worldwide Bitcoin mining infrastructure, no mandatory two-stage block building, and no single privileged template server.
- [x] (2026-03-11 19:05Z) Rewrote the plan around permissionless template builders, parent-agnostic candidate artifacts, compact ASIC-facing jobs, and a transaction lifecycle that keeps heavy proof bytes off the mining path.
- [x] (2026-03-11 06:45Z) Cut the first fresh-testnet PoW migration slice: `consensus/src/substrate_pow.rs` now uses a 32-byte nonce plus `sha256d(pre_hash || nonce)`, the runtime PoW pallet/smoke tests were updated to the same nonce width and hash function, and the node RPC/mining surfaces were moved off implicit `u64` pool-share nonces.
- [x] (2026-03-11 06:45Z) Added additive artifact-market and compact-job surfaces: `CandidateArtifact` / `ArtifactAnnouncement` / `ArtifactClaim` naming aliases were added in consensus/runtime-facing types, `node/src/substrate/artifact_market.rs` and `node/src/substrate/template_builder.rs` were introduced, `hegemon_compactJob` / `hegemon_submitCompactSolution` were added, and prover RPC now exposes artifact announcement + fetch endpoints.
- [x] (2026-03-11 06:45Z) Updated operator/testnet docs for the laptop -> `hegemon-ovh` -> `hegemon-prover` rollout, including the boot-wallet flow, the approved `HEGEMON_SEEDS` list, the current `config/dev-chainspec.json` hash, and the SSH-tunneled private-prover topology.
- [x] (2026-03-11 14:24Z) Root-caused the blocked wallet flow to a runtime validation bug: `validate_shielded_transfer_*` was reading the persisted `CoinbaseProcessed` flag from the previous best state and rejecting next-block mempool transfers as stale. Removed that check from unsigned validation, kept it in `apply_*`, added a regression test in `pallets/shielded-pool/src/lib.rs`, regenerated the chainspec, redeployed OVH/prover/laptop, and completed a confirmed boot-wallet -> test-wallet -> boot-wallet round trip on the fresh chain.
- [x] (2026-03-11 20:10Z) Added a real runtime regression in `runtime/tests/kernel_wallet_transfer.rs` that seeds a wallet note, builds a real wallet transaction, wraps it in a kernel `ActionEnvelope`, proves `Kernel::validate_unsigned` accepts it, and then executes `Kernel::submit_action` successfully against the production `StarkVerifier` runtime configuration.
- [x] (2026-03-11 20:10Z) Added `./scripts/test-substrate.sh restart-recovery` plus the `restart-recovery-harness` CI job to emulate the laptop -> OVH/public node -> private prover stack topology locally, stop the prover node + external worker, verify the OVH-like node keeps mining, then restart the prover stack and require resync to the same tip.
- [x] (2026-03-11 20:10Z) Removed the remaining live SHA-256d PoW compatibility names (`Blake3Seal` / `Blake3Algorithm`) and deleted the wallet proof-debug artifact so the shipping code and tests now use the fresh-testnet vocabulary directly.
- [x] (2026-03-11 19:25Z) Fixed the fresh-runtime proof-availability default for the proofless lane by switching `runtime/src/manifest.rs` to `ProofAvailabilityPolicy::SelfContained`, rebuilt the release node, regenerated a fresh raw easy spec from the updated binary, and confirmed that a one-shot proofless sidecar transfer is now admitted successfully instead of dying immediately as `BadProof`.
- [x] (2026-03-11 19:59Z) Instrumented `pallets/kernel`, `pallets/shielded-pool::family`, and `circuits/aggregation` to surface the actual strict-aggregation failure path. The strict `8`-tx proofless batch now reproduces cleanly: submission succeeds, `prepare_block_proof_bundle` starts, the aggregation prover verifies all eight inner proofs, and then the cold recursive cache build stalls at `aggregation_profile stage=cache_circuit_build_start`.
- [x] (2026-03-11 20:57Z) Added worker-thread-local aggregation cache prewarm in `node/src/substrate/prover_coordinator.rs` and switched the default warmup policy in `circuits/aggregation/src/lib.rs` to target-only when liveness is disabled / queue capacity is `1`. This moved the first strict-batch cold start out of live traffic and into worker startup, and showed that the `8`-proof `MergeRoot` shape still spends more than a minute just in `cache_circuit_build` before any block traffic starts.
- [ ] Complete the deeper consensus/runtime cutover from legacy `BlockProofBundle` / centralized authoring assumptions to a fully inline `CandidateArtifact` block body and retire the remaining legacy pooled-hash compatibility path.

## Surprises & Discoveries

- Observation: the current live Substrate mining path still computes work as `blake3(pre_hash || nonce)`, which is not compatible with the worldwide SHA-256 Bitcoin mining stack this redesign is supposed to leverage.
  Evidence: `consensus/src/substrate_pow.rs` defines `compute_work` as BLAKE3 over `pre_hash` and `nonce`, while the higher-level docs already describe a Bitcoin-style compact-target PoW surface.

- Observation: the current live consensus path still requires miner identity material on the validity path.
  Evidence: `consensus/src/pow.rs` rejects blocks unless `validator_set_commitment` resolves to a known miner key and the header carries a valid ML-DSA signature. Industrial Bitcoin mining infrastructure does not work that way; pool auth and miner identity are off-chain control-plane concerns.

- Observation: the current public miner story already assumes pooled hashing against a template provider rather than independent shielded block authorship by ordinary users.
  Evidence: `runbooks/authoring_pool_upgrade.md` treats pooled hashing as the public path, and `hegemon-app/src/App.tsx` labels pooled hashing as the intended path for ordinary users while describing authoring as rare and operator-managed.

- Observation: the repository already has the beginnings of an external proving market, but it is still wired around the current authoring node.
  Evidence: `node/src/substrate/rpc/prover.rs` exposes external work-package RPCs and a dedicated prover-worker binary already exists, but the current work results still feed the local authoring pipeline rather than a public parent-agnostic artifact market.

- Observation: the current operator runbooks already treat common seed configuration and time sync as hard mining invariants.
  Evidence: `runbooks/miner_wallet_quickstart.md`, `runbooks/two_person_testnet.md`, and `runbooks/authoring_pool_upgrade.md` all insist on a shared approved `HEGEMON_SEEDS` list and NTP/chrony because partitions and future-skewed timestamps break PoW operation.

- Observation: the node crate was already much closer to the target nonce width than the Substrate PoW helpers were.
  Evidence: `consensus::header::PowSeal`, `node/src/miner.rs`, and the consensus test helpers already carry a `[u8; 32]` nonce, while `consensus/src/substrate_pow.rs`, runtime smoke tests, and pool-share RPC still assumed `u64`.

- Observation: introducing the new artifact-market vocabulary can be done safely as an additive layer before the full block-body cutover.
  Evidence: the existing proving path already flows through one reusable payload object (`BlockProofBundle` in the runtime, `ProvenBatch` in consensus) and one prepared-bundle cache (`node/src/substrate/prover_coordinator.rs`), which made `CandidateArtifact`/announcement surfaces straightforward to add without destabilizing proof generation first.

- Observation: the currently advertised public seed endpoints still serve the old genesis and therefore cannot be reused for the laptop-only fresh-genesis smoke test.
  Evidence: after regenerating `config/dev-chainspec.json` locally and starting a release node with the legacy public seeds, compatibility probes reported `peer_genesis=04d82e...` while the local fresh genesis was `cfe3ba0d...`, and the node stayed at height 0 until the stale peers were removed.

- Observation: the shielded transfer rejection was not a bad proof; it was a mempool-validity bug caused by block-local bookkeeping being persisted into the next best state.
  Evidence: the wallet-built bundle passed `StarkVerifier` and binding-hash verification locally, the anchor and nullifier were valid on-chain, and direct storage inspection showed `CoinbaseProcessed = 0x01` on the live best block. The unsigned validator rejected on that flag before proof verification.

- Observation: the fresh proofless lane was still running against an inline-proof policy on newly generated dev specs until the runtime manifest was updated.
  Evidence: a one-shot `HEGEMON_WALLET_DA_SIDECAR=1 HEGEMON_WALLET_PROOF_SIDECAR=1` submit against a spec generated from the pre-fix release binary was rejected as `Pool(InvalidTransaction::BadProof)`, while the same submit succeeded after rebuilding the release node with `ProofAvailabilityPolicy::SelfContained` as the manifest default and regenerating the raw spec.

- Observation: the current strict proofless batch path is not wallet-bound anymore once the policy fix lands; it stalls inside the recursive aggregation cold start.
  Evidence: with `HEGEMON_AGG_PROFILE=1`, the strict `8`-tx batch reaches `prepare_block_proof_bundle: starting aggregation stage`, logs `aggregation_profile stage=decode_and_shape`, verifies all eight inner proofs (`cache_verify_inner tx_index=0..7`), then emits `aggregation_profile stage=cache_circuit_build_start tx_count=8` and makes no further progress before the harness times out waiting for a prepared bundle.

- Observation: moving aggregation cache warmup onto the actual prover worker threads is necessary but not sufficient.
  Evidence: after adding worker-thread-local prewarm, the startup log showed `aggregation_profile stage=cache_verify_inner tx_count=8` followed by `aggregation_profile stage=cache_circuit_build_start tx_count=8` during node startup, before any throughput traffic was submitted. With target-only warmup in strict mode, the first-batch cost moved ahead of traffic, but `cache_circuit_build_done` still arrived only after roughly 110 seconds on the test machine, and the next bottleneck became `common_prepare_metadata` / `common_commit_preprocessed`.

- Observation: the repository does not yet have an end-to-end multi-prover throughput path for proofless batches.
  Evidence: the coordinator publishes fan-out `leaf_batch_prove` work packages, but the shipped standalone worker only handles `root_finalize`. At the same time, `build_flat_batch_proofs_from_materials` still requires transaction witnesses, which proofless sidecar work packages do not expose. That leaves `MergeRoot` as the only viable proofless batch mode, and it is currently a single cold recursive build.

## Decision Log

- Decision: this redesign targets a fresh testnet rather than an in-place migration of the current chain.
  Rationale: the current compatibility surface bakes in the wrong assumptions: `BlockProofBundle`, BLAKE3 mining, miner-signature validity, and centralized authoring. A clean testnet cut is simpler and more honest.
  Date/Author: 2026-03-11 / Codex

- Decision: reject two-stage block building as the target architecture.
  Rationale: the mining path must look like compact Bitcoin-style header jobs, not a miner-visible current-parent proof-finalize dance. Parent-specific execution can remain in the template builder and importer without forcing a second proof stage.
  Date/Author: 2026-03-11 / Codex

- Decision: the heavy public proof object is a parent-agnostic `CandidateArtifact`, not a same-parent finalized bundle.
  Rationale: proof artifacts must be reusable across parents until transaction conflicts or anchor expiry invalidate the ordered tx set. Reuse is how the prover market avoids becoming a centralized author moat.
  Date/Author: 2026-03-11 / Codex

- Decision: keep ASIC-facing mining jobs compact and Stratum-like.
  Rationale: worldwide Bitcoin mining infrastructure expects small jobs over a template server or local farm controller. ASICs should not receive full proof bytes, DA payloads, or shielded-state data.
  Date/Author: 2026-03-11 / Codex

- Decision: remove miner identity from the consensus validity path for the fresh testnet.
  Rationale: pool and farm operators can authenticate miners off-chain. Requiring ML-DSA miner identity material in block validity is incompatible with the target mining infrastructure and makes the block producer role needlessly permissioned.
  Date/Author: 2026-03-11 / Codex

- Decision: keep share accounting and payout smoothing off-chain and optional.
  Rationale: protocolizing pool shares would make consensus depend on pool business logic. The base protocol should pay the winning block and the included artifact claims; pools can keep PPS/FPPS-style products as overlays.
  Date/Author: 2026-03-11 / Codex

- Decision: a template builder is a permissionless role.
  Rationale: any full node that tracks the tip, validates public artifacts, and serves compact jobs should be able to compete. The architecture must not require one privileged public author endpoint.
  Date/Author: 2026-03-11 / Codex

- Decision: the first fresh-testnet artifact path keeps winning blocks self-contained by carrying the chosen artifact inline in the block body.
  Rationale: miners should hash compact jobs, but import should not depend on an out-of-band artifact fetch on the critical path. The market can still distribute artifacts pre-block via announcements and fetch-on-demand; the final block should carry the winning artifact bytes for deterministic import.
  Date/Author: 2026-03-11 / Codex

- Decision: remove the old BLAKE3 PoW type aliases from the live code path once the fresh chain and transaction round trip were green.
  Rationale: once the wallet flow and live rollout were stable, keeping `Blake3Seal` / `Blake3Algorithm` around only preserved the wrong mental model. The fresh-testnet SHA-256d path should be explicit in code, tests, and logs.
  Date/Author: 2026-03-11 / Codex

- Decision: split seed handling into two phases for rollout.
  Rationale: before `hegemon-ovh` is redeployed onto the fresh chainspec, the current public endpoints still point at the old network and will only create incompatible peers. Local fresh-genesis smoke tests therefore run with no public seeds, and the approved shared seed list is published only after OVH is serving the fresh genesis.
  Date/Author: 2026-03-11 / Codex

- Decision: `CoinbaseProcessed` remains an `apply_*` ordering invariant, not a `validate_*` mempool invariant.
  Rationale: the flag is per-block execution state. Reading it during transaction-pool validation against the previous best block incorrectly makes every next-block unsigned transfer stale on a chain that mints a coinbase every block.
  Date/Author: 2026-03-11 / Codex

- Decision: treat `ProofAvailabilityPolicy::SelfContained` as the fresh-testnet default from genesis.
  Rationale: the permissionless scaling redesign assumes proofless sidecar admission plus same-block `CandidateArtifact` import. Requiring operators or benchmarks to manually flip the chain out of `InlineRequired` just recreates the wrong architecture by default.
  Date/Author: 2026-03-11 / Codex

- Decision: do not interpret `HEGEMON_PROVER_WORKERS` as evidence of prover-market scaling for a single strict batch.
  Rationale: the current local coordinator schedules one `root_finalize` bundle job for one strict candidate. More local worker slots do not increase throughput unless there are multiple jobs to run or the chunked `leaf_batch_prove` path is actually consumable by external workers.
  Date/Author: 2026-03-11 / Codex

- Decision: in strict throughput mode, aggregation warmup should target the exact batch shape instead of checkpointing through `1/2/4/...`.
  Rationale: when `HEGEMON_PROVER_LIVENESS_LANE=0` and `HEGEMON_BATCH_QUEUE_CAPACITY=1`, intermediate warmup shapes are dead work. Warming only the final target shape moves the real cost forward without wasting startup on lanes the scheduler will never use.
  Date/Author: 2026-03-11 / Codex

## Outcomes & Retrospective

The previous version of this document was directionally right about rejecting centralized pooled authoring as the final architecture, but it still carried too much of the current authoring-node mindset into the redesign. The major course correction in this rewrite is to stop treating “public miners” as miniature authors or provers and to instead treat them as what the worldwide Bitcoin mining stack actually is: SHA-256 hashpower behind template servers, pool endpoints, and farm-local controllers.

The surviving architecture is now explicit. The chain exposes a parent-agnostic public artifact market. Template builders consume that market and current chain state, build valid block candidates, and serve compact jobs to miners. ASICs remain dumb. Provers remain public. Pools remain optional overlays. There is no mandatory second proof round and no single privileged author server.

## Context and Orientation

This section explains the target architecture from scratch.

The redesign introduces six roles:

- **Wallet**: creates a shielded transaction and proves any private witness material locally or through a user-chosen delegate. Wallets do not participate in the public block-level proof market.
- **Full node**: validates blocks, keeps the mempool, tracks the canonical chain state, and imports winning blocks.
- **Prover**: computes a public `CandidateArtifact` over an exact ordered transaction set. Provers are not miners and do not need to run ASICs.
- **Template builder**: a permissionless full-node role that observes the tip, mempool, and artifact market; chooses a valid artifact-backed candidate for the current parent; and serves compact mining jobs.
- **Farm broker**: an optional local controller inside a mining farm that pulls jobs from one or more template builders and serves rack controllers or ASICs over a Stratum-compatible surface. A broker is local and replaceable. It is not a consensus role.
- **Hasher / ASIC**: a machine that only searches the compact job’s nonce and rolling fields. It does not parse full blocks, proofs, or shielded state.

Today the repository already contains parts of this system, but in the wrong shape for the target architecture:

- `node/src/substrate/rpc/prover.rs` already exposes external proving work, but still for the current authoring path.
- `node/src/substrate/rpc/hegemon.rs` already exposes pooled-hashing RPCs, but still assumes one process-local pool surface and in-memory share accounting.
- `node/src/substrate/service.rs` and `pallets/shielded-pool/src/types.rs` still center the block proof path on `BlockProofBundle`.
- `consensus/src/substrate_pow.rs` and related runtime code still use the wrong mining surface for actual Bitcoin infrastructure.

For the fresh testnet, the redesign intentionally cuts those assumptions and replaces them with a new consensus-facing surface.

## Rejected Architectures

### Rejected: every miner is a full author and prover

This fails immediately against the target mining infrastructure. Worldwide Bitcoin hashpower is not operated by turning every rig into a full stateful author. That would throw away the existing pool, farm-controller, and Stratum operating model and replace it with something industrial miners will not adopt.

### Rejected: one public author forever

This is the current bootstrap shape. It is good enough to keep a testnet alive, but it is not the target. A single public author controls template construction, artifact selection, payout capture, and the public mining entry point. That is exactly the moat this redesign is supposed to remove.

### Rejected: two-stage block building as the target

A miner-visible bundle stage plus finalize stage is the wrong mental model for the industrial mining surface. It puts current-parent proof choreography too close to the compact hashing path. The architecture should let proofs happen ahead of time, then let template builders do only cheap parent-specific execution and header construction when the tip moves.

### Rejected: huge miner-facing templates

Full proof bytes and block bodies may be large, but the ASIC-facing job must remain small. If every mining round requires shipping large proof payloads to workers, the design has already lost the compatibility game.

### Rejected: miner identity as block-validity metadata

Per-rig or per-pool miner identity belongs in pool auth, farm control planes, or operator telemetry. It must not sit on the critical block-validity path for the fresh testnet.

### Rejected: consensus-managed share payouts

The protocol should pay winning blocks and artifact claims. It should not attempt to settle every pool worker share on-chain. That would entangle consensus with pool business logic and would not help permissionless base-layer participation.

## Surviving Architecture

The architecture that survives the clarified requirements is:

**permissionless template builders + public parent-agnostic candidate artifacts + compact ASIC-facing mining jobs + protocol-native artifact fees + optional pools and farm brokers on top**

That sentence has very specific meaning.

### Parent-agnostic artifact

A `CandidateArtifact` is a public proof object over an exact ordered transaction set. It binds the ordered tx set, the transaction-statement commitment, and whatever public proof payload is needed for the chain’s block-level proof model. It does **not** bind the current parent hash, current nullifier set root, or the resulting post-state root. Those parent-specific facts are handled by template builders and importers through deterministic execution.

### Permissionless template builders

Any full node that can:

- track the best parent,
- track the mempool,
- validate public artifacts,
- execute the selected tx set against the current parent,
- and serve compact mining jobs

is a template builder.

Template builders can be:

- independent public authoring nodes,
- pool operators,
- local farm controllers,
- or solo miners with enough infrastructure.

The protocol does not bless one of them as special.

### Compact mining jobs

The mining path that ASICs see is small. The mining job contains:

- the job ID,
- the header fields or midstate to hash,
- the compact target,
- time/version rolling rules,
- and stale-job signaling.

The ASIC never sees the full artifact bytes or full tx body. Those remain on the template-builder side of the line.

### Optional pools and brokers

Pools remain allowed and commercially useful. A pool or farm broker can smooth payouts, aggregate shares, switch upstream template builders, and expose Stratum-compatible endpoints to miners. That is fine because it is an application-layer business on top of the permissionless base, not a consensus requirement.

## What A Template Builder Does

The template builder is the adapter between the full-node/proof world and the hasher world.

Its responsibilities are:

1. Observe the current best parent and mempool.
2. Observe artifact announcements and fetch full artifact bytes on demand.
3. Choose an ordered tx set and a usable artifact for that tx set.
4. Execute the ordered tx set against the current parent state to confirm:
   - anchors are still valid,
   - nullifiers are not already spent,
   - fee and reward rules are satisfied,
   - the resulting state root is known.
5. Assemble the full block body, including the chosen artifact bytes and reward bundle.
6. Derive the compact mining job for ASICs and pooled hashers.
7. Serve jobs, accept shares, detect stale jobs, and broadcast full blocks when a winning solution arrives.

The template builder is not a prover. It does not need to create the heavy artifact itself. It only needs to choose and validate one.

## What A Farm Broker Does

The farm broker is optional but important for real mining operations.

It lives inside a mining farm or pool edge and does four things:

- talks upstream to one or more template builders,
- exposes a Stratum-compatible downstream surface to ASICs,
- fails over between upstream template builders without reconfiguring every rig,
- and optionally applies pool or farm business rules such as worker accounting and payout smoothing.

If a miner wants the protocol to avoid one central server, the farm broker is the answer: local control-plane decentralization on top of a permissionless public artifact market.

## Proposed Block Format

The fresh-testnet block format should be explicit.

The **header** carries only compact commitments and PoW material:

    Header {
      version,
      parent_hash,
      height,
      timestamp_ms,
      tx_set_commitment,
      artifact_hash,
      post_state_root,
      reward_commitment,
      pow_bits,
      pow_nonce,
      optional_miner_signature
    }

The **body** carries the actual data needed for deterministic import:

    Body {
      ordered_transactions,
      inline_candidate_artifact,
      reward_bundle
    }

The **public artifact** is reusable before inclusion:

    CandidateArtifact {
      artifact_id,
      tx_set_commitment,
      tx_statements_commitment,
      tx_count,
      da_root,
      proof_mode,
      proof_payload,
      claims_commitment
    }

The **artifact claims** define who gets paid when the artifact is included:

    ArtifactClaim {
      recipient_address,
      amount,
      artifact_id
    }

The **announcement** that moves around the network before inclusion is small:

    ArtifactAnnouncement {
      artifact_id,
      tx_set_commitment,
      tx_count,
      byte_size,
      transport_hints
    }

The **compact mining job** is what the ASIC or pool worker receives:

    CompactMiningJob {
      job_id,
      header_prefix_or_midstate,
      pow_target,
      time_bounds,
      rolling_mask,
      clean_jobs
    }

The important architectural line is this:

- the block body may still be large,
- the artifact market may still move large proof bytes between full nodes,
- but the miner-facing work item must remain small.

## State Boundary

The old design mixed parent-agnostic and parent-specific facts inside the same heavy proof object. This redesign does not.

The new `CandidateArtifact` should bind only facts that depend on the ordered transaction set itself:

- the transaction ordering,
- the transaction-statement commitment,
- the tx count,
- the data-availability commitment,
- the proof payload and proof mode,
- the claim commitment.

The following facts should be checked by deterministic execution during template building and import rather than being forced into a current-parent proof:

- whether each anchor is still valid for the current parent,
- whether nullifiers are already spent in the current parent state,
- what the resulting post-state root is,
- which parent hash the block extends.

This is the key move that lets artifacts remain reusable while still letting nodes reject invalid blocks at import.

## End-to-End Flow

The high-level system flow is:

1. A wallet creates a transaction and proves any private witness material locally.
2. The wallet broadcasts the transaction to the network.
3. Full nodes validate the transaction enough to mempool it and gossip it onward.
4. Provers observe profitable ordered tx sets and publish `ArtifactAnnouncement` metadata for matching `CandidateArtifact`s.
5. Template builders fetch promising artifacts, validate them, and keep them in a local cache.
6. When a new parent arrives, each template builder chooses a tx set and artifact for that parent, executes the tx set against the parent state, and builds a full block candidate.
7. The template builder serves a compact mining job to ASICs, pool workers, or farm brokers.
8. Hashers submit shares. A full-target solution turns the cached candidate into a real block.
9. The winning block is broadcast with the inline artifact.
10. Other nodes verify the artifact, execute the ordered tx set against the same parent, confirm the resulting state root and reward commitment, and import the block.

No part of that flow requires a single global author or a second proof-finalize round on the mining path.

## Bootstrap Test Topology

Before opening the network to outside miners and provers, test the basic architecture with three machines:

- **public template-builder node**: the first public full node plus template builder plus Stratum job server.
- **prover node**: a prover-only machine that runs a full node or artifact-aware client, watches the mempool, computes `CandidateArtifact`s, and publishes them.
- **laptop**: a wallet plus full node plus CPU miner or local broker used to verify the end-to-end user path.

All three machines must run the same fresh-testnet chain spec, the same approved seed list, and healthy NTP or chrony. For any shared mining environment, keep:

    HEGEMON_SEEDS="hegemon.pauli.group:30333,158.69.222.121:30333"

The point of this test topology is to prove the decoupling:

- the prover node proves but does not build jobs,
- the public template-builder node builds jobs but does not need to prove,
- `laptop` hashes and sends transactions without proving or authoring blocks.

### Basic closed-network smoke test

Run the first end-to-end test in this order:

1. Start the public template-builder node as a public full node and template builder. It should expose the compact mining-job surface publicly or to the test network, but it does not need local proving enabled.
2. Start the prover node and let it sync. It should subscribe to mempool traffic and artifact-announcement traffic.
3. Start `laptop` as a wallet and full node. Optionally also start a CPU miner or local broker that points at the public template-builder node.
4. Submit one shielded transaction from the wallet on `laptop`.
5. Verify that the prover node observes the candidate tx set, computes a `CandidateArtifact`, and announces it.
6. Verify that the public template-builder node fetches the artifact, validates it, executes the tx set against the current parent, and derives a compact job.
7. Verify that `laptop` receives only the compact job, hashes on it, and can submit shares or a full solution without downloading full artifact bytes.
8. Verify that if `laptop` or the public template-builder node finds a winning solution, the resulting block includes the inline artifact, imports cleanly, pays the artifact claim, and pays the miner reward.

The smoke test passes only if proving, template building, and mining are all visibly decoupled.

### Failure checks before opening the network

Before onboarding outside users, also verify the failure stories:

- If the prover node is offline, the public template-builder node still mines empty or smaller ready candidates rather than exposing unstable proof-wait jobs.
- If the public template-builder node is offline, the wallet on `laptop` still reaches the chain through other full nodes, and another template builder can be started without protocol changes.
- If the current parent changes while a cached artifact remains valid, the public template-builder node should rebuild a compact job without requiring a new proof round.

## Life Of A Transaction

The transaction lifecycle should be explicit in this plan because it is central to the new architecture.

### Stage 1: wallet creation

The wallet creates a shielded transaction and any local private proof material. At this stage, the transaction is portable and independent of any public prover market.

### Stage 2: mempool admission

Full nodes admit the transaction to the mempool if it passes ordinary stateless and bounded checks. The transaction is now visible to other full nodes, template builders, and provers.

### Stage 3: candidate-set formation

Template builders and provers independently notice that the transaction belongs to some ordered tx set that may be economically worth proving and mining. At this point nothing has been mined yet; the transaction is only a public candidate.

### Stage 4: artifact coverage

A prover creates a `CandidateArtifact` over an exact ordered tx set containing the transaction and announces that artifact to the network. The transaction is now artifact-covered for that exact ordered set.

### Stage 5: templating for a specific parent

A template builder sees a current parent `P`, checks whether the artifact-covered tx set is valid against `P`, and if so builds a full block candidate that includes the transaction. If the current parent makes the set invalid because of conflicts or expired anchors, the transaction remains in the mempool and waits for another candidate opportunity.

### Stage 6: hashing

ASICs and pooled hashers grind on the compact job derived from that candidate header. The transaction is now on the mining path, but miners still only see a compact job rather than full proof data.

### Stage 7: inclusion

If a full-target solution arrives first, the candidate becomes a real block and the transaction is included. If another block wins first, the job becomes stale. The transaction usually remains in the mempool unless the competing block consumed or invalidated it.

### Stage 8: confirmation

After block import, the transaction leaves the mempool and becomes part of the canonical state. Wallets eventually detect the new note commitments after syncing the updated chain state.

The key property is that parent changes do **not** force reproving as the default miner-visible workflow. They only cause template builders to reevaluate whether cached artifact-backed tx sets are still valid for the new parent.

## Join Stories

The permissionless property is easiest to understand as operator stories.

### Story 1: CPU miner without proving hardware joins

This is the default user story after launch.

The operator:

- downloads the correct fresh-testnet build,
- uses the published fresh-testnet chain spec,
- uses the same approved `HEGEMON_SEEDS` list as the rest of the network,
- enables NTP or chrony,
- chooses a public template-builder or pool endpoint,
- enters a payout address,
- starts hashing.

This miner does **not** ask anyone for a shared secret, whitelist entry, or proving slot. If they dislike one builder or pool, they can point at another one or run their own local broker. Their permissionless right is the freedom to join the mining market without needing proving hardware or operator approval.

### Story 2: prover-only operator joins

This is the default high-CPU or high-memory contributor story.

The operator:

- downloads the correct fresh-testnet build,
- syncs a full node or artifact-aware client on the public network,
- watches mempool and artifact-announcement traffic,
- chooses an economically attractive ordered tx set,
- computes a `CandidateArtifact`,
- publishes an `ArtifactAnnouncement`,
- serves the artifact bytes over the public artifact-fetch protocol.

They do not need a direct commercial relationship with any one template builder. If any builder includes the artifact in a winning block, the claim is paid by consensus. That is the permissionless prover story.

### Story 3: new template builder or pool joins

This is the decentralization story for operators who want to compete on the authoring side.

The operator:

- syncs a full node,
- enables the template-builder role,
- subscribes to the public artifact market,
- executes candidate tx sets against the current parent,
- serves compact mining jobs to its own miners or public customers.

It does not need to be blessed as “the author.” It becomes relevant if it builds good templates, relays quickly, and offers a good business surface to miners. Miners can switch to it without a consensus change.

### Story 4: mining farm runs a local broker

This is the realistic large-operator story.

The farm:

- runs one or more local brokers inside the farm network,
- connects those brokers to multiple upstream template builders,
- exposes one local Stratum endpoint to the ASIC fleet,
- uses the broker to fail over upstreams and manage local worker accounting.

That lets the farm keep its existing operational shape while avoiding dependence on one public server. The ASIC fleet stays dumb and does not need to know about proofs or the artifact market.

### Story 5: solo operator graduates from miner to builder

This is how the network stays permissionless over time.

A user may start as a CPU miner pointing at someone else’s builder. Later, if they want more control, they can run:

- a full node,
- a template builder,
- and optionally their own public or private miner fleet.

They do not need to become a prover first. They only need the ability to consume the public artifact market and build valid jobs. That is what removes the privileged-author moat.

## Crypto-Economic Model

This redesign creates three distinct markets. They must not be collapsed into one operator monopoly.

### Hashpower market

ASIC operators and pooled hash workers sell hashpower. They care about:

- compact jobs,
- low stale rate,
- predictable payouts,
- fast failover between upstreams,
- and not having to understand shielded-state or proof internals.

The protocol should respect that reality rather than trying to turn every miner into a full author.

### Template-building market

Template builders compete on:

- uptime,
- fast block relay,
- good mempool policy,
- low-latency artifact selection,
- good reward capture,
- and, for pools, attractive commercial payout products.

This is where today’s worldwide mining infrastructure already knows how to compete. Pools and farm brokers belong here, not in consensus.

### Artifact market

Provers compete to publish valid `CandidateArtifact`s. Their customers are template builders, pools, and solo authors. The chain pays artifact claims by consensus when the artifact is included in a winning block.

### Fee split

Each transaction must quote two fee buckets:

- `miner_fee`: paid to the winning block builder / miner side.
- `artifact_fee_cap`: the maximum budget available to artifact claims for the artifact-backed inclusion path.

The winning block is valid only if the included artifact claims total less than or equal to the sum of `artifact_fee_cap` across the chosen tx set.

The fresh-testnet default rule should be:

- the included artifact claims are paid by consensus,
- any unused artifact-fee budget falls to the winning block reward path rather than being burned.

That creates direct economic pressure for template builders to prefer cheaper valid artifacts, which in turn creates real price competition among provers.

### Pools remain optional overlays

Pools and farm brokers can still offer:

- PPS/FPPS-style smoothing,
- fixed or hedged payouts,
- internal share accounting,
- and worker management.

Those are business-layer features. They should remain off-chain and optional.

## Mining-Surface Constraints

The fresh testnet must satisfy all of the following if it wants the worldwide Bitcoin mining stack to be a plausible future consumer of the protocol:

- The PoW function and header hashing path must be genuinely Bitcoin-style SHA-256 compatible. No BLAKE3 mining shortcuts on the main surface.
- The miner-facing work item must remain compact and Stratum-friendly.
- The winning block may carry large proof material, but the mining job must not.
- Template refresh on a new parent must be cheap enough that the mining path does not become a proof-waiting multiround loop.
- Miner identity must not be required in the validity path.
- Pools and farm brokers must be able to sit on top without becoming consensus dependencies.

## Plan of Work

This redesign is large enough that it must be implemented in explicit milestones. Each milestone should produce a testable, observable behavior.

### Milestone 1: cut the fresh-testnet consensus and mining surface

The first milestone creates the new chain surface. Update `consensus/spec/block_header.md`, `consensus/spec/consensus_protocol.md`, `DESIGN.md`, and `METHODS.md` so the fresh testnet uses Bitcoin-style SHA-256-compatible header mining, compact-target fields, and no miner-identity requirement in block validity. In code, remove the BLAKE3 mining shortcut from `consensus/src/substrate_pow.rs` and the mandatory miner-signature / validator-set path from `consensus/src/pow.rs` and the runtime validity path. The result of this milestone is simple: a fresh-testnet node can mine blocks without any miner ML-DSA identity being required in consensus, and the compact hashing path is the one real mining surface.

Acceptance for this milestone is behavioral. Start a fresh-testnet node, mine a block through the new PoW surface, and verify that block validity depends on the compact target and header hash only. An invalid or missing optional miner signature must not make an otherwise valid PoW block fail import.

### Milestone 2: replace `BlockProofBundle` with `CandidateArtifact`

The second milestone defines the new artifact market. In `pallets/shielded-pool/src/types.rs`, replace the current block-proof payload model with `CandidateArtifact`, `ArtifactClaim`, and the new reward-commitment surface. In `node/src/substrate/service.rs` and the importer path, change block verification so the inline artifact is verified against the ordered tx set and deterministic execution against the current parent computes `post_state_root`. The result is that a proof object can be produced ahead of time over an ordered tx set and then reused across different parents until conflicts invalidate that set.

Acceptance for this milestone is that the same `CandidateArtifact` can be accepted as the proof object for more than one parent candidate during local testing, provided the ordered tx set still passes deterministic execution against each parent.

### Milestone 3: add permissionless template builders

The third milestone creates the new template-builder role. Add `node/src/substrate/template_builder.rs` and supporting wiring so any full node can track the tip, mempool, and artifact cache; choose the best artifact-backed tx set; execute it against the current parent; and derive a compact mining job plus a fully cached block body. This milestone must also remove any “wait for proof bytes while miners hash” behavior from the mining path. If no artifact-backed candidate is ready, the builder either mines an artifact-free/empty candidate or waits for the next valid ready candidate. It must not expose unstable proof-wait jobs to hashers.

Acceptance for this milestone is that two independent nodes can run as template builders on the same fresh testnet, observe the same public artifact, and each derive its own valid compact mining jobs without sharing a secret or depending on one designated author.

### Milestone 4: expose a real miner-facing job surface and an optional farm broker

The fourth milestone puts the compact mining job on a real operator surface. Add a Stratum-compatible job server to the template-builder path and add a new optional local broker binary or module that can connect to multiple upstream template builders and serve one downstream farm endpoint. The first version can be Stratum V1-compatible if that lowers implementation risk, but the interface must remain compact-job-first and must not expose full proof material to miners. The result is that a mining farm can point dumb hashers at a local endpoint while that local endpoint chooses or fails over between multiple permissionless template builders.

Acceptance for this milestone is that a broker can switch between two upstream builders without requiring ASIC reconfiguration and without miners ever downloading full block bodies or artifacts.

### Milestone 5: retire centralized-author assumptions from the product and runbooks

The fifth milestone finishes the social layer. Update `runbooks/authoring_pool_upgrade.md`, `runbooks/miner_wallet_quickstart.md`, `hegemon-app/src/App.tsx`, and any related docs or UI so the public story is no longer “one public author with private proving forever.” Pools remain allowed, but the base protocol should now be described as permissionless template builders plus public provers plus optional pools/brokers. Keep `HEGEMON_SEEDS` and NTP/chrony guidance explicit in every operator-facing mining path, and make it clear that all miners on the same network must use the same approved seed list.

Acceptance for this milestone is that the docs and UI no longer imply that public mining depends on one special authoring node, while still making clear that pooled hashing and farm brokers are valid overlays for payout smoothing and operations.

## Concrete Steps

These are the exact commands and checkpoints the implementer should wire into the milestones above. Run them from the repository root unless otherwise stated.

1. Build and test the workspace before cutting the new surface:

       make setup
       make node
       cargo test --workspace

   This establishes a clean baseline before the fresh-testnet branch diverges from the current chain surface.

2. After Milestone 1 lands, verify the new mining surface:

       cargo test -p consensus
       cargo test -p node

   Add focused tests for:

       cargo test -p consensus --test pow_sha256_surface
       cargo test -p consensus --test optional_miner_signature

3. After Milestone 2 lands, verify artifact reuse and deterministic execution:

       cargo test -p node --test candidate_artifact_reuse
       cargo test -p node --test candidate_artifact_import

   The first test must prove that one artifact can back multiple parent candidates until a conflict invalidates it.

4. After Milestone 3 lands, run two local template builders and one prover on the fresh testnet:

       export HEGEMON_SEEDS="hegemon.pauli.group:30333,158.69.222.121:30333"
       export HEGEMON_MINER_ADDRESS="<fresh-testnet-shielded-address-a>"
       HEGEMON_TEMPLATE_BUILDER=1 ./target/release/hegemon-node --chain fresh-pqc-testnet --base-path /tmp/hegemon-tb-a --port 30333 --rpc-port 9944

       export HEGEMON_MINER_ADDRESS="<fresh-testnet-shielded-address-b>"
       HEGEMON_TEMPLATE_BUILDER=1 ./target/release/hegemon-node --chain fresh-pqc-testnet --base-path /tmp/hegemon-tb-b --port 30334 --rpc-port 9945

       HEGEMON_PROVER_RPC_URL=http://127.0.0.1:9944 ./target/release/<prover-worker-binary>

   The exact flags may change during implementation, but the observable target is fixed: both builders must independently surface compact jobs derived from public artifacts.

5. After Milestone 4 lands, run the farm broker against two upstream builders:

       cargo build --release -p hegemon-farm-broker
       ./target/release/hegemon-farm-broker --listen 127.0.0.1:3333 --upstream stratum://127.0.0.1:3334 --upstream stratum://127.0.0.1:3335

   Add focused tests for:

       cargo test -p node --test template_builder_job_flow
       cargo test -p node --test farm_broker_failover

6. Keep the mining network healthy during every step:

       export HEGEMON_SEEDS="hegemon.pauli.group:30333,158.69.222.121:30333"

   Also keep NTP or chrony enabled on every mining host because future-skewed PoW timestamps are rejected.

## Validation and Acceptance

The redesign is successful only when all of the following are true on the fresh testnet.

### Behavioral acceptance

1. Two independent template builders can run on the same network without a shared secret or one privileged author designation.
2. One external prover can publish a public `CandidateArtifact` that either template builder can use.
3. A mining farm or local broker can receive compact jobs from a template builder without downloading full proof bytes.
4. ASIC-facing or simulated miner-facing work remains compact and stable during the hashing window.
5. A winning block carries the chosen artifact inline and imports deterministically against the parent state.
6. Artifact claims are paid by consensus when that artifact is included.
7. The winning block reward path can still be mapped to a single miner/pool payout address, while pool share accounting remains off-chain and optional.
8. If one template builder disappears, another one can continue building jobs from the same public artifact market.
9. If a parent changes before a candidate wins, the transaction normally returns to the mempool or is reconsidered under cached artifact coverage; the miner path does not become a mandatory multi-proof finalize loop.

### Regression acceptance

The old centralized path is considered retired only when:

- the fresh-testnet consensus surface no longer depends on BLAKE3 mining,
- miner signatures are not required in block validity,
- the docs no longer present one public author as the normal long-term architecture,
- and the compact mining surface is separate from the heavy proof/artifact surface.

### Performance acceptance

This redesign is acceptable only if the hashing path preserves a real stable-work window. The pass condition is not “a block can eventually be mined.” The pass condition is:

- a new parent arrives,
- a template builder can choose a ready artifact-backed candidate,
- the compact job reaches miners,
- miners retain a meaningful stable hash window before the next expected parent.

If the measured stale rate or stable-work window is unacceptable at the current target block time, do not reintroduce two-stage miner-visible proof choreography. Increase the block interval or shrink the artifact-critical-path cost explicitly.

## Idempotence and Recovery

This plan is intentionally written for a fresh testnet so that the implementation can be retried safely.

- If a milestone fails, keep the last working fresh-testnet chain spec and do not partially backport the change to the current chain.
- The old `BlockProofBundle` and pooled-mining RPC surface may remain behind bootstrap or legacy feature flags for comparison and recovery, but they must not remain the default fresh-testnet path once the new surface exists.
- The first winning-block path should keep artifacts inline in blocks so import remains deterministic even if pre-block artifact caches are incomplete.
- A template builder that has no ready artifact-backed candidate should mine an empty or smaller ready candidate rather than exposing unstable proof-wait jobs to ASICs.

## Artifacts and Notes

The most important facts that shaped this plan are:

    The current Substrate mining shortcut is not Bitcoin-infrastructure-compatible because it still hashes blake3(pre_hash || nonce).
    The current consensus path still requires miner identity material for validity.
    The current public miner story already assumes pooled hashing against template providers.
    The repository already has external proving work packages, so proof generation can be detached from one local prover.
    The new target is a fresh testnet, so compatibility debt should not be allowed to dictate the architecture.

The plan also keeps the operator invariants already established elsewhere in the repository:

    HEGEMON_SEEDS="hegemon.pauli.group:30333,158.69.222.121:30333"

All miners on the same network must use the same approved seed list to avoid partitions and forks, and all mining hosts must keep NTP or chrony enabled because future-skewed timestamps are rejected.

## Interfaces and Dependencies

The following interfaces must exist by the end of the redesign.

In consensus-facing proof types, define:

    pub struct CandidateArtifact { ... }
    pub struct ArtifactClaim { ... }
    pub struct ArtifactAnnouncement { ... }
    pub struct CompactMiningJob { ... }

In the template-builder path, define:

    pub trait TemplateBuilder {
        fn build_best_candidate(&self, parent_hash: H256) -> Result<BlockTemplate, Error>;
        fn current_job(&self) -> Option<CompactMiningJob>;
        fn submit_solution(&self, job_id: [u8; 32], nonce: [u8; 32]) -> Result<Block, Error>;
    }

In deterministic validation, define:

    pub fn validate_candidate_artifact(
        artifact: &CandidateArtifact,
        transactions: &[Transaction],
    ) -> Result<(), Error>;

    pub fn execute_candidate_set_against_parent(
        parent_state: &StateSnapshot,
        transactions: &[Transaction],
        artifact: &CandidateArtifact,
    ) -> Result<ExecutionResult, Error>;

In the mining surface, define:

    pub fn derive_compact_job(template: &BlockTemplate) -> CompactMiningJob;
    pub fn encode_stratum_job(job: &CompactMiningJob) -> StratumMessage;

The primary repository touch points are:

- `consensus/spec/block_header.md`
- `consensus/spec/consensus_protocol.md`
- `consensus/src/substrate_pow.rs`
- `consensus/src/pow.rs`
- `runtime/src/lib.rs`
- `pallets/shielded-pool/src/types.rs`
- `node/src/substrate/service.rs`
- `node/src/substrate/rpc/prover.rs`
- `node/src/substrate/rpc/hegemon.rs`
- `node/src/substrate/template_builder.rs` (new)
- `node/src/substrate/artifact_market.rs` (new)
- `node/src/substrate/stratum.rs` or equivalent mining-job server surface (new)
- `runbooks/miner_wallet_quickstart.md`
- `runbooks/authoring_pool_upgrade.md`
- `hegemon-app/src/App.tsx`

No interface in the final architecture may require:

- one privileged public author node,
- a mandatory second proof-finalize round on the mining path,
- miner ML-DSA identity for block validity,
- or on-chain pool share settlement.

## Change Note

2026-03-11: rewritten after the target was clarified. The plan now assumes a fresh testnet and is built around worldwide Bitcoin-style mining infrastructure, parent-agnostic public `CandidateArtifact`s, permissionless template builders, compact ASIC-facing jobs, optional pools and farm brokers, and deterministic parent-specific execution during import instead of two-stage block building.
