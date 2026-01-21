# Cold Archive + Wallet Recovery: Multi‑Year Notes Without Forcing Full Nodes to Store Everything

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds.

Reference: repository root `.agent/PLANS.md` defines the ExecPlan format and maintenance requirements. Every update to this file must remain consistent with that guidance.

## Purpose / Big Picture

Make Hegemon usable for real commerce over long time horizons by enabling multi‑year wallet recovery without requiring every consensus node to store ciphertext data forever.

This plan complements hot data availability (DA) by introducing a “cold archive” market:

- Hot DA: enforced, short window, required for block acceptance.
- Cold archive: opt-in, priced, multi-year retention, used for recovery.

After this work, a user can:

1. Receive funds while offline longer than the hot DA window (weeks/months).
2. Come back later, pick an archive provider, and recover ciphertexts needed to discover/decrypt incoming notes.
3. Rely on protocol-enforced incentives (not just goodwill) that archive providers actually store and serve data.

The “it works” proof is:

- On devnet, after hot DA pruning, a wallet can still recover its notes by querying an archive provider.
- A misbehaving archive provider can be challenged and penalized on-chain.

## Progress

- [x] (2026-01-21T00:00Z) Draft cold archive + recovery ExecPlan (this file).
- [ ] Define the recovery contract: exactly what data is covered, what is paid for, what is guaranteed, and what is not.
- [ ] Implement archive provider registration + bonding on-chain.
- [ ] Implement archive contracts (purchase, renewal, expiration).
- [ ] Implement challenge/response auditing using DA chunk proofs (slash on failure).
- [ ] Implement wallet/RPC integration for selecting providers and retrieving ciphertext ranges.
- [ ] End-to-end demo: prune hot DA, recover via archive provider, decrypt notes.

## Surprises & Discoveries

- Observation: The node currently stores DA data in-memory only, so “retention” is not real yet and must be implemented before archive contracts are meaningful.
  Evidence: `node/src/substrate/service.rs` defines `DaChunkStore` as an in-memory LRU with small capacity.

Update this section after hot DA is implemented and we can meaningfully test archive retrieval.

## Decision Log

- Decision: Make cold archival an explicit market with explicit pricing and explicit guarantees, not an implicit “full nodes keep everything.”
  Rationale: PQ private commerce generates large ciphertext streams. Forcing every consensus node to store multi‑year data centralizes the network. Pricing and specialization are the only credible path.
  Date/Author: 2026-01-21 / Codex

- Decision: Enforce archive provider behavior with a challenge/response audit mechanism built on existing DA chunk proofs.
  Rationale: “Proving non-response” is hard, but we can prove “can respond to random challenges.” If a provider cannot produce valid chunk proofs for randomly chosen indices over time, they are not storing/serving data reliably and should lose their bond.
  Date/Author: 2026-01-21 / Codex

- Decision: Keep the archive market interface generic so that external storage networks can participate as providers without being protocol requirements.
  Rationale: The protocol should specify requirements (what must be retrievable, how to verify) and incentives. Providers can be a local node, a dedicated service, or an adapter to an external network. The chain should not depend on a single external DA vendor.
  Date/Author: 2026-01-21 / Codex

## Outcomes & Retrospective

Not started. Update after the first successful recovery demo and the first successful slashing demo.

## Context and Orientation

Why recovery is hard in a PQ private chain:

- Wallets need ciphertexts to discover incoming notes and extract note secrets.
- If ciphertexts are pruned after a hot DA window, a wallet that was offline longer cannot recover by “just scanning the chain,” because the chain no longer carries ciphertext bytes.

What we already have to build on:

- A DA commitment (`da_root`) and a chunk proof system (`state/da`).
- A DA chunk request/response protocol in the node (`node/src/substrate/network_bridge.rs`) and an RPC method (`da_getChunk`).

What cold archival must add:

- A way to pay someone to keep serving old DA data.
- A way to verify (and enforce) that they continue serving it.
- A wallet flow that can switch from “hot DA from peers” to “cold archive provider” when needed.

Define “archive contract” in plain language:

- A user buys a promise: “for roots in range [H_start, H_end], data is retrievable until time T_end.”
- The provider posts a bond. If they fail audits, they lose some or all bond.
- The user pays a fee that is priced in bytes and time.

## Plan of Work

### Milestone 1: Define the archive interface and threat model

Goal: decide what “archive provider” must do, and what attacks we are preventing.

Work:

- Define exactly what data an archive provider must serve:
  - Option A: raw ciphertext bytes in transaction order for each block.
  - Option B: DA chunks + proofs (preferred, because it composes with DA encoding).
- Pick Option B: provider must serve `(da_root, global_chunk_index) -> chunk_bytes + proof` and optionally a “ciphertext range” convenience API built on top.
- Define the minimal audit statement:
  - “Given a random challenge (root, index), provider can return a valid chunk proof within D blocks.”
- Define the privacy goal:
  - Archive provider must not learn *which notes* a wallet owns, but it may learn *which block ranges* the wallet requests. This is an acceptable baseline; stronger PIR-style retrieval is out of scope for the first version.

Acceptance:

- The decision and definitions above are recorded in this ExecPlan, and the next milestones use them consistently.

### Milestone 2: Implement on-chain provider registry + bonds

Goal: providers can register, post bonds, and be discoverable by wallets.

Work:

- Add a new pallet (example name `pallet_archive_market`) with storage:
  - provider id (AccountId or PQ identity hash),
  - bond amount,
  - advertised price parameters (per-byte-per-block, minimum duration),
  - and service endpoints (opaque bytes; wallet interprets off-chain).
- Implement extrinsics:
  - `register_provider(params, bond)`
  - `update_provider(params)`
  - `unregister_provider()` (only after all contracts expire)

Acceptance:

- On devnet, providers can register and are visible via an RPC query.

### Milestone 3: Implement archive contracts (purchase + renewal + expiration)

Goal: users can buy retention for a range of DA roots.

Work:

- Define a contract object keyed by `(provider_id, contract_id)` storing:
  - covered block range or DA root range,
  - expiration block,
  - paid amount,
  - and remaining bond at stake for that contract.
- Implement extrinsics:
  - `buy_contract(provider_id, start_block, end_block, duration_blocks, max_price)`
  - `renew_contract(contract_id, additional_duration, max_price)`
  - `cancel_contract(contract_id)` (optional; refunds are policy-specific)

Acceptance:

- A devnet demo creates and renews a contract and shows storage state changes.

### Milestone 4: Implement auditing and slashing with DA chunk challenges

Goal: make “provider keeps data” enforceable.

Work:

- Add an on-chain audit scheduler:
  - Every `AUDIT_PERIOD` blocks, pick random `(contract, root, index)` challenges derived from block hashes (simple on-chain randomness).
  - Store challenges with a deadline `challenge_deadline = now + AUDIT_RESPONSE_WINDOW`.
- Add an extrinsic:
  - `respond_to_challenge(challenge_id, da_chunk_proof)` where `da_chunk_proof` is verifiable against the committed root using `state/da` verification logic (multi-page aware).
- If deadline passes without a valid response:
  - slash provider bond for that contract,
  - optionally pay a portion to the challenger / to treasury,
  - mark the contract as “failed” so wallets stop relying on it.

Important: do not attempt to “prove non-response” off-chain. The chain only needs to enforce “respond by deadline or lose bond.”

Acceptance:

- A test demonstrates:
  - provider responds with a valid proof and passes,
  - provider fails to respond and is slashed.

### Milestone 5: Wallet/RPC integration for recovery

Goal: wallets can use archive providers when hot DA is pruned.

Work:

- Add RPC methods:
  - `archive_listProviders()`
  - `archive_listContracts(provider_id)`
  - `archive_getCiphertexts(provider_id, start_index, limit)` (convenience; implemented by provider service off-chain)
- Update wallet sync logic:
  - If hot DA fetch fails for older blocks, fall back to configured archive provider(s).
  - Keep the wallet’s viewing keys local; the wallet only requests ciphertext ranges, not note identifiers.

Acceptance:

- A dev scenario:
  - Mine blocks with incoming notes to a wallet.
  - Prune hot DA on the node.
  - Wallet still recovers notes via archive provider RPC.

## Concrete Steps

From the repository root:

0. If this is a fresh clone, install toolchains first:

    make setup

1. Implement and validate hot DA first (this plan depends on it):

    Follow `.agent/DA_SIDECAR_HOT_AVAILABILITY_EXECPLAN.md` through the “persistent hot retention store” milestone.

2. Add the archive market pallet and tests; run:

    cargo test -p pallet-archive-market
    cargo test --workspace

3. Run a dev node and register a provider; then create an archive contract.

4. Run the recovery demo scenario and record the outputs in this file.

## Validation and Acceptance

Final acceptance for this plan:

1. A wallet can recover notes after hot DA pruning by using an archive provider.
2. Providers are incentivized and enforceable: failing audits triggers slashing.
3. The archive market is optional: the chain remains live and secure without any archive providers (but recovery beyond the hot window becomes a user choice).

## Idempotence and Recovery

- Contracts and challenges must be safe to replay and safe to resume after node restarts.
- On devnet, provide a single “wipe everything” procedure (delete chain db + DA store + archive provider store + wallet db).
- If auditing produces too much chain load, reduce `AUDIT_PERIOD` or challenge batch sizes and record the change in `Decision Log`.

## Artifacts and Notes

Record here:

- A transcript showing a contract purchase and a successful audit response.
- A transcript showing a failed audit and slashing.
- A transcript showing wallet recovery after hot DA pruning.

## Interfaces and Dependencies

At the end of this plan, the repo must include:

- A pallet implementing provider registry, contracts, challenges, and slashing.
- A verification function callable from the runtime (native) that checks DA chunk proofs against `da_root` (multi-page aware).
- Wallet-facing RPCs for provider discovery and ciphertext retrieval.
