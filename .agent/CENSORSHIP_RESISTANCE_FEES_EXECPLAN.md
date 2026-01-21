# Censorship Resistance + Fees: Align Incentives Without Killing Privacy

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds.

Reference: repository root `.agent/PLANS.md` defines the ExecPlan format and maintenance requirements. Every update to this file must remain consistent with that guidance.

## Purpose / Big Picture

Make Hegemon’s transaction inclusion rules and fee mechanics compatible with private commerce at scale.

This plan is about alignment: if the fee market rewards “public bidding” and miner/sequencer discretion, privacy collapses into MEV (front-running and censorship become profitable, and users reveal intent by bidding). If the fee market does not pay for real costs (DA bytes, proving work, storage), the chain becomes unreliable and centralized.

After this work, a developer can:

1. Estimate fees for a shielded transfer from public parameters (bytes, retention policy, proof verification policy) without interacting with an auction.
2. Submit shielded transfers and observe deterministic inclusion ordering within blocks (no “who paid a higher tip gets in first”).
3. Use a “forced inclusion” path to prevent censorship by a single sequencer or miner, with explicit DoS resistance.

The “it works” proof is:

- A devnet run where blocks show deterministic ordering for shielded transfers.
- A devnet run where a forced-inclusion commitment results in the corresponding transfer being included within a bounded window.
- Wallet tooling can quote fees from RPC without scanning mempools or participating in auctions.

## Progress

- [x] (2026-01-21T00:00Z) Draft censorship resistance + fees ExecPlan (this file).
- [ ] Confirm the current fee accounting path for shielded transfers (what is enforced vs. only emitted as events).
- [ ] Define a protocol fee schedule that prices (a) DA bytes, (b) proof verification, and (c) retention time, and implement it for devnet.
- [ ] Implement deterministic ordering rules for shielded transfers inside a block (consensus-enforced).
- [ ] Implement a forced inclusion mechanism with DoS bounds.
- [ ] Add wallet/RPC support for fee quoting and forced inclusion flow.
- [ ] End-to-end demo: censoring miner/Sequencer fails to exclude a forced-inclusion transfer.

## Surprises & Discoveries

- Observation: Shielded transfer calls carry `fee` / `total_fee` fields, but fee *payment* is not obviously enforced at the pallet level; events exist, but “who gets paid” needs auditing.
  Evidence: `pallets/shielded-pool/src/lib.rs` emits `BatchShieldedTransfer { total_fee }` but the shown batch path only stores nullifiers/commitments and updates the Merkle tree.

Update this section after auditing coinbase + fee flows end-to-end.

## Decision Log

- Decision: Use a base-fee style schedule (deterministic, protocol-computed) instead of a public priority auction for the private transaction lane.
  Rationale: Public priority bidding reveals user urgency and often correlates with transaction value. It also incentivizes miners/Sequencers to reorder and censor for profit. Deterministic base fees keep privacy intact while still paying for costs.
  Date/Author: 2026-01-21 / Codex

- Decision: Price DA explicitly as `bytes × retention_time`, and make that cost visible to wallets.
  Rationale: For PQ private transfers, ciphertext bandwidth and storage dominate. If fees do not price DA, the chain will either centralize (only a few nodes can afford to serve data) or become unusable (data is missing).
  Date/Author: 2026-01-21 / Codex

- Decision: Add forced inclusion as an explicit protocol feature rather than hoping “competition among miners” solves censorship.
  Rationale: World commerce requires credible liveness even under adversarial participants. A forced inclusion mechanism creates a hard backstop against sequencer or miner censorship, at the cost of bounded on-chain load.
  Date/Author: 2026-01-21 / Codex

## Outcomes & Retrospective

Not started. Update after deterministic ordering and forced inclusion are live on devnet.

## Context and Orientation

Actors and where censorship happens:

- On the L1, miners choose which transactions to include in blocks. Even with PoW, a large miner (or cartel) can censor.
- In a rollup architecture, sequencers choose ordering and can censor long before L1 sees anything.

We need two lanes:

- A “high-throughput private lane” (rollup batches) that is optimized for throughput and privacy, and uses deterministic fees.
- A “censorship escape hatch” lane (forced inclusion) that allows a censored user to get a transaction commitment onto L1 and force it into the rollup within a bounded time.

Definitions (plain language):

- “Base fee”: a protocol-defined minimum fee for inclusion, computed from measurable costs and recent demand. It is not negotiated per transaction.
- “Tip”: an extra fee paid to jump the queue. This plan avoids tips for the private lane because they leak information and create MEV incentives.
- “Forced inclusion commitment”: a small on-chain object (a hash) that commits to a transaction or to a rollup input, and carries enough fee/bond to prevent spam.

Where to look in the repo today:

- Block size/time constraints: `runtime/src/lib.rs` (`RuntimeBlockLength`, `PowTargetBlockTime`).
- Shielded transfer execution and events: `pallets/shielded-pool/src/lib.rs`.
- Transaction propagation and mempool behavior: `node/src/substrate/service.rs` (custom tx propagation task).
- Settlement-style batching (potential hook for rollup sequencing incentives): `pallets/settlement/src/lib.rs`.

## Plan of Work

### Milestone 1: Make fee payment explicit and enforceable (L1 baseline)

Goal: stop pretending fees exist; make them real and measurable.

Work:

- Audit the existing shielded transfer flows to answer:
  - Where is `fee` accounted?
  - How does it reach miners (if at all)?
  - Does a malicious sender get inclusion without paying a miner?
- Implement an explicit “fee sink” for shielded transfers that is compatible with a shielded pool:
  - Option A: fees are accumulated in a per-block bucket and paid to the miner via the shielded coinbase note.
  - Option B: fees are burned (anti-spam) and miners are paid only by subsidy. This is simpler but reduces long-term miner incentives.
- Pick one option, implement it, and add a unit/integration test that proves fees are either paid or burned deterministically.

Acceptance:

- A test demonstrates that a transfer with fee `f` causes the miner payout or the burn counter to change by exactly `f`.

### Milestone 2: Define and implement a base fee schedule for private transfers and rollup batches

Goal: wallets can quote fees without a public auction.

Work:

- Define the fee model as a sum of objective costs:
  - `fee = fee_proof + fee_da + fee_retention`
- Define `fee_proof` as a function of verification cost (measured in time or weight) for the relevant proof type (tx proof, batch proof, or rollup proof).
- Define `fee_da` as `bytes_published × price_per_byte`.
- Define `fee_retention` as `bytes_published × hot_window_blocks × price_per_byte_block` (or an equivalent).
- Implement the fee schedule as runtime constants plus a governance-updatable parameter set, and expose an RPC method `fee_quote` for the wallet.

Acceptance:

- Wallet can call an RPC method and get an exact fee quote for a given “bundle size” without consulting the mempool.

### Milestone 3: Consensus-enforced deterministic ordering inside blocks

Goal: remove miner discretion that creates MEV opportunities for the private lane.

Work:

- Define an ordering rule for shielded transfers within a block that is:
  - deterministic,
  - based only on committed data (e.g., transaction hash or proof hash),
  - and cheap to check during import.
- Enforce it as a consensus rule in the node’s block import pipeline:
  - Reject blocks that contain shielded transfers out of order.
  - (If needed) enforce ordering only within the private lane portion of the block, not for all extrinsics.

Acceptance:

- A dev block built with out-of-order transfers is rejected during import with a clear error.

### Milestone 4: Forced inclusion commitments (anti-censorship escape hatch)

Goal: a censored user has a credible path to get included.

Work:

- Add a new pallet (or extend an existing one) that stores a bounded queue of forced-inclusion commitments:
  - Each commitment includes: `tx_commitment_hash`, `expiry_block`, and a `bond`.
  - The bond is forfeited if the commitment is invalid or expires unused. This prevents DoS.
- Define a rule for how forced-inclusion commitments are “satisfied”:
  - For L1 direct inclusion: the committed transaction must appear in a block before expiry.
  - For rollup inclusion: the committed rollup input must appear in a posted rollup batch before expiry.
- Define a penalty if miners/sequencers ignore forced inclusions:
  - Option A (strict): blocks are invalid if they ignore satisfiable forced inclusions. This is powerful but can be DoS’d without careful bounds.
  - Option B (economic): a bond posted by the sequencer is slashed if forced inclusions are missed. This requires sequencer identities and bonds.
- Implement the minimal safe version:
  - Keep the forced-inclusion queue small and rate-limited.
  - Require fees/bonds high enough to price block space and verification.

Acceptance:

- A dev test demonstrates: submitting a forced-inclusion commitment and then submitting the committed transaction results in inclusion within the promised window.

## Concrete Steps

From the repository root:

0. If this is a fresh clone, install toolchains first:

    make setup

1. Locate current fee handling for shielded transfers:

    rg -n \"total_fee|fee\" pallets/shielded-pool/src/lib.rs

2. Start a dev chain and submit a transfer; inspect events for fee accounting:

    HEGEMON_MINE=1 ./target/release/hegemon-node --dev --tmp

3. After implementing Milestones 1–4, add an end-to-end script under `scripts/` that:
  - submits multiple transfers,
  - forces a particular one via forced inclusion,
  - and asserts ordering + inclusion in logs.

## Validation and Acceptance

Final acceptance for this plan:

1. Fees are enforceable and paid/burned deterministically.
2. Wallet fee quotes come from deterministic on-chain parameters (no auction participation required).
3. Private-lane ordering inside blocks is deterministic and consensus-enforced.
4. A forced inclusion mechanism exists, is DoS-bounded, and demonstrably defeats simple censorship on devnet.

## Idempotence and Recovery

Forced inclusion must be safe to retry:

- Re-submitting the same commitment should be rejected or idempotent.
- Expired commitments must be pruned automatically.
- Devnet resets must document how to wipe commitment queues and wallet state.

## Artifacts and Notes

Record here:

- A test output or log excerpt showing fee payment/burn.
- A rejection log for out-of-order private transactions.
- A forced inclusion demo transcript (commitment submitted, then included).

## Interfaces and Dependencies

At the end of this plan, the repo must include:

- A runtime-stored fee parameter set (base prices for proof verification and DA bytes) plus an RPC that returns quotes.
- A consensus-enforced ordering rule for the private lane (implemented in node import).
- A forced inclusion commitment interface (pallet + RPC + wallet CLI integration).
