# CashVM ↔ Hegemon Bridge: PQ Activity‑Aggregating STARK Covenant (CashVM 2026)

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds.

Reference: repository root `.agent/PLANS.md` defines the ExecPlan format and maintenance requirements. Every update to this file must remain consistent with that guidance.

## Purpose / Big Picture

Build a *post‑quantum*, *non‑custodial*, *competitive‑aggregator* “validity rollup” on 2026 CashVM using only standard transactions and no further consensus changes. Users generate large, non‑aggregated STARK proofs on device, lock funds + an aggregation fee into intent UTXOs, and any aggregator can advance the covenant by publishing an on-chain transaction that verifies a single aggregated/recursive STARK proof and updates the rollup state.

“Bridge CashVM and Hegemon” means: the *same privacy semantics* (notes, commitments, nullifiers, join–split) are implemented in both environments, and the same proof artifacts can be verified by Hegemon’s Rust verifier while CashVM enforces the settlement/custody via covenants. The bridge does not introduce rent extraction: aggregators are replaceable, unpermissioned, and paid only by explicit per‑activity fees attached to intent UTXOs.

After this work, a developer can:

1. Produce a user “activity proof” (large, non‑aggregated) for a deposit / transfer / withdrawal intent.
2. Produce a recursive aggregated proof for a batch of intents.
3. Construct a CashVM‑standard covenant transaction that spends the rollup state UTXO + those intent UTXOs, pays fees, emits withdrawals, and creates the next state UTXO.
4. Verify locally (in a Rust harness) that the CashVM covenant bytecode accepts the transaction, and that tampering with any intent/output causes rejection.
5. (Optional bridge demo) Submit the same aggregated proof to a Hegemon devnet and observe that it verifies and advances a mirror “CashVM rollup state root” stored on Hegemon.

## Progress

- [x] (2026-01-23T16:00Z) Draft CashVM↔Hegemon STARK covenant ExecPlan (this file).
- [x] (2026-01-24T00:00Z) Clarified “cacheable success” note to avoid implying “rejection is forever”; timelock-style rejections can become valid later, while success remains stable unless double-spent.
- [ ] Pin down the *exact* 2026 CashVM standardness limits to enforce in tests (transaction size, per-input unlocking bytecode, any limits on pushdata/witness, and any “density” execution caps).
- [ ] Prototyping: add a Rust “CashVM transaction + script” harness under `spikes/cashvm-covenant/` that can execute the covenant bytecode against a fully-resolved spending transaction.
- [ ] Define the rollup state format, intent format, and canonical digests (hashes) used to bind proofs to on‑chain data.
- [ ] Implement the user activity proof public inputs and aggregation proof public inputs needed by the covenant.
- [ ] Prototyping: generate a covenant verifier bytecode candidate and assert it stays under 10KB unlocking bytecode in the harness.
- [ ] Implement single-transaction (sub‑100KB) verification path; add the multi‑transaction proof-fragment fallback with atomic final commit (no covenant DoS).
- [ ] End-to-end demo: create N intents (including at least one deposit + one withdrawal), aggregate, and pass the covenant validation harness.
- [ ] (Optional) Hegemon bridge demo: mirror the CashVM state root in a Hegemon pallet and accept updates proven from CashVM transactions.

## Surprises & Discoveries

- Observation: Current Hegemon non-aggregated transaction proofs are on the order of hundreds of kilobytes; CashVM standardness caps require the *on‑chain* proof to be either much smaller or verified across multiple simultaneous transactions.
  Evidence: `circuits-bench --smoke --json --prove` in `.agent/WORLD_COMMERCE_SCALABILITY_EXECPLAN.md` records ~357 KiB per transfer for the current Plonky3 transaction proof.

- Observation: Treat “cacheable success” as *monotonic validity*: once a spend becomes valid, it stays valid forever unless double-spent. However, some *rejections* may be transient (for example, timelock-style constraints): they are fast to recheck later and can flip from invalid→valid as chain height/time advances. Design must never assume “rejection is final,” and must not rely on time-based challenge windows for security.
  Evidence: The challenge statement explicitly calls out “cacheable success” (suggesting stable acceptance), while timelock semantics in UTXO systems are typically monotonic (invalid now, valid later, then valid forever).

## Decision Log

- Decision: Port the *Hegemon shielded pool join–split* semantics (Zcash Sapling/Orchard-style notes, commitments, nullifiers) as the “privacy system” inside the CashVM covenant.
  Rationale: This repo already implements and documents the semantics (see `METHODS.md`), and those semantics map cleanly to a UTXO covenant as a state-transition system.
  Date/Author: 2026-01-23 / Codex

- Decision: Represent the canonical rollup state UTXO as a singleton using a unique CashToken (an NFT) that must be carried forward on every valid state transition.
  Rationale: Intent UTXOs must be spendable *only* in a transaction that also spends the real state UTXO; a singleton token is the cleanest UTXO-native way to make “the” state input unforgeable without any global registry or consensus change.
  Date/Author: 2026-01-23 / Codex

- Decision: Make the expensive STARK verification happen in exactly one input (the state UTXO); all intent inputs enforce only “co-spend with the state singleton + commit-to-batch binding,” not full proof verification.
  Rationale: Per‑input 10KB unlocking bytecode and density caps make “verify the same aggregated proof in every intent input” a non-starter. We need O(1) heavy verification per covenant-advance transaction.
  Date/Author: 2026-01-23 / Codex

- Decision: Bind the aggregated proof to the covenant transaction by committing to a canonical digest of (a) the old state, (b) the new state, and (c) the multiset of intent commitments consumed in the transaction, plus the set of withdrawal outputs.
  Rationale: Without explicit binding, a prover could present a valid proof about some other set of intents/outputs while spending real on-chain UTXOs; binding makes the proof statement “about this exact transaction.”
  Date/Author: 2026-01-23 / Codex

- Decision: Provide a multi‑transaction proof-fragment path where the state UTXO is spent only in the final “commit” transaction (atomic final commit).
  Rationale: If an intermediate transaction could spend the state UTXO and then stall, it would DoS the covenant. Keeping state consumption only in the final transaction avoids that.
  Date/Author: 2026-01-23 / Codex

## Outcomes & Retrospective

Not started (this plan is design-first).

## Context and Orientation

This plan is written to the CashVM challenge constraints:

1. CashVM is computationally universal and “gas-free” (bounded by density/standardness rules).
2. UTXO validation is modeled as: each spent output runs a function of the *resolved spending transaction* (and its own locking state), returning reject or cacheable success. “Cacheable success” should be read as “once valid, stays valid” (except for double-spentness); do not assume rejects are final if the system includes monotonic predicates such as timelocks.
3. We must not require any further CashVM consensus changes or custom node patches.
4. We must not introduce protocol rents: aggregators are replaceable and are paid only by explicit per‑activity fees chosen by users.
5. No UI and no specification of the out‑of‑band message layer are in scope.

Terms used below:

- **UTXO**: an “unspent transaction output,” a coin/token container that can be spent exactly once as an input to a later transaction.
- **Covenant**: a UTXO locking condition that restricts *how* it may be spent by inspecting the spending transaction.
- **P2S**: “pay to script,” i.e., an output that commits to a script by hash and is spent by revealing that script and satisfying it.
- **Intent UTXO**: a user-created UTXO that locks funds + a fee to be processed by the rollup (deposit/transfer/withdraw) only when an aggregated proof includes it.
- **Aggregator**: an unpermissioned off‑chain actor that collects user proofs and publishes a covenant-advance transaction with an aggregated proof.
- **STARK**: a transparent, hash‑based proof system (post‑quantum under standard assumptions) that can prove correct execution of an arithmetic program.
- **Recursive / aggregated proof**: a proof that attests to the validity of many other proofs or many state transitions, so on‑chain verification work is O(1) per batch.

Privacy system chosen (“port the behavior of [choose privacy system]”):

We port Hegemon’s shielded pool as described in `METHODS.md`:

- A **note** is a private UTXO-like object with `(asset_id, value)` and recipient encryption data.
- A **note commitment** `cm` is a hash commitment to the note’s contents; commitments are inserted into an append-only Merkle tree.
- A **nullifier** `nf` is a hash derived from a spent note that prevents double-spends; the chain maintains a set/accumulator of seen nullifiers.
- A **join–split** proves: consumed notes exist in the commitment tree, revealed nullifiers are correctly derived, new commitments are correctly formed, and value is conserved (per asset).

Existing Hegemon implementation (what we reuse conceptually and, where possible, directly):

- Transaction proof public inputs and verification: `circuits/transaction-core/src/p3_air.rs` (`TransactionPublicInputsP3`) and `circuits/transaction-core/src/p3_verifier.rs`.
- Proof aggregation (recursive verification of many transaction proofs): `circuits/aggregation/` plus the consensus integration described in `.agent/PROOF_AGGREGATION_P3_EXECPLAN.md`.
- The long-term design goal is already “PQ privacy + proof aggregation + DA” in `.agent/WORLD_COMMERCE_SCALABILITY_EXECPLAN.md`; this plan focuses on adapting the *same validity kernel* to CashVM’s covenant model and bridging it back to Hegemon.

## Plan of Work

### 1) Specify the CashVM on-chain objects (UTXOs) and invariants

We define three UTXO types:

1. **State UTXO (singleton)**: carries a unique NFT `STATE_NFT` that identifies this rollup instance. The state UTXO’s script enforces that any valid spend must:

   - Verify an aggregated proof about a batch of intents and the old→new state transition.
   - Create exactly one next-state UTXO that also carries `STATE_NFT`.
   - Pay the aggregator at least the sum of the included intent fees.
   - Emit any transparent withdrawals required by the batch (coins/tokens to user-selected scripts).

2. **Intent UTXO**: created by a user wallet for each activity. It carries:

   - The deposited coins/tokens (for deposits), or dust + fee (for internal transfers), or just fee (for withdrawals).
   - An **intent commitment** `ic` committed by the intent’s script itself (so it is immutable on chain).

   The intent UTXO’s script enforces:

   - This UTXO can only be spent in a transaction that also spends the real state UTXO (by requiring the presence of `STATE_NFT` in some input).
   - The spending transaction must commit to `ic` in a canonical “batch digest” that the state proof also commits to (details below).

3. **Proof-fragment UTXO (optional, multi-tx fallback)**: carries chunks of proof bytes (or chunk digests) that the final commit transaction will consume. These UTXOs must be spendable without special authority (anyone can spend) because their only job is data carriage; safety comes from committing to their digests in the final proof and final transaction.

The core invariant is: coins/tokens can only leave the covenant as withdrawals in a state transition proven by a valid aggregated proof.

### 2) Define canonical commitments and transaction binding

We need binding so that “a proof about some batch” cannot be replayed to spend different on-chain intent UTXOs.

Define the following hashes (exact choice of hash must match what is feasible in CashVM bytecode; this plan assumes a collision-resistant 256-bit hash is available and names it `H256`):

- `ic = H256("intent" || activity_type || activity_public_commitment || fee_commitment || deposit_commitment || withdrawal_commitment)`
- `batch_intents_root = MerkleRoot256( sort([ic_0, ic_1, ...]) )`
- `batch_withdrawals_root = MerkleRoot256( sort([wd_0, wd_1, ...]) )` where each `wd_k` commits to one transparent output (script hash + asset + amount).
- `tx_binding = H256("tx" || old_state_digest || new_state_digest || batch_intents_root || batch_withdrawals_root)`

The aggregated proof’s public inputs must include `tx_binding`. The state covenant bytecode recomputes `tx_binding` from the resolved spending transaction and checks it matches the proof’s public input.

Intent scripts must also be able to locally check they are included in `batch_intents_root` without redoing full work; this is where we have two viable patterns:

1. **Per-intent Merkle path**: Each intent input provides `(batch_intents_root, merkle_path)` and the intent script verifies inclusion of its `ic`. This adds O(log n) data per intent input.
2. **State-only check**: The intent script only enforces “must co-spend with the state NFT” and relies on the state proof to ensure “every non-state intent input was included.” This requires that the state covenant can enumerate all intent inputs, extract their `ic` values, and recompute `batch_intents_root` itself.

We choose (2) unless CashVM’s introspection cannot efficiently enumerate all inputs; (2) keeps intent inputs smaller and makes the covenant-advance transaction more scalable in encoded size.

### 3) Specify user activity proofs (large, non-aggregated)

Each user wallet creates an activity proof off-chain and transmits it out-of-band to aggregators. On chain, only `ic` is committed.

We define three activity types:

1. **Deposit**: consumes transparent coins/tokens from the user and creates one or more new shielded note commitments.
2. **Transfer**: consumes existing shielded notes and creates new shielded notes (shielded→shielded).
3. **Withdraw**: consumes shielded notes and creates transparent outputs (shielded→transparent).

The activity proof statement reuses the join–split statement from `METHODS.md` but adds one more binding:

- The proof must include `ic` as a public input so it is non-malleably associated with the specific on-chain intent UTXO that paid for it.

For withdrawals, the proof must also commit to `batch_withdrawals_root` (or to its own withdrawal leaf `wd_k`), so the batch proof can ensure transparent outputs match what the user authorized.

### 4) Specify the batch/aggregation proof (on-chain verified)

An aggregator produces one aggregated proof per covenant-advance transaction. This proof must establish:

1. Every included activity proof verifies with respect to an allowed commitment-tree root (a “root set”).
2. The set of nullifiers is free of duplicates and not already present in the old nullifier accumulator.
3. The new commitment tree root is the result of appending all new note commitments from the batch.
4. The new nullifier accumulator root is the result of inserting all new nullifiers from the batch.
5. The set of transparent withdrawals committed by user proofs matches the actual transaction outputs (by matching `batch_withdrawals_root`).
6. `tx_binding` matches the on-chain transaction (binding to the exact intents and outputs).

This proof is the *only* expensive proof that must be verified inside CashVM. All other checks (value conservation, note membership, nullifier derivation) are inside this proof or inside the per-user proofs it recursively verifies.

### 5) CashVM covenant bytecode design (state + intent)

The covenant is expressed as CashVM bytecode with two scripts:

1. **State script** (runs when spending the singleton state UTXO):

   - Parses the spending transaction.
   - Extracts all non-state input `ic` values and computes `batch_intents_root` (or reads it from a designated field and checks consistency).
   - Extracts withdrawal outputs and computes `batch_withdrawals_root`.
   - Computes `tx_binding`.
   - Verifies the aggregated STARK proof with public input `tx_binding` (and the old/new state digests).
   - Enforces “carry forward `STATE_NFT` into exactly one next-state output.”
   - Enforces aggregator fee payment ≥ sum(intent fees) − mining_fee_budget (exact fee accounting policy is off-chain competitive; on-chain just enforces a minimum payout path that makes theft impossible).

2. **Intent script** (runs when spending each intent UTXO):

   - Checks the spending transaction includes the singleton `STATE_NFT` as an input (co-spend with state).
   - (If we use pattern (1) above) verifies its own inclusion in `batch_intents_root`.
   - Does *not* verify the aggregated proof.

Bytecode size rules to enforce in the harness:

- State script bytecode (unlocking) must fit under CashVM’s per-input unlocking bytecode cap (given as 10KB in the challenge).
- Covenant-advance transactions must be under the 100KB encoded transaction cap.

### 6) Multi-transaction proof verification fallback (optional)

If the aggregated proof cannot fit under 100KB, split it across multiple “proof-fragment” transactions:

1. One or more `ProofChunkTx` transactions publish `k` proof chunk UTXOs, each carrying ≤90KB of raw chunk bytes.
2. The final `CommitTx` spends:

   - The state UTXO (carrying `STATE_NFT`)
   - All selected intent UTXOs
   - All proof chunk UTXOs

   and then verifies the proof by hashing/reassembling the chunks inside the state script (or verifying chunk hashes against a digest committed in the proof).

Atomicity condition:

- Only `CommitTx` is allowed to spend the state UTXO. All chunk transactions are optional and do not affect liveness.

### 7) Bridge to Hegemon (optional but answers the “bridge?” question)

We support two bridge surfaces:

1. **Shared proof kernel**: Hegemon verifies the same aggregated proof (Rust verifier), and stores the CashVM rollup state digest in a pallet. This gives indexers/wallets one place to watch the state and allows Hegemon to provide DA/archival services for the rollup without changing CashVM.
2. **Asset bridge**: implement a one-way trust-minimized path CashVM→Hegemon by having Hegemon validate CashVM inclusion proofs for covenant deposits and mint corresponding representations on Hegemon. The reverse direction (Hegemon→CashVM) is harder without a CashVM light client; if CashVM lacks timelocks/challenge periods, the practical option is a federated bridge for the reverse direction.

This plan treats the asset bridge as a stretch goal; the core deliverable is the CashVM covenant itself.

## Concrete Steps

From the repository root:

1. Follow the standard repo setup (needed for any Rust build):

    make setup
    make node

2. Create a prototype harness crate:

    mkdir -p spikes/cashvm-covenant
    # (Add a Cargo.toml workspace member and a minimal lib+tests; see Interfaces below.)

3. Implement the minimal CashVM model needed for this plan:

   - A “resolved transaction” struct that includes all inputs with their previous outputs (value, token data, and script hash).
   - A bytecode interpreter for the subset needed by the covenant (stack ops, hashing, basic arithmetic, tx introspection).
   - A “standardness checker” that rejects transactions/script sizes above the CashVM caps we are targeting.

4. Implement covenant scripts in the harness as bytecode blobs and write tests:

   - `test_happy_path_single_tx`: 1 state UTXO + 2 intent UTXOs → 1 next-state UTXO + 1 withdrawal output; expect accept.
   - `test_reject_missing_state_nft`: attempt to spend intent without state; expect reject.
   - `test_reject_tampered_withdrawal`: change withdrawal script hash; expect reject (proof binding).
   - `test_reject_tampered_intent_set`: remove an intent input; expect reject.

5. (When proof plumbing is wired) integrate with the existing Plonky3 proof artifacts:

   - Use `circuits/transaction` to generate per-user proofs.
   - Use `circuits/aggregation` to generate an aggregated proof that exposes `tx_binding` (new public input).
   - Feed the aggregated proof bytes into the covenant harness verifier.

## Validation and Acceptance

This plan is accepted when the repository can run a deterministic local demo (no external CashVM node required) that shows:

1. **Correctness**: The covenant harness accepts a valid covenant-advance transaction and rejects any of the following:
   - Spending an intent without the state singleton.
   - Changing any transparent withdrawal output (amount, asset, or script) without changing the proof.
   - Including an intent input that is not committed by the proof binding.
2. **Standardness**: The demo transaction(s) are under the stated CashVM limits:
   - ≤100KB encoded size per transaction.
   - ≤10KB unlocking bytecode per input (state and intent scripts).
3. **Aggregator market**: No aggregator identity is hard-coded; any actor with the proofs can produce the covenant-advance transaction and collect the attached fees.
4. **PQ posture**: No ECC / RSA / pairings are introduced; everything is hash-based + STARK-based.

## Idempotence and Recovery

All harness tests must be idempotent. No test should depend on wall-clock time, randomness without a fixed seed, or an external node. If a demo requires generated artifacts (proof bytes), they must be generated deterministically in the test or stored as fixed fixtures committed to the repo.

## Artifacts and Notes

When implementing, include in this section:

- The exact CashVM size limits and how the harness enforces them.
- The chosen `H256` hash (and why it is feasible in CashVM bytecode).
- One example transcript showing a passing `test_happy_path_single_tx` and a failing `test_reject_tampered_withdrawal`.

## Interfaces and Dependencies

Add a prototype crate at `spikes/cashvm-covenant/` with (at minimum) the following public API:

- In `spikes/cashvm-covenant/src/tx.rs`, define:

    pub struct ResolvedTx { pub inputs: Vec<ResolvedInput>, pub outputs: Vec<Output> }
    pub struct ResolvedInput { pub prevout: Outpoint, pub prev_output: Output, pub unlocking: Vec<u8> }
    pub struct Output { pub value: u64, pub tokens: Vec<Token>, pub locking: Locking }
    pub enum Locking { P2S([u8; 32]) /* plus any minimal forms needed */ }

- In `spikes/cashvm-covenant/src/vm.rs`, define:

    pub struct Vm;
    impl Vm {
        pub fn eval_output(&self, spending: &ResolvedTx, input_index: usize) -> Result<(), VmError>;
    }

- In `spikes/cashvm-covenant/src/covenant.rs`, define:

    pub struct RollupParams { pub state_nft: TokenId, pub h256: HashId, pub limits: StandardnessLimits }
    pub fn build_state_script(params: &RollupParams, state: &RollupState) -> Vec<u8>;
    pub fn build_intent_script(params: &RollupParams, ic: [u8; 32]) -> Vec<u8>;

The goal of these interfaces is not to perfectly emulate CashVM; it is to be strict enough to catch the two failures we care about early: (a) we exceeded standardness limits, or (b) our covenant script is missing a binding and can be exploited by transaction malleation.

## Change Notes

2026-01-23: Initial draft created to answer the CashVM bridge/covenant challenge and to map the existing Hegemon privacy kernel onto a covenant-based settlement model.
2026-01-24: Clarified the “cacheable success” observation to distinguish stable success from potentially transient failures (e.g., timelocks), per reviewer feedback.
