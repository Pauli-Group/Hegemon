```md
# Enforce deterministic PoW retargeting, subsidy schedule, and block templates

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds.

Reference: repository root `.agent/PLANS.md` defines the ExecPlan format and maintenance requirements. Every update to this file must remain consistent with that guidance.

## Purpose / Big Picture

Ship a deterministic PoW rule set that matches the specification in `consensus/spec/consensus_protocol.md`: headers must expose `pow_bits`, `nonce`, and the running `supply_digest`, miners must respect the Bitcoin/Zcash-style halving schedule, nodes must recompute subsidies and reject blocks whose rewards overshoot the schedule, and the difficulty retarget algorithm (120-block window, 20 s target interval, ×¼…×4 clamp) plus the median-time-past/future-skew checks must gate fork choice. Block template helpers must fill in coinbase data so proof circuits and MASP accounting see the new subsidy commitments. Full-node tests must cover incorrect `pow_bits`, timestamp failures, and halving boundaries. After this change, anyone can run `cargo test -p consensus` to watch the new validation logic prevent malformed PoW blocks and confirm that subsidy accounting matches the documented schedule.

## Progress

- [x] (2024-05-31 12:30Z) Draft plan: capture scope, context, and work breakdown.
- [x] (2024-05-31 13:10Z) Add header/type fields for PoW bits, nonce, supply digest, and coinbase helpers.
- [x] (2024-05-31 13:25Z) Introduce reward schedule utilities, integrate into PoW application, recompute supply digest, and enforce coinbase semantics.
- [x] (2024-05-31 13:40Z) Implement timestamp checks, retarget window storage, deterministic difficulty calculation, and fork-choice history.
- [x] (2024-05-31 13:55Z) Update block-template helpers/tests to emit proper coinbase commitments and fee accounting.
- [x] (2024-05-31 14:05Z) Author consensus tests for difficulty mismatch, median-time-past/future skew, and subsidy enforcement.
- [ ] Refresh `consensus/spec/consensus_protocol.md`, `DESIGN.md`, and `METHODS.md` to describe the new rules.
- [ ] Run `cargo test -p consensus` and finalize documentation of observed behavior.

## Surprises & Discoveries

- Observation: _None yet._
  Evidence: _Pending implementation._

## Decision Log

- Decision: _None yet._
  Rationale: _Pending implementation._
  Date/Author: _N/A._

## Outcomes & Retrospective

_Pending execution._

## Context and Orientation

Consensus code lives under `consensus/`. Relevant components:

- `consensus/src/header.rs` defines `BlockHeader`, `PowSeal`, and serialization helpers. Currently the header only stores `PowSeal { nonce, target }` with `target` already expanded; the spec now requires a distinct `pow_bits` field and explicit `nonce` plus a running `supply_digest`.
- `consensus/src/types.rs` contains `Transaction`, `ConsensusBlock`, and helper commitments. We need helper structs/enums for coinbase data (e.g., minted amount, fee accumulator tags) so miners can represent the minted subsidy either via a dedicated transaction or balance-tag metadata.
- `consensus/src/pow.rs` validates PoW blocks, maintains the `PowNode` DAG, and enforces state/nullifier/proof rules. It currently lacks reward logic, timestamp clamps, and deterministic retargeting.
- `consensus/tests/common.rs` builds fake PoW/BFT blocks for integration tests. This helper must now construct coinbase commitments and ensure transaction bundles include minted funds.
- `consensus/tests/*.rs` exercise fork choice and simulation logic; new tests must cover difficulty/timestamp/subsidy failures.
- Documentation: `DESIGN.md`, `METHODS.md`, and `consensus/spec/consensus_protocol.md` describe consensus behavior; they must mention the new header fields, supply digest math, and retarget/timestamp enforcement details.

Terminology reminders:
- `pow_bits`: compact encoding of the PoW target, same as Bitcoin’s nBits. Converts to a BigUint target.
- `supply_digest`: cumulative running total of minted minus burned units; used to verify subsidy schedule deterministically.
- `R(height)`: per-height block subsidy function with halving intervals; mirror Bitcoin/Zcash (start value TBD from code/tests, halved every 840k blocks or as defined once requirements clarified).
- `Median-time-past (MTP)`: the strict median of the last 11 block timestamps; each new block’s timestamp must be strictly greater than that median. Future skew limit = parent timestamp must be ≤ local clock + 90 s; for deterministic tests use a parameter.
- `RETARGET_WINDOW = 120`: difficulty adjusted every 120 blocks, using observed timestamps across the window and clamping adjustments to ×¼…×4.

## Plan of Work

1. **Header/type expansion**
   - Extend `consensus/src/header.rs::BlockHeader` with explicit `pow_bits`, `nonce`, and `supply_digest` fields. Replace `PowSeal::target` with `pow_bits` storage plus helper that derives the full target. Update `encode_signing_fields`/`encode_full_header` to serialize the new fields, ensuring signing hash includes supply data. Update `ensure_structure` to require `pow_bits`/`nonce` presence for PoW headers and validate coinbase metadata.
   - In `consensus/src/types.rs`, add helper types for coinbase data: e.g., `CoinbaseTarget` enumerating `Transaction` vs. implicit balance-tag, plus `CoinbaseCommitment`/`SupplyDigest` wrappers. Update transaction constructors to optionally mark coinbase outputs if required.

2. **Reward schedule utilities**
   - Introduce a reward module (new file `consensus/src/reward.rs` or within `pow.rs`) defining constants for `RETARGET_WINDOW`, `TARGET_INTERVAL_MS`, halving interval, genesis subsidy, and function `fn block_subsidy(height: u64) -> u64` (and convenience `fn supply_digest(parent: u128, minted: u64, fees: i128, burns: u64) -> u128`). Unit tests should cover halving math.
   - Update `consensus/src/pow.rs` to use the new utilities: recompute minted amount for each block, ensure block transactions carry exactly that subsidy (via coinbase transaction amount or flagged balance tag). Recompute and verify `supply_digest` equals parent digest plus minted minus burns plus fees. If block attempts to mint more than allowed, reject with `ConsensusError::InvalidSubsidy` (add variant as needed).

3. **Timestamp + retarget enforcement**
   - Add MTP and future-skew checks to `PowConsensus::apply_block`. Maintain a rolling deque/history of the last `RETARGET_WINDOW` headers (hash, timestamp, pow_bits) inside `PowConsensus` or `PowNode` so reorgs can recompute expected targets. Implement deterministic difficulty retarget: for each block, derive expected `pow_bits` from parent history; if mismatch, reject. When storing nodes, persist timestamp and pow_bits to allow reorg recalculation.
   - Implement helper `fn expected_pow_bits(&self, parent_hash: &[u8;32], new_timestamp: u64) -> Result<u32>` that traverses `RETARGET_WINDOW` ancestors, calculates new target at window boundaries, and otherwise inherits parent value.

4. **Block template helpers**
   - Update `consensus/tests/common.rs::assemble_pow_block` (and any other template builder) to create a coinbase transaction or metadata that encodes minted subsidy plus collected fees. Ensure the helper fills `pow_bits`, `nonce`, and `supply_digest` consistently with the new rules so integration tests remain ergonomic.
   - Provide new helper functions to compute fees from `Transaction.balance_tag` or explicit fields so MASP accounting stays consistent. Ensure test harness updates any circuits/mocks that expect `fee_commitment` or `balance_tag` semantics.

5. **Testing**
   - Add new tests under `consensus/tests/` verifying:
     a. Blocks whose `pow_bits` disagree with deterministic retargeting are rejected.
     b. Blocks failing median-time-past (timestamp ≤ median of last 11) or exceeding the future skew fail validation.
     c. Subsidy enforcement: blocks after a halving that still mint the higher subsidy are rejected, and `supply_digest` mismatches are caught.
   - Extend existing tests to assert the new header fields and supply logic propagate correctly.

6. **Documentation**
   - Update `consensus/spec/consensus_protocol.md` with explicit descriptions of `pow_bits`, `nonce`, `supply_digest`, the reward schedule, and how block templates encode coinbase commitments.
   - Reflect the same in `DESIGN.md` (consensus section) and `METHODS.md` (implementation details, testing approach).

## Concrete Steps

1. Draft code changes per sections above, editing:
   - `consensus/src/header.rs`
   - `consensus/src/types.rs`
   - `consensus/src/pow.rs`
   - `consensus/tests/common.rs`
   - `consensus/tests/*.rs` for new cases
   - `consensus/spec/consensus_protocol.md`, `DESIGN.md`, `METHODS.md`
2. Add any new modules such as `consensus/src/reward.rs` and ensure `consensus/Cargo.toml` exports them if needed.
3. Run `cargo fmt` to maintain style.
4. Run `cargo test -p consensus` to validate functionality.

## Validation and Acceptance

- `cargo test -p consensus` should pass, including new tests exercising difficulty/timestamp/subsidy logic.
- Manual inspection: constructing a PoW block via `assemble_pow_block` with mismatched subsidy or incorrect `pow_bits` must now yield `ConsensusError::Pow` or the appropriate error.
- Documentation diff should describe the new header fields, reward schedule, and retarget logic in all referenced markdown files.

## Idempotence and Recovery

- Re-running block-template helpers or the new tests should be deterministic because all randomness uses deterministic seeds; the retarget calculator relies solely on stored header history.
- If a migration step fails (e.g., history storage incomplete), rolling back the code changes and rerunning `cargo test` returns the tree to the original behavior; no persistent state changes are made.

## Artifacts and Notes

_Pending implementation._

## Interfaces and Dependencies

- `BlockHeader` gains `pow_bits: u32`, `nonce: [u8; 32]`, `supply_digest: u128` (or similar) fields referenced by `PowSeal` or replacement structure.
- New reward API:

    pub const RETARGET_WINDOW: u64 = 120;
    pub const TARGET_BLOCK_INTERVAL_MS: u64 = 20_000;
    pub const HALVING_INTERVAL: u64 = 210_000; // Matches Bitcoin’s halving cadence.
    pub const MAX_FUTURE_SKEW_MS: u64 = 90_000;

    pub fn block_subsidy(height: u64) -> u64 { /* halving logic */ }

    pub fn expected_pow_bits(prev_bits: u32, timestamps: &[u64]) -> u32 { /* clamp ×¼…×4 */ }

- `PowConsensus::apply_block` must call new helpers to check timestamps, compute expected pow bits, recompute supply digest, and validate coinbase data before updating the DAG.
```
