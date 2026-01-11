# Consensus Audit (Spec ↔ Implementation)

This document reconciles the consensus-related specs in `consensus/spec/` with the *shipping* implementation used by the Substrate node binary (`hegemon-node`). It is intended as an engineering checklist: it names which code paths are consensus-critical today, highlights divergence that can cause accidental forks, and enumerates invariants that should be enforced by CI.

Keep this synchronized with `DESIGN.md` (consensus architecture), `METHODS.md` (operator workflow), and `consensus/spec/` (formal protocol spec). If the canonical consensus rules change, update all of them together.

## Scope: “Consensus” vs “Local Policy”

- **Consensus-critical rule**: if two honest nodes running the canonical client can disagree about block acceptance or fork choice, it is consensus-critical.
- **Local policy**: a rule that only affects local resource usage or relay behavior, but cannot change what blocks are accepted as valid.

This repo currently implements some “consensus-like” gates (proof verification, DA sampling) in the node service rather than in the runtime. That is fine for a single-client world, but it is *consensus-critical* for interoperability: another client that skips those checks can follow a different chain tip.

## Canonical Implementation (What `hegemon-node` Runs Today)

### PoW and fork-choice (Substrate path)

The Substrate node uses `sc-consensus-pow` with a Blake3-based seal format and a runtime-provided difficulty:

- Seal and work function: `blake3(pre_hash || nonce)` and `work <= target(bits)` (`consensus/src/substrate_pow.rs`).
- Difficulty source of truth: runtime API `DifficultyApi::difficulty() -> U256` backed by `pallet-difficulty` storage (`runtime/src/apis.rs`, `pallets/difficulty/src/lib.rs`).
- Import pipeline: `sc_consensus_pow::PowBlockImport` is instantiated in `node/src/substrate/service.rs` and used for network block import (`node/src/substrate/service.rs`).

**Expected fork-choice** for PoW in Substrate’s PoW engine is *cumulative difficulty*, not “longest height”. `PowBlockImport` will compute total difficulty and set `ForkChoiceStrategy::Custom(...)` **only if** the caller leaves `BlockImportParams.fork_choice` unset.

### Block validity gates beyond PoW (current node behavior)

The node service performs additional validity gates during import:

- Commitment proof extraction and verification (for blocks with shielded transfers): `node/src/substrate/service.rs` (`verify_proof_carrying_block(..)`), with proof bytes carried via `ShieldedPool::submit_commitment_proof` (`pallets/shielded-pool/src/lib.rs`).
- Data-availability encoding + sampling gate: `node/src/substrate/service.rs` (`sample_da_for_block(..)` and DA stores).

These are currently *implemented as node import policy*, not runtime-enforced consensus. If the project intends these to be part of the canonical ledger rules, they must be treated as consensus-critical and consistently applied by all nodes.

### Coinbase (shipping implementation)

The “coinbase” in the Substrate chain is implemented as a **shielded coinbase inherent** that mints a note into the shielded pool:

- Inherent call: `ShieldedPool::mint_coinbase` (`pallets/shielded-pool/src/lib.rs`).
- Inherent data provider construction: `node/src/substrate/service.rs` (builds encrypted note + commitment, injects inherent data).

This differs materially from the “coinbase commitment + supply digest in header” described by the legacy `consensus/` spec and types.

## Legacy Consensus Stack (What `consensus/spec/` Describes)

The files under `consensus/spec/` describe a *separate* consensus stack built around:

- Custom header struct `consensus::header::BlockHeader` (`consensus/src/header.rs`).
- A non-Substrate PoW state machine `consensus::PowConsensus` with cumulative-work tracking (`consensus/src/pow.rs`).
- A “coinbase data + supply_digest in header” model (`consensus/spec/consensus_protocol.md`).

This stack is not what `hegemon-node` imports/produces today. Until the repo chooses one canonical stack and removes the other (or fences it as “bench/sim only”), `consensus/spec/` should be treated as **non-authoritative for `hegemon-node`**.

## Divergence Matrix (Spec vs Shipping Node)

| Topic | `consensus/spec/consensus_protocol.md` (legacy spec) | `hegemon-node` (shipping Substrate path) | Risk |
|---|---|---|---|
| PoW hash | Mentions `sha256d(...)` | Blake3 seal: `blake3(pre_hash || nonce)` | Cross-implementation confusion; incorrect audits |
| Nonce width | 256-bit nonce | `Blake3Seal.nonce: u64` | Mismatch in security analysis + header formats |
| Difficulty window | `RETARGET_WINDOW = 120` | `pallet-difficulty` uses `RETARGET_INTERVAL = 10` | Spec does not match chain behavior |
| Timestamp rules | Median-time-past, +90s skew | Substrate timestamp inherent checks; no explicit MTP in runtime | Different reorg/acceptance surface |
| Fork choice | “cumulative work” | Intended cumulative difficulty via `PowBlockImport`, but caller currently sets `LongestChain` | Consensus safety risk (incorrect best-chain selection) |
| Coinbase/supply | `supply_digest` in header | Shielded coinbase inherent; supply visible via runtime state/RPC, not header | Incorrect economic monitoring if operators use spec assumptions |
| Proof & DA gates | Listed as consensus steps | Enforced by node service during import (configurable) | Consensus split risk if toggled or multi-client |

## Consensus-Split Hazards (Action Items)

1. **Fork-choice override bypasses PoW total difficulty**
   - The network import path sets `BlockImportParams.fork_choice = Some(ForkChoiceStrategy::LongestChain)` before calling `PowBlockImport.import_block(..)` (`node/src/substrate/service.rs`).
   - This prevents `PowBlockImport` from applying the PoW engine’s total-difficulty fork choice.

2. **Multiple “difficulty” implementations exist**
   - `pallets/difficulty` (U256 difficulty + bits) is used by the shipping node.
   - A deprecated runtime `pow` pallet also tracks “difficulty bits” and does its own retarget (`runtime/src/lib.rs` module `pow`).
   - `consensus::reward` defines `RETARGET_WINDOW = 10` for the legacy consensus crate.

3. **Environment-variable toggles can change validity**
   - Proof verification and commitment proof inclusion are gated by env vars (e.g. `HEGEMON_COMMITMENT_BLOCK_PROOFS`, `HEGEMON_PARALLEL_PROOF_VERIFICATION`).
   - DA sampling parameters are also env-driven (`HEGEMON_DA_*`).
   - If these gates are consensus-critical for the network, they must not be optional per-node.

## CI Invariants (Should Be Enforced)

The following invariants are phrased so they can be turned into tests. Treat the “MUST” list as release-blocking for consensus changes.

### MUST: PoW import and fork-choice invariants

- **No manual fork-choice override for PoW imports**: code that calls `sc_consensus_pow::PowBlockImport::import_block` MUST leave `BlockImportParams.fork_choice` as `None`, so the PoW engine can set `ForkChoiceStrategy::Custom` based on total difficulty.
- **Seal placement is canonical**: imported network headers MUST have the PoW seal removed from the header digest and provided via `post_digests.last()` (Substrate PoW engine requirement).
- **Difficulty coherence**: `ConsensusApi::difficulty_bits()` MUST be consistent with `DifficultyApi::difficulty()` (i.e., `difficulty_bits == target_to_compact(U256::MAX / difficulty)` within the tolerance that `consensus::Blake3Algorithm` enforces).

Suggested tests:
- Unit/integration test in `tests/multi_node_substrate.rs` that exercises the network import path and asserts the `PowBlockImport` fork-choice is not overridden.

### MUST: Commitment proof + tx-proof invariants (if treated as consensus)

- **Singleton commitment proof**: for any block containing ≥1 shielded transfer, exactly one `ShieldedPool::submit_commitment_proof` extrinsic MUST be present, and it MUST validate against the included shielded transfers.
- **No proof on empty blocks**: for blocks with zero shielded transfers, `submit_commitment_proof` MUST be absent.

Suggested tests:
- Extend `consensus/tests/commitment_proof_handoff.rs`-style coverage with a Substrate-extrinsic block assembly test (construct extrinsics, ensure import rejects missing/duplicate proof).

### SHOULD: Data availability invariants (if treated as consensus)

- **DA root determinism**: DA encoding and `da_root` MUST be deterministic from ordered ciphertext payloads and params (`state/da`).
- **Sampling non-bypass**: if DA sampling is part of consensus for a given network, its parameters and enforcement MUST be fixed and not operator-configurable.

### SHOULD: Documentation invariants

- A single “canonical consensus” document MUST exist for the shipping node, and `consensus/spec/` MUST either be updated to match it or explicitly labeled as legacy/bench-only.

## Next Steps (Recommended)

1. Decide which consensus stack is canonical:
   - Option A: Substrate (`hegemon-node`) is canonical; update/migrate `consensus/spec/` to describe the Substrate chain.
   - Option B: Legacy `consensus::PowConsensus` is canonical; deprecate/remove Substrate PoW path.
2. Fix fork-choice wiring so PoW uses total difficulty (Substrate PoW engine semantics).
3. Convert “consensus-critical env toggles” into a single on-chain/runtime configuration surface (or remove them), so operators cannot accidentally split themselves from the network.

