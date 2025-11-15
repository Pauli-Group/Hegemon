# Consensus Protocol Specification

This document describes the hybrid consensus design for the synthetic hegemonic currency chain. The protocol prioritizes a stake-weighted BFT core inspired by HotStuff, while providing an optional proof-of-work (PoW) compatibility mode for permissionless liveness. Both modes share common validation rules for STARK proofs, nullifier uniqueness, and state commitments.

## Validator Identities and Staking

- Validators are identified by ML-DSA-65 public keys. Each key is paired with a stake amount denominated in the native asset.
- The validator set is updated via governance transactions recorded on-chain. Each update produces a `validator_set_commitment` hashed into block headers.
- Stakes are locked for a configurable unbonding period (default: 21 epochs). During this time, validators can be slashed for misbehavior.

## Consensus Modes

### BFT / Proof-of-Stake Mode

- Consensus proceeds in numbered **views**. Each view has a designated leader chosen via weighted round-robin on stake.
- Blocks move through three phases (Prepare, Pre-Commit, Commit). Validators sign messages for each phase, producing quorum certificates (QCs) once signatures representing ≥2/3 of stake are collected.
- A block is *justified* when it carries a QC for its parent and includes the parent’s `view`. It becomes *committed* once its child carries a QC referencing it and the grandchild carries a QC referencing the child (standard HotStuff 3-chain rule).
- Leaders propose blocks by broadcasting `Prepare` messages containing the full block and parent QC. Validators verify the block (proofs, nullifiers, signatures) before voting.
- Fork choice prefers the highest `view` with a valid QC. In case of equal views, the block with the highest `height` wins.

### PoW Compatibility Mode

- Nodes may optionally accept PoW-sealed blocks. PoW blocks must satisfy the same state transition rules as BFT blocks but replace QCs with a valid nonce such that `sha256(header) <= target`.
- PoW difficulty is encoded in the `pow_target` field. The target adjusts every `N` blocks based on observed timestamps (default: 120 blocks).
- When both PoW and BFT blocks exist at the same height, BFT blocks take precedence if they contain a QC with ≥2/3 stake. PoW blocks serve as a liveness fallback during stake churn or validator downtime.

## Block Validation

Before voting on or accepting a block, validators MUST perform the following checks in order:

1. **Header integrity**: verify field ranges, timestamp window, height continuity, and matching parent hash.
2. **Validator set**: recompute `validator_set_commitment` from the locally tracked set. Reject mismatches.
3. **STARK proof commitments**: invoke the block proof verifier (via `ProofVerifier`) to ensure the commitment matches the block’s transaction bundle.
4. **Nullifier uniqueness**: recompute the nullifier root by applying each transaction’s nullifiers to the current accumulator. Reject duplicates or stale nullifiers.
5. **Merkle root**: recompute the note commitment tree root after applying all outputs. Must match `state_root`.
6. **Balance commitment**: verify the aggregated fee commitment aligns with per-transaction `balance_tag`s.
7. **Signature verification**:
   - BFT mode: verify each signature in the aggregate using the bitmap; ensure total stake weight ≥2/3 and signatures correspond to the current view.
   - PoW mode: verify the proposer’s ML-DSA signature and confirm `sha256(header) <= target`.
8. **Slashing checks**: compare the received votes with stored history. Detect double-signing (same view, different parent) and prepare evidence for gossip.

## Nullifier Uniqueness Enforcement

- Each block maintains a sorted vector of nullifiers. The consensus state keeps a Merkle tree over all past nullifiers.
- When a new nullifier appears, the validator verifies it does not already exist in the set. Duplicate detection triggers block rejection and slashing evidence against the proposer for including invalid transactions.
- Nullifier additions are appended to the accumulator and committed via `nullifier_root` in the header.

## Slashing Conditions

Validators are slashed (stake partially or fully burned) for:

1. **Double-signing**: producing two distinct `Prepare` votes for the same view but different parent hashes.
2. **Surround votes**: voting for a block that skips a justified ancestor with lower view number.
3. **Invalid block proposal**: proposing a block with incorrect proofs, nullifiers, or state commitments.
4. **Liveness faults**: failing to sign any block for `k` consecutive views without justification (configurable; results in gradual stake decay rather than immediate slash).

Slashing evidence includes the conflicting headers, signatures, and view numbers. Evidence is gossiped network-wide and included in future blocks as special transactions, triggering automatic stake deductions.

## Fork-Choice Rule

- Maintain a DAG keyed by `block_hash` with edges pointing to parents.
- For BFT blocks, prioritize the chain containing the highest view number with a valid QC (highest justified view). Tie-break on cumulative stake weight of votes and, finally, by lexicographically smallest block hash.
- For PoW blocks, compute cumulative work. A PoW chain can only replace a BFT chain if the BFT chain lacks a committed tip or if the PoW chain’s latest block carries a validator signature aggregate from ≥1/3 stake (weak subjectivity fallback).

## Networking Expectations

The P2P layer must provide:

- Authenticated connections using ML-DSA identities.
- Encrypted channels derived from ML-KEM session keys.
- Reliable gossip for block proposals, votes, and slashing evidence with deduplication.
- Priority channels for QC propagation to guarantee fast finality.

## State Synchronization

- Nodes missing blocks request them via encrypted RPC over the P2P channel.
- Light clients verify only headers and proof commitments. They rely on `validator_set_commitment` updates to detect validator rotations.

## Parameters

- View timeout: 4 seconds (configurable). Validators move to the next view if they do not observe a valid proposal or QC within the timeout.
- Unbonding period: 21 epochs (default). PoW mode bypasses staking but still requires validator signatures for proof verification.
- Maximum block size: 1 MB serialized, limited by transaction proofs.

## Safety and Liveness Guarantees

- Assuming <1/3 stake is Byzantine, the HotStuff-style BFT mode guarantees safety (no two conflicting committed blocks) and liveness (eventual commitment) under partial synchrony.
- PoW mode inherits probabilistic finality. Nodes should treat PoW blocks as provisional until they collect either (a) six confirmations or (b) an attached QC.
- Nullifier uniqueness is enforced deterministically by the proof verifier and the consensus state updates; duplications are slashable faults.

## Future Work

- Introduce aggregated ML-DSA signatures to compress `signature_bitmap`.
- Implement optimistic responsiveness by dynamically adjusting view timeouts based on observed latency.
- Extend PoW mode with hybrid leader election (e.g., proposer boosted by PoW but finalized by stake votes).

