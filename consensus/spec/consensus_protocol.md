# Consensus Protocol Specification

This document defines the proof-of-work (PoW) consensus layer for the synthetic hegemonic currency chain. The protocol mirrors
the survivability characteristics of Bitcoin/Zcash—deterministic block validation rules coupled with probabilistic finality—
while preserving the project’s STARK-based execution model and nullifier accounting.

## Canonical Chain Parameters

| Parameter | Value | Notes |
|-----------|-------|-------|
| Target block interval | 20 seconds | Used for difficulty retargeting and throughput sizing. |
| Difficulty window (`RETARGET_WINDOW`) | 120 blocks | Canonical window for recalculating the PoW target. |
| Max timestamp skew | +90 seconds | Reject blocks whose timestamp exceeds local time + 90 s. |
| Median-time-past window | 11 blocks | Block timestamp must be strictly greater than the median of the past 11 headers. |
| Target encoding | Compact `pow_bits` (Bitcoin-style) | 1-byte exponent + 3-byte mantissa; `target = mantissa × 256^(exponent−3)`. |
| Work metric | `work = floor((2^256 − 1) / (target + 1))` | Used for cumulative-work comparison. |
| Finality guidance | ≥ 120 confirmations for economic finality under ≤30% adversarial hash power. |

All downstream implementations MUST treat these values as canonical and expose them in configuration files only when the network
explicitly authorizes a hard fork.

## Block Structure and PoW Header

Each block header contains:

1. `parent_hash`
2. `height`
3. `timestamp`
4. `state_root` (commitment to execution state)
5. `nullifier_root`
6. `proof_commitment` (STARK accumulator commitment)
7. `version_commitment`
8. `fee_commitment`
9. `supply_digest` (little-endian 128-bit running total of net issuance)
10. Optional PoW seal containing `pow_bits` (compact target) and a 256-bit `nonce`

A block is valid if `sha256d(header_without_proof) ≤ target(pow_bits)` where `target()` expands the compact encoding above.

## Miner / Full-Node Block Validation

Before propagating or extending a block, miners and full nodes MUST execute the following validation sequence:

1. **Header integrity**
   - Confirm `height = parent.height + 1` and `parent_hash` matches the canonical parent.
   - Check that `timestamp` > median time past (11-window) and `timestamp ≤ local_clock + 90s`.
   - Verify `pow_bits` encodes a target within the permitted global min/max and that `sha256d(header) ≤ target`.
2. **Difficulty retarget consistency**
   - For blocks where `height mod RETARGET_WINDOW = 0`, recompute the expected target from the prior 120 blocks (see
     [Difficulty Adjustment](#difficulty-adjustment)). Reject mismatches.
3. **STARK proof commitments**
   - Feed the block’s execution trace into the STARK verifier. Confirm that the commitment matches the supplied
     `proof_commitment` and that the proof enforces the state transition for every transaction in the block.
4. **Nullifier uniqueness**
   - Apply each transaction’s nullifiers to the nullifier accumulator. Reject blocks containing any nullifier that already
     exists in the global set.
5. **Supply rules and coinbase commitment**
   - Every PoW block must include a coinbase commitment describing how many native units were minted, how many fees were
     aggregated, and any explicit burns. This commitment can be a dedicated transaction referenced by index or a standalone
     `balance_tag`, but it must exist so the MASP circuit sees the same data. Nodes recompute the running `supply_digest`
     as `parent_digest + minted + fees − burns` and reject blocks that exceed the scheduled subsidy or whose digest fails to
     match the header field.
6. **State commitment**
   - Recompute the post-state Merkle root (notes, commitments, nullifiers). The resulting `state_root` and `nullifier_root`
     must match the header values.
7. **Signature checks**
   - Block authors sign only the transaction bundle; there is no validator-set aggregate. Nodes verify transaction-level
     ML-DSA signatures per the execution spec.

Any block that fails one of these steps is invalid and should be treated as an orphan regardless of its PoW score.

## Difficulty Adjustment

Every 120 blocks the network retargets difficulty using the observed timestamps of the preceding window.

Let:
- `W = 120` (window length)
- `T_target = 20 s` (target interval)
- `target_prev` = target at the start of the window
- `t_actual = timestamp_last − timestamp_window_start`

The provisional new target is `target_prov = target_prev × (t_actual / (W × T_target))`. Clamp this value to within `¼ × target_prev`
and `4 × target_prev` to avoid extreme swings. The final `pow_bits` equals `encode_compact(clamp(target_prov))`.

Implementations MUST track the window start timestamp so `t_actual` is deterministic even during reorgs. Because the target is
a header field, honest nodes will reject any block whose encoded difficulty disagrees with the deterministic computation.

## Timestamp and Orphan Handling

- A block timestamp must be greater than the median of the last 11 accepted blocks (median-time-past rule) and no more than
  90 seconds into the future relative to the node’s clock. Blocks violating either constraint are rejected outright.
- Nodes should store received but currently invalid future-dated blocks in an orphan pool and revalidate them once time
  catches up; if still invalid they must be discarded.
- Headers must form a single parent chain. If two competing blocks share the same parent, nodes retain both until the
  cumulative-work fork choice selects a winner.

## Cumulative-Work Fork Choice

Nodes maintain the chain whose cumulative work (sum of `work(target)` for every block) is strictly greater than competing forks.
When comparing candidates:

1. Prefer the chain with higher cumulative work.
2. Break ties by comparing the most recent block hash lexicographically.
3. If a chain was previously marked invalid due to failed validation, it may never be selected regardless of work.

Reorganizations are permitted whenever a fork with strictly greater work appears. Clients seeking probabilistic finality should
wait for 120 confirmations (~40 minutes) before considering a transaction final given the assumed ≤30% adversarial hash share.

## Nullifier Accounting

The nullifier tree is an append-only Merkle accumulator. Block producers must present membership witnesses that prove every
nullifier was unused before inclusion. Because consensus does not rely on validator-set commitments, nullifier enforcement is
purely state-based: duplicate detection results in block rejection and the offending block becomes a permanent orphan.

## Supply and Reward Schedule

- Each block mints `R(height)` native units. `R()` starts at 50 · 10⁸ base units and halves every 840,000 blocks, mirroring
  the Bitcoin/Zcash cadence. After 64 halvings the subsidy floor remains at zero.
- The coinbase commitment tracks `(minted, fees, burns)` so the MASP proof can enforce balance. The consensus layer only
  accepts coinbase commitments whose `minted` component is ≤ `R(height)`.
- The `supply_digest` accumulates the net delta deterministically: `parent_digest + minted + fees − burns`. Because it is a
  plain 128-bit counter, full nodes can audit total issuance without replaying the entire history.

## Finality and Reorg Expectations

- Honest miners should assume probabilistic finality: the chance of a successful reorg of depth `d` decreases exponentially with
  `d` under the ≤30% adversary assumption. Publish exchange policy using the ≥120-confirmation guideline.
- Wallets may display “soft finality” after 12 confirmations (~4 minutes) but should warn users that deeper reorgs remain
  possible.
- Nodes must handle reorgs by rolling back state to the common ancestor, reapplying transactions using the deterministic
  executor, and ensuring nullifier uniqueness holds after the switch.

## Networking Expectations

- P2P links remain authenticated using ML-DSA identities and encrypted using ML-KEM-derived session keys, as described in the
  networking spec.
- Gossip priorities favor tip headers and STARK commitments so miners can quickly validate candidate forks.

## Future Extensions

- Explore cross-chain work proofs so this PoW network can checkpoint into external ledgers.
- Investigate non-interactive fraud proofs for invalid block detection to complement the deterministic verifier.

This PoW-focused specification supersedes the earlier staking/HotStuff design. All client implementations must track the
parameters defined above to remain interoperable.
### Coinbase encoding

Block template builders must either (a) include an explicit coinbase transaction and reference it via index or (b) supply a
standalone `balance_tag` that matches the MASP proof’s public inputs. In either case miners must encode the minted amount,
fee total, and burn total so full nodes can recompute `supply_digest`. Templates that omit the coinbase data or fail to link it
to a transaction are invalid and will be rejected by consensus.
