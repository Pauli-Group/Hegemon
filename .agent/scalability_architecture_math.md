# Scalability Architecture Math Notes (Proof-Carrying Blocks + Data Availability)

This file is the quantitative companion to `.agent/scalability_architecture_execplan.md`. It exists to make the scalability architecture falsifiable: every security or scaling claim in the ExecPlan should reduce to a concrete formula, parameter choice, or measurable benchmark described here.

The intent is not “math for vibes”. The intent is: before we touch consensus code, we can answer “what breaks, with what probability, under what adversary, at what throughput, with what parameter settings?”

## 0. Quick Summary (what this file concludes)

1. With the current Winterfell parameter choices in the repo (64-bit base field + `FieldExtension::None` for transaction proofs), the STARK soundness is not “96 bits” or “128 bits”. The limiting term is the standard field-size bound `Pr[bad passes] ≤ deg/|F|`. For the current transaction AIR, `trace_length = 2^15` and `blowup = 2^3`, so the relevant degree scale is ~`2^18`, giving a best-case ceiling of about `64 - 18 ≈ 46` bits before we even discuss post-quantum hash collisions. If we want “settlement-grade” validity, we must change proof parameters (field extension and/or base field choice) and explicitly accept the performance cost.

2. If we keep 256-bit hashes, then “post-quantum collision security” is ~85 bits (generic bound ~2^(n/3)). This caps the effective security level of any component that relies on collision resistance (Merkle commitments, Fiat–Shamir transcripts, DA Merkle roots). Setting a baseline target of 85-bit PQ security is internally consistent with 256-bit digests, but it still requires removing the current field-size bottleneck (which is ~46-bit-ish for the current transaction AIR on a ~64-bit base field without extensions).

3. “Deterministic DA sampling derived from producer-known data (e.g. parent hash and height)” is not a security mechanism against a malicious block producer. The producer can always ensure the deterministically sampled chunks are available and withhold the rest. In PoW it is strictly worse if sampling depends on the current block hash because the producer can grind the hash to bias samples.

4. A DA scheme that actually works in an adversarial setting must use one of:
   - Private per-node randomized sampling (network-level enforcement: refuse to relay blocks whose sampled shares cannot be fetched/verified), or
   - An unpredictability source the block producer cannot bias at commitment time (e.g., delayed sampling from future randomness / finality), or
   - A committee / threshold randomness beacon (which is a different consensus design problem).

5. Proof-carrying blocks are mathematically sound as a scaling move: verification becomes O(1) per block while prover work remains O(number of transactions). The hard constraint becomes block producer latency (how long it takes to generate the recursive proof), not verification.

Everything else in this file expands those statements into formulas and parameter guidance.

## 0.1 Decision: “256-bit hashes” implies “~85-bit PQ collision security”

If we keep 256-bit digests everywhere, then we must treat ~85 bits as the ceiling for “PQ collision security” and therefore as the realistic ceiling for STARK soundness insofar as it depends on collision resistance. This is a coherent target if we explicitly accept it.

However, the repo’s current Winterfell recursion machinery does not yet support the proof parameter changes needed to reach 85 bits in the first place (it currently rejects inner proofs with field extensions). That is the main remaining math-to-implementation gap after lowering the security target from 128 to 85.

## 1. Notation and Targets

### 1.1 Variables

- `m`: number of transactions in a block.
- `T_block`: target block interval (seconds). In current design docs this is 60 seconds.
- `p_tx`: probability that an invalid transaction is accepted due to transaction-proof soundness failure (per transaction attempt).
- `p_block`: probability that an invalid block is accepted due to block-proof soundness failure (per block attempt).
- `N_tx`: total number of transaction attempts over some horizon (lifetime or period).
- `N_block`: total number of blocks over some horizon.

Data availability (DA):

- `D`: total bytes of “blob data” that must be available for a block (ciphertexts + whatever else we decide is DA-only).
- `c`: chunk size in bytes (bytes per shard).
- `k`: number of data shards (Reed–Solomon “data”).
- `p`: number of parity shards (Reed–Solomon “parity”).
- `n = k + p`: total shards/chunks.
- `t`: number of shards withheld/unavailable.
- `s`: number of sampled shards per sampling node.
- `H`: number of honest sampling nodes whose samples are independent.

### 1.2 Practical security targets (not vibes)

We need a target that relates to money risk, not academic “128 bits everywhere”. A workable target is:

- Validity risk target over horizon: the probability of *any* successful invalid spend over `N_tx` attempts should be negligible.
- DA risk target per block: the probability that a malicious producer gets a block accepted that later cannot be reconstructed by honest nodes should be negligible (for some definition of “accepted”).

Use union bounds as a conservative baseline:

- `P(any invalid tx accepted) ≤ N_tx * p_tx`
- `P(any invalid block accepted) ≤ N_block * p_block`

Example sanity numbers:

- 4 years at 60s blocks: `N_block ≈ 2.1 million ≈ 2^21`.
- 10^12 lifetime tx attempts: `N_tx ≈ 2^40`.

If we want `P(any invalid tx accepted) ≤ 2^-60`, we need `p_tx ≤ 2^-(60 + 40) = 2^-100`.

If we want `P(any invalid block accepted) ≤ 2^-60` over 4 years, we need `p_block ≤ 2^-(60 + 21) = 2^-81`.

These are conservative (union bound), but they give you a non-handwavy goal: transaction proof soundness around ~100 bits is a sane “settlement-ish” baseline at scale. ~46 bits (current config) is not.

## 2. STARK Soundness Math (Winterfell-specific)

This section is “read the upstream math and translate it into parameters we control in code”.

Winterfell’s documentation (in `winter-air`’s `ProofOptions` docs) states:

- Conjectured soundness is bounded by `num_queries * log2(blowup_factor) + grinding_factor`.
- Soundness is also bounded by the finite field size: for ~64-bit fields, extensions are needed for 100+ bits.
- Soundness is also bounded by the collision resistance of the hash function used in the protocol.

### 2.1 The knobs we have in code today

In this repo, transaction proofs default to:

- `num_queries = 32`
- `blowup_factor = 8`  (so `log2(blowup_factor) = 3`)
- `grinding_factor = 0`
- `field_extension = None`

This is in:

- `circuits/transaction/src/stark_prover.rs` (`default_proof_options()`)
- `circuits/transaction/src/rpo_prover.rs` (reuses the same options)

Winterfell’s bound gives:

- Query/bLowup bound: `32 * 3 + 0 = 96 bits`.

But this “96 bits” is not the full story. STARK soundness has multiple terms; one of them is the field-size term that comes from Schwartz–Zippel style reasoning:

- If a verifier samples a random challenge `z` from field `F`, then for any non-zero polynomial `P` of degree `deg(P)`, `Pr[P(z)=0] ≤ deg(P)/|F|`.

In Winterfell STARKs, the degrees you are protecting against are on the order of the LDE / composition polynomial degrees, which are bounded (up to small constant factors) by the LDE domain size:

- `lde_domain_size = trace_length * blowup_factor`.

For the current transaction proof:

- `trace_length = MIN_TRACE_LENGTH = 32768 = 2^15` (from `circuits/transaction-core/src/stark_air.rs`)
- `blowup_factor = 8 = 2^3` (from `circuits/transaction/src/stark_prover.rs` `default_proof_options()`)
- So `lde_domain_size = 2^15 * 2^3 = 2^18`.

Thus the field-size term cannot be better than roughly:

- `deg/|F| ≈ 2^18 / 2^64 = 2^-46` (ignoring small constants).

So the “realistic ceiling” for transaction-proof validity soundness in the current configuration is on the order of ~46 bits, not ~64 and not ~96.

Winterfell’s own docs are consistent with this. In `winter-air`’s `ProofOptions` docs, they explicitly say:

- For ~64-bit base fields, quadratic extension is needed for ~100 bits; cubic for 128+.

Actionable conclusion: with 64-bit base field + `FieldExtension::None`, we cannot reach ~85-bit validity soundness for the current transaction AIR. “Turn the query knob” does not fix this; it only improves the FRI-query term, not the field-size term.

This directly affects the scalability plan because a recursive block proof that verifies transaction proofs inherits the transaction-proof soundness ceiling.

The same ceiling shows up in the repo’s existing recursion-proof parameter choices. For example, `circuits/epoch/src/recursion/recursive_prover.rs` uses:

- `num_queries = 16`
- `blowup_factor = 32` (so `log2(blowup_factor) = 5`)
- `grinding_factor = 4`
- `field_extension = None`

Query/bLowup bound: `16 * 5 + 4 = 84 bits`, but with `FieldExtension::None` it is still capped by the base field size.

### 2.2 FieldExtension implications (cost and benefit)

`FieldExtension` in Winterfell selects the field used for the composition polynomial (not the entire trace). Increasing extension degree generally:

- Improves soundness (because random challenges live in a larger field).
- Increases proof size and prover time (Winterfell warns “as much as 50%”).

If we want a concrete baseline like `p_tx ≤ 2^-100`, we cannot stay in `FieldExtension::None`.

Pragmatic parameter direction:

- For 100-ish bits target: consider `FieldExtension::Quadratic` + enough queries/blowup.
- For 128-ish bits target: consider `FieldExtension::Cubic` + enough queries/blowup.

### 2.3 Soundness under recursion (composition)

Let:

- `ε_tx` be the soundness error for an inner transaction proof (probability a false statement is accepted by the verifier).
- `ε_block` be the soundness error for the outer recursive block proof.

If the block proof verifies `m` transaction proofs, a conservative bound is:

- `P(block accepts invalid tx) ≤ ε_block + m * ε_tx`

Over a horizon of `N_block` blocks with average `m̄` tx per block:

- `P(any invalid tx ever accepted) ≤ N_block * ε_block + (N_block * m̄) * ε_tx`
- Note: `N_block * m̄` is exactly `N_tx` if every tx is attempted on-chain.

This shows why transaction-proof soundness is the primary lever: `ε_tx` is multiplied by total transaction volume.

### 2.3.1 “How many bits is enough?” (a concrete way to decide)

If we accept the union-bound model and want:

- `N_tx * 2^-λ ≤ 2^-μ` (total validity failure probability ≤ 2^-μ)

Then we need:

- `λ ≥ μ + log2(N_tx)`

Example:

- If `N_tx ≈ 2^40` and we want `μ = 60`, we need `λ ≥ 100`.

This gives a concrete yardstick: “~100-bit validity soundness” is a plausible lifetime safety target at high volume; “~46-bit” is not.

If we instead decide to cap our target at `λ = 85` to match 256-bit PQ collision security, then:

- For `N_tx ≈ 2^40`, `P(any failure) ≤ 2^40 * 2^-85 = 2^-45` (~2.8e-14).
- For `N_tx ≈ 2^60`, `P(any failure) ≤ 2^60 * 2^-85 = 2^-25` (~3e-8).

So “85-bit validity soundness” can be defensible for moderate lifetime volume, but it is not “absurdly safe forever”; the risk scales linearly with total attempted transactions.

### 2.4 Hash function bound (what “post-quantum” means here)

Winterfell says soundness is limited by hash collision resistance. In post-quantum terms:

- If a digest is `n` bits, classical generic collision cost is ~`2^(n/2)`.
- Quantum generic collision cost is ~`2^(n/3)` (best-known generic bound for collision finding).

So a 256-bit digest has:

- Classical collision security ~128 bits.
- Quantum collision security ~85 bits.

If we truly require 128-bit post-quantum collision security for the Merkle commitments inside the STARK, a 256-bit digest is not enough; you need ~384-bit digests. This would be a protocol-wide change because commitments, nullifiers, Merkle nodes, and hashes are currently modeled as 32 bytes in many places.

Actionable conclusion: we must pick what “post-quantum security target” actually means for STARK commitments, and then make the digest size consistent with that choice. Right now the design docs and code do not line up on this point.

## 3. Proof-Carrying Blocks: Complexity and Latency Budgets

### 3.1 Why verification scales (and what does not)

If blocks include one recursive proof that verifies all transaction proofs and state updates:

- Verifier work per block becomes O(1) (verify one proof + small header checks).
- Proof size is roughly O(num_queries * log(trace_length)) for a fixed AIR, which grows slowly with trace length (logarithmic).

What does not scale:

- Prover work for the recursive proof is still O(m): the prover must simulate verification of `m` inner proofs inside the outer trace.

So the bottleneck moves from “every node verifies m proofs” to “block producer must generate one outer proof fast enough”.

### 3.2 Block producer budget constraint

In a PoW chain where the header commits to the proof:

- The miner cannot start “real mining” until it has the proof commitment, because the header hash depends on it.
- Therefore, outer proof generation latency competes with mining time and increases stale rate.

A practical requirement (not a theorem) is:

- `T_prove_outer(m) << T_block`

Even a weak constraint like `T_prove_outer(m) ≤ 5s` for `T_block = 60s` is already challenging if recursive verification per inner proof is heavy.

This is why Milestone 1 in the ExecPlan (measure recursion overhead against real transaction proofs) is not optional. It is the gating measurement that determines feasible `m`.

### 3.3 State growth math (commitment tree and nullifiers)

If each transaction has `i` input nullifiers and `o` output commitments, then per block:

- Nullifiers added: `m * i`
- Commitments appended: `m * o`

If commitments are 32 bytes on the wire, commitment payload per block is:

- `Bytes_cm = 32 * m * o`

If nullifiers are 32 bytes:

- `Bytes_nf = 32 * m * i`

These are small compared to ciphertext payloads and proof payloads, but they still matter for bandwidth and storage.

## 4. Data Availability (DA): Reed–Solomon + Sampling Math

The ExecPlan currently sketches “encode blob into erasure-coded chunks, Merkle root over chunks, sample a few chunks”.

This section spells out the math and also explains why deterministic sampling is broken.

### 4.1 1D Reed–Solomon model

Take a blob of size `D` bytes.

Choose:

- `k` data shards
- `p` parity shards
- `n = k + p`

Set chunk size:

- `c = ceil(D / k)` (each data shard is `c` bytes; last padded)

Encoding overhead:

- Total bytes transmitted/stored: `n * c`
- Overhead factor: `(k + p) / k = 1 + p/k`

Reconstruction:

- Any `k` shards suffice to reconstruct.
- Availability fails if fewer than `k` shards are obtainable.
- So a withholding attacker must cause `t > p` shards to be unavailable to break reconstructability.

Minimal withholding to break availability:

- `t_min = p + 1`
- Withheld fraction: `f_min = (p + 1) / n`

Merkle proof size for a sampled chunk:

- For a binary Merkle tree over `n` chunk hashes, authentication path length is `ceil(log2(n))`.
- With 32-byte hashes, Merkle proof size is `32 * ceil(log2(n))` bytes.

Example: for `n = 192`, `ceil(log2(n)) = 8`, so a Merkle proof is 256 bytes.

### 4.2 Sampling detection probability (single node)

Assume a node samples `s` distinct shard indices uniformly at random without replacement and tries to fetch them. If the producer has withheld `t` shards (cannot or will not serve them), the probability the node misses all withheld shards is:

- Exact: `P_miss = C(n - t, s) / C(n, s)`
- Upper bound (useful approximation for sizing): `P_miss ≤ (1 - t/n)^s`

So detection probability is:

- `P_detect = 1 - P_miss`

Bandwidth cost per sampling node (excluding transport framing and retries):

- Each sampled chunk download is `c` bytes of data plus ~`32 * ceil(log2(n))` bytes of Merkle proof.
- So per block: `Bytes_sampled ≈ s * (c + 32 * ceil(log2(n)))`.

Sizing rule of thumb (for small `t/n`):

- `s ≥ ln(1/δ) / (t/n)` to make `P_miss ≤ δ`

Plugging `t = p + 1` gives a conservative sizing for the “bare minimum” withholding attacker.

### 4.3 Sampling detection probability (many honest samplers)

If `H` honest nodes sample independently and all refuse to accept/relay a block when they fail to fetch a sample, then the probability the block escapes detection (all miss) is approximately:

- `P_escape ≈ (P_miss)^H`

This is why per-node randomized sampling is powerful: the producer cannot predict all samplers’ choices.

### 4.4 Why deterministic sampling is not a security mechanism

If sample indices are deterministically derived from public data known to the producer at block construction time (e.g., parent hash and height), then:

- The producer knows exactly which shards will be sampled by every validator.
- The producer can publish those sampled shards and withhold the rest.
- Every validator passes its DA check, yet the blob may still be unreconstructable for anyone who didn’t receive the extra shards.

In PoW this is worse if sampling depends on the current block hash:

- The producer can grind over nonces to find a hash that yields “favorable” sample indices (sample only shards it is willing to publish).

Therefore, deterministic sampling only works if the sampling seed is unpredictable to the producer at the time the DA root is committed. Parent hash and height do not satisfy that.

This is not a minor tweak. It is a fundamental correctness issue that must be resolved before implementation.

### 4.5 DA designs that actually have teeth (and the math you size from)

Option A: Per-node private sampling (network-level enforcement)

- Each node chooses its own random `s` indices after receiving a block header (or block body).
- The node requests those shards; if any fail, it refuses to relay/extend the block.
- Security comes from the probability analysis above (`P_miss`), amplified across `H` nodes.
- This is probabilistic and does not require a global deterministic sampling rule.

Option B: Delayed sampling from future randomness (consensus-level enforcement)

- Commit to DA root in block `B`.
- Define sampling seed as some randomness not known when producing `B`, for example derived from block `B + r` after `r` confirmations.
- Nodes treat `B` as provisional until the delayed DA check passes.
- Math is still `P_miss`, but correctness depends on “producer cannot predict/bias future randomness enough to avoid sampling”.
- In PoW, “cannot bias” is subtle; it requires an analysis of grinding power and reorg games.

Option C: Committee / beacon randomness

- Add a randomness beacon (threshold signature / VRF committee) that the producer cannot bias unilaterally.
- This is a new consensus subsystem; the math includes threshold security, committee honesty assumptions, and liveness.

For this project’s current posture (“PoW, no committees”), Option A is the only one that is immediately implementable without changing consensus.

## 5. Choosing Concrete DA Parameters (example sizing)

This section turns formulas into example numbers. These are not “final”; they are “starting points you can defend”.

Assume we want, per honest sampling node:

- `P_miss ≤ 2^-40` against a minimally-withholding attacker (`t = p + 1`).

Pick `k = 128`, `p = 64`:

- `n = 192`
- `t_min = 65`
- `f_min = 65/192 ≈ 0.339`

Using the approximation `P_miss ≈ (1 - f_min)^s`:

- Need `s ≥ ln(2^40) / ln(1/(1 - 0.339))`
- `ln(2^40) ≈ 27.7`
- `ln(1/(0.661)) ≈ 0.414`
- `s ≥ 27.7 / 0.414 ≈ 67`

So `s = 64` is slightly under this bound, `s = 72` clears it, `s = 80` gives slack.

Bandwidth cost per sampler is `s * c`. If `c = 1024 bytes`, then `s = 80` costs ~80 KB of fetch per block, which is tiny.

Including Merkle proofs with `n = 192` (256-byte proofs):

- `Bytes_sampled ≈ 80 * (1024 + 256) ≈ 102,400 bytes` (~100 KB).

Now amplify across nodes:

- If `H = 10` honest nodes sample independently with `P_miss = 2^-40`, then `P_escape ≈ 2^-400` (essentially zero).

This shows why per-node randomized sampling is attractive: you can keep `s` modest.

What these numbers do not solve:

- Selective publication: if sampling is deterministic, the producer can always cheat.
- Real-world network timing: a node must have timeouts; “missing” could just be latency. That becomes an engineering parameter (timeouts, retries).

## 6. Proof Size and Bandwidth Budgets (back-of-envelope)

The scalability architecture must fit into network reality. A useful first-order model of per-block bandwidth is:

- `Bytes_block ≈ Bytes_header + Bytes_state_delta + Bytes_proof + Bytes_ciphertexts`

Where:

- `Bytes_state_delta ≈ 32 * (m * i + m * o)` for nullifiers + commitments.
- `Bytes_ciphertexts` depends on ML-KEM ciphertext sizes and memo/encryption formats.

If each output carries one ML-KEM ciphertext of 1088 bytes plus AEAD payload, a safe crude placeholder is:

- `Bytes_ciphertexts_per_output ≈ 1200–1600 bytes`
- So `Bytes_ciphertexts_per_tx ≈ o * 1200–1600`

Example with `i = 2`, `o = 2`, `m = 1000`:

- `Bytes_state_delta ≈ 32 * (1000*2 + 1000*2) = 128,000 bytes`
- `Bytes_ciphertexts ≈ 1000 * 2 * 1400 ≈ 2.8 MB`
- `Bytes_proof` (recursive block proof) target maybe tens of KB to low hundreds of KB.

So a “1000 tx / 60s” block is plausibly a few MB. That is a network design question, not an impossibility.

DA schemes become relevant when `Bytes_ciphertexts` dominates and we want to decouple “on-chain header/validity” from “bulk blob distribution”.

For 1D RS DA with `k = 128`, `p = 64`, overhead factor is `1 + p/k = 1.5x`, so a `D = 2.8 MB` ciphertext blob becomes ~`4.2 MB` encoded across DA chunks (before gossip duplication).

## 7. Theory Work Required (what must be proven or at least bounded)

If we want to claim “end-to-end PQ + scalable + safe”, we need more than engineering. The minimal theory work list:

1. STARK soundness in the Quantum Random Oracle Model (QROM) for the Fiat–Shamir transform used, with explicit parameters.
   - The repo currently mixes “Grover halves security” intuition with collision-based commitments; those are different quantum models.

2. Hash/permutation security claims for the in-circuit hash used in recursion (RPO / Poseidon-style permutations):
   - Required: bounds against algebraic attacks, differential/linear attacks, and quantum generic attacks.
   - Required: explicit mapping from “round count” to “security level”.

3. Recursive composition security:
   - If inner proofs are verified in-circuit, prove that the outer proof’s statement binds to the exact public inputs we use to update state.
   - Explicitly define what is public input vs witness for the outer proof (especially whether inner proof bytes are included and how they are bound).

4. DA sampling security against adaptive adversaries:
   - If we choose per-node sampling, the claim is: “with high probability, a withheld blob cannot propagate because honest nodes will detect missing shards and refuse to relay”.
   - This needs a model of honest node fraction and independence assumptions.

5. PoW grinding/bias analysis if any sampling seed depends on block hash:
   - If the producer can choose among many candidate hashes, it can bias any deterministic sampling derived from the hash.
   - You need a bound on bias as a function of hashpower spent.

This is why the ExecPlan should treat DA sampling design as a gated “math-first” milestone, not an implementation detail.

## 8. Concrete Parameter Recommendations (v0, v1)

These are starting points to drive implementation and benchmarking. They are intentionally explicit so we can say “we used X, got Y, changed to Z”.

### 8.1 Validity proofs (transaction + recursive block)

v0 (engineering / measure-first, not production-grade):

- Keep existing inner proof options to get recursion working end-to-end.
- Measure actual effective security assumptions and overhead.
- Explicitly document that this is not settlement-grade.

v1 (aiming at “union-bound safe” lifetime security):

- Upgrade transaction proofs used by consensus to use `FieldExtension::Quadratic` or `Cubic`.
- Choose `(num_queries, blowup_factor, grinding_factor)` so `num_queries * log2(blowup_factor) + grinding_factor ≥ 100`.
- Keep hashes consistent with recursion (RPO Fiat–Shamir everywhere that will be recursively verified).

If we refuse to change digest sizes beyond 256 bits, acknowledge that post-quantum collision security is not 128 bits and state the actual bound we accept.

### 8.2 Data availability (if we keep 1D RS + sampling)

v0 (simple, measurable):

- RS parameters: `k = 128`, `p = 64`, `n = 192`
- Chunk size: `c = 1024 bytes` (tune later)
- Sampling: per-node randomized, `s = 80` samples per block
- Relay rule: do not relay/extend blocks until sampled chunks are fetched and verified against DA Merkle root.

This gives per-node `P_miss` around 2^-40 against minimal withholding, and becomes overwhelming across multiple honest nodes.

If we insist on “consensus-determined sampling”, we must introduce unpredictability (delayed sampling or randomness beacon). Without it, the math says it is not a security mechanism.

## 9. What to Measure (to turn this into engineering reality)

Before implementing the architecture, Milestone 1 must produce these numbers:

- Inner transaction proof size (bytes) and verification time (ms).
- Outer recursive verifier proof size (bytes) and verification time (ms).
- Outer prover time (ms) for verifying 1 inner proof, then 2, 4, 8, … (to estimate slope).

For DA, we need:

- Encode time for RS parameters (k, p, c) for realistic blob sizes.
- Fetch+verify time for `s` samples under realistic latency and timeouts.
- Practical rate of false negatives due to timeouts (engineering, but it affects the “missing” predicate).

Until those are measured, “fundamentally scalable” is not an implementation task; it is a hypothesis.
