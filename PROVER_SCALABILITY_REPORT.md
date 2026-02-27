# Hegemon Network Scalability and Prover Optimization Report (Validated Revision)

## 0. Latest empirical bottleneck (measured on February 27, 2026)

Environment:

- `hegemon-prover` (32 vCPU / 256 GiB RAM), branch `codex/review-zk-circuits-and-pqc`.
- Strict aggregation test (`tx_count=2`) on local benchmark node (`--dev --tmp --rpc-port 9955`).
- Profiling enabled with `HEGEMON_AGG_PROFILE=1`.

Observed aggregation stage timings for the first `tx_count=2` cache miss:

- `cache_verify_inner(tx0)`: ~2.17s
- `cache_verify_inner(tx1)`: ~2.17s
- `cache_circuit_build`: ~87.95s
- `cache_airs_setup`: ~11.03s
- `common_prepare_metadata`: ~9.09s
- `common_commit_preprocessed`: **~817.57s (13.63 min)**
- `common_build_lookups` (32 threads): ~0.02s
- `cache_build_ms total`: **~930.01s (15.50 min)**
- `runner_run`: ~15.99s

After this point, the run remained in outer proving with high memory pressure (RSS reached ~77 GiB) and did not finish within short operational windows. This confirms the dominant bottleneck is not wallet submission or peer connectivity; it is recursion keygen/preprocessing and first-cache proving latency for multi-tx aggregation.

Operational consequence:

- With same-block `submit_proven_batch` requirements, first multi-tx cache build time alone can jam transaction inclusion for many minutes unless the cache is prebuilt ahead of user traffic.

## 0.1 Critical problems, implemented mitigations, and expected gains

### Critical problems (validated on `hegemon-prover`)

1. Cold recursive aggregation cache build dominates latency.
   - `tx_count=2` reaches `common_prepare_metadata`, then remains in `common_commit_preprocessed` for many minutes.
   - In the latest strict run, `common_commit_preprocessed` had not completed after >14 minutes (job was still active with ~37 GiB RSS).
2. First-user experience is dominated by cold-start proving, not by networking or wallet RPC.
3. Throughput tests were historically mixing two goals:
   - measuring end-to-end inclusion TPS,
   - warming recursive aggregation caches.
   This made operator feedback noisy and hard to act on.

### Implemented mitigations in this revision

1. Throughput harness now supports explicit warmup mode:
   - `HEGEMON_TP_PREWARM_ONLY=1`
   - exits after a ready proven batch is observed, before inclusion/mining stage.
2. Throughput harness now supports network wiring without editing script internals:
   - `HEGEMON_TP_SEEDS`
   - `HEGEMON_TP_MAX_PEERS`
3. Strict wait is now measured and emitted:
   - `prewarm_metrics ... strict_wait_ms=...`

### Validation snapshot

- `tx_count=1`, `prewarm_only=1`:
  - `Prepared proven batch candidate ... build_ms=255`
  - `strict_wait_ms=1046`
- `tx_count=2`, strict aggregation:
  - cold build reaches `common_prepare_metadata`, then stalls in `common_commit_preprocessed` for >14 minutes.

### Quantitative expectation from this mitigation set

This change does not make cold recursion itself faster; it makes operations deterministic:

1. Operators can prewarm before user traffic.
   - Expected user-visible latency improvement for first multi-tx aggregation:
     - from O(10–20 min) cold to O(seconds–tens of seconds) once warm.
2. Networked benchmark runs can be executed with explicit seeds/peer caps, avoiding hidden single-node assumptions.
3. TPS measurements become comparable across runs because warmup and inclusion phases are now separable.

## 0.2 Newly validated architecture bug and fix (February 27, 2026)

### Critical problem: incremental batch-shape churn

During mempool ramp-up, the coordinator was effectively willing to upsize candidates one step at a time (`1 -> 2 -> 3 -> 4 ...`) in liveness mode. For recursive aggregation, each new `tx_count` shape can trigger another heavy cache build path and stale in-flight work.

This is exactly the wrong economic profile for a prover market: expensive large machines should spend cycles on a small number of high-value batch shapes, not on adjacent intermediate shapes.

### Implemented solution

1. Added checkpointed upsizing as the default coordinator behavior.
   - New mode keeps deterministic geometric laddering against `HEGEMON_BATCH_TARGET_TXS` (for example `1/2/4/8/.../target`) instead of per-transaction `+1` upsizing.
2. Added explicit legacy override:
   - `HEGEMON_BATCH_INCREMENTAL_UPSIZE=1` restores old per-step behavior.
3. Wired benchmark harness passthrough:
   - `HEGEMON_TP_BATCH_INCREMENTAL_UPSIZE` now controls the mode in throughput runs.
4. Added tests:
   - coordinator tests now validate both checkpoint mode and legacy override.
   - shape-ramp test proves unique scheduled batch shapes drop from 8 to 4 for target=8, queue=4.

### Validation snapshot (same workload, same host: `hegemon-prover`)

Workload:

- `tx_count=4`, liveness mode enabled, queue capacity 4, strict aggregation.
- Fast-proof benchmark mode used to isolate coordinator scheduling effects quickly.

Observed from node logs:

1. Legacy incremental mode (`HEGEMON_BATCH_INCREMENTAL_UPSIZE=1`):
   - preemption occurred at `existing_best_tx_count=3 -> candidate_tx_count=4`
2. Checkpoint mode (`HEGEMON_BATCH_INCREMENTAL_UPSIZE=0`, default):
   - preemption occurred at `existing_best_tx_count=2 -> candidate_tx_count=4`

Interpretation:

- checkpoint mode skips at least one intermediate expensive shape under the same tx ramp (`3` in this case), reducing wasted stale work before the target batch.
- this effect grows with larger targets and noisier mempool ramps.

### Quantitative expectation from this fix

For liveness+throughput mixed operation:

1. Unique shape count per ramp drops from roughly `O(target_txs)` toward `O(log2(target_txs))`.
2. Stale proving pressure drops proportionally (fewer superseded candidates).
3. Better prover ROI on big machines:
   - more cycles on target batches,
   - fewer cycles on transient intermediate candidates.

## 0.3 Robustness vs attackability (current verdict)

Current design is not "easy to break", but it is not yet at mature-internet-grade hardening either.

### Strong points already in place

1. Chain-isolation hardening:
   - strict genesis compatibility filters for peer sync/discovery (`HEGEMON_PQ_STRICT_COMPATIBILITY`).
2. Proof-carrying safety:
   - SelfContained mode fail-closes proofless sidecar transfers without a matching `submit_proven_batch`.
3. Prover-market abuse controls:
   - package TTL, per-source submission limits, per-package caps, payload-size caps.
4. Candidate sanitation:
   - duplicate-binding and nullifier-conflicting transfers filtered before expensive proving.

### Remaining high-priority risk classes

1. Cold-start proving DoS economics:
   - first-time recursive shape builds remain very expensive.
2. Resource exhaustion by adversarial tx shape churn:
   - now mitigated by checkpoint upsizing, but still sensitive under many distinct batch targets across nodes.
3. Observability gap for operator response:
   - stronger alerting/SLOs are still needed around prepare-latency, stale-job ratio, and ready-batch age.

### Practical verdict

- Robust enough for controlled testnet iteration with tuned operators.
- Not yet robust enough for open, adversarial public onboarding at scale until cold-cache latency and operational guardrails are tightened further.

## 0.4 Newly fixed cache architecture bug on big provers (February 27, 2026)

### Critical problem

The aggregation prover cache mixed two very different artifact classes:

1. full recursion entries (circuit + verifier targets), which are **not thread-safe** and therefore stay thread-local; and
2. `CommonData` preprocessing (the `common_commit_preprocessed` path), which is expensive and can be shared across workers.

With multiple prover workers, this caused duplicate cold preprocessing for the same `(tx_count, pub_inputs_len, proof_shape)` under contention.

### Implemented solution

1. Kept full recursion entries thread-local for correctness.
2. Added a process-wide singleflight cache for `CommonData`, keyed by the same aggregation shape.
3. New behavior:
   - first worker builds and publishes `CommonData`;
   - concurrent workers for the same key wait and reuse it instead of rebuilding preprocessing.

### Validation snapshot (`hegemon-prover`, fast strict run, tx_count=4 ramp)

Observed for `tx_count=2` under worker contention:

- `cache_circuit_build` appeared twice (`~84.97s`, `~119.01s`) as expected for thread-local full entries.
- `cache_airs_setup` appeared twice (`~11.31s`, `~12.27s`).
- `common_prepare_metadata` appeared once for that shape (`~8.91s`) before long preprocessing.

Interpretation:

- duplicate full-entry build still exists by design (non-thread-safe circuit objects),
- but shared `CommonData` preprocessing is now deduped per shape across workers.

### Quantitative expectation

Using measured cold-stage magnitudes (`common_commit_preprocessed` dominates at ~817s):

- Old two-worker same-shape cold path (approx):
  - `2 * (circuit + airs + common_commit)` ~= `2 * (90s + 11s + 817s)` ~= **1836s**
- New two-worker same-shape cold path (approx):
  - `2 * (circuit + airs) + 1 * common_commit` ~= `2 * (90s + 11s) + 817s` ~= **1019s**

Expected savings under two-worker contention: roughly **44–46% less cold-stage wall-clock/cost** for that shape.
Savings increase with more contending workers because `common_commit` remains singleflight.

### Why this matters for your objective

This change directly improves the economics of large prover machines:

- less duplicated preprocessing work,
- better memory/CPU efficiency under concurrent proving pressure,
- better path to sustained batched proving where per-tx cost must drop below single-proof mode.

It is necessary but not sufficient for 10–100 TPS; additional work is still required on cold-start latency and batch-shape residency.

## 0.5 Controlled A/B benchmark: single-proof vs aggregation (February 27, 2026)

Environment:

- Host: `hegemon-prover` (32 vCPU / 256 GiB RAM)
- Script: `scripts/throughput_sidecar_aggregation_tmux.sh`
- Build/profile: `HEGEMON_TP_FAST=1`, `HEGEMON_TP_PROFILE=max`
- Workload: `tx_count=4`, `workers=1`, `coinbase_blocks=6`

### A) Single-proof baseline (`HEGEMON_TP_PROOF_MODE=single`)

Measured output:

- `payload_cost_metrics included_tx_count=4 tx_proof_bytes_total=1428166 proven_batch_bytes=0 payload_bytes_per_tx=357041.50`
- `throughput_round_metrics ... inclusion_tps=0.056389 end_to_end_tps=0.052505 effective_tps=0.056389`

Interpretation:

- Single-proof path currently works end-to-end under this benchmark.
- Cost is very high in block payload terms (~357 KB per tx of inline proof bytes).

### B) Aggregation prewarm (`HEGEMON_TP_PROOF_MODE=aggregation`, strict, prewarm-only)

Measured output with bounded wait (`HEGEMON_TP_STRICT_PREPARE_TIMEOUT_SECS=300`):

- `Strict aggregation mode: timed out waiting for local proven batch candidate.`
- Profile before timeout:
  - `cache_circuit_build tx_count=4 build_ms=226222`
  - `cache_airs_setup tx_count=4 setup_ms=25422`
  - `common_prepare_metadata ... total_ms=26300`
  - no completed `common_commit_preprocessed` / no ready batch before timeout

Interpretation:

- Under current architecture, aggregation does not yet beat single-proof mode for first-user latency at `tx_count=4`; it misses readiness entirely in the bounded window.
- This validates that the remaining bottleneck is still deep preprocessing/commitment in recursive aggregation cold-start.

### Quantitative conclusion vs objective

Current result is opposite of the product objective:

1. **Faster**: not achieved yet in cold path (aggregation readiness misses while single mode delivers ~0.056 TPS in this test).
2. **Cheaper**: aggregation should be cheaper per tx once ready, but current readiness latency prevents that benefit from being realized at user-visible timescales.

Immediate acceptance gate for "big prover advantage":

1. `tx_count=4` strict-ready latency < 60s after warmup.
2. inclusion TPS in aggregation mode > single mode on the same workload.
3. payload bytes/tx in aggregation mode materially below ~357 KB/tx single-proof baseline.

## 0.6 Latest implementation checkpoint (commit `dcb7977c`, February 27, 2026)

Implemented in code:

1. One-pass candidate preprocessing + parallel commitment/aggregation build path remains active and validated.
2. Aggregation hot-path optimizations:
   - precomputed witness assignment plans (target -> witness-id) in cache entry build,
   - runtime witness assignment now reuses those plans,
   - challenge derivation parallelized across proofs using `HEGEMON_AGG_LEVEL_PARALLELISM`,
   - recursion public-value buffer reserves based on first packed proof to reduce realloc churn.
3. Prover coordinator stage controls:
   - additive env controls: `HEGEMON_AGG_STAGE_LOCAL_PARALLELISM`, `HEGEMON_AGG_STAGE_QUEUE_DEPTH`, `HEGEMON_PROVER_STAGE_MAX_INFLIGHT_PER_LEVEL`,
   - per-level inflight dispatch cap enforcement,
   - stage plan/status snapshot API for observability.
4. Additive stage RPC endpoints:
   - `prover_getStageWorkPackage`,
   - `prover_submitStageWorkResult`,
   - `prover_getStagePlanStatus`.
5. Throughput harness artifacts and parser flow remain active from prior checkpoint.

Validation:

1. `make check` passed on this revision (fmt, clippy `-D warnings`, workspace tests/doc tests).
2. Targeted tests passed:
   - `aggregation-circuit`,
   - `hegemon-node` coordinator/service/rpc suites.

Latest measured A/B (same host/profile, local benchmark harness, `tx_count=1`):

1. Aggregation mode (`postopt-throughput-tx1`):
   - `submission_tps=0.727802`
   - `inclusion_tps=0.194250`
   - `end_to_end_tps=0.129735`
   - `payload_bytes_per_tx=407574`
   - `strict_wait_ms=1112`
2. Single-proof mode (`postopt-single-tx1`):
   - `submission_tps=0.709723`
   - `inclusion_tps=0.059709`
   - `end_to_end_tps=0.054924`
   - `payload_bytes_per_tx=356893`

Observed ratio (aggregation vs single, `tx_count=1`):

1. inclusion TPS: ~`3.25x`
2. end-to-end TPS: ~`2.36x`

Important caveat:

- This is still far below the `>=10 TPS` gate and uses a singleton workload.
- A `tx_count=2` strict aggregation run on laptop orchestration still entered a long strict-wait path and was aborted to avoid wasting runtime; full remote-first sustained runs on `hegemon-prover` + `hegemon-ovh` remain required for acceptance.

## 1. Computational operations by operator and scaling vs TPS

Let:

- $T$ = target TPS
- $\Delta_b$ = block time in seconds
- $n = T\Delta_b$ = transactions per block
- $I, O$ = avg inputs/outputs per shielded transaction

### 1.1 Wallet (user client)

**Operations**

- Key derivation / address management (low frequency).
- Note encryption/decryption for sent/received outputs.
- Chain scanning (trial decrypt / candidate detection over output ciphertext stream).
- Optional local proof generation.

**Scaling**

- Outbound proving cost scales with user’s own send rate, not global TPS.
- Inbound scanning cost scales with global output flow:
  - per-second scanning work is roughly proportional to $T \cdot O$.
  - this is the dominant wallet bottleneck at large $T$.

**Main load location**

- CPU + battery (mobile) for scan/decrypt path.
- I/O and bandwidth for syncing ciphertext stream.

### 1.2 Prover / coordinator (prover market)

**Operations**

- Build witnesses for transaction proofs.
- Generate transaction STARK proofs.
- Generate commitment proof (nullifier uniqueness + statement commitment binding).
- Generate/verify aggregation proof artifact for block-level validity compression.

**Scaling**

- Total proving demand is approximately linear in transaction flow:
  - transaction proving throughput requirement: $\Theta(T)$ proofs/sec (modulo batching).
- Aggregation proving grows with batch size; proving work is not free even when on-chain verification is $O(1)$.
- Commitment-proof workload tracks per-block transaction count $n$ and nullifier/statement set sizes.

**Main load location**

- This is the heaviest compute role: FFT/LDE-heavy proving, transcript hashing, witness generation, serialization/compression.
- Resource pressure shifts from validators to prover workers (CPU/GPU, RAM, memory bandwidth).

### 1.3 Miner / block producer

**Operations**

- PoW hashing (difficulty race).
- Candidate block assembly from mempool and ready proven bundles.
- Header signing and block propagation.

**Scaling**

- PoW hashing cost is independent of TPS target (set by difficulty, not transaction count).
- Assembly/scheduling overhead increases with mempool pressure and proof-readiness coordination.
- In current architecture, miners are bottlenecked by **proof availability latency**, not proving themselves, when they depend on external proving.

### 1.4 Full node / validator-equivalent verifier

**Operations**

- Verify block-level proof artifacts (commitment + aggregation path as configured).
- Deterministic state transition checks and updates.
- Nullifier-set and commitment-tree updates.
- Signature and block-structure validation.

**Scaling**

- Cryptographic proof verification count can be bounded to $O(1)$ per block in aggregation mode.
- Deterministic per-transaction checks and state updates still scale with block load ($\Theta(n)$).

**Main load location**

- Moderate CPU for verification + hashing.
- Persistent I/O and state update overhead for nullifier/commitment state.

---

## 2. Where the load goes as TPS grows

### 2.1 Balance feasibility

A sustainable balance is feasible if and only if:

1. proving throughput keeps up with transaction inflow,
2. block bodies remain bounded (proof sidecar/aggregation strategy),
3. wallet scan path is offloaded or filtered enough to remain usable.

In this model, the architecture intentionally concentrates expensive cryptography in prover infrastructure and keeps consensus verification compact.

### 2.2 Bottlenecks at increasing TPS

1. **Prover throughput bottleneck** (first-order)
   - If proving capacity $C_p$ (tx proofs/sec equivalent) falls below arrival rate $T$, backlog grows:
   - $\text{queue growth} \approx (T - C_p)^+$.

2. **Wallet scanning bottleneck**
   - Naive trial scanning scales with network-wide output flow, not user activity.
   - Mobile wallets become non-viable without delegated scanning/indexing.

3. **Bandwidth/storage bottleneck (DA + ciphertext payloads)**
   - Commitments/nullifiers are compact, but encrypted notes dominate payload growth.
   - Sidecar and retention policies become mandatory at high throughput.

4. **Coordination/liveness bottleneck**
   - If block builders wait synchronously for non-ready proofs, liveness degrades.
   - Asynchronous prebuild + fallback subset selection is required for stable block production.

---

## 3. Quantitative scaling model (engineering)

### 3.1 Per-block compute envelopes

With $n = T\Delta_b$:

- Prover market total work per block:
  $$
  W_{\text{prover}}(n) \approx n \cdot w_{\text{tx}} + w_{\text{commit}}(n) + w_{\text{agg}}(n)
  $$
- Node verification work per block:
  $$
  W_{\text{node}}(n) \approx w_{\text{verify-const}} + n \cdot w_{\text{state-step}}
  $$
  where $w_{\text{verify-const}}$ is bounded proof verification cost (aggregation + commitment), and $w_{\text{state-step}}$ is deterministic per-tx update/check cost.

### 3.2 Capacity planning for proving

If one prover worker handles $\mu$ tx-proofs/sec-equivalent and there are $k$ workers:
$$
C_p = k\mu
$$
To avoid unbounded queueing, target:
$$
k \ge \frac{T}{\mu} \cdot (1 + \text{headroom})
$$
with explicit headroom for burstiness and failed jobs.

### 3.3 Proof-size pressure

For FRI-style proofs, proof size grows approximately with:

- query count,
- Merkle branch depth (thus logarithmic in evaluation domain size),
- digest size,
- number of commitment trees/openings.

A practical sketch:
$$
|\pi| \propto Q \cdot \log N_{\text{LDE}} \cdot (\text{hash bytes}) \cdot c_{\text{openings}} + \text{caps + evaluations}
$$
This is not exact, but directionally correct for optimization planning.

---

## 4. Prover micro-optimization: detailed and prioritized

### 4.1 Parameter guardrails (must preserve security target)

Current production profile:

- `log_blowup = 4` (blowup factor 16)
- `num_queries = 32`
- `pow_bits = 0`

Engineering soundness heuristic used in current docs:
$$
\lambda_{\text{FRI}} \approx Q\log_2(B) + \text{pow\_bits}
$$
So baseline is $32\cdot 4 = 128$ bits.

**Implication**: any reduction in $Q$ must be compensated (or offset by other proven parameter effects) before claiming unchanged 128-bit target.

### 4.2 “Can ship sooner” optimization track

1. **Aggressive prover parallelism and scheduling**
   - Keep asynchronous coordinator queueing.
   - Prefer largest-ready-subset inclusion policy to preserve liveness when full batch is not ready.
   - Maintain deterministic fallback candidates (including singleton liveness candidate).

2. **Witness pipeline optimization**
   - Profile witness generation separately from cryptographic proving.
   - Remove serialization and allocation hot spots before touching AIR design.

3. **Proof artifact compression/transport tuning**
   - Continue compression and cache-warm verifier artifacts where safe.
   - Keep strict binding checks so compression never weakens statement binding semantics.

4. **Runtime-configurable proving tiers for non-production**
   - Preserve strict production defaults while allowing explicit “fast/dev” profiles for local iteration.

### 4.3 “Medium-risk, high-upside” circuit/AIR optimization track

1. **MASP balance argument redesign**
   - Current sort/permutation approach is robust but can be cost-heavy.
   - Investigate lookup-based accumulation variants (LogUp/Lasso-like ideas) to reduce constraint/memory footprint.
   - Must preserve clear soundness argument and deterministic serialization/binding.

2. **Poseidon2 usage minimization in expensive paths**
   - Keep protocol-critical in-circuit hashes stable.
   - Where possible, reduce unnecessary repeated hash invocations through trace/layout engineering.

3. **Trace width/degree tuning**
   - Minimize transition degree and quotient chunk pressure without changing statement semantics.
   - Any proposal that changes degree/bound assumptions must be benchmarked with actual row counts and soundness accounting.

### 4.4 Engineering redesign options

1. **Field migration (Goldilocks → BabyBear/Mersenne31)**
   - Potential SIMD/GPU throughput gains.
   - But this is a protocol-level migration touching AIRs, constants, recursion compatibility, serialization, and governance/versioning.

2. **Hash/transcript stack redesign (e.g., mixed hash strategy)**
   - Could improve CPU throughput in non-recursive contexts.
   - Requires strict compatibility analysis for recursive verification and transcript consistency.

3. **Higher-arity FRI / altered folding strategy**
   - Can reduce layer count and branch overhead.
   - Trade-off with prover complexity and implementation risk must be measured, not assumed.

---

## 5. 128-bit PQ compatibility analysis of optimization ideas

### 5.1 Field size vs security

Small base fields (e.g., 31-bit) do not directly provide 128-bit soundness. Security comes from full protocol parameters (queries, blowup, extension field behavior, transcript/hash assumptions), not from base-field size alone.

### 5.2 Hash capacity and PQ collision margins

Current 48-byte digest / 384-bit capacity design is aligned with an engineering target around 128-bit PQ collision resistance under BHT-style reasoning.

### 5.3 Soundness accounting discipline

Every optimization proposal must carry updated accounting for:

- FRI/IOP engineering soundness,
- transcript/hash binding margin,
- minimum of the two as effective system target.

No parameter change should be accepted with only prover-speed wins reported.

### 5.4 Compatibility of recommendations with 128-bit PQ targets

The following classifies each recommendation from this report against three distinct requirements:

- **Authentication**: block/header/network identity signatures (ML-DSA path).
- **Soundness**: STARK/FRI proof-system soundness + transcript/commitment binding.
- **Encryption**: note/privacy encryption path (ML-KEM + AEAD).

#### A) Compatible now (no PQ-security downgrade when implemented carefully)

1. **Scheduler/parallelism/witness-pipeline optimization**
   - Authentication: **Compatible** (no signature primitive change).
   - Soundness: **Compatible** (no proof-parameter weakening required).
   - Encryption: **Compatible** (no KEM/AEAD primitive change).

2. **Proof compression/transport/cache engineering**
   - Authentication: **Compatible**.
   - Soundness: **Compatible if lossless and binding-preserving** (proof bytes, statement commitments, and transcript inputs must remain canonical and unchanged).
   - Encryption: **Compatible**.

3. **Lookup-based MASP argument redesign (LogUp/Lasso-like direction)**
   - Authentication: **Compatible**.
   - Soundness: **Conditionally compatible** (requires fresh soundness analysis, implementation audit, and updated public-input/binding tests).
   - Encryption: **Compatible**.

#### B) Conditionally compatible (research-track; do not assume immediate equivalence)

4. **Field migration to BabyBear/Mersenne31**
   - Authentication: **Compatible** if ML-DSA stack is unchanged.
   - Soundness: **Conditionally compatible** only if parameterization and extension-field choices are re-derived to keep >=128-bit engineering target under the adopted model.
   - Encryption: **Compatible** if ML-KEM + AEAD parameters are unchanged.

5. **Hash/transcript redesign or mixed-hash strategy**
   - Authentication: **Compatible** if signature suite unchanged.
   - Soundness: **Conditionally compatible**; transcript consistency, recursion constraints, and commitment binding must be re-proven and benchmarked.
   - Encryption: **Usually compatible**, provided note-encryption domain separation and KDF/AEAD path are unchanged.

6. **Reducing FRI queries and compensating with grinding**
   - Authentication: **Compatible**.
   - Soundness: **Conditionally compatible**; only safe with explicit recalculation. Under current engineering heuristic with blowup 16, lowering from 32 queries to 24 requires ~32 grinding bits (not 16) to return to 128.
   - Encryption: **Compatible**.

### 5.5 Bottom-line answer for this report

Yes, the optimization direction is compatible with keeping 128-bit PQ security **if** changes preserve the current cryptographic primitives for authentication/encryption and maintain (or re-establish with evidence) the proof-system soundness target.

In practical terms:

- **Authentication (ML-DSA)**: remains at target unless signature primitives/parameters are changed.
- **Encryption (ML-KEM + AEAD)**: remains at target unless KEM/AEAD/KDF parameters are changed.
- **Soundness (FRI + transcript/hash binding)**: the sensitive axis; every prover/circuit/hash/FRI change needs formalized re-accounting and acceptance criteria before deployment.

---

## 6. Thorough investigation: recursive STARK systems and transferable methods

This section focuses on **what can be transferred** to Hegemon’s current Plonky3/Goldilocks/Poseidon2 stack without violating the 128-bit PQ criteria.

### 6.1 SP1 (Succinct)

Observed architecture/techniques:

- Multi-stage recursion pipeline (`compress`, `shrink`, `wrap`) and explicit recursion worker orchestration.
- Recursive verifier key management and verification-key root/binding checks in recursion flow.
- Basefold/stacked PCS style with batched evaluations and explicit FRI query handling.
- Dedicated GPU proving path (CUDA kernels) and CPU/GPU split for heavy polynomial steps.

Transferable methods for Hegemon:

1. **Recursion task pipeline engineering**
   - Implementability: **High** (architectural/software change, not cryptographic redesign).
   - Security impact: **Compatible** if statement/vk bindings remain strict.

2. **Verifier-key root binding and strict recursion artifact checks**
   - Implementability: **Medium-High**.
   - Security impact: **Strongly positive** for soundness hardening.

3. **GPU offload for FRI/batching hotspots**
   - Implementability: **Medium** (hardware + kernel integration complexity).
   - Security impact: **Neutral-positive** if deterministic checks and identical transcript semantics are preserved.

### 6.2 RISC Zero

Observed architecture/techniques:

- Explicit layered proving stack (RISC-V prover + recursion prover + optional STARK-to-SNARK translator).
- Hardware abstraction supporting CPU/CUDA/Metal paths in recursion proving.
- Security model explicitly separates STARK security from the non-PQ SNARK wrapping path.

Transferable methods for Hegemon:

1. **Layered prover service boundaries** (prove/aggregate/optional final translation stages).
   - Implementability: **High**.
   - Security impact: **Compatible** if all mandatory validity logic remains in STARK path.

2. **Backend abstraction for heterogeneous proving hardware**.
   - Implementability: **High-Medium**.
   - Security impact: **Compatible**.

3. **Negative transfer warning**: BN254/Groth16 wrapping as a required validity path.
   - Implementability: technically possible but **NOT compatible** with strict end-to-end PQ goals if made mandatory.

### 6.3 Boojum (zkSync-era)

Observed architecture/techniques:

- Goldilocks-focused engineering with aggressive vectorization and row/column placement strategy.
- Heavy use of additive/log-derivative lookup arguments.
- Early movement to extension-field challenges in critical argument parts.
- Explicit `compute_fri_schedule` style derivation of query count/folding schedule from target security parameters.

Transferable methods for Hegemon:

1. **Lookup-heavy rewrite for costly balance/permutation logic**.
   - Implementability: **Medium** (AIR redesign).
   - Security impact: **Conditionally compatible** after renewed soundness proof/accounting.

2. **Security-driven FRI scheduling tooling** (parameter synthesis from target bits, blowup, PoW).
   - Implementability: **High**.
   - Security impact: **Positive** (reduces parameter drift risk).

3. **Constraint placement and memory locality optimization**.
   - Implementability: **Medium-High**.
   - Security impact: **Compatible**.

### 6.4 Plonky3 core ecosystem

Observed architecture/techniques:

- Variable-arity FRI support (`max_log_arity`) with per-round arity commitments in transcript.
- Built-in engineering soundness estimator: 
  $$
  \lambda_{\text{FRI}} = \log_2(B)\cdot Q + \text{query\_pow\_bits}
  $$
- Explicit handling of query PoW, commit PoW, and proof-shape consistency checks.

Transferable methods for Hegemon:

1. **Explore variable-arity FRI for proof-size reduction**.
   - Implementability: **Medium** (needs prover/verifier/plumbing updates).
   - Security impact: **Conditionally compatible** with full parameter re-derivation.

2. **Transcript-binding hardening for folding schedule and query parameters**.
   - Implementability: **High**.
   - Security impact: **Positive**.

3. **Automated soundness budget checks in CI** (reject unsafe parameter deltas).
   - Implementability: **High**.
   - Security impact: **Positive**.

### 6.5 Stwo (StarkWare libs)

Observed architecture/techniques:

- Circle-STARK style with explicit `FriConfig` controls (`blowup`, `queries`, fold step).
- Strong SIMD backend engineering for FRI fold/decompose with CPU fallback paths.
- Query/decommitment pipeline separated cleanly from commitment phase.

Transferable methods for Hegemon:

1. **SIMD-first FRI kernels with safe fallbacks**.
   - Implementability: **Medium-High**.
   - Security impact: **Compatible**.

2. **Decommitment pipeline specialization** (compute positions + witness values once, reuse).
   - Implementability: **Medium**.
   - Security impact: **Compatible**.

3. **Fold-step experimentation** (where supported) to reduce layers.
   - Implementability: **Research-medium** in current stack.
   - Security impact: **Conditionally compatible** with full verifier and soundness updates.

### 6.6 SHARP/StarkEx lineage (operational pattern)

Observed architecture/technique class:

- Shared proving/aggregation service model: many user jobs amortized into fewer verifier-facing artifacts.
- Publicly available material is stronger on operational architecture than on low-level prover internals; transfer here is therefore organizational/economic rather than algebraic.

Transferable method for Hegemon:

- **Prover-market coordinator economics and batching policy** inspired by shared-prover operations.
  - Implementability: **High** (operational design).
  - Security impact: **Compatible** if statement binding remains strict and fail-closed.

### 6.7 Cross-system implementation matrix for Hegemon

#### Adopt now (high ROI, low cryptographic risk)

1. Recursion/prover pipeline orchestration (async workers, bounded queues, deterministic fallback subsets).
2. Verifier-key/statement-binding hardening for all recursive and aggregated artifacts.
3. Soundness budget tooling and CI guards for FRI/query/PoW parameter drift.
4. Hardware abstraction and profiling discipline (CPU vs GPU) without transcript/semantics changes.

#### Implement next (requires circuit or prover refactor)

1. Lookup-based MASP balance redesign replacing expensive sort-heavy paths where possible.
2. Memory-layout and trace-placement optimization to reduce proving constant factors.
3. Selective SIMD/GPU kernels for dominant FRI and batching stages.

#### Research track (only behind explicit security re-derivation)

1. Variable/higher-arity FRI schedules.
2. Field migration (Goldilocks to 31-bit field families).
3. Hash/transcript stack changes in recursive context.

#### Avoid for strict PQ objective

- Any mandatory SNARK wrapping path based on pairing assumptions (e.g., BN254 Groth16) as the only accepted validity artifact.

---

## 7. Practical roadmap for Hegemon scaling

### Phase 1 — Immediate hardening and throughput (no cryptographic redesign)

1. **Prover coordinator pipeline upgrade**
   - Implement: bounded async queues, deterministic fallback candidate sets, singleton liveness candidate, explicit retry/backoff.
   - Success condition: no liveness stalls when full proven batch is unavailable.

2. **Binding and verification hardening**
   - Implement: strict statement commitment checks, verifier-key root binding, fail-closed block import for required proof artifacts.
   - Success condition: tampered/foreign proof artifacts always reject.

3. **Soundness guardrails in CI**
   - Implement: automatic check that active FRI/query/PoW settings satisfy declared engineering target; reject unsafe config deltas.
   - Success condition: parameter regression cannot merge unnoticed.

### Phase 2 — Prover performance engineering (same cryptographic statement)

1. **Witness hot-path optimization**
   - Implement: profile-guided optimization of serialization, memory allocation, and witness assembly.
2. **Hardware abstraction and kernel targeting**
   - Implement: isolate FRI/batching hotspots behind backend interface (CPU baseline + optional GPU/SIMD path).
3. **Decommitment/query pipeline optimization**
   - Implement: cache/reuse query-position derived structures where safe; reduce repeated derivation overhead.

Security note: all Phase 2 items are compatible with 128-bit PQ target if transcript semantics and public-input binding are unchanged.

### Phase 3 — Circuit-level upgrades (conditional on renewed analysis)

1. **Lookup-based MASP redesign**
   - Implement: replace highest-cost sort/permutation subpaths with lookup-style arguments where they reduce trace/memory pressure.
   - Gate: new soundness analysis + adversarial tests + deterministic encoding checks.

2. **Trace layout/degree optimization**
   - Implement: row/column placement and degree-pressure reduction while preserving statement semantics.
   - Gate: unchanged validity semantics + improved benchmarked throughput.

### Phase 4 — Research-track changes (protocol-level)

1. **Variable/higher-arity FRI experiments**
2. **Field migration feasibility (Goldilocks -> 31-bit families)**
3. **Hash/transcript redesign feasibility in recursion context**

Gate for all Phase 4 work:

- explicit re-derived soundness budget,
- transcript/binding audit,
- migration/rollback plan,
- governance/versioning plan.

### Non-negotiable security constraints across all phases

1. **Authentication** must remain on PQ signature path (ML-DSA family) unless replaced by an equal-or-better PQ alternative.
2. **Encryption** must remain on ML-KEM + robust AEAD/KDF path unless replaced by an equal-or-better PQ alternative.
3. **Soundness** must remain at or above 128-bit engineering target under the adopted model; speedups that reduce this target are rejected.

This preserves the core design goal: decentralizable verification with economically scalable proving.
