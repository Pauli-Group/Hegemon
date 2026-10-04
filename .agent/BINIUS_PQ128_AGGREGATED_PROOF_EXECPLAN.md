# RETRACTED: Binius PQ128 aggregated transaction proofs

> **Rejected 2026-08-18.** This plan is retained as falsification evidence, not implementation authority. It violated Hegemon's self-contained proof-carrying transaction invariant and promoted an unmeasured one-MiB aggregate allowance into a proof-size claim. No production Binius recursive verifier, strict-PQ 520-proof aggregate, or qualifying latency measurement exists. The measured off-block leaf traffic alone is roughly 148-159 MiB for 520 actions before strict-PQ widening. Do not implement or cite this plan as the selected architecture.

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept current as implementation proceeds.

This document follows `.agent/PLANS.md`. It is self-contained and intentionally supersedes any proposal to reactivate Poseidon or to place one strict-PQ Binius proof inside every canonical block action.

## Purpose / Big Picture

Hegemon needs private transaction proofs whose deployed, composed security claim reaches at least 128 post-quantum bits. Fresh consensus semantics use BLAKE2b-384 rather than Poseidon. A strict binary-field proof is substantially larger than the 124,080-byte artifact ceiling required to keep 520 transfers inside the current 64 MiB block budget. Trying to squeeze that proof into each action either misses the byte target or weakens the security claim.

The selected architecture separates two proof lifetimes:

1. A wallet creates a zero-knowledge `BiniusLeafProofV5`. It accompanies a pending action through RPC, relay, admission, and miner proof-cache paths, but it is not serialized into a canonical block.
2. A block producer constructs one `BiniusBlockAggregateV5` proving that every ordered action has an accepted leaf proof and that the exact ordered public statements imply the advertised state transition. The block contains proof-free actions plus this one aggregate.

The aggregate may be non-zero-knowledge only because its private witness is restricted to already-zero-knowledge leaf-proof bytes and verifier scratch values. The aggregate circuit must have no API by which note secrets, Merkle paths, spend keys, authorization witnesses, or prover randomness can enter directly.

This makes proof size an amortized block cost. At the hard one-MiB aggregate gate and 520 transfers, aggregate proof bytes cost at most 2,017 bytes per action. Using the current conservative proof-free action geometry, the full block is at most 3,633,941 bytes rather than roughly 67.1 MiB.

## Progress

- [x] (2026-08-18) Pinned upstream Binius64 commit `3f96163049f680b2909f6545690bd929f1b48c44` and measured raw honest transcripts.
- [x] (2026-08-18) Rejected current Flock as the production transaction backend: it is non-ZK, its shipped profiles stop at 120 bits, and it has no Hegemon relation.
- [x] (2026-08-18) Proved by exact source accounting that current Binius64 has no composed PQ128 parameter point: 96-bit query-only security, 256-bit Merkle/Fiat-Shamir hashes, and GF(2^128) challenges are all insufficient.
- [x] (2026-08-18) Measured the direct IronSpartan and wrapped-ZK proof-size frontier and rejected per-action placement.
- [x] (2026-08-18) Derived the exact 520-action wire budget and the BLAKE2b relation compression count.
- [x] (2026-08-18) Rejected the two-lifetime Binius leaf/aggregate architecture after adversarial review exposed the missing recursion evidence, unmeasured aggregate, off-block bandwidth, block-producer centralization, and loss of self-contained transaction authority.
- [ ] Implement the isolated V5 byte-native transaction statement and BLAKE2b relation.
- [ ] Implement a canonical proof codec and strict security profile in a pinned `transaction-binius` crate.
- [ ] Implement ordered leaf-proof aggregation and prove that the aggregate witness surface excludes transaction secrets.
- [ ] Integrate the separate pending-proof blob and proof-free block action grammars.
- [ ] Close Rust/Lean differential, QROM, zero-knowledge, performance, and release-authorization gates.
- [ ] Activate only at a fresh rules hash/genesis after every gate below passes.

## Surprises & Discoveries

- Current Binius64's `SECURITY_BITS = 96` controls only the FRI query term. The source explicitly excludes folding and every other protocol error from that number.
- The shipped SHA-256 and BLAKE3 Merkle suites have 256-bit roots, which provide only about `2^(256/3) = 2^85.3` generic quantum collision work.
- The unconditional BitAnd reduction has degree at most 126. For six equal error buckets at a 256-bit classical baseline, even an optimistic challenge field needs at least 266 bits; GF(2^256) is not enough.
- The smallest measured direct Boolean IronSpartan proof for one BLAKE2b compression is 246,048 bytes at the upstream 96-bit/SHA-256 profile. At 64 compressions it is 414,752 bytes. Bit-blasting loses the word-oriented Binius advantage.
- The wrapped-ZK Binius proof grows much more slowly with relation size: 298,304 bytes for one BLAKE2b compression and 321,120 bytes for 64 at the same upstream profile. Its fixed overhead is large, but it is the better leaf-proof base.
- A current proof-free inline action conservatively occupies 4,967 bytes. Therefore one one-MiB aggregate plus 520 actions and the 2,525-byte coinbase reservation occupies 3,633,941 bytes.
- Generic framed BLAKE2b costs 158 compressions for the complete two-input/two-output universal relation. Unique 16-byte personalization values plus fixed-width layouts reduce this to 89; computing the public authorization-intent digest outside the circuit and binding it as an exact public input reduces it to 85 without hiding less information.
- Binary Merkle multiproofs are smaller than 4-ary or 8-ary proofs for the measured query geometry. Same-stage row-wise oracle co-commitment is valuable, but staged commitments that depend on earlier transcript challenges cannot be merged.

## Decision Log

- Decision: abandon Poseidon as an active V5 transaction primitive.
  Rationale: the strict security target is not met by the old six-Goldilocks-word output, and the width-16 repair still lacks parameter-specific cryptanalysis. Fresh V5 relation semantics use typed BLAKE2b-384 values only.
  Date/Author: 2026-08-18, Codex.

- Decision: use Binius, not Flock, as the primary leaf and aggregate implementation family.
  Rationale: Binius has an implemented ZK wrapper, a byte/bit-oriented BLAKE2b circuit, an experimental verifier-circuit seam, and materially smaller measured transcripts. Flock remains a useful outer-aggregation benchmark but is currently non-ZK, at most 120-bit, and explicitly research-only.
  Date/Author: 2026-08-18, Codex.

- Decision: never serialize V5 leaf proofs into canonical block actions.
  Rationale: exact measurements and hard lower bounds make the strict-PQ per-action feasible set empty under the 124,080-byte artifact limit. Aggregation removes approximately 64.5 MiB of repeated proof bytes at 520 actions.
  Date/Author: 2026-08-18, Codex.

- Decision: require a proof-internal BLAKE2b-512 Merkle/Fiat-Shamir suite while retaining BLAKE2b-384 for semantic consensus identifiers.
  Rationale: 384-bit collision output sits exactly at the generic quantum 128-bit boundary and leaves no composition margin. Internal 512-bit digests trade modest aggregate bytes for a defensible margin; semantic values remain the frozen 48-byte consensus types.
  Date/Author: 2026-08-18, Codex.

- Decision: prototype GF(2^384) challenges and a 259-bit minimum classical query budget, but derive final values from the composed security calculator.
  Rationale: the source-derived optimistic field minimum is 266 bits. A cubic extension of GHASH's GF(2^128) gives a natural 48-byte field and avoids inventing a marginal 266-bit field. `s=259`, inverse-rate log 4, and 284 queries are only the first sizing point; activation requires the final QROM calculation to report at least 128 concrete bits after all losses.
  Date/Author: 2026-08-18, Codex.

- Decision: the aggregate circuit may be non-ZK, but its witness type must be proof-byte-only.
  Rationale: leaf proofs are already visible to mempool relays and are required to be zero-knowledge. Revealing functions of those proof bytes does not reveal transaction secrets, while removing a second ZK wrapper materially reduces the block proof.
  Date/Author: 2026-08-18, Codex.

## Exact baseline and budget

The checked full-KEM, two-output, stablecoin-disabled fixture has this current geometry:

| Component | Bytes |
|---|---:|
| Bare SmallWood proof | 117,942 |
| `NativeTxLeafArtifact` wrapper | 6,080 |
| Artifact | 124,022 |
| Remaining inline action encoding | 4,970 |
| Full pending action | 128,992 |

The block budget is 67,108,864 bytes and reserves 2,525 bytes for coinbase. Therefore:

    maximum artifact at 520 = floor((67,108,864 - 2,525) / 520) - 4,970
                            = 124,080 bytes

The measured strict-PQ candidates do not fit:

| Upstream 96-bit/SHA-256 profile | 1 BLAKE2b compression | 8 | 64 |
|---|---:|---:|---:|
| Wrapped Binius ZK, best rate | 298,304 | 309,664 | 321,120 |
| Direct Boolean IronSpartan, best rate | 246,048 | 327,984 | 414,752 |

These numbers are raw proof transcripts at upstream commit `3f961630`. They are not Hegemon security-qualified. Raising only the FRI query target, widening only the field, or widening only the Merkle hash does not produce a composed PQ128 proof.

For the selected block grammar, conservatively retaining a one-byte empty proof marker in each action:

    block_bytes(n, Q) = 2,525 + n * 4,967 + Q
    block_bytes(520, 1,048,576) = 3,633,941
    aggregate_bytes_per_action = ceil(1,048,576 / 520) = 2,017

V5 should remove the obsolete proof field entirely and can additionally remove 371 bytes of derived/repeated action fields, but neither saving is needed to pass the hard gate.

## Selected V5 protocol

### Leaf proof

`BiniusLeafProofV5` proves the exact canonical byte statement for two inputs, two outputs, four balance slots, and depth-32 membership. The proof relation retains note-opening binding, nullifier derivation, membership/anchor equality, spend authorization, hidden-value ranges, per-asset conservation, stablecoin issuance equality, and active/padding constraints.

Ciphertext hashing, balance-tag hashing, canonical slot ordering, public monetary ranges, version/profile validation, and authorization-intent hashing run natively before proof verification. Their exact canonical values or typed digests are public inputs, so moving them does not create an unbound authority.

Use unique RFC 7693 16-byte personalization values and fixed-width preimages for every in-relation BLAKE2b-384 role. This reduces the universal relation to 85 compressions while preserving hidden authorization-mode privacy. Every personalization value, field order, padding rule, and output length is part of the rules hash and cross-language vectors.

The leaf proof travels as a separate bounded `PendingProofBlobV5` keyed by `(RulesHash48, ActionId48, ProofProfileId48, proof_hash)`. Pending actions carry a proof reference, not an unbounded nested allocation. Admission exact-decodes the action first, derives the statement, then verifies the referenced leaf proof. Successful verification caches the exact statement/proof/profile tuple.

### Block aggregate

`BiniusBlockAggregateV5` verifies each ordered leaf proof and binds:

- chain id, rules hash, height, parent block id, and proof profile;
- exact action count and ordered `ActionRoot48`;
- every reconstructed leaf statement and action id;
- parent and resulting state roots;
- commitment-tree and nullifier-accumulator roots/counts;
- fee, supply, proof, and version commitments;
- the exact transaction order and state-transition deltas.

The aggregate witness contains only canonical leaf proof bytes and verifier scratch data. Its type and circuit frontend expose no transaction witness type. A static dependency/field audit and a differential leakage test enforce that boundary.

Canonical blocks serialize proof-free V5 actions plus one aggregate. Validators reconstruct the same ordered statements from action bytes and verify the aggregate once. They do not trust prior mempool admission and do not need the leaf proofs for block validity.

Nodes retain admitted leaf-proof blobs content-addressed for the configured reorg horizon. A node can requeue an orphaned action only if it still has the exact proof blob; otherwise the wallet resubmits. Missing blobs never affect canonical replay or state validity.

## Strict security profile

The first implementation profile is deliberately conservative:

- semantic hashes: typed, personalized BLAKE2b-384;
- proof Merkle and Fiat-Shamir hash: domain-separated BLAKE2b-512;
- algebraic challenge field: GF(2^384), represented as a cubic extension of GF(2^128);
- FRI starting point: six-bucket classical budget `s = 259`, inverse-rate log `R = 4`, `q = 284`;
- all random-oracle and field challenges rejection-sampled without modular aliases;
- proof codec: versioned, canonical, exact-consuming, fixed-width scalars/digests, bounded section counts, no attacker-declared allocation before total-length validation;
- zero knowledge: complete wrapper/PCS theorem and implementation, not PCS masking alone;
- aggregation: non-ZK only under the proof-byte-only witness theorem.

`s = 259` is a benchmark starting point, not release authority. The composed calculator must include FRI proximity, folding, ring switching, all sumcheck/BitAnd degrees, ZK masking, every Fiat-Shamir round, hash collision/preimage events, batch size, and a finite QROM query bound. The compiled profile is activated only if the resulting floor is at least 128 bits.

## Hard activation gates

All gates are conjunctive.

1. **Semantics.** Rust, independent reference, and Lean agree on every canonical statement field and every BLAKE2b personalization/KAT. Every single-field and ordering mutation rejects.
2. **No counterfeit.** The aggregate acceptance theorem composes leaf extraction/refinement for every ordered action with the exact state transition. No receipt, cache entry, or self-described digest substitutes for proof verification.
3. **Privacy.** Leaf proofs pass simulator/differential tests and an external ZK review. Aggregate circuit witness APIs statically and dynamically exclude transaction secrets.
4. **Concrete security.** The checked calculator and an independent review report at least 128 post-quantum bits after every algebraic, PCS, hash, batch, multi-round Fiat-Shamir, and QROM term. No `research_only` or caller-supplied authority can satisfy the release gate.
5. **Leaf bytes.** Honest maximum-shape proof target is at most 1,048,576 bytes and hard cap is 1,572,864 bytes. Decode rejects the cap plus one before allocation or hashing.
6. **Aggregate bytes.** Honest 520-action aggregate is at most 1,048,576 bytes. The exact full block remains at or below 3,633,941 bytes under the conservative action grammar.
7. **Throughput.** On the pinned reference machine, leaf verification p95 is at most 250 ms, 520-leaf aggregate proving p95 is at most 30 seconds, aggregate verification p95 is at most 500 ms, and peak resident memory stays within the published operator profile.
8. **Amortization.** Blocks contain zero leaf-proof bytes. A test counts proof bytes at every block/storage/transport/DA boundary and fails if an aggregate is added without removing the leaves.
9. **Failure atomicity.** Invalid, missing, reordered, duplicated, wrong-rules, wrong-parent, or wrong-state aggregates reject before state or persistent-index mutation. Crash/reorg tests yield exactly the old or new canonical state.
10. **Versioning.** Old Poseidon, SmallWood, Flock, and experimental Binius profiles are decode-only historical grammars with no active-height authority. Activation uses a fresh rules hash/genesis and rejects mixed forms before proof work.
11. **Release.** Full CI, formal, conformance, adversarial, performance, policy, and external-review gates are green. The current fail-closed production authorization remains closed until then.

If any gate fails, V5 transfers remain disabled. Poseidon is not a fallback.

## Implementation plan

### Milestone 1: byte-native relation and vectors

Create an isolated `circuits/transaction-binius` crate pinned to a reviewed Binius fork. Implement the 559-byte canonical public statement, the 85-compression personalized BLAKE2b relation, hidden authorization, ranges, balance, and state membership. Add an independent scalar reference and generated Rust/Lean vectors. Differentially compare every accepted witness and every isolated mutation.

Acceptance: the circuit/reference/vector suites pass, all mandatory mutations reject, and there is no Poseidon dependency in the active V5 graph.

### Milestone 2: strict proof primitives and codec

Implement the GF(2^384) extension, BLAKE2b-512 hash suite, configurable complete soundness budget, canonical proof envelope, size tracker, and same-stage co-commitment optimization. Retain binary Merkle multiproofs. Pin proof-size components against honest transcript bytes.

Acceptance: the size tracker equals real proof bytes for every rate/profile case; truncation/trailing/oversize/wrong-profile inputs reject; independent arithmetic/KAT tests pass.

### Milestone 3: leaf proving and admission

Wire wallet proving, the separate pending-proof blob, proof cache, fair admission queues, and exact statement reconstruction. Do not change the canonical block grammar yet.

Acceptance: end-to-end wallet-to-mempool proofs verify, malformed traffic is bounded before heavy work, and the leaf byte/time/memory gates pass.

### Milestone 4: aggregate verifier circuit

Extend the Binius verifier-circuit seam to the strict ZK leaf verifier. Batch homogeneous verifier instances, bind the ordered action root and state transition, and produce a non-ZK aggregate whose witness is proof-byte-only. Add proof-count 1, 8, 64, and 520 benchmarks.

Acceptance: a 520-action aggregate passes the byte/time gates; every reordered, duplicated, omitted, substituted, or state-mutated action rejects; dependency audits prove no secret transaction witness type reaches the circuit.

### Milestone 5: V5 block/storage/network integration

Add a fresh proof-free action grammar and one aggregate field to the canonical block. Keep pending proof blobs in a separate bounded content store for the reorg horizon. Update import, sync, mining, RPC, wallet, reorg, startup, DA, and light-client paths atomically.

Acceptance: block serialization contains zero leaf-proof bytes; fresh nodes sync and validate from actions plus aggregate; reorgs remain safe with or without retained proof blobs; mixed old/new grammar rejects before allocation.

### Milestone 6: formal and release authority

Prove the exact action-to-statement projection, leaf-verifier acceptance refinement, ordered aggregate composition, proof-byte-only witness boundary, and composed security calculation. Commission independent Binius/protocol/QROM and implementation audits.

Acceptance: the formal claim ledger records concrete bits at least 128 and every authority boolean required by the release checker is backed by real evidence. Only then freeze rules/genesis and activate.

## Validation commands

Commands will become exact as crates land. The final gate must include at least:

    cargo test -p transaction-binius --all-features
    cargo test -p transaction-binius-ref --all-features
    cargo test -p consensus --lib binius_v5
    cargo test -p hegemon-node --lib native::binius_v5_tests:: -- --test-threads=1
    bash scripts/check_formal_core.sh
    bash scripts/check_formal_crypto.sh
    python3 scripts/check_consensus_hash_profile.py --enforce-v5
    python3 scripts/check_binius_production_authorization.py config/formal-security-claims.json

Benchmark output must record the exact git commit, compiler flags, CPU, memory, proof profile, statement digest, proof bytes, block bytes, prover/verify distributions, and peak RSS. A projection never substitutes for an honest maximum-shape proof.

## Rollback and recovery

Every milestone before activation is additive and fail-closed. The V5 manifest remains inactive until the final rules/genesis switch. After activation, rollback means a new coordinated rules version; nodes never reinterpret V5 bytes under an older profile. Pending proof blobs are caches and may be rebuilt or discarded. Canonical blocks remain self-contained because actions plus aggregate are sufficient for validation.

## Outcomes & Retrospective

The investigation established only that current direct Binius and Flock implementations do not meet the standalone Hegemon proof contract. It did not establish a viable aggregate. The aggregate proposal is rejected because Hegemon requires each canonical transaction to retain its independently verifiable proof through relay, mining, storage, synchronization, reorg, and fresh replay. Future work must optimize a standalone proof under the 124,080-byte artifact ceiling; aggregation may be benchmarked only as an optional verification optimization that never removes transaction proofs or becomes consensus authority.
