# SuperNeo Feasibility Memo

Status: no-go at Phase 1. Do not build a spike crate. Do not wire a new proof kind. Do not touch remote infrastructure.

This memo uses the frozen raw baseline in `output/prover-recovery/2026-03-14/raw-baseline/benchmark.json` and the current repo contracts in `consensus/src/proof.rs`, `consensus/src/batch_proof.rs`, `circuits/transaction`, and `circuits/aggregation`.

## 1. Relation Choice

The only honest folded relation here is not "verify 1 Hegemon tx proof." It is:

"Verify `k` canonical Hegemon tx proofs under the production Goldilocks/FRI verifier, preserve transaction order, and emit the exact ordered public outputs consensus needs for the covered tx range."

To preserve block semantics without weakening `consensus/src/proof.rs`, the folded proof must expose at least:

- ordered statement hashes, because the statement hash commits to ciphertext hashes, value balance, stablecoin bindings, version binding, and the rest of the public statement that consensus otherwise only sees through `tx_statement_bindings`;
- ordered padded nullifiers and commitments, because consensus binds those directly against block transactions;
- a common anchor, total fee, and circuit/version binding for the covered range.

Anything narrower is either another wrapper or a semantics change.

## 2. Arithmetization Choice

If SuperNeo were attempted, the arithmetization must be a direct verifier relation for the tx proof, expressed in a CCS-like form that SuperNeo can fold. AIR-to-CCS lowering of the original transaction witness relation is the wrong target because it recreates a witness-bound public lane.

The tx-proof verifier being folded is already heavy in this repo:

- production tx proofs use Goldilocks with production FRI settings `log_blowup=4`, `num_queries=32`;
- each tx proof carries `76` Goldilocks public inputs before transcript material;
- the underlying tx AIR uses `8192` rows;
- the best local proxy for "verifier-inside-another-proof" is the existing recursive aggregation path, and its warmed tiny shapes are already expensive: a singleton/binary merge proxy measured `19616022 / 11935172 / 7859506` witness/add/mul rows and `133886 ms` warm, while a `k=2` root leaf measured `30404798 / 18437798 / 12147322` rows and `227329 ms` warm.

That does not prove SuperNeo would match those constants, but it does prove the actual verifier relation is not small. The honest estimate is "multi-million constraints per tx verifier instance, with no repo-local evidence that the narrow `k=2` case fits comfortably inside a 60-second budget."

## 3. Field and Ring Compatibility

Hegemon today assumes:

- Goldilocks base-field arithmetic for transaction, batch, and commitment proving;
- a quadratic extension field for FRI challenges (`BinomialExtensionField<Val, 2>`);
- Poseidon2-based Merkle commitments inside the tx proof stack;
- six-limb canonical encodings for every 48-byte commitment-like value.

SuperNeo is attractive on paper because it targets folding over small fields, but the actual Hegemon verifier relation still has to model:

- Goldilocks arithmetic exactly;
- extension-field challenge arithmetic for the tx-proof verifier;
- Poseidon2 transcript and Merkle-opening checks from the tx proof;
- conversions between consensus byte encodings and field limbs.

The unavoidable compatibility cost is not "can it use a small field in principle?" It is "can it encode this exact Goldilocks-plus-extension verifier relation without turning the prototype into a new proving stack."

## 4. Commitment and Transcript Compatibility

A real SuperNeo path would add a new commitment and Fiat-Shamir layer on top of the existing tx-proof stack. The tx proofs being consumed already rely on:

- Poseidon2-based FRI commitments and transcript material inside the Plonky3 proof;
- BLAKE3 statement hashing at the consensus boundary;
- existing block-commitment Poseidon/BLAKE3 bindings.

So the stack would no longer be "raw tx proofs plus current consensus checks." It would become:

"existing tx-proof commitments and transcript" plus "new SuperNeo commitments and transcript."

That is still plausibly post-quantum if implemented correctly, but it is a larger assumption surface and a much larger integration surface than raw shipping.

## 5. Cost Model

### Raw baseline to beat

- `k=1`: `354244 B/tx`, verify `7.688 ms/tx`
- `k=2`: `354240 B/tx`, verify `7.901 ms/tx`
- `k=4`: `354238 B/tx`, verify `8.316 ms/tx`
- `k=8`: `354237 B/tx`, verify `8.499 ms/tx`

### Public-output floor

If the folded proof emitted only the minimum ordered outputs above, the public-output floor would be tiny relative to raw shipping:

- `k=1`: about `300 B/tx`
- `k=2`: about `270 B/tx`
- `k=4`: about `255 B/tx`
- `k=8`: about `248 B/tx`

That floor is not the real object. The real object is "public outputs plus the SuperNeo proof."

### Honest engineering estimate

There is a plausible path for proof bytes to beat raw shipping by `k<=8` if the folded proof stays roughly constant-size and the verifier work is amortized. There is not a credible local path yet for prove time.

The only measured repo-local proxy for this relation is the current recursive verifier path, and it is already too slow:

- nearest `k=1` proxy: `133886 ms` warm;
- `k=2` proxy: `227329 ms` warm.

Even a very generous 4x constant-factor win would still leave the `k=2` case at roughly `56.8 s` before coordinator overhead, block assembly, artifact serialization, or any safety margin. That is not an honest prototype gate for a 60-second chain.

Verifier time and serial tail are less clearly fatal than prove time. A successful folding proof would probably verify in one constant-size check instead of `k` tx-proof checks, so there is a plausible path to a low node-side serial tail. The problem is earlier: there is no credible narrow prototype that gets the prover below the block budget quickly enough to justify the implementation.

## 6. Integration Surface

A real SuperNeo prototype would require changes across at least these areas:

- a new proof crate for the folding relation and proof format;
- `circuits/transaction-core` or a sibling crate to expose the tx verifier relation in the new arithmetization;
- `circuits/bench` to benchmark the candidate locally against raw shipping;
- `consensus/src/batch_proof.rs` and `consensus/src/proof.rs` for a new `proof_kind` and verification dispatch;
- later, if Phase 2 survived, node-side assembly in `node/src/substrate/service.rs` and scheduling in `node/src/substrate/prover_coordinator.rs`.

That is not a narrow "new crate and one benchmark" spike. It is a foundational proving-stack branch.

## Kill Gate

Required claim: credible path to smaller `bytes/tx` than raw shipping by `k<=8`

Result: maybe on paper, but not grounded tightly enough in a repo-local implementation plan to justify coding.

Required claim: verifier cost remains low enough for the low-TPS regime

Result: plausible, but unmeasured and not the bottleneck that currently kills the design.

Required claim: witness-free

Result: yes, in principle.

Required claim: implementation surface is narrow enough for a prototype rather than a multi-month rewrite

Result: no.

## Go / No-Go

No-go.

SuperNeo fails the Phase 1 kill gate on implementation surface, and it does not clear the stronger product gate that matters here: "more prover power must yield more real inclusion TPS under a 60-second block budget."

The right conclusion is not "SuperNeo is bad forever." The right conclusion is "SuperNeo is not the next honest prototype in this repository."

The immediate pivot is to keep the local falsification loop intact and refuse any new candidate until it has a narrower relation than "full tx-proof verifier folding" or a much stronger local argument for fitting under the budget.
