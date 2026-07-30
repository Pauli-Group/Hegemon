# Transaction Proof SmallWood Level-5 Soundness

This note freezes the exact V4/Gamma statement, transcript, and no-grinding
parameter profile selected for Hegemon's production `SmallwoodCandidate`
backend. It distinguishes three different facts:

1. the deterministic relation and parser/verifier chain checked by Rust and Lean;
2. the concrete interactive SmallWood error terms computed for that relation; and
3. the cryptographic assumptions needed to carry those terms into the deployed
   SHA-512 Fiat-Shamir execution.

It is not a claim that formalization proves SHA-512 or Poseidon2 cryptanalysis,
the compiler, the CPU, storage durability, data availability, or network
privacy.

## Active production statement

The active protocol binding is:

- circuit version `4`;
- crypto suite `3` (`Gamma`);
- backend `SmallwoodCandidate`;
- arithmetization `DirectPacked64CompressedLevel5`;
- transcript `hegemon.sha512-level5-field-xof.v1`; and
- radix-2 DECS evaluation domain.

The exact active relation has:

- `public_value_count = 78`;
- `raw_witness_len = 241`;
- `lppc_row_count = 699`;
- `lppc_packing_factor = 64`;
- `effective_constraint_degree = 8`; and
- `constraint_count = 890`.

The V4 relation binds note openings, spend authorization, Merkle
authentication, nullifiers, output ciphertext hashes, balance equations,
61-bit monetary ranges, and Poseidon2 transitions. V2/Beta and V3/Beta proof
formats remain verification-only historical replay surfaces; no new block
authoring path selects them.

The implementation lives in:

- [smallwood_frontend.rs](/Users/pldd/Projects/Reflexivity/Hegemon/circuits/transaction/src/smallwood_frontend.rs)
- [smallwood_engine.rs](/Users/pldd/Projects/Reflexivity/Hegemon/circuits/transaction/src/smallwood_engine.rs)
- [smallwood_semantics.rs](/Users/pldd/Projects/Reflexivity/Hegemon/circuits/transaction/src/smallwood_semantics.rs)
- [proof.rs](/Users/pldd/Projects/Reflexivity/Hegemon/circuits/transaction/src/proof.rs)

## Exact active profile

The selected no-grinding profile is:

- `rho = 5`;
- `nb_opened_evals = 5`;
- `beta = 7`;
- `opening_pow_bits = 0`;
- `decs_nb_evals = 1,048,576 = 2^20`;
- `decs_nb_opened_evals = 20`;
- `decs_eta = 33`; and
- `decs_pow_bits = 0`.

The prover and verifier bind this complete profile into the transcript.
Canonical field elements are obtained by rejection sampling, not modular
reduction. Opening challenges must use the first valid nonce, so a prover
cannot grind among several accepted challenge sets. DECS indices must be
distinct.

## SmallWood parameter mapping

Using the paper's notation for the active relation:

- `|F| = 2^64 - 2^32 + 1` (Goldilocks);
- `s = 64`;
- `n = 699`;
- `d = 8`;
- `m1 = 1`;
- `m2 = 78`;
- `ell' = 5`;
- `rho = 5`;
- `beta = 7`;
- `ell = 20`;
- `N = 2^20`; and
- `eta = 33`.

The derived dimensions are:

- `n_pcs = n + 2*rho = 709`;
- `d_j = s + ell' - 1 = 68`;
- `d_Q = d*d_j - s = 480`;
- `n_rows = beta*(s + ell') = 483`;
- `n_cols = 107`; and
- `n_decs = n_rows = 483`.

The implementation computes these values from the exact production statement;
the release profile command and Rust/Lean conformance tests reject drift.

## Exact interactive terms

The implemented integer arithmetic evaluates the four SmallWood terms:

```text
epsilon1 = (N / d^beta + 2) * |F|^(-eta)
           * (1 + n_decs^(eta+1) / |F|)
epsilon2 = |F|^(-rho)
           * (1 + (m1*s + m2)^(rho+1) / |F|)
epsilon3 = binom(d_Q, ell') / binom(|F|, ell')
epsilon4 = binom(n_cols + ell - 1, ell) / binom(N, ell)
```

For the exact active profile, diagnostic base-2 floors are:

- `epsilon1`: `268.1729055` bits;
- `epsilon2`: `319.9999999` bits;
- `epsilon3`: `274.5892793` bits;
- `epsilon4`: `262.7514375` bits; and
- exact aggregate: `262.7177764` bits.

The exact integer comparisons, not those rounded decimals, enforce the strict
260-bit interactive floor. The margin is intentional: the final adaptive
QROM statement charges the explicit query-dependent loss rather than
advertising the interactive floor as the deployed post-quantum security level.

## Fiat-Shamir and extraction chain

The formal production chain is:

```text
canonical proof bytes
  -> exact V4/Gamma parser
  -> accepted Rust verifier trace
  -> exact SHA-512 counter-mode challenges and rejection sampling
  -> restored PCS/PIOP/DECS messages and authenticated Merkle rows
  -> round-by-round extractor
  -> exact Hegemon transaction relation
  -> ordered independent transactions
  -> accepted block supply transition
```

`SmallWoodProductionAcceptanceClosure.lean` derives the transcript,
reconstructed messages, rows, and accepted relation from canonical accepted
proof bytes. `SmallWoodCmsQrom.lean` proves the finite compressed-oracle
adaptive extraction bound. `SmallWoodProductionSupplyChain.lean` composes the
extracted relation with transaction identity, fees, coinbase, and claimed
supply. These modules are imported by the top-level `HegemonCrypto` library.

No generic BCS/QROM theorem is postulated in that final chain. The residual
cryptographic assumptions are:

- deployed domain-separated SHA-512 behaves as the modeled QRO with the
  explicitly charged instantiation loss;
- SHA-512 and Poseidon2 satisfy the required collision and preimage properties
  in their exact deployed domains; and
- the checked parser/verifier refinement corresponds to compiled Rust and its
  machine environment.

## Size and performance selection

The release benchmark compares the real 64-lane production candidate with the
real 128-lane candidate under the same strict interactive-security gate. Proof
bytes are randomized, so measurements are observations rather than consensus
constants. Consensus enforces the 524,288-byte native transaction-leaf cap.

The 128-lane candidate uses 543 rows, packing factor 128, `beta = 5`,
`N = 2^21`, 19 DECS openings, and `eta = 38`. It is rejected as the production
default because it produces a larger proof and takes substantially longer to
prove while providing no useful security advantage above the already required
floor. The 64-lane candidate is therefore the measured Pareto choice between
the two implemented Level-5 geometries.

The final July 30, 2026 release-mode run on the development machine measured:

| Candidate | Wrapped proof | Prove | Verify | Interactive floor |
| --- | ---: | ---: | ---: | ---: |
| 64 lanes, 699 rows | 184,875 B | 15.286 s | 31.602 ms | 262.717776 bits |
| 128 lanes, 543 rows | 234,026 B | 60.293 s | 47.131 ms | 265.922737 bits |

The active fixture's complete native transaction-leaf artifact is 191,019
bytes because it includes the proof wrapper and native transaction context in
addition to the randomized SmallWood proof. The 128-lane candidate is 49,151
bytes larger and 3.94 times slower to prove in the same run.

Reproduce both candidates with:

```bash
cargo test -p transaction-circuit \
  compressed_level5_radix2_roundtrip_benchmark \
  --release -- --ignored --nocapture
```

## Product boundary

The active proof is one independent proof per transaction. There is no
authoring-time receipt-root, recursive-block, accumulation, or aggregation
artifact added to new blocks. Historical decoders remain only for chain replay.

This formal chain establishes the exact statement that must be secured and
reduces the remaining cryptographic boundary to named hash/QRO and compiled
implementation assumptions. It does not turn those assumptions into
self-issued external review, and it does not prove zero knowledge or global
unlinkability.
