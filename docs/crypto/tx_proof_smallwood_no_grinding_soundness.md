# Retained SmallWood Level-5 Soundness Status

This note freezes the exact V4/Gamma statement, transcript, and no-grinding
parameter profile retained for Hegemon's compact `SmallwoodCandidate` path. It
distinguishes three different facts:

1. the deterministic relation and finite parser/verifier conformance surfaces checked by Rust and Lean;
2. the concrete interactive SmallWood error terms computed for that relation; and
3. the cryptographic assumptions needed to carry those terms into the deployed
   SHA-512 Fiat-Shamir execution.

It is not a deployed end-to-end soundness claim. The formalization does not yet
prove the exact-map-to-canonical-semantic bridge, universal compiled-verifier
refinement, SHA-512 ideal-QROM instantiation, Poseidon2 cryptanalysis, the
compiler, the CPU, storage durability, data availability, or network privacy.

## Current status

| Question | Answer |
| --- | --- |
| What do the actual parameters prove? | Under the proved committed-support uniform-matrix theorem, the four-term interactive error is about `2^-262.3777366`. The ideal finite-QROM calculation passes the stated `2^64`-query/`2^-128` and `2^128`-query/half-success tests. |
| What may production claim? | No composed production bit count is available. Production is disabled because the exact conventional-hash relation, complete zero knowledge, concrete hash reductions, and Rust-verifier refinement are incomplete. |
| What attack is known? | No end-to-end SmallWood transaction forgery is recorded. The strongest documented generic component attack is quantum collision search against the retained 384-bit Poseidon2 semantic digest at about `2^128` queries; no retained construction turns that collision algorithm into an accepted transaction forgery. |

The parameter calculation, production status, and attack record are separate.
None may be substituted for another.

## Retained profile statement

The retained profile identity is:

- circuit version `4`;
- crypto suite `3` (`Gamma`);
- backend `SmallwoodCandidate`;
- arithmetization `DirectPacked64CompressedLevel5`;
- transcript `hegemon.sha512-level5-field-xof.v1`; and
- radix-2 DECS evaluation domain.

The exact retained relation has:

- `public_value_count = 78`;
- `raw_witness_len = 241`;
- `lppc_row_count = 699`;
- `lppc_packing_factor = 64`;
- `effective_constraint_degree = 8`; and
- `constraint_count = 890`.

The V4 Rust relation constrains note openings, spend authorization, Merkle
authentication, nullifiers, output ciphertext hashes, balance equations,
61-bit monetary ranges, and Poseidon2 transitions. V2/Beta and V3/Beta proof
formats remain compatibility decoders. Native block validity cannot reach them
without an explicit inclusive historical authorization, and the production
manifest currently authorizes none.

The implementation lives in:

- [smallwood_frontend.rs](/Users/pldd/Projects/Reflexivity/Hegemon/circuits/transaction/src/smallwood_frontend.rs)
- [smallwood_engine.rs](/Users/pldd/Projects/Reflexivity/Hegemon/circuits/transaction/src/smallwood_engine.rs)
- [smallwood_semantics.rs](/Users/pldd/Projects/Reflexivity/Hegemon/circuits/transaction/src/smallwood_semantics.rs)
- [proof.rs](/Users/pldd/Projects/Reflexivity/Hegemon/circuits/transaction/src/proof.rs)

## Exact retained profile

The selected no-grinding profile is:

- `rho = 5`;
- `nb_opened_evals = 5`;
- `beta = 2`;
- `opening_pow_bits = 0`;
- `decs_nb_evals = 1,048,576 = 2^20`;
- `decs_nb_opened_evals = 23`;
- `decs_eta = 5`; and
- `decs_pow_bits = 0`.

The prover and verifier bind this complete profile into the transcript.
Canonical field elements are obtained by rejection sampling, not modular
reduction. Opening challenges must use the first valid nonce, so a prover
cannot grind among several accepted challenge sets. DECS indices must be
distinct.

## SmallWood parameter mapping

Using the paper's notation for the retained relation:

- `|F| = 2^64 - 2^32 + 1` (Goldilocks);
- `s = 64`;
- `n = 699`;
- `d = 8`;
- `m1 = 1`;
- `m2 = 78`;
- `ell' = 5`;
- `rho = 5`;
- `beta = 2`;
- `ell = 23`;
- `N = 2^20`; and
- `eta = 5`.

The derived dimensions are:

- `n_pcs = n + 2*rho = 709`;
- `d_j = s + ell' - 1 = 68`;
- `d_Q = d*d_j - s = 480`;
- `n_unstacked_cols = 749`;
- `n_rows = beta*(s + ell') = 138`;
- `n_cols = ceil(n_unstacked_cols / beta) = 375`; and
- `n_decs = n_rows = 138`.

The implementation computes these values from the exact retained statement;
the release profile command and Rust/Lean conformance tests reject drift.

## Exact interactive terms

The implemented integer arithmetic evaluates the four SmallWood terms:

```text
epsilon1 = |F|^(-eta)
epsilon2 = |F|^(-rho)
epsilon3 = falling(d_Q + s, ell') / falling(|F| - s, ell')
epsilon4 = falling(n_cols + ell - 1, ell) / falling(N, ell)
```

The first term is specific to the retained full independent uniform coefficient
matrix. The extractor selects one bad support from the committed rows before
that matrix is sampled; failure is one codimension-`eta` affine fiber. Charging
a union over every possible support is valid for the historical scalar-power
challenge family but double-counts the retained uniform-matrix failure event.

For the exact retained profile, diagnostic base-2 floors are:

- `epsilon1`: `319.9999999` bits;
- `epsilon2`: `319.9999999` bits;
- `epsilon3`: `274.5892793` bits;
- `epsilon4`: `262.3780408` bits; and
- exact aggregate: `262.3777366` bits.

The exact integer comparisons, not those rounded decimals, enforce the strict
260-bit interactive floor. The margin is intentional: the final adaptive
QROM statement charges the explicit query-dependent loss rather than
advertising the interactive floor as the deployed post-quantum security level.

## Separate attack record

The repository contains mutation campaigns and malformed proof constructions
that the verifier rejects. Those are negative tests, not successful attacks.
No retained artifact makes the verifier accept a transaction for which no
valid witness exists.

The strongest documented generic algorithm concerns the retained six-limb,
384-bit Poseidon2 semantic digest. Generic collision search costs about
`2^192` classical hash calls or `2^128` quantum hash queries. This leaves no
generic quantum collision margin above 128 bits, but it is a hash component
result. Calling it a SmallWood forgery would require a separate
collision-to-counterfeit construction, and none is retained.

The easiest interactive error term, about `2^-262.378`, suggests a generic
quantum search scale near `2^131.189` verifier evaluations only if an attacker
can first construct false proofs that attain that event. No such construction
is known in this repository, so that estimate is not recorded as an attack.

## Fiat-Shamir and extraction boundaries

The intended deployment reduction is:

```text
accepted compiled V4/Gamma proof bytes
  -> compiled parser/verifier refinement
  -> exact SHA-512 counter-mode challenges and rejection sampling
  -> ideal logical-QROM instantiation with quantified loss
  -> restored PCS/PIOP/DECS messages and authenticated Merkle rows
  -> round-by-round extractor
  -> exact production constraint map
  -> canonical Hegemon transaction semantics
  -> ordered independent transactions
  -> accepted block supply transition
```

The current theorems do not compose that full arrow chain.
`SmallWoodProductionAcceptanceClosure.lean` proves consequences of a
`CallerSuppliedVerifierEvidence` record; it does not construct that record from
an arbitrary compiled Rust acceptance. `SmallWoodCmsQrom.lean` proves a finite
compressed-oracle bound for an ideal logical-oracle game. No production module
consumes that probability theorem. `SmallWoodProductionSupplyChain.lean`
reaches transaction identity, fees, coinbase, claimed supply, and the
no-counterfeit critical-path certificate only after callers separately provide
per-proof extraction success and canonical semantic refinement, plus Poseidon2
constraint-digest refinement and pair-local no-collision evidence.

The indexed formal security-authority type intentionally has no constructor for
`deployedEndToEnd`. The open obligations are:

- construct the modeled verifier-evidence record from every accepted compiled
  Rust execution;
- compose the ideal logical-QROM failure event with the extractor used by the
  block theorem and quantify deployed SHA-512 instantiation loss;
- prove the exact production row model refines canonical transaction semantics;
- prove production Poseidon2 constraint rows compute the deployed digest; and
- retain SHA-512/Poseidon2 collision and preimage hardness assumptions in their
  exact deployed domains.

## Size and performance selection

Candidate parameters remain benchmark-local until a profile is a strict proof
size, prover-time, and verifier-time Pareto improvement under unchanged
conservative security accounting. Exact proof bytes vary because compact
authentication paths share nodes selected by randomized challenges, so compare
bands and medians from the same run.

The August 17, 2026 release-mode audit measured:

| Profile | Exact wrapped median | Combined prove + verify | Conditional `Q = 2^128` CMS envelope* |
| --- | ---: | ---: | ---: |
| retained `N=2^20,q=23` | 117,878 B | 3.070 s | 0.1443 |
| `N=2^19,q=25` | 120,296 B | 1.720 s | 0.6995 (fails target) |
| `N=2^19,q=26` | 122,337 B | 1.773 s | 0.000564 |
| `N=2^21,q=21` | 115,076 B | 6.396 s | 0.4811 |
| `N=2^22,q=20` | 114,379 B | 12.244 s | 0.002466 |
| `N=2^23,q=19` | 113,490 B | 26.9 s | 0.0000799 |

\* The envelope assumes the unproved fixed-prechallenge/full-oracle compiled
reduction and excludes deployed SHA-512 instantiation loss. It is a pruning
diagnostic, not deployed security authority.

The smallest measured candidate saves about 3.7% but is roughly nine times
slower. Faster candidates are larger, and the one smaller-domain candidate
that approaches the active size fails even the conditional half-success
criterion. No candidate improves both bytes and runtime, so the active
`2/23/5` profile is retained. The three-sample active band was
117,750--117,942 bytes; the `2^23/19` band was 113,234--113,554 bytes. The
active current-row planner ceiling is
124,982 B. A proposed shared-row planner is larger at 126,166 B and only
242.153 interactive bits, so it is rejected. The planner now charges 64-byte
SHA-512 digests for Level-5 paths; its former 32-byte accounting understated
the active projection by 14,752 B.

The active proof is dominated by opening payloads (about 39.2%), opened values
(21.4%), transcript data (20.5%), and the compact Merkle commitment (18.9%).
The checked-in complete native transaction-leaf artifact remains 124,022 B.
The new balance-tag reconstruction adds no bytes and measured 23.94 us versus
15.634 ms for full native fixture verification, about 0.153% of that path.
Consensus enforces the 524,288-byte native transaction-leaf cap.

Reproduce the active and candidate measurements with:

```bash
cargo test -p transaction-circuit \
  compressed_level5_radix2_roundtrip_benchmark \
  --release -- --ignored --nocapture

cargo run -p transaction-circuit --release \
  --example pq128_profile_bench -- 3

cargo run -p superneo-bench --release \
  --example native_tx_leaf_precheck_bench
```

## Product boundary

The retained proof format is self-contained and does not require a receipt,
aggregate, sidecar, or cache. It is not authorized for new production blocks.
Historical replay requires an explicit release-owned binding and height range.

The checked arithmetic and internal theorems establish useful pieces of the
statement that must be secured. Until the obligations above are discharged,
they remain conditional research evidence rather than production authorization.
They do not turn assumptions into self-issued external review, and they do not
prove zero knowledge or global unlinkability.
