# Transaction Proof SmallWood Candidate No-Grinding Soundness

This note freezes the exact active witness-free public SmallWood statement shape and no-grinding parameter profile used by the integrated Rust `SmallwoodCandidate` backend.

Important status note:

- the currently integrated prover/verifier backend in the repo is the packed Rust candidate, not the old scalar fallback,
- the Rust-side packed frontend material lands on the V3 `DirectPacked64CommittedBindingsInlineMerkleSkipInitialMdsV2` statement shape,
- two consecutive full V3 release prove/verify runs produced randomized `104,687`-byte and `104,559`-byte proofs, and the regression enforces the `524,288`-byte native `tx_leaf` cap directly,
- the active V3 no-grinding profile uses `32768 / 24 / 3`; the `32768 / 23 / 3` profile is historical V2 verification material and fails the V3 production soundness guard,
- but this note should still be read as the exact no-grinding security note for the candidate statement, not as a blanket claim that the backend is final.

It is intentionally narrow. This is not a blanket release claim for every future SmallWood frontend Hegemon might build. It is the exact engineering note for the active integrated statement behind `TxProofBackend::SmallwoodCandidate`.

The answer for the active integrated backend is:

- the old random-linear-check envelope is gone,
- the packed candidate statement is witness-free and public,
- and the exact no-grinding candidate profile clears a conservative `128-bit` floor for that packed statement,
- but this note should still be read as a narrow soundness note for the current candidate geometry, not as a blanket claim that every future SmallWood frontend or arithmetization experiment inherits the same bound.

## What statement is actually proved

The current `SmallwoodCandidate` proof bytes are now just a Rust-native SmallWood PCS/ARK transcript:

- proof object: [smallwood_frontend.rs](/Users/pldd/Projects/Reflexivity/Hegemon/circuits/transaction/src/smallwood_frontend.rs)
- backend dispatch: [proof.rs](/Users/pldd/Projects/Reflexivity/Hegemon/circuits/transaction/src/proof.rs)
- native backend bridge: [smallwood_native.rs](/Users/pldd/Projects/Reflexivity/Hegemon/circuits/transaction/src/smallwood_native.rs)
- Rust prover/verifier engine: [smallwood_engine.rs](/Users/pldd/Projects/Reflexivity/Hegemon/circuits/transaction/src/smallwood_engine.rs)
- Rust semantic constraint kernel: [smallwood_semantics.rs](/Users/pldd/Projects/Reflexivity/Hegemon/circuits/transaction/src/smallwood_semantics.rs)

The compact bridge proof no longer serializes any witness envelope. Instead, the public statement is derived directly from:

- `TransactionPublicInputsP3::to_vec()`
- `version.circuit`
- `version.crypto`

and from fixed shape metadata for the packed expanded native witness.

The shipped default is `DirectPacked64CommittedBindingsInlineMerkleSkipInitialMdsV2`. Historical V2 proof bytes remain verification-only and cannot be selected by the production prover.

The exact active public statement fields are:

- `public_value_count = 78`
- `raw_witness_len = 388`
- `lppc_row_count = 1531`
- `lppc_packing_factor = 64`
- `effective_constraint_degree = 8`
- `nonlinear_expression_count = 11604`
- `nonlinear_root_count = 1722`

Those values are locked by the current integrated V3 shape and generated exact-map tests in [smallwood_frontend.rs](/Users/pldd/Projects/Reflexivity/Hegemon/circuits/transaction/src/smallwood_frontend.rs). Older bridge and structural targets are research data, not the statement proved by the shipped backend.

The V3 map includes complete active/stable sparse linear tables and an explicit nonlinear expression/root program over the same packed witness. Public fields, note openings, authorization bindings, balance equations, value ranges, and Poseidon transitions are bound in one version-owned relation. The exact-table digest is audit metadata only and is not accepted as a semantic premise. The implementation lives across [smallwood_frontend.rs](/Users/pldd/Projects/Reflexivity/Hegemon/circuits/transaction/src/smallwood_frontend.rs), [smallwood_engine.rs](/Users/pldd/Projects/Reflexivity/Hegemon/circuits/transaction/src/smallwood_engine.rs), and [smallwood_semantics.rs](/Users/pldd/Projects/Reflexivity/Hegemon/circuits/transaction/src/smallwood_semantics.rs).

The current no-grinding claim also assumes the hardened PCS/evaluation binding now implemented in the Rust engine:

- the full PCS commitment transcript is hashed into the PIOP transcript input
- `partial_evals` carry the real non-head opened coefficients rather than a zero placeholder
- the DECS opening challenge hashes full opened combis (`combi_heads || rcombi_tails`)
- commitment-time and verifier-time openings are both derived from the exact LVCS interpolation domain, not from the earlier broken consecutive-domain shortcut helpers
- verifier shape checks fail-closed before deep recomputation, and DECS opening indices are required to be distinct

The redteam regressions covering those seams now live in [smallwood_engine.rs](/Users/pldd/Projects/Reflexivity/Hegemon/circuits/transaction/src/smallwood_engine.rs) and [transaction.rs](/Users/pldd/Projects/Reflexivity/Hegemon/circuits/transaction/tests/transaction.rs).

Proof-specific verifier-profile digests bind the actual SmallWood arithmetization tag extracted from the proof wrapper. The version-owned V3 default is pinned to `DirectPacked64CommittedBindingsInlineMerkleSkipInitialMdsV2`.

## Exact no-grinding profile

The current candidate profile is now:

- `rho = 3`
- `nb_opened_evals = 3`
- `beta = 2`
- `opening_pow_bits = 0`
- `decs_nb_evals = 32768`
- `decs_nb_opened_evals = 24`
- `decs_eta = 3`
- `decs_pow_bits = 0`

These values are bound in both:

- [smallwood_frontend.rs](/Users/pldd/Projects/Reflexivity/Hegemon/circuits/transaction/src/smallwood_frontend.rs)
- [smallwood_engine.rs](/Users/pldd/Projects/Reflexivity/Hegemon/circuits/transaction/src/smallwood_engine.rs)

So the repo is not claiming a paper-default or grinding-assisted profile. It is claiming an exact no-grinding profile.

## Machine-checked profile and semantic boundary

`Hegemon.Transaction.SmallWoodTranscriptBinding` now treats the complete active verifier-profile material as one parameter record. A typed 16-constructor field inventory derives both the mutation labels and mutation functions, covering circuit version, crypto suite, arithmetization, effective constraint degree, `rho`, opened evaluations, `beta`, opening grinding, DECS evaluation count, DECS opening count, `eta`, DECS grinding, and the four Poseidon geometry fields. Lean proves both grinding fields are zero, proves the active parameters fit the production `u16`/`u64` serialization domain, and proves the field constructors and labels are unique. The production Rust test reconstructs every mutation, requires exact byte equality with Lean, proves that its 16-field profile array differs at exactly the named field index, rejects duplicate or missing mutation names, and requires every mutation to differ from the active profile. Lean also exhibits the out-of-range mutation `circuitVersion + 2^16`, proves that it aliases the serialized active profile, and proves that it is excluded by the well-formed production-domain predicate. The rejection theorem is deliberately quantified over named in-range mutations; it is not a false injectivity claim over unrestricted `Nat`, and it does not assert that the runtime rejects supported legacy profiles. This is a profile-drift and transcript-binding gate, not a cryptographic proof of the Fiat-Shamir transform.

`Hegemon.Transaction.SmallWoodProductionConstraintRefinement` reconstructs the exact production map from canonical public values and deterministically projects one satisfying witness into equation-backed authorization, output-validity, and balance relations. `Hegemon.Consensus.AcceptedSmallWoodBlockComposition` then binds the verified transaction claims, ordered batch identity, ordered fees, coinbase, supply delta, and claimed supply to the same accepted block projection. The final deployed theorem composes these facts from accepted proof bytes under explicit SmallWood proof-system soundness and note-hash collision-resistance assumptions. Exact extraction, same-witness row semantics, cross-object identity, ordering, and accepted-chain supply linkage are no longer separate assumptions.

## Theorem surface used here

This note follows the explicit CAPSS / SmallWood soundness terms given in the paper’s theorem for the Fiat-Shamir compiled argument.

Primary source:

- “SmallWood: Practical Transparent Arguments for Small Circuits,” ePrint 2025/1085, https://eprint.iacr.org/2025/1085.pdf

The explicit term decomposition appears in the CAPSS theorem:

- `ε_se-ks <= Q_RO^2 / 2^(2λ) + Q_RO * ε1 / 2^κ1 + Q_RO * ε2 / 2^κ2 + Q_RO * ε3 / 2^κ3 + Q_RO * ε4 / 2^κ4`

For the implemented no-grinding profile we set:

- `κ1 = κ2 = κ3 = κ4 = 0`
- `opening_pow_bits = 0`
- `decs_pow_bits = 0`

As with Hegemon’s other tx-proof notes, this is a release-engineering note, not a blanket claim about every possible random-oracle query budget. The floor below is the term-wise per-proof floor for the exact implemented statement and exact no-grinding profile.

## Mapping the implemented statement to SmallWood parameters

Using the notation from the SmallWood paper's Table 1 for the active V3 statement:

- `|F| = 2^64 - 2^32 + 1` (Goldilocks)
- `s = 64`
- `n = 1531`
- `d = 8`
- `m1 = 1`
- `m2 = 78`
- `ℓ' = 3`
- `ρ = 2`
- `β = 2`
- `ℓ = 24`
- `N = 32768`
- `η = 3`

The exact derived PCS/LVCS terms are:

- `n_pcs = n + 2ρ = 1535`
- witness-polynomial degree convention gives `d_j = s + ℓ' - 1 = 66`
- masked polynomial-constraint degree `d_Q = d * (s + ℓ' - 1) - s = 464`
- LVCS row count `n_rows = β * (s + ℓ') = 134`
- LVCS row-vector width `n_cols = ceil((Σ_j ν_j) / β) = 776`
- DECS polynomial count `n_decs = n_rows = 134`

The implementation enforces that the DECS opened leaf indices are distinct, so the live verifier matches the `ℓ = 24` count used below instead of silently accepting duplicate openings.

This note uses the exact LVCS row-vector size computed by the active Rust backend, not a historical bridge or structural target.

## Exact term values

With the mappings above, the SmallWood terms become:

- `ε1 = (N / d^β + 2) * |F|^(-η) * (1 + n_decs^(η+1) / |F|)`
- `ε2 = |F|^(-ρ) * (1 + (m1 * s + m2)^(ρ+1) / |F|)`
- `ε3 = binom(d_Q, ℓ') / binom(|F|, ℓ')`
- `ε4 = binom(n_cols + ℓ - 1, ℓ) / binom(N, ℓ)`

For the exact current candidate profile:

- `ε1 < 2^-182.99`
- `ε2 < 2^-128.00`
- `ε3 < 2^-165.44`
- `ε4 < 2^-129.08`

So the exact no-grinding floor for the implemented witness-free public statement is:

- `min(182.99, 128.00, 165.44, 129.08) = 128.00 bits`

The dominant term is `ε2`, not the DECS term and not the LVCS geometry term.

## Why the parameter bump matters

Two earlier candidate profiles fail if instantiated honestly:

- the old `nb_opened_evals = 2` profile leaves `ε3` at only about `2^-110.34`
- the historical V2 `32768 / 23 / 3` profile falls below the floor on the larger V3 statement and is rejected by the production guard

That is why the current no-grinding candidate moved to:

- `nb_opened_evals = 3`
- `decs_nb_evals = 32768`
- `decs_nb_opened_evals = 24`
- `decs_eta = 3`

The 24th distinct DECS opening is required by the V3 geometry. A focused regression substitutes 23 openings and requires the production soundness guard to reject the profile before proving.

## What this note does and does not prove

What it proves:

- the current `SmallwoodCandidate` statement is witness-free,
- the public statement is direct and code-derived,
- the bound is instantiated against the exact implemented statement shape,
- the current no-grinding profile clears a conservative `128-bit` floor for that exact statement.
- the full active profile material is mutation-checked across Lean and production Rust,
- exact semantic rows imply the Hegemon accepted-transaction relation and canonical no-theft facts,
- accepted proof extraction reaches those rows through an explicit proof-system soundness boundary,
- and accepted block identity, ordering, fees, coinbase, supply delta, and claimed supply compose over one production projection.

What it does not prove:

- that `SmallwoodCandidate` is now release-ready,
- that the current bridge geometry is the final SmallWood tx frontend,
- that the final SmallWood tx backend has reached the smaller `934`-row structural target.
- primitive PCS/PIOP/DECS, random-oracle, Merkle/commitment, or hash security,
- arbitrary compiler correctness beyond the checked generated Rust/Lean map boundary,
- or privacy and liveness properties outside the no-counterfeit theorem.

Today the Rust engine proves the V3 packed semantic relation over the live `64`-lane geometry, and the shipped committed-binding path stays under the native `tx_leaf` cap. V2 remains historical verification-only material.

## Product conclusion

This milestone closes the four production-bound no-counterfeit tracks while preserving explicit cryptographic assumptions:

- the candidate statement is now witness-free and public,
- the active integrated backend now carries an exact no-grinding `128-bit` note for that exact statement,
- all 16 typed security-relevant profile mutations are checked across Lean and Rust with an exact named-field delta assertion,
- exact accepted rows imply the local accepted-transaction and no-theft relations,
- the final theorem binds accepted-proof extraction, exact same-witness equations, cross-object identity, ordering, and same-block supply composition,
- the remaining assumptions name primitive SmallWood proof-system soundness and note-hash collision resistance,
- and the active proof bytes stay below the native `tx_leaf` cap without a Plonky3 dependency in the shipped node graph.
