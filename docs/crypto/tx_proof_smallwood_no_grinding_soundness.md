# Transaction Proof SmallWood Candidate No-Grinding Soundness

This note freezes the witness-free public SmallWood statement shape and no-grinding parameter profile that the packed SmallWood frontend is supposed to realize.

Important status note:

- the currently integrated prover/verifier backend in the repo is the packed Rust candidate, not the old scalar fallback,
- the Rust-side packed frontend material exists and lands on the current packed bridge statement shape,
- the exact serialized proof envelope for that current candidate now projects to `239460` bytes and fits below both the shipped `354081`-byte tx-proof baseline and the `524288`-byte native `tx_leaf` cap,
- but release proving is still too slow, so this note should be read as the exact no-grinding security note for the candidate statement, not as a claim that the backend is product-ready today.

It is intentionally narrow. This is not a release claim for a full SmallWood transaction-validity proof. It is the exact engineering note for the packed statement Hegemon wants behind `TxProofBackend::SmallwoodCandidate`.

The answer for that packed target is:

- the old random-linear-check envelope is gone,
- the packed candidate statement is witness-free and public,
- and the exact no-grinding candidate profile clears a conservative `128-bit` floor for that packed statement,
- but the integrated backend is still not release-ready because proving cost is still too high even though the backend is now Rust-native and the proof bytes are below the shipped baseline.

## What statement is actually proved

The current `SmallwoodCandidate` proof bytes are now just a Rust-native SmallWood PCS/ARK transcript:

- proof object: [smallwood_frontend.rs](/Users/pldd/Projects/Reflexivity/Hegemon/circuits/transaction/src/smallwood_frontend.rs)
- backend dispatch: [proof.rs](/Users/pldd/Projects/Reflexivity/Hegemon/circuits/transaction/src/proof.rs)
- native backend bridge: [smallwood_native.rs](/Users/pldd/Projects/Reflexivity/Hegemon/circuits/transaction/src/smallwood_native.rs)
- Rust prover/verifier engine: [smallwood_engine.rs](/Users/pldd/Projects/Reflexivity/Hegemon/circuits/transaction/src/smallwood_engine.rs)
- Rust semantic constraint kernel: [smallwood_semantics.rs](/Users/pldd/Projects/Reflexivity/Hegemon/circuits/transaction/src/smallwood_semantics.rs)

The proof no longer serializes any witness envelope. Instead, the public statement is derived directly from:

- `TransactionPublicInputsP3::to_vec()`
- `version.circuit`
- `version.crypto`

and from fixed shape metadata for the packed expanded native witness.

The exact public statement fields are:

- `public_value_count = 78`
- `raw_witness_len = 3991`
- `poseidon_permutation_count = 145`
- `poseidon_state_row_count = 4640`
- `expanded_witness_len = 59749`
- `lppc_row_count = 934`
- `lppc_packing_factor = 64`
- `effective_constraint_degree = 8`

Those values are locked by the current unit test in [smallwood_frontend.rs](/Users/pldd/Projects/Reflexivity/Hegemon/circuits/transaction/src/smallwood_frontend.rs).

The linear constraints are now sparse public selectors over the packed witness rows, not transcript-derived dense random checks. The selector indices are the first `78` witness coordinates, and the public targets are the corresponding direct public field values. That implementation now lives in the Rust semantic/kernel path across [smallwood_frontend.rs](/Users/pldd/Projects/Reflexivity/Hegemon/circuits/transaction/src/smallwood_frontend.rs), [smallwood_engine.rs](/Users/pldd/Projects/Reflexivity/Hegemon/circuits/transaction/src/smallwood_engine.rs), and [smallwood_semantics.rs](/Users/pldd/Projects/Reflexivity/Hegemon/circuits/transaction/src/smallwood_semantics.rs).

## Exact no-grinding profile

The current candidate profile is now:

- `rho = 2`
- `nb_opened_evals = 3`
- `beta = 3`
- `opening_pow_bits = 0`
- `decs_nb_evals = 4096`
- `decs_nb_opened_evals = 37`
- `decs_eta = 10`
- `decs_pow_bits = 0`

These values are bound in both:

- [smallwood_frontend.rs](/Users/pldd/Projects/Reflexivity/Hegemon/circuits/transaction/src/smallwood_frontend.rs)
- [smallwood_engine.rs](/Users/pldd/Projects/Reflexivity/Hegemon/circuits/transaction/src/smallwood_engine.rs)

So the repo is not claiming a paper-default or grinding-assisted profile. It is claiming an exact no-grinding profile.

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

Using the notation from the SmallWood paper’s Table 1:

- `|F| = 2^64 - 2^32 + 1` (Goldilocks)
- `s = 64`
- `n = 934`
- `d = 8`
- `m1 = 1`
- `m2 = 78`
- `ℓ' = 3`
- `ρ = 2`
- `β = 3`
- `ℓ = 37`
- `N = 4096`
- `η = 10`

The exact derived PCS/LVCS terms are:

- `n_pcs = n + 2ρ = 938`
- witness-polynomial degree convention gives `d_j = s + ℓ' - 1 = 66`
- masked polynomial-constraint degree `d_Q = d * (s + ℓ' - 1) - s = 464`
- LVCS row count `n_rows = β * (s + ℓ') = 198`
- LVCS row-vector width `n_cols = ceil((Σ_j ν_j) / β) = 318`
- DECS polynomial count `n_decs = n_rows = 198`

The `n_cols = 318` value is the dangerous one. If you instantiate `ε4` against the wrong matrix dimension, you lie to yourself by dozens of bits. This note uses the exact LVCS row-vector size from the actual `pcs-alloc.c` construction, not a prettier surrogate.

## Exact term values

With the mappings above, the SmallWood terms become:

- `ε1 = (N / d^β + 2) * |F|^(-η) * (1 + n_decs^(η+1) / |F|)`
- `ε2 = |F|^(-ρ) * (1 + (m1 * s + m2)^(ρ+1) / |F|)`
- `ε3 = binom(d_Q, ℓ') / binom(|F|, ℓ')`
- `ε4 = binom(n_cols + ℓ - 1, ℓ) / binom(N, ℓ)`

For the exact current candidate profile:

- `ε1 < 2^-616.76`
- `ε2 < 2^-128.00`
- `ε3 < 2^-165.44`
- `ε4 < 2^-133.28`

So the exact no-grinding floor for the implemented witness-free public statement is:

- `min(616.76, 128.00, 165.44, 133.28) = 128.00 bits`

The dominant term is `ε2`, not the DECS term and not the LVCS geometry term.

## Why the parameter bump matters

Two earlier candidate profiles fail if instantiated honestly:

- the old `nb_opened_evals = 2` profile leaves `ε3` at only about `2^-110.34`
- the old `decs_nb_opened_evals = 21` profile leaves `ε4` at only about `2^-76.42`

That is why the current no-grinding candidate moved to:

- `nb_opened_evals = 3`
- `decs_nb_opened_evals = 37`

Those are not cosmetic tweaks. They are the first exact no-grinding values that make the implemented witness-free statement clear the term-wise `128-bit` bar without invoking grinding.

## What this note does and does not prove

What it proves:

- the current `SmallwoodCandidate` statement is witness-free,
- the public statement is direct and code-derived,
- the bound is instantiated against the exact implemented statement shape,
- the current no-grinding profile clears a conservative `128-bit` floor for that exact statement.

What it does not prove:

- that `SmallwoodCandidate` is now release-ready,
- that the current SmallWood polynomial constraints already encode full `NativeTxValidityRelation`,
- that the final SmallWood tx backend has reached the smaller packed geometry needed for a proof-size win.

Today the Rust engine proves the real packed semantic relation, but the current `4`-lane bridge geometry is still too wide to beat the shipped Plonky3 proof. So this note is exact, but still narrow.

## Product conclusion

This milestone is complete in the narrow sense the user asked for:

- the candidate statement is now witness-free and public,
- and the repo now carries an exact no-grinding `128-bit` note for that exact statement.

The next milestone is different:

- reduce the packed relation geometry from the current heavy bridge shape toward the frozen `64`-lane target,
- while preserving the witness-free public statement shape and this no-grinding discipline.
