# Transaction Proof SmallWood Candidate No-Grinding Soundness

This note freezes the exact active witness-free public SmallWood statement shape and no-grinding parameter profile used by the integrated Rust `SmallwoodCandidate` backend.

Important status note:

- the currently integrated prover/verifier backend in the repo is the packed Rust candidate, not the old scalar fallback,
- the Rust-side packed frontend material exists and lands on the current packed bridge statement shape,
- the shipped default now has a structural upper bound of `90830` bytes on the current backend, while the checked exact sampled release proofs on the current benchmark witness now land in the `87086 .. 87214` byte band after the compact inner wire-format rewrite replaced nested bincode lengths with one flat profile-checked layout,
- and the latest focused local release roundtrips on the current host measured about `6.1s` directly on the old bridge statement and about `5.4s` on the older compact-binding branch before the final `skip-initial-mds` promotion, after promoting the smaller checked no-grinding DECS point `32768 / 24 / 3`, keeping the preallocated DECS row buffers with thread-local scratch, deleting the duplicated input-position rows from the live bridge, deleting the duplicated stable-selector rows, deleting the duplicated input/output selector rows, deleting the duplicated public witness rows too, and then killing the witness-carrying direct alternate envelope in favor of the same succinct row-aligned PCS path,
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

`DirectPacked64V1` is no longer a witness-carrying alternate envelope. It now uses the same normal row-scalar PCS/opening line as the bridge baselines, with only the arithmetization tag distinguishing the modes. But the shipped default is no longer the old `1447`-row bridge-aligned statement. It is the leaner `DirectPacked64CompactBindingsInlineMerkleSkipInitialMdsV1` branch, so this note covers that exact active shipped geometry.

The exact active public statement fields are:

- `public_value_count = 78`
- `raw_witness_len = 72`
- `poseidon_permutation_count = 143`
- `poseidon_state_row_count = 4433`
- `expanded_witness_len = 76032`
- `lppc_row_count = 1188`
- `lppc_packing_factor = 64`
- `effective_constraint_degree = 8`

Those values are locked by the current integrated inline-Merkle shape test in [smallwood_frontend.rs](/Users/pldd/Projects/Reflexivity/Hegemon/circuits/transaction/src/smallwood_frontend.rs). The repo still also carries the separate frozen structural target (`raw_witness_len = 3991`, `poseidon_permutation_count = 145`, `expanded_witness_len = 59749`, `lppc_row_count = 934`), but that is not the statement the live backend is proving today.

The linear constraints are now sparse bridge selectors over the packed witness rows, not transcript-derived dense random checks. Public values are no longer embedded as duplicated witness rows; they are carried directly in the public statement and transcript binding, while the linear system enforces duplicated secret-row equalities plus the bridge-side constant/copy relations that tie the compact witness rows to the grouped Poseidon program. The current row-aligned statement also binds the previously missing public tx fields explicitly: active output ciphertext hashes and stablecoin policy version / policy hash / oracle / attestation commitments now occupy dedicated local secret rows that are linearly tied to the public statement. That implementation now lives in the Rust semantic/kernel path across [smallwood_frontend.rs](/Users/pldd/Projects/Reflexivity/Hegemon/circuits/transaction/src/smallwood_frontend.rs), [smallwood_engine.rs](/Users/pldd/Projects/Reflexivity/Hegemon/circuits/transaction/src/smallwood_engine.rs), and [smallwood_semantics.rs](/Users/pldd/Projects/Reflexivity/Hegemon/circuits/transaction/src/smallwood_semantics.rs).

The current no-grinding claim also assumes the hardened PCS/evaluation binding now implemented in the Rust engine:

- the full PCS commitment transcript is hashed into the PIOP transcript input
- `partial_evals` carry the real non-head opened coefficients rather than a zero placeholder
- the DECS opening challenge hashes full opened combis (`combi_heads || rcombi_tails`)
- commitment-time and verifier-time openings are both derived from the exact LVCS interpolation domain, not from the earlier broken consecutive-domain shortcut helpers
- verifier shape checks fail-closed before deep recomputation, and DECS opening indices are required to be distinct

The redteam regressions covering those seams now live in [smallwood_engine.rs](/Users/pldd/Projects/Reflexivity/Hegemon/circuits/transaction/src/smallwood_engine.rs) and [transaction.rs](/Users/pldd/Projects/Reflexivity/Hegemon/circuits/transaction/tests/transaction.rs).

Proof-specific verifier-profile digests now also bind the actual SmallWood arithmetization tag extracted from the proof wrapper instead of assuming bridge mode. The version-only helper is now pinned to canonical `DirectPacked64CompactBindingsInlineMerkleSkipInitialMdsV1`, because that path has no proof bytes to inspect and the shipped default must still remain version-owned.

## Exact no-grinding profile

The current candidate profile is now:

- `rho = 2`
- `nb_opened_evals = 3`
- `beta = 2`
- `opening_pow_bits = 0`
- `decs_nb_evals = 32768`
- `decs_nb_opened_evals = 23`
- `decs_eta = 3`
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

Using the notation from the SmallWood paper’s Table 1 for the active integrated bridge statement:

- `|F| = 2^64 - 2^32 + 1` (Goldilocks)
- `s = 64`
- `n = 1188`
- `d = 8`
- `m1 = 1`
- `m2 = 78`
- `ℓ' = 3`
- `ρ = 2`
- `β = 2`
- `ℓ = 23`
- `N = 32768`
- `η = 3`

The exact derived PCS/LVCS terms are:

- `n_pcs = n + 2ρ = 1192`
- witness-polynomial degree convention gives `d_j = s + ℓ' - 1 = 66`
- masked polynomial-constraint degree `d_Q = d * (s + ℓ' - 1) - s = 464`
- LVCS row count `n_rows = β * (s + ℓ') = 134`
- LVCS row-vector width `n_cols = ceil((Σ_j ν_j) / β) = 604`
- DECS polynomial count `n_decs = n_rows = 134`

The implementation now also enforces that the DECS opened leaf indices are distinct, so the live verifier matches the `ℓ = 23` count used below instead of silently accepting duplicate openings.

The old `n_cols = 1001` value was the dangerous one. The current integrated backend is materially narrower, but this note still uses the exact LVCS row-vector size from the active Rust backend rather than the smaller frozen structural target.

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
- `ε4 < 2^-131.91`

So the exact no-grinding floor for the implemented witness-free public statement is:

- `min(182.99, 128.00, 165.44, 131.91) = 128.00 bits`

The dominant term is `ε2`, not the DECS term and not the LVCS geometry term.

## Why the parameter bump matters

Two earlier candidate profiles fail if instantiated honestly:

- the old `nb_opened_evals = 2` profile leaves `ε3` at only about `2^-110.34`
- the old active-bridge `16384 / 29 / 3` profile cleared the floor, but the new checked sweep shows it was not the smallest passing point on the live bridge statement
- the old `4096 / 65 / 10` rescue profile was conservative but bloated, landing at about `224 KB` instead of using the narrower live bridge geometry honestly
- the later `32768 / 22 / 4` point also cleared the floor, but it is larger than the active line in the checked realistic sweep

That is why the current no-grinding candidate moved to:

- `nb_opened_evals = 3`
- `decs_nb_evals = 32768`
- `decs_nb_opened_evals = 23`
- `decs_eta = 3`

Those are not cosmetic tweaks. The checked realistic no-grinding sweep artifact `docs/crypto/tx_proof_smallwood_profile_sweep.json` now shows that Bridge/direct still prefer `32768 / 24 / 3`, while the shipped inline-Merkle arithmetization has one smaller passing point at `32768 / 23 / 3`.

## What this note does and does not prove

What it proves:

- the current `SmallwoodCandidate` statement is witness-free,
- the public statement is direct and code-derived,
- the bound is instantiated against the exact implemented statement shape,
- the current no-grinding profile clears a conservative `128-bit` floor for that exact statement.

What it does not prove:

- that `SmallwoodCandidate` is now release-ready,
- that the current bridge geometry is the final SmallWood tx frontend,
- that the final SmallWood tx backend has reached the smaller `934`-row structural target.

Today the Rust engine proves the real packed semantic relation over the live `64`-lane row-aligned geometry, and the shipped `DirectPacked64CompactBindingsInlineMerkleSkipInitialMdsV1` path now has a structural upper bound of `90830` bytes with checked exact sampled release proofs landing in the `87086 .. 87214` byte band on the current benchmark witness. That is about `4.1x` smaller than the shipped Plonky3 proof, about `13.6% .. 13.7%` smaller than the old `100956`-byte bridge baseline, and about `11.3% .. 11.6%` smaller than the former `98532`-byte shipped default. The remaining structural research gap is still the distance between the current direct bridge statement and the much smaller semantic LPPC frontier, but the live direct lane no longer cheats with a witness side payload. So this note is exact on the security surface and honest about the current shipped backend floor.

## Product conclusion

This milestone is complete in the narrow sense the user asked for:

- the candidate statement is now witness-free and public,
- the active integrated backend now carries an exact no-grinding `128-bit` note for that exact statement,
- and the active proof bytes stay below both the shipped Plonky3 baseline and the native `tx_leaf` cap.

The next milestone is different:

- reduce the packed relation geometry from the current `1447`-row bridge toward the frozen `64`-lane target,
- while preserving the witness-free public statement shape and this no-grinding discipline.
