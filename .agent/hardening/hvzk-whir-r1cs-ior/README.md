# CFW26 Section 11 R1CS-to-IOR source reference

Verdict: **retained branch-relative diagnostic; no theorem or production authority**.

This directory makes the algebra around CFW26 Construction 11.4 executable for a tiny, exactly bound R1CS fixture. It does not claim to implement the theorem in Theorem 11.3. The paper text currently has two independent blockers that this reference refuses to repair silently:

1. Construction 11.4 Step 3 and Step 8's first equality add each inner mask with coefficient `1`. Step 8's second equality and the honest-verifier zero-knowledge proof use coefficient `2`; the latter's uniformity argument explicitly relies on multiplication by `2` being bijective when `char(F) != 2`.
2. Step 9 declares each inner succinct linear form to be `sl_id` but gives it the pair `(pow(alpha_i), ze(rho)_M)` as state. Definitions 5.1 and 5.2 require an identity-form state to already be the complete `t x n` matrix. The printed pair would instead need a typed scalar-multiplied form from Definition 5.4, or a pre-multiplied matrix state. The three main forms are also declared as identity forms while their states are entire matrix descriptions; the required target is a `1 x ell` witness-column row fixed at `alpha`, which is not the printed matrix shape and whose state omits `alpha`. The footnote calls this an abuse of notation but does not define the missing typed evaluator. No repair is selected by the construction.

Accordingly, `cfw26_r1cs_ior.py` exposes two coherent diagnostic branches:

- `construction_literal_coefficient_1`: coefficient `1` in the constraint polynomial and derived output relation;
- `proof_sketch_coefficient_2`: coefficient `2` in both places, matching the later decomposition and HVZK proof.

Each branch produces a deterministic honest transcript, passes the direct sumcheck equations, and passes two independently typed derived-output encodings: `(a)` `sl_id` with a pre-multiplied `1 x n` state and `(b)` `times(sl_id)` with a structured `(matrix, scalar)` state. Swapping a transcript's branch tag without recomputing its derived relation is rejected. The exactly printed Step 9 state and the paper-literal output relation always fail closed.

## What the simulator does—and does not do

`simulate_public_view` is an executable **public affine sampler**. It has no witness parameter. For fixed public verifier coins it samples a point in the affine space `T(v_A,v_B,v_C)` described in the proof sketch and returns independently simulated answers for a fixed, non-adaptive query plan within the Reed–Solomon query bound.

That is not a distributional theorem. The source does not prove that its deterministic sampler has the real protocol's distribution, does not model adaptive distinguishers, does not implement a PCS commitment/opening simulator, does not program a Fiat–Shamir random oracle, and does not simulate a whole proof view. It therefore proves neither complete ZK nor the paper's HVZK theorem. All such capabilities are false in `certificate.json`.

The JSON transcript parser is strict and canonical for this source fixture: exact key sets, canonical lowercase 8-byte field encodings, canonical lowercase 64-byte digests, exact schema/version types, no duplicate-key alternate encoding, no trailing bytes, and immutable byte input. It is intentionally not a bounded production/consensus parser and carries full oracle vectors rather than PCS commitments.

## Exact primary-source anchors

The reviewed primary source is *Zero-Knowledge IOPPs for Constrained Interleaved Codes*, IACR ePrint 2026/391, PDF SHA-256 `6a2092b7bc50e5ea68ec8e679c4b830f2fe260c961dc08ee7582b7e652a46f7c` and SHA-512 `be9595b264ccbb6e5d848a10e24f907089ff478c7efe99967a5d0f236bffcaf87c53cc82eec53f74856a08a4db8a6884084c8238291f44d06aa2d703eef5c2dd` (82-page PDF inspected 2026-08-22).

- Printed page 29, Proposition 3.19: an RS code of polynomial dimension `ell` has message length `ell-t`, randomness length `t`, and perfect `t`-query ZK. The source therefore constructs a polynomial of dimension `message_length+t`; it does not conflate code dimension with message length.
- Printed page 34, Definition 4.7: the query-bounded distinguishers used here are explicitly non-adaptive.
- Printed page 35, Definitions 5.1, 5.2, and 5.4: a succinct form evaluates to a `t x n` matrix; `sl_id` takes that matrix as state; scalar multiplication is a distinct typed form.
- Printed pages 35–36, Definition 5.8: the output relation applies the main and mask linear-form matrices to their corresponding encoded messages and targets.
- Printed pages 66–67, Theorem 11.3: `ell=n0`, `ell` is a power of two, prover communication is the exact stated oracle/non-oracle expression, the IOR is queryless, and HVZK additionally assumes odd characteristic, `ell_out >= 2*ell_in`, `ell_in >= 4`, and `t`-query ZK encodings.
- Printed page 67, Construction 11.4 Steps 1–3: inner masks vanish at `0` and `1`; Step 3's constraint factors contain one copy of each mask sum.
- Printed pages 67–69, Steps 4–7: outer masks, affine sumcheck messages, the final non-Boolean challenge, and outer evaluation targets.
- Printed page 69, Step 8: the first displayed equality has one mask sum, while the immediately following displayed equality has `2` times the mask sum.
- Printed page 69, Step 9: `sl_in,M,i=sl_id` is paired with state `(pow(alpha_i), ze(rho)_M)`, while each main `sl_M=sl_id` receives an entire matrix description rather than a `1 x ell` row fixed at `alpha`; neither satisfies Definition 5.2's required state shape as printed.
- Printed page 70, Step 10: the construction exports the main, inner-mask, and outer-mask oracles and their opening witness to the target relation.
- Printed pages 70–71, HVZK proof sketch: the simulator samples `v_A,v_B,v_C` uniformly, samples uniformly from the affine space `T`, and the value claim uses coefficient `2` plus `char(F) != 2`; the final hybrid has exactly `4 log ell + 5` encoded oracles.

Primary URL: <https://eprint.iacr.org/2026/391>. The PDF is not vendored here. No public erratum selecting a branch was identified during this audit. Plonky3 issue 1590 also describes the Section 11 R1CS reduction as out of scope for the PCS implementation, so a Hiding-WHIR PCS cannot be treated as this output relation: <https://github.com/Plonky3/Plonky3/issues/1590>.

## Exact retained fixture

The executable fixture is deliberately small and non-production:

- Goldilocks field `p = 0xffffffff00000001` (odd characteristic);
- `ell=n0=4`, eight variables and eight constraints, Boolean index width and sumcheck round count `3`;
- inner message length `4`, outer message length `8`, and one non-adaptive query per oracle;
- 1 main oracle, 9 inner-mask oracles, and 3 outer-mask oracles;
- 154 oracle field elements, 31 direct prover field elements, and 185 total prover field elements before any PCS/wire replacement;
- deterministic canonical JSON transcript: 6,837 bytes for the coefficient-1 branch and 6,829 bytes for the coefficient-2 branch.

Those byte counts are fixture serialization measurements, **not proof sizes**, PCS sizes, Hegemon relation measurements, or architecture-candidate evidence.

## Unequal Hegemon geometry is not a Section 11 carrier

The downstream source-only mixed R1CS screen reports `m=20,457,227` constraints, `n=19,311,555` nonconstant variables, `l_public=10,152`, and `nnz=94,551,238`; therefore its witness/private-plus-auxiliary count is `n-l_public=19,301,403`. That is a general R1CS geometry. CFW26 Definition 11.2 does not accept arbitrary unequal `(m,n,l)`: it defines `(ell+n0) x (ell+n0)` matrices and exactly `ell+n0` constraints. Theorem 11.3 further assumes `ell=n0` and power-of-two `ell`.

Under the explicit local equal-half candidate mapping `z=(v[ell],w[ell])`, the minimum arithmetic projection is:

- `ell=n0=2^25=33,554,432` because the 19,301,403-element witness half is the largest lower bound;
- square matrix/constraint side `2*ell=2^26=67,108,864`;
- total nonconstant carrier variables `2*ell-1=67,108,863` after accounting for the standard constant in `v`;
- 33,544,279 parser-fixed public zero elements after the constant and 10,152 public bits;
- 14,253,029 existential witness zero elements, requiring the same number of zero constraints;
- 32,398,608 remaining canonical zero rows;
- candidate embedded matrix nonzeros `94,551,238 + 2*14,253,029 = 123,057,296` under the local `x*1=0` padding-row convention;
- main committed witness-message length `ell=2^25`, sumcheck Boolean width `log2(2ell)=26`, and theorem hybrid count `4 log2(ell)+5=105`.

`section11_padding_projection` retains those arithmetic counts, but returns `authoritative_carrier=false`, `matrix_embedding_constructed=false`, `parser_padding_binding_proved=false`, and `semantic_refinement_proved=false`. The downstream compiler has a source-only candidate padding projection; neither it nor this directory retains the expanded `2^26` square matrices, proves that parser-fixed public padding and existential zero rows preserve the exact Hegemon relation, or binds a WHIR PCS/profile to the resulting vectors. The main WHIR codeword length, query schedule, proof bytes, and security ledger therefore remain undefined. Passing the `ell=4` toy does not establish completeness of the actual carrier.

## Reproduce

These checks use only Python's standard library, write no bytecode cache, and invoke no Cargo, rustc, Lake, build, proof generation, dependency installation, clone, or network operation:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -B .agent/hardening/hvzk-whir-r1cs-ior/test_cfw26_r1cs_ior.py -v
PYTHONDONTWRITEBYTECODE=1 python3 -B .agent/hardening/hvzk-whir-r1cs-ior/cfw26_r1cs_ior.py self-check
PYTHONDONTWRITEBYTECODE=1 python3 -B .agent/hardening/hvzk-whir-r1cs-ior/check_cfw26_r1cs_ior.py
```

`certificate.json` is the canonical fail-closed result, `mutation-ledger.json` records every retained negative check, and `source-manifest.json` pins the exact audited local files with SHA-512. The checker verifies all hashes and canonical JSON, reruns both branch diagnostics and all unit tests, confirms the paper-literal/type failures, and reasserts every false authority capability.

## Authority boundary

This directory has no Hegemon transaction compiler, no full Hegemon R1CS, no PCS, no WHIR carrier, no commitment parser, no Fiat–Shamir transcript, no QROM composition, no RBR instantiation, no whole-view simulator, and no measured production proof. `complete_zk=false`, `strict_pq128=false`, and `production_authorized=false` are mandatory. Any checker-observed drift fails closed.
