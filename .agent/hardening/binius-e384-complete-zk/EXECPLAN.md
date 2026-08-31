# Close complete ZK for the single-copy E384 BaseFold candidate

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` are maintained as work proceeds. This file follows `.agent/PLANS.md` from the repository root.

## Purpose / Big Picture

The selected size-tournament candidate uses B128 committed symbols and E384 interactive challenges. Before it can carry a private transaction, every proof byte that depends on a witness must have a joint witness-free simulation argument. This plan makes that requirement executable. A reviewer can run a dependency-free Rust audit and see both the exact linear-algebra gate and concrete failing distributions; the result must continue to print `complete_zk=false` until the real authenticated BaseFold compiler exports its observation matrices and a whole-proof SHA-512 QROM simulator implements the frozen interface.

## Progress

- [x] (2026-08-22 09:10Z) Read the exact B128/E384 arithmetic, transcript, retained M4 joint-rank audit, retained outer-distribution audit, architecture tournament, and repository design/methods instructions.
- [x] (2026-08-22 09:18Z) Implement exact E384 Gaussian elimination, mask-span checking, same-statement generator checks, low-bit-first fold observation rows, and executable leak extraction in `prototypes/standalone-shake256-binius/strict-mixed-field/src/complete_zk.rs`.
- [x] (2026-08-22 09:22Z) Specify two full-E384 dummy multiplication rows, disqualify the historical two-B128 design by a rank-three coset translation, and add a conservative endpoint distance ledger over denominator `2^384`.
- [x] (2026-08-22 09:25Z) Add an exhaustive whole-proof-view inventory, witness-free simulator interface, canonical public rejection sampler, independent 64-byte index-bound leaf tapes, and checked parameterized byte accounting.
- [x] (2026-08-22 09:31Z) Ran the isolated direct-`rustc` harness against the exact current B128/E384 source: 32 tests passed, including 13 complete-ZK tests, and the status binary printed `complete_zk=false` and `production_authorized=false`.
- [x] (2026-08-22 10:02Z) Added the actual B128 entropy-domain rank interface and an exact scalar-encoder screen. The systematic zero leaf gives a universal appended-tail no-go. After matching the live paired-query sampler, all 56 three-pair schedules leak in both retained small geometries.
- [x] (2026-08-22 10:10Z) Specified and bounded the exploratory `P+Z_H R` alternative, required its mask degree bound to equal the complete paired-leaf/layer/group/terminal B128 observation count rather than nominal `q`, and added checked capacity/direct-wire accounting. It has no whole-BaseFold theorem and is not implementation authority.
- [x] (2026-08-22 10:34Z) Bound the negative certificate to exact current encoder/audit source digests, recorded the raw round-zero `pi`/`omega` serializer fields, proved the leaf-zero recurrence for all 120 supported `(d,r)` pairs, corrected the exact event probability to `q/2^(d+r-1)`, and added fail-closed mutation tests.
- [x] (2026-08-22 11:02Z) Compared the live seam to Diamond ePrint 2025/1015 Construction 4.1 and replaced the ad hoc repair preference with a theorem-faithful geometry/wire API: setup on `ell+1`, `kappa=gamma*2^theta` high coefficients/opened points, fresh blind commitment, virtual oracle, interleaved sumcheck/FRI, degree-one terminal, and salted openings. The current mixed backend matches none of those gates.
- [x] (2026-08-22 11:12Z) Ran the dependency-free certificate suite: 18 Python tests passed, including source-digest, leaf-invariant, paired-probability, raw-`pi`/`omega`, Diamond-doubling, ad hoc-authority, and capability mutation cases. The valid negative checker exited 2 with `complete_zk=false`; `rustfmt --check` passed and no trailing whitespace was found.
- [ ] Re-run the current-digest direct-Rust tests after free disk reaches the 28 GiB gate. The earlier 32-test and integrated 47-test runs predate the newest paired-query/repair-inventory source.
- [ ] Integrate exact backend matrices, exact production geometry, a concrete joint simulator, and the SHA-512 QROM programming reduction. These are intentionally outside this negative/conditional workstream and every capability remains false.

## Surprises & Discoveries

- Observation: Counting one dummy wire per query is not a rank result. The verifier sees raw original leaves, folded values, and the terminal codeword, so the sufficient fixed-transcript condition is `rank(O G_r) = rank([O G_r | O G_w])` for the exact serialized observation map `O`.
  Evidence: the backend now exports the exact observation inventory as `raw_opening_observations_for_queries(d,r,g,&query_indices)`, but no `G_r`, `G_w`, or relation-mask kernel exists, so the joint rank object remains unavailable.

- Observation: Two B128 dummy scalars cannot hide a general E384 endpoint translation.
  Evidence: weights `1,Y` have B128 column rank two, while adjoining translation `Y^2` raises rank to three. The translated marginal occupies a disjoint coset and has exact statistical distance one.

- Observation: Leaf salt is not an algebraic mask.
  Evidence: `OpenedLeafFrame` therefore binds an independent 64-byte tape and exact index for QROM programming, while `ViewMaskContract` separately requires a full-E384 statistical mask for the underlying oracle value.

- Observation: The exact Gao--Mateer encoder's leaf zero is systematic with respect to active coordinate zero and independent of appended tail dummies for every supported dimension/rate.
  Evidence: `bit_reverse(0)=0`; only block zero touches leaf zero; its twiddle is the empty sum and equals zero. The proof enumerates all 120 admitted `(d,r)` pairs without allocating codewords. The live sampler selects pair indices and opens both siblings, so query pairs `[0,1,2]` expose leaves `[0,1,2,3,4,5]`; the left-null vector `[1,0,0,0,0,0]` exposes active coordinate zero. Both small layouts leak on all 56 pair schedules.

- Observation: Pair expansion doubles the relevant leaf-zero event relative to a single-leaf sampler.
  Evidence: the without-replacement population is `L=2^(d+r-1)` pair indices and pair zero contains leaf zero, so the event probability is exactly `q/L`, equivalently `2q/2^(d+r)`. The maximum admitted pair-population log is 25.

- Observation: The source tree is being edited concurrently. A naïve direct standalone compile stopped in the separately owned `mixed_basefold_pcs.rs`, not in this module.
  Evidence: `direct_rustc.py` now creates a temporary crate root from the exact current `lib.rs`, omits only `authenticated_basefold`, `mixed_basefold_pcs`, and any existing `complete_zk` module declarations, then reinserts the owned module by exact path. This isolates the audit without copying field arithmetic.

## Decision Log

- Decision: Keep the construction parameterized and fail closed instead of inventing `n`, rate, query count, terminal length, or authentication-node count.
  Rationale: none of those values is frozen for the fresh single-copy E384 profile, and an estimated byte total would not qualify as a measured or serializer-derived proof size.
  Date/Author: 2026-08-22 / Codex complete-ZK workstream.

- Decision: Require full-E384 statistical masks for algebraic values and treat 64-byte leaf tapes only as commitment-programming inputs.
  Rationale: a salted hash can hide a preimage computationally in the random-oracle model, but it cannot repair an algebraic raw-opening rank leak.
  Date/Author: 2026-08-22 / Codex complete-ZK workstream.

- Decision: Replace the two-B128 endpoint patch with two complete E384 multiplication triples.
  Rationale: two B128 scalars span at most two of E384's three B128 lanes; two full-E384 rows admit the same-field distribution analysis with endpoint loss bounded by `(n+d+1)/2^384`.
  Date/Author: 2026-08-22 / Codex complete-ZK workstream.

- Decision: Forbid prover-selected retries and nonces.
  Rationale: every exceptional challenge is handled by the verifier-reproducible first accepted candidate among sixteen domain-separated transcript counters. A witness-dependent retry would create a selective-failure channel.
  Date/Author: 2026-08-22 / Codex complete-ZK workstream.

- Decision: Reject appended dummy count as a hiding theorem and require a disjoint-domain vanishing-codeword mask or an equivalently exact relation-kernel construction.
  Rationale: leaf zero receives no appended-dummy coefficient, so any query of it exposes an active coordinate with conditional distance one. `q` dummy variables do not imply rank `q` for the actual encoder.
  Date/Author: 2026-08-22 / Codex complete-ZK workstream.

- Decision: Size the vanishing mask from the maximum distinct opened B128-coordinate inventory, not the nominal transcript query count.
  Rationale: each query opens two siblings; later layers expose three lanes per E384 value; folded collisions change each layer's distinct union; every group and every terminal value is serialized. For independent group polynomials, the per-group degree bound is `m = u_0 + 3*sum_{l>0}u_l + 3*t` and total entropy is `g*m`. The exact observation rank can be lower, but only a live `G_r/G_w` audit may exploit that reduction.
  Date/Author: 2026-08-22 / Codex complete-ZK workstream.

- Decision: Treat zero PCS-wire overhead as a conditional theorem requiring an explicit relation-free-tail refinement, never as a property of unused compiled slots.
  Rationale: if `H` is the full current `N`-point message/MLE domain, `deg Z_H=N` and every nonzero `R` exceeds the current degree bound. Verifier-known zeros and padding remain relation-owned unless the live compiler proves they may be randomized without changing reductions or public-padding compression. Current M4 source exports no such proof, so its spare degree and live wire delta are null.
  Date/Author: 2026-08-22 / Codex complete-ZK workstream.

- Decision: Prefer a faithful port of Diamond Construction 4.1 over the exploratory `P+Z_H R` transform.
  Rationale: Diamond supplies the relevant perfect-IOP-ZK theorem and explicitly requires setup on `ell+1`, `kappa=gamma*2^theta` random high coefficients, a blind commitment, virtual-oracle interleaving, and BCS salted openings. The current appended-dummy channel and the exploratory vanishing mask do not inherit that theorem. The latter remains only a fail-closed rank/capacity alternative.
  Date/Author: 2026-08-22 / Codex complete-ZK workstream.

## Outcomes & Retrospective

The module now states an implementable sufficient linear masking gate and produces a concrete leak whenever the gate fails. It also freezes the source-faithful Diamond geometry/wire seam, missing whole-view simulator surface, endpoint repair, leaf identity, retry behavior, and byte equations. This is useful negative and integration evidence, not complete ZK: the current backend lacks every Diamond compiler step; exact transaction/BaseFold composition, QROM programming, serializer refinement, and production geometry remain absent. The correct result is therefore `complete_zk=false` and `production_authorized=false`.

## Context and Orientation

`B128` is the 128-bit binary field used for committed codeword symbols. `E384` is a degree-three extension represented by three B128 coefficient lanes and used for interactive challenges. BaseFold commits to codewords, derives challenges with Fiat--Shamir, recursively folds codewords, and opens selected leaves plus a terminal codeword. A raw opening is dangerous because it exposes a linear functional of the original witness oracle, regardless of whether the Merkle authentication path itself looks random.

The only source file owned by this plan is `prototypes/standalone-shake256-binius/strict-mixed-field/src/complete_zk.rs`. The retained evidence and machine-readable status live under `.agent/hardening/binius-e384-complete-zk/`. Integration into `lib.rs`, semantic hashes, transport, consensus, and production capability selection belongs to other workstreams.

For a fixed public transcript, write the verifier view as `W w + R r`, where `w` ranges over same-statement witness differences and `r` is uniform simulator randomness. The two view distributions are identical exactly when every column of `W` belongs to the image of `R`, equivalently `rank(R)=rank([R|W])`. In the raw-opening model, `W=O G_w` and `R=O G_r`: `O` contains every serialized raw and terminal linear functional, `G_w` spans every same-statement witness delta, and `G_r` maps independent E384 masks into the relation kernel. The module checks these identities by exact E384 Gaussian elimination and emits a left-nullspace distinguisher on failure.

## Plan of Work

First, keep the algebraic audit independent from backend internals. The backend must export the exact query/fold/terminal observation matrix and exact witness/mask generators. Feed those into `RawOpeningModel::audit`; do not replace them with counts or random tests. The compiler's refinement proof must bind `expected_witness_delta_rank` to the real same-statement delta space. `maximum_distinct_opened_b128_coordinates` supplies only the conservative entropy ledger: per-group `m = u_0 + 3*sum_{l>0}u_l + 3*t`, total `g*m`. `plan_conservative_vanishing_mask_basefold` solves the corresponding dimension fixed point while holding `r` and `q` fixed. Neither count is a substitute for matrix rank.

Second, port Diamond Construction 4.1 faithfully in the large binary field selected by the backend. The port must run setup on `ell+1`, append `kappa=gamma*2^theta` high coefficients, commit an independent blind polynomial, use the virtual combination oracle, interleave sumcheck and FRI, retain the degree-one terminal, and add the cited salted-opening grammar. Only then instantiate every entry in `ALL_PROOF_VIEW_CLASSES` for the surrounding transaction proof. Commitment roots, authentication paths, sampler outcomes, and the final transcript digest need a single joint programmable-SHA-512 simulation. Each strict opened grouped leaf carries one independently sampled 64-byte tape and binds its oracle group, layer, exact index, lane count, and all coefficient lanes; this 64-byte QROM choice is stronger than the paper's 32-byte classical BCS salt but does not itself prove QROM composition.

Third, append two full-E384 dummy multiplication rows to the outer relation. Commit `(a_i,b_i,c_i=a_i b_i)` for both rows, expose the endpoint only after its equality weights are transcript-derived, and include the endpoint loss in the global statistical/QROM union. Never reinterpret two B128 dummy values as full E384 entropy.

Fourth, derive exceptional challenges canonically. For each role, hash transcript state plus a fixed role and counter, select the first acceptable value among sixteen candidates, and fail on public exhaustion. Do not serialize a nonce or retry after any witness-derived event.

Finally, freeze exact proof geometry and fill `CompleteZkOverheadGeometry` from the serializer. The exact incremental equation is `framing + 64*(new roots + new authentication nodes + opened grouped-leaf tapes) + 48*(opened mask values + explicit masked claims + terminal values) + 32*(three widened endpoint values)`. Values committed behind a root contribute wire bytes only when their lanes are actually opened; all such opened full-E384 mask values belong in the 48-byte term.

## Concrete Steps

Work from `/Users/pldd/Projects/Reflexivity/Hegemon`. Format only the owned module without traversing concurrently edited child modules:

    rustfmt --edition 2024 --config skip_children=true \
      prototypes/standalone-shake256-binius/strict-mixed-field/src/complete_zk.rs

Once `df` reports at least 28 GiB free, build and run the isolated dependency-free audit. The harness uses the exact current B128/E384 implementation but deliberately does not compile the concurrently in-flight PCS modules. Do not run it during the active 17 GiB hard stop:

    PYTHONDONTWRITEBYTECODE=1 python3 \
      .agent/hardening/binius-e384-complete-zk/direct_rustc.py

The status output must end with:

    exact_raw_opening_matrix_exported=false
    whole_proof_simulator_implemented=false
    complete_zk=false
    production_authorized=false

An earlier 2026-08-22 source revision reported:

    test result: ok. 32 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out
    view_inventory_complete=false
    two_b128_endpoint_disqualified=true
    full_e384_endpoint_repair_specified=true
    exact_raw_opening_matrix_exported=false
    whole_proof_simulator_implemented=false
    complete_zk=false
    production_authorized=false

## Validation and Acceptance

The direct test suite must pass exact field-rank translation, executable left-null leakage, relation-kernel rejection, declared witness-rank rejection, low-bit-first fold ordering, duplicate/out-of-range query rejection, leaf identity mutation, endpoint span disqualification, exhaustive toy-field endpoint distributions, statistical-bound arithmetic, canonical sampler exhaustion, witness-dependent retry rejection, byte-overflow rejection, exhaustive view inventory, and fail-closed status.

That earlier pass does not validate the current source digests. Passing the deferred current-digest tests is necessary but not sufficient. Promotion additionally requires a real backend-derived `RawOpeningModel` whose view audit passes for every admitted transcript class, a concrete `WholeProofViewSimulator` implementation that consumes no witness, a reviewed adaptive SHA-512 QROM programming reduction, exact geometry in the byte ledger, and Rust-verifier/serializer refinement. Until all are present, any `complete_zk=true` or `production_authorized=true` is a release-blocking contradiction.

## Idempotence and Recovery

The Rust harness creates binaries under `/tmp` and is therefore deferred while free space is below the 28 GiB gate. The Python checker may run with `PYTHONDONTWRITEBYTECODE=1`; it creates no bytecode. Do not delete or rewrite other workers' files. If the direct compile later fails in a concurrently edited sibling module, record the exact error, notify its owner, and retry only after that module reaches a stable checkpoint.

## Artifacts and Notes

The fixed two-B128 counterexample is:

    weights = [1, Y]
    translation = Y^2
    rank_B128(weights) = 2
    rank_B128([weights | translation]) = 3
    statistical distance = 1

The selected endpoint repair uses two independent full-E384 pairs `(a_0,b_0)` and `(a_1,b_1)`, with `c_i=a_i b_i`. For outer dimension `n` and consecutive-row Hamming distance `d`, the local endpoint loss is conservatively bounded by `(n+d+1)/2^384`. This is not the whole-proof QROM bound.

## Interfaces and Dependencies

`RawOpeningModel::audit` is the exact linear audit. `WholeProofViewSimulator` is the witness-free joint simulator interface. `ProgrammableCommitmentSimulator` freezes SHA-512 leaf and parent programming. `SimulatorCoinSource` supplies independently domain-separated E384 masks and 64-byte leaf tapes. `CompleteZkOverheadGeometry::exact_overhead` is the checked byte ledger. These interfaces use only the local B128/E384 implementation and the Rust standard library; no external crate is introduced.

Revision note, 2026-08-22: created the fail-closed plan after the architecture tournament selected the single-copy mixed E384 route and the SmallWood Boolean route exceeded the wire-size envelope.
