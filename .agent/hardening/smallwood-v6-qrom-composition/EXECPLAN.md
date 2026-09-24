# Build a fail-closed SmallWood V6 PQ/QROM composition ledger

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` remain current in accordance with `.agent/PLANS.md`.

## Purpose / Big Picture

Hegemon needs a reproducible answer to whether one exact SmallWood transaction proof has strictly more than 128 bits of composed post-quantum security. This lane recomputes every finite PCS/IOP, Fiat-Shamir, hash, sampler, grinding, and history term with exact rational arithmetic; binds the calculation to profile, domains, registry, and source; and reports missing reductions. Its safe observable outcome is a machine-readable negative certificate. Parameter screens and candidate-declared booleans never become production authority.

## Progress

- [x] Read `AGENTS.md`, `DESIGN.md`, `METHODS.md`, `README.md`, `.agent/PLANS.md`, `.agent/SMALLWOOD_SHAKE256_PRODUCTION_EXECPLAN.md`, the SmallWood engine/frontend, statement/relation sources, and local formal QROM modules.
- [x] Implemented strict JSON parsing, exact fractions, four interactive terms, three CMS terms, exact sampler aborts, grinding/retry and history accounting, and unconditional fail-closed capability output.
- [x] Froze the historical rejected `HGF6ST02` 893-byte/128-limb statement, strict disjoint-coset DECS identity, 64-byte leaf tape plus index binding, and 1,472-byte opened-tape payload.
- [x] Added twelve checker-owned source roles, canonical source-manifest framing, statement/registry sole-owner checks, typed domain-source checks, and frozen scalar/M4 tournament pins including the M4 source checker and Binius-tree identity.
- [x] Added a checker-owned 43-role inventory spanning semantic hashes, three opaque stablecoin authorities, eleven consensus hash448 roles, sixteen proof SHA-512 roles, and two manifests.
- [x] Reproduced the exact 214-byte `HGF6HR02` registry and raw SHA-512 digest `840e4426...a19631`; bound 79 calls and 145 Keccak permutations.
- [x] Added strict integer role caps and a mutation test proving an unavoidable SHAKE256 preimage role fails at exactly 128 quantum bits.
- [x] Split global hash accounting into one SHAKE256 collision screen, one rejected Keccak[c=1024] collision screen, one rejected Keccak[c=1024] preimage/PRF screen, and one SHA-512 leaf-hiding screen; no 79-call or 145-permutation union multiplier is allowed.
- [x] Disqualified `HGF6HR02`: its rate-72/capacity-1,024 `Shake512Output448` is not a FIPS SHAKE function and is a new primitive authority.
- [x] Added a no-winner conventional-successor comparison for split SHA3-512 and RFC 7693 BLAKE2b-448/keyed mode.
- [x] Passed 25 lightweight Python tests; no Cargo, network, or heavy build was used.
- [x] Refreshed the core-only Lean bookkeeping module to the rejected mixed profile and re-typechecked it without dependency builds.
- [x] Retained an exact twelve-file source snapshot and framed relation-manifest pin; the checked certificate passed the binding gate at capture, and any later concurrent edit fails closed.
- [x] Audited the live Binius field/channel traits and separated the rejected B128/SHA-256/96-bit profile from the proposed SHA-512 E384/E512 channel.
- [x] Added an exact finite-population query gate and a dependency-free port of the source-pinned retained-M4 query/frontier projection.  The depth-20, rate-`1/8`, historical `2^-264` component minimum is `q=318`; freezing the incomplete scaffold's other eleven terms gives a distinct modeled `q=310` minimum for composed bits just over 128.  Neither is production-selectable.  Their mixed-E384 static projections are 1,555,840 and 1,528,928 bytes before ZK repair.
- [x] Passed 16 field/challenge checker tests, including exact q116/q319 source reproduction, q318/q310 projections, SHA-256 negative control, E384 coefficient boundary, and fail-closed authority flags.
- [x] Integrated the systematic-leaf-zero privacy no-go: raw `pi`/`omega` openings have conditional statistical distance one.  The specified per-group `P+Z_H R_g` repair needs `m` coefficients per group for the maximum whole-view opened B128-coordinate count, not merely q coefficients, and requires a full geometry/security recomputation.  The source-faithful Diamond Construction 4.1 setup on `ell+1` with `kappa = gamma*2^theta` appended random coefficients makes both retained byte checkpoints zero-ZK-cost counterfactuals.
- [x] Audited standard SHA-512 truncation, HMAC/HKDF, split SHA3-512/SHAKE256, KMAC/TupleHash/ParallelHash, RFC 7693 BLAKE2b, lower-query-cap relabeling, and LaZer Pack/LNP-Lite against primary sources. Added a digest-bound audit-only 15-role registry, exact 400-bit width gate, compatibility geometry, source-operation schedules, DFM20 widening arithmetic, and valid-negative mutation tests.
- [x] Refreshed the final quiescent scalar/M4/checker pins and twelve-source manifest (`6458fedf...acc20b9`); the dependency-free evaluator now reports `input_valid=true`, `source_binding.binding_pass=true`, and all production capabilities false. All 55 tests pass.
- [ ] Production closure remains external: choose a conventional keyed construction, measure exact V6 geometry/proof bytes, enforce physical/history caps, complete reductions/refinements/zero knowledge, and obtain independent review.

## Surprises & Discoveries

- Observation: `HGF6HR02` solves the numerical capacity problem but fails the conventional-hash gate.
  Evidence: algorithm tag 2 uses Keccak-f[1600], rate 72, capacity 1,024, and suffix `0x1f`. FIPS 202 and the local RustCrypto `sha3` implementation expose SHAKE128/256 only. The code-defined “SHAKE512” is novel.

- Observation: uniform FIPS SHAKE256 cannot carry the six secret/preimage/PRF roles under a strict target.
  Evidence: its classical preimage ceiling is 256 bits and its Grover ceiling is 128 bits. The low-budget counterfactual `Q^2/2^256` equals `2^-128` at `Q=2^64`, while the gate requires strictly less.

- Observation: collision-only SHAKE256-448 roles retain numerical margin.
  Evidence: their generic quantum collision cap is `floor(448/3)=149` bits. Alternate accepted encodings must reduce to collision; native second-preimage strength is not assumed.

- Observation: the live stablecoin surface superseded the historical 56-byte diagnostic fields but still fails strict composition.
  Evidence: `HX448C02` is 869 bytes / 125 limbs and carries exact 48-byte live fields. Policy has an exact public 61-byte SCALE source and RFC 7693 BLAKE2b-384 constructor; oracle and attestation lack canonical source grammars and secrecy classifications. A compatibility-preserving 400-bit repair that retains all three live fields is 953 bytes / 137 limbs; the 809-byte form is replacement-only migration.

- Observation: raw SHA3-512 over secret input is not automatically a production PRF/KDF.
  Evidence: split SHA3-512 gives good width/key-search screens and an exact 151-permutation schedule, but no executed prefix-keyed PRF/KDF QROM reduction exists. HMAC/HKDF is not inherently required for a uniform 384-bit seed; a reviewed keyed construction and reduction is required.

- Observation: neither the smaller unkeyed BLAKE2b screen nor its keyed repair can yet win.
  Evidence: the exact unkeyed mixed schedule is 83 calls / 28 BLAKE2b compressions / 105 SHAKE256 permutations (133 heterogeneous cores), but raw secret hashing has no PRF/KDF authority.  The keyed/personalized repair is 83 calls / 32 BLAKE2b compressions / 105 SHAKE permutations (137 cores).  RFC 7693 supplies a conventional keyed MAC, but no reviewed deployed BLAKE2b QRO or multi-user PRF/KDF reduction with bounded QROM loss is pinned.  Keccak permutations and BLAKE2 compression calls are not proof-row or proof-byte measurements, and authorization `policy_root` has no enforced entropy lower bound.

- Observation: the ideal SmallWood CMS work-factor screen has limited headroom.
  Evidence: the historical 699-row regression fixture is about `0.1443` at `2^128` queries before deployed losses. A `2^32` per-proof union exceeds one, so a proved shared tagged-product-oracle history theorem is structurally necessary.

- Observation: physical SHA-512 calls remain uncapped.
  Evidence: Goldilocks rejection sampling can draw additional blocks, while the optimized prover leaf path bypasses the existing digest counter. Structural counts are not an enforced global query ledger.

- Observation: canonical sampling without replacement saves only one query for the historical 264-bit component allocation and does not determine a production count.
  Evidence: `q=317` fails and `q=318` is the exact fixed-set component minimum on `M=2^20`, `B=7M/16`; the exact SHA-512-derived `q=318` compact-frontier projection is 1,555,840 bytes, 7,136 bytes larger than the `q=319` projection because the transcript-selected frontier changes.  The frozen incomplete union crosses 128 modeled bits at q310, but its missing reductions can raise that count.

- Observation: no enumerated retained 4+3-tree checkpoint fits the provisional 512-KiB screen.
  Evidence: even the rejected historical q116 fixed-synthetic-transcript E384 serializer projection is 695,840 bytes before framing or ZK repair.  This is a topology-specific comparison, not an immutable parser rule or universal BaseFold lower bound.

- Observation: field width and transcript width do not repair complete ZK.
  Evidence: the Gao–Mateer zero leaf is systematic and raw `pi`/`omega` exposure has conditional TV one.  The disjoint-domain vanishing mask is specified but not integrated.  Each independently encoded group needs `m` coefficients for its maximum opened B128-coordinate inventory across initial siblings, later E384 lanes, and terminal values; q alone is not the rank or degree.  Diamond ePrint 2025/1015 Construction 4.1 sets BaseFold up on `ell+1` and appends `kappa = gamma*2^theta` random coefficients, so the current q310/q318 byte projections charge zero ZK cost and must be recomputed.  Without a proved relation-free tail, any full-domain mask increases the power-of-two message dimension.

## Decision Log

- Decision: Reject both the uniform-SHAKE256 profile and `HGF6HR02`.
  Rationale: the former reaches exactly 128-bit quantum preimage strength; the latter introduces a nonstandard XOF authority. Neither satisfies the objective.
  Date/Author: 2026-08-22 / Codex

- Decision: Do not rotate to another registry identity yet.
  Rationale: split SHA3-512 lacks a concrete Keccak/sponge QROM bridge and keyed-role reduction; unkeyed BLAKE2b lacks PRF/KDF authority; keyed BLAKE2b lacks a deployed bounded-loss QRO/multi-user PRF bridge and authorization-key entropy contract. There is no defensible smallest winner.
  Date/Author: 2026-08-22 / Codex

- Decision: Require exact `Fraction` comparison strictly below `2^-128` at `2^64` total quantum queries and below `1/2` at `2^128` queries.
  Rationale: equality at 128 is not “greater than 128,” and floating estimates cannot decide the gate.
  Date/Author: 2026-08-22 / Codex

- Decision: Carry one global term per primitive/property pair and forbid call/permutation unions.
  Rationale: 79 uses and 145 internal permutations specify relation coverage and cost, not 79 or 145 independent primitive failures.
  Date/Author: 2026-08-22 / Codex

- Decision: Keep source/profile/domain binding separate from cryptographic authority.
  Rationale: pins detect drift but cannot prove PCS, Fiat-Shamir, PRF, hiding, extraction, refinement, or zero knowledge.
  Date/Author: 2026-08-22 / Codex

- Decision: Keep all universal refinements hard-coded as unexecuted and production false.
  Rationale: a profile cannot self-issue evidence receipts.
  Date/Author: 2026-08-22 / Codex

- Decision: Rank the exact retained 4+3-tree E384/E512 implementation as noncompetitive, without treating 512 KiB as immutable or claiming a universal BaseFold lower bound.
  Rationale: at the incomplete-scaffold q310 checkpoint, mixed E384 is 1,528,928 bytes, already 184,100 bytes larger than the retained 1,344,828-byte B128 comparator before ZK repair.  Different grouping/topology can change the result, and the 512-KiB parser-safety bound is provisional.
  Date/Author: 2026-08-22 / Codex

- Decision: Leave every standard-suite candidate and LaZer Pack unselected.
  Rationale: SHA-512/HMAC and split SHA3/SHAKE lack concrete deployed-hash QROM bridges; KMAC's applicable theorem is QIPM-only and needs keys longer than the rate; BLAKE2b's exact theorem is classical; and Pack starts at 125.678 bits and has only a heuristic classical-ROM Fiat--Shamir argument. The SHA-512-left400 schedule is an audit-only explicit-concrete-QRO experiment, not authority.
  Date/Author: 2026-08-22 / Codex

## Outcomes & Retrospective

The ledger gives a source-bound negative answer. The exact historical `HGF6HR02` registry and its generic numerical margins are reproducible, but the candidate is rejected because its wider XOF is nonstandard. The live `HX448C02` stablecoin policy constructor is now exact, while its 384-bit width and the still-undefined oracle/attestation source grammars keep strict composition closed. The 15-role escape registry and all standard-suite candidates remain unauthorized because deployed reductions are absent. All 55 dependency-free composition, field, source, domain, schedule, and LaZer mutation/arithmetic tests pass.

The production objective is not complete. Exact V6 LPPC geometry and proof bytes are unmeasured; the retained pins are a rejection snapshot rather than release evidence; physical SHA-512 and epoch history are unenforced; and PCS/IOP/Fiat-Shamir/hash/grinding/union, complete-ZK, parser/wire, relation/compiler, Rust-verifier, and independent-review gates remain open. `composed_pq128` and `production_authorized` stay false.

## Context and Orientation

`circuits/transaction/src/full_shake448_statement.rs` owns `HGF6ST02`, `HEG-F6V2`, and `HGF6HR02`. `smallwood_shake256_full_relation.rs` owns the Boolean Keccak compiler; `full_shake448_relation.rs` owns the full semantic program; `smallwood_v6_adapter.rs` lowers it; `smallwood_v6_envelope.rs` owns transport; `smallwood_engine.rs` and `smallwood_frontend.rs` are the proof engine and verifier boundary. `crypto/hash448/src/lib.rs` owns consensus SHAKE256-448 domains.

This directory is an isolated accounting lane. `profile.json` is a negative artifact. `composition.py` validates and recomputes it. `test_composition.py` creates temporary synthetic geometry/loss fixtures solely to exercise otherwise unreachable arithmetic. `formal/crypto/HegemonCrypto/SmallWoodV6CompositionAccounting.lean` is finite bookkeeping, not security authority.

## Plan of Work

Keep the exact rejected registry and retained source snapshot reproducible. If concurrent owners change a pinned file, accept the deliberate fail-closed mismatch and repin only after reviewing the new rejection artifact. Do not choose SHA-512-left400, SHA3-512, KMAC, or BLAKE2b until the stated concrete-hash assumption or bridge, exact keyed-role construction, min-entropy contract, fixed authorization mux, emitted geometry, proof bytes, and complete QROM composition are independently reviewed.

## Concrete Steps

From the repository root, run:

    python3 -m unittest discover -s .agent/hardening/smallwood-v6-qrom-composition -p 'test_*.py' -v

Expected tail:

    Ran 55 tests
    OK

Run the negative certificate:

    python3 .agent/hardening/smallwood-v6-qrom-composition/composition.py --profile .agent/hardening/smallwood-v6-qrom-composition/profile.json --repo-root .

Expect status 2, `input_valid: true`, `composed_pq128: false`, and `production_authorized: false`. The blockers must include the nonstandard `HGF6HR02` primitive, unresolved strict stablecoin constructors/margins, geometry, physical/history caps, reductions, refinements, complete zero knowledge, and review.

Run the conventional-suite/LaZer escape screen:

    PYTHONDONTWRITEBYTECODE=1 python3 .agent/hardening/smallwood-v6-qrom-composition/escape_hatch.py

Expect status 2, `status: valid-negative`, the exact 15-role registry digest,
`standard_suite_selected: false`, `lazer_pack_qrom_authorized: false`,
`composed_pq128: false`, and `production_authorized: false`.

If the existing core-only Lean environment is available, run without building dependencies:

    cd formal/crypto
    lake env lean HegemonCrypto/SmallWoodV6CompositionAccounting.lean

## Validation and Acceptance

The isolated lane is accepted when the 55 tests pass; both role-registry digests reproduce; an exact-128 preimage mutation fails; nonstandard primitive and unresolved-authority gates fail; stale statement/route/projection, source/domain mutation, missing loss, unsafe DECS, history overflow, malformed JSON, CLI authorization attempts, live SHA-256 controls, finite-query boundaries, q116/q319/q318/q310 projection mutations, 384/392-bit collision widths, lower query-cap relabeling, duplicate escape domains, and LaZer widening arithmetic all fail. It does not accept the larger production claim.

## Idempotence and Recovery

The checker is read-only. Tests use automatically removed temporary directories. Source repinning must be deliberate and reviewed after all owners stabilize; never patch around a mismatch. No Cargo, dependency download, or heavy build is needed.

## Artifacts and Notes

The checked profile is a retained rejection artifact. The 699-row geometry and synthetic tiny losses in tests are historical arithmetic fixtures, not V6 measurements or reductions. Exact numerators and denominators decide every numeric gate; diagnostic bit estimates do not.

## Interfaces and Dependencies

`composition.py` uses only the Python standard library. Its CLI accepts `--profile` and optional `--repo-root`, exits 1 for malformed input, and exits 2 for every valid negative certificate. The Lean module imports only core `Init.Data.Rat` and is not connected to production authority.

Revision note (2026-08-22): superseded historical 79/124 uniform-SHAKE256 evidence with the exact 79/145 `HGF6HR02` registry; classified 43 roles; rejected exact-128 preimage terms, the novel rate-72 XOF, and opaque stablecoin authorities; and added the no-winner conventional-successor tournament.

Revision note (2026-08-22): marked `HGF6ST02` historical; incorporated live `HX448C02` 869-byte mixed-width stablecoin geometry; added the 953-byte compatibility-preserving 400-bit experiment, exact standard-suite schedules, a 15-role audit registry, lower-cap no-go, and exact LaZer/DFM20 counterfactual thresholds. All capability flags remain false.
