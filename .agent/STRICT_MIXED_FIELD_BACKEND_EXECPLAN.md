# Strict mixed-field backend ExecPlan

This ExecPlan is a living document and must be maintained in accordance with
`.agent/PLANS.md`. The `Progress`, `Surprises & Discoveries`, `Decision Log`,
and `Outcomes & Retrospective` sections record the actual implementation state;
prototype completion never implies a production security claim.

## Purpose

Build a standalone, self-contained proof backend for the maximum Hegemon
production relation whose committed symbols remain compact B128 values while its
algebraic Fiat–Shamir challenges are sampled in a real `GF(2^384)` field. The
backend must earn the strict security lane before any proof-size result can
enter the verified frontier.

This plan is research-only until the production verifier, the independent
composed verifier, and the formal/refinement gates exist. It does not authorize
consensus integration.

## Progress

- [x] (2026-08-21 18:51Z) Implement the exact pinned GHASH B128 field and true
  cubic E384 field with serialization, inversion, and irreducibility KATs.
- [x] (2026-08-21 18:51Z) Implement coefficient-lane lifting, reconstruction,
  arbitrary E384 folding, differential multilinear tests, and product-ring
  cross-term negatives.
- [x] (2026-08-21 18:51Z) Add type-separated mixed prover/verifier channels,
  local SHAKE256 E384 transcript sampling, canonical `HGMXSC01` transparent
  sumcheck, exact parser, and serializer-produced wire counters.
- [x] (2026-08-21 18:51Z) Validate the dependency-free source with a direct
  lightweight Rust test build: 19 passed, 0 failed. No Cargo target or proof
  artifact was retained because the 28-GiB admission gate was closed.
- [x] (2026-08-21 18:51Z) Run the fixed lightweight executable directly; it
  reports a 464-byte research-only proof with 12 B128 symbols, four explicit
  E384 claims, one root, and two transcript-derived E384 rounds.
- [x] (2026-08-21) Audit the degree-aware characteristic-two masking kernel:
  exhaustive GF(4) fibers and transcript distributions plus 192 deterministic
  B128/E384 cases pass; restricted/reused masks, revealed delta, and unbound
  terminal controls fail closed.
- [x] (2026-08-22) Implement the dependency-free scalar Gao--Mateer
  Reed--Solomon/DP24 E384 BaseFold kernel with SHA-512 roots/transcript,
  explicit independent per-leaf tapes, canonical without-replacement queries,
  compact per-layer Merkle frontiers, exact parser/serializer, and mutation
  negatives. This is an equal-dimension research kernel, not live M4.
- [x] (2026-08-22) Integrate the fail-closed complete-ZK rank audit. The last
  direct `rustc` checkpoint passed 48 tests; the current source contains 51
  tests after later complete-ZK additions, which were not rerun after the hard
  disk stop. The backend exports the raw observation inventory but not
  relation-bound `G_w`/`G_r`, so all capability flags remain false.
- [x] (2026-08-22) Correct the serializer-derived retained-M4 mixed-depth
  screen. `q=319` is the conservative with-replacement 264-component count;
  exact without-replacement sampling needs q318, while freezing the incomplete
  ledger's other eleven terms makes q310 its modeled composed->128 minimum.
  At q310 and tree depths `13,18,20,11,16,12,9`, the fixed-synthetic-transcript
  projection is 1,528,928 bytes. It is not a proof measurement or universal
  lower bound, but it is larger than the retained 1,344,828-byte comparator
  before ZK/QROM repair and makes this exact 4+3-tree implementation
  noncompetitive.
- [ ] Replace the transparent full-table opening with a reviewed binding and
  hiding vector PCS over B128 coefficient lanes.
- [ ] Integrate the mixed channel into the pinned sumcheck/FRI verifier with
  fail-closed profile/domain checks and maximum-degree accounting.
- [ ] Complete maximum-relation refinement, end-to-end ZK, composed PQ128/QROM,
  independent parser agreement, and two-artifact reproduction gates.

## Surprises & Discoveries

- Observation: an E384 challenge is uniform without rejection when sampled
  from 48 SHAKE256 bytes.
  Evidence: E384 is represented by three arbitrary canonical 128-bit
  coefficients, so all `2^384` byte strings map bijectively to field elements.
- Observation: “no explicit E384 values” and “no explicit challenges” are not
  equivalent wire properties.
  Evidence: the toy sends two 48-byte E384 sumcheck claims per round while all
  E384 challenges remain transcript-derived and cost zero bytes.
- Observation: making the type split executable does not solve the PCS.
  Evidence: the honest four-value toy is exactly 464 bytes because it transmits
  all twelve B128 lane symbols; this is transparent and non-hiding.
- Observation: `Z(X)=X(X+1)` alone is not a complete quadratic mask in
  characteristic two. The endpoint-sum kernel is exactly `{a+b*Z(X)}`;
  omitting the independent full-E384 constant mask exposes a coefficient.
- Observation: a hidden but unbound terminal delta destroys soundness. The
  executable negative control satisfies a false public sum by selecting that
  delta after the challenged round.
- Observation: the existing upstream mixed-depth verifier seam is not matched
  by its prover.
  Evidence: `FRIParams::optimal_for_batch` and
  `FRIQueryVerifier::new_batch` already handle mixed lengths and a generic
  `Elem`, while `IPProverChannel`, `FRIFoldProver`, and
  `MerkleIPProverChannel` hard-code challenges, folded buffers, and committed
  scalars to one `F`.
- Observation: canonical compact frontiers do not rescue the retained 4+3
  tree geometry under strict query count and full-extension values.
  Evidence: the q310 fixed schedule opens `[305,310,310,292,310,301,237]`
  leaves and needs `[1234,2771,3391,654,2151,937,194]` SHA-512 frontier nodes;
  before framing or ZK repair this projects to 1,528,928 bytes.
- Observation: appended dummy coefficients do not make the scalar Gao--Mateer
  opening zero knowledge.
  Evidence: leaf zero is systematic and reveals an active coordinate with TV
  one when queried. A surviving design needs a disjoint commitment domain and
  `P+Z_H R` with at least q independent B128 coefficients, then an exact
  whole-view `rank(O G_r)=rank([O G_r|O G_w])` certificate. The current
  diagnostic finalists have 79,128 and 90,600 raw nonlinear u64 words, which
  imply at least 39,564 and 45,300 B128 symbols and force n16. Their numerical
  slack plus q310 does not prove a relation-free mask tail; the exact full
  domain, capacity, degree growth, and wire delta are unknown.
- Observation: a power-of-two E512 field does not remove the mixed-channel
  blocker unless the entire M4 scalar is widened.
  Evidence: mixed E512 is 1,763,232 bytes on the same schedule; all-E512 is
  1,883,136 bytes and also changes initial-oracle packing.

## Decision Log

- Decision: mirror the pinned channel shape with separate associated types for
  committed symbols, challenges, and claims instead of forcing one field type.
  Rationale: B128 coefficient lanes and E384 algebra must remain distinguishable
  at compile time; a cast or triple-B128 alias would reintroduce the product-ring
  error.
  Date/Author: 2026-08-21 / Codex.
- Decision: include a dependency-free SHAKE256 implementation with a standard
  KAT in the isolated crate.
  Rationale: importing the pinned transcript would restore its hard-wired
  `BinaryField` sampler, while adding a new dependency would require a Cargo
  lock/build operation during a closed disk gate.
  Date/Author: 2026-08-21 / Codex.
- Decision: serialize the complete three-lane table in the toy proof.
  Rationale: this makes the committed-symbol/challenge-field seam and exact wire
  cost directly executable without pretending that an unimplemented compact
  PCS exists.
  Date/Author: 2026-08-21 / Codex.
- Decision: do not port the retained BaseFold prover channel further under the
  current 4+3-tree topology.
  Rationale: its corrected q310 fixed-schedule projection is already 1,528,928
  bytes, above the retained comparator while charging zero complete-ZK and
  production overhead. A different grouping/topology can be smaller, so this
  is an implementation-route decision rather than a universal BaseFold no-go.
  Date/Author: 2026-08-22 / Codex.
- Decision: route the next bounded screen to a one-level mixed-field
  Ligerito/TensorSwitch opening over the exact maximum M4 relation.
  Rationale: it removes the three wide FRI-round trees that dominate the
  retained result. Existing 112,784-byte Pay1x2/n14 evidence is not transferable;
  the maximum-relation serializer and complete-ZK terms must pass the same cap.
  Date/Author: 2026-08-22 / Codex.

## Outcomes & Retrospective

The isolated prototype now demonstrates one complete mixed-field interaction
and one real low-degree/authentication kernel:
B128 coefficient-lane material is rooted and serialized as B128, degree-one
sumcheck claims and folds are computed in E384, and SHAKE256 derives canonical
E384 challenges without adding proof bytes. Exact decoding and mutation tests
plus the fixed `src/main.rs` KAT make the seam falsifiable. This removes the
type/interface ambiguity but does not reduce proof size or earn PCS binding,
hiding, live-M4 integration, complete ZK, or PQ/QROM capabilities. More
importantly, the corrected retained-tree q310 projection is 1,528,928 bytes,
so this topology is not the smallest current route even before those missing
gates are completed. The strict production frontier remains empty; the next
work is a different one-level opening topology, not further optimization of
this BaseFold wire.

## Current pinned-source finding

Pinned Binius64 revision:

```text
3f96163049f680b2909f6545690bd929f1b48c44
```

The pinned field crate supplies `BinaryField128bGhash` and the degree-two
`GhashSq256b` extension. Its BaseFold/FRI/Spartan channels require
`BinaryField`, and the binary tower only exposes power-of-two extension degrees.
There is no `GF(2^384)` challenge type or mixed-field channel. A type alias or a
triple of independently sampled B128 values is not an implementation.

The isolated algebraic KAT is at
`prototypes/standalone-shake256-binius/strict-mixed-field/`.

The independently audited local hiding kernel is at
`prototypes/standalone-shake256-binius/char2-hvzk-sumcheck-kernel/`. Its exact
local wire is `48*linear_rounds + 96*quadratic_rounds`, with zero explicit
terminal-delta bytes. Hidden-mask commitment/opening cost remains unknown.

## Algebraic construction

Use the exact pinned GHASH base field:

```text
B128 = GF(2)[X] / (X^128 + X^7 + X^2 + X + 1)
```

Define the challenge field:

```text
E384 = B128[Y] / (Y^3 + Y + 1)
```

The cubic irreducibility witness is executable and independent of any
security label: for `q = 2^128`, the residue computation gives
`Y^q - Y = Y^2 (mod Y^3 + Y + 1)`. The cubic is coprime to `Y^2` because its
constant term is one, so it has no root in `B128`; a cubic with no root is
irreducible. E384 elements serialize as three little-endian B128 coefficients
(48 bytes) only when explicitly transmitted.

Three independently sampled B128 challenges are the product ring `B128^3`,
not E384. Its nonzero coordinate vectors `(1,0,0)` and `(0,1,0)` multiply to
zero. That zero-divisor counterexample is a hard rejection of treating
independent repetitions as one scalar in Schwartz–Zippel, sumcheck, or FRI
soundness accounting.

## Required mixed-field interface

The existing `BinaryField`-only channel must not be widened by a cast. Add an
explicit research interface with separate types:

```text
Committed = B128
Challenge  = E384
Digest     = SHAKE256-512 (64 bytes)
```

The interface must specify, in order:

1. Transcript observation and domain separation.
2. Sampling of E384 challenges from 48 transcript bytes with rejection only if
   a canonical encoding rule requires it; all sampled values must be uniform.
3. Lifting B128 committed symbols into E384 for algebraic evaluation.
4. Exact fold/sumcheck operations and their degree accounting over E384.
5. A PCS/vector opening format that states which values are B128 symbols and
   which are E384 values. A fold of a B128 codeword by an E384 scalar is an
   E384 value; it cannot be silently serialized as 16 bytes.
6. Verifier rejection of the existing Binius `BinaryField` path when the
   mixed-field profile tag is absent or the field/domain fingerprint differs.

The compact target requires either a vector PCS that commits B128 coefficient
lanes while evaluating in E384, or a measured count of explicit E384 openings.
The current Binius Merkle/FRI path does neither.

The isolated crate now implements this interface at toy level. The
`MixedFieldProverChannel`/`MixedFieldVerifierChannel` associated types fix
`CommittedSymbol = B128` and `Challenge = Claim = E384`.
`Shake256E384Transcript` observes framed context/root/claims and maps exactly 48
XOF bytes to each E384 challenge. `prove_toy_mixed_sumcheck` and
`verify_toy_mixed_sumcheck_exact` run a low-bit-first multilinear sumcheck over
a transparently transmitted three-lane table. This is an interface milestone,
not the missing PCS or pinned-verifier integration.

## Exact wire formula

For a declared mixed-field proof wire, with no implicit fields:

```text
proof_bytes = fixed_bytes
            + 16 * base_symbol_elements
            + 48 * explicit_wide_elements
            + 64 * (merkle_root_count + merkle_auth_node_count)
```

The `48 * explicit_wide_elements` term is zero only when all E384 values are
transcript-derived or reconstructible from authenticated B128 lanes. The
isolated `MixedFieldWire` implementation checks this arithmetic. It must be
populated from actual serializer counters, not inferred from a static estimate.

For the canonical transparent toy with `N = 2^n` table values, the exact
serializer output is:

```text
toy_bytes = 16 + 48*N + 64 + 96*n
```

The fields are the 16-byte header, `3*N` B128 coefficient symbols, one 64-byte
root, and two explicit 48-byte E384 claims per round. The writer returns the
counter object that generated those exact bytes. The 48-byte transcript
challenges are observed only and therefore add zero wire bytes. For `N = 4`,
the test pins the exact result to 464 bytes.

## Security gates

No strict-lane promotion is permitted until all of these are independently
true:

- Full Hegemon relation and private witness semantics are proved by the exact
  backend, including malformed and public-binding negatives.
- End-to-end zero knowledge is demonstrated for the maximum relation with a
  simulator/statistical bound of at least 128 bits.
- The degree-aware sumcheck mask source is bound before Fiat--Shamir
  challenges, the round chain terminates in one opening of that same masked
  oracle, and neither the terminal delta nor separate witness/mask evaluations
  are revealed. Local affine-fiber hiding alone is insufficient.
- Every randomizer that hides an E384 transcript value is a uniform E384
  element encoded as three independently sampled B128 coefficient symbols.
  Single-B128 OTP, trace, dummy, Libra, or PCS masks are rejected. In
  particular, two B128 dummy rows span at most dimension two in the
  three-dimensional extension and can give disjoint transcript support for an
  allowed endpoint translation. The strict simulator supplies a separate
  B128-linear rank and correlated-endpoint certificate; same-field B128
  endpoint estimates are not accepted as E384 evidence.
- The actual E384 protocol has a reviewed maximum algebraic union degree with
  `log2(D) <= 120`, yielding at least 264 classical field bits.
- FRI, sumcheck, Fiat–Shamir, multi-target, Merkle, semantic-hash,
  key-entropy, commitment-hiding, rho-privacy, and ZK failure terms are
  composed with the declared QROM rules. The existing scaffold must report a
  floor of at least 128 bits; no term may be omitted because it is inconvenient.
- SHAKE256-448 is used for semantic hashes and SHAKE256-512 for proof
  commitments/transcript outputs, with exact domain labels and transcript-order
  KATs.
- Two independently generated strict proof artifacts pass the same exact
  parser/verifier and every verification gate. Randomized zero-knowledge proofs
  are not required to have identical digests; each retained artifact is bound
  to its candidate source, public statement, coins provenance, and own digest.
- The production parser/verifier and independent composed verifier accept the
  exact same bytes and reject mutation, truncation, wrong-profile, and trailing
  data cases.

Until then `strict_pq_profile.py --require-release` must remain failing because
the capability flags are not earned.

## Byte optimization order

1. Reproduce the full relation with a deliberately unoptimized mixed-field
   implementation and record the serializer breakdown.
2. Eliminate redundant B128 advice only when the verifier reconstructs it from
   an authenticated commitment and a formally specified invariant.
3. Batch B128 coefficient lanes in the PCS without changing the E384 field
   equations or widening the authentication path.
4. Re-sweep fold schedules under strict parameters. Keep only measurements
   that pass every strict gate; weak-profile geometry is a diagnostic, never a
   frontier point.
5. Run the exact block/action capacity calculation using measured proof bytes.

## Resource and stop controls

- Admit heavy runs only with at least 30,064,771,072 free bytes; abort below
  21,474,836,480 bytes.
- Run one candidate at a time, with a 5 GiB run-root cap, 4 GiB cargo-target
  cap, 8 GiB reported RSS cap, and 1,800-second wall cap.
- Delete disposable `target` trees and unqualified proof dumps after hashing
  the report. Retain exactly the two canonical proof artifacts required by the
  production parser gate once a candidate passes the relation, binding, ZK,
  PQ128, and size preconditions; cap and content-address both artifacts.
- A failed strict security gate is a normal negative result; it must not be
  relabeled as a compact win.

## Exit criteria

The plan is complete only when a measured standalone proof has a strict
release-authorized report, two reproductions, exact serializer counters,
independent verifier agreement, and a reviewable patch against the pinned
source. Until then the strict frontier is empty, regardless of any smaller
transparent or 96-bit proof.

Plan revision note (2026-08-22): recorded the executable authenticated
low-degree kernel, exact compact-frontier serializer, integrated fail-closed
complete-ZK audit, systematic-leaf ZK no-go, pinned-source channel blocker,
E512 competitor, and corrected q310 1,528,928-byte retained-tree projection.
The 4+3-tree implementation is noncompetitive rather than a universal
BaseFold no-go, and the strict frontier stays empty.
