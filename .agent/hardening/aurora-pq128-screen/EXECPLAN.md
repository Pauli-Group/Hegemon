# Aurora all-W64 PQ128 architecture screen

This ExecPlan is a living record for a bounded source, relation, and security
tournament lane. It follows `.agent/PLANS.md`. The lane is isolated to this
directory, performs no proof build, and cannot authorize a backend or
production route.

## Purpose

Determine whether Aurora's binary-field R1CS IOP and a modified BCS compiler
can already carry the exact prospective all-W64 Hegemon transaction relation
as one self-contained, completely zero-knowledge, strictly greater-than-128-bit
post-quantum/QROM proof. Preserve exact primary-source expressions, but never
convert an asymptotic formula, an implementation size counter, or a historical
benchmark into same-relation proof bytes.

## Progress

- [x] Read `AGENTS.md`, `DESIGN.md`, `METHODS.md`, `README.md`, and
  `.agent/PLANS.md` before writing.
- [x] Inspect and visually verify Aurora Definition 4.4 and Theorem 9.2.
- [x] Inspect and visually verify CMS19 Theorem 8.6 and Appendix B, plus BCS16
  Lemma 7.5's exact statistical-ZK loss.
- [x] Audit the pinned official libiop source without cloning or building it.
- [x] Freeze the exact binary full-relation projection or enumerate every
  characteristic-two mapping gap.
- [x] Derive the strict PCS/IOP/Fiat-Shamir/hash/grinding/union ledger.
- [x] Add the canonical certificate, checker, and mutation tests.
- [x] Run dependency-free verification and record final hashes.

## Surprises & Discoveries

- Observation: Aurora's zero-knowledge definition is whole-view and permits
  queries during the interaction; Theorem 9.2 is therefore materially stronger
  than a witness-masking argument.
  Evidence: Definition 4.4 requires identical distributions for every
  bounded-query verifier and straightline simulation, and the paragraph after
  the definition explicitly allows queries at any time to any oracle already
  received.

- Observation: whole-Aurora QROM soundness does not follow from FRI's
  round-by-round soundness.
  Evidence: CMS19 Theorem 8.6 requires the complete underlying IOP to have
  round-by-round soundness. The 2023 FRI result covers FRI and a stated
  delta-correlated class, while no inspected source proves that Aurora's R1CS
  algebraic core is in that class. Preon's Aurora extraction path is explicitly
  conjectural.

- Observation: the pinned libiop source is not a canonical binary-field proof
  wire.
  Evidence: its BCS README says final transcript serialization is missing;
  `bcs_common.tcc` prints that binary-field or non-algebraic-hash
  serialization/deserialization is not implemented; its logical size counter
  omits query-position bytes.

- Observation: the BCS statistical-ZK term uses total IOP proof length in
  bits, not compressed SNARK bytes or Merkle leaves.
  Evidence: BCS16 Lemma 7.5 gives exactly
  `z'(x,lambda)=z(x)+p(x)*2^(-lambda/4+2)`.

- Observation: even the conditional 29,509,133-row source projection rules out
  a 512-bit BCS digest before any soundness or union term is charged.
  Evidence: Theorem 9.2 forces `|L|>=2^27`; the theorem-minimal 28-bit binary
  field gives `p_bits>=15,032,385,536`, at most 92.192645 bits from Lemma 7.5
  at lambda 512, and a floor-only minimum lambda of 656. Pinned libiop's
  smallest supported GF64 profile needs lambda 664.

- Observation: a characteristic-two macro attempt produced exact arithmetic
  counts but not an accepted executable R1CS.
  Evidence: the unfrozen attempt reports `m=37,364,095`, `n=21,531,353`,
  `l=9,704`, and `nnz=156,526,483`, but retains no concrete A/B/C coordinates,
  frozen typed IR, or verified lowering; it is excluded from theorem and
  proof-size arithmetic.

## Decision Log

- Decision: keep Aurora a first-class theorem candidate rather than reject it
  merely because the original paper predates QROM Fiat-Shamir proofs.
  Rationale: Theorem 9.2 supplies complete bounded-query perfect ZK, and CMS19
  gives an applicable compiler shape if whole-protocol RBR can be proved.
  Date/Author: 2026-08-22 / Codex.

- Decision: require an explicit whole-Aurora RBR or generalized-special-
  soundness proof; component FRI RBR cannot fill that gate.
  Rationale: the premise of CMS19 is on the complete IOP, and conjectural
  state-restoration inheritance is not production evidence.
  Date/Author: 2026-08-22 / Codex.

- Decision: leave `proof_bytes`, lower bound, and upper bound null until a
  canonical binary-field wire and exact parameter profile exist.
  Rationale: Aurora's theorem reports full oracle length in field symbols,
  whereas BCS compresses those oracles; libiop's counter is neither a complete
  serializer nor a same-relation artifact.
  Date/Author: 2026-08-22 / Codex.

- Decision: disable proof-of-work/grinding in the candidate model and leave
  its term null until a theorem-backed implementation profile does so.
  Rationale: pinned libiop adds a non-standard final proof-of-work optimization
  whose exact QROM reduction and physical-call accounting are not supplied.
  Date/Author: 2026-08-22 / Codex.

## Outcomes & Retrospective

The bounded screen is complete and negative. Aurora's whole-view perfect IOP
zero knowledge is preserved as positive theorem evidence, but the complete
NIZK gate fails on the exact relation, whole-protocol RBR, digest-width,
concrete-hash, canonical-wire, and refinement premises. The unfrozen binary
macro projection is retained only as non-authoritative arithmetic. No
architecture winner, strict security claim, proof-byte claim, retained proof,
parser authority, verifier refinement, or production route exists.

The canonical checker passed with every local primary PDF and pinned libiop
source present. The 21 dependency-free tests passed, including authority,
proof-byte, RBR, and binary-relation fail-open mutations. `git diff --check`
passed and this directory contains no bytecode cache.

## Context and Orientation

The prospective source relation is described by
`.agent/hardening/hx512-semantic-suite/`. Its all-W64 BLAKE2b-512 schedule
contains the full 2-input/2-output, all-mask, stablecoin, authorization, and
manifest/state surface, but its current geometry is a source projection rather
than a characteristic-two compiled matrix.

Aurora ePrint 2018/828 defines an IOP for R1CS over binary extension fields.
Theorem 9.2 uses nested padded subspaces `H1,H2`, a disjoint affine subspace
`L`, perfect zero knowledge against `b` oracle queries, and FRI. CMS19 ePrint
2019/834 provides a modified BCS QROM theorem only when the entire IOP has
round-by-round soundness. The pinned libiop commit is implementation evidence,
not theorem or production authority.

## Plan of Work

Create `aurora_pq128_screen.py` to build a deterministic certificate. Record
the exact theorem expressions as strings and exact rational screens only when
all inputs are known. Distinguish the complete-Iop oracle length `p` from the
compressed BCS wire. Include the binary relation mapping status, public-input
padding, matrix geometry or explicit nulls, field-width and FRI parameters,
modified BCS digest width, physical semantic and proof hash calls, every
composition category, and all authority gates.

Create `check_screen.py` as the fail-closed entrypoint. It must regenerate the
certificate, validate local repo source pins, optionally verify the inspected
primary PDFs and pinned raw libiop files, reject any authority promotion, and
reject every non-null proof artifact field.

Create `test_aurora_pq128_screen.py` with exact theorem-expression,
zero-knowledge, RBR-premise, binary-mapping, implementation-wire,
composition-category, comparator, source-pin, canonical-readback, and
fail-open mutation tests.

Write `REPORT.md` with a concise source-grounded verdict. It must label the
Theorem 9.2 oracle-length equation as an uninstantiated core expression and
historical Aurora sizes as non-comparable.

## Concrete Steps

From `/Users/pldd/Projects/Reflexivity/Hegemon`, run only dependency-free
commands:

    PYTHONDONTWRITEBYTECODE=1 python3 -B .agent/hardening/aurora-pq128-screen/aurora_pq128_screen.py --write
    PYTHONDONTWRITEBYTECODE=1 python3 -B .agent/hardening/aurora-pq128-screen/check_screen.py --require-local-sources
    PYTHONDONTWRITEBYTECODE=1 python3 -B -m unittest discover -s .agent/hardening/aurora-pq128-screen -p 'test_*.py' -v
    git diff --check -- .agent/hardening/aurora-pq128-screen

Do not run Cargo, CMake, libiop, a proof generator, or an expanded-matrix
materializer.

## Validation and Acceptance

Acceptance for this screen requires a canonical certificate, matching source
hashes, passing dependency-free tests, exact theorem expressions, explicit
whole-Aurora RBR failure, exact or null binary relation geometry, all six
composition categories, and fail-closed authority. `proof_bytes`, proof-byte
bounds, and retained proof artifact must remain null.

Architecture or production acceptance is outside this lane. It would require
an exact characteristic-two relation/refinement, a complete-Iop RBR theorem,
fully instantiated proven FRI parameters, a concrete conventional-hash QROM
bridge, a canonical parser and wire, a retained same-relation proof, mutation
and restart verification, verifier refinement, and consensus lifecycle
binding.

## Idempotence and Recovery

Generation is deterministic and overwrites only the generated certificate in
this directory. The checker computes expected bytes in memory before comparing
them. A source-pin mismatch fails before writing. No cleanup, checkout, reset,
network fetch, registry edit, or route activation is permitted.

## Artifacts and Notes

The retained package will contain this ExecPlan, `REPORT.md`, the generator,
checker, tests, and canonical `certificate.json`. The final handoff records
their SHA-512 hashes and verification results.

## Interfaces and Dependencies

The scripts use only Python's standard library. Repo dependencies are read-only
JSON/source artifacts pinned by SHA-512. Primary PDFs and raw pinned libiop
files live under `/private/tmp` and are optional for a portable default check,
but are mandatory in the source-verification run used to freeze this package.
