# Build and audit the random-padding PCS / one-round FRI seam

This ExecPlan is a living document maintained in accordance with
`.agent/PLANS.md`. The sections `Progress`, `Surprises & Discoveries`,
`Decision Log`, and `Outcomes & Retrospective` must remain current as work
continues. It is intentionally isolated to
`prototypes/standalone-shake256-binius/m4-random-padding-zk-pcs-fri/`; shared
design, methods, consensus, ledger, and frontier files are out of scope.

## Purpose / Big Picture

The preceding random-high-coefficient analysis supplied a fixed-matrix lemma
and a first-level byte screen but no proof that could be encoded, committed,
opened, parsed, and verified. After this milestone, a developer can run one
small dependency-free implementation that performs those operations over the
actual B128 and E256 fields. The executable verifier fully reveals small tables
so its degree and fold checks are honest. A separate n15 model then shows how
much one concrete later commitment layer adds to the old 63,320/116,952 screens
without pretending that query-only openings constitute a complete FRI.

## Progress

- [x] (2026-08-21 21:05Z) Read `DESIGN.md`, `METHODS.md`, `.agent/PLANS.md`, the precursor random-padding audit, and the pinned E256 arithmetic seam.
- [x] (2026-08-21 21:18Z) Implemented pinned B128 arithmetic, true `GhashSq256b` E256 arithmetic, nonzero affine-domain encoding, interpolation, and adjacent-coefficient folding.
- [x] (2026-08-21 21:31Z) Implemented four-symbol salted leaves, three Merkle commitments, canonical multiproofs, root-derived schedules, two E256 transcripts, exact serialization, and exact parsing.
- [x] (2026-08-21 21:40Z) Implemented exhaustive small-n degree/fold/terminal verification and exported every base-point, fold-coordinate, and terminal-coordinate observation row.
- [x] (2026-08-21 21:48Z) Added exact B128 Gaussian rank audit and mutation, truncation, trailing, root, query, zero-domain, noncanonical-count, claim, and reused-pad negatives.
- [x] (2026-08-21 22:00Z) Corrected strict proof/root/Fiat--Shamir digests from the precursor's non-strict 56-byte width to 64-byte SHAKE256 output; added separate 32-byte-unproved and 148-byte theorem-scoped salt rows.
- [x] (2026-08-21 22:05Z) Froze the n15 serializer-topology rows and documented the missing proximity terms. No production allocation or Cargo invocation was performed.
- [x] (2026-08-21 22:18Z) Added the authenticated single-combined-fold-tree best case, rejected terminal-value elision, and charged all 15 degree-halving rounds as a structural floor.
- [ ] Replace exhaustive revelation with a reviewed succinct binary-field proximity protocol and export its complete production observation matrix. This requires new protocol work and is not supplied by this milestone.
- [ ] Integrate adaptive BCS zero knowledge, the theorem-scoped salt requirement, two-E256 product soundness, extraction, and composed PQ128/QROM security. Every corresponding authority flag remains false.

## Surprises & Discoveries

- Observation: a real first coefficient-fold layer needs three trees, not the single tree charged by the source-only screen.
  Evidence: the shared B128 codeword has one root, and each branch-specific E256 fold has a different beta and therefore a different folded codeword/root.
- Observation: one E256 fold does not reduce B128 commitment storage at a fixed rate.
  Evidence: halving the coefficient count and then encoding two B128 coordinates per E256 evaluation leaves exactly 1,048,576 B128 symbols at n15/rate-1/32 in each folded tree.
- Observation: strict digest width alone materially changes the screen.
  Evidence: with 64-byte roots/frontiers, the q33 one-round 32-byte-salt topology is 118,192 bytes rather than the earlier 105,000-byte 56-byte calculation.
- Observation: the executable full observation matrix is far from hidden.
  Evidence: the fixture has 104 serialized B128 rows, padding rank 4, and joint rank 8; row count is not used as a substitute for Gaussian rank.
- Observation: the exhaustive verifier is honest but cannot be a compactness strategy.
  Evidence: n15/rate-1/32 full revelation is 75,497,904 bytes at 32-byte salts and 166,724,016 bytes at 148-byte salts.
- Observation: combining both branch folds helps only if their folded query indices overlap.
  Evidence: with a shared 33-index fold schedule the combined tree is 89,744 bytes, 28,448 below the separate-tree topology; its product-soundness gate remains false.
- Observation: one fold cannot finish the proximity argument.
  Evidence: n15 needs 15 coefficient halvings, and the authenticated combined-tree structural floor alone is 325,424 bytes at 32-byte salts.

## Decision Log

- Decision: fully reveal all three tables in the executable toy.
  Rationale: complete interpolation gives an honest degree and fold check without claiming an unimplemented succinct FRI theorem.
  Date/Author: 2026-08-21 / Codex.
- Decision: commit one folded E256 table per branch as B128 coordinate lanes.
  Rationale: the branches use distinct true-field beta challenges, while every Merkle leaf retains exactly four B128 symbols.
  Date/Author: 2026-08-21 / Codex.
- Decision: derive proof indices from all roots and the external public context and omit indices from the wire.
  Rationale: the verifier can reconstruct one canonical opening order and reject query or root drift without an index alias.
  Date/Author: 2026-08-21 / Codex.
- Decision: use 64-byte SHAKE256 proof digests and list 56 bytes only as a rejected negative control.
  Rationale: 56-byte semantic hashes are not the strict proof commitment/Fiat--Shamir profile.
  Date/Author: 2026-08-21 / Codex.
- Decision: keep the executable salt at the requested 32 bytes but price 148 bytes separately.
  Rationale: 32 bytes has no integrated direct BCS/QROM theorem; 148 bytes is the theorem-scoped n18 input, and neither is authority until the theorem is composed.
  Date/Author: 2026-08-21 / Codex.
- Decision: refuse low-degree authority for a partial opening.
  Rationale: membership in committed leaves does not prove proximity to a low-degree codeword.
  Date/Author: 2026-08-21 / Codex.
- Decision: credit no verifier-known terminal-value elision.
  Rationale: both E256 terminal values in this seam are witness-dependent; removing them would delete a binding observation rather than reconstruct a public value.
  Date/Author: 2026-08-21 / Codex.
- Decision: screen a single combined branch-fold tree with shared q33 indices.
  Rationale: it preserves one authenticated commitment to both fixed lane pairs and gives the maximum structural saving, while its missing branch-product theorem stays explicit.
  Date/Author: 2026-08-21 / Codex.

## Outcomes & Retrospective

The milestone creates a real small-n proof wire rather than another formula.
The 2,736-byte fixture exact-decodes, verifies three SHAKE256-512 commitments,
interpolates the base and both E256 coordinate codewords, checks each fold and
terminal, and exports 104 rows whose values reproduce every serialized linear
observation. Twenty-three adversarial tests pass.

The main architecture result is negative but useful. Instantiating only one
later branch-specific fold layer raises the q33 topology to 118,192 bytes with
unproved 32-byte salts or 133,504 bytes with theorem-scoped 148-byte salts. The
q66 forms are 219,056 and 249,680 bytes. These totals still omit the relation
PIOP and later FRI rounds, so the old 63,320/116,952 records cannot be treated
as complete proof sizes. The prototype does not move the production frontier.

The maximum honest packing screen is 89,744 bytes: one combined tree commits
both E256 branch folds and authenticates a fully shared 33-index fold query
set. It saves 28,448 bytes from 118,192, with no terminal elision. Completing
all 15 coefficient halvings has a 325,424-byte 32-byte-salt structural floor
(387,427 bytes with exact per-tree theorem-scoped salts) before the omitted protocol/security
terms. Thus the combined layout is useful locally but does not rescue the cap.

## Context and Orientation

`random_padding_fri.py` is the implementation and report generator.
`test_random_padding_fri.py` is its adversarial suite. `README.md` explains the
wire and authority boundary. All files use only the Python standard library.

B128 is the binary field defined by `X^128 + X^7 + X^2 + X + 1`; elements are
16-byte little-endian polynomial-basis words. E256 is the true quadratic
extension `B128[Y]/(Y^2 + X*Y + X)`; it is serialized as two B128 coordinates.
A Reed--Solomon codeword here is the vector of one polynomial evaluated at all
points of a fixed nonzero affine coset. A Merkle frontier is the minimal set of
sibling hashes needed to reconstruct one root from a canonical opened-leaf
set. FRI means a protocol that proves proximity to low degree through recursive
folding. This prototype implements one fold and verifies it by exhaustive
revelation; its query-only production model is not a FRI proof.

The n15 byte model uses 32,768 message coefficients and rate `1/32`, hence
1,048,576 B128 symbols and 262,144 leaves in each of three trees. It calculates
counts only and never constructs those arrays.

## Plan of Work

Keep arithmetic, commitment, parser, verifier, matrix export, rank audit, and
topology reporting together in `random_padding_fri.py` so the small seam can be
audited without dependency indirection. Maintain exact domain separation for
leaf, node, E256 challenge, query, and schedule-digest requests. Keep the proof
grammar fixed-width except for the three count-derived opening sections.

The exhaustive verifier must continue to require every leaf in canonical order
before it interpolates. A partial proof may pass `verify_membership`, but
`verify` must reject it as an unauthorized low-degree proof. When a succinct
replacement is attempted, add its commitments and every opened value to the
same exported observation matrix before any rank or ZK claim is considered.

The production report must show both salt widths and keep every authority gate
false. Do not allocate n15 tables, run Cargo, edit shared architecture files,
or mutate the sealed ledger/frontier from this directory.

## Concrete Steps

Work from `/Users/pldd/Projects/Reflexivity/Hegemon`. Run:

    PYTHONDONTWRITEBYTECODE=1 python3 \
      prototypes/standalone-shake256-binius/m4-random-padding-zk-pcs-fri/random_padding_fri.py \
      --check --report

Expect the first line:

    RANDOM_PADDING_FRI_CHECK_PASS

Run the adversarial suite:

    PYTHONDONTWRITEBYTECODE=1 python3 -m unittest -v \
      prototypes/standalone-shake256-binius/m4-random-padding-zk-pcs-fri/test_random_padding_fri.py

Expect `Ran 25 tests` followed by `OK`. Finally run:

    git diff --check -- \
      prototypes/standalone-shake256-binius/m4-random-padding-zk-pcs-fri

It must produce no output.

## Validation and Acceptance

Acceptance is source-only. The CLI must print its pass marker and a JSON report
whose production gates are all false. The exhaustive fixture must verify at
exactly 2,736 bytes. A partial canonical multiproof must verify membership but
must be rejected as a low-degree proof. Mutation, truncation, trailing bytes,
root drift, query drift, zero-domain selection, bad counts, and claim drift
must reject. The matrix test must reproduce every opened base/fold value and
terminal coordinate from the exported rows, then compute padding rank 4 and
joint rank 8. The n15 model must report 118,192/219,056 bytes at 32-byte salts
and 133,504/249,680 bytes at 148-byte salts.
The combined-fold best case must be 89,744 bytes with zero credited terminal
elision, and the 15-round structural floor must be 325,424 bytes.

No proof artifact, security theorem, production parser, or frontier promotion
is an acceptance criterion.

## Idempotence and Recovery

The validation commands only read source and use in-memory toy arrays. Setting
`PYTHONDONTWRITEBYTECODE=1` prevents cache writes. They are safe to rerun. If a
test fails, edit only this directory and rerun the commands; do not delete a
shared target directory or use Cargo. No production codeword is ever created.

## Artifacts and Notes

The frozen evidence transcript is:

    RANDOM_PADDING_FRI_CHECK_PASS
    Ran 25 tests in under one second
    OK

The serializer identity is:

    fixed = 48 + 3*64 + 64 + 4*32 = 432 bytes
    opened leaf = 4*16 + salt_bytes
    frontier node = 64 bytes

At q33, the three-tree schedule opens 66 base leaves and 33 leaves in each
folded tree, with frontiers 788 and 427/427. At q66 it opens 132 and 66/66,
with frontiers 1,444 and 788/788.

## Interfaces and Dependencies

The stable public interfaces in `random_padding_fri.py` are `encode`,
`commit`, `open_commitment`, `prove`, `parse_proof`, `verify_membership`, `verify`,
`export_observation_matrix`, `audit_observation_matrix`,
`reused_padding_fixed_view_delta`, `ProductionTopology`,
`production_topologies`, `combined_fold_tree_best_case`,
`all_rounds_structural_floor`, and `report`. The module depends only on `argparse`,
`functools`, `hashlib`, `json`, `math`, `secrets`, `struct`, `dataclasses`, and `typing`
from the Python standard library.

Revision note: completed the honest exhaustive toy, full-row export, strict
64-byte digest correction, salt-scope split, and n15 topology audit on
2026-08-21. Succinct FRI and all security composition remain open.
