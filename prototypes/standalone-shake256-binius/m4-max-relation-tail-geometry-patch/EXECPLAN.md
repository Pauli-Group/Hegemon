# Make the maximum M4 relation leave a guaranteed n15 random tail

This ExecPlan is a living document maintained under `.agent/PLANS.md`. It is
self-contained for the isolated source-static optimization in this directory.

## Purpose / Big Picture

The maximum 83-Keccak M4 relation previously had only 100 guaranteed unused
B128 symbols in an n15 oracle under its conservative source bound. The random
padding construction needs 1,060 symbols in its conditional screen and 1,984
in its larger screen. This work makes redundant source computations explicit
without changing the scalar relation, so the conservative lower bound on the
unused tail exceeds both existing requirements before a disk-heavy compile.

## Progress

- [x] (2026-08-21) Read `DESIGN.md`, `METHODS.md`, `.agent/PLANS.md`, the
  maximum source, and the pinned builder, zero-fold, CSE, fusion, byte-swap,
  and Keccak sources.
- [x] (2026-08-21) Derived three scalar-equivalent source rewrites and exact
  gate-output reductions.
- [x] (2026-08-21) Added a source-pinned isolated patch; the live relation was
  not edited.
- [x] (2026-08-21) Added and ran an allocation-free differential/static
  certificate.
- [x] (2026-08-21) Applied the patch to a temporary copy and parsed it with
  `rustfmt`; removed the temporary copy afterward.
- [ ] Compile the patched circuit and freeze exact `n_hidden_words` only after
  the repository's 28-GiB disk admission gate opens.

## Surprises & Discoveries

- Observation: public decode was almost an identity round-trip. It extracted
  all 853 bytes, but only seven individual flag bytes were needed; eleven
  digests and nine integers were immediately packed again.
  Evidence: the frozen source counter assigns 3,074 attempted outputs to
  decode. Direct word reads plus seven byte reads require 366.
- Observation: source-static explicit reuse matters even though pinned CSE is
  enabled. The conservative upper bound intentionally credited no uncompiled
  CSE, so writing the two reuse identities once removes 1,248 outputs from the
  upper bound.
- Observation: the old full-profile requirement fits by only 49 B128 symbols.
  Any additional real FRI/proximity observations can consume this margin.

## Decision Log

- Decision: preserve all 83 Keccak calls and every assertion; optimize only
  representation and duplicated derived wires.
  Rationale: the task forbids narrowing the scalar relation or reward-hacking
  the proof schedule.
  Date/Author: 2026-08-21, Codex.
- Decision: ship an isolated patch rather than edit the live maximum source.
  Rationale: exact compilation is blocked by disk admission and the user asked
  for a separately auditable copy/patch.
  Date/Author: 2026-08-21, Codex.
- Decision: count the 86 removed leading-zero XOR folds against the raw source
  saving.
  Rationale: otherwise the claimed conservative upper reduction would double
  count folds already credited by the baseline audit.
  Date/Author: 2026-08-21, Codex.

## Outcomes & Retrospective

The isolated patch reduces the conservative source-static upper from 65,336
to 61,469 hidden words, a net guaranteed cut of 3,867. This gives at most
30,735 active B128 symbols and at least 2,033 unused n15 symbols. It therefore
covers the existing 1,060- and 1,984-symbol screens with margins of 973 and 49.
It does not freeze a compiled count or establish a PCS, ZK, or security claim.

## Context and Orientation

The live source is
`prototypes/standalone-shake256-binius/m4-full-production-prototype/src/lib.rs`.
It declares 114 verifier-owned words and 671 witness words, then builds one M4
main circuit containing 83 Keccak-f permutations. The baseline allocation-free
audit is
`.agent/hardening/binius-pq128-proof-size/max-relation-geometry/static_geometry.py`.
An “attempted output” is a Rust builder operation that creates an internal
wire before compiler fusion or CSE. Counting all such outputs gives a safe
source-static upper, provided already credited immediate folds are subtracted
exactly once.

## Plan of Work

Keep the live source untouched. Apply
`hegemon-m4-max-tail-geometry-67e7f6ac.patch` only to an exact pinned copy. The
patch replaces byte extract/repack public decoding with direct unaligned word
loads, shares Merkle deltas, and returns normalized balance values/selectors
from note validation for later reuse. Maintain
`check_tail_geometry_patch.py` as the executable certificate for source pins,
patch shape, scalar identities, and upper-bound arithmetic.

## Concrete Steps

From the repository root, run:

    git apply --check prototypes/standalone-shake256-binius/m4-max-relation-tail-geometry-patch/hegemon-m4-max-tail-geometry-67e7f6ac.patch
    PYTHONDONTWRITEBYTECODE=1 python3 prototypes/standalone-shake256-binius/m4-max-relation-tail-geometry-patch/check_tail_geometry_patch.py --pretty

The first command emits nothing and exits zero. The second reports a 61,469
hidden-word upper and 2,033-symbol tail lower. It creates no Python bytecode.

When disk admission is at least 28 GiB, apply the patch in an isolated worktree,
compile the circuit, run the maximum scalar/M4 differential suite, and record
the exact hidden-word and constraint statistics. Do not promote the static row.

## Validation and Acceptance

Acceptance for this source-static milestone requires: exact source/upstream
pins; `git apply --check` success; deterministic public-decode, constant-range,
Merkle, and balance-cache differential checks; exact accounting of the 86
removed baseline folds; a net cut of at least 3,768 hidden words so the
1,984-symbol tail fits; and explicit false compiled/frontier flags. The current
certificate passes all of these with a 3,867-word cut.

## Idempotence and Recovery

The checker is read-only and idempotent. It refuses source or upstream drift.
If the patch stops applying, regenerate and re-audit it against the changed
source rather than bypassing a pin. Temporary parse copies must use a unique
directory under `/private/tmp` and be deleted by exact path.

## Artifacts and Notes

The decisive accounting is:

    direct public decode and transport attempted-output cut   2,705
    shared Merkle deltas                                        896
    reused balance byte swaps                                   352
    raw attempted-output cut                                  3,953
    removed baseline leading-zero folds                         -86
    net conservative hidden-word cut                          3,867

## Interfaces and Dependencies

The patch adds only private helpers and the private `BalanceNote` carrier. It
does not alter a public Rust API, serialization grammar, witness layout,
statement width, Keccak schedule, or backend profile. Its only dependencies are
the already pinned M4 frontend and byte/Keccak gadgets.

Revision note (2026-08-21): created the complete isolated optimization plan and
recorded the verified source-static outcome; compiled validation remains gated.
