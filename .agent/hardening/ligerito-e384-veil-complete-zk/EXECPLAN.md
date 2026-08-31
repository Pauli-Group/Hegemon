# Establish or reject a VEIL complete-ZK wrapper for one-level Ligerito

This ExecPlan is a living document. The sections `Progress`, `Surprises &
Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to
date as work proceeds. Maintain it in accordance with `.agent/PLANS.md`.

## Purpose / Big Picture

Hegemon needs a self-contained transaction proof whose verifier learns nothing
about the witness beyond the public statement. The one-level Ligerito screen
currently exposes a full folded residual vector and raw Reed--Solomon row
values. This plan determines whether the VEIL compiler from ePrint 2026/683 can
hide that exact view in the mixed `B128`/`E384` backend, and specifies the
source changes required if it cannot. A reader can observe the present outcome
by running the dependency-free checker and seeing the fail-closed status plus
the exact rank counterexample.

## Progress

- [x] (2026-08-22 10:05Z) Pinned the exact one-level Ligerito proof model and
  enumerated every serialized witness-dependent observation.
- [x] (2026-08-22 10:15Z) Audited the existing character-two HVZK sumcheck,
  random-tail, coefficient-mask, grouped-relation, Libra, and compact
  multiproof patches against that surface.
- [x] (2026-08-22 10:25Z) Read the staged primary VEIL paper and published
  `slop-veil 6.4.0` source without importing or building either artifact.
- [x] (2026-08-22 10:35Z) Derived an executable rank-three versus rank-one
  counterexample and a query-padding Vandermonde necessity test.
- [x] (2026-08-22 10:48Z) Added the fail-closed checker, source pins, provenance
  checks, conservative geometry ledger, mutation tests, and audit report.
- [ ] Extract the real maximum M4 interactive verifier as a typed MIOP. This is
  intentionally unstarted because the current source does not expose the
  needed observation functionals or full relation geometry.
- [ ] Implement and prove a binary/additive zk-Ligerito MCS and whole-view
  simulator. This must remain unstarted until the MIOP extraction fixes the
  field, query, code, and acceptance interfaces.
- [ ] Compose the resulting interactive simulator with SHA-512/SHAKE
  Fiat--Shamir in the QROM and measure the canonical wire. No capability flag
  may change before this item is complete.

## Surprises & Discoveries

- Observation: The current Hegemon masks fail before any cryptographic hiding
  argument is needed.
  Evidence: for the executable `E384/B128` block,
  `rank(O G_r)=1` and `rank([O G_r|O G_w])=3`; a left-null functional gives
  conditional total variation one.

- Observation: Compact authentication does not reduce the privacy obligation.
  Evidence: the pinned prototype serializes the complete `terminal` vector and
  every selected `opened_rows` value unchanged; the compact frontier only
  authenticates them.

- Observation: The published crate has generic PCS trait names but only one
  concrete context.
  Evidence: the source contains exactly one `impl ZkIopCtx for`, for
  `KoalaBearDegree4Duplex`; the proof type contains `BasefoldProof`, and the
  crate directly depends on both BaseFold crates.

- Observation: The source has privacy bad values that are not conditioned out.
  Evidence: comments require an RLC coefficient different from zero and minus
  one, while the prover samples it directly; the random mask row is multiplied
  by an unrestricted batching-challenge power.

- Observation: The paper's 12-percent experimental result is not portable.
  Evidence: the experiment uses a 31-bit prime field, degree-four extension,
  BaseFold, Poseidon2, and a 100-bit target, none of which matches the Hegemon
  binary fields, Ligerito screen, conventional hashes, or PQ128/QROM goal.

## Decision Log

- Decision: Reject wrapping the already serialized one-level proof.
  Rationale: VEIL compiles an underlying interactive MIOP and replaces its
  oracle commitment/opening layer. It does not establish zero knowledge for an
  arbitrary noninteractive byte string containing supplemental hash checks.
  Date/Author: 2026-08-22 / Codex.

- Decision: Treat three full `B128` random columns as only a local sufficient
  rank repair, not a complete-ZK result.
  Rationale: they span one `E384` observation only when their mixing
  coefficient is nonzero; the full adaptive transcript, direct messages,
  commitments, and abort behavior remain unsimulated.
  Date/Author: 2026-08-22 / Codex.

- Decision: Do not substitute Hegemon's PCS through the published generic
  traits.
  Rationale: the concrete implementation depends on multiplicative two-adic
  domains and BaseFold. `GF(2^128)` has no positive power-of-two multiplicative
  subgroup, so an additive-code implementation and new proof are required.
  Date/Author: 2026-08-22 / Codex.

- Decision: Report only a direct source-structure byte floor and the paper's
  symbolic formula.
  Rationale: the full M4 constraint geometry, changed distance/query count,
  circuit-evaluation proof, authentication delta, and QROM parameters are
  unknown. A numeric total would be false precision.
  Date/Author: 2026-08-22 / Codex.

- Decision: Keep `complete_zk`, `strict_pq128`, `frontier_eligible`, and
  `production_authorized` false.
  Rationale: the checker proves a no-go for current masks and does not implement
  a new protocol or whole-view simulator.
  Date/Author: 2026-08-22 / Codex.

## Outcomes & Retrospective

The bounded audit achieved a source-pinned negative result. It identifies a
concrete rank leak in the current view, distinguishes the abstract VEIL theorem
from its experimental BaseFold crate, shows why the generic PCS facade cannot
host the current binary stack, and gives a conservative byte floor. Nine
dependency-free tests include authority and rank mutations. The intended user
outcome, a complete-ZK production proof, remains unavailable; the smallest
honest next unit is an explicit interactive M4 MIOP export, not another mask
receipt around the existing proof bytes.

## Context and Orientation

`B128` denotes the 128-bit binary base field. `E384` denotes a degree-three
extension of that field, so one `E384` value has three independent `B128`
coordinates. An MIOP, or multilinear interactive oracle proof, is an
interactive public-coin protocol whose prover messages are field values or
multilinear-polynomial oracles and whose verifier accepts using polynomial
conditions. A whole-view simulator is an algorithm that, from the public
statement and verifier randomness alone, produces the same distribution as
every field message, oracle opening, commitment, authentication path, and abort
event seen by the verifier.

The one-level model is implemented in
`.agent/hardening/binius-pq128-proof-size/strict_refold_pcs_prototype.py` and
parameterized in `strict_refold_pcs_model.py`. The current masking components
live under `prototypes/standalone-shake256-binius/char2-hvzk-sumcheck-kernel/`
and the adjacent `m4-zk-*`, random-tail, and compact-multiproof patch folders.
The staged primary paper is `/private/tmp/veil-2026-683.txt`. The staged crate
source is `/private/tmp/slop-veil-6.4.0.kJf1od/slop-veil-6.4.0`.

The retained audit is entirely under
`.agent/hardening/ligerito-e384-veil-complete-zk/`. The Python checker performs
binary-field linear algebra, derives geometry, pins primary/local sources, and
refuses every authority claim. Its tests deliberately mutate authority and
rank facts to demonstrate fail-closed behavior.

## Plan of Work

First, preserve the negative certificate and use it as the admission gate for
future work. Any change to the one-level prototype, existing mask patches,
paper extraction, or staged crate files must rotate the corresponding source
pin and re-run the entire audit. Source drift is a review event, not an
automatic pin update.

Next, add a new module beside the real M4 prover that exports the interactive
protocol before Fiat--Shamir. Each prover field message must carry its exact
linear or polynomial dependence on the witness and random masks. Each oracle
must declare one field, dimensions, evaluation query, and commitment identity.
The verifier must expose only fixed-format random coins and polynomial
acceptance checks. Supplemental SHAKE, parsing, and authentication logic must
either be proven public and witness-independent or arithmetized into the
declared acceptance predicate.

Then implement a fresh binary/additive zk-Ligerito MCS. Pad every data column
with at least the maximum base query count in independent `B128` values and add
three full independent `B128` mask columns. Sample the mask-column coefficient
from a nonzero domain without selective failure. Export actual query sets and
observation matrices after challenges so the rank equality can be checked for
every admitted branch. Prove code projection rank, distance, proximity
generator soundness, binding, and IOPP strength at the chosen geometry.

Finally, mask every exposed field message independently and prove the complete
arithmetic verifier predicate with a simulator-backed circuit-evaluation
scheme. Compose the PCS and direct-message simulators, including abort/retry,
Fiat--Shamir, Merkle, parser, hash-domain, grinding, and union terms in the
QROM. Only after that composition passes at 128 bits should the canonical proof
be serialized, measured, mutation-tested, restart-tested, and considered for
production admission.

## Concrete Steps

Run all commands from `/Users/pldd/Projects/Reflexivity/Hegemon`. Under the disk
stop, disable Python bytecode and do not run Cargo, Lake, rustc, or proof builds.

Run the source and certificate checker:

    PYTHONDONTWRITEBYTECODE=1 python3 \
      .agent/hardening/ligerito-e384-veil-complete-zk/ligerito_veil_audit.py

The expected compact output includes:

    "status": "REJECT_CURRENT_TRANSCRIPT_SOURCE_FAITHFUL_PORT_REQUIRED"
    "current_mask_rank": 1
    "current_joined_rank": 3
    "source_checks_passed": true
    "complete_zk": false
    "production_authorized": false

Run the mutation and geometry tests:

    PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover \
      -s .agent/hardening/ligerito-e384-veil-complete-zk \
      -p 'test_*.py' -v

Expect nine tests and `OK`. Then inspect whitespace without changing unrelated
files:

    git diff --check -- \
      .agent/hardening/ligerito-e384-veil-complete-zk

## Validation and Acceptance

The bounded audit is accepted when the checker reports no source failures,
rank one versus rank three, and all authority flags false; all nine tests pass;
mutating `complete_zk` to true is rejected; mutating the current mask rank is
rejected; and `git diff --check` has no output. It is a failure if the checker
claims that local three-coordinate closure proves the whole protocol, accepts
source drift, treats the generic trait as a binary PCS implementation, imports
the staged crate, or reports a numeric complete-VEIL proof size.

The future implementation is accepted only when a verifier-view simulator can
be executed using no witness, its output distribution/refinement theorem covers
the exact serialized proof, the composed QROM bound is at least 128 bits, and a
fresh node verifies the unchanged self-contained artifact without sidecars or
caches.

## Idempotence and Recovery

All current commands are read-only and idempotent. They create no bytecode when
the environment variable is set. If a source pin fails, inspect the exact diff
and redo the mathematical audit before changing the pin. Do not overwrite or
clean shared worktree changes. If staged paper or crate source disappears,
retain the negative result but report the missing primary-source evidence; do
not replace it with an unpinned download under the disk stop.

## Artifacts and Notes

The direct source-structure payload floor for degree-three `E384/B128` masking
is `96q + 192` bytes before new constraint proofs, authentication, framing, or
parameter changes. It is 3,840 bytes at `q=38` and 6,048 bytes at `q=61`.
These are lower bounds, not complete proof sizes.

The paper's full symbolic inventory, evaluated at Hegemon widths only after all
parameters exist, charges 64 bytes per digest and 48 bytes per extension-field
value. The public paper experiment cannot supply those parameters because it
uses a different field, PCS, hash, and security target.

## Interfaces and Dependencies

The current audit depends only on Python's standard library. It exposes these
stable functions in `ligerito_veil_audit.py`:

    ligerito_prefix_rank_counterexample() -> dict[str, object]
    query_padding_rank_example() -> dict[str, object]
    source_geometry(log_relation_size, fold_variables, query_count) -> dict[str, int]
    paper_symbolic_overhead_bytes(...) -> dict[str, int]
    build_certificate() -> dict[str, object]
    validate_certificate(certificate) -> list[str]
    source_checks(paper, slop_root) -> list[str]

The future production implementation must not reuse the concrete
`ZkBasefoldProver` merely through `ZkPcsProver`. It needs a new additive
binary-field PCS interface whose proof, verifier, simulator, code parameters,
query schedule, and serializer are all explicit and independently testable.

Revision note (2026-08-22): Created the plan after the bounded source audit so
that the negative evidence, exact blockers, validation commands, and smallest
source-faithful continuation survive task handoff without relying on chat
history.

