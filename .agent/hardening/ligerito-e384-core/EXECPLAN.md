# Ship or falsify the exact one-level E384 Ligerito opening core

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`,
`Decision Log`, and `Outcomes & Retrospective` must be kept current as the work proceeds.

This plan follows `.agent/PLANS.md`. It is intentionally bounded to the authenticated
opening layer. It does not allocate a Hegemon identity, duplicate the M4 relation compiler,
or authorize any production route.

## Purpose / Big Picture

The repository has a compact mixed-field proof-size model and a toy executable called a
"Johnson-Ligerito" core. That object uses SHAKE256, derives its own evaluation claim, and
does not expose the interactive protocol surface required by a complete-zero-knowledge
compiler. The purpose of this work is to replace that ambiguous evidence with one exact,
source-complete implementation of the base case in Section 5 of the Ligerito paper:
encode the columns of a `B128` matrix, commit to encoded rows with SHA-512, partially
sumcheck a public inner product over `E384`, send the terminal partial evaluation, and
authenticate distinct sampled rows. A reader can inspect a canonical parser, exact wire
ledger, mutation tests, and the precise interactive view that a future VEIL-like wrapper
would have to hide.

Success for this bounded plan means the core source and adversarial tests exist and all
production/privacy flags remain false. It does not mean that the full Hegemon relation has
been compiled, that the Flock/Johnson list-decoding extension has been proved for this
mixed-field code, that complete zero knowledge exists, or that Fiat--Shamir is secure in
the QROM.

## Progress

- [x] (2026-08-22) Read `AGENTS.md`, `DESIGN.md`, `METHODS.md`, `README.md`,
  `.agent/PLANS.md`, and the living SmallWood production ExecPlan before editing.
- [x] (2026-08-22) Audited the existing strict-refold size model/prototype and the staged
  primary Ligerito, TensorSwitch, and VEIL sources without compiling or importing code.
- [x] (2026-08-22) Coordinated the complete-ZK boundary with
  `/root/smallwood_complete_zk`; recorded its typed MIOP, rank, simulator, and nonzero-mask
  requirements.
- [x] (2026-08-22) Implemented the exact one-level `B128`/`E384` prover,
  interactive fixed-coin verifier, SHA-512 Merkle commitment, Fiat--Shamir wrapper,
  canonical parser, and byte/resource ledger in the owned path.
- [x] (2026-08-22) Added the stateful pre-Fiat--Shamir prover, typed interactive view,
  exact raw observation-row exports, and a fail-closed complete-ZK wrapper contract.
- [x] (2026-08-22) Added deterministic tiny vectors and adversarial mutation tests. Per
  the delegated source-only constraint, their source was AST-checked but no proof/test was
  executed.
- [x] (2026-08-22) Retained `source_screen.json`, ran the formula-only checker, documented
  the quantitative comparator and disqualifiers in the owned `README.md`, and sent the exact
  metrics/wording to the root agent for shared-document integration.

## Surprises & Discoveries

- Observation: the existing `strict_refold_pcs_prototype.py` is algebraically close to the
  Section 5 base case, but its public functional is internally derived after commitment and
  its transcript/Merkle primitive is SHAKE256 rather than SHA-512.
  Evidence: `_new_transcript`, `_padding_augmented_basis`, `prove`, and `verify` in that
  prototype.

- Observation: the checked-in `q=68` result is not the soundness bound stated in the
  Ligerito paper. It imports the Flock/BCHKS Johnson-list-decoding screen. The source
  Ligerito unique-decoding term for Reed--Solomon is
  `((m-n-1)/(2m))^q + m*k'/|F| + 2*k'/|F|`.
  Evidence: equations (4) and (15) in `/private/tmp/ligerito.txt` and
  `johnson_query_count` in `strict_refold_pcs_model.py`.

- Observation: the TensorSwitch main PCS is not a one-level protocol. Lemma 8.3 assumes
  at least two iterations and commits multiple tensor-code oracles; labeling the Section 5
  Ligerito base case "TensorSwitch" would not be source-faithful.
  Evidence: Lemma 8.3 and Theorem 8.5 in `/private/tmp/tensorswitch-2025-2065.txt`.

- Observation: exposing raw authenticated rows and the terminal vector is exactly the
  non-ZK surface. The current global coefficient mask has rank one where witness
  differences have rank three over `B128`.
  Evidence: `.agent/hardening/ligerito-e384-veil-complete-zk/README.md` and its retained
  checker/certificate.

- Observation: the source-authoritative unique-decoding optimum under the stated `n=16`,
  264-bit source target, and 512-MiB oracle cap is not the old rate-`1/256`, `q=68`
  profile. The exact minimum is `p=5`, rate `1/2`, `q=132`, a 2-MiB oracle, and a
  208,400-byte fixed wire.
  Evidence: the dependency-free `--report` path and retained `source_screen.json`.

- Observation: removing the inherited 264-bit source convention does not reverse the core
  comparison. An optimistic 128-bit equation-(15)-only screen chooses `p=6`, rate `1/2`,
  `q=64`, and 136,048 bytes. This is still 17,978 bytes (15.23%) above the active-like
  SmallWood report and 11,980 bytes above the historical raw cap; the optimistic VEIL direct
  floor produces 142,384 bytes before its dominant missing wrapper.
  Evidence: `source_screen.json` and the formula-only source checker.

- Observation: the exact opening core alone is 90,330 bytes (76.51%) larger than the
  checked-in 118,070-byte active-like SmallWood report and 84,332 bytes above the historical
  124,068-byte raw cap. The VEIL direct-structure floor adds 12,864 bytes, for 221,264
  bytes before the missing constraint/simulator wrapper.
  Evidence: `README.md`, `source_screen.json`, and
  `docs/crypto/tx_proof_smallwood_backend_opening_surface_report.json:14`.

## Decision Log

- Decision: implement the paper's unique-decoding Section 5 protocol and keep the
  Johnson/Flock alternative out of the authoritative parameter calculation.
  Rationale: a source-complete core must not silently depend on a different list-decoding
  theorem whose mixed-field premises have not been refined.
  Date/Author: 2026-08-22 / Codex (`/root/ligerito_e384_core`).

- Decision: make the external statement contain an exact public `E384` functional and
  expected claim, while the proof carries and binds the same claim.
  Rationale: deriving a target from the committed witness proves only self-consistency. A
  PCS opening must bind a verifier-supplied claim.
  Date/Author: 2026-08-22 / Codex (`/root/ligerito_e384_core`).

- Decision: use full-output SHA-512 with length-delimited domain separation for the
  transcript, Merkle tree, profile, statement identifier, query sampling, and padding.
  Rationale: this is the conventional hash requested by the architecture tournament and
  removes the prototype's SHAKE naming ambiguity. It is not itself a QROM theorem.
  Date/Author: 2026-08-22 / Codex (`/root/ligerito_e384_core`).

- Decision: expose the interactive message/coin/query schedule and exact linear
  observation rows, but keep `complete_zk`, `strict_pq128`, `frontier_eligible`, and
  `production_authorized` false.
  Rationale: a wrapper can compose those rows with relation-specific witness and mask
  generators; this core cannot invent the missing generators, simulator, or QROM proof.
  Date/Author: 2026-08-22 / Codex (`/root/ligerito_e384_core`).

- Decision: record a fixed maximum-frontier grammar disadvantage, but not an absolute
  Ligerito no-go.
  Rationale: 208,400 bytes is already larger than the active-like SmallWood core report,
  yet neither route has a same-gate exact new-relation plus complete-ZK artifact. Comparing
  final sizes would require inventing unknown wrapper costs.
  Date/Author: 2026-08-22 / Codex (`/root/ligerito_e384_core`).

## Outcomes & Retrospective

The bounded outcome is a real source-complete authenticated opening kernel and a retained
formula/source certificate, not a production proof backend. The SHA-512/parser/Merkle wire,
stateful interactive schedule, fixed-coin verifier, exact observation operator, allocation gate,
and negative tests are now explicit in one owned path. AST parsing, the formula-only report,
the fail-closed source checker, `git diff --check`, and the disk gate passed. In accordance
with the delegated source-only constraint, no proof generation or mutation suite was run, so
the retained certificate explicitly records `toy_proof_executed=false` and
`mutation_tests_executed=false`.

The fixed-grammar result is unfavorable to this one-level route: even its optimistic
136,048-byte source-128 core loses to the 118,070-byte active-like SmallWood report before
the full relation and complete-ZK gates; the inherited conservative source-264 profile is
208,400 bytes. The result does not establish an absolute no-go because the missing costs are
not symmetric or measured, a variable-length authentication grammar was not measured, and
neither source target is a composed QROM theorem. Every production/privacy/security gate
remains false.

## Context and Orientation

`B128` is `GF(2^128)` in the polynomial basis
`x^128 + x^7 + x^2 + x + 1`. `E384` is its cubic extension with
`Y^3 + Y + 1`. For a relation bucket of `2^n` base-field symbols, choose
`C = 2^p` matrix columns and `R = 2^(n-p)` message rows. A Reed--Solomon
generator maps each length-`R` column to `M = R * 2^rate` encoded rows.
Each Merkle leaf contains one encoded row of `C` base-field symbols. The
partial sumcheck eliminates the `p` column variables, leaving an `R`-element
`E384` terminal vector. The verifier samples `q` distinct encoded rows and
checks that folding each opened row equals evaluating the terminal polynomial
at that code-domain point.

The existing size/model evidence is under
`.agent/hardening/binius-pq128-proof-size/`. The complete-ZK counterexample is
under `.agent/hardening/ligerito-e384-veil-complete-zk/`. The new owned path is
`.agent/hardening/ligerito-e384-core/`; no other agent's path should be edited.

## Plan of Work

First, implement dependency-free field arithmetic, exact SHA-512 framing, a stateful
transcript, Reed--Solomon column encoding, an index/level-bound Merkle tree, canonical
compact multiproofs, and the characteristic-two partial sumcheck. Keep matrix ordering
explicit: public coefficient index `row + R*column` is the paper's column-stacked `vec(X)`;
the prover only transposes to a row-major scratch layout for adjacent column folds.

Second, freeze a fixed header and proof grammar. Exact decoding must reject profile drift,
reserved bits, unexpected parameters, truncation, and trailing bytes. The serializer must
assert equality between actual bytes and a component ledger. The verifier receives expected
parameters and the full public opening statement; the proof's statement identifier and claim
must match both.

Third, export a typed interactive view before treating Fiat--Shamir bytes as authority. The
view distinguishes direct field messages, the multilinear-oracle commitment, public coins,
distinct query indices, raw openings, algebraic acceptance constraints, and computational
SHA-512/parser/Merkle checks. Export exact linear observation rows for all witness-dependent
algebraic messages. A complete-ZK contract will require relation-supplied `G_w` and wrapper
mask generator `G_r`, the rank equality on every admitted branch, joint masked commitment,
nonzero random-column sampling, a fixed-randomness simulator, and QROM composition.

Fourth, add tiny deterministic tests covering honest roundtrip, field identities, statement
replay, every wire section, noncanonical bytes, query uniqueness, Merkle padding, algebraic
row reproduction, byte/resource formulas, and the fail-closed privacy contract. Do not run
production parameters or allocate a production oracle.

Finally, write a concise evidence report. It must distinguish the implemented unique-decoding
core from the unproved Johnson/Flock option, explain why TensorSwitch is not this one-level
protocol, publish exact modeled bytes and oracle resources, and state that no full M4 relation,
complete ZK, composed QROM proof, or production integration exists.

## Concrete Steps

All commands run from `/Users/pldd/Projects/Reflexivity/Hegemon`.

1. Inspect only staged/source files with `rg`, `sed`, and `git diff -- <owned-path>`.
2. Edit only `.agent/hardening/ligerito-e384-core/` with `apply_patch`.
3. Perform syntax/source checks with bytecode disabled. No Cargo, Lake, rustc, dependency
   installation, production proof generation, or large oracle allocation is authorized.
4. Confirm `df -h .` remains above the disk gate and inspect the owned diff.

## Validation and Acceptance

The bounded implementation is acceptable when source inspection establishes all of the
following and the tiny test suite expresses corresponding executable assertions:

* the public functional and claim are external and statement-bound;
* the matrix layout matches column encoding and row commitment in Ligerito Section 5;
* every verifier coin follows commitment/direct-message observation;
* query indices are unbiased, distinct, and derived after the terminal message;
* Merkle leaves bind profile, index, width, and data, while internal nodes bind level and
  parent index;
* parse then serialize is byte-identical, and no trailing/reserved/profile drift is accepted;
* the byte ledger equals the serializer grammar for every accepted parameter object;
* mutations of header, statement id, root, claim, sumcheck, terminal, opened row, actual
  frontier, padded frontier, context, functional, or expected claim reject;
* the typed interactive view exports actual challenges, queries, openings, and linear
  observation rows; and
* every production/security/privacy capability remains false unless independent evidence is
  later supplied.

## Idempotence and Recovery

The source and tests are deterministic and do not create caches when run with
`PYTHONDONTWRITEBYTECODE=1`. No command in this plan deletes files or mutates another
agent's work. If a source edit is interrupted, reapply only the missing hunk in the owned
path. Never regenerate or overwrite the shared strict-refold or VEIL audit directories.

## Artifacts and Notes

Primary source excerpts are staged at `/private/tmp/ligerito.txt`,
`/private/tmp/tensorswitch-2025-2065.txt`, and `/private/tmp/veil-2026-683.txt`.
Those are evidence inputs, not repository artifacts. The retained repository outputs will be
the implementation, its adversarial tests, this ExecPlan, and `README.md` under the owned
path.

## Interfaces and Dependencies

The implementation uses only Python's standard library. Its public API will include:

* `Parameters`: exact geometry, source Ligerito error terms, resource counts, profile id,
  fixed header, and wire ledger;
* `OpeningStatement`: public context, public `E384` functional, expected claim, and exact
  statement identifier;
* `prove` and `verify`: canonical noninteractive SHA-512 wrapper around the exact
  one-level interactive algebra;
* `Proof.parse` and `Proof.serialize`: strict fixed-format wire boundary;
* `extract_interactive_view`: typed commitments, direct messages, coins, queries,
  openings, and acceptance constraints;
* `export_observation_rows`: exact linear rows over raw source coordinates after concrete
  challenges and queries; and
* `complete_zk_contract`: fail-closed wrapper obligations and capability flags.

No production code imports this module, and the module provides no function that can turn a
capability flag on.
