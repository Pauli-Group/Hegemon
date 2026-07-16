# Formal Cryptography Architecture Sanity Check

Status: research-open. This architecture defines the proof target and its trust boundaries. It does
not claim that the deployed SmallWood proof system is knowledge-sound.

## Security objective

The formal cryptography work must make it harder to state or prove the wrong theorem than to state
the real production theorem. In particular, it must prevent a proof about a weakened relation,
lossy constraint translation, unchecked executable predicate, unfinished upstream theorem, or
research-only verifier from acquiring production authority.

The design therefore separates three concerns:

1. `formal/lean` specifies deterministic production semantics and the exact generated SmallWood
   constraint program.
2. `formal/crypto` states conventional algebraic and probabilistic cryptographic targets and may
   import the production model.
3. Rust consensus and release policy remain independent of `formal/crypto` until every promotion
   obligation is discharged and the dependency boundary is changed deliberately.

The dependency direction is one-way:

```text
Rust runtime and release policy      formal/lean
              |                          |
              +------ no imports --------+
                                         |
                                         v
                                  formal/crypto
```

`scripts/check_formal_crypto.sh --isolation-only` enforces the missing reverse arrows in a small
always-on CI workflow. The full gate runs in a separate, path-scoped workflow because it is not
needed for unrelated runtime changes. The sanity package deliberately has no direct external proof
library dependency; primary papers guide later reductions without forcing CI to build unrelated
research trees.

## Minimal definitions

`HegemonCrypto.CCS.System` uses the conventional CCS data:

- a finite field;
- matrices indexed by rows and witness columns;
- one coefficient per sum term; and
- a multiset of matrix factors per term.

A multiset is required: replacing it with a set would silently erase repeated factors and change
the polynomial. `System.Satisfies` is the declarative equation. `System.satisfiesB` is the finite
executable checker. `System.satisfiesB_iff` proves they agree for every instance.

`HegemonCrypto.SmallWood.Relation` does not invent a second transaction language. It directly
requires both `ProductionConstraintMapBound` and `ExactProductionConstraintMapEvaluates` from the
production formal model. `ExactCCSRefinement` is the only intended conversion interface: a future
CCS encoder must prove an if-and-only-if statement for every production statement and witness. No
inhabitant is provided now.

`HegemonCrypto.SmallWood.KnowledgeSoundnessTarget` fixes the release-level game boundary directly.
It requires the standard QROM, bounds all quantum hash queries by `q_H`, bounds prior proof
interactions by `q_P`, defines the bad event as verifier acceptance without an extracted exact
production-relation witness, and compares that event's probability with one exact rational loss
function. The event probability remains an interface: a future finite-dimensional quantum model
must derive it from channels, oracle unitaries, and final measurement. The module contains no
theorem or instance asserting that a SmallWood verifier satisfies the target.

## Required theorem ladder

The following names denote security roles, not numbered protocol variants. Let `R_prod` be the
exact production statement/witness relation, `V_bytes` the canonical proof-byte verifier, and
`V_rust` the shipped Rust entry point.

1. `compile_exact`: for every production statement and witness, the generated CCS assignment
   satisfies the generated system if and only if `R_prod` holds. This is a deterministic theorem
   with zero cryptographic error.
2. `interactive_complete`: the exact SmallWood PIOP/LVCS/DECS prover is accepted on every valid
   encoded witness.
3. `interactive_extractable`: against every bounded malicious interactive prover, acceptance
   without extraction of an `R_prod` witness has probability at most the sum of the proved PIOP,
   PCS, commitment, and sampling terms.
4. `fiat_shamir_rom_adaptive_knowledge_soundness`: the exact non-interactive transcript remains
   knowledge-sound when an adversary observes and submits many proofs and chooses statements
   adaptively in the classical random-oracle model. The published SmallWood/CAPSS result provides a
   stronger extractable route in this model; its implementation-specific hypotheses and loss terms
   still need mechanization.
5. `fiat_shamir_qrom_adaptive_knowledge_soundness`: the same claim for an adversary making
   superposition random-oracle queries. It is a separate theorem, not a flag on the ROM theorem.
   Generic multi-round measure-and-reprogram results exist, but applying one to the exact SmallWood
   transcript, preserving adaptive witness extraction, and deriving a concrete loss is genuine
   theory work.
6. `decode_exact`: canonical decoding accepts exactly one byte representation of each proof and
   statement, consumes all input, rejects cross-profile encodings, and produces the mathematical
   object used by the cryptographic verifier. This is deterministic and contributes zero error.
7. `rust_refines`: `V_rust` returns true if and only if `V_bytes` returns true on the same decoded
   object, parameters, transcript domains, and primitive calls. This is deterministic and
   contributes zero error.
8. `production_knowledge_soundness`: for every adaptively chosen statement and proof produced by a
   bounded adversary, the probability that `V_rust` accepts while the extractor returns no valid
   `R_prod` witness is at most one explicit `epsilon_total`. The theorem must state the model,
   parameter record, random-oracle query bound, proof-query bound, primitive assumptions, and every
   additive or multiplicative reduction loss.

Simulation extractability is a separate stronger game in which the adversary also receives proofs
from a simulator and extraction must still succeed for a fresh accepting proof. Require it only for
a privacy or composition theorem whose reduction actually exposes such a simulator oracle. It is
not a substitute for the standard adaptive knowledge-soundness release theorem, and it must carry
its own simulation-query bound.

The final theorem is unavailable if any arrow is missing. Deterministic compiler, codec, and Rust
refinement arrows have error zero; they must never be hidden inside a cryptographic epsilon.
Cryptographic terms are composed symbolically and then evaluated with exact rational arithmetic.

This separation also fixes what Lean can and cannot establish. The production-to-CCS, transcript,
codec, and Rust refinements are substantial but conventional mechanization. The published
SmallWood result supplies a classical-ROM route for the PIOP/PCS layer, subject to proving that the
current implementation meets its exact hypotheses. The SmallWood paper does not supply the needed
QROM theorem. The generic multi-round Fiat-Shamir result of Don, Fehr, and Majenz proves that such
transfers can be possible, but does not instantiate Hegemon's protocol or concrete bound. Finally,
security of the concrete hash primitive remains a named cryptographic assumption; Lean can prove
correct use and reduction to that assumption, not derive collision or preimage resistance from the
implementation alone.

Primary theory inputs:

- SmallWood, including the revised extractable binding treatment:
  <https://eprint.iacr.org/2025/1085>
- Multi-round Fiat-Shamir measure-and-reprogram in the QROM:
  <https://eprint.iacr.org/2020/282>

## QROM model choice

In the standard QROM, a random function `H : X -> Y` is exposed to a quantum adversary through
the unitary map `|x, y> -> |x, y xor H(x)>`. A security experiment must therefore describe the
adversary as a sequence of quantum operations making at most `q_H` calls to that unitary, followed
by a classical measurement that returns a statement and proof. Inspecting a query as if it were a
classical log changes the adversary's state and is not a valid proof step.

The relevant model choices are:

| Model | Use in Hegemon |
| --- | --- |
| Quantum adversary with only classical hash queries | Too weak for a post-quantum Fiat-Shamir claim; an attacker can evaluate the public hash circuit coherently |
| Standard programmable QROM | Required release model; permits the reduction to reprogram a uniformly random oracle and charges the exact disturbance/query loss |
| Standard QROM with adaptive multi-theorem knowledge soundness | Required no-counterfeit game; the adversary may observe and submit many proofs and choose statements adaptively |
| Standard QROM with simulation extractability | Conditional stronger game for a privacy or composition reduction that actually exposes simulated proofs |
| Extractable or non-observable QROM variants | Research tools or stronger idealizations only; they receive no production credit unless reduced back to the standard QROM |
| Different transform or standard-model argument | Fallback if the exact SmallWood transcript does not meet a usable standard-QROM theorem; this changes the protocol and must be evaluated as such |

Hegemon should model one tagged random oracle whose input includes every existing transcript domain,
the exact statement bytes, all prior messages, and the challenge position. Proving disjoint tags is
equivalent to independent oracles prevents cross-protocol challenge reuse without inventing a
different hash primitive per round. `q_H` counts all quantum queries across every tag. A separate
`q_P` bounds prior proof interactions; `q_S` exists only in the optional simulation-extractability
game.

For mechanization, start with a finite quantum query algorithm rather than a bespoke quantum Turing
machine: alternating finite-dimensional quantum channels and calls to the oracle unitary, followed
by a measurement. Prove the generic measure-and-reprogram or compressed-oracle lemma once, then
instantiate it with the exact SmallWood transcript. This yields an information-theoretic query
bound and avoids hiding an asymptotic complexity model inside the protocol theorem. Runtime and
memory costs remain separate resource bounds.

The final concrete-security gate must evaluate the whole function
`epsilon_total(parameters, q_H, q_P)`. It must not label the system by the base error at `q_H = 1`.
For example, if the applicable transfer has a term `C(rounds) * (q_H + 1)^2 * epsilon_base`, then a
base term near `2^-128` reaches constant size after roughly `2^64` queries before the round
constant. A 128-bit post-quantum work-factor claim under that loss would need a correspondingly
smaller base error, a tighter theorem, or a protocol/parameter change. The exact SmallWood
instantiation decides which case applies.

## Threat analysis

| Attack | Required defense |
| --- | --- |
| Weaken the relation until extraction is trivial | Reuse the bounded exact production relation; require an exact iff refinement into CCS |
| Omit, reorder, substitute, or duplicate polynomial factors | Represent factors as multisets and keep kernel-checked adversarial cases |
| Make the executable checker differ from the mathematical predicate | Prove `rowSatisfiedB_iff` and `satisfiesB_iff` generically |
| Hide a proof gap behind `sorry`, `axiom`, `unsafe`, or `native_decide` | Reject those constructs locally and audit every credited declaration transitively |
| Import an unfinished upstream theorem indirectly | Allow only `propext`, `Classical.choice`, and `Quot.sound` in credited declaration dependencies |
| Smuggle a broad research dependency into the target | Permit only the local `formal/lean` direct dependency and pin all of its transitive Git revisions in `lake-manifest.json` |
| Turn a research result into runtime acceptance | Reject references from Cargo manifests, `formal/lean`, release workflows, and formal claim registries |
| Prove an interactive result but claim a Fiat-Shamir result | Keep interactive, ROM, and QROM obligations distinct |
| Prove an abstract verifier but ship different bytes or code | Keep canonical serialization and Rust verifier refinement as explicit obligations |
| Substitute a review bundle or marker for a proof | `openObligations = Finset.univ`; production authorization evaluates to false |

The standalone auditor loads compiled constants without contributor extensions, computes
transitive axioms with `Lean.collectAxioms`, and rejects any dependency outside the explicit kernel
allowlist. An upstream `sorry` cannot receive Hegemon credit merely because a dependency builds.

## Promotion obligations

The research package cannot become proof authority until all of these are complete:

1. Prove exact production-program to CCS refinement, including field normalization and every row,
   column, coefficient, factor multiplicity, public input, and witness slot.
2. Define the concrete prover and verifier rounds and prove honest-prover completeness.
3. Construct the extractor and prove interactive knowledge soundness with an explicit error bound.
4. Prove the commitment and polynomial-commitment binding reductions used by that extractor.
5. Prove adaptive multi-theorem knowledge soundness for the exact Fiat-Shamir transcript in the
   classical random-oracle model, and separately prove simulation extractability if a consuming
   privacy or composition theorem uses simulated proofs.
6. Prove the separate adaptive multi-theorem knowledge-soundness result in the quantum
   random-oracle model required by Hegemon's post-quantum claim; a QROM simulation-extractability
   theorem remains a separate conditional obligation.
7. Compose concrete field, query, degree, LVCS/DECS, PCS, and repetition parameters into a
   reviewed numerical security bound.
8. Prove canonical transcript and proof serialization, cross-version rejection, and exact Rust
   verifier refinement.
9. Audit prover randomness, secret lifetime, side channels, denial-of-service bounds, and failure
   handling in the executable implementation.
10. Obtain independent cryptographic review of the construction, reductions, and parameters.

Completing an item changes its named obligation; it does not create numbered copies of the model.
No migration or compatibility version enters the research definitions unless the production wire
format itself has a distinct consensus identity.

## Operational checks

Run the full sanity check from the repository root:

```bash
bash scripts/check_formal_crypto.sh
```

A cold build requires temporary space for the local formal model and Mathlib. The script refuses to
start dependency resolution below its free-space threshold. The generated `formal/crypto/.lake`
directory is untracked and can be removed independently without cleaning any Rust target or user
worktree.

The expected result is deliberately limited: canonical CCS semantics, a non-vacuous
relation-bound target statement, adversarial tests, immutable dependencies, a clean axiom audit,
and a proved open release posture. It is not a deployed cryptographic security certificate.
