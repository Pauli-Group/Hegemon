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
                                         |
                                         v
                               pinned research libraries
```

`scripts/check_formal_crypto.sh --isolation-only` enforces the missing reverse arrows in a small
always-on CI workflow. The full gate runs in a separate, path-scoped workflow because a cold ArkLib
and Mathlib build is large and is not needed for unrelated runtime changes.

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

`HegemonCrypto.SmallWood.KnowledgeSoundnessTarget` is definitionally ArkLib's probabilistic
straight-line extractor target, instantiated with the SmallWood relation. It quantifies over
malicious provers and a nonnegative extraction-error bound. The module contains no theorem or
instance asserting that a SmallWood verifier satisfies it.

## Threat analysis

| Attack | Required defense |
| --- | --- |
| Weaken the relation until extraction is trivial | Reuse the bounded exact production relation; require an exact iff refinement into CCS |
| Omit, reorder, substitute, or duplicate polynomial factors | Represent factors as multisets and keep kernel-checked adversarial cases |
| Make the executable checker differ from the mathematical predicate | Prove `rowSatisfiedB_iff` and `satisfiesB_iff` generically |
| Hide a proof gap behind `sorry`, `axiom`, `unsafe`, or `native_decide` | Reject those constructs locally and audit every credited declaration transitively |
| Import an unfinished upstream theorem indirectly | Allow only `propext`, `Classical.choice`, and `Quot.sound` in credited declaration dependencies |
| Drift a research dependency | Pin every Git package to an immutable 40-character commit in `lake-manifest.json` |
| Turn a research result into runtime acceptance | Reject references from Cargo manifests, `formal/lean`, release workflows, and formal claim registries |
| Prove an interactive result but claim a Fiat-Shamir result | Keep interactive, ROM, and QROM obligations distinct |
| Prove an abstract verifier but ship different bytes or code | Keep canonical serialization and Rust verifier refinement as explicit obligations |
| Substitute a review bundle or marker for a proof | `openObligations = Finset.univ`; production authorization evaluates to false |

The pinned ArkLib tree contains unfinished declarations. This is visible and not waived. Hegemon
uses one standard definition from that tree and accepts it only because the standalone auditor
loads compiled constants without contributor extensions, computes transitive axioms with
`Lean.collectAxioms`, and rejects any dependency outside the explicit kernel allowlist. An upstream
`sorry` cannot receive Hegemon credit merely because the package builds.

## Promotion obligations

The research package cannot become proof authority until all of these are complete:

1. Prove exact production-program to CCS refinement, including field normalization and every row,
   column, coefficient, factor multiplicity, public input, and witness slot.
2. Define the concrete prover and verifier rounds and prove honest-prover completeness.
3. Construct the extractor and prove interactive knowledge soundness with an explicit error bound.
4. Prove the commitment and polynomial-commitment binding reductions used by that extractor.
5. Prove the Fiat-Shamir transformation in the classical random-oracle model.
6. Prove the separate quantum-random-oracle result required by Hegemon's post-quantum claim.
7. Compose concrete field, query, degree, FRI, PCS, and repetition parameters into a reviewed
   numerical security bound.
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

A cold build requires substantial temporary space. The script refuses to start dependency
resolution below its free-space threshold. The generated `formal/crypto/.lake` directory is
untracked and can be removed independently without cleaning any Rust target or user worktree.

The expected result is deliberately limited: canonical CCS semantics, exact target statement,
adversarial tests, immutable dependencies, a clean axiom audit, and a proved open release posture.
It is not a deployed cryptographic security certificate.
