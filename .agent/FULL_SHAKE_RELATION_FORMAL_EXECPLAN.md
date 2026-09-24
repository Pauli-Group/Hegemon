# Mechanize the full SHAKE256 relation's semantic boundary

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept current as work proceeds. This plan follows `.agent/PLANS.md`.

## Purpose / Big Picture

Hegemon needs a formal statement of what the prospective V5/Delta full SHAKE256 proof is meant to authorize before proof-size work can be called production work. After this change, a reviewer can execute Lean obligations that enumerate the exact nine accepted and seven rejected two-input/two-output masks, enforce 61-bit values and zero public value balance, expose conservation and no-mint facts, enforce typed accumulator and value-lock lineage across five authorization modes, and account for every byte in the fixed 853-byte statement grammar with 56-byte digests. A separate, additive theorem now characterizes exactly when uniformly sampled linear padding makes fixed linear observations witness-independent and proves full output translation-invariance from a surjective padding map. The model deliberately cannot certify cryptographic SHAKE correctness, M4 circuit refinement, Rust parser refinement, adaptive Fiat--Shamir zero knowledge, or PQ128/QROM security; those are named certificate fields that must be supplied by separate evidence.

## Progress

- [x] (2026-08-21 19:20Z) Read `.agent/PLANS.md`, `DESIGN.md`, `METHODS.md`, the prospective Rust scalar oracle, and existing Lean transaction and parser conventions.
- [x] (2026-08-21 19:34Z) Added the executable activity-mask, fixed public-slot padding/nonzero/duplicate-nullifier rules, signed amount, 61-bit balance, zero-value-balance, stable issuance, and no-mint core.
- [x] (2026-08-21 19:42Z) Added the typed five-mode authorization state machine, derived ordered signer-policy validation, exact one-fresh-slot approval transition, and negative regressions for typed-state forgery, duplicate approval, and a final spend without an accumulator input.
- [x] (2026-08-21 19:48Z) Added the exact 853-byte width ledger, parser acceptance facts, truncation/trailing/nonbinary/negative-zero/wrong-digest-width regressions, and explicit release-certificate boundary.
- [x] (2026-08-21 20:08Z) Direct-checked all four isolated modules and the umbrella import with warnings as errors using a 2.5 MiB temporary `.olean` tree, then removed that exact temporary tree. Free space stayed above the 20 GiB hard reserve.
- [x] (2026-08-21 21:25Z) Added a deterministic Lean JSON generator and byte-identical committed fixture for all sixteen masks, exact 853/56 widths, all five valid authorization modes, seven lineage/type attacks, six balance rows, and seven stable surfaces. Added a no-serde Rust integration test that independently recomputes each finite decision and exercises the real scalar verifier for all masks and named authorization cases. Direct Lean elaboration and generator/fixture byte comparison passed; focused Cargo execution remains disk-gated below 28 GiB.
- [x] (2026-08-21 22:10Z) Added every executable finite-vector bridge input to the sealed production-frontier surface: generator source, Lake target wiring, Lean toolchain and dependency manifest, committed JSON, and Rust differential source. Per-path mutation and deletion regressions now stale all six certificates or stop at a hard missing-file error. The expanded 12-test Python gate suite and a fresh 3.0 MiB warning-as-error Lean/generator pass succeed; no Cargo or prover ran.
- [x] (2026-08-21 19:56Z) Added `RandomPadding.lean`: finite field/vector-space and linear-map interfaces, permutation-coupled uniform distributions, the exact witness-independence/range equivalence, full-uniform translation invariance from full row rank, zero-rank and binary key-reuse negative theorems, and explicit uninhabited-by-this-namespace Vandermonde and adaptive Fiat--Shamir certificate propositions. Direct warning-as-error elaboration used a 500 KiB temporary output and no Cargo build.
- [ ] Extend the bridge to arbitrary parser mutation families and establish an acceptance-iff Rust decoder/scalar proof; finite vector agreement does not inhabit the refinement certificate.
- [ ] Prove the M4 constraint system refines the Rust scalar oracle and discharge the cryptographic, privacy, and strict soundness certificate fields.

## Surprises & Discoveries

- Observation: The full fixed statement is 853 bytes, not 800 and not a rounded word count. The exact decomposition is `8 + 2 + 4 + 56 + 112 + 112 + 112 + 32 + 8 + 9 + 190 + 56 + 152 = 853`.
  Evidence: `canonical_width_ledger_is_exactly_853` in `formal/lean/Hegemon/FullShakeRelation/Grammar.lean`.
- Observation: The seven rejected masks are exactly the shapes with no active input or no active output; the remaining Cartesian product has nine accepted masks.
  Evidence: `exact_nine_activity_masks` and `exact_seven_rejected_activity_masks` in `formal/lean/Hegemon/FullShakeRelation/Core.lean`.
- Observation: Typed note lineage is a necessary no-forgery boundary. A generic single-key spend that could create an accumulator or value-lock output would bypass the threshold state machine.
  Evidence: `single_key_typed_state_forgery_rejects` in `formal/lean/Hegemon/FullShakeRelation/StateMachine.lean`.
- Observation: A dependency-free vector consumer can cover the entire finite decision table without adding serde to the prospective scalar crate, but the generic negative-delta balance row is intentionally accepted only below `PublicBalanceSurface`; the production native row rejects it.
  Evidence: `negative_delta_burn` is true in the generated `balance_cases`, while `native_negative_delta` is false in `stable_cases` and the Rust test treats that distinction explicitly.
- Observation: Fixed-matrix random padding has an exact algebraic criterion: two witnesses have identical uniform-seed distributions exactly when their active observation difference is in the image of the padding map. Surjectivity therefore gives output translation invariance, while a zero map hides only already-equal active observations.
  Evidence: `same_distribution_iff_active_shift_in_padding_range`, `full_row_rank_padding_gives_full_uniform_output`, `full_row_rank_padding_is_witness_independent`, and `zero_padding_rank_hides_iff_active_observations_equal` in `formal/lean/Hegemon/FullShakeRelation/RandomPadding.lean`.
- Observation: The fixed-matrix result cannot be lifted silently to reused randomness or adaptive transcript queries. In characteristic two, two observations sharing one pad cancel that pad exactly; witness-independent query scheduling, all terminal/FRI rows, SHAKE transcript salt binding, BCS simulation, and the QROM bound remain separate premises.
  Evidence: `reused_padding_exposes_binary_active_difference` and `AdaptiveFiatShamirZkCertificate` in `formal/lean/Hegemon/FullShakeRelation/RandomPadding.lean`.
- Observation: The real M4 shift reduction is generally linear only over GF(2), not B128-linear in one packed-symbol coefficient. A concrete certificate must expand each B128 tail symbol into its 128 binary basis bits (or prove an equivalent linearized-polynomial representation) and include those rows in the verifier-bound adaptive schedule.
  Evidence: source tracing of `fold_words` and the unfinished `LinearObservationSink` integration; no concrete certificate inhabits this obligation.

## Decision Log

- Decision: Model 56-byte digests as opaque `Nat` values in the semantic layer.
  Rationale: Shape and state-machine theorems must not silently claim SHAKE256 cryptography. Exact digest byte width is accounted for in the grammar, while hash binding is an explicit external certificate.
  Date/Author: 2026-08-21 / Codex.
- Decision: Use fixed `Slot2` structures rather than variable-length lists for public input and output activity.
  Rationale: The Rust grammar has exactly two input flags and two output flags; a list model would permit shapes the parser cannot express.
  Date/Author: 2026-08-21 / Codex.
- Decision: Encode strict release readiness as a structure containing uninhabited-by-default propositions, not as booleans defaulting to success.
  Rationale: This prevents the current semantic skeleton from reward-hacking a strict security or implementation-refinement claim.
  Date/Author: 2026-08-21 / Codex.
- Decision: Commit deterministic Lean output and parse it with a small test-only Rust parser rather than add serde.
  Rationale: The bridge remains isolated and disk-light, rejects duplicate/trailing JSON structure, and does not expand the prospective production dependency surface.
  Date/Author: 2026-08-21 / Codex.
- Decision: Bind the complete finite-vector evidence supply chain into the same production-surface digest as the relation.
  Rationale: Pinning semantic modules without the generator, exact fixture, consumer, compiler selection, and target wiring allowed those evidence-producing bytes to drift without invalidating certificates.
  Date/Author: 2026-08-21 / Codex.
- Decision: Define equality of finite uniform distributions by a bijective reindexing of their explicit seed space.
  Rationale: This gives an exact multiplicity-preserving statement using Lean `Std` alone, avoiding unsupported probability-library assumptions while proving the same finite uniform law.
  Date/Author: 2026-08-21 / Codex.
- Decision: Leave the concrete nonzero-distinct high-tail Vandermonde rank proof and adaptive Fiat--Shamir simulation as certificate propositions with no namespace-provided inhabitant.
  Rationale: The current dependency-free formal tree has no polynomial/matrix library, and treating transcript-derived query independence or BCS/QROM programming as an axiom would falsely promote a fixed-schedule lemma to complete zero knowledge.
  Date/Author: 2026-08-21 / Codex.

## Outcomes & Retrospective

The source skeleton now makes the exact semantic target reviewable and executable without importing SmallWood or Poseidon. It closes the most important specification-level typed-state exploit and names every remaining authority seam. The isolated modules, umbrella import, finite vector generator, and fixed-matrix padding theorem pass Lean with warnings as errors, and the committed JSON is byte-identical to generator output. The random-padding result is a real fixed-schedule theorem, including its sharp zero-rank and key-reuse failures; it is not an adaptive zero-knowledge proof. The Rust differential source covers the finite table without a new dependency; its focused Cargo execution remains blocked by the 28 GiB admission threshold. This is not yet a production formal certificate: concrete Vandermonde rank, adaptive schedule independence, all FRI/terminal-row inclusion, SHAKE transcript salt binding, BCS/QROM simulation, arbitrary parser/scalar acceptance equivalence, Rust/M4 refinement, complete-ZK simulation, and strict PQ128/QROM analysis remain open.

## Context and Orientation

The prospective scalar oracle is `circuits/standalone-full-shake256-relation-prototype/src/lib.rs`. It defines a V5/Delta shielded transaction with two fixed input slots, two fixed output slots, four sorted balance-asset slots, 56-byte SHAKE256-derived public digests, a zero signed public value balance, optional nonzero stable issuance, and five private authorization modes. Its exact public statement encoding is 853 bytes. The formal model lives only under `formal/lean/Hegemon/FullShakeRelation/` and does not import the old SmallWood semantic closure.

`Core.lean` defines fixed activity slots and balance semantics. `StateMachine.lean` defines note types and authorization transitions. `Grammar.lean` defines the byte ledger and parser decision surface. `RandomPadding.lean` proves the additive finite-vector-space hiding lemma for fixed linear observation maps and defines the remaining concrete-rank/adaptive-transcript certificates. `SecurityBoundary.lean` lists evidence that this semantic model cannot itself prove. `formal/lean/Hegemon/FullShakeRelation.lean` is the umbrella import.

## Plan of Work

First, direct-check the umbrella module without producing a large build artifact. Correct all elaboration errors and treat warnings as errors. Next, add a small vector generator under the same namespace whose JSON covers all sixteen masks, the canonical parser fixture, and each negative mutation. Add a Rust test that consumes those vectors through `decode_canonical_statement` and the scalar oracle. Do not equate matching fixtures with refinement; add a certificate theorem only after an exact acceptance-equivalence proof or independently reviewed exhaustive boundary argument exists.

For the random-padding branch, instantiate `FiniteVectorSpace` and `LinearMap` with the actual committed-codeword and observation spaces. Prove the concrete high-tail evaluation matrix is surjective for the complete fixed union of query, terminal, and FRI rows. Then prove that the Fiat--Shamir schedule is witness-independent or supply the stronger BCS/QROM simulator theorem; the fixed-matrix theorem alone is not enough.

Then map every M4 constraint family to one semantic predicate and establish both directions: an accepted M4 trace yields the Lean facts, and every valid semantic witness has a satisfying M4 trace. Finally, supply the cryptographic and privacy certificates from independent SHAKE framing, SHAKE512 commitment/salt binding, E384/PCS/QROM, and complete-zero-knowledge arguments. Only a value of `StrictReleaseCertificate` with all of these fields can support release wording.

## Concrete Steps

Work from `/Users/pldd/Projects/Reflexivity/Hegemon`. The ordinary integrated command, once the repository build gate is open, is:

    cd formal/lean
    lake build Hegemon

While the repository build gate is closed, direct-check each source module to an exact temporary output tree, put that tree on `LEAN_PATH` for dependent modules, direct-check `Hegemon/FullShakeRelation.lean`, then direct-check and run `Hegemon/FullShakeRelation/GenerateFullShakeRelationVectors.lean`. Compare its stdout byte-for-byte with `testdata/formal_core_vectors/full_shake_relation.json`, and remove only that exact temporary tree. The direct generator pass remains a few MiB and exits zero with `-DwarningAsError=true`. Do not run `lake build Hegemon` while the heavy-work gate is closed. Once free space reaches the 28 GiB focused-build threshold, run `cargo test --manifest-path circuits/standalone-full-shake256-relation-prototype/Cargo.toml --test lean_full_shake_relation_vectors`; until then, Rust status is source/static only.

## Validation and Acceptance

The first milestone is accepted only when the direct Lean command exits zero and the executable theorems establish the concrete mask lists, the 853-byte total, 56-byte digest width, zero-delta no-mint equality, 61-bit bounds, nonzero enabled stable issuance, typed-state forgery rejection, duplicate-approval rejection, and final-spend type rejection. Short, trailing, nonbinary-flag, negative-zero, and 48-byte-digest parser surfaces must all evaluate to rejection.

The fixed-matrix privacy milestone additionally requires `RandomPadding.lean` to elaborate with warnings as errors and establish the bidirectional range criterion, surjective/full-row-rank full-uniform theorem, zero-padding-rank failure, and binary reused-pad leakage theorem without `sorry`, `admit`, or `axiom`. Production formal acceptance additionally requires the concrete Vandermonde certificate, fixed or correctly simulated transcript scheduling, all terminal/FRI rows, SHAKE512 commitment and transcript-salt binding, the focused Rust vector test, arbitrary-input Rust parser/scalar acceptance equivalence, M4 bidirectional refinement, complete zero knowledge, and strict composed PQ128/QROM evidence. Finite cross-language vector agreement and fixed-matrix distribution equality do not substitute for those requirements.

## Idempotence and Recovery

All changes are additive. Direct Lean checking is read-only unless an output path is explicitly supplied, which this plan does not do. If validation is interrupted, rerun the single direct command. Do not delete shared Cargo or Lean caches to make space; wait for the disk gate or remove only a separately identified disposable artifact with operator approval.

## Artifacts and Notes

The fixed ledger is:

    header and flags       14
    public digests        392
    assets and balances    49
    stablecoin binding    190
    balance tag            56
    activation binding    152
    total                 853

The current release certificate intentionally contains external proposition fields. No constructor or theorem in this namespace manufactures those fields.

## Interfaces and Dependencies

The umbrella module is `Hegemon.FullShakeRelation`. It depends only on Lean `Std` and its own namespace. The stable public interfaces are `activityAccepted`, `balanceRowAccepted`, `publicBalanceAccepted`, `authModeAccepted`, `statementParserAccepts`, `AcceptedStatementParserFacts`, `FiniteVectorSpace`, `LinearMap`, `SameUniformDistribution`, `WitnessIndependent`, `FullRowRank`, `HighTailVandermondeCertificate`, `AdaptiveFiatShamirZkCertificate`, `CryptographicAssumptions`, `ImplementationRefinementCertificates`, `PrivacyCertificates`, and `StrictReleaseCertificate`. Future Rust and M4 refinement work must target these definitions or update this plan and the corresponding semantic definitions atomically.

Revision note (2026-08-21): Added the deterministic finite Lean-to-JSON-to-Rust bridge, documented its no-serde implementation and generic-row/native-row distinction, sealed its complete executable supply chain in the production-surface hash with adversarial drift tests, and kept arbitrary-input refinement and focused Cargo execution explicit rather than promoting source-only work.

Revision note (2026-08-21): Added the dependency-free fixed-matrix random-padding theorem, exact negative controls, and explicit concrete-rank/adaptive-transcript certificate boundary. This prevents the algebraic result from being reported as adaptive Fiat--Shamir ZK before SHAKE512 salt binding, BCS/QROM simulation, and the complete observation matrix are proved.
