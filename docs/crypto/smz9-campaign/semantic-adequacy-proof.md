# Bind the HGV8RP03 equations to the typed transaction specification

This living ExecPlan follows `.agent/PLANS.md`. It concerns mathematical evidence only; no runtime, carrier, capability, registry, or release policy is changed.

## Purpose / Big Picture

The goal is to derive transaction rules from the exact accepted 43,904-word packed assignment, rather than assuming that a successful honest-witness lowering proves every adversarial assignment is meaningful. A checked Lean theorem should remove a real semantic hypothesis. The full objective remains accepted native proof bytes to a valid typed transaction; the local milestone is a reusable interpreter theorem and an exact constraint consequence.

## Progress

- [x] (2026-09-07 15:08Z) Traced raw packed acceptance, nonlinear roots, the CSR linear equations, typed decoding, and honest-witness validation.
- [x] (2026-09-07 15:11Z) Identified the inactive-nullifier noninterference example and the Rust/Lean balance-padding constant mismatch.
- [x] (2026-09-07 15:16Z) Strict Lean checked reusable interpreter soundness, both public transparent balance words zero, and the generic theorem covering all 849 private singleton-one/zero-target equations.
- [x] (2026-09-07 15:22Z) Strict Lean checked all 69 Boolean witness root families in all 64 lanes, covering 4,416 private coordinates.
- [x] (2026-09-07 15:27Z) Strict Lean checked the four dense radix-4 row families in all 64 lanes, covering 256 private digits, and the corrected admitted-public domain definition.
- [x] (2026-09-07 15:27Z) Traced all candidate frontend public checks and recorded the source-grounded next private semantic obligations.
- [x] (2026-09-07 15:28Z) All five principal theorem axiom audits report only `propext`, `Classical.choice`, and `Quot.sound`; no new source axiom, `sorry`, `admit`, or `native_decide` was added.
- [x] (2026-09-07 15:29Z) Independent read-only review found no mathematical scope defect; replaced one overly broad reference to "verified frontend code" with "source-inspected frontend code" to preserve the unproved execution-refinement boundary.
- [ ] Coordinator integration and broader gates remain outside this worker's two-file ownership.

## Surprises & Discoveries

Raw `RelationProgramComponents.AcceptsPacked` checks 120 canonical field words but not every frontend structural rule. If public input flag word 0 is zero, changing public word 4 to one preserves all nonlinear roots and all linear equations. The nonlinear expression at index 8 reads word 4 but is dead. In the public expression graph only indices 8 and 266 depend on word 4; index 266 is the product of public flag word 0 and word 4. The sole affected CSR equation is attempt 18312, family 20, local index zero: flag times packed word 28772 equals flag times public word 4. The actual frontend rejects the mutated inactive nullifier. This is a false overstrong formal domain, not an accepted transaction forgery.

The Lean semantic specification originally set `balancePaddingAssetId` to `fieldModulus - 1`, whereas Rust canonically reduces `u64::MAX`, giving 4,294,967,294. The exact relation program agrees with Rust. Consequently the Rust default asset list `[0,4294967294,4294967294,4294967294]` violated the original Lean strict asset ordering. The coordinator corrected the specification constant to `(2^64 - 1) % fieldModulus` and added kernel-checked equality, canonicality, and non-`p-1` lemmas. This is a formal-model correction; Rust and the pinned program were not changed for it.

Descriptor names are not an adequate substitute for expression indices: input direction Boolean constraints and input membership roots are interleaved, while some descriptor labels present an uninterrupted direction span. Proof extraction must follow the exact executable graph and CSR attempts.

## Decision Log

The actual semantic entry domain includes successful canonical frontend admission as well as packed equation acceptance. Public rules already enforced by source-inspected frontend code should not be falsely required to follow from the private algebraic relation. The universal execution-refinement theorem remains unproved. This changes the formal contract, not the protocol. Decision: 2026-09-07.

Begin positive semantic extraction with transparent value balance. Exact attempts 15672 and 15673 bind one packed word to both public sign and magnitude; attempt 19262 forces that word to zero. This derives two concrete transaction rules from actual equations and exercises reusable interpreter reasoning without relying on all five desired semantic conclusions as hypotheses. Decision: 2026-09-07.

## Outcomes & Retrospective

The local positive milestone is implemented and strict-Lean-checked. `evaluated_program_satisfies_each_node` proves, by induction through the actual interpreter, that the final trace satisfies every canonical graph node equation. It is not a receipt asking for a semantic conclusion. `accepted_packed_transparent_value_balance_is_zero` derives both public zero words from exact CSR attempts. `accepted_packed_unconditional_zero_coordinate` applies to each of the 849 exact singleton-one/zero-target attempts; the exact count is kernel-checked. These include dense/top padding, authorization inline padding, hash dummy states, stable role padding, range padding, and numerical padding.

`accepted_packed_boolean_witness_rows` binds an exact kernel-checked list of 69 real nonlinear roots to their private source rows and derives Boolean values in every lane using the proved Goldilocks primality certificate. `accepted_packed_dense_radix_four_rows` likewise derives digits less than four for rows 247 through 250 in every lane. These supply real private witness shape constraints without assuming honest lowering, decoding success, or any of the five desired semantic conclusions.

This does not complete accepted-program-to-typed-transaction adequacy. The current uninhabited full receipt is still not a security proof. The new results remove explicit sub-obligations in canonical private shape, while typed decoding, cryptographic links, asset conservation, and the complete stablecoin transition remain independently accountable. Public admission must also be proved from actual frontend execution, not merely inserted as an unexplained assumption.

## Context and Orientation

`formal/lean/Hegemon/Transaction/Poseidon2V8RelationProgram.lean` defines a small expression interpreter: each expression reads public words, witness rows, or earlier computed values. Its output is a list of field values. A CSR attempt is a sparse linear equation whose coefficients and target come from the public-only expression graph. `formal/crypto/HegemonCrypto/SmallWoodV8Smz9RelationProgramComponentsGenerated.lean` contains the exact 8,271 nonlinear expressions, 830 roots, 565 public expressions, and 20,569 linear attempts parsed from the pinned 852,305-byte program. Its SHA-512 is `8477896dc765c3776fefc93bb74fb0c7668a677abdc60697b0c216bc9b4363e46a8b7cadc557dba4a1e4ccdfe572e5b2833879dd465079b12b6044a51a5612c3`.

`formal/lean/Hegemon/Transaction/Poseidon2V8SemanticSpecification.lean` independently defines typed transaction validity. `Poseidon2V8SemanticAdequacy.lean` currently assembles five assumed universal refinements but does not inhabit them. `circuits/transaction/src/smallwood_poseidon2_v8_semantics.rs` contains an honest typed decoder and relower check; only the honest compiler invokes the full-witness check in production source. The proof verifier sees sampled openings and cannot reuse that honest check as its extraction theorem.

## Plan of Work

The first milestone adds `formal/crypto/HegemonCrypto/SmallWoodV8Smz9SemanticBinding.lean`. Prove that evaluating a canonical expression graph yields values satisfying every expression equation when read against the final list. Then specialize to the exact generated graph and sparse attempts to establish canonical zero transparent balance. The second milestone records the source checks that justify the public frontend premise and the precise remaining private relation families. The coordinator integrates existing-file changes and broad gates.

The implemented semantic entry predicate is `CanonicalPublicPackedDomain`: one typed statement encodes to the exact public word list, satisfies the fixed public semantic rules, and shares that list with an accepted packed program. This is a corrected mathematical domain, not a claim that the complete Rust execution refinement has been proved.

The next constructive canonical-shape step is to use CSR family 4, attempts 15665 through 15671, to reconstruct seven values from thirty proved radix-4 digits plus one proved top bit. The natural sum is at most `2^61-1`, below the field modulus; proving that no modular wrap occurs yields the 61-bit bounds for packed words 0, 2176, 4352, and 5120 and public words 44, 46, and 62. The decoder's 721 source descriptors locate the typed words but do not themselves prove decoding success. Continue with selector uniqueness, inactive sources, authorization shape, and the stable numeric representations.

For cryptographic links, the interpreter theorem now exposes the exact nonlinear equations for all 125 real Poseidon2 calls. A further induction must identify their two 182-row groups with the fixed permutation, including all S-box and linear-layer equations. CSR families 10 through 35 then bind sponge absorption, note commitments, input Merkle orientation and public roots, nullifiers, output commitments, action intent, and authorization digests to those calls. This needs exact executable indices, not descriptor labels.

For per-asset balance, combine bounded note values with Boolean activity and selector constraints, the canonical public asset list using the corrected padding value, and the exact per-asset equations. An equality in the field does not by itself prove an equality of ordinary nonnegative amounts; each signed sum's bounds must exclude a multiple of the modulus. For stablecoin transition, families 36 through 85 plus the stable nonlinear roots bind disabled-source zeroing, direction flags, role padding, policy/configuration tree paths, issuer commitments, scalar ranges, decimal scaling, epochs, retirement gates, and collateral products/subtraction. The exact disabled-at-context branch must preserve parent height and before/after roots, not use the retired all-zero disabled-state interpretation.

These are ordered proof-construction steps using the new interpreter and private-shape theorems. They are not certified merely by being listed here, and no complete five-family constructor is asserted.

## Concrete Steps

From `formal/crypto`, run the cached toolchain without invoking builds or dependency installation:

    lake env lean -DwarningAsError=true -DautoImplicit=false HegemonCrypto/SmallWoodV8Smz9SemanticBinding.lean

The command exits zero with no warnings. To audit theorem dependencies without creating a build artifact, stream the same source with a print directive appended:

    awk '1; END { print "#print axioms HegemonCrypto.SmallWood.V8Smz9SemanticBinding.accepted_packed_boolean_witness_rows" }' HegemonCrypto/SmallWoodV8Smz9SemanticBinding.lean | lake env lean -DwarningAsError=true -DautoImplicit=false --stdin

Keep one Lean process at a time in this worker. Available disk was 41 GiB at the start; stop new generation below 40 GiB and keep new source and scratch files below 40 MiB. No retained witness or proof bytes are modified.

## Validation and Acceptance

The module must compile without `sorry`, `admit`, new axioms, or `native_decide`; exact source checks use ordinary kernel reduction. Its result must expose a property of the accepted input, not another receipt asking a caller to assert that same property. Print axioms of the principal theorem during integration. The proof must retain explicit limitations: no proof-system extraction, Rust execution refinement, concrete hash security, or production authorization is supplied by this local result.

The local strict source check passed on 2026-09-07. All five principal theorem audits (`evaluated_program_satisfies_each_node`, transparent balance zero, unconditional private zero coordinate, Boolean private rows, and dense radix-4 rows) reported exactly the standard Lean logical axioms `propext`, `Classical.choice`, and `Quot.sound`. This is proof-kernel evidence for those named statements, not a complete transaction-soundness result. The two new files total under 45 KiB, no build artifact was emitted by this worker, and free disk remained 41 GiB.

## Idempotence and Recovery

Only the two new worker-owned files are edited. Re-running Lean checks is read-only unless the coordinator requests an explicit scratch output. Preserve all pre-existing changes. The coordinator can remove these new files without changing runtime behavior, though doing so loses the new mathematical evidence.

## Artifacts and Notes

Read-only parser reproduction uses `scripts/generate_poseidon2_v8_relation_program_components_lean.py`; `parse_components` validates exact byte length, SHA-512, and complete section exhaustion before yielding the graph. The affected inactive-nullifier expression/attempt indices above were obtained from this exact parser, not descriptor names.

Every inspected candidate verification route reaches the public gate in `circuits/transaction/src/smallwood_poseidon2_v8_frontend.rs`. The standard verifier at line 1043 calls the factory route at line 1030, which calls `validate_verifier_input` at line 1035. The factory at line 207 calls `V8PublicStatement::try_from_public_words`; its decoder at `smallwood_poseidon2_v8_types.rs:357-449` checks field representations, Boolean encodings, fixed widths, and public structure. The adapter repeats structure validation at `smallwood_poseidon2_v8_semantics.rs:4020`. The relation-supplied helper at frontend line 1006 calls `ensure_relation_matches_input`, whose first action at line 1120 is the same public gate. Compact verification at lines 799 and 965 and the associated report paths use those gates too.

`validate_public_structure` at types line 506 checks version/suite (509/512), fee bounds (515), zero transparent balance (526), asset layout (529/565), active/inactive digest shape (530), duplicate nullifiers (548), stable compatibility (551/586), parent-height bound (552), and enabled action intent (555). Disabled mode at line 594 compares with exact `disabled_at_context`, preserving parent and equal before/after root while zeroing other stable fields. `validate_verifier_input` at frontend line 1151 parses at 1160 and independently recomputes the expected action intent and seven-limb relation binding at 1173. These source anchors explain why public admission belongs in the domain; they are not a universal Rust-to-Lean execution theorem.

## Interfaces and Dependencies

Import the existing generated components and canonicality theorem. Use the existing `evalFieldExpression`, `evalExpressionNodes`, `evalCsrTerms`, and `AcceptsPacked` definitions unchanged. Any entrypoint refinement must include the actual frontend's canonical statement checks and exact encoding, with hash, decoder execution, and proof extraction assumptions named separately rather than silently folded into the algebraic theorem.

Revision note (2026-09-07): Created the execution record after identifying two concrete obstacles to the original universal statement, then expanded the positive milestone to exact private zero, Boolean, and radix-4 constraints. Recorded the fixed public model, verified source entrypoints, and ordered remaining proof construction without claiming complete adequacy.
