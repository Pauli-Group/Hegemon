# Close the Deployed SmallWood No-Counterfeit Critical Path

This ExecPlan is a living document maintained under `.agent/PLANS.md`. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` are updated as execution proceeds.

## Purpose / Big Picture

The deployed native block path must accept only the SmallWood transaction proof relation and must carry one canonical ordered block object from transaction proof verification through claim, recursive artifact, DA identity, and supply accounting. After this work, Lean will prove that an accepted canonical native block, under only explicitly named primitive and proof-system cryptographic assumptions, satisfies exact SmallWood semantic constraints and changes supply only through that block's coinbase, fees, and burns. The checked mechanized-assumption inventory will move honestly from 9/20 to at least 13/20 without changing its fixed policy.

Plonky3 is removed from the shipped native executable first. The active SmallWood and SuperNeo code moves to a Hegemon-owned Goldilocks field implementation, while legacy Plonky3 proof, aggregation, commitment, and disclosure modules are excluded from every production dependency path and fail closed at retained decode boundaries. Consensus encoding, genesis, storage, RPC, and the shipped recursive-block testnet path remain compatible. The intentional runtime change is that Plonky3 and ReceiptRoot block artifacts are rejected and cannot be constructed or admitted; historical SmallWood V2 transaction proof bytes remain verification-only while all new proofs use SmallWood V3.

## Progress

- [x] (2026-07-13) Verified PR #199 and #200 merged, fetched `origin`, and created isolated branch `codex/deployed-smallwood-no-counterfeit-closure` from post-merge `origin/main` at `8be2a170fa66e19fa27ed8f16bf0b6ed2f2053e2`.
- [x] (2026-07-13) Recomputed the independent baseline at 9/20 closed tracks (45%).
- [x] (2026-07-13) Completed the initial kill gate and demonstrated that the native tx-leaf verifier still accepted a legacy `Plonky3Fri` artifact through a non-ignored production test.
- [x] (2026-07-13) Removed the selectable legacy transaction backend dispatch, retained wire value 1 only as a rejecting tombstone, and migrated executable transaction/native fixtures to SmallWood.
- [x] (2026-07-13) Removed every Plonky3 package from the locked `hegemon-node`, `wallet`, and `walletd` normal/build dependency graphs, replaced active field arithmetic with `hegemon-field`, and added `scripts/check_native_runtime_dependencies.sh` as a fail-closed graph gate across all three shipped binaries.
- [x] (2026-07-14) Closed the security-review ReceiptRoot tombstone gap: the first Lean-conformance-checked proof-policy gate and native mode conversion now reject ReceiptRoot, and the live verifier has only the recursive branch. Baseline research sources remain excluded from every shipped dependency graph and were not used for this closure.
- [x] (2026-07-13) Made SmallWood V3 the only proving format, committed the private Merkle/policy binding inside the proof relation, required an empty outer auxiliary witness, and retained SmallWood V2 only for historical verification compatibility.
- [x] (2026-07-13) Rebuilt the Rust-to-Lean constraint map as the exact active/stable sparse linear tables plus the complete generated nonlinear expression AST, ordered roots, family spans, and program digest; the first summary-only map and semantic booleans are gone.
- [x] (2026-07-13) Mechanized accepted-proof extraction and AIR-row implementation equivalence from exact map evaluation under only the named deployed proof-system soundness boundary.
- [x] (2026-07-13) Rebuilt recursive cross-object identity and accepted-chain supply composition from the exact production projections; Rust now consumes every Lean transaction, identity, fee, coinbase, and claimed-supply fixture and rejects all named mutations.
- [x] (2026-07-13) Regenerated claims, blueprint, matrix, active-goal evidence, `DESIGN.md`, and `METHODS.md` with the exact theorem, call-graph, and retained-assumption delta; all independent policy checkers pass.
- [x] (2026-07-13) Re-ran the requested adversarial headless review and triggered the kill gate: three independently validated formal-assurance findings show that the generated 13/20 closure claim is not sound. The four provisional credits are invalid and no PR may be opened from this state.
- [x] (2026-07-13) Confirmed and locally fixed a separate production V3 no-grinding regression: the corrected production-relation test measured 123.724981 bits with 23 DECS openings, so V3 now uses 24 openings and fails closed below 128 bits while historical V2 retains its exact 23-opening verification profile. Focused V3 guard/profile tests and the full ignored V2 compatibility proof round trip passed.
- [x] (2026-07-13) Replaced the impossible raw-opening hash injectivity premise with collision resistance over the canonical 18 Goldilocks inputs actually absorbed by production Poseidon2. Lean now proves the `0`/field-modulus raw-limb alias explicitly and derives exact value/asset equality only under the executable canonical value/asset bounds; the matching Rust alias regression passes.
- [x] (2026-07-13) Parameterized the exact production map by the canonical 78 verifier fields and rejected wrapper/map substitution for every input/output activity pattern.
- [x] (2026-07-13) Refined exact accepted rows into equation-backed production spend-authorization, output-validity, and balance-conservation relations over one shared witness. The older toy `SmallWoodSemanticConstraintsSatisfied` path is not used as a production substitute.
- [x] (2026-07-13) Replaced the arbitrary geometry-only map bound with a generated 16-pattern verifier-map selector, compressed from 23 MB of duplicated maps to one 2.4 MB base-plus-patches artifact; Rust reconstruction, Lean elaboration, and the generator drift gate pass, including explicit zero-linear-table and stale-public-value rejection.
- [x] (2026-07-13) Bound each deployed proof map to the exact 78-field projection of its canonical `BoundPublicInputs` and `StatementFields`, and replaced the eight family-pass booleans with universal indexed linear/nonlinear equations plus equation-backed spend, output, and balance subrelations.
- [x] (2026-07-13) Removed caller-selected exact-table digests from the semantic map and proof theorem. The digest is now a separate conformance artifact; semantic acceptance reconstructs the complete map solely from canonical public values, while digest truncation and mismatch remain explicit audit-artifact rejection cases.
- [x] (2026-07-14) Replaced the final circular output-value consequence with 30 exact sparse-linear production note-hash bindings per active output, generated exact binding indices for all 16 activity masks, reconstructed the deployed 18-word Poseidon2 preimage in Lean, and derived value/asset equality only from primitive collision resistance over fully constrained accepted images.
- [x] (2026-07-14) Strengthened the fixed 13/20 release-policy evidence so the four credits require the final no-counterfeit theorem, exact output-hash map binding, and construction of the accepted production hash image; no denominator, threshold, or policy exception changed.
- [x] (2026-07-14) Removed every `native_decide` code-generation axiom from the credited four-track theorem dependency closure. The active-goal axiom audit now passes with only the allowed Lean kernel axioms, while the focused final modules compile in 21 seconds at approximately 1.2 GiB RSS.
- [x] (2026-07-14) Narrowed the final certificate to active SmallWood V3/Beta, added generated positive/negative version-scope conformance against the production default and native ingress manifest, and recorded historical V2/Beta replay as a coordinated-activation residual rather than silently changing testnet consensus.
- [x] (2026-07-14) Remediated the headless adversarial review findings in release command parsing and artifact provenance, descriptor-bound cross-platform packaging, malformed-proof reachability, exact receipt-root child verification, and app no-SSH disclosure behavior.
- [ ] Pass focused and aggregate Lean/Rust/adversarial/formal/release/native-smoke validation.
- [ ] Run a headless Codex Security branch-diff review and remediate every valid finding.
- [ ] Commit, push, open a draft PR to `main`, and drive every required final-head check green without merging or deploying.

## Surprises & Discoveries

- Observation: post-#200 native tx-leaf verification selected a backend from the transaction version and dispatched to the legacy verifier.
  Evidence: `protocol/versioning/src/lib.rs` mapped circuit 2 / crypto suite gamma to `Plonky3Fri`; `circuits/superneo-hegemon/src/lib.rs` passed that backend to `verify_transaction_proof_bytes_for_backend`; `tests::native_tx_leaf_artifact_round_trip` passed while asserting `Plonky3Fri`.

- Observation: `NodeConfig.supported_versions` did not constrain the native announced-block path.
  Evidence: its only native-node references were declaration and default initialization; native block import proceeded directly to artifact verification.

- Observation: the first production constraint map was not an exact map and the claimed refinement was circular.
  Evidence: `ProductionConstraintMap` carried only geometry, counts, and a digest; `exactProductionConstraintTableEvaluates` separately evaluated trusted semantic booleans, and the proof-system assumption concluded that same semantic-bearing predicate. A compiled Lean countermodel relabeled the map while preserving the claimed semantics.

- Observation: the first SmallWood proof format serialized all 1,158 auxiliary words used for private Merkle and policy checks.
  Evidence: the production proof round trip preserved 9,264 bytes of exact auxiliary field elements, including depth-32 paths and private policy roots.

- Observation: the first block-composition model and generated vectors did not bind the exact production object.
  Evidence: the Lean model omitted required production actions and proof identity inputs; Rust tests checked only fixture shape before constructing unrelated hard-coded transactions and supply data.

- Observation: the full formal gate still compiled the retired disclosure circuit through the default wallet and walletd dependency graphs even after the node graph was clean.
  Evidence: `wallet` enabled `disclosure-proofs` by default, `walletd` depended directly on `disclosure-circuit`, and both release builds therefore selected Plonky3 packages. The shipped graph gate now checks all three binaries, proof create/verify entry points fail closed, and walletd advertises the capability as disabled.

- Observation: `productionConstraintMapBoundB` accepts coherent non-production maps and does not derive the verifier-selected map from canonical public inputs.
  Evidence: Lean evaluated a map with substituted public values, zero linear constraints, empty linear tables, and a zero digest as production-bound while `productionConstraintMapAccepts` rejected it. The accepted-proof theorem remains instantiable with that map because `DeployedSmallWoodProof.exactMap` is free.

- Observation: the claimed AIR-to-semantics theorem reaches only a new record of eight generated-family Boolean evaluations, not the canonical transaction relation.
  Evidence: `production_smallwood_air_rows_are_implementation_equivalent` never constructs `SmallWoodSemanticConstraintsSatisfied`; the final block certificate requires `ProductionAcceptedTransactionRelation` and never invokes `accepted_proof_and_semantic_constraints_imply_transaction_relation` or the canonical no-theft theorem.

- Observation: the production note-opening collision-resistance premise is uninhabited.
  Evidence: openings differing only by a 64-bit limb `0` versus the Goldilocks modulus are unequal but have identical 18-word preimages after production modulo reduction. A focused Lean counterexample proved `not ProductionHashCollisionResistance spec` for every spec.

- Observation: production admission already prevents monetary and asset aliases even though arbitrary 32-byte note-opening limbs remain non-injective.
  Evidence: `NoteData::validate` bounds values by `MAX_NOTE_VALUE = 2^61 - 1` and requires canonical asset identifiers below the field modulus; the exact no-counterfeit consequence therefore needs canonical 18-field input binding and value/asset equality, not equality of all raw opening bytes.

- Observation: the V3 production relation outgrew the 23-opening no-grinding profile without updating the production test target.
  Evidence: after changing the existing test from diagnostic `Bridge64V1` to `DirectPacked64CommittedBindingsInlineMerkleSkipInitialMdsV2`, the repository estimator reported 123.724981 bits. Twenty-four openings report at least 128 bits, and the new production prove/verify guard rejects weaker geometry.

- Observation: the generated exact-table digest was embedded in `ProductionConstraintMap` even though Lean reconstructed the map using a digest supplied by the candidate itself.
  Evidence: a digest-only mutation could be reconstructed by `productionConstraintMapForCanonicalValues?` because the candidate digest was passed directly into template instantiation. The digest never participates in constraint evaluation, so it is now an audit-only `ProductionConstraintArtifact` field and no longer appears in the semantic map or accepted-proof theorem.

- Observation: the first repaired final theorem still packaged output value/asset equality directly inside a production collision-resistance premise.
  Evidence: `ProductionAcceptedOutputTraceCollisionResistance` could be satisfied by assuming the exact consequence the no-counterfeit theorem claimed to derive. The replacement carries every executed production binding and exact 18-word preimage; `ProductionPoseidon2HashCollisionResistance` states only primitive preimage uniqueness for equal accepted commitments.

- Observation: output note-hash secret rows do not all use the same packed lane.
  Evidence: the generator's independent 16-mask uniqueness check failed on an active output until value/asset bindings were read from chunk 0 and authorization-key bindings from chunk 2. The failed generation prevented an incorrect formal table from being accepted.

- Observation: the first exact-row proof chain depended transitively on `native_decide` facts for nonlinear DAG expansion and balance-root interpretation.
  Evidence: the standalone active-goal auditor rejected seven generated code-evaluation axioms in the final theorem. Replacing them with brute-force kernel `decide` peaked near 23 GiB and was stopped as non-viable for CI.

- Observation: preserving replay of the existing V2 SmallWood chain and forbidding every future permissionless V2 block are different consensus requirements.
  Evidence: the local prover and `kernel_manifest().binding_allowed` action-ingress gate select only V3, while native block replay keeps the V2 verifier executable for compatibility. A network-wide V2 retirement needs a deliberately coordinated activation height or checkpoint; this PR does not invent one.

## Decision Log

- Decision: Remove the legacy selectable proof backend rather than merely add a late native admission boolean.
  Rationale: a guard would leave the backend executable and would not satisfy the requested SmallWood-only deployed proof surface. Compiler-guided removal exposes every construction and verification dependency.
  Date/Author: 2026-07-13 / Codex

- Decision: Remove `p3-field`, `p3-goldilocks`, and every other Plonky3 package from the shipped `hegemon-node`, `wallet`, and `walletd` dependency graphs, using a Hegemon-owned Goldilocks implementation for unchanged field arithmetic and fail-closed tombstones for the retired disclosure proof calls.
  Rationale: retaining Plonky3 arithmetic or proof crates in any shipped executable path does not satisfy the operator's explicit boundary. A locked `cargo tree` gate across all release binaries prevents reintroduction while preserving consensus encodings, wallet storage records, and RPC method compatibility.
  Date/Author: 2026-07-13 / Codex

- Decision: Retract all four provisional closure credits until the adversarial countermodels are eliminated in source and the final generated conformance tests consume one exact production artifact.
  Rationale: a compiling theorem whose premise assumes its semantic conclusion, or a vector test that ignores its fixture, is not mechanized closure under the fixed 20-track policy.
  Date/Author: 2026-07-13 / Codex

- Decision: Keep primitive hash, PQ, random-oracle, PCS/FRI, and proof-system soundness assumptions explicit, but do not retain assumptions whose conclusions are exact constraint extraction, implementation equivalence, object identity, ordering completeness, or supply linkage.
  Rationale: primitive security is an external cryptographic boundary; the four target relations are repository-owned deterministic semantics and must be mechanized.
  Date/Author: 2026-07-13 / Codex

- Decision: State production note-hash collision resistance over canonical field-input lists and derive only the canonical value/asset equality needed for no-counterfeit accounting.
  Rationale: raw 32-byte limbs are intentionally reduced modulo Goldilocks and are therefore not injective. Requiring raw-opening equality is false, while canonical input collision resistance matches the executable hash and preserves exact monetary/asset binding under existing admission bounds without changing runtime bytes.
  Date/Author: 2026-07-13 / Codex

- Decision: Encode all 16 input/output activity shapes as exact patches over one generated baseline map rather than duplicating the complete nonlinear program and sparse table sixteen times.
  Rationale: the generator proves every reconstructed map byte-for-byte equal to the verifier-derived Rust map on independent probes and production fixtures, while the compressed Lean module builds at 6.4 GiB peak RSS instead of exceeding practical CI memory with the duplicated artifact.
  Date/Author: 2026-07-13 / Codex

- Decision: Treat the BLAKE3 exact-table digest as conformance metadata, not semantic proof input.
  Rationale: Lean structurally carries and evaluates every sparse-linear entry and nonlinear expression/root. Accepting a caller-provided digest adds no semantic evidence and creates a misleading self-authentication path. The Rust vectors still compare the production digest exactly, but the theorem reconstructs the semantic map from canonical public values alone.
  Date/Author: 2026-07-13 / Codex

- Decision: State production transaction semantics as the complete generated equation system partitioned into spend, output, balance, range, authorization, and Poseidon families over one witness, rather than route through the older toy semantic model.
  Rationale: the older model uses non-production helper hashes and cannot honestly establish implementation equivalence. The generated relation is the executable AIR semantics; the retained cryptographic assumptions are only proof-system soundness and production-hash collision resistance.
  Date/Author: 2026-07-13 / Codex

- Decision: Make output commitment binding an explicit accepted-image theorem instead of a field-equality premise hidden inside a named collision-resistance assumption.
  Rationale: the production map already contains the exact sparse constraints needed to reconstruct all three Poseidon2 chunks. Carrying their execution into an 18-word image makes value/asset equality a theorem consequence and leaves only primitive collision resistance at the final boundary.
  Date/Author: 2026-07-14 / Codex

- Decision: Credit the exact production nonlinear family equations and independent semantic-program binding directly, rather than transitively expanding the full 11,604-node DAG through `native_decide`.
  Rationale: exact proof evaluation already yields every indexed equation over one witness, and `productionSemanticProgramBoundB` binds the semantic prefix independently. The direct relation is kernel-checkable, preserves spend/output/balance and Poseidon family coverage, removes code-generation axioms, and stays within practical CI memory.
  Date/Author: 2026-07-14 / Codex

## Context and Orientation

The active transaction frontend and verifier are in `circuits/transaction/src/smallwood_frontend.rs`, `smallwood_semantics.rs`, and `smallwood_engine.rs`. Native tx-leaf wrapping is in `circuits/superneo-hegemon/src/lib.rs`; canonical claim, batch, recursive, and DA binding are in `consensus/src/proof.rs`; native action ordering and supply replay are in `node/src/native/block_flow.rs` and `node/src/native/node_impl.rs`.

The formal transaction boundary is in `formal/lean/Hegemon/Transaction/SmallWoodSemanticClosure.lean` and `SmallWoodNoCounterfeit.lean`. Claim and batch bindings are in `TxValidityClaimMatching.lean` and `Consensus/ProvenBatchBinding.lean`; supply replay is in `Consensus/SupplyInvariant.lean`. The fixed closure policy and score are enforced by `scripts/hegemon_formal_core` and `config/highest-standard-formal-verification-matrix.json`.

## Plan of Work

First, delete the legacy backend identity and version mapping, make transaction construction and verification unconditionally SmallWood, and migrate native/backend fixtures so no accepted artifact or test selects the removed backend. Use workspace compilation and focused tests to find and remove every stale call site. Preserve wire decoding only where rejecting historical bytes requires a reserved-value error; do not retain a verifier.

Second, define a production-map artifact generated from the actual SmallWood frontend shape and linear-constraint builder. It must enumerate every relevant row family, term offset/index/coefficient/target encoding, public statement field, wrapper field, proof/receipt/claim identity, ordered transaction field, DA root input, and supply input. Lean owns the corresponding typed model and emits accepted plus omit/reorder/substitute/duplicate/wrap/truncate/mismatch vectors; Rust compares those vectors against production functions.

Third, replace `SmallWoodExactConstraintExtractionAssumption` with a proof-system soundness boundary whose conclusion is satisfaction of the exact production relation, then prove the deterministic refinement from that relation to `ProductionSmallWoodSemanticConstraintsSatisfied`. Prove the Rust builder map equal to the Lean sparse linear tables and nonlinear expression/root program for every active row and field, not by a caller-populated boolean certificate. Replace the toy modulo-65537 output commitment with the production note-opening hash relation under an explicit production-hash collision-resistance assumption.

Fourth, introduce concrete canonical records for proof, receipt, claim, recursive batch, ordered transactions, DA encoding, coinbase, fees, burns, and supply step. Prove production admission projections force equality of these records and use that equality to compose transaction no-theft into accepted-chain supply conservation. Add adversarial identity mutations for omission, ordering, substitution, duplication, truncation, and mismatched accounting.

Fifth, update the fixed policy evidence to close exactly the four named tracks only after their final theorem identities elaborate with no new unwaived axioms. Update architecture/method docs and all generated evidence. Run every validation command from the request, including the complete formal-core final success line and isolated temporary native node smoke because runtime code changes.

Finally, run the Codex Security diff workflow headlessly, fix findings, commit intentionally, push, open a draft PR, and monitor the final head until every required GitHub check is green. Do not merge, deploy, restart existing nodes, or alter any persistent chain data.

## Validation and Acceptance

Acceptance requires: aggregate `lake build Hegemon`; focused module/generator builds; zero new unwaived axiom dependencies; generated vector and Rust conformance suites; all adversarial mutations; `bash scripts/check_formal_core.sh` through `=== Hegemon formal-core gate passed ===`; claims/blueprint/matrix/goal checkers; `cargo fmt --all -- --check`; `git diff --check`; strict lints; affected transaction/backend/consensus/node tests; locked release node build; an isolated `--dev --tmp` smoke; a clean headless Security diff review; a draft PR; and all required final-head GitHub checks green.

The closure inventory must report at least 13/20 (65%) with the fixed denominator and policy unchanged. The final theorem may retain only named primitive/proof-system cryptographic assumptions and must not retain assumptions for the four closed relations or their spend/output/balance/ordering/accounting consequences.

## Outcomes & Retrospective

The initial kill gate correctly rejected the first 13/20 claim. The three blockers it found have since been removed: canonical public values select one exact 16-pattern map; the generated linear and nonlinear equations, not family booleans, provide the production transaction relation on one witness; and every active output now carries 30 executed production bindings into an exact 18-word Poseidon2 image whose value/asset consequence is derived from primitive collision resistance. A subsequent adversarial pass also removed the candidate-supplied digest from the semantic map and the circular output-equality premise from the final theorem.

Focused Lean elaboration, generated-table drift, vector generation, and the Rust every-row conformance test pass after those repairs. The goal remains in progress until aggregate validation, final headless Security review, intentional commit/push, draft PR creation, and all final-head GitHub checks complete.

No merge, deployment, persistent-node action, or genesis change has occurred. The branch remains isolated and uncommitted while final evidence and validation are completed.

Plan amendment, 2026-07-13: execution resumed after the validated kill-gate report. The continuation order is canonical note-hash repair, transaction-parameterized verifier map, exact-row production relation, regenerated evidence, aggregate validation, headless security review, and only then draft-PR publication.

Plan amendment, 2026-07-14: the final formal remediation makes the output-hash lane explicit: generated uniqueness over all 16 activity masks, 30 executed sparse bindings per active output, an exact 18-word accepted image, and primitive-only Poseidon2 collision resistance. Validation, final headless review, package regeneration, and PR publication remain outstanding.
