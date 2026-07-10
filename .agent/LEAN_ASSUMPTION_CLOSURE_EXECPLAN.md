# Close Hegemon's Lean Assumption Boundary

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds. This document is maintained in accordance with `.agent/PLANS.md`.

## Purpose / Big Picture

Hegemon already has broad Lean coverage for transaction admission, supply accounting, replay, commitment publication, privacy projections, and release policy. The remaining risk is depth: several top-level certificates obtain no-theft and no-counterfeiting facts only after accepting broad propositions named proof-system soundness, witness extraction, parser equivalence, or complete native-node equivalence. The current completion percentage treats explicit assumptions as completed coverage, which is useful inventory but is not assumption discharge.

After this plan is complete, the repository will expose two separate measurements: formal surface coverage and mechanized assumption closure. The deployed SmallWood statement will have a machine-checked profile and adversarial mutation contract, concrete AIR constraint satisfaction will imply the Hegemon transaction relation while cryptographic PCS and random-oracle security remain named assumptions, accepted block proof artifacts will be shown unable to bypass verified transaction claims, the supply theorem will compose those facts into one accepted-chain no-counterfeit boundary, and the security-critical native byte-to-publication path will use a scoped refinement certificate instead of a single undifferentiated complete-node assumption. The active native lattice backend's exact algebraic and canonicalization claims will be mechanized without claiming a hidden-witness extractor or general proof-of-knowledge soundness.

The result is observable by running `bash scripts/check_formal_core.sh`. The gate must regenerate the new Lean vectors, run production Rust conformance and mutation tests, validate both completion measurements, reject local proof placeholders or undeclared axioms, and finish with `=== Hegemon formal-core gate passed ===`. The shipped node and wallet behavior must remain wire- and testnet-compatible because this work changes proof evidence and test gates, not consensus serialization or accepted runtime rules.

## Progress

- [x] (2026-07-10 12:00Z) Created goal and branch `codex/lean-assumption-closure`; confirmed GitHub CLI authentication and preserved unrelated untracked app build directories without staging them.
- [x] (2026-07-10 12:05Z) Reviewed `.agent/PLANS.md`, `DESIGN.md`, `METHODS.md`, the formal claims ledger, completion matrix, residual-assumption roadmap, SmallWood soundness envelope, transaction soundness boundary, supply invariant, materialized native refinement, native backend theorem note, and formal-core gate.
- [x] (2026-07-10 16:20Z) Implemented `SmallWoodSemanticClosure`: exact active input, output, public-shape, and balance rows imply spend authorization, output binding, valid balance, and `AcceptedTransactionRelation`; the accepted-proof extraction premise concludes only existence of an exact satisfying row record.
- [x] (2026-07-10 16:35Z) Added the generated active-profile contract and production Rust conformance suite for all 16 single-field mutations, including both zero-grinding fields, arithmetization, opening geometry, and Poseidon geometry; added targeted inline-Merkle mutation cases to the red-team campaign.
- [x] (2026-07-10 16:45Z) Added `SmallWoodNoCounterfeit`, composing exact semantics, transaction-claim matching, proven-batch/recursive admission, fee/native-delta binding, and accepted-chain supply replay into one no-counterfeit certificate.
- [x] (2026-07-10 16:55Z) Audited the native refinement boundary and recorded the existing scoped raw-ingress, exact-decode, canonical-publication, reorg, and startup row-equivalence modules as closed tracks; retained arbitrary parser internals and complete native-node equivalence as a distinct open track rather than duplicating the existing certificates.
- [x] (2026-07-10 17:10Z) Added `NativeBackendAlgebra` and Lean-to-Rust vectors for reducer bounds, nonzero challenge polynomials, exact 312/305-bit arithmetic, dimensions, Euclidean bounds, coefficient canonicalization, digit bounds, and deterministic fold-data uniqueness. Kept finite-field irreducibility/unit discharge, collision reduction, flattening, external cryptanalysis, and proof-of-knowledge explicitly open.
- [x] (2026-07-10 17:20Z) Split the formal matrix into 100% formal-surface coverage and 10/18 (`55.5556%`) equal-count mechanized assumption closure; formal-core recomputes both, rejects malformed/open-without-work tracks, and grants no closure credit for merely naming an assumption.
- [x] (2026-07-10 17:32Z) Updated `DESIGN.md`, `METHODS.md`, formal README, SmallWood/native theorem notes, claims, blueprint, matrix, and this plan with exact achieved and residual boundaries.
- [x] (2026-07-10 18:45Z) Ran targeted Lean/Rust mutation tests, aggregate `lake build Hegemon`, the complete formal-core gate, CI-mode proving red team, formatting and JSON/shell metadata checks, release node build, deterministic review-package parity, and an isolated release-node mining/RPC/SIGTERM smoke. The separate live testnet listener remained untouched.
- [ ] Run a Codex Security branch-diff scan against `origin/main`; remediate every valid finding and rerun affected gates.
- [ ] Commit only intended files, push the branch, open a draft PR against `main`, and keep iterating until every required GitHub check is green. Do not merge.

## Surprises & Discoveries

- Observation: the current `100.0` completion value measures theorem/gate coverage plus explicit assumption accounting, not discharged assumptions.
  Evidence: `config/highest-standard-formal-verification-matrix.json` permits a row to reach 100 when remaining proof, parser, storage, bridge, or native-node obligations are explicit certificate fields.

- Observation: the current SmallWood envelope already isolates six residual classes, so this plan can shrink the boundary without rewriting downstream publication theorems.
  Evidence: `SmallWoodProofSystemResidualAssumptions` names AIR constraint soundness, PCS opening binding, transcript random-oracle behavior, Merkle/commitment hash security, witness extraction completeness, and verifier implementation equivalence separately.

- Observation: the active native fold layer is intentionally a deterministic canonicalization and binding construction, not a general hidden-witness argument.
  Evidence: `docs/crypto/native_backend_formal_theorems.md` states that accepted folds have one deterministic recomputation path and explicitly disclaims a hidden-witness extractor and Neo/SuperNeo CCS soundness claim.

- Observation: the requested scoped raw-ingress, reorg, startup, and canonical-publication refinement was already present and stronger than the broad residual wording suggested.
  Evidence: `RawIngressFullBytePublicationSurface`, `NativePublicationRowEquivalence`, `CanonicalReorgChainAdmission`, and `CanonicalStateReload` already expose exact decoded/materialized/planned/canonical row equality on the covered paths. The honest remaining gap is arbitrary parser internals and complete Rust node refinement.

- Observation: assuming all of `validPublicInputShape` inside the new semantic record would have made input/output validity circular, and requiring inactive private output rows to be zero would have been stronger than production.
  Evidence: the final `smallwoodPublicShapeCoreValid` contains only independent shape/scalar/stablecoin facts, while input/output validity is derived from exact rows; inactive outputs constrain public commitment/hash fields only, matching the production relation.

- Observation: artifact kind and acceptance alone did not establish recursive no-bypass behavior.
  Evidence: the final certificate also requires exact transaction-claim matching plus `ProvenBatchBinding` route, proof-kind, and acceptance facts before deriving the recursive SmallWood no-counterfeit result.

## Decision Log

- Decision: Keep primitive cryptographic hardness as named assumptions, but require Lean to prove the semantic implication from exact accepted AIR constraints to Hegemon transaction validity.
  Rationale: proving a random oracle, PCS, or hash primitive secure inside this repository is neither credible nor necessary. Proving that the exact constraint system enforces the intended ledger relation is repository-owned work and closes the specification attack class.
  Date/Author: 2026-07-10 / Codex

- Decision: Do not change consensus serialization, proof bytes, chain versioning, genesis, or runtime admission behavior in this plan unless a validated security defect requires it.
  Rationale: the work must merge without resetting or partitioning the existing testnet. Evidence-only and test-gate changes are sufficient for the planned assurance improvements.
  Date/Author: 2026-07-10 / Codex

- Decision: Use one declarative profile and constraint-family manifest as the cross-language source of truth, with Lean-generated vectors checked against production Rust.
  Rationale: hand-maintained prose and duplicated constants permit benchmark/spec drift. A checked manifest makes changed geometry, opening counts, or omitted constraint families fail formal-core.
  Date/Author: 2026-07-10 / Codex

- Decision: Report formal coverage and assumption closure independently.
  Rationale: a coverage score should reward explicit residual accounting, while a closure score must not grant credit for an unresolved mechanized-refinement proposition. Keeping both prevents misleading progress while preserving the useful coverage inventory.
  Date/Author: 2026-07-10 / Codex

- Decision: Count mechanized closure tracks equally and require every open track to state concrete remaining work.
  Rationale: the previous weighted surface rows answer a different question. An equal-count inventory is auditable, avoids subjective pseudo-precision, and makes additions/removals visible in review.
  Date/Author: 2026-07-10 / Codex

- Decision: Keep accepted-proof extraction and production AIR-row implementation equivalence as two separate open tracks.
  Rationale: a sound proof system over the wrong relation and a correct relation behind an unsound extractor are independent failure classes. Combining them would recreate the opaque assumption this plan is intended to remove.
  Date/Author: 2026-07-10 / Codex

- Decision: Do not claim the native ring irreducibility, collision reduction, flattening, or proof-of-knowledge argument as mechanized.
  Rationale: this branch checks the exact arithmetic and canonicalization model, but those deeper algebraic and cryptographic arguments are not present as Lean proofs. The documentation and matrix must preserve that boundary.
  Date/Author: 2026-07-10 / Codex

## Outcomes & Retrospective

Implementation and local acceptance validation are complete; security review and publication are in progress. The branch closes the exact SmallWood semantic implication, active profile drift/no-grinding contract, verified-claim/recursive admission composition, accepted-chain supply composition, scoped native publication/reorg/startup tracks, native challenge arithmetic, fold canonicalization model, digit/Euclidean arithmetic, and existing statement/wrapper binding. It deliberately leaves eight tracks open: accepted-proof extraction, complete SmallWood AIR-row implementation equivalence, arbitrary parser/full-node refinement, native irreducibility/unit discharge, collision reduction/flattening/proof-of-knowledge, cryptographic privacy games, positive external bridge receipt soundness, and DA/storage runtime semantics.

Local acceptance evidence:

    cargo fmt --all --check
    cargo fmt --manifest-path scripts/hegemon_formal_core/Cargo.toml -- --check
    git diff --check
    lake build Hegemon
    bash scripts/check_formal_core.sh
    HEGEMON_REDTEAM_MODE=ci bash scripts/run_proving_redteam.sh
    make node

The formal-core gate ended with `=== Hegemon formal-core gate passed ===`; the Lean axiom report found no temporary axioms, unwaived dependencies, or budget violations; and the CI-mode red team passed all nine campaigns. The release binary started on temporary dev state with no seeds or peers, answered RPC, mined to height 4, reported its mining sync gate open, and exited cleanly after SIGTERM. No changed path is under `consensus/`, `network/`, `node/`, runtime serialization, chain-spec, or genesis code. The regenerated native review package passed its SHA-256 check and deterministic package/claim parity. Security-scan results, final commit ids, and the draft PR URL will be appended after review and publication.

## Context and Orientation

Lean source lives under `formal/lean/Hegemon`. `formal/lean/Hegemon/Transaction/SmallWoodVerifierSoundnessEnvelope.lean` is the current transaction proof review boundary. It composes wrapper, public-statement, transcript, authorization-row, input/output-row, balance, and AIR-final-row facts, but its production certificate retains proof-system and implementation-equivalence propositions. `formal/lean/Hegemon/Transaction/AcceptedTransactionSoundness.lean` defines the target accepted transaction relation. `formal/lean/Hegemon/Transaction/ProofSystemBoundary.lean` maps deployed verifier facts into no-theft and per-asset conservation facts. `formal/lean/Hegemon/Consensus/SupplyInvariant.lean` lifts transaction-level native delta authorization through claimed supply steps. `formal/lean/Hegemon/Native/MaterializedConsensusDaBlobRefinement.lean` carries these facts through native publication while naming parser, proof, storage, availability, and complete-node residuals.

Production SmallWood code lives in `circuits/transaction/src/smallwood_frontend.rs`, `circuits/transaction/src/smallwood_engine.rs`, and `circuits/transaction/src/smallwood_semantics.rs`. The frontend constructs the packed statement and linear constraints; the engine commits, proves, and verifies; the semantic kernel validates the relation-specific rows. The active backend is `DirectPacked64CompactBindingsInlineMerkleSkipInitialMdsV1`. Its current no-grinding note is `docs/crypto/tx_proof_smallwood_no_grinding_soundness.md`.

The block-level native proof path lives in `circuits/superneo-hegemon` and `circuits/superneo-backend-lattice`, with admission and publication in `consensus` and `node/src/native`. Transaction artifacts are individually verified and then bound into ordered claims consumed by receipt-root and recursive-block artifacts. The new Lean theorem must preserve that architecture and prove that block artifacts cannot replace or invent verified transaction claims.

`scripts/check_formal_core.sh` is the aggregate local and CI gate. It builds Lean, generates vectors into temporary files, passes those files to focused Rust tests through environment variables, validates the claims and blueprint ledgers, checks axiom dependencies, and runs release posture checks. New formal modules and generators must be imported by `formal/lean/Hegemon.lean`, declared in `formal/lean/lakefile.lean` when they expose executables, represented in the claims ledger and blueprint, and invoked by this script.

## Plan of Work

First, introduce a SmallWood semantic closure module. Define concrete records for the exact active public profile, per-input accepted constraint rows, per-output accepted constraint rows, and balance/AIR rows. The semantic closure predicate must require exact index-aligned projection to the canonical public statement and witness lists. Prove by list induction that accepted input rows imply `authorizeInputSlots`; prove that accepted balance rows imply `validBalance` and public authorized deltas; prove output rows bind every active commitment and ciphertext hash and zero every inactive row. Compose those results with the existing canonical statement surface to derive `AcceptedTransactionRelation` and `CanonicalProofSystemNoTheftBoundaryFacts`. The only incoming proof-system premise should be a narrowly worded cryptographic extraction premise: an accepted SmallWood proof yields a witness satisfying this exact constraint predicate. It must not directly assert transaction authorization or balance validity.

Second, make the active profile and constraint inventory executable. Lean will own the expected arithmetization identifier, public-value count, row count, packing factor, effective degree, opening counts, zero grinding bits, transcript-domain/profile binding requirements, distinct-opening requirement, and the required security constraint families. A generator will emit accepted and adversarially mutated cases. Rust will reconstruct the values from the production active profile and constraint builder. The gate must reject omitted families, duplicate names, changed geometry, nonzero grinding, duplicate opening acceptance, unbound transcript/profile data, and mutations to input authorization, Merkle, nullifier, output commitment, output ciphertext hash, native balance, stablecoin selector, and stablecoin metadata constraints.

Third, add an accepted-chain no-counterfeit composition module. It will consume the concrete SmallWood semantic closure, exact transaction-claim matching, native tx-leaf admission, proven-batch/receipt-root/recursive-block binding, coinbase accounting, and supply-step replay. The theorem will state that every accepted canonical prefix preserves authorized native supply and per-asset isolation. Primitive hash, PCS, transcript, and backend cryptographic assumptions remain explicit. A sibling rejection theorem and generated vectors will cover forged claimed supply, mismatched verified claims, fee/native-delta mismatch, unauthorized non-native mint, and recursive artifact mismatch.

Fourth, split native refinement into named components. Define a scoped certificate for exact pending-action and block-action decode, semantic action-hash projection, proof verification and claim matching, replay planning, atomic commit/durability admission, canonical index publication, reorg replay, and startup reload. Existing theorems and blueprint order gates will provide most fields. The materialized transfer review will consume this scoped certificate and retain a smaller residual record for parser implementation internals, storage behavior below the admitted durability barrier, and any native path not covered by the certificate. No runtime behavior changes are expected.

Fifth, add the native backend algebra module. Work over the concrete Goldilocks modulus and prove the exact nonzero low-degree challenge condition, retaining invertibility under a named irreducibility/low-degree-unit premise. Define deterministic fold-data recomputation and prove accepted data are unique, encode the `3^5 / 2^320` challenge-point bound and `128`-leaf composition loss as checked integer inequalities, and expose the exact boundary as canonicalization plus named irreducibility, BK-MSIS, random-oracle, estimator, and external-review assumptions. Do not introduce a witness-extraction theorem or describe the unmechanized factorization/reduction as closed.

Sixth, change measurement and documentation. Keep the existing coverage percentage for compatibility, add a mechanized assumption-closure percentage and open-track inventory, and make the checker recompute both. Update the release certificate and roadmap only where needed to expose the narrower records. Update `DESIGN.md`, `METHODS.md`, `formal/lean/README.md`, claims, and blueprint with exact wording that cannot be mistaken for unconditional cryptographic security.

Finally, validate and publish. Run targeted Lean builds and Rust tests after each milestone, then the complete formal-core gate, workspace formatting, metadata validation, relevant node tests, a release node build, and a local compatibility smoke test using an isolated temporary chain. Confirm the diff contains no consensus encoding, genesis, version, or network-identity changes. Run a Codex Security diff scan against `main`, fix every validated finding, commit the intended files, push the branch, open a draft PR, and monitor/fix GitHub Actions until every required check is green.

## Concrete Steps

Work from `/Users/pldd/Projects/Reflexivity/Hegemon` on branch `codex/lean-assumption-closure`.

Build a focused Lean module from `formal/lean` with:

    lake build Hegemon.Transaction.SmallWoodSemanticClosure

Generate and check the active SmallWood contract with commands that will be added to `scripts/check_formal_core.sh`. The expected result is that the Lean generator produces valid JSON and the production Rust test reports one passing generated-vector test containing both accepted and mutated cases.

Build the native backend algebra and accepted-chain modules with:

    lake build Hegemon.Native.NativeBackendAlgebra Hegemon.Transaction.SmallWoodNoCounterfeit

Run the complete gate from the repository root with:

    bash scripts/check_formal_core.sh

The required terminal line is:

    === Hegemon formal-core gate passed ===

Run runtime compatibility checks without touching the user's existing node data:

    cargo fmt --all --check
    cargo test -p transaction-circuit --lib smallwood -- --nocapture
    cargo test -p consensus --lib -- --nocapture
    cargo test -p hegemon-node --lib native -- --nocapture
    make node
    HEGEMON_MINE=1 ./target/release/hegemon-node --dev --tmp

The exact focused test filters may be narrowed as implementation reveals package names, but the final plan revision must record every command actually used and its result. The temporary node must start, answer RPC, and mine without reading or modifying the persistent testnet directory.

## Validation and Acceptance

The SmallWood milestone is accepted only when an accepted concrete constraint witness yields `AcceptedTransactionRelation` and no-theft facts without a premise whose conclusion already states spend authorization, valid balance, or per-asset conservation. The cryptographic extraction premise must mention only existence of an exact satisfying constraint witness.

The adversarial milestone is accepted only when production Rust matches the complete Lean-generated profile and required-family manifest and every generated omission or mutation case rejects. A profile or constraint-family change must fail formal-core until Lean, Rust, security arithmetic, and documentation are updated together.

The no-counterfeit milestone is accepted only when one theorem composes verified transaction claims, authorized deltas, coinbase, fees, burns, supply replay, and block artifact matching. The theorem and claim text must enumerate remaining cryptographic assumptions and must not claim external review or unconditional proof-system soundness.

The native refinement milestone is accepted only when the broad residual record is split into named covered and remaining components and the production blueprint gates demonstrate each covered component on mined, announced/synced, reorg, and startup paths.

The whole plan is accepted only when focused tests, `bash scripts/check_formal_core.sh`, formatting, metadata checks, release build, isolated runtime smoke, security diff scan, and all required GitHub Actions checks pass. The pull request must remain draft or unmerged for the user to decide.

## Idempotence and Recovery

All generators write to temporary files and may be rerun safely. Focused Lean and Rust builds may be repeated. The isolated node smoke uses `--tmp` and must not reuse `~/.hegemon-node-testnet-*` or any operator base path. If a generated-vector test fails, keep the generated file long enough to inspect it, fix the source of truth, and rerun; do not edit generated output manually.

The unrelated `hegemon-app/dist-canary-*` directories existed before this branch and are not part of the PR. Stage explicit paths only. Never use `git add -A`, destructive resets, or persistent testnet resets. If GitHub Actions fails, inspect the exact job log, reproduce locally where possible, amend with a new commit, and push normally.

## Artifacts and Notes

Initial branch evidence:

    main at 53cad173b
    branch codex/lean-assumption-closure
    GitHub repository Pauli-Group/Hegemon
    default branch main
    gh authenticated as pldallairedemers

Initial claim inventory:

    enforced                 112
    research_only              8
    candidate_under_review      1
    disabled_fail_closed        1

The highest-value open transaction risks are `spend-authorization-soundness-not-mechanized`, `accepted-transaction-soundness-assumptions-not-discharged`, and `deployed-tx-verifier-soundness-not-discharged`. The native backend remains `candidate_under_review`; this plan does not silently promote it.

## Interfaces and Dependencies

New Lean modules should use existing repository types rather than duplicate public transaction or supply models. `SmallWoodSemanticClosure` must consume `PublicInputShape`, `InputSpendWitness`, `BalanceWitness`, `BalanceSlot`, `CanonicalTxStatementSurface`, and the existing SmallWood input/output/balance/AIR surfaces. The accepted-chain module must consume `SupplyInvariant` and existing consensus/native artifact admission facts. The native algebra module must remain independent of runtime Rust and model only the exact public algebra and deterministic acceptance contract.

New Rust conformance code belongs beside existing SmallWood frontend/engine tests unless a small shared manifest type is needed. It must query production profile constructors and constraint builders rather than duplicate expected constants in tests. The Lean generator communicates through JSON and an environment variable following existing `HEGEMON_LEAN_*_VECTORS` patterns.

The formal-core checker under `scripts/hegemon_formal_core` owns matrix and claims validation. Extend its typed JSON model and tests for the second measurement rather than adding an unchecked shell-only calculation. Preserve backward parsing only if CI or release tooling still consumes older matrix fixtures.

Revision note (2026-07-10): Created the plan after reviewing the current formal/runtime boundary. It deliberately prioritizes assumption reduction and drift failure over additional certificate-only theorem count.
