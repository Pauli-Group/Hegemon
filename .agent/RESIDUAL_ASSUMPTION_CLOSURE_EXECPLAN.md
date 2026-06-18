# Close Residual Assumptions With Mechanized Refinement

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds. This document follows `.agent/PLANS.md`.

## Purpose / Big Picture

Hegemon's formal matrix now reaches 100% by making remaining assumptions explicit. The next standard is to reduce the non-standard assumptions themselves. After this plan is complete, parser, native-node, proof-system, and bridge gaps will be mechanized refinement obligations with Lean theorem surfaces and Rust conformance gates; primitive cryptographic hardness will stay as named assumptions; and DA retention, storage durability, global privacy, release infrastructure, scanner completeness, and performance preservation will be enforced by fail-closed gates and monitoring rather than informal prose.

The visible outcome is that `bash scripts/check_formal_core.sh` fails if any residual is downgraded from one of three permitted categories: mechanized refinement work, named cryptographic assumption, or fail-closed system-model assumption. A developer can inspect `formal/lean/Hegemon/Release/AssumptionClosureRoadmap.lean`, this ExecPlan, `config/formal-security-claims.json`, `config/formal-security-blueprint.json`, and `config/highest-standard-formal-verification-matrix.json` to see the status.

## Progress

- [x] (2026-06-18 18:55Z) Added `formal/lean/Hegemon/Release/AssumptionClosureRoadmap.lean`, a Lean theorem surface that classifies residuals into mechanized parser/native/proof/bridge tracks, named primitive cryptographic assumptions, and fail-closed system-model assumptions.
- [x] (2026-06-18 18:56Z) Imported the new module through `formal/lean/Hegemon.lean` and built `cd formal/lean && lake build Hegemon.Release.AssumptionClosureRoadmap Hegemon`, which completed 173 jobs successfully.
- [x] (2026-06-18 19:03Z) Registered the new roadmap in `config/formal-security-claims.json` and `config/formal-security-blueprint.json`.
- [x] (2026-06-18 19:05Z) Updated `DESIGN.md`, `METHODS.md`, `formal/lean/README.md`, and `config/highest-standard-formal-verification-matrix.json` so the status is discoverable without reading Lean source.
- [x] (2026-06-18 19:11Z) Ran metadata gates: `jq empty`, `check-claims`, `check-blueprint`, and `git diff --check` all passed.
- [x] (2026-06-18 19:25Z) Ran `bash scripts/check_lean_formal.sh`; it passed with 2413 theorem declarations, 1056 axiom-free theorem declarations, 1357 declarations depending only on waived kernel axioms, and zero temporary axiom theorem leaks.
- [x] (2026-06-18 19:28Z) Committed the roadmap slice as `d04a4b95 Classify residual assumptions for closure`.
- [x] (2026-06-18 19:55Z) Added `Hegemon.Release.SystemModelAssumptionGate`, `config/system-model-assumption-gates.json`, and the formal-core `check-system-model-gates` command so DA/storage/global-privacy/release/scanner/performance residuals are release-blocking fail-closed evidence gates instead of prose.
- [x] (2026-06-18 20:08Z) Validated the system-model gate slice: targeted Lean build passed over 174 jobs; `bash scripts/check_lean_formal.sh` passed with 2417 theorem declarations and zero temporary axiom theorem leaks; `cargo test --quiet --manifest-path scripts/hegemon_formal_core/Cargo.toml` passed 121 tests; `check-system-model-gates`, `check-formal-inventory`, `check-claims`, `check-blueprint`, JSON validation, rustfmt check, and `git diff --check` passed.
- [x] (2026-06-18 20:10Z) Committed the system-model gate slice as `990288aa Gate system-model assumptions fail-closed`.
- [x] (2026-06-18 20:08Z) Added a native metadata bincode parser-oracle milestone: production current/legacy `NativeBlockMeta` exact decode is checked against an independent fixint/full-consumption/canonical-reencode oracle over valid, trailing, truncated, noisy, oversized, action-overrun, payload-overrun, and miner-field-overrun byte cases, and `scripts/check_formal_core.sh` now runs that gate.
- [x] (2026-06-18 20:08Z) Validated the native metadata parser-oracle slice: JSON validation, rustfmt check, focused native metadata oracle test, shell syntax, whitespace check, formal inventory, `check-claims`, and `check-blueprint` all passed; blueprint now records 622 falsification cases with the new parser-oracle case.
- [ ] For later milestones, replace each mechanized-track proposition with deeper theorem packages and generated Rust conformance gates.

## Surprises & Discoveries

- Observation: The highest-standard completion certificate already has broad external assumption fields, but it did not classify which residuals are supposed to be closed by further mechanization versus which are legitimate cryptographic or system-model assumptions.
  Evidence: `Hegemon.Release.HighestStandardCompletionCertificate.ExternalSecurityAssumptionBundle` carries parser, proof, storage, DA, native-node, primitive crypto, privacy, bridge, release, and performance fields in one bundle.

## Decision Log

- Decision: Add a new release-level roadmap module instead of editing the completion certificate directly.
  Rationale: The completion certificate is the 100% closure artifact; changing its shape would ripple through many existing theorem calls. A sibling roadmap theorem keeps the current certificate stable while making the next assurance frontier machine-checkable.
  Date/Author: 2026-06-18 / Codex

- Decision: Treat parser/native/proof/bridge residuals as mechanized refinement tracks, not as acceptable permanent assumptions.
  Rationale: These are implementation-equivalence gaps inside the Hegemon codebase. They should be burned down by Lean specs, generated vectors, and Rust gates.
  Date/Author: 2026-06-18 / Codex

- Decision: Treat primitive cryptography and proof-system hardness as named assumptions until full cryptographic reductions are available.
  Rationale: Proving ML-KEM, ML-DSA, BLAKE-family transcript security, STARK/FRI/PCS soundness, ciphertext indistinguishability, and OS RNG quality inside the repo is a cryptographic research project. The honest highest standard is to name, review, and gate them.
  Date/Author: 2026-06-18 / Codex

- Decision: Treat DA retention, storage/fsync behavior, global privacy, release infrastructure, scanner completeness, and performance preservation as system-model assumptions with fail-closed gates and monitoring.
  Rationale: These depend on operators, networks, disks, cloud hosts, GitHub enforcement, advisory feeds, traffic behavior, and benchmarking. Lean can prove fail-closed policy and checked evidence consumption, not universal environmental honesty.
  Date/Author: 2026-06-18 / Codex

## Outcomes & Retrospective

This first slice converts the user-facing classification into a Lean theorem surface and makes the next milestones explicit. It does not yet close the deep parser/native/proof/bridge gaps; it prevents them from being mislabeled as ordinary cryptographic assumptions.

The second slice starts closing the fail-closed system-model bucket by adding a theorem-backed release gate and formal-core checker for DA retention, storage durability, global privacy boundary, release infrastructure, dependency scanner completeness, and performance budget monitoring evidence.

The third slice starts burning down the parser mechanized-refinement bucket at a concrete trust boundary: native metadata exact decode now has an independent arbitrary-byte/mutation oracle gate. This narrows parser drift around current-first/legacy-fallback bincode metadata acceptance while keeping bincode implementation correctness itself outside the claim.

## Context and Orientation

The repository's current formal-verification status is tracked in `config/highest-standard-formal-verification-matrix.json`. The top-level Lean completion certificate lives at `formal/lean/Hegemon/Release/HighestStandardCompletionCertificate.lean`, and the new classification surface lives at `formal/lean/Hegemon/Release/AssumptionClosureRoadmap.lean`.

A mechanized refinement track means a gap should eventually be represented by a Lean executable specification plus production Rust conformance. Parser refinement covers arbitrary raw bytes and canonical decoding. Native-node refinement covers RPC/network ingress through replay, reorg, startup, sync, storage, and accepted publication. Proof/AIR refinement covers deployed proof objects, public statements, witness constraints, and verifier soundness boundaries. Bridge refinement covers PQ-clean receipt verification, decoded receipt grammar, replay-key uniqueness, and authorized mint publication.

A named cryptographic assumption means Hegemon relies on external hardness or soundness claims, such as ML-KEM/ML-DSA security, hash/transcript collision resistance, STARK/FRI/PCS soundness, ciphertext indistinguishability, external review of the native lattice backend, and OS RNG quality.

A fail-closed system-model assumption means Hegemon cannot prove the external world behaves honestly, but it can define evidence and rejection policies. DA availability, storage fsync semantics, global traffic-analysis privacy, release infrastructure enforcement, dependency scanner completeness, and performance budgets belong here.

## Plan of Work

First, keep the classification theorem small and stable. The module `AssumptionClosureRoadmap.lean` defines three records: `MechanizedRefinementTracks`, `NamedPrimitiveCryptoAssumptions`, and `FailClosedSystemModelAssumptions`. The combined `ResidualAssumptionClosureRoadmap` exposes the three classes through named theorems. This is already implemented and builds.

Second, register the roadmap as a formal claim and blueprint node. The claim should cite the four theorem names in `AssumptionClosureRoadmap.lean`, the ExecPlan, the completion certificate, and the matrix. The blueprint node should depend on `formal.highest-standard-completion-certificate` and explain that this node is a classifier and ratchet, not a claim that the deep residuals are already discharged.

Third, update docs. `DESIGN.md` and `METHODS.md` should state that residuals are now split into mechanized tracks, named crypto assumptions, and fail-closed system-model assumptions. `formal/lean/README.md` should point readers to the new module.

Fourth, implement deeper milestones one at a time:

- Parser milestone: for every trust-boundary type still using partial exact-decode evidence, define a bounded Lean byte grammar, generate round-trip/rejection vectors, and add arbitrary-byte oracle corpora. Acceptance is a passing formal-core gate plus a reduced parser residual list in the matrix.
- Native-node milestone: define a raw-ingress-to-publication transition relation covering RPC/network bytes, pending actions, staged sidecars, block imports, reorgs, startup reload, sync, and storage publication. Acceptance is a theorem that accepted publication refines the transition relation plus Rust gates for each ingress family.
- Proof/AIR milestone: split cryptographic STARK/FRI assumptions from concrete AIR-to-Hegemon-statement constraints. Acceptance is a theorem that deployed public inputs, witness rows, balance, authorization, nullifiers, Merkle paths, ciphertext hashes, and stablecoin exceptions imply the transaction relation, with STARK/FRI soundness left as a named assumption.
- Bridge milestone: keep positive inbound minting disabled until a PQ-clean receipt verifier exists. Then bind decoded receipt bytes, verifier output, replay keys, external-chain assumptions, amount/range authorization, and native mint publication into one theorem surface.
- System-model milestone: add fail-closed gates for DA retention evidence, storage durability barriers, privacy telemetry/leakage budgets, branch-protection/export checks, dependency scanner freshness, and performance budgets.

## Concrete Steps

Run commands from `/Users/pldd/Projects/Reflexivity/Hegemon`.

To build the new Lean module:

    cd formal/lean && lake build Hegemon.Release.AssumptionClosureRoadmap Hegemon

Expected result:

    Built Hegemon.Release.AssumptionClosureRoadmap
    Built Hegemon
    Build completed successfully

To validate metadata after registering the claim and blueprint node:

    jq empty config/formal-security-claims.json config/formal-security-blueprint.json config/highest-standard-formal-verification-matrix.json
    cargo run --quiet --manifest-path scripts/hegemon_formal_core/Cargo.toml -- check-claims config/formal-security-claims.json
    cargo run --quiet --manifest-path scripts/hegemon_formal_core/Cargo.toml -- check-blueprint config/formal-security-blueprint.json --claims config/formal-security-claims.json

To run the full formal gate when a deeper milestone changes Rust or formal-core:

    bash scripts/check_formal_core.sh

## Validation and Acceptance

This first slice is accepted when `lake build Hegemon.Release.AssumptionClosureRoadmap Hegemon`, `bash scripts/check_lean_formal.sh`, JSON validation, claim checking, blueprint checking, and `git diff --check` pass. A later implementation milestone is accepted only when its claim no longer lists the corresponding mechanized track as open or when that track is replaced by a theorem-backed, production-bound claim.

## Idempotence and Recovery

All edits are additive or metadata-only. Re-running the Lean build and metadata gates is safe. If a JSON edit fails validation, revert only the bad JSON hunk or regenerate the exact claim/node patch; do not reset unrelated branch work.

## Artifacts and Notes

The first successful Lean build transcript was:

    cd formal/lean && lake build Hegemon.Release.AssumptionClosureRoadmap Hegemon
    Built Hegemon.Release.AssumptionClosureRoadmap
    Built Hegemon
    Build completed successfully (173 jobs).

## Interfaces and Dependencies

The first slice defines these theorem names:

    Hegemon.Release.AssumptionClosureRoadmap.residual_closure_roadmap_exposes_mechanized_refinement_tracks
    Hegemon.Release.AssumptionClosureRoadmap.residual_closure_roadmap_exposes_named_primitive_crypto_assumptions
    Hegemon.Release.AssumptionClosureRoadmap.residual_closure_roadmap_exposes_fail_closed_system_model_assumptions
    Hegemon.Release.AssumptionClosureRoadmap.residual_closure_roadmap_splits_all_open_assumptions

Future claims and blueprint nodes should use these theorem names to keep the residual classification executable and indexed by formal-core.
