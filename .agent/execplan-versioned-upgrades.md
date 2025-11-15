# Multi-version circuit governance and activation

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds. This plan must be maintained in accordance with `.agent/PLANS.md`.

## Purpose / Big Picture

We need to let the synthetic hegemonic currency network evolve its proving circuits and cryptographic suites without fragmenting the privacy pool. Operators should be able to accept blocks that contain transactions proven under different circuit revisions, roll out recursive verifier updates gradually, and execute emergency primitive swaps governed by documented activation procedures. After implementing this plan, transactions and blocks will advertise which circuit revision and cryptographic suite they rely on, validators will verify proofs using the correct version-specific keys, governance docs will describe how to activate/deprecate versions, and regression tests will enforce multi-version acceptance behavior.

## Progress

- [x] (2024-06-07 15:00Z) Draft initial ExecPlan covering scope, context, and work breakdown.
- [x] (2024-06-07 16:10Z) Added the shared `protocol-versioning` crate plus consensus `Transaction`/`BlockHeader` updates, hashing changes, and new tests for version commitments.
- [x] (2024-06-07 17:10Z) Threaded version metadata through transaction witnesses/proofs and block recursion, added multi-version verifying key maps, new block-circuit tests, and wallet/fixture updates.
- [x] (2024-06-07 18:00Z) Added `VersionSchedule`/`VersionProposal` governance logic to consensus (BFT + PoW) and new version policy tests.
- [x] (2024-06-07 18:20Z) Authored `governance/VERSIONING.md` plus the `runbooks/emergency_version_swap.md` operational guide.
- [x] (2024-06-07 18:30Z) Documented multi-version behavior in DESIGN.md/METHODS.md and ensured regression tests (block flow + consensus) cover mixed bindings.
- [ ] Summarize outcomes once review is complete.

## Surprises & Discoveries

- Observation: The workspace lacked a neutral place to share version identifiers between consensus and circuit crates; creating a small `protocol-versioning` crate prevented circular dependencies and kept serde/commitment helpers reusable.
  Evidence: Consensus, transaction-circuit, block-circuit, wallet, and integration tests all import the new crate after the change set.

## Decision Log

- Decision: Create a dedicated `protocol-versioning` crate instead of embedding version types inside `consensus`.
  Rationale: Multiple crates (transaction circuit, block circuit, wallet, integration tests) need the same version binding definitions, and a shared crate avoids duplicating serialization logic or creating dependency cycles.
  Date/Author: 2024-06-07 / assistant

## Outcomes & Retrospective

- Implemented end-to-end version awareness (transactions, proofs, block headers, consensus), added governance scaffolding, and documented both steady-state activation and emergency swap procedures. Regression tests exercise mixed-version blocks and consensus scheduling so future proposals can build on a proven path.

## Context and Orientation

The repository centers on a consensus crate (`consensus/`) that defines `Transaction`, `Block`, and `BlockHeader` types plus helpers such as `compute_fee_commitment`. Recursive block verification lives under `circuits/block/`, where `BlockProof` glues together individual `transaction_circuit::TransactionProof`s. The transaction proving/verification logic is in `circuits/transaction/`, which exposes `TransactionProof`, `TransactionPublicInputs`, and the AIR that enforces constraints. Documentation about architectural goals lives in `DESIGN.md`, while `METHODS.md` explains shielded transaction behavior. There are also specs under `consensus/spec/` that describe headers and consensus rules.

Currently, transactions and block proofs assume a single circuit version and cryptographic suite. Recursive block verification (`circuits/block/src/proof.rs`) takes a single `VerifyingKey` and applies it to every transaction proof. To enable phased rollouts we need to:

1. Introduce explicit version identifiers (for circuit revisions and cryptographic suite IDs) and thread them through consensus types, proofs, and headers.
2. Extend recursive block verification so that each transaction proof carries its version metadata, validators select the correct verifying key, and block digests commit to which versions were accepted.
3. Document governance for activating/deprecating versions and provide operational runbooks for emergency swaps, including how to migrate notes via special upgrade circuits.
4. Ensure regression tests cover multi-version acceptance (e.g., mixing v1 and v2 proofs in one block) and that docs describe emergency steps.

## Plan of Work

1. **Define shared version identifiers**
   - Create a new module under `consensus/src/version.rs` (or similar) that defines enums/structs like `CircuitVersion` and `CryptoSuiteId`, along with helper constants for known revisions. Provide serialization-friendly representations (e.g., `u16`). Update `consensus/src/lib.rs` to expose them.
   - Extend `consensus::Transaction` to include `circuit_version` and `crypto_suite` fields. Update constructors, hashing, and any helper functions/tests so IDs participate in transaction hashes. Likewise, extend `BlockHeader` with aggregated version metadata (e.g., a `version_vector` hash summarizing all transaction versions) or include top-level `circuit_version`/`crypto_suite` fields if that's the consensus rule. Document how these identifiers are encoded in the header.

2. **Propagate version metadata through transaction proofs**
   - Update `circuits/transaction::TransactionPublicInputs` (and fixtures) to include fields for `circuit_version` and `crypto_suite`. Ensure `TransactionWitness` or constants define these values so proofs can assert them. For now they may be simple constants per build, but they must exist in the data structure.
   - Adjust serialization helpers and fixtures in `circuits/transaction/fixtures/*.json` plus associated tests.

3. **Recursive verifier multi-version support**
   - Modify `TransactionProof` to carry version metadata (maybe referencing `TransactionPublicInputs`). Ensure `circuits/block::fold_digest` incorporates version info so aggregated digests change when versions differ.
   - In `circuits/block/src/proof.rs`, change APIs so `prove_block`/`verify_block` accept a `HashMap<CircuitVersion, VerifyingKey>` (or similar) rather than a single key. Each `TransactionProof` should specify its `circuit_version`, and the verifier selects the corresponding key. Introduce validation errors when proofs declare unknown versions or when crypto suite IDs mismatch the available verifying key metadata.
   - Ensure the execution trace records per-version counts so block proofs can report how many transactions for each version were accepted. This can feed into block headers as aggregated metadata.

4. **Consensus integration**
   - Update any consensus-level validation logic (e.g., when ingesting transactions or assembling blocks) to require that version identifiers match allowed sets. Compute and store a block-level commitment summarizing `(circuit_version, crypto_suite)` pairs—either via a simple sorted hash or by reusing the recursive aggregation digest.
   - If there are governance activation states (e.g., allowed versions set), add configuration structures or placeholder toggles in `consensus/src` that reference the new version IDs.

5. **Governance and activation docs**
   - Extend `DESIGN.md` and `METHODS.md` to describe multi-version support, version identifiers, and the high-level lifecycle (proposal, activation, deprecation, migration). Add a new document (e.g., `governance/VERSIONING.md` or update `consensus/spec/*.md`) describing ZIP-style proposal flow and the special upgrade circuits for migrating notes.
   - Create an operational runbook (e.g., `RUNBOOK.md` or `docs/runbooks/version-swaps.md`) that gives step-by-step instructions for emergency primitive swaps: declaring a proposal, building upgrade proofs, broadcasting activation heights, and monitoring rollouts.

6. **Regression tests**
   - Add unit tests in `consensus/src/types.rs` ensuring transaction hashes change when version IDs change and that block-level commitments capture multi-version mixes.
   - Extend `circuits/block` tests (or add new ones) verifying that mixing transaction proofs with two circuit versions is accepted when both keys are supplied, and rejected when an unsupported version appears.
   - Add tests covering governance config (if implemented) and serialization of version metadata.

7. **Documentation & finalization**
   - Update docs to match implementation, ensure `cargo test --all` passes, summarize outcomes in this plan, and prepare a PR summarizing the change.

## Concrete Steps

1. Work in repo root. Add `consensus/src/version.rs`, update `consensus/src/lib.rs` to export the module.
2. Modify `consensus/src/types.rs` and `consensus/src/header.rs` to include version metadata, adjusting helper functions/tests accordingly.
3. Edit `circuits/transaction/src/public_inputs.rs`, `witness.rs`, `trace.rs`, `proof.rs`, and fixtures to propagate version fields.
4. Update `circuits/block/src/proof.rs` APIs and any consumers to accept multiple verifying keys and to include version-aware aggregation logic.
5. Write docs under `DESIGN.md`, `METHODS.md`, and a new governance/runbook file as described above.
6. Implement regression tests in consensus + circuits crates. Run `cargo test --all` from repo root.

## Validation and Acceptance

- Run `cargo test --all` and expect all suites to pass, including new multi-version acceptance tests.
- Demonstrate (via tests or docs) that a block containing mixed-version transactions verifies when both versions are allowed but fails otherwise.
- Confirm documentation outlines governance activation steps and emergency runbooks.

## Idempotence and Recovery

- Structural changes to data types and docs are additive; rerunning `cargo test --all` is safe.
- The new runbook describes how to revert/disable a version if necessary.
- Tests are deterministic; rerunning after fixes ensures consistent results.

## Artifacts and Notes

_To be populated with notable outputs (e.g., sample test logs) as work progresses._

## Interfaces and Dependencies

- `consensus/src/version.rs` will define:

    pub type CircuitVersion = u16;
    pub type CryptoSuiteId = u16;

    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
    pub struct VersionBinding {
        pub circuit: CircuitVersion,
        pub crypto: CryptoSuiteId,
    }

  Along with helper constants for known versions.

- `Transaction` gains `version: VersionBinding`, and `BlockHeader` gains `version_matrix: [u8; 32]` (or similar) summarizing all transactions; helper functions compute these commitments.
- `circuits/block::verify_block` signature becomes:

    pub fn verify_block(
        tree: &mut CommitmentTree,
        proof: &BlockProof,
        verifying_keys: &HashMap<CircuitVersion, VerifyingKey>,
    ) -> Result<BlockVerificationReport, BlockError>

  and analogous for `prove_block` if needed.

- Documentation specifies governance activation heights and proposal flow referencing new version IDs.
