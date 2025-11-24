```md
# Security assurance program: cryptanalysis reviews, formal verification, and adversarial pipelines

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds.

This plan must be maintained in accordance with `.agent/PLANS.md`. All contributors must update every section as work evolves.

## Purpose / Big Picture

We need an end-to-end security assurance loop that goes beyond unit tests. After this work lands, the repo will contain:

1. Documented commissioning processes for independent lattice/hash cryptanalysis of our parameter choices, wired back into `DESIGN.md` and `METHODS.md`.
2. Concrete formal-verification/model-checking artifacts for the transaction STARK circuit and HotStuff-inspired consensus, plus instructions on how to run them.
3. Well-scoped third-party audits (cryptography, protocol, implementation) captured in docs/runbooks so we can integrate findings and update governance documents quickly.
4. CI-backed continuous security testing pipelines (fuzzing & adversarial sims) that target transaction validation, the network handshake, and wallet address handling.

Someone reading this plan should be able to reproduce those outcomes from scratch.

## Progress

- [x] (2025-02-14 00:00Z) Draft context survey + file inventory for docs, circuits, consensus, wallet, and CI.
- [x] Commissioning documentation for lattice/hash cryptanalysis (docs + DESIGN/METHODS hooks).
- [x] Third-party audit scope doc + DESIGN/METHODS updates.
- [x] Formal verification artifacts for circuits + consensus (new files, instructions, METHOD references).
- [x] Continuous security testing harnesses for transaction validation, networking, wallet + CI job wiring + docs.
- [x] (2025-11-24 11:20Z) Validated docs/tests: `cargo fmt --all -- --check` (pass), `cargo clippy --workspace --all-targets --all-features -- -D warnings` (pass), `cargo test --workspace` (pass including security fuzz/adversarial harnesses). Updated Outcomes/Retrospective accordingly.

## Surprises & Discoveries

- Observation: Transaction witness fuzzing needed bounded budgets to avoid saturating MASP balance slots.
  Evidence: `circuits/transaction/tests/security_fuzz.rs` normalizes outputs/fees before asserting on `balance_slots`.

## Decision Log

- Decision: Model-checking artifacts live in TLA+ with checked-in TLC configs.
  Rationale: Keeps invariants readable and aligns with `.agent/PLANS.md` guidance for self-contained specs.
  Date/Author: 2025-02-14 / assistant

## Outcomes & Retrospective

- Security commissioning docs, audit scopes, and formal verification artifacts are in place with runnable instructions and cross-links in DESIGN/METHODS.
- Continuous security/adversarial harnesses (transaction witness fuzzing, network handshake tampering, wallet address fuzzing) are green in `cargo test --workspace`; CI job wiring documented and validated locally.
- Formatting and clippy succeeded; no outstanding blockers. Future work: monitor proptest budgets in CI and keep TLC/Apalache instructions current.

## Context and Orientation

Repository structure highlights:

- `DESIGN.md` and `METHODS.md` capture architectural and procedural commitments. All security processes must thread through them per root `AGENTS.md`.
- Cryptography primitives live under `crypto/`, with parameter descriptions in `DESIGN.md §1`. We need a companion document in `docs/` that spells out how to commission lattice/hash reviews for ML-DSA, ML-KEM, SLH-DSA, Poseidon-style hashes, and the STARK AIR implementations.
- Circuits live under `circuits/{transaction,block}` with documentation `circuits/README.md`. No formal verification artifacts exist yet; we will add them under `circuits/formal/` and link to them from `METHODS.md` and the README.
- Consensus specifications live under `consensus/spec/`. We will add a model-checking artifact (e.g., TLA+) under `consensus/spec/formal/` capturing safety/liveness invariants of the HotStuff-like protocol, plus instructions for TLC/Apalache usage.
- `docs/THREAT_MODEL.md` and `runbooks/` currently lack content about third-party audit scopes or security test pipelines. We'll extend them with a new `docs/SECURITY_REVIEWS.md` describing commissioning, scoping, and integration steps, and a `runbooks/security_testing.md` referencing CI entry points.
- `.github/workflows/ci.yml` runs lint/test/bench jobs only. We'll add a `security-adversarial` job that executes the new fuzz/adversarial harnesses to ensure continuous coverage.

## Plan of Work

1. **Document cryptanalysis commissioning**
   - Create `docs/SECURITY_REVIEWS.md` covering three tracks: lattice cryptanalysis, hash/circuit cryptanalysis, and integration loops. Include actionable steps for parameter set validation, deliverable expectations, and how to log findings.
   - Update `DESIGN.md §1` and `METHODS.md` to reference the commissioning process and specify the currently selected parameter sets and review cadence. Mention how results map back to `crypto/` implementations.

2. **Third-party audit scopes & integration**
   - Within `docs/SECURITY_REVIEWS.md`, add explicit scopes for cryptography, protocol, and implementation audits, plus severity triage + feedback loop instructions.
   - Update `DESIGN.md` (consensus/ledger sections) and `METHODS.md` (operational guidance) to mention how audit outcomes must be recorded (e.g., new appendices referencing docs) and how they affect upgrade procedures.

3. **Formal verification artifacts**
   - Create `circuits/formal/transaction_balance.tla` (or similar) modeling note inputs/outputs, enforcing nullifier uniqueness and MASP balance invariants. Provide `circuits/formal/README.md` with instructions to run TLC and interpret counterexamples.
   - Create `consensus/spec/formal/hotstuff_safety.tla` capturing views, QCs, and commit rules. Document invariants for safety (no conflicting commits) and liveness assumptions. Provide README instructions referencing Apalache/TLC commands.
   - Update `METHODS.md` and `circuits/README.md` to describe how to run these artifacts as part of release validation.

4. **Continuous security testing pipelines**
   - Add dev-dependencies (`proptest`, `rand`, etc.) to relevant crates as needed.
   - Implement new tests:
     * `circuits/transaction/tests/security_fuzz.rs`: property-based fuzz on `TransactionWitness` enforcing balance slot invariants and verifying rejection of invalid witness sizes.
     * `network/tests/adversarial.rs`: randomized handshake tampering test ensuring signature/nonce mismatches are detected.
     * `wallet/tests/address_fuzz.rs`: property-based address encode/decode tests plus adversarial mutation detection.
   - Add `tests/security_pipeline.rs` (workspace-level) to orchestrate wallet/network/circuit harnesses if cross-crate coordination is needed.
   - Update `.github/workflows/ci.yml` with a dedicated `security-adversarial` job that runs the new tests with longer proptest cases and surfaces artifacts.
   - Document how to run these pipelines locally in `docs/SECURITY_REVIEWS.md` and `runbooks/security_testing.md`.

5. **Integration loop documentation**
   - Update `DESIGN.md` and `METHODS.md` sections describing lifecycle (e.g., upgrade path, governance) to mention where to record results (maybe `docs/SECURITY_REVIEWS.md#finding-log`).
   - If necessary, add a short section to `DESIGN.md` referencing the verification artifacts and continuous testing.

6. **Validation**
   - Run `cargo fmt`, `cargo clippy --workspace --all-targets --all-features`, `cargo test --workspace`, plus targeted commands for new tests (if not covered) and `cargo test -p network -- --ignored` if needed. Run TLC/Apalache instructions (or at least include sample commands) and capture their outputs or stubs.

## Concrete Steps

1. Add new documentation files and update existing ones as outlined above.
2. Add formal verification directories/files with runnable specs.
3. Implement fuzz/adversarial tests in the specified crates.
4. Update CI workflow to run the new security job.
5. Run formatting, linting, and all tests. Execute the new security harness locally to ensure determinism.
6. Update `runbooks/security_testing.md` with how to re-run the security job manually and how to respond to failures.

## Validation and Acceptance

- `cargo fmt --all` and `cargo clippy --workspace --all-targets --all-features -D warnings` must pass.
- `cargo test --workspace` must pass, including new property tests.
- Running `cargo test -p transaction-circuit --test security_fuzz -- --ignored --test-threads=1` (or equivalent) should demonstrate the fuzz harness.
- `cargo test -p network --tests` must include the adversarial tests and pass.
- `cargo test -p wallet --tests` must include the new address fuzz tests and pass.
- `.github/workflows/ci.yml` must include the `security-adversarial` job running `cargo test --package transaction-circuit --test security_fuzz`, `cargo test -p network --test adversarial`, and `cargo test -p wallet --test address_fuzz` (or analogous commands) plus a new workspace-level adversarial simulation (if created).
- TLC/Apalache commands documented in the READMEs must parse without syntax errors (can be smoke-tested locally by invoking `apalache-mc check hotstuff_safety.tla` if tool is installed; otherwise, include instructions and sample output expectation).

## Idempotence and Recovery

- Docs additions are additive; re-running steps overwrites files deterministically.
- Tests are property-based but bounded (set `PROPTEST_MAX_CASES`), so they should be deterministic when seeded; mention environment variables in docs.
- CI job addition is additive; if it fails, revert to previous commit or fix tests.

## Artifacts and Notes

- Include snippets of TLC run logs or sample proptest output in READMEs to show success criteria.
- Provide example JSON snippet for how to log cryptanalysis findings in `docs/SECURITY_REVIEWS.md`.

## Interfaces and Dependencies

- Use the existing Rust workspace; new dev-dependencies may include `proptest = "1"`, `rand = "0.8"`, and `once_cell` for deterministic RNG seeds.
- TLA+ specs should be pure text files referencing invariants `TypeOK`, `NoDoubleCommit`, `EventualCommit`.
- Network adversarial tests should rely on `PeerIdentity` API already exposed.
```
