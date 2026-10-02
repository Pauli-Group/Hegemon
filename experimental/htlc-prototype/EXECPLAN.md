# Check a small isolated SHA-256 hashlock and HTLC reference relation


This living ExecPlan follows `.agent/PLANS.md`. Maintain Progress, Surprises & Discoveries, Decision Log and Outcomes & Retrospective as the work proceeds. All writes belong to `experimental/htlc-prototype` in the isolated checkout `/private/tmp/hegemon-htlc-20261002`, branch `codex/htlc-isolated-development`, baseline `47072042`.

## Purpose / Big Picture


A developer can construct a Boolean circuit for SHA-256 of exactly 32 bytes, evaluate its witness, and independently reject incorrect assignments by checking its equations. A separate executable reference relation demonstrates the policy a future shielded hash-and-time locked contract (HTLC) would need: either the claim authority spends with a valid secret, or the refund authority spends once the authenticated Hegemon height reaches the committed timeout. Both paths consume the same locked note and nullifier. This is an experiment, not a change to the live transaction relation or a deployment.

## Progress


- [x] (2026-10-02) Read the supplied current AGENTS instructions, `.agent/PLANS.md`, relevant DESIGN native-node/proof-mode and METHODS independent-proof sections. Inspect existing Boolean infrastructure and historical HTLC guidance.
- [x] (2026-10-02) Coordinator approved the smallest additive standalone crate and explicit auth/height trust boundaries.
- [x] (2026-10-02) Implement SHA-256 bit gates, witness evaluation, independent equation checker and measured counts.
- [x] (2026-10-02) Implement committed locked-note policy, exact spend intent, shared private-key nullifier and claim/refund reference admission.
- [x] (2026-10-02) Coordinator authorized one compiler job with the separate target; nine isolated offline locked tests, clippy with warnings denied and formatting pass.
- [x] (2026-10-02) Record exact evidence and exclusions in README and this plan; freeze source for independent review.
- [x] (2026-10-02) Independent scoped source review found no actionable defect in SHA wiring/equations, branch/nullifier semantics, authorization/context binding, or documented claim boundaries. The reviewer did not independently run the tests.

## Surprises & Discoveries


The existing `BoolWire`/`CandidateBoolConstraint` machinery is inside `circuits/transaction/src/full_blake2b448_relation.rs` and includes candidate-specific relations. Reusing it as a crate dependency would couple this experiment to the live transaction crate. The isolated crate therefore defines a small local Boolean intermediate representation: an ordered list of gates, each defining exactly one output bit. No top-level Cargo or existing source is modified.

The fixed-width circuit has 55,210 defining-gate equations and 55,466 assignment wires. Exhaustive mutation is practical by rotating the same verifier's equation order to the changed wire; the acceptance relation remains identical and a successful pass still covers all gates. Another 215 mutations use ordinary public verification order. The final nine tests finish in 0.92 seconds. `/usr/bin/time -l` could not obtain macOS clock-rate statistics inside the sandbox (`sysctl kern.clockrate: Operation not permitted`); that wrapper returned failure after its cargo tests passed. The final plain cargo invocation returned exit zero. No measured peak-RSS claim is made.

## Decision Log


Decision: Restrict SHA-256 to a 32-byte secret and its one-block padding. Rationale: This is the proposed interoperable hashlock input width; fixed padding makes every non-input bit constant and limits scope. Date/Author: 2026-10-02, HTLC worker/coordinator.

Decision: Use a standalone `[workspace]` with only sha2 pinned to 0.10.9. Rationale: sha2 serves as a differential oracle and as the host commitment hash; the hashlock checker must use explicit Boolean gate equations rather than sha2 verification. Date/Author: 2026-10-02, HTLC worker.

Decision: Keep authorization and authenticated chain-state validation behind explicit trusted interfaces. Rationale: A bare untrusted Boolean cannot establish signature verification, note membership, unspent state or authenticated height. The interfaces must validate these facts in a future integration; unit-test fixtures do not discharge that obligation. Date/Author: 2026-10-02, coordinator/HTLC worker.

Decision: Claims have no timeout expiry. Rationale: After refund maturity, claim and refund race for the same nullifier, following Bitcoin-style HTLC semantics. Date/Author: 2026-10-02, coordinator/HTLC worker.

Decision: Preserve the host reference boundary rather than imply all policy rules have constraints. Rationale: Only the SHA-256 preimage relation is represented by gates; the note/intent/nullifier commitments, balance/version/timelock and external auth/context checks remain host code. Date/Author: 2026-10-02, HTLC worker.

## Outcomes & Retrospective


The bounded implementation is complete: a fixed-shape 32-byte SHA-256 constraint checker and host HTLC claim/refund reference relation, with nine passing tests, lint/format acceptance and a 22 MiB separate build target. Tests compare 68 fixed/random SHA vectors, flip every assignment wire, reject every non-Boolean wire mutation, cover exact intent/policy/context/auth binding and demonstrate a shared-nullifier branch race. No tracked baseline file changed. Independent scoped source review found no actionable defects; this is not a production security audit or formal proof.

The result cannot establish production proof cost, RP05 row/cap fit, ZK, signature security, live authenticated height, node lifecycle behavior or atomic-swap deployment. The commitment/nullifier hashes are experimental host constructions with no inherited production PQ128 or composed post-quantum security claim. An integration must supply actual cryptographic authorization and authenticated consensus state and constrain the whole reference relation, then generate fresh proofs and qualify the unchanged-byte lifecycle before release authority is considered.

## Context and Orientation


The native product carries independent self-contained `tx_leaf` proofs and requires unchanged proof bytes through wallet/RPC, relay, mempool, mining, block import, sync, restart, reorg and fresh-node verification. This experiment touches none of those paths. A successor proof relation would require new identity, full proof generation, independent security work, lifecycle checks and release authorization. Existing mathematical endpoints and retained proof evidence do not cover the new SHA-256 gadget.

`src/hashlock.rs` will hold the Boolean circuit. A wire is an index into a byte-valued assignment; accepted wire values must be 0 or 1. Constants, XOR, AND, NOT, three-input parity and majority gates define every internal wire. Rotation is only rewiring; modulo-2^32 addition uses parity/majority carry equations. The input is 256 bits and output is 256 digest bits pinned to the caller's expected digest. `src/relation.rs` will hold the host reference relation, with a domain-separated note commitment and nullifier derived from the same private nullifier key/note identity for both branches.

## Plan of Work


First add the standalone manifest and local modules. Build a fixed-shape SHA circuit without witness-dependent branching. Include message padding, length 256 bits, SHA initialization, the 64-word message schedule, 64 compression rounds and final feed-forward. Expose circuit construction, witness evaluation, independent verification and actual gate/Boolean/pin counts. Next define a versioned locked-note opening and its commitment, a canonical one-output transfer intent, and claim/refund branch witnesses. Bind external authorization to the note, nullifier, branch, exact intent and authenticated parent context. Finally test all gates through differential vectors, every-wire mutation, non-Boolean assignments and relation failure cases.

## Concrete Steps


Work in `/private/tmp/hegemon-htlc-20261002/experimental/htlc-prototype`. After obtaining the coordinator's compiler lane, use a separate target directory:

    CARGO_TARGET_DIR=/private/tmp/hegemon-htlc-target-20261002 CARGO_BUILD_JOBS=1 cargo test --offline --locked -- --nocapture
    CARGO_TARGET_DIR=/private/tmp/hegemon-htlc-target-20261002 CARGO_BUILD_JOBS=1 cargo clippy --offline --locked --all-targets -- -D warnings
    cargo fmt --all -- --check

Use cached dependencies and the installed Rust toolchain. Do not run `make setup`, `make node`, a production build or a node for this isolated test. Check free disk before compiling; budget this build directory below 2 GiB. If dependencies are unavailable offline, report the exact missing package to the coordinator instead of fetching or expanding the build.

## Validation and Acceptance


Tests must compare constrained digests with sha2 for fixed 32-byte known vectors and reproducible random inputs. A correct witness must satisfy every equation. Every wire must have an input pin or defining gate; flipping any internal output must be rejected by the equation verifier. Wrong digest/input pins and byte-valued non-Boolean assignments must reject. Print exact wire/gate/Boolean/pin counts from the constructed circuit, without extrapolating RP05 cap fit.

Reference-relation tests must admit the authorized claim before, at and after timeout, admit refund only at/after timeout, reject incorrect preimage, authority, version, note commitment, nullifier, exact intent, authenticated context and spent state, and demonstrate that a shared unspent set allows only the first competing branch. Reorg, restart and actual node lifecycle are not exercised here.

## Idempotence and Recovery


All code is additive under the new directory. The commands can be rerun without changing primary files or node/wallet state. A failed test should be corrected in these new files and rerun once. Keep Cargo.lock for reproducible dependency resolution. Build artifacts stay in the isolated temporary target directory and can be inspected without touching retained proofs. No commit, push, deployment or benchmark submission is authorized.

## Artifacts and Notes


Final source acceptance output (2026-10-02; installed rustc/cargo 1.91.1):

    SHA256 constrained vectors=68
    Counts { wires: 55466, constants: 2, not: 2048, xor: 2048,
      and: 4096, parity: 26368, majority: 20648, gate_equations: 55210,
      boolean_constraints: 55466, input_pins: 256, output_pins: 256,
      total_constraints: 111188 }
    exhaustive flipped/non-Boolean wires=55466
    test result: ok. 9 passed; 0 failed; ... finished in 0.92s
    Doc-tests: 0 passed; 0 failed
    cargo clippy --offline --locked --all-targets -- -D warnings: exit 0 (0.23s)
    cargo fmt --all -- --check: exit 0
    du -sh /private/tmp/hegemon-htlc-target-20261002: 22M

The directory contains Cargo.toml/Cargo.lock, src/lib.rs, src/hashlock.rs, src/relation.rs, README.md and this EXECPLAN.md. All are new and uncommitted; no commit/push/deployment was performed. The main coordinator retains the final user-facing handoff.

## Interfaces and Dependencies


`Sha256Hashlock::new()`, `evaluate(&[u8;32])`, `verify(preimage, digest, assignment)` and `counts()` must form a reusable fixed-shape constraint interface. `LockedNote::commitment()`, `LockedNote::nullifier()`, `authorization_message(...)` and `check_spend(...)` define the reference semantics. An `Authorizer` validates authority binding and external authorization bytes against the exact authorization transcript. An `AuthenticatedChain` validates note membership/unspent state and supplies the authenticated parent hash/height. These trusted implementations remain outside this experiment. sha2 is pinned and never used as a substitute for the SHA gate checker.

Revision note (2026-10-02): Initial plan reflects the approved smallest contract and deliberately isolates all future proof/production work.

Revision note (2026-10-02): Completed implementation/validation and recorded actual Boolean IR counts, exhaustive mutation method, successful plain cargo results, small build size and the explicit host/external-oracle trust boundaries.
