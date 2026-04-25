# CashVM Bridge Objects Experiment

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds.

Reference: repository root `.agent/PLANS.md` defines the ExecPlan format and maintenance requirements. This document must remain self-contained and executable from a fresh checkout.

## Purpose / Big Picture

This work tests whether Hegemon can expose the same bridge light-client statement to Bitcoin Cash CashVM that it already exposes to RISC Zero. The user-visible result is a new experimental crate that converts Hegemon bridge outputs into BCH-friendly, SHA-256-oriented objects, checks whether proof envelopes fit expected CashVM standardness limits, chunks proof bytes when they do not fit one transaction, and models the covenant state transition needed to consume a Hegemon bridge message exactly once.

The experiment does not claim to be a production BCH covenant or a full CashVM interpreter. It answers the immediate engineering question: which objects are needed, how large are they, which parts fit CashVM’s 2026 constraints, and what state transition a production covenant must enforce.

## Progress

- [x] (2026-04-25T05:25:59Z) Read `.agent/PLANS.md`, `DESIGN.md`, and `METHODS.md` before editing.
- [x] (2026-04-25T05:25:59Z) Created this focused ExecPlan because the existing `.agent/CASHVM_BRIDGE_STARK_COVENANT_EXECPLAN.md` targets a broader CashVM privacy rollup, while the current task is a narrower Hegemon bridge-object feasibility experiment.
- [x] (2026-04-25T05:25:59Z) Add `zk/cashvm-bridge` as an isolated workspace crate.
- [x] (2026-04-25T05:25:59Z) Define CashVM-facing bridge output, proof envelope, proof chunk, and state commitment objects.
- [x] (2026-04-25T05:25:59Z) Add tests for canonical encoding, proof chunking, replay-state update, and covenant-model tamper rejection.
- [x] (2026-04-25T05:25:59Z) Add a size-report command for measured Hegemon/RISC Zero proof objects.
- [x] (2026-04-25T05:25:59Z) Update `DESIGN.md`, `METHODS.md`, and bridge docs with the experiment outcome.
- [x] (2026-04-25T05:25:59Z) Run full validation commands and record outputs.

## Surprises & Discoveries

- Observation: The repository already contains `.agent/CASHVM_BRIDGE_STARK_COVENANT_EXECPLAN.md`, but that plan is intentionally broader than this request.
  Evidence: Its purpose is a CashVM validity-rollup covenant carrying Hegemon privacy semantics, while this request asks for objects equivalent to the existing RISC Zero bridge objects.

- Observation: The CashVM-facing bridge output is 516 bytes, not the 404-byte RISC Zero journal.
  Evidence: `cargo test -p cashvm-bridge --lib` initially failed when the test expected 404 bytes; the adapter now intentionally carries additional BCH semantic fields, the Hegemon message root, and the confirmation/minimum-work policy checked by the proof.

- Observation: Current RISC Zero receipt envelopes are too large for one standard CashVM transaction, but the Hegemon long-range proof input is not.
  Evidence: `cargo run -p cashvm-bridge --bin cashvm_bridge_report` reports `HegemonLongRangeProofV1: bytes=9951 fits_standard_tx=true`, `RISC Zero succinct envelope: bytes=224508 fits_standard_tx=false stack_elements_required=23 fragment_transactions_required=3`, and `RISC Zero composite envelope: bytes=492158 fits_standard_tx=false stack_elements_required=50 fragment_transactions_required=6`.

- Observation: The first covenant model accepted next-state policy changes unless the proof was otherwise valid.
  Evidence: Review of `verify_cashvm_bridge_spend_model` after tests passed showed it checked the proof against the previous verifier hash and minimum soundness but did not require the next state to preserve those policy fields. The model now rejects `NextPolicyMismatch`.

- Observation: The first CashVM bridge output omitted confirmation/minimum-work policy and the spend model did not rebind the CashVM SHA-256 message digest to the source message.
  Evidence: Hostile review showed that the output was not fully self-describing and an arbitrary `cashvm_message_hash` could be carried in a proven output while the Hegemon message hash still matched. The output now carries `confirmations_checked` and `min_work_checked`, and the spend model rejects `CashVmMessageHashMismatch`.

- Observation: The first hardened output still omitted `message_root`, making it less equivalent to the RISC Zero journal than necessary.
  Evidence: Security review compared `CashVmBridgeOutputV1` to `BridgeCheckpointOutputV1`. `message_root` is now carried in the CashVM-facing statement, increasing the output to 516 bytes while still fitting one standard CashVM transaction model.

## Decision Log

- Decision: Keep the CashVM bridge experiment in a separate `zk/cashvm-bridge` crate rather than adding BCH-specific objects directly to `consensus-light-client`.
  Rationale: Hegemon consensus should standardize the source-chain statement and `BridgeCheckpointOutputV1`; CashVM is a destination adapter with BCH-specific hash, size, and UTXO-state constraints. Keeping the adapter separate avoids turning BCH policy into Hegemon consensus surface.
  Date/Author: 2026-04-25 / Codex

- Decision: Use SHA-256-domain-separated CashVM-facing encodings instead of BLAKE3/Poseidon in the CashVM adapter.
  Rationale: CashVM can natively execute SHA-family hashes. A BCH landing covenant should verify compact SHA-256-friendly public outputs rather than reimplement Hegemon’s internal 48-byte BLAKE3 commitments in script.
  Date/Author: 2026-04-25 / Codex

- Decision: Model the covenant state with a 128-byte commitment object.
  Rationale: The 2026 Pay-to-Script upgrade raises token commitments to 128 bytes. A bridge singleton NFT can carry exactly one compact state commitment if we store digests and counters rather than full checkpoint data.
  Date/Author: 2026-04-25 / Codex

- Decision: Treat raw RISC Zero receipt verification on BCH as an unfavorable compatibility path and target CashVM-native STARK/hash proof objects instead.
  Rationale: The measured RISC Zero envelopes require 23 or 50 stack-sized pushes and 3 or 6 fragment transactions at a 90000-byte fragment payload, while the actual Hegemon long-range proof input fits one transaction. The proof transport, not the Hegemon statement, is the CashVM bottleneck.
  Date/Author: 2026-04-25 / Codex

## Outcomes & Retrospective

Milestone completed: the repository now has a concrete CashVM bridge-object experiment under `zk/cashvm-bridge`. It proves that Hegemon’s source-side compact witness is small enough for BCH-style constraints, models a 128-byte covenant state commitment, and makes the RISC Zero receipt-size problem explicit. Remaining work is production-grade: implement a real CashVM script/verifier, decide whether replay state should be append-only or sparse, and benchmark an actual CashVM-native STARK verifier rather than a Rust model.

Validation completed:

    cargo fmt --check
    passed

    cargo test -p cashvm-bridge --lib
    running 6 tests
    test result: ok. 6 passed; 0 failed

    cargo run -p cashvm-bridge --bin cashvm_bridge_report
    HegemonLongRangeProofV1: bytes=9951 fits_standard_tx=true fits_unlocking=true fits_stack_element=true stack_elements_required=1 fragment_payload_bytes=90000 fragment_transactions_required=1
    RISC Zero journal: bytes=404 fits_standard_tx=true fits_unlocking=true fits_stack_element=true stack_elements_required=1 fragment_payload_bytes=90000 fragment_transactions_required=1
    CashVM bridge output: bytes=516 fits_standard_tx=true fits_unlocking=true fits_stack_element=true stack_elements_required=1 fragment_payload_bytes=90000 fragment_transactions_required=1
    RISC Zero succinct envelope: bytes=224508 fits_standard_tx=false fits_unlocking=false fits_stack_element=false stack_elements_required=23 fragment_payload_bytes=90000 fragment_transactions_required=3
    RISC Zero composite envelope: bytes=492158 fits_standard_tx=false fits_unlocking=false fits_stack_element=false stack_elements_required=50 fragment_payload_bytes=90000 fragment_transactions_required=6

    cargo clippy -p cashvm-bridge --all-targets -- -D warnings
    passed

    /usr/bin/time -p ./target/release/cashvm_bridge_report
    real 0.00
    user 0.00
    sys 0.00

## Context and Orientation

Hegemon already has a bridge light-client statement. The shared verifier lives in `consensus-light-client/src/lib.rs`, where `BridgeCheckpointOutputV1` records the source chain ID, rules hash, checkpoint and tip hashes/work, message root, message hash, message nonce, confirmations checked, and minimum work checked. RISC Zero support lives under `zk/risc0-bridge`; it proves a `HegemonLongRangeProofV1` in a zkVM and returns a `RiscZeroBridgeReceiptV1` with an authenticated 404-byte journal.

CashVM is Bitcoin Cash’s stack-based contract VM. The May 2026 upgrade path adds better loops, functions, bitwise operations, Pay-to-Script standardness, and 128-byte token commitments. CashVM is not a RISC-V zkVM. It should not receive a raw RISC Zero receipt. Instead, it needs BCH-specific objects: a compact SHA-256-friendly bridge output, a proof envelope sized for BCH standard transactions, proof chunks if the proof is too large, and a state commitment that a singleton CashToken NFT can carry forward.

The new experimental crate is `zk/cashvm-bridge`. It depends on `consensus-light-client` and `protocol-kernel` to reuse the Hegemon source statement and bridge message types. It must not become a dependency of Hegemon consensus or the native node.

## Plan of Work

First, create `zk/cashvm-bridge` and add it to the workspace. The crate will expose plain Rust structs and deterministic manual encoders. Manual encoders make byte sizes explicit and avoid accidentally inheriting SCALE details that CashVM scripts would not implement.

Second, define `CashVmBridgeOutputV1`. It is the BCH-facing counterpart of `BridgeCheckpointOutputV1`; it carries Hegemon checkpoint/tip data, message root, confirmation/work policy, and BCH-friendly fields: a SHA-256 message digest, destination token category, recipient locking bytecode hash, and amount. It also exposes a `statement_digest` that a proof envelope can bind.

Third, define `CashVmBridgeStateV1` as exactly 128 bytes when encoded. It stores a magic/version tag, verifier script hash, accepted checkpoint digest, replay root, minted supply, sequence, security bits, and flags. This models the state carried in a CashToken NFT commitment.

Fourth, define `CashVmProofEnvelopeV1` and `CashVmProofChunkV1`. The envelope records the proof system, verifier script hash, claimed PQ soundness, statement digest, and proof bytes. The chunking helper splits large proof bytes under a conservative per-chunk payload cap and gives each chunk a chained accumulator so a final covenant can prove reassembly order.

Fifth, define `verify_cashvm_bridge_spend_model`. This is a Rust model of the covenant transition. It checks proof envelope binding, minimum soundness, source-message binding, replay-root update, checkpoint digest update, sequence increment, and minted-supply update. It rejects tampered messages, weak proof profiles, wrong verifier hashes, and replay-root mismatches.

Finally, add tests and a size-report binary. The binary should print whether current measured Hegemon objects fit a one-transaction CashVM path and how many chunks are required for RISC Zero succinct and composite envelope sizes.

## Concrete Steps

Run these commands from `/Users/pldd/Projects/Reflexivity/Hegemon`:

    cargo test -p cashvm-bridge --lib
    cargo run -p cashvm-bridge --bin cashvm_bridge_report
    cargo fmt --check

Expected behavior after implementation:

    cargo test -p cashvm-bridge --lib
    test result: ok. All tests pass.

    cargo run -p cashvm-bridge --bin cashvm_bridge_report
    Prints CashVM limits, the 128-byte state commitment size, one-transaction fit status for 9,951-byte Hegemon long-range proof inputs, and chunk counts for 224,508-byte succinct and 492,158-byte composite RISC Zero envelopes.

## Validation and Acceptance

Acceptance is not just compilation. The crate must demonstrate these behaviors:

1. A Hegemon `BridgeCheckpointOutputV1` plus `BridgeMessageV1` converts into a deterministic CashVM bridge output.
2. `CashVmBridgeStateV1::commitment_bytes()` returns exactly 128 bytes.
3. A valid spend model advances replay state and minted supply.
4. Tampering with the message, verifier hash, proof soundness, or next replay root rejects.
5. The standardness report says a small Hegemon long-range proof fits one standard transaction but current RISC Zero receipt envelopes require chunking.

## Idempotence and Recovery

All changes are additive. The crate has no network side effects, no database writes, and no live BCH dependency. If a test fails, rerun `cargo test -p cashvm-bridge --lib` after fixing the crate. If workspace membership causes unrelated build issues, the crate can still be tested with `cargo test --manifest-path zk/cashvm-bridge/Cargo.toml --lib`.

## Artifacts and Notes

The relevant existing measured sizes are:

    HegemonLongRangeProofV1: 9,951 bytes
    BridgeMessageV1 example: 171 bytes
    RISC Zero authenticated journal: 404 bytes
    RISC Zero succinct envelope: 224,508 bytes
    RISC Zero composite envelope: 492,158 bytes

These numbers are used only for the size-report experiment; the production BCH verifier should target a smaller CashVM-native proof format rather than raw RISC Zero envelopes.

## Interfaces and Dependencies

In `zk/cashvm-bridge/src/lib.rs`, define:

    pub struct CashVmBridgeOutputV1 { ... }
    pub struct CashVmBridgeStateV1 { ... }
    pub struct CashVmProofEnvelopeV1 { ... }
    pub struct CashVmProofChunkV1 { ... }
    pub struct CashVmStandardnessReport { ... }
    pub fn cashvm_output_from_hegemon(...)
    pub fn verify_cashvm_bridge_spend_model(...)
    pub fn chunk_cashvm_proof(...)
    pub fn cashvm_standardness_report(...)

Use `sha2::Sha256` for all CashVM-facing digests. Use `consensus-light-client` and `protocol-kernel` only as source types.
