# Production Hardening: Remove Scaffolded Crypto and Unsafe Defaults

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds.

Reference: repository root `.agent/PLANS.md` defines the ExecPlan format and maintenance requirements. Every update to this file must remain consistent with that guidance.

## Purpose / Big Picture

Production builds must not rely on placeholders, unsafe fallbacks, or misleading security features. After this change, the node and wallet will only accept real cryptographic proofs, commitments and nullifiers will have full‑strength (256‑bit) encodings, viewing keys will no longer embed spend keys, and the node will refuse to run with mock state execution outside development profiles. A user can start the node, submit a shielded transaction, and verify that it is rejected if any proof, commitment, or Merkle root is malformed, while developers can still enable explicit dev‑only features when testing.

The visible proof is that production builds either (a) succeed with full cryptographic verification and correct 256‑bit commitments/nullifiers or (b) refuse to run or reject transactions when required safety hooks are missing. This plan is focused on production‑compiled code; explicitly gated dev‑only features can remain but must be opt‑in and impossible to reach in production builds.

## Progress

- [x] (2025-12-20 01:01Z) Create the production hardening ExecPlan.
- [x] (2025-12-20 04:47Z) Remove production paths that accept legacy or placeholder verification behavior.
- [x] (2025-12-20 04:47Z) Replace 64‑bit commitment/nullifier encodings with 256‑bit encodings across circuits, runtime, wallet, and state.
- [x] (2025-12-20 04:47Z) Remove spend‑key leakage from viewing keys and align PRF derivations across crates.
- [x] (2025-12-20 04:47Z) Remove misleading “binding signature” semantics from production transactions.
- [x] (2025-12-20 04:47Z) Enforce real state execution in non‑dev nodes and block CLI paths that emit empty proofs.
- [x] (2025-12-20 04:47Z) Fix wallet serialization truncation and production defaults that embed predictable seeds/tokens.
- [x] (2025-12-20 04:47Z) Update docs, tests, and hardening scripts to match the new guarantees.
- [x] (2025-12-20 07:05Z) Replace toy Poseidon constants with NUMS-derived constants and 63 full rounds across circuits/runtime/crypto.
- [x] (2025-12-20 07:05Z) Wire batch proof verification, enforce full binding hash checks, and require `--dev` to start the node.
- [x] (2025-12-20 07:50Z) Gate legacy commitment helpers, enforce AIR hash non-zero/match, bound Merkle root history, remove hard-coded sudo key, and make balance commitment checks fallible.
- [x] (2025-12-20 08:35Z) Disable dev-only shielding in production, add proof-size/fee-range guards, and honor RPC deny-unsafe config.
- [x] (2025-12-20 09:05Z) Enforce shielded coinbase subsidy bounds and reject oversized proofs in unsigned validation.

## Surprises & Discoveries

None yet. Update this section as soon as unexpected behavior is observed, with short evidence snippets.

## Decision Log

- Decision: Move commitments and nullifiers to 256‑bit outputs represented as four 64‑bit field limbs, while retaining a 32‑byte on‑chain encoding.
  Rationale: The current 64‑bit output caps collision resistance at ~64 bits and violates the post‑quantum security target. A 4‑limb sponge output allows 256‑bit encodings without changing the base field.
  Date/Author: 2025-12-20 / Codex

- Decision: Gate any “fast” or “structural‑only” proof verification behind explicit dev/test features, and reject proofs without cryptographic bytes in production.
  Rationale: Production must never accept proofs that were not cryptographically verified.
  Date/Author: 2025-12-20 / Codex

- Decision: Replace the “binding signature” name with a plain “binding hash” unless a real signature scheme is implemented.
  Rationale: The current field is a hash commitment, not a signature; the name is misleading and suggests security that does not exist.
  Date/Author: 2025-12-20 / Codex

- Decision: Adopt NUMS Poseidon parameters (width 3, 63 full rounds, SHA-256-derived constants) for commitments/nullifiers/Merkle hashing.
  Rationale: The previous toy Poseidon constants and 8-round configuration do not meet binding/hiding assumptions; NUMS constants provide transparent, non-adversarial parameters.
  Date/Author: 2025-12-20 / Codex

- Decision: Require `--dev` at node startup until non-dev profiles are re-enabled with audited production defaults.
  Rationale: Prevent accidental non-dev starts while hardening work remains in flight; force explicit dev-mode acknowledgement.
  Date/Author: 2025-12-20 / Codex

- Decision: Feature-gate legacy Blake2-wrapped commitment/nullifier helpers and require explicit opt-in for any non-circuit hashing.
  Rationale: Production must only expose circuit-compatible commitments and nullifiers to avoid unsafe or inconsistent hashing paths.
  Date/Author: 2025-12-20 / Codex

- Decision: Enforce a bounded Merkle root history (prune beyond `MerkleRootHistorySize`).
  Rationale: Prevent state bloat and DoS via unbounded anchor storage while keeping a configurable validation window.
  Date/Author: 2025-12-20 / Codex

- Decision: Disable the non-proof `shield` extrinsic in production builds; require proof-backed shielding via `shielded_transfer`.
  Rationale: The simple shield path cannot bind the transparent deposit amount to the note commitment without a proof.
  Date/Author: 2025-12-20 / Codex

## Outcomes & Retrospective

Delivered:
- Production verification now requires real STARK proof bytes/public inputs; legacy and fast verification paths are gated behind explicit features and checked by the hardening script.
- Commitments, nullifiers, and Merkle roots use 4-limb (256-bit) Poseidon outputs with canonical limb checks across circuits, pallet, wallet, and state.
- Poseidon hashing now uses NUMS-derived constants with 63 full rounds, aligned across circuits, runtime, and crypto helper crates.
- Viewing keys store a view-derived nullifier key (`view_nf`), wallet stores migrate safely, and PRF derivations are aligned across crates.
- “Binding signature” renamed to `binding_hash` across runtime, RPC, wallet, tests, and docs.
- Batch proof verification is wired to the batch circuit, and binding hashes are validated as full 64-byte commitments.
- Non-dev nodes refuse mock state execution without an explicit flag; wallet batch proofs are opt-in and memos now hard-fail on oversize payloads.
- Legacy commitment helpers are feature-gated; AIR hash enforcement and bounded Merkle root history prevent silent verification bypass and state bloat.
- Dev-only shielding is disabled in production, unsigned shielded transfers enforce proof size limits, and fee range checks block modulus-malleable proofs.
- Documentation, runbooks, and production checks updated to reflect protocol-breaking encoding changes and operational resets.

Open items:
- None in this ExecPlan scope.

Lessons learned:
- Feature-gating dev-only verification paths plus script-level checks keeps production builds honest without blocking test workflows.

## Context and Orientation

This repository implements a single shielded pool with STARK proofs. A “note commitment” is a public 32‑byte identifier for a note, and a “nullifier” is a public 32‑byte identifier for a spend. Both are currently derived from a 64‑bit field element and serialized by left‑padding; this is too small for production security. The Merkle tree (`state/merkle/src/lib.rs`) stores commitments as field elements and the on‑chain pallet (`pallets/shielded-pool`) validates those encodings. The wallet stores commitments and uses them to build Merkle paths for proofs.

The transaction circuit code lives under `circuits/transaction-core` and `circuits/transaction`. The proof verifier accepts a “fast” set of STARK options and the transaction proof `verify()` function falls back to a legacy consistency checker if no cryptographic proof bytes are present. In the wallet, the `FullViewingKey` currently stores the raw spend key, which is not a safe viewing key. The node’s Substrate client falls back to mock state execution with a zero state root when callbacks are missing. The wallet CLI has a batch send path that encodes an empty proof. All of these are compiled into production unless explicitly gated.

Terms used in this plan:

“Commitment” is the public hash of a note’s contents. “Nullifier” is the public hash used to prevent double‑spends. A “Merkle root” is the root hash of the commitment tree used as the anchor for proofs. A “STARK proof” is a cryptographic proof produced by Winterfell. “Production build” means a binary compiled with the runtime `production` feature and without dev/test features.

Key files to be changed include:

`circuits/transaction-core/src/hashing.rs`, `circuits/transaction-core/src/constants.rs`, `circuits/transaction/src/stark_prover.rs`, `circuits/transaction-core/src/stark_verifier.rs`, `circuits/transaction/src/proof.rs`, `state/merkle/src/lib.rs`, `pallets/shielded-pool/src/commitment.rs`, `pallets/shielded-pool/src/verifier.rs`, `wallet/src/viewing.rs`, `wallet/src/keys.rs`, `wallet/src/store.rs`, `wallet/src/extrinsic.rs`, `wallet/src/notes.rs`, `node/src/substrate/client.rs`, and `node/src/config.rs`. Documentation updates must touch `DESIGN.md`, `METHODS.md`, and `docs/THREAT_MODEL.md` at minimum.

## Plan of Work

### Milestone 1: Lock down production verification paths

Replace any verification code paths that accept legacy or structural‑only proofs. This means updating `circuits/transaction/src/proof.rs` so that `verify()` returns an error if `stark_proof` or `stark_public_inputs` are missing, and moving the legacy consistency checker behind an explicit `legacy-proof` feature used only by tests. In `circuits/transaction-core/src/stark_verifier.rs`, remove the “fast” acceptable options from production builds and keep a single, security‑reviewed set of `ProofOptions`. If a fast profile is still needed for testing, gate it behind a `stark-fast` feature and ensure production builds do not enable it. Update the wallet prover configuration in `wallet/src/prover.rs` so that it actually uses the supplied `StarkProverConfig` values to build `ProofOptions`, and enforce a minimum security floor in production builds. Update `scripts/verify-no-legacy-production.sh` to fail if legacy verification or fast options are present in production targets.

End state: a production build must fail to verify any proof that does not include real STARK bytes, and the verifier must only accept one set of security parameters.

### Milestone 2: Replace 64‑bit commitment/nullifier encodings with 256‑bit outputs

Define a new commitment/nullifier encoding as four 64‑bit field limbs (32 bytes total). In `circuits/transaction-core/src/hashing.rs`, introduce helpers to convert 32‑byte encodings into four field elements and vice‑versa, and make the Poseidon sponge output four limbs by continuing the sponge and extracting four field elements. Update `note_commitment`, `nullifier`, and `merkle_node` to operate on and output these 4‑limb values. In the circuit AIR and prover (`circuits/transaction/src/stark_air.rs`, `circuits/transaction/src/stark_prover.rs`), update the trace to handle four‑limb commitments/nullifiers and update public inputs to carry 4‑limb representations. Replace `is_canonical_bytes32` logic so it validates each limb against the field modulus instead of checking 24 leading zeros.

Update the Merkle tree implementation (`state/merkle/src/lib.rs`) to store nodes as the 4‑limb commitment type rather than a single field element. Update the pallet commitment code (`pallets/shielded-pool/src/commitment.rs`) and verifier input validation (`pallets/shielded-pool/src/verifier.rs`) to use the new canonical encoding and 4‑limb hashing. Update wallet storage (`wallet/src/store.rs`) to persist commitments as 32‑byte encodings and rebuild Merkle paths using the new hash function. Any code that assumes commitments or nullifiers are 64‑bit field values must be updated to work with four‑limb encodings.

This is a protocol‑breaking change. The plan assumes a new chain genesis for production use. Update chain spec generation and runbooks to explicitly require resetting `node.db` and wallet stores when switching to the new commitment scheme. Document this break in `DESIGN.md` and `METHODS.md`, and record the security margins in `docs/THREAT_MODEL.md`.

End state: commitments, nullifiers, and Merkle roots are full 256‑bit encodings derived from a non‑toy Poseidon sponge, and all on‑chain/off‑chain components agree on the encoding.

### Milestone 3: Fix viewing keys and PRF alignment

Define a view‑only nullifier key derived from the view key (`sk_view`) with an explicit domain tag (for example `b"view_nf"`). Store this derived key inside `FullViewingKey` rather than raw spend bytes. Update `wallet/src/viewing.rs` to compute nullifiers from the view‑derived key and update `wallet/src/keys.rs` to expose the derivation for reuse. Align the pallet’s `circuit_prf_key` helper in `pallets/shielded-pool/src/commitment.rs` with `transaction_core::hashing::prf_key` so the PRF derivation is consistent across crates. Update `METHODS.md` to describe the new view‑only nullifier derivation and remove references to exposing spend keys inside viewing keys.

This change affects wallet serialization. Bump the wallet store version and add a migration that, when it encounters an old `FullViewingKey`, derives the view‑only nullifier key and discards the embedded spend key. Make the migration idempotent so it can be rerun safely.

End state: viewing keys are safe to export (no spend key) while still enabling nullifier computation, and all PRF derivations match the circuit.

### Milestone 4: Remove misleading “binding signature” semantics

Rename the “binding signature” concept to “binding hash” unless a real signature scheme is introduced. Update `pallets/shielded-pool/src/types.rs`, `pallets/shielded-pool/src/verifier.rs`, and the wallet transaction bundle types (`wallet/src/rpc.rs`, `wallet/src/extrinsic.rs`, and builders in `wallet/src/tx_builder.rs` and `wallet/src/shielded_tx.rs`) to use the new name and semantics. The verifier should still recompute the hash and compare, but documentation and type names must not suggest a signature. Update the pallet README and `METHODS.md` accordingly. If the change is wire‑format incompatible, bump the transaction version binding and update any JSON or RPC schemas to match.

End state: the code and docs no longer claim a signature where only a hash exists.

### Milestone 5: Remove mock state execution and empty‑proof CLI paths

In `node/src/substrate/client.rs`, remove the production fallback that executes extrinsics with a zero state root. Replace it with a hard error unless an explicit dev flag is enabled. Add a configuration check in `node/src/config.rs` or node startup that rejects non‑dev profiles if state execution callbacks are missing. For the wallet CLI, remove or gate the batch‑send path that constructs empty proofs. Add a `batch-proofs` feature to the wallet crate, and when it is disabled (default for production) the `substrate-batch-send` command should return a clear error or be removed from the CLI entirely.

End state: non‑dev nodes cannot run without real state execution, and CLI paths cannot emit empty proofs in production.

### Milestone 6: Fix memo truncation and insecure defaults

Replace silent truncation of note payload/memo in `wallet/src/notes.rs` and `node/src/shielded_coinbase.rs` with explicit length checks that return errors if sizes exceed the pallet maximums. Add tests covering oversize memos to prevent regression. In `node/src/config.rs`, add validation that rejects default `api_token` and default `miner_seed` values when running in non‑dev profiles; provide explicit CLI or environment overrides for production.

End state: user data is not silently truncated, and production nodes cannot start with predictable secrets.

### Milestone 7: Documentation, tests, and production checks

Update `DESIGN.md`, `METHODS.md`, `docs/THREAT_MODEL.md`, and `docs/API_REFERENCE.md` to reflect the new commitment encoding, proof verification behavior, viewing key semantics, and binding hash naming. Update `scripts/verify-no-legacy-production.sh` to fail if any legacy proof fallback, fast proof options, or mock execution code is present in production builds. Add or update tests in `circuits/transaction-core`, `pallets/shielded-pool`, `wallet`, and `state/merkle` to cover canonical encoding checks, 4‑limb hashing, and viewing‑key migration.

End state: documentation and tests enforce the hardened production guarantees.

## Concrete Steps

All commands below assume the working directory is the repository root.

Fresh clone prerequisites (must run before any build on a new machine):

    make setup
    make node

Local compilation and targeted tests during development:

    cargo test -p transaction-core
    cargo test -p transaction-circuit
    cargo test -p pallet-shielded-pool
    cargo test -p wallet
    cargo test -p state-merkle

Production hardening checks:

    ./scripts/verify-no-legacy-production.sh

Manual validation (dev chain) after changes:

    HEGEMON_MINE=1 ./target/release/hegemon-node --dev --tmp

Expected output examples should be added to this section as each milestone is implemented, using short indented transcripts.

## Validation and Acceptance

Acceptance is observable:

1. A production build rejects any transaction proof missing STARK bytes or public inputs, and no legacy consistency checker can be triggered in production builds.
2. Commitments, nullifiers, and Merkle roots are full 32‑byte values; canonical encoding checks validate each 64‑bit limb against the field modulus and no longer rely on “24 zero bytes” padding.
3. The wallet can generate and verify a shielded transfer without truncating memos; oversized memos cause a clear error.
4. A `FullViewingKey` export no longer contains a spend key, and nullifiers computed from that viewing key still match the chain.
5. Non‑dev nodes refuse to start or mine when state execution is not wired.
6. The batch‑send CLI path cannot emit empty proofs in production builds.

Test expectations:

Run the test commands listed in “Concrete Steps” and ensure all pass. Add a new test that constructs a 4‑limb commitment, serializes it to bytes, deserializes it, and verifies canonical encoding; ensure this fails for any limb ≥ field modulus. Add tests that verify `FullViewingKey` migration and nullifier consistency. Ensure `scripts/verify-no-legacy-production.sh` fails before the changes and passes after.

## Idempotence and Recovery

These steps are safe to rerun; failures should be handled explicitly. Protocol‑level changes to commitment encoding require a chain reset for dev environments. Provide a clear recovery path:

1. Stop the node.
2. Delete `node.db` and any wallet store files.
3. Restart the node with `--dev --tmp` and regenerate wallets.

Wallet store migrations must be versioned and idempotent so repeated runs do not corrupt data. Any production config validation errors should be explicit and actionable (for example: “api_token must be set to a non‑default value for non‑dev profiles”).

## Artifacts and Notes

Example commitment encoding (4‑limb, 32‑byte total):

    0x<limb0><limb1><limb2><limb3>

Example expected hardening failure (non‑dev start without state execution):

    ERROR: state execution is not configured; refuse to start in non‑dev profile

Add real transcripts here as milestones are completed.

## Interfaces and Dependencies

Introduce a canonical commitment type and helpers in `transaction_core::hashing` so every crate uses the same encoding.

In `circuits/transaction-core/src/hashing.rs`, define:

    pub type Commitment = [u8; 32];
    pub fn bytes32_to_felts(bytes: &Commitment) -> Option<[Felt; 4]>;
    pub fn felts_to_bytes32(felts: &[Felt; 4]) -> Commitment;
    pub fn is_canonical_bytes32(bytes: &Commitment) -> bool;

Update any function that returns a commitment or nullifier to return `Commitment` and use these helpers for canonical encoding and decoding.

In `wallet/src/viewing.rs`, define:

    pub struct FullViewingKey {
        pub incoming: IncomingViewingKey,
        nullifier_key: [u8; 32], // view‑only nullifier key
    }

and ensure the stored `nullifier_key` is derived from `sk_view` (not `sk_spend`).

In `pallets/shielded-pool/src/types.rs`, rename `BindingSignature` to `BindingHash` (or equivalent) and update all references accordingly. This should be reflected in any RPC payloads or extrinsic encodings.

Dependencies should remain within the existing Winterfell and hash crates already in the workspace; avoid introducing new external hash crates unless strictly necessary, and document any new dependency in `DESIGN.md` and `docs/THREAT_MODEL.md`.
