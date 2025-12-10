# Consensus and P2P stack with PQ authentication

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds. PLANS.md (located at `.agent/PLANS.md`) governs this document and must be followed precisely.

## Purpose / Big Picture

The goal is to stand up an initial end-to-end consensus and networking stack that ties together the repository's STARK-based transaction proofs, Merkle state, and post-quantum cryptographic primitives. After completing the work, a node process will be able to: (1) produce and verify block headers carrying STARK proof commitments, note commitment tree roots, and ML-DSA validator signatures; (2) execute a basic BFT-style block validation flow enforcing nullifier uniqueness with a slashing-oriented fork choice rule; (3) participate in a secure P2P overlay using ML-DSA identities and ML-KEM-derived session keys to gossip transactions and blocks; and (4) run deterministic simulation tests plus protocol-level fuzzing that demonstrate liveness and safety against faulty peers.

## Progress

- [x] (2025-02-14 00:00Z) Draft comprehensive specification docs for block headers and consensus rules.
- [x] (2025-02-14 00:00Z) Scaffold new `consensus` and `network` crates with data structures, crypto plumbing, and validation logic.
- [x] (2025-02-14 00:00Z) Implement BFT-style consensus engine with nullifier uniqueness checks and fork-choice/slashing semantics.
- [x] (2025-02-14 00:00Z) Build P2P handshake, authenticated identity layer, and gossip protocols using ML-DSA and ML-KEM.
- [x] (2025-02-14 00:00Z) Author simulation + fuzz tests covering consensus safety/liveness and adversarial network behavior.
- [x] (2025-02-14 00:00Z) Update design/methods docs if architecture diverges and finalize documentation (no doc changes required).

## Surprises & Discoveries

- Observation: ML-KEM encapsulation had to target the counterparty public key; early handshake attempts encapsulated to the local keypair, producing mismatched session keys.
  Evidence: Initial secure channel decrypts failed with `Encryption` errors until the encapsulation inputs were corrected.

- Observation: Serde derive support stops at 32-byte arrays, so block header hashing now uses custom byte encoding instead of `bincode` derives.
  Evidence: Compilation errors (`E0277`) arose when deriving `Serialize` for `[u8; 48]` proof commitments.

## Decision Log

- Decision: Encode block header signing preimages manually to avoid serde trait gaps on 48-byte commitments.
  Rationale: Manual encoding keeps the format deterministic without introducing third-party serde helper crates.
  Date/Author: 2025-02-14 / assistant.

- Decision: Use responder-generated ML-KEM ciphertexts and shared secrets to seed session keys, combining both handshake secrets through SHA-256.
  Rationale: Ensures symmetric key derivation while staying within the deterministic crypto module already in the repo.
  Date/Author: 2025-02-14 / assistant.

## Outcomes & Retrospective

- Consensus crate now validates block headers, nullifiers, and signatures for both BFT and PoW paths, with fork-choice producing slashing evidence on equivocation.
- Network crate authenticates peers with ML-DSA, performs ML-KEM-derived key exchanges, and encrypts gossip messages; integration tests demonstrate successful decrypts.
- Simulation and fuzz suites exercise validator liveness, slashing detection, and nullifier uniqueness, catching earlier handshake regressions during development.

Remaining follow-ups: extend docs in `DESIGN.md` if future iterations introduce additional consensus variants.

## Context and Orientation

The repository is a Rust workspace composed of crates for cryptography (`crypto/`), transaction/block proving circuits (`circuits/transaction` and `circuits/block`), and Merkle state management (`state/merkle`). There is currently no consensus or networking crate. Consensus must incorporate:

- STARK proof commitments produced by the block circuit (`circuits/block`). These commitments summarize batched transaction proofs.
- Nullifier tracking to prevent double spends, leveraging the note commitment tree managed by `state/merkle`.
- ML-DSA signatures and ML-KEM session keys from the `crypto` crate.

The plan introduces a `consensus` crate with two main modules: `spec/` (human-readable spec files) and `core/` (Rust implementation). It also adds a `network` crate to encapsulate the P2P layer. Simulation tests will live under `tests/` in a new integration module and rely on deterministic RNG fixtures from `crypto`.

## Plan of Work

1. **Specification authoring.** Create Markdown docs under `consensus/spec/` describing block header layout, commitment fields, signature requirements, and consensus state transitions. Detail validator staking, slashing triggers, and fork-choice algorithm.
2. **Crate scaffolding.** Add `consensus/` and `network/` crates to the workspace. Define data structures for block headers, validator sets, nullifier sets, and peer identities. Implement serialization (using `serde`) and hashing helpers (via `crypto::hashes`).
3. **Consensus engine.** Implement a simplified HotStuff-style BFT consensus with stake-weighted voting. Include nullifier uniqueness enforcement by maintaining a map/set keyed by nullifier hash. Define slashing conditions for double-signing and fork-choice rules favoring the highest justified view number. Provide a PoW fallback variant as an alternate module to satisfy the user requirement.
4. **Proof verification.** Hook the consensus validation flow to verify block proof commitments using `circuits/block` verification stubs (or placeholder trait if verifier not yet implemented). Ensure block verification checks Merkle roots, nullifier updates, and ML-DSA signatures.
5. **Networking layer.** Create P2P handshake exchanging ML-DSA identity certificates, followed by ML-KEM key exchange deriving symmetric session keys for AES-256-GCM encryption. Implement gossip for transactions and blocks with rate limiting and deduplication. Provide stubs for message encoding/decoding and integrate with consensus event loop.
6. **Testing.** Build deterministic simulations using async runtimes (e.g., `tokio` or `smol`) to instantiate multiple validator nodes. Cover happy-path liveness, Byzantine misbehavior (double-sign, equivocation), and network partitions. Add fuzz tests with `proptest` or custom random message scheduling to assert safety invariants (no double inclusion of nullifiers, consistent finalized blocks).
7. **Documentation updates.** If consensus design deviates from `DESIGN.md` or `METHODS.md`, update those files. Ensure new spec docs cross-reference the design rationale.

## Concrete Steps

1. Run `cargo new --lib consensus` and `cargo new --lib network`, then add them to `Cargo.toml` workspace members.
2. Populate `consensus/spec/` with `block_header.md` and `consensus_protocol.md`, describing header fields, proof commitment layout, signatures, staking, fork-choice, and slashing logic.
3. In `consensus/src/lib.rs`, define modules for `header`, `validator`, `state`, `bft`, and `pow`. Implement data structures and verification traits. Provide unit tests validating serialization, hashing, and signature verification using `crypto::ml_dsa` fixtures.
4. In `consensus/src/bft.rs`, implement HotStuff-like phases (Prepare, Pre-Commit, Commit) with stake-weighted quorum certificates. Ensure nullifier set updates throw errors on duplicates. Include PoW variant in `consensus/src/pow.rs` verifying proof-of-work difficulty plus proof commitments.
5. In `network/src/lib.rs`, create peer identity type wrapping ML-DSA keys, handshake state machine performing ML-KEM key exchange, and encrypted transport using `aes-gcm`. Implement gossip routers for transactions and blocks, including deduplication caches keyed by hash.
6. Add integration tests in `tests/consensus_sim.rs` spinning up multiple validator instances connected via in-memory channels to exercise consensus under normal and adversarial scenarios. Use deterministic RNG seeds from `crypto::hashes::test_rng`. Add fuzz tests in `tests/fuzz_protocol.rs` leveraging `proptest` to randomize message schedules and peer faults.
7. Update `Cargo.toml` dependencies and ensure `cargo fmt`, `cargo clippy`, and `cargo test --all` pass. Document behavior in new spec files and ensure README references the consensus layer.

## Validation and Acceptance

- Running `cargo test --all` must pass and include new unit and integration tests demonstrating consensus liveness and safety invariants.
- Simulation tests should show that honest validators finalize blocks with valid proofs and nullifier sets. Evidence includes log assertions or counters.
- Fuzz tests must cover adversarial inputs without panics, and must fail before the fix if consensus validation is intentionally broken.

## Idempotence and Recovery

All introduced commands are additive and safe to rerun. Creating crates via `cargo new` can be repeated only after deleting the generated directories; note this in instructions. Tests are deterministic given fixed RNG seeds, so rerunning them is safe. No destructive migrations are involved.

## Artifacts and Notes

To be populated with command transcripts and noteworthy code snippets as implementation proceeds.

## Interfaces and Dependencies

- Depend on `crypto` crate modules: `crypto::ml_dsa` for key generation and signatures, `crypto::ml_kem` for key exchange, `crypto::hashes` for hashing and commitments.
- Use `serde` and `bincode` for message serialization. Employ `tokio` for async networking and `aes-gcm` for encryption.
- Define public interfaces:

    In `consensus/src/lib.rs`:
        pub struct BlockHeader { /* fields */ }
        pub struct Block { pub header: BlockHeader, pub transactions: Vec<Transaction> }
        pub trait ProofVerifier { fn verify_block(&self, header: &BlockHeader) -> Result<(), ProofError>; }
        pub trait ConsensusEngine { fn apply_block(&mut self, block: Block) -> Result<ConsensusUpdate, ConsensusError>; }

    In `network/src/lib.rs`:
        pub struct PeerIdentity { /* ML-DSA keys */ }
        pub struct SecureChannel { /* session keys */ }
        pub trait Gossip { fn broadcast_block(&self, block: Block); fn broadcast_transaction(&self, tx: TransactionEnvelope); }

