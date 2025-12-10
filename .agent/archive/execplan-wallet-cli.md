# Wallet key hierarchy, note encryption, and CLI tooling

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds.

Reference: repository root `.agent/PLANS.md`. All instructions there apply to this plan.

## Purpose / Big Picture

We need an end-to-end wallet layer that can derive hierarchical keys from a root secret, produce diversified addresses, encrypt/decrypt notes and memos with ML-KEM + AEAD, expose viewing keys for scanning/auditing, and provide CLI/test harnesses so humans can generate addresses, craft transactions, and recover balances using viewing keys. After this work someone can run a CLI command to create a wallet, derive addresses, encrypt notes to another wallet, and verify via tests that incoming/outgoing viewing keys recover balances compatible with the transaction circuit’s `NoteData`/`TransactionWitness` expectations.

## Progress

- [x] (2025-11-15 20:50Z) Drafted initial ExecPlan describing wallet crate, note encryption, viewing keys, CLI, and tests.
- [x] Scaffold the `wallet` crate with module layout, dependencies, and re-exports referenced below. (2025-11-15 21:35Z: crate added to workspace with deps and module skeletons.)
- [x] Implement hierarchical key derivations and address PRFs in `wallet/src/keys.rs` with tests. (2025-11-15 22:10Z: root/derived keys, address encoding, tests in place.)
- [x] Implement ML-KEM note encryption/memo AEAD plus ciphertext structs in `wallet/src/notes.rs` with tests. (2025-11-15 22:45Z: note/memo AEAD + deterministic ML-KEM integration complete.)
- [x] Implement incoming/outgoing/full viewing key structs and scanning helpers in `wallet/src/viewing.rs` (or similar) wired to transaction circuit data types. (2025-11-15 23:05Z: incoming/full VKs decrypt and produce circuit-compatible witnesses.)
- [x] Build CLI binaries (e.g., `wallet-cli`) supporting address generation, transaction crafting, and viewing-key balance recovery plus integration tests/harnesses. (2025-11-16 00:10Z: `wallet` CLI with generate/address/tx-craft/scan commands plus end-to-end tests.)
- [x] Update DESIGN.md and METHODS.md to reflect concrete wallet/address/encryption behavior. (2025-11-16 00:15Z: documented wallet crate, HKDF labels, AEAD layout, and CLI workflows.)
- [x] Add automated tests exercising key derivation, encryption/decryption round-trips, viewing key scanning, and CLI flows; run `cargo test --all`. (2025-11-16 00:20Z: unit + CLI integration tests plus `cargo test --all` passing.)
- [x] (2025-11-16 00:30Z) Final review complete; ExecPlan updated with decisions and retrospective, workspace tests re-run, and PR prepared.

## Surprises & Discoveries

- None encountered. Implementation followed the original design expectations and integrations were straightforward.

## Decision Log

- (2025-11-15) Adopted ChaCha20-Poly1305 for AEAD-wrapping of both note payloads and memos, driven by the 256-bit key size matching ML-KEM shared secrets and availability of constant-time Rust crates.
- (2025-11-15) Encoded diversified shielded addresses with Bech32m (`shca` HRP) to align with ecosystem conventions and allow checksumed human-facing strings.
- (2025-11-16) Exported CLI artifacts as JSON (witnesses, ciphertexts, balance reports) to interoperate with existing transaction-circuit tooling and simplify integration tests.

## Outcomes & Retrospective

- Hierarchical key derivation, diversified address generation, ML-KEM note encryption, and viewing key flows are fully implemented in the `wallet` crate with unit tests.
- The new CLI covers wallet generation, address derivation, transaction crafting, and ledger scanning; integration tests drive end-to-end coverage.
- Documentation (DESIGN.md §4.3, METHODS.md §4.5) now reflects the concrete algorithms and workflows, keeping the spec in sync with the implementation.

## Context and Orientation

Current workspace members include `crypto`, `circuits/transaction`, `circuits/block`, `state/merkle`, `consensus`, and `network`, but there is no wallet crate yet. The design docs (`DESIGN.md` §4 and `METHODS.md` §4) describe the intended key hierarchy, diversified addresses, and ML-KEM-based note encryption but nothing implements it. The transaction circuit expects `NoteData` (value, asset_id, pk_recipient, rho, r) and `TransactionWitness` contains `sk_spend` plus nullifier/commitment logic. Our wallet layer must produce these witness inputs, compute note commitments/nullifiers consistent with `circuits/transaction`, and supply ciphertext payloads for the network layer. We will add a new `wallet` crate with modules:

- `wallet/src/lib.rs` exporting keys, notes, addresses, viewing key types, and CLI helpers.
- `wallet/src/keys.rs` handling `sk_root`, derived keys, diversifier PRFs, address encoding/decoding, and nullifier key derivations using `synthetic-crypto` hashing utilities.
- `wallet/src/notes.rs` defining plaintext/note ciphertext formats, ML-KEM encapsulation/decapsulation utilities, AEAD wrappers for note payloads/memos, and conversion helpers into `circuits::transaction::note::NoteData`.
- `wallet/src/viewing.rs` (or similarly named) implementing incoming/full viewing key structs, scanning/decapsulation loops, and methods to derive outgoing note metadata for auditing.
- `wallet/src/bin/wallet.rs` (CLI) using `clap` to expose commands for key generation, address derivation, crafting transaction witnesses/commitments, and viewing-key-based scanning/balance recovery.
- Integration tests under `wallet/tests` or workspace `tests/` verifying CLI flows and ledger scanning.

The wallet crate will depend on:

- `synthetic-crypto` for ML-KEM, deterministic RNG, and hash utilities.
- `circuits/transaction` for `NoteData`, `InputNoteWitness`, `TransactionWitness`, etc.
- External crates for AEAD (e.g., `chacha20poly1305`), serialization (`serde`, `bincode`/`hex`), and CLI (`clap`, `anyhow`).

## Plan of Work

1. **Scaffold the wallet crate**
   - Create `wallet/Cargo.toml` with dependencies on `synthetic-crypto`, `circuits-transaction` (crate rename), `serde`, `serde_json`, `bincode`, `rand`, `clap`, `anyhow`, `chacha20poly1305`, `hex`, etc.
   - Add `wallet/src/lib.rs` declaring modules `keys`, `notes`, `viewing`, `address`, `cli` (if needed) and re-exporting core structs (`RootSecret`, `DerivedKeys`, `ShieldedAddress`, `NoteCiphertext`, `IncomingViewingKey`, etc.).
   - Update workspace `Cargo.toml` members to include `"wallet"` and ensure `wallet` uses edition 2021.

2. **Implement hierarchical key derivations in `wallet/src/keys.rs`**
   - Define `RootSecret([u8; 32])` with serialization helpers, `from_entropy`, `from_bytes`, `to_bytes`.
   - Implement deterministic HKDF-like derivation using `crypto::deterministic::expand_to_length` or a small HKDF helper to produce 32-byte derived keys for `sk_spend`, `sk_view`, `sk_enc`, `sk_derive`.
   - Define `SpendKey`, `ViewKey`, `EncryptionKeySeed`, `DiversifierKey`, `NullifierKey`, with methods to compute `pk_recipient = blake3(sk_view || diversifier)` and `address_tag = sha256("addr-tag" || sk_view || diversifier_index_le)`.
   - Implement address diversification PRFs: given `diversifier_index: u32`, derive `diversifier_bytes = sha256("diversifier" || sk_derive || index_le)` and use that to deterministically derive ML-KEM key pairs (seed in `MlKemKeyPair::generate_deterministic`).
   - Provide `ShieldedAddress` struct (version byte, diversifier index, ML-KEM public key bytes, address tag) plus Bech32/base32 or hex encoding/decoding for CLI use.
   - Unit tests verifying derivations are deterministic and domain separated, `ShieldedAddress::encode/decode` round-trips, and `pk_recipient` lengths match circuit expectations.

3. **Implement note encryption/memo AEAD in `wallet/src/notes.rs`**
   - Define `NotePlaintext` (value, asset_id, rho, r, memo bytes, diversifier index) and conversion to/from `NoteData`.
   - Use ML-KEM deterministic keygen from `keys::DerivedAddress` to obtain `MlKemPublicKey`/`MlKemSecretKey` per address.
   - When encrypting: encapsulate using recipient PK with random seed, derive shared secret -> HKDF to produce AEAD key and nonce(s). Use `chacha20poly1305` (256-bit key) to encrypt `NotePayload = (value, asset_id, rho, r, addr_tag, memo_commitment)`. Provide optional separate AEAD for memo (if memos stored separately) or include memo in payload; requirement mentions “AEAD wrapping for memos and note payloads” so wrap both: first encrypt note body, then memo (maybe with independent nonce derived by HKDF label "memo").
   - Define `NoteCiphertext` struct bundling `MlKemCiphertext`, `note_payload: Vec<u8>`, `memo_ciphertext: Vec<u8>`, plus authentication tags.
   - Implement `NoteCiphertext::encrypt` (takes recipient address + plaintext) and `NoteCiphertext::decrypt` (takes `IncomingViewingKey`/`AddressKeyMaterial`) returning `NotePlaintext` if authentication succeeds.
   - Provide tests verifying encryption/decryption round-trip, deterministic seed ensures reproducible test vectors when RNG seeded, and failure cases (bad tag, wrong key) return errors.

4. **Viewing keys and scanning (`wallet/src/viewing.rs`)**
   - Define `IncomingViewingKey` containing `diversifier_key`, `sk_enc(seed)`, map of derived addresses, and ML-KEM secret key derivation helper (`fn decap(&self, diversifier_index)` returning `MlKemSecretKey`). Provide method `scan_note(&self, note_ct: &NoteCiphertext) -> Option<RecoveredNote>` that iterates over candidate diversifier indices (bounded or dynamic) to attempt decapsulation/decryption.
   - Define `FullViewingKey` extending incoming key with `pk_recipient` derivation material and `nullifier_key` (derived from `sk_spend` or `sk_view` per design). Provide method `compute_nullifier(rho, position)` returning `[u8;32]` consistent with `circuits::transaction::hashing::nullifier(prf_key, ...)` by storing the PRF key inside FVK.
   - Provide `OutgoingViewingKey` or watchers for memos/outgoing detection as needed.
   - Ensure `FullViewingKey` can produce `TransactionWitness`-compatible data: e.g., `fn to_transaction_witness_inputs(&self, notes: &[RecoveredNote], merkle_root: Felt, fee: u64) -> TransactionWitness` by populating `sk_spend` (requires wallet to hold actual `SpendKey`). Document separation: wallet root controls `SpendKey`; FVK does not include `sk_spend`, but wallet owner (with root) can convert to FVK easily.
   - Tests verifying scanning finds inserted notes, `FullViewingKey` computes same nullifier as circuit `TransactionWitness`, and viewing key serialization works.

5. **CLI tooling and test harnesses**
   - Add `wallet/src/bin/wallet.rs` using `clap` with subcommands:
     - `wallet generate` – create new root secret, print encoded address and viewing keys.
     - `wallet address derive --index N --format json` – derive diversified address, show `pk_recipient`, ML-KEM public key, encoded string.
     - `wallet tx craft --inputs input.json --outputs outputs.json --fee X` – load notes, construct `TransactionWitness`, output JSON containing nullifiers, commitments, ciphertexts.
     - `wallet scan --viewing-key vk.json --ledger ledger.json` – use incoming/full viewing key to decrypt note ciphertexts and compute balance.
   - CLI uses serialization helpers defined in wallet library (structures for addresses, viewing keys, ciphertext). Provide `serde` implementations for saving/loading from disk.
   - Provide sample data/harness in `wallet/tests/cli.rs` or workspace `tests/wallet_cli.rs` that spawns CLI commands (via `assert_cmd` or `escargot`) to ensure flows succeed.

6. **Documentation updates**
   - Update `DESIGN.md` section 4 with actual note encryption pipeline (nonce derivation, AEAD choice, address encoding) and viewing key capabilities.
   - Update `METHODS.md` to reflect concrete algorithms for HKDF labels, ciphertext layout, CLI usage expectations.

7. **Testing/validation**
   - Add unit tests in wallet crate verifying each module.
   - Add integration tests ensuring CLI command outputs and viewing key scanning produce expected balances and `TransactionWitness` data matches circuit hashing functions.
   - Run `cargo fmt`, `cargo clippy --all`, and `cargo test --all` to ensure workspace passes.

## Concrete Steps

1. `cargo new wallet --lib` inside repo root; update workspace `Cargo.toml` to include `"wallet"`.
2. Add dependencies to `wallet/Cargo.toml` (`synthetic-crypto`, `circuits-transaction` via `path = "../circuits/transaction"`), plus external crates (`serde`, `serde_json`, `bincode`, `clap`, `anyhow`, `rand`, `hex`, `chacha20poly1305`, `sha2`, `thiserror`).
3. Implement `wallet/src/lib.rs`, `keys.rs`, `notes.rs`, `viewing.rs`, `address.rs`. Keep modules small and document public interfaces with doc-comments.
4. Create CLI binary `wallet/src/bin/wallet.rs` hooking into library modules.
5. Add tests under `wallet/src/` and `wallet/tests/` verifying derivations, encryption, scanning, CLI flows.
6. Update docs (`DESIGN.md`, `METHODS.md`) accordingly.
7. Run workspace formatting and tests:
   - `cargo fmt --all`
   - `cargo clippy --all -- -D warnings`
   - `cargo test --all`

## Validation and Acceptance

- Unit tests in `wallet` verifying deterministic derivations, address encoding, note encryption/decryption, and viewing key scanning must pass.
- Integration test (CLI harness) demonstrates generating two wallets, sending a note, crafting a transaction witness, and recovering balances with an incoming viewing key.
- CLI commands produce valid JSON artifacts matching `circuits/transaction` structures (e.g., `TransactionWitness` serialization accepted by circuit tests).
- Running `cargo test --all` passes, showing wallet crate integrates with workspace.
- Documentation updates clearly describe wallet/address/encryption flow.

## Idempotence and Recovery

- Creating the wallet crate and running `cargo fmt/test` are idempotent; rerunning commands will update files deterministically.
- CLI commands write outputs only to specified files/STDOUT; reruns overwrite same outputs due to deterministic derivations.
- Tests do not modify global state beyond target dirs; `cargo clean` can reset if needed.

## Artifacts and Notes

- Provide sample address/viewing-key JSON fixtures under `wallet/tests/fixtures/` referenced by CLI tests.
- Include transcripts in doc comments or README snippet showing CLI usage for manual verification.

## Interfaces and Dependencies

- `wallet::keys` exposes:
      pub struct RootSecret(pub [u8; 32]);
      impl RootSecret { pub fn derive(&self) -> DerivedKeys { … } }
      pub struct DerivedKeys { pub spend: [u8;32], pub view: [u8;32], pub enc: [u8;32], pub derive: [u8;32]; }
      pub struct ShieldedAddress { pub diversifier_index: u32, pub pk_enc: [u8;1184], pub addr_tag: [u8;32], pub pk_recipient: [u8;32]; }
      pub fn derive_ml_kem_pair(sk_derive: &[u8;32], index: u32) -> MlKemKeyPair;

- `wallet::notes` exposes:
      pub struct NotePlaintext { pub value: u64, pub asset_id: u64, pub rho: [u8;32], pub r: [u8;32], pub memo: Vec<u8>, pub pk_recipient: [u8;32]; }
      pub struct NoteCiphertext { pub kem: MlKemCiphertext, pub payload: Vec<u8>, pub memo_ct: Vec<u8>; }
      impl NoteCiphertext { pub fn encrypt(addr: &ShieldedAddress, note: &NotePlaintext, rng: impl RngCore) -> Self; pub fn decrypt(ivk: &IncomingViewingKey, ct: &NoteCiphertext) -> Result<RecoveredNote, WalletError>; }

- `wallet::viewing` exposes:
      pub struct IncomingViewingKey { … } with methods to derive addresses and decrypt notes; 
      pub struct FullViewingKey { pub incoming: IncomingViewingKey, pub nullifier_key: [u8;32]; }
      pub struct RecoveredNote { pub note: NotePlaintext, pub diversifier_index: u32 } linking back to circuit `NoteData`.

- CLI binary uses `clap::Parser` and library modules to implement commands described above.

