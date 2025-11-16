# Wallet daemon, RPC sync, and transaction submission

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds.

Reference: repository root `.agent/PLANS.md`. All instructions there apply to this plan.

## Purpose / Big Picture

Operators need a real wallet that can keep up with the node’s RPC API, manage encrypted account state, detect incoming notes, and submit transactions end-to-end. After this work, someone can initialize two wallet stores, export a viewing key to a watch-only instance, run `wallet daemon` (or a `sync` subcommand) against a running node, send funds from one wallet to the other, and observe balances plus nullifier handling update automatically. The daemon talks to the node over HTTP/WebSocket, rebuilds a local commitment tree, tracks nullifiers, and maintains the most recent note ciphertexts so the incoming viewing key can recover notes.

## Progress

- [x] (2025-02-14 12:20Z) Drafted initial ExecPlan covering RPC additions, wallet storage/daemon, transaction submission, and integration tests.
- [x] Extend consensus + node crates to carry note ciphertext bytes inside `consensus::Transaction`, persist them in `Storage`, and expose `/wallet/{commitments,ciphertexts,nullifiers}` RPC endpoints with pagination plus `/transactions/submit` accepting the new payload.
- [x] Add wallet-side RPC client/transport types (`wallet::rpc`) plus CLI subcommands (`init`, `daemon`, `sync`, `status`, `send`, `export-viewing-key`) that authenticate with the node API, keep a local Merkle tree/nullifier set, and manage encrypted stores.
- [x] Implement encrypted wallet storage (Argon2 + ChaCha20-Poly1305), key derivation caching, tracked note/nullifier metadata, and background sync worker that fetches blocks/commitments/nullifiers/ciphertexts via the RPC client while updating balances.
- [x] Wire transaction submission plumbing: pick notes, compute nullifiers/fees, build `TransactionWitness`, call `transaction_circuit::proof::prove`, wrap ciphertexts + proof in the canonical JSON payload, POST to the node, and track async status (poll `/blocks/latest` + `/ws` events for mined/confirmed updates).
- [x] Extend wallet README + METHODS/DESIGN to describe the daemon workflow, storage layout, RPC expectations, and note how friends can import viewing keys. Cover flows with integration tests that start a test node + two wallets, ensuring send/receive/balance updates/nullifier handling all work.

## Surprises & Discoveries

- None yet.

## Decision Log

- None yet.

## Outcomes & Retrospective

- Pending.

## Context and Orientation

The repo already has a `wallet` crate that can derive keys, encrypt notes, and run a CLI for generate/address/tx-craft/scan based on local JSON fixtures. It lacks any persistence, RPC connectivity, or transaction submission logic. The `node` crate exposes `/transactions`, `/blocks/latest`, `/wallet/notes`, `/metrics`, and `/ws` endpoints guarded by the `x-auth-token` header, but it currently only ingests `transaction_circuit::TransactionProof` bodies and does not persist note ciphertexts or expose the commitment/nullifier stream that wallets need. The `consensus::types::Transaction` structure carries nullifiers, commitments, balance tags, and version bindings but no ciphertext data.

State synchronization requires:

- The node storing every note commitment, nullifier, and ciphertext in insertion order, exposing them over paginated RPC endpoints.
- A wallet daemon maintaining the same `state_merkle::CommitmentTree` depth as the node so it can compute note positions for witnesses.
- Storage encryption for secrets, tracked notes (value/asset_id/rho/r), nullifier status, and cursors pointing at the last synced commitment/ciphertext indices.
- Transaction submission code that wraps the existing `transaction_circuit` witness/proof flows and posts to the updated node API, then polls WebSocket/HTTP endpoints for confirmation.

## Plan of Work

1. **Consensus & node transport upgrades**
   - Extend `consensus::types::Transaction` with a `ciphertexts: Vec<Vec<u8>>` field representing serialized note ciphertext payloads. Update `Transaction::new` and `compute_transaction_id` to incorporate this field (hash over ciphertext bytes in order). Adjust all call sites (tests, block builder) to pass the extra argument, defaulting to empty for old fixtures.
   - Introduce a `TransactionBundle` struct (in a shared module under `wallet/src/rpc.rs` or `wallet/src/transport.rs`) that contains a `TransactionProof` plus the concrete `wallet::NoteCiphertext` list. Node API, gossip, and wallet RPC client will all use this struct for serialization.
   - Update `node::transaction::ValidatedTransaction` to store ciphertext bytes; change `proof_to_transaction` to accept ciphertext slices and `felt_vec_to_commitments` to zip them, ensuring length consistency. Broadcast the bundle (proof + ciphertext) over gossip instead of proof-only payloads.
   - Extend `node::storage::Storage` with a `ciphertexts` tree keyed by global commitment index, plus helper methods `append_ciphertext(index, bytes)` and `load_ciphertexts(start, limit)`. Provide paginated versions of `load_commitments` (`load_commitments_range`) so RPC can serve incremental updates.
   - Expand `node::api` with new routes:
     * `POST /transactions` now accepts `TransactionBundle` JSON.
     * `GET /wallet/commitments?start=&limit=` returning `{ entries: [{ index, value_hex }] }`.
     * `GET /wallet/ciphertexts?start=&limit=` returning `{ entries: [{ index, ciphertext: <base64> }] }` where ciphertext bytes are bincode-serialized `NoteCiphertext` structs.
     * `GET /wallet/nullifiers` returning `{ nullifiers: [<hex>] }` (full set; fine for now) and extend `/wallet/notes` to include `next_index`.
   - Update `node::service::accept_block` so that when appending commitments it also stores the matching ciphertext bytes. Validate in `validate_and_add_transaction` that ciphertext count equals non-zero commitments.

2. **Wallet RPC client + storage layer**
   - Create `wallet/src/rpc.rs` exposing `WalletRpcClient` with blocking `reqwest` under the hood. Methods: `latest_block`, `note_status`, `commitments(start, limit)`, `ciphertexts(start, limit)`, `nullifiers()`, `submit_transaction(TransactionBundle)`, plus a WebSocket helper to subscribe to `/ws` events (using `tokio_tungstenite` or `websocket` crate) for async status.
   - Define `wallet/src/store.rs` containing the encrypted wallet file format: `WalletFile { version, salt, nonce, ciphertext }` and `WalletState { root: RootSecret, derived: DerivedKeys, ivk: IncomingViewingKey, fvk: FullViewingKey, ovk: OutgoingViewingKey, notes: Vec<TrackedNote>, spent_nullifiers: HashSet<[u8;32]>, next_commitment_index: u64, next_ciphertext_index: u64 }`.
   - Use `argon2` to derive a 32-byte key from the passphrase + salt, encrypt `WalletState` using `ChaCha20Poly1305`. Provide APIs `WalletStore::create(path, passphrase)` and `WalletStore::open(path, passphrase)` plus mutation helpers that auto-save.
   - Add `TrackedNote` struct storing note plaintext, memo, commitment value, Merkle position, ciphertext index, and nullifier. Keep a local `state_merkle::CommitmentTree` inside the store (persisted as serialized vector) to recompute positions when fetching new commitments.
   - Implement background sync logic (`WalletSyncEngine`): given RPC client + store, fetch commitments/ciphertexts starting at stored cursors, append to tree, decode ciphertext bytes into `NoteCiphertext`, decrypt via IVK, and if note belongs to wallet add to tracked notes. Fetch nullifiers and mark tracked notes as spent when their computed nullifier is present. Update balances per asset id.

3. **CLI/daemon UX**
   - Extend `wallet/src/bin/wallet.rs` with new subcommands:
     * `init`: create encrypted store, optionally print first address.
     * `daemon`: run an infinite sync loop with configurable interval; also expose `sync` for one-shot fetch (use same engine but stop after one cycle).
     * `status`: show balances and pending transactions (read from store only).
     * `send`: pick spendable notes to cover `value + fee`, compute witness inputs (positions/nullifiers), craft ciphertexts for outputs, run `prove`, submit via RPC client, and record pending transaction metadata in the store so daemon can watch status.
     * `export-viewing-key`: dump incoming viewing key JSON so a friend can import watch-only mode (CLI flag `--watch-only` uses IVK only).
   - Parameterize commands with `--store`, `--passphrase`, `--rpc-url`, `--auth-token`, `--poll-interval`, etc. Non-interactive inputs keep CI deterministic.
   - Add watch-only mode in store: allow storing `IncomingViewingKey` without root secret and skip spending features.

4. **Transaction submission & status tracking**
   - Implement `wallet::transaction_builder` helper that selects inputs, builds `TransactionWitness`, runs `transaction_circuit::proof::prove`, and returns `TransactionBundle` along with local metadata (nullifiers, positions). Use existing note encryption to build ciphertexts for recipients (addresses + memos + change note back to self).
   - Add pending transaction tracking to store: `PendingTx { tx_id, submitted_at, nullifiers, commitments, status }`. When daemon runs, poll `/blocks/latest` and `/wallet/nullifiers` to see if pending nullifiers entered the chain; update status to `Mined` and track confirmation count via height difference.
   - Integrate WebSocket listener in daemon (spawned thread) to react to `NodeEvent::Transaction` / `NodeEvent::Block` for faster updates; fall back to polling when WS unavailable.

5. **Docs & tests**
   - Update `wallet/README.md`, `DESIGN.md` (section on wallet sync + RPC), and `METHODS.md` (operations + tests) to explain the new daemon workflow, file format, RPC endpoints, and viewing-key export/import.
   - Add integration tests under `wallet/tests/rpc_flow.rs` (or `tests/wallet_daemon.rs`) that:
     1. Start a temporary node service + API server (use tokio runtime in tests).
     2. Initialize two wallet stores (sender full wallet, receiver watch-only via exported IVK).
     3. Run sync to fetch genesis data, craft/send a payment, and assert the receiver detects incoming note + updated balance while the sender’s note is marked spent once mined.
     4. Verify nullifier handling by submitting another transaction that spends the new note and ensuring balances drop + nullifier recorded.
   - Cover error cases (invalid passphrase, mismatched ciphertext length) with unit tests in wallet crate.

## Concrete Steps

1. Modify `consensus/src/types.rs` to add `ciphertexts: Vec<Vec<u8>>`, update constructors/hash, and adjust downstream callers/tests.
2. Add shared `TransactionBundle` struct (likely `wallet/src/rpc/types.rs`) plus serde helpers; expose it via `pub use` so node can import.
3. Update `node` crate: `transaction.rs`, `service.rs`, `mempool.rs`, `api.rs`, `storage.rs`, and `Cargo.toml` (add `reqwest`? no) to accept/store ciphertext bytes, expose new RPC endpoints, and validate bundle lengths.
4. Add wallet RPC client + store modules, integrate `argon2`, `reqwest` (blocking), `state-merkle`, `tokio-tungstenite` (for WebSocket), and `parking_lot` for store locking.
5. Extend CLI with new subcommands, hooking up store + RPC client.
6. Implement sync/daemon logic and transaction builder.
7. Write integration tests and unit tests.
8. Update docs.
9. Run `cargo fmt`, `cargo clippy --all -- -D warnings`, `cargo test --all`, plus targeted wallet/node tests.

## Validation and Acceptance

- `wallet daemon` against a test node continually fetches new commitments/ciphertexts/nullifiers without panics, updating the local commitment tree and showing accurate balances via `wallet status`.
- `wallet send` posts a transaction that shows up in the node’s `/transactions` response, enters the mempool (confirmed via `/ws` event), and eventually appears in `/wallet/commitments`; the receiver’s watch-only wallet decrypts the ciphertext and reports the credit.
- Integration test spins up two wallets + node and asserts end-to-end send/receive plus nullifier-based spent detection.
- Docs describe how to initialize stores, run daemon, export viewing keys, and monitor pending transactions.

## Idempotence and Recovery

- RPC sync logic maintains cursors so rerunning `wallet sync` picks up where it left off without duplicating notes; store writes are atomic (write temp file then rename) so crashes do not corrupt state.
- Daemon handles network errors with retries/backoff and does not drop secrets.
- Transaction submission retries only before the bundle is accepted; after receiving a tx_id it avoids double-submitting.

## Artifacts and Notes

- Include JSON snippets showing `TransactionBundle` and RPC responses in docs.
- Document encrypted store layout (base64 salt/nonce/ciphertext) in README for debugging.

## Interfaces and Dependencies

- New dependency set for wallet crate: `argon2`, `reqwest`, `tokio-tungstenite`, `url`, `parking_lot`, `state-merkle` (feature gating if needed).
- `wallet::rpc` defines:
      pub struct WalletRpcClient { ... }
      impl WalletRpcClient {
          pub fn new(base_url: Url, auth_token: String) -> Self;
          pub fn latest_block(&self) -> Result<LatestBlock>;
          pub fn submit_transaction(&self, bundle: &TransactionBundle) -> Result<TxSubmitResponse>;
          pub fn commitments(&self, start: u64, limit: u64) -> Result<Vec<CommitmentEntry>>; // etc.
      }
- `wallet::store` defines:
      pub struct WalletStore { path: PathBuf, inner: Arc<Mutex<WalletState>> }
      pub fn init(path, passphrase) -> Result<()>;
      pub fn load(...) -> Result<Self>;
      pub fn with_mut<F: FnOnce(&mut WalletState)>(&self, f: F) -> Result<()>;
  and `WalletState` includes `state_merkle::CommitmentTree` snapshot + tracked notes/pending txs.
- `wallet::transaction_builder` exposes `build_transaction(outputs, fee, store_state) -> Result<(TransactionBundle, PendingTx)>`.
