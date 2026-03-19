# API Reference Overview

This reference summarizes the public APIs of the monorepo components and points to the authoritative source files. It complements `DESIGN.md §1-3` (architecture) and `METHODS.md §APIs`. Update all three when signatures or invariants change.

## `crypto/` (Rust crate `synthetic-crypto`)

- `ml_dsa` module
  - `Keypair::generate(seed: &[u8; 48]) -> Keypair`
  - `Keypair::sign(&self, msg: &[u8]) -> Signature`
  - `VerifyKey::verify(&self, msg: &[u8], sig: &Signature) -> Result<()>`
  - Security margin: ML-DSA-65 (Dilithium 3) sized keys (pk 1952 B, sk 4000 B, sig 3293 B).
- `ml_kem` module
  - `Keypair::encapsulate(&self, rng_seed: &[u8; 32]) -> (Ciphertext, SharedSecret)`
  - `SecretKey::decapsulate(&self, ct: &Ciphertext) -> SharedSecret`
  - Security margin: ML-KEM-1024; shared secrets truncated to 32 bytes.
- `hashes` module
  - `commit_note(message: &[u8], randomness: &[u8]) -> [u8; 48]` (BLAKE3-384 by default) and `commit_note_with(.., CommitmentHash::Sha3)` for SHA3-384 commitments.
  - `sha3_256`, `blake3_256`, `blake3_384`, and Poseidon-style field hashing helpers. `commit_note_with` uses SHA3-384 when requested. BLAKE3-384 is the default digest for commitments/nullifiers, while BLAKE3-256 remains the default for PQ address tagging and other 32-byte identifiers.
  - `derive_nullifier(nk: &[u8; 32], position: u64, rho: &[u8; 32]) -> [u8; 48]` and `derive_prf_key` use the same domain tags.
  - Domain separation constants `b"c"`, `b"nk"`, `b"nf"` are enforced to avoid cross-protocol collisions.

## `circuits/`

- `transaction-circuit` crate exposes `proof::prove(witness, proving_key) -> TransactionProof` and `proof::verify(proof, verifying_key) -> VerificationReport`. The direct STARK path is `TransactionProverP3::prove_transaction(witness)` and `p3_verifier::verify_transaction_proof_bytes_p3(proof_bytes, pub_inputs)`. Production verification rejects missing STARK proof bytes/public inputs, and commitment/nullifier encodings are 48-byte values with six canonical limbs (validated via `hashing_pq::is_canonical_bytes48`).
- `disclosure-circuit` crate exposes `prove_payment_disclosure(claim, witness) -> PaymentDisclosureProofBundle` and `verify_payment_disclosure(bundle)`. The claim binds `value`, `asset_id`, `pk_recipient`, and `commitment`; the witness supplies `rho` and `r`. `PaymentDisclosureProofBundle` carries `proof_bytes` plus the `air_hash` used for verifier binding.
- `block-circuit` crate aggregates multiple transaction proofs via `BlockCircuit::prove(block_inputs)`.
- `circuits/bench` binary crate (`circuits-bench`) provides `cargo run -p circuits-bench -- --iterations N --prove` to compile circuits, generate witnesses, and optionally verify proofs. Output includes constraint rows, hash rounds, and per-proof latency.

## `consensus/`

- Rust crate `consensus` exposes `BlockBuilder`, ledger-state transition helpers, and PQ signature utilities that miners call w
hen assembling payloads.
- Go benchmarking module `consensus/bench` offers `cmd/netbench`:
  - Flags: `--miners`, `--payload-bytes`, `--pq-signature-bytes`, `--smoke`.
  - Output: JSON summary with `messages_per_second`, `avg_latency_ms`, `pq_signature_bytes` so operators can project miner gossi
p budgets.

## `wallet/`

- Rust crate `wallet` exposes CLI subcommands via `clap` definitions in `wallet/src/bin/wallet.rs`, covering offline helpers, Substrate RPC flows, and compliance tooling.
- `wallet payment-proof create|verify|purge` generates and verifies disclosure packages (payment proofs) and manages stored outgoing disclosure records.
- `wallet substrate-sync`, `wallet substrate-daemon`, and `wallet substrate-send` are the Substrate RPC paths for live wallets.
- Wallet sync falls back to archive providers for ciphertext recovery when hot DA is pruned. Configure `HEGEMON_WALLET_ARCHIVE_WS_URL` or ensure providers are discoverable via `archive_listProviders`.
- `wallet::disclosure::{DisclosurePackage, DisclosureClaim, DisclosureConfirmation, DisclosureProof}` defines the JSON schema and encoding helpers used to serialize/deserialize payment-proof packages.
- `wallet::TransactionBundle` and shielded-transfer payloads use `binding_hash` (a 64-byte hash commitment), not a signature.
- `wallet/bench` binary crate (`wallet-bench`) accepts `--iterations` and reports note construction/sec, nullifier derivations/sec, and encryption throughput.

## `walletd/`

- `walletd` is a sidecar daemon that speaks newline-delimited JSON over stdin/stdout for GUI clients.
- Requests: `{ id, method, params }`. Responses: `{ id, ok, result?, error?, error_code? }`. `error_code` is snake_case.
- `status.get` returns `protocolVersion`, `capabilities`, `walletMode`, `storePath`, balances, pending entries, note summary, and `genesisHash`.
- `sync.once`, `tx.send`, `disclosure.create`, and `disclosure.verify` mirror the wallet CLI flows without log parsing.
- The daemon holds an exclusive `<store>.lock` file to prevent concurrent access to the same wallet store.

## Runtime kernel and shielded family

- `pallet-kernel`
  - `submit_action(envelope)` is the only live public dispatch surface for proof-native protocol actions.
  - `FamilyRoots` stores the active family roots.
  - `KernelGlobalRoot` commits to the family-root map and is part of the live validity shape.

- `pallet-shielded-pool`
  - remains the first kernel family backend for shielded commitments, nullifiers, fee accounting, and proof verification
  - no longer exposes its six live state-changing calls as a public runtime dispatch surface
  - still implements the underlying action semantics for:
    - per-transfer shielded proofs
    - batch transfer proofs
    - aggregation-mode markers
    - proven block-batch payloads
    - shielded coinbase minting

## Node RPC endpoints

Hegemon-specific RPC methods exposed on the Substrate JSON-RPC server:

- `hegemon_miningStatus() -> MiningStatus`
- `hegemon_startMining(params?: { threads: number }) -> MiningControlResponse`
- `hegemon_stopMining() -> MiningControlResponse`
- `hegemon_compactJob(params?: { auth_token?: String }) -> CompactJobResponse`
- `hegemon_submitCompactSolution(request: { worker_name: String, job_id: String, nonce: String, auth_token?: String }) -> SubmitPoolShareResponse`
- `hegemon_poolWork(params?: { auth_token?: String }) -> PoolWorkResponse`
- `hegemon_submitPoolShare(request: { worker_name: String, nonce: String, pre_hash: String, parent_hash: String, height: u64, auth_token?: String }) -> SubmitPoolShareResponse`
- `hegemon_poolStatus(params?: { auth_token?: String }) -> PoolStatusResponse`
- `hegemon_consensusStatus() -> ConsensusStatus`
- `hegemon_telemetry() -> TelemetrySnapshot`
- `hegemon_storageFootprint() -> StorageFootprint`
- `hegemon_nodeConfig() -> NodeConfigSnapshot` (base path, chain spec identity, listen addresses, PQ verbosity, peer limits)
- `hegemon_peerList() -> Vec<PeerDetail>` (connected PQ peers with address, direction, best height/hash, last-seen seconds)
- `hegemon_peerGraph() -> PeerGraphSnapshot` (direct peers plus reported peers from discovery)

Compact mining RPC notes:
- `hegemon_compactJob` is the preferred compact-job miner surface. It exposes a stable `job_id`, `pre_hash`, `parent_hash`, and share/network targets without assuming an implicit `u64` nonce.
- `hegemon_submitCompactSolution` accepts a 32-byte nonce (`0x`-prefixed hex) plus the advertised `job_id`.

Legacy / experimental pool-worker RPC notes:
- `hegemon_poolWork` exposes the current authoring template to pooled hash workers.
- `hegemon_submitPoolShare` remains as a compatibility path and now also accepts a 32-byte nonce (`0x`-prefixed hex); full-target solutions are forwarded into the mining coordinator.
- `hegemon_poolStatus` reports aggregate and per-worker share accounting for the current process.
- These pool-worker RPCs are not part of the current default desktop or `InlineTx` operator flow. They remain in-tree for compatibility and experiments.

`CompactJobResponse` fields:
- `available: bool`
- `job_id: Option<String>` (hex)
- `height: Option<u64>`
- `pre_hash: Option<String>` (hex)
- `parent_hash: Option<String>` (hex)
- `network_bits: Option<u32>` (compact PoW bits)
- `share_bits: Option<u32>` (compact bits; defaults to network difficulty unless `HEGEMON_POOL_SHARE_BITS` is set)
- `reason: Option<String>`

`PoolWorkResponse` fields:
- `available: bool`
- `height: Option<u64>`
- `pre_hash: Option<String>` (hex)
- `parent_hash: Option<String>` (hex)
- `network_difficulty: Option<u32>` (compact PoW bits)
- `share_difficulty: Option<u32>` (compact bits; defaults to network difficulty unless `HEGEMON_POOL_SHARE_BITS` is set)
- `reason: Option<String>`

`SubmitPoolShareResponse` fields:
- `accepted: bool`
- `block_candidate: bool`
- `network_target_met: bool`
- `error: Option<String>`
- `accepted_shares: u64`
- `rejected_shares: u64`
- `worker_accepted_shares: u64`
- `worker_rejected_shares: u64`

`PoolStatusResponse` fields:
- `available: bool`
- `network_difficulty: Option<u32>`
- `share_difficulty: Option<u32>`
- `accepted_shares: u64`
- `rejected_shares: u64`
- `worker_count: usize`
- `workers: Vec<PoolWorkerStatusEntry>`

`PoolWorkerStatusEntry` fields:
- `worker_name: String`
- `accepted_shares: u64`
- `rejected_shares: u64`
- `block_candidates: u64`
- `payout_fraction_ppm: u64` (accepted-share fraction scaled by 1,000,000)
- `last_share_at_ms: Option<u64>`

`PeerDetail` fields:
- `peer_id: String` (hex)
- `address: String` (`ip:port`)
- `direction: String` (`inbound` | `outbound`)
- `best_height: u64`
- `best_hash: String` (hex)
- `last_seen_secs: u64`

`PeerGraphSnapshot` fields:
- `local_peer_id: String` (hex)
- `peers: Vec<PeerDetail>` (direct peers)
- `reports: Vec<PeerGraphReportSnapshot>`

`PeerGraphReportSnapshot` fields:
- `reporter_peer_id: String` (hex)
- `reporter_address: String` (`ip:port`)
- `reported_at_secs: u64`
- `peers: Vec<PeerGraphPeer>`

`PeerGraphPeer` fields:
- `peer_id: String` (hex)
- `address: String` (`ip:port`)

Archive market RPC methods exposed on the Substrate JSON-RPC server:

- `archive_listProviders() -> Vec<ArchiveProviderEntry>`
- `archive_getProvider(account_id_hex: String) -> Option<ArchiveProviderEntry>`
- `archive_providerCount() -> u32`
- `archive_listContracts(account_id_hex: String) -> Vec<ArchiveContractEntry>`
- `archive_getContract(contract_id: u64) -> Option<ArchiveContractEntry>`

Block validity and data-availability RPC methods exposed by the Substrate node:

- `block_getCommitmentProof(block_hash: H256) -> Option<CommitmentProofResult>`
  - Returns the commitment proof bytes and public inputs for a block, or `null` if the block has no commitment proof (e.g., coinbase-only blocks).
  - `CommitmentProofResult`: `{ proof_bytes: Bytes, public_inputs: CommitmentProofPublicInputs }`
- `da_getChunk(da_root: H256, chunk_index: u32) -> Option<DaChunkResult>`
  - Returns an erasure-coded chunk and its Merkle proof for the given DA root.
  - `DaChunkResult`: `{ chunk: Bytes, merkle_proof: Vec<H256> }`
- `da_getParams() -> DaParams`
  - Returns global DA parameters (chunk size, sample count, encoding scheme).

Experimental prover-market RPC methods exposed on the Substrate node:

- `prover_getWorkPackage() -> Option<WorkPackageResponse>`
- `prover_getStageWorkPackage() -> Option<WorkPackageResponse>`
- `prover_submitWorkResult(request) -> SubmitWorkResultResponse`
- `prover_submitStageWorkResult(request) -> SubmitWorkResultResponse`
- `prover_getWorkStatus(package_id) -> Option<WorkStatusResponse>`
- `prover_getMarketParams() -> MarketParamsResponse`
- `prover_getStagePlanStatus() -> StagePlanStatusResponse`
- `prover_listArtifactAnnouncements() -> Vec<ArtifactAnnouncementResponse>`
- `prover_getCandidateArtifact(tx_statements_commitment: String, tx_count: u32) -> Option<CandidateArtifactResponse>`

These prover RPCs are experimental surfaces for recursive / market research. The live
`InlineTx` path does not publish external proving work by default.

`WorkPackageResponse` can now carry `root_finalize_payload` for standalone private
prover workers. In the current branch this payload is intended for the
experimental `MergeRoot` root-finalize path and includes:

- resolved transaction proof material (bincode + base64)
- statement hashes
- `tx_statements_commitment`
- DA metadata
- commitment-proof public inputs (starting/ending roots and nullifier data)

Standalone private prover worker binary:

- `hegemon-prover-worker`
  - Polls `prover_getStageWorkPackage`
  - Builds commitment proof + merge-root payload for `root_finalize`
  - Submits the completed bundle with `prover_submitStageWorkResult`
  - Remains experimental and is not required for the normal `InlineTx` deployment path

Legacy RPC endpoints (`block_getRecursiveProof`, `epoch_*`) are removed; recursive epoch proofs are temporarily disabled until a Plonky3 recursion path is reintroduced.

Artifact market RPC notes:

- `prover_listArtifactAnnouncements` returns lightweight reusable-artifact metadata for prepared candidate artifacts.
- `prover_getCandidateArtifact` returns the SCALE-encoded `CandidateArtifact` payload for a matching `(tx_statements_commitment, tx_count)` pair when one is available.

## Documentation hooks

Every module README now contains a **Doc Sync** section referencing this file plus `DESIGN.md` and `METHODS.md`. When adding a new API surface, ensure:

1. Function signature and expected behavior are documented here.
2. DESIGN.md explains how it fits the architecture.
3. METHODS.md instructs operators/testers how to exercise it.

Failure to update all three will cause CI docs checks (see `.github/workflows/ci.yml`) to fail.
