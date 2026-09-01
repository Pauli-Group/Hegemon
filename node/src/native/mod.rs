//! Native Hegemon node service.
//!
//! Native Hegemon node service.
//! It keeps the existing JSON-RPC compatibility surface while the ledger,
//! mempool, sync, and shielded state machines are native.

use anyhow::{anyhow, Context, Result};
use axum::extract::{DefaultBodyLimit, State};
use axum::http::{header, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use bincode::Options;
use clap::Parser;
use codec::{Decode, Encode};
use consensus::{
    CommitmentTreeState, DaParams, ProofEnvelope, Transaction, TxValidityArtifact,
    COMMITMENT_TREE_DEPTH,
};
#[cfg(test)]
use consensus_light_client::header_mmr_root_from_hashes;
use consensus_light_client::{
    bridge_checkpoint_output_from_anchor_v2, bridge_checkpoint_output_with_tip_from_anchor_v2,
    canonical_bridge_checkpoint_output_bytes_v2, canonical_trusted_checkpoint_bytes_v2,
    compare_work, cumulative_work_after, decode_risc0_bridge_journal, empty_header_mmr_root,
    flyclient_sample_indices, hash_meets_target, header_mmr_append_peaks,
    header_mmr_opening_from_hashes, header_mmr_peaks_from_hashes, header_mmr_root_from_peaks,
    pow_hash_from_pre_hash, verify_pow_header_v2_with_expected_bits, BridgeCheckpointOutputV1,
    BridgeCheckpointOutputV2, BridgeMessageV1, Hash32, HeaderMmrLeafWitnessV2,
    HegemonLightClientProofV2, HegemonLongRangeProofV2, PowHeaderV2, PowHeaderV3,
    RiscZeroBridgeReceiptV1, TrustedCheckpointV2, TrustedCheckpointV3,
    HEGEMON_BRIDGE_LONG_RANGE_MIN_SAMPLE_COUNT_V1, HEGEMON_BRIDGE_LONG_RANGE_MIN_TIP_WORK_V1,
    HEGEMON_CHAIN_ID_V1, HEGEMON_LIGHT_CLIENT_RULES_HASH_ACTIVE,
    HEGEMON_LIGHT_CLIENT_RULES_HASH_V1, HEGEMON_LONG_RANGE_PROOF_MAX_MESSAGE_PAYLOAD_BYTES_V1,
    HEGEMON_NATIVE_LIGHT_CLIENT_VERIFIER_HASH_V2, HEGEMON_RISC0_BRIDGE_IMAGE_ID_V1,
};
use crypto::hash384::{
    ActionBodyHash48, ActionId48, ActionRoot48, ActionSemanticId48, BlockId48, BodyHash48,
    BridgeMessageRoot48, DaRoot48, FeeCommitment48, HeaderMmrHash48, KernelRoot48,
    NullifierAccumulatorRoot48, ProofCommitment48, RulesHash48, StateRoot48,
    TransactionStatementsCommitment48, VersionCommitment48, Work64, WorkHash48,
};
use network::{
    p2p::WireMessage,
    service::{ConnectedPeerSnapshot, DirectedProtocolMessage, ProtocolSender},
    wire, GossipRouter, NatTraversalConfig, P2PService, PeerId, PeerIdentity, PeerStore,
    PeerStoreConfig, ProtocolHandle, ProtocolId, ProtocolMessage, RelayConfig,
};
use parking_lot::{Condvar, Mutex, RwLock};
use protocol_kernel::manifest::{
    kernel_manifest, protocol_manifest, StablecoinPolicyManifestEntry,
};
use protocol_kernel::types::KernelVersionBinding;
use protocol_kernel::{
    bridge_message_root, bridge_payload_hash, empty_bridge_message_root, inbound_replay_key,
    BridgeMintPayloadV1, BridgeVerifierRegistrationV1, InboundBridgeArgsV1, InboundReplayReject,
    InboundReplayState, OutboundBridgeArgsV1, ACTION_BRIDGE_INBOUND, ACTION_BRIDGE_OUTBOUND,
    ACTION_REGISTER_BRIDGE_VERIFIER, BRIDGE_MINT_APP_FAMILY_ID_V1, BRIDGE_MINT_PAYLOAD_VERSION_V1,
    FAMILY_BRIDGE,
};
use protocol_shielded_pool::family::{
    MintCoinbaseArgs, ShieldedTransferInlineArgs, ShieldedTransferSidecarArgs,
    SubmitCandidateArtifactArgs, ACTION_MINT_COINBASE, ACTION_MINT_POSEIDON2_V8_COINBASE,
    ACTION_SHIELDED_TRANSFER_INLINE, ACTION_SHIELDED_TRANSFER_SIDECAR,
    ACTION_SMALLWOOD_POSEIDON2_PRODUCTION_INLINE, ACTION_SUBMIT_CANDIDATE_ARTIFACT,
    FAMILY_SHIELDED_POOL,
};
use protocol_shielded_pool::poseidon2_production_transport::preflight_poseidon2_production_smz9_inline_args_exact;
use protocol_shielded_pool::poseidon2_v8_coinbase::{
    MintPoseidon2V8CoinbaseArgs, POSEIDON2_V8_COINBASE_ARGS_SCALE_BYTES,
    POSEIDON2_V8_COINBASE_RAW_CIPHERTEXT_BYTES,
};
use protocol_shielded_pool::smallwood_v5_transport::{
    decode_smallwood_v5_inline_args_exact, SMALLWOOD_V5_TRANSPORT_ACTION_ID,
};
use protocol_shielded_pool::types::{
    BlockProofMode, BlockRewardBundle, CandidateArtifact, CoinbaseNoteData, EncryptedNote,
    ProofArtifactKind as PoolProofArtifactKind, StablecoinPolicyBinding, BLOCK_PROOF_BUNDLE_SCHEMA,
    DIVERSIFIED_ADDRESS_SIZE, ENCRYPTED_NOTE_SIZE, MAX_BATCH_SIZE, MAX_CIPHERTEXT_BYTES,
    NATIVE_TX_LEAF_ARTIFACT_MAX_SIZE, RECURSIVE_BLOCK_V2_ARTIFACT_MAX_SIZE,
};
use protocol_shielded_pool::verifier::{ShieldedTransferInputs, StarkVerifier};
use protocol_shielded_pool::{NullifierReject, NullifierState, PersistentKeySet48};
use rand::{rngs::OsRng, RngCore};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::{json, Value};
use sled::transaction::Transactional;
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fs::{self, OpenOptions};
use std::io::{Cursor, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, RwLock as StdRwLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::net::TcpListener;
use tokio::sync::Semaphore;
use tokio::task::JoinHandle;
use tokio::time::{interval, MissedTickBehavior};
use tower::limit::ConcurrencyLimitLayer;
use tracing::{debug, info, warn};
use transaction_circuit::hashing_pq::felts_to_bytes48;
use transaction_circuit::smallwood_v5_envelope::decode_envelope_exact;
use transaction_core::hashing_pq::ciphertext_hash_bytes;
use wallet::{NoteCiphertext, NotePlaintext, ShieldedAddress};

pub(crate) const META_BEST_KEY: &[u8] = b"best";
pub(crate) const META_GENESIS_KEY: &[u8] = b"genesis";
pub(crate) const META_NULLIFIER_ACCUMULATOR_KEY: &[u8] = b"nullifier_accumulator_v2";
pub(crate) const META_CANONICAL_STATE_CHECKPOINT_PREFIX: &[u8] = b"canonical_state_checkpoint_v1/";
pub(crate) const META_VERIFIED_BLOCK_RECORD_PREFIX: &[u8] = b"verified_block_record_v1/";
pub(crate) const NATIVE_CANONICAL_STATE_CHECKPOINT_SCHEMA_V1: u16 = 1;
pub(crate) const NATIVE_DEV_POW_BITS: u32 = consensus::reward::GENESIS_BITS;
pub(crate) const NATIVE_GENESIS_TIMESTAMP_MS: u64 = 1_782_840_600_000;
pub(crate) const HASHES_PER_ROUND: u64 = 16_384;
pub(crate) const MINING_ROUNDS_PER_WORK: u64 = 16;
pub(crate) const NATIVE_DA_CHUNK_SIZE_TIERS: [u32; 3] = [1_024, 4_096, 16_384];
pub(crate) const MIN_NATIVE_DA_CHUNK_SIZE: u32 = NATIVE_DA_CHUNK_SIZE_TIERS[0];
pub(crate) const MAX_NATIVE_DA_CHUNK_SIZE: u32 = NATIVE_DA_CHUNK_SIZE_TIERS[2];
pub(crate) const DEFAULT_DA_SAMPLE_COUNT: u32 = 4;
pub(crate) const MAX_NATIVE_DA_ENCODING_CACHE_BLOCKS: usize = 8;
/// Process-local proof-validity cache. Persisted rows are deliberately not
/// authoritative: a restart must re-run SmallWood verification before any
/// body can enter this cache.
pub(crate) const MAX_NATIVE_IN_PROCESS_VERIFIED_BLOCKS: usize = 1_024;
/// Process-local canonical state snapshots used only after the corresponding
/// body has been verified in this process. The cap covers the maximum native
/// sync/reorg response with headroom and prevents checkpoint memory growth.
pub(crate) const MAX_NATIVE_IN_PROCESS_CANONICAL_CHECKPOINTS: usize = 512;
pub(crate) const NATIVE_WORK_TEMPLATE_REFRESH_INTERVAL: Duration = Duration::from_secs(1);
pub(crate) const DEFAULT_BRIDGE_FLYCLIENT_SAMPLE_COUNT: u32 =
    HEGEMON_BRIDGE_LONG_RANGE_MIN_SAMPLE_COUNT_V1;
pub(crate) const MIN_INBOUND_BRIDGE_CONFIRMATIONS: u32 = 2;
pub(crate) const NATIVE_RISC0_RECEIPT_VERIFIER_ENABLED: bool = false;
pub(crate) const NATIVE_PQ_CLEAN_BRIDGE_VERIFIER_BOUND: bool = false;
pub(crate) const NATIVE_EXTERNAL_BRIDGE_VERIFIER_SOUNDNESS_ACCEPTED: bool = false;
pub(crate) const NATIVE_POSITIVE_INBOUND_BRIDGE_MINT_ENABLED: bool = false;
pub(crate) const MAX_BRIDGE_WITNESS_BACKSCAN_BLOCKS: u64 = 4_096;
pub(crate) const MAX_NATIVE_BRIDGE_PROOF_RECEIPT_BYTES: usize = 512 * 1024;
pub(crate) const MAX_NATIVE_BRIDGE_MESSAGE_PAYLOAD_BYTES: usize =
    HEGEMON_LONG_RANGE_PROOF_MAX_MESSAGE_PAYLOAD_BYTES_V1;
pub(crate) const MAX_NATIVE_BRIDGE_ACTION_DYNAMIC_BYTES: usize =
    MAX_NATIVE_BRIDGE_PROOF_RECEIPT_BYTES + MAX_NATIVE_BRIDGE_MESSAGE_PAYLOAD_BYTES;
pub(crate) const MAX_NATIVE_BRIDGE_MINT_AMOUNT: u64 = i64::MAX as u64;
pub(crate) const MAX_NATIVE_MEMPOOL_ACTIONS: usize = 10_000;
/// Fresh-genesis V2 sync protocol. V1 peers must not exchange blocks whose DA
/// metadata/body transport rules they cannot validate.
pub(crate) const NATIVE_SYNC_PROTOCOL_ID: ProtocolId = 0x4847_4e54;
pub(crate) const MAX_NATIVE_SYNC_RESPONSE_BLOCKS: u64 = 256;
pub(crate) const MAX_NATIVE_SYNC_RESPONSE_BLOCKS_USIZE: usize =
    MAX_NATIVE_SYNC_RESPONSE_BLOCKS as usize;
pub(crate) const MAX_NATIVE_SYNC_RESPONSE_WORKERS: usize = 2;
/// Retired chunk record tags retained only for explicit negative decoding
/// tests. Production chunk admission accepts only the V3 tag exported by
/// `sync_chunks` and never upgrades either historical grammar.
pub(crate) const NATIVE_SYNC_CHUNK_RECORD_ENCODING_LEGACY_V1: u8 = 1;
pub(crate) const NATIVE_SYNC_CHUNK_RECORD_ENCODING_CURRENT_V2: u8 = 2;
pub(crate) const MAX_NATIVE_SYNC_CHUNK_BYTES: usize = 4 * 1024 * 1024;
pub(crate) const MAX_NATIVE_SYNC_CHUNK_SESSIONS: usize = 2;
pub(crate) const NATIVE_SYNC_CHUNK_SESSION_TTL: Duration = Duration::from_secs(30);
pub(crate) const NATIVE_SYNC_CHUNK_SESSION_MAX_LIFETIME: Duration = Duration::from_secs(2 * 60);
pub(crate) const NATIVE_SYNC_REQUEST_BLOCKS: u64 = 64;
pub(crate) const MAX_NATIVE_SYNC_IMPORT_BATCH_BLOCKS: usize = 32;
pub(crate) const NATIVE_SYNC_BEST_ANNOUNCE_INTERVAL: Duration = Duration::from_secs(2);
pub(crate) const NATIVE_SYNC_PENDING_ACTION_REBROADCAST_INTERVAL: Duration = Duration::from_secs(5);
pub(crate) const NATIVE_SYNC_PENDING_ACTION_REBROADCAST_LIMIT: usize = 8;
pub(crate) const NATIVE_SYNC_PENDING_ACTION_REBROADCAST_BYTES: usize = 8 * 1024 * 1024;
pub(crate) const NATIVE_SYNC_REQUEST_RATE_WINDOW: Duration = Duration::from_secs(10);
// Sync responses carry full native block metadata. Keep one live request in
// flight, but retry quickly enough that a dropped response does not freeze
// fresh-node catch-up for minutes.
pub(crate) const NATIVE_SYNC_REQUEST_RETRY_AFTER: Duration = Duration::from_secs(20);
pub(crate) const NATIVE_SYNC_UNVERIFIED_TARGET_COOLDOWN: Duration = Duration::from_secs(20);
pub(crate) const MAX_NATIVE_SYNC_UNVERIFIED_TARGET_COOLDOWNS: usize = 1024;
pub(crate) const MAX_NATIVE_SYNC_REQUESTS_PER_WINDOW: u32 = 4;
pub(crate) const NATIVE_SYNC_REQUEST_RATE_LIMIT_STATE_TTL: Duration = Duration::from_secs(10 * 60);
pub(crate) const MAX_NATIVE_SYNC_REQUEST_RATE_LIMIT_PEERS: usize = 4096;
pub(crate) const NATIVE_SYNC_REORG_BACKFILL_BLOCKS: u64 = 32;
pub(crate) const NATIVE_SYNC_BOOTSTRAP_BACKFILL_FLOOR: u64 = 1;
pub(crate) const NATIVE_SYNC_MAX_REORG_BACKFILL_BLOCKS: u64 = MAX_NATIVE_SYNC_RESPONSE_BLOCKS - 1;
pub(crate) const APPROVED_PUBLIC_JOIN_SEED_OVH: &str = "hegemon.pauli.group:30333";
pub(crate) const APPROVED_PUBLIC_JOIN_SEED_DEV: &str = "devnet.hegemonprotocol.com:30333";
pub(crate) const APPROVED_PUBLIC_JOIN_SEEDS: &str =
    "hegemon.pauli.group:30333,devnet.hegemonprotocol.com:30333";
pub(crate) const AES_GCM_TAG_BYTES: usize = 16;
pub(crate) const PQ_IDENTITY_SEED_FILE: &str = "pq-identity.seed";
pub(crate) const PQ_IDENTITY_SEED_LEN: usize = 32;
pub(crate) const MAX_NATIVE_RPC_ACTION_BYTES: usize = 2 * 1024 * 1024;
pub(crate) const MAX_NATIVE_CHAIN_GET_BLOCK_ACTION_BYTES: usize = 2 * 1024 * 1024;
pub(crate) const MAX_NATIVE_DA_CIPHERTEXT_UPLOADS: usize = 1024;
pub(crate) const MAX_NATIVE_DA_PROOF_UPLOADS: usize = 256;
pub(crate) const MAX_NATIVE_STAGED_CIPHERTEXTS: usize = 100_000;
pub(crate) const MAX_NATIVE_STAGED_PROOFS: usize = 10_000;
pub(crate) const MAX_NATIVE_STAGED_PROOF_BYTES: usize = 32 * 1024 * 1024;
pub(crate) const DEFAULT_NATIVE_WALLET_PAGE_LIMIT: u64 = 128;
pub(crate) const MAX_NATIVE_WALLET_PAGE_LIMIT: u64 = 1024;
pub(crate) const MIN_NATIVE_ARCHIVE_KEM_CIPHERTEXT_BYTES: usize = 32;
pub(crate) const MIN_NATIVE_WALLET_CIPHERTEXT_BYTES: usize =
    ENCRYPTED_NOTE_SIZE + MIN_NATIVE_ARCHIVE_KEM_CIPHERTEXT_BYTES;
pub(crate) const MAX_NATIVE_TIMESTAMP_ROWS: u64 = 4096;
pub(crate) const MAX_NATIVE_RPC_BATCH_REQUESTS: usize = 128;
pub(crate) const MAX_NATIVE_RPC_BODY_BYTES: usize = 8 * 1024 * 1024;
pub(crate) const MAX_NATIVE_RPC_CONCURRENT_REQUESTS: usize = 8;
pub(crate) const MAX_NATIVE_MEMPOOL_ACTION_BYTES: usize = 64 * 1024 * 1024;
pub(crate) const MAX_NATIVE_BLOCK_ACTIONS: usize = MAX_NATIVE_MEMPOOL_ACTIONS;
pub(crate) const MAX_NATIVE_BLOCK_ACTION_PAYLOAD_BYTES: usize =
    MAX_NATIVE_RPC_ACTION_BYTES + 16 * 1024;
pub(crate) const MAX_NATIVE_BLOCK_ACTION_BYTES: usize = MAX_NATIVE_MEMPOOL_ACTION_BYTES;
/// Maximum SCALE bytes outside `PendingAction::public_args` for the canonical
/// two-output V8 shape. This includes the public-argument compact-length
/// prefix. The exact codec regression below source-binds the value instead of
/// treating a hand calculation as release evidence.
pub const POSEIDON2_V8_MAX_PENDING_ACTION_OUTER_BYTES: usize = 225;
/// Route-specific full-record cap. The nested HGV8/SWP8/SMZ9 parser retains
/// its independent 131,072-byte inline-argument cap; native relay and block
/// admission additionally bound the complete SCALE `PendingAction` record.
pub const POSEIDON2_V8_MAX_PENDING_ACTION_BYTES: usize =
    protocol_shielded_pool::poseidon2_production_transport::POSEIDON2_PRODUCTION_MAX_ACTION_BYTES
        + POSEIDON2_V8_MAX_PENDING_ACTION_OUTER_BYTES;
/// Local typed form of the protocol-versioning QROM action ceiling. Both V8
/// transactions and the paired V8 coinbase consume this budget. The
/// independent 64 MiB encoded-action budget is not evidence for this cap.
pub(crate) const MAX_POSEIDON2_V8_ACTIONS_PER_BLOCK: usize =
    protocol_versioning::SMALLWOOD_POSEIDON2_PRODUCTION_MAX_PROOF_ACTIONS_PER_BLOCK as usize;
pub(crate) const UNOBSERVED_POSEIDON2_V8_PLAN_APPLICATION_COUNT: usize =
    MAX_POSEIDON2_V8_ACTIONS_PER_BLOCK + 1;
/// Native V2 permits a miner to forfeit the subsidy by omitting coinbase.
/// When coinbase is present it is still unique, exact, and final.
pub(crate) const NATIVE_V2_COINBASE_REQUIRED: bool = false;
pub(crate) const MAX_NATIVE_BLOCK_META_BYTES: usize =
    MAX_NATIVE_BLOCK_ACTION_BYTES + (MAX_NATIVE_BLOCK_ACTIONS * 32) + 1024 * 1024;
pub(crate) const MAX_NATIVE_SYNC_MESSAGE_BYTES: usize = wire::MAX_WIRE_FRAME_LEN;
pub(crate) const MAX_NATIVE_SYNC_RESPONSE_TARGET_BYTES: usize = wire::MAX_WIRE_FRAME_LEN / 2;
/// A range worker retains at most one worst-case native body budget. Small
/// blocks still fill the normal 64-block request; large bodies return a
/// canonical prefix and continue through the next range request.
pub(crate) const MAX_NATIVE_SYNC_RESPONSE_MATERIALIZED_BYTES: usize = MAX_NATIVE_BLOCK_META_BYTES;
pub(crate) const MAX_NATIVE_SYNC_PENDING_ACTION_BYTES: usize =
    MAX_NATIVE_BLOCK_ACTION_PAYLOAD_BYTES;
/// Chunk payloads stay far below the encrypted 16 MiB transport frame. This
/// leaves ample room for the protocol envelope, locator, and AEAD tag while
/// bounding per-message allocation independently of the native block limit.
pub(crate) const MAX_NATIVE_BLOCK_BODY_CHUNK_BYTES: usize = 1024 * 1024;
pub(crate) const MAX_NATIVE_BLOCK_BODY_CHUNKS: usize =
    MAX_NATIVE_BLOCK_META_BYTES.div_ceil(MAX_NATIVE_BLOCK_BODY_CHUNK_BYTES);
pub(crate) const NATIVE_ACTION_BODY_CHUNK_RPC_SCHEMA: &str = "hegemon.native.action-body-chunk-v1";
pub(crate) const MAX_NATIVE_INLINE_BLOCK_ANNOUNCE_BYTES: usize = 256 * 1024;
pub(crate) const MAX_NATIVE_BLOCK_BODY_REASSEMBLIES_PER_PEER: usize = 1;
pub(crate) const MAX_NATIVE_BLOCK_BODY_REASSEMBLIES_GLOBAL: usize = 4;
pub(crate) const MAX_NATIVE_BLOCK_BODY_REASSEMBLY_RESERVED_BYTES: usize =
    MAX_NATIVE_BLOCK_META_BYTES * MAX_NATIVE_BLOCK_BODY_REASSEMBLIES_GLOBAL;
pub(crate) const NATIVE_BLOCK_BODY_REASSEMBLY_TTL: Duration = Duration::from_secs(2 * 60);
pub(crate) const NATIVE_BLOCK_BODY_REASSEMBLY_MAX_LIFETIME: Duration = Duration::from_secs(10 * 60);
/// Canonical identity-free native block-body grammar. Schema 2 was an
/// unreleased identity-bearing interim format and is rejected, never upgraded.
pub(crate) const NATIVE_BLOCK_BODY_SCHEMA_VERSION: u16 = 3;
/// Postcard enum tags are part of the native sync wire grammar. The exact V3
/// locator/body carrier occupies tags 4..=7. PR 203's stored-record chunk
/// fallback occupies tags 8..=9 and must remain fail-closed until it can
/// decode and verify the same V3 carrier without any metadata-era conversion.
/// Tag 10 is the compact tip announcement and has its own bounded admission.
pub(crate) const NATIVE_SYNC_EXACT_LOCATOR_BODY_TAGS: std::ops::RangeInclusive<u8> = 4..=7;
pub(crate) const NATIVE_SYNC_RECORD_FALLBACK_TAGS: std::ops::RangeInclusive<u8> = 8..=9;
pub(crate) const NATIVE_SYNC_ANNOUNCE_TIP_TAG: u8 = 10;
pub(crate) const MAX_NATIVE_BLOCK_BODY_QUEUE_PER_PEER: usize =
    MAX_NATIVE_SYNC_RESPONSE_BLOCKS_USIZE;
pub(crate) const MAX_NATIVE_BLOCK_BODY_QUEUE_GLOBAL: usize =
    MAX_NATIVE_BLOCK_BODY_QUEUE_PER_PEER * MAX_NATIVE_BLOCK_BODY_REASSEMBLIES_GLOBAL;
pub(crate) const MAX_NATIVE_BLOCK_BODY_SENDS_GLOBAL: usize = 2;
pub(crate) const MAX_NATIVE_BLOCK_BODY_SEND_QUEUE_GLOBAL: usize = 16;
pub(crate) const MAX_NATIVE_BLOCK_BODY_SEND_CACHE_BYTES: usize =
    MAX_NATIVE_SYNC_RESPONSE_MATERIALIZED_BYTES;
pub(crate) const MAX_NATIVE_BLOCK_BODY_SEND_CACHE_ENTRIES: usize =
    MAX_NATIVE_SYNC_RESPONSE_BLOCKS_USIZE;
pub(crate) const NATIVE_BLOCK_BODY_REQUEST_RATE_WINDOW: Duration = Duration::from_secs(10);
pub(crate) const MAX_NATIVE_BLOCK_BODY_REQUESTS_PER_WINDOW: u32 = 2;
pub(crate) const MAX_NATIVE_BLOCK_BODY_EGRESS_BYTES_PER_PEER_WINDOW: usize =
    MAX_NATIVE_BLOCK_META_BYTES;
pub(crate) const MAX_NATIVE_BLOCK_BODY_EGRESS_BYTES_GLOBAL_WINDOW: usize =
    MAX_NATIVE_BLOCK_META_BYTES * MAX_NATIVE_BLOCK_BODY_SENDS_GLOBAL;
pub(crate) const NATIVE_BLOCK_BODY_REQUEST_RATE_STATE_TTL: Duration = Duration::from_secs(10 * 60);
pub(crate) const MAX_NATIVE_BLOCK_BODY_REQUEST_RATE_PEERS: usize = 4096;
pub(crate) const MAX_NATIVE_PENDING_PROOF_ADMISSIONS_IN_FLIGHT: usize = 3;
pub(crate) const MAX_NATIVE_PEER_PENDING_PROOF_ADMISSIONS_IN_FLIGHT: usize = 1;
pub(crate) const MAX_NATIVE_LOCAL_PENDING_PROOF_ADMISSIONS_IN_FLIGHT: usize = 1;
pub(crate) const MAX_NATIVE_WORK_TEMPLATE_PROOFS_IN_FLIGHT: usize = 1;
pub(crate) const MAX_NATIVE_PEER_PENDING_PROOF_QUEUE: usize = 512;
pub(crate) const MAX_NATIVE_PEER_PENDING_PROOF_QUEUE_BYTES: usize = MAX_NATIVE_MEMPOOL_ACTION_BYTES;
pub(crate) const MAX_NATIVE_PEER_PENDING_PROOF_OUTSTANDING_PER_PEER: usize = 2;
/// Non-proof relays still enter the durable group-commit path, so they run on
/// bounded blocking workers rather than the Tokio sync receive loop. Multiple
/// peers may join one group commit, while one active item per peer preserves
/// fair scheduling.
pub(crate) const MAX_NATIVE_PEER_NON_PROOF_ADMISSIONS_IN_FLIGHT: usize = 4;
pub(crate) const MAX_NATIVE_PEER_NON_PROOF_QUEUE: usize = 512;
pub(crate) const MAX_NATIVE_PEER_NON_PROOF_QUEUE_BYTES: usize = MAX_NATIVE_MEMPOOL_ACTION_BYTES;
pub(crate) const MAX_NATIVE_PEER_NON_PROOF_OUTSTANDING_PER_PEER: usize = 2;
pub(crate) const MAX_NATIVE_PEER_PENDING_PROOF_RATE_PEERS: usize = 4_096;
pub(crate) const MAX_NATIVE_PEER_PENDING_PROOFS_PER_WINDOW: u32 = 128;
pub(crate) const NATIVE_PEER_PENDING_PROOF_RATE_WINDOW: Duration = Duration::from_secs(10);
pub(crate) const NATIVE_PEER_INVALID_PROOF_COOLDOWN: Duration = Duration::from_secs(5);
pub(crate) const NATIVE_PEER_PENDING_PROOF_STATE_TTL: Duration = Duration::from_secs(10 * 60);
/// Pending-action durability requests wait only this long for siblings before
/// one leader commits the bounded group. The window is short relative to an
/// fsync but long enough for concurrent RPC and relay workers to share it.
pub(crate) const NATIVE_PENDING_ACTION_GROUP_COMMIT_WINDOW: Duration = Duration::from_millis(2);
pub(crate) const MAX_NATIVE_PENDING_ACTION_GROUP_COMMIT_ACTIONS: usize = 64;
pub(crate) const MAX_NATIVE_PENDING_ACTION_GROUP_COMMIT_BYTES: usize = 8 * 1024 * 1024;
pub(crate) const MAX_NATIVE_PENDING_ACTION_GROUP_COMMIT_QUEUE: usize = 512;
pub(crate) const MAX_NATIVE_PENDING_ACTION_GROUP_COMMIT_QUEUE_BYTES: usize =
    MAX_NATIVE_MEMPOOL_ACTION_BYTES;
pub(crate) const MAX_NATIVE_BLOCK_IMPORTS_IN_FLIGHT: usize = 1;
pub(crate) const MAX_NATIVE_SYNC_IMPORT_QUEUE_ITEMS: usize = 4;
pub(crate) const MAX_NATIVE_SYNC_IMPORT_QUEUE_BYTES: usize = MAX_NATIVE_BLOCK_META_BYTES * 2;
pub(crate) const MAX_NATIVE_PENDING_PROOF_PREFLIGHT_RETRIES: usize = 2;
pub(crate) const MAX_NATIVE_WORK_TEMPLATE_SNAPSHOT_RETRIES: usize = 2;
pub(crate) const MAX_NATIVE_REJECTED_PENDING_ACTIONS: usize = 4_096;
pub(crate) const NATIVE_REJECTED_PENDING_ACTION_TTL: Duration = Duration::from_secs(10 * 60);
pub(crate) const MAX_NATIVE_MINING_THREADS: u32 = 64;
pub(crate) const NATIVE_MINING_BACKGROUND_THREAD_CAP: u32 = 2;
pub(crate) const NATIVE_MINING_RESERVED_SERVICE_THREADS: u32 = 3;
pub(crate) const NATIVE_EMPTY_DIGEST48: [u8; 48] = [0u8; 48];

#[cfg(test)]
pub(crate) static NATIVE_OWNED_ANNOUNCE_WRAPPER_ACTION_BYTES: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Debug, Parser)]
#[command(name = "hegemon-node")]
#[command(about = "Native Hegemon node")]
pub struct NativeCli {
    /// Print the compiled production cryptographic profile as JSON and exit.
    #[arg(long)]
    pub print_crypto_profile: bool,
    /// Run an ephemeral development chain.
    #[arg(long)]
    pub dev: bool,
    /// Store node state in a process-specific temporary directory.
    #[arg(long)]
    pub tmp: bool,
    /// Node base path.
    #[arg(long, value_name = "PATH")]
    pub base_path: Option<PathBuf>,
    /// JSON-RPC port.
    #[arg(long, default_value_t = 9944)]
    pub rpc_port: u16,
    /// Expose JSON-RPC on all interfaces.
    #[arg(long)]
    pub rpc_external: bool,
    /// RPC method policy: auto, safe, or unsafe.
    #[arg(long, default_value = "auto")]
    pub rpc_methods: String,
    /// CORS policy. Default is no browser cross-origin access; set explicitly for trusted UIs.
    #[arg(long)]
    pub rpc_cors: Option<String>,
    /// P2P listen port.
    #[arg(long, default_value_t = 30333)]
    pub port: u16,
    /// P2P listen address.
    #[arg(long)]
    pub listen_addr: Option<String>,
    /// Node display name.
    #[arg(long)]
    pub name: Option<String>,
}

#[derive(Clone, Debug)]
pub struct NativeConfig {
    pub dev: bool,
    pub tmp: bool,
    pub base_path: PathBuf,
    pub db_path: PathBuf,
    pub rpc_addr: SocketAddr,
    pub p2p_listen_addr: String,
    pub node_name: String,
    pub rpc_methods: String,
    pub rpc_external: bool,
    pub rpc_cors: Option<String>,
    pub seeds: Vec<String>,
    pub max_peers: u32,
    pub mine: bool,
    pub mine_threads: u32,
    pub bootstrap_mining_authoring: bool,
    pub miner_address: Option<String>,
    pub pow_bits: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RpcMethodPolicy {
    Safe,
    Unsafe,
}

impl RpcMethodPolicy {
    fn label(self) -> &'static str {
        match self {
            Self::Safe => "safe",
            Self::Unsafe => "unsafe",
        }
    }
}

impl NativeConfig {
    pub fn from_cli(cli: NativeCli) -> Result<Self> {
        let base_path = resolve_base_path(&cli)?;
        let db_path = base_path.join("native-chain.sled");
        let rpc_methods =
            effective_rpc_methods_label(&cli.rpc_methods, cli.rpc_external)?.to_string();
        let rpc_ip = if cli.rpc_external {
            IpAddr::from(Ipv4Addr::UNSPECIFIED)
        } else {
            IpAddr::from(Ipv4Addr::LOCALHOST)
        };
        let rpc_addr = SocketAddr::new(rpc_ip, cli.rpc_port);
        let p2p_listen_addr = cli
            .listen_addr
            .clone()
            .unwrap_or_else(|| format!("0.0.0.0:{}", cli.port));
        let seeds = env_list("HEGEMON_SEEDS");
        let max_peers = std::env::var("HEGEMON_MAX_PEERS")
            .ok()
            .and_then(|raw| raw.parse::<u32>().ok())
            .unwrap_or(64);
        let mine = env_bool("HEGEMON_MINE");
        let mine_threads = std::env::var("HEGEMON_MINE_THREADS")
            .ok()
            .map(|raw| parse_mining_thread_count_str(&raw, "HEGEMON_MINE_THREADS"))
            .transpose()?
            .unwrap_or(1);
        let bootstrap_mining_authoring = env_bool("HEGEMON_BOOTSTRAP_AUTHORING");
        if mine && !cli.dev && seeds.is_empty() && !bootstrap_mining_authoring {
            return Err(anyhow!(
                "refusing live mining with empty HEGEMON_SEEDS; set HEGEMON_SEEDS=\"{}\" or explicitly set HEGEMON_BOOTSTRAP_AUTHORING=1 for a deliberate first-author bootstrap",
                APPROVED_PUBLIC_JOIN_SEEDS
            ));
        }
        let miner_address = std::env::var("HEGEMON_MINER_ADDRESS")
            .ok()
            .map(|raw| raw.trim().to_string())
            .filter(|raw| !raw.is_empty());
        let pow_bits = if cli.dev {
            NATIVE_DEV_POW_BITS
        } else {
            consensus::pow::DEFAULT_GENESIS_POW_BITS
        };

        Ok(Self {
            dev: cli.dev,
            tmp: cli.tmp,
            base_path,
            db_path,
            rpc_addr,
            p2p_listen_addr,
            node_name: cli.name.unwrap_or_else(|| "hegemon-native".to_string()),
            rpc_methods,
            rpc_external: cli.rpc_external,
            rpc_cors: cli.rpc_cors,
            seeds,
            max_peers,
            mine,
            mine_threads,
            bootstrap_mining_authoring,
            miner_address,
            pow_bits,
        })
    }

    fn permits_empty_seed_authoring(&self) -> bool {
        self.dev || self.bootstrap_mining_authoring
    }

    fn public_testnet_profile(&self) -> bool {
        if !self.dev || self.tmp {
            return false;
        }
        self.seeds.iter().any(|seed| {
            let seed = seed.trim();
            seed.eq_ignore_ascii_case(APPROVED_PUBLIC_JOIN_SEED_OVH)
                || seed.eq_ignore_ascii_case(APPROVED_PUBLIC_JOIN_SEED_DEV)
        }) || (self.bootstrap_mining_authoring
            && self
                .base_path
                .to_string_lossy()
                .to_ascii_lowercase()
                .contains("testnet"))
    }

    fn chain_spec_id(&self) -> &'static str {
        if self.public_testnet_profile() {
            "hegemon-native-testnet"
        } else if self.dev {
            "hegemon-native-dev"
        } else {
            "hegemon-native"
        }
    }

    fn chain_type(&self) -> &'static str {
        if self.public_testnet_profile() {
            "testnet"
        } else if self.dev {
            "dev"
        } else {
            "live"
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct NativeBlockMeta {
    chain_id: [u8; 32],
    rules_hash: [u8; 32],
    height: u64,
    hash: [u8; 32],
    parent_hash: [u8; 32],
    #[serde(with = "serde_array48")]
    state_root: [u8; 48],
    #[serde(with = "serde_array48")]
    kernel_root: [u8; 48],
    #[serde(with = "serde_array48")]
    nullifier_root: [u8; 48],
    extrinsics_root: [u8; 32],
    #[serde(with = "serde_array48")]
    message_root: [u8; 48],
    message_count: u32,
    header_mmr_root: [u8; 32],
    header_mmr_len: u64,
    timestamp_ms: u64,
    pow_bits: u32,
    nonce: [u8; 32],
    work_hash: [u8; 32],
    #[serde(with = "serde_array48")]
    cumulative_work: [u8; 48],
    supply_digest: u128,
    tx_count: u32,
    #[serde(default)]
    action_bytes: Vec<Vec<u8>>,
    #[serde(default = "native_empty_digest48_default", with = "serde_array48")]
    da_root: [u8; 48],
    #[serde(default)]
    da_chunk_size: u32,
    #[serde(default)]
    da_sample_count: u32,
    #[serde(default)]
    da_blob_len: u64,
    #[serde(default)]
    da_chunk_count: u32,
}

/// Fresh-genesis native V3 wire/canonical metadata.  Unlike the internal sled
/// row below, this type is self-contained: peers receive the exact canonical
/// action bodies needed to reconstruct and validate the block independently.
/// The distinct fixed-width wrappers make block identity, work, action roots,
/// MMR roots, rules, and cumulative work impossible to interchange by type.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct NativeBlockMetaV3 {
    pub(crate) chain_id: [u8; 32],
    pub(crate) rules_hash: RulesHash48,
    pub(crate) height: u64,
    pub(crate) hash: BlockId48,
    pub(crate) parent_hash: BlockId48,
    pub(crate) state_root: StateRoot48,
    pub(crate) kernel_root: KernelRoot48,
    pub(crate) nullifier_root: NullifierAccumulatorRoot48,
    pub(crate) proof_commitment: ProofCommitment48,
    pub(crate) extrinsics_root: ActionRoot48,
    pub(crate) tx_statements_commitment: TransactionStatementsCommitment48,
    pub(crate) version_commitment: VersionCommitment48,
    pub(crate) fee_commitment: FeeCommitment48,
    pub(crate) message_root: BridgeMessageRoot48,
    pub(crate) message_count: u32,
    pub(crate) header_mmr_root: HeaderMmrHash48,
    pub(crate) header_mmr_len: u64,
    pub(crate) timestamp_ms: u64,
    pub(crate) pow_bits: u32,
    pub(crate) nonce: [u8; 32],
    pub(crate) work_hash: WorkHash48,
    pub(crate) cumulative_work: Work64,
    pub(crate) supply_digest: u128,
    pub(crate) tx_count: u32,
    pub(crate) action_bytes: Vec<Vec<u8>>,
    pub(crate) da_root: DaRoot48,
    pub(crate) da_chunk_size: u32,
    pub(crate) da_sample_count: u32,
    pub(crate) da_blob_len: u64,
    pub(crate) da_chunk_count: u32,
}

pub(crate) const NATIVE_STORED_BLOCK_META_SCHEMA_V3: u16 = 3;

/// Internal content-addressed sled row for a V3 block.  It deliberately omits
/// the potentially 64 MiB action vector and instead binds the exact canonical
/// SCALE `Vec<Vec<u8>>` blob by a dedicated ActionBodyHash48 and byte length.
/// This is never a network or consensus wire replacement for NativeBlockMetaV3.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode, Serialize, Deserialize)]
pub(crate) struct StoredNativeBlockMetaV3 {
    pub(crate) schema_version: u16,
    pub(crate) chain_id: [u8; 32],
    pub(crate) rules_hash: RulesHash48,
    pub(crate) height: u64,
    pub(crate) hash: BlockId48,
    pub(crate) parent_hash: BlockId48,
    pub(crate) state_root: StateRoot48,
    pub(crate) kernel_root: KernelRoot48,
    pub(crate) nullifier_root: NullifierAccumulatorRoot48,
    pub(crate) proof_commitment: ProofCommitment48,
    pub(crate) extrinsics_root: ActionRoot48,
    pub(crate) tx_statements_commitment: TransactionStatementsCommitment48,
    pub(crate) version_commitment: VersionCommitment48,
    pub(crate) fee_commitment: FeeCommitment48,
    pub(crate) message_root: BridgeMessageRoot48,
    pub(crate) message_count: u32,
    pub(crate) header_mmr_root: HeaderMmrHash48,
    pub(crate) header_mmr_len: u64,
    pub(crate) timestamp_ms: u64,
    pub(crate) pow_bits: u32,
    pub(crate) nonce: [u8; 32],
    pub(crate) work_hash: WorkHash48,
    pub(crate) cumulative_work: Work64,
    pub(crate) supply_digest: u128,
    pub(crate) tx_count: u32,
    pub(crate) body_hash: BodyHash48,
    pub(crate) body_len: u64,
    pub(crate) action_body_hash: ActionBodyHash48,
    pub(crate) action_body_len: u64,
    pub(crate) da_root: DaRoot48,
    pub(crate) da_chunk_size: u32,
    pub(crate) da_sample_count: u32,
    pub(crate) da_blob_len: u64,
    pub(crate) da_chunk_count: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct EncodedNativeActionBodyV3 {
    pub(crate) hash: ActionBodyHash48,
    pub(crate) len: u64,
    pub(crate) bytes: Vec<u8>,
}

/// One exact bounded slice of a canonical block's SCALE `Vec<Vec<u8>>`
/// action body. Construction is restricted to the node helper that verifies
/// every embedded action id and the header action root before releasing bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct NativeActionBodyRpcChunk {
    pub(crate) block_hash: [u8; 32],
    pub(crate) height: u64,
    pub(crate) parent_hash: [u8; 32],
    pub(crate) tx_count: u32,
    pub(crate) extrinsics_root: [u8; 32],
    pub(crate) action_body_hash: ActionBodyHash48,
    pub(crate) action_body_len: u64,
    pub(crate) chunk_index: u32,
    pub(crate) chunk_count: u32,
    pub(crate) bytes: Vec<u8>,
}

pub(crate) fn native_empty_digest48_default() -> [u8; 48] {
    NATIVE_EMPTY_DIGEST48
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct LegacyNativeBlockMetaV1 {
    chain_id: [u8; 32],
    rules_hash: [u8; 32],
    height: u64,
    hash: [u8; 32],
    parent_hash: [u8; 32],
    #[serde(with = "serde_array48")]
    state_root: [u8; 48],
    #[serde(with = "serde_array48")]
    kernel_root: [u8; 48],
    #[serde(with = "serde_array48")]
    nullifier_root: [u8; 48],
    extrinsics_root: [u8; 32],
    #[serde(with = "serde_array48")]
    message_root: [u8; 48],
    message_count: u32,
    header_mmr_root: [u8; 32],
    header_mmr_len: u64,
    timestamp_ms: u64,
    pow_bits: u32,
    nonce: [u8; 32],
    work_hash: [u8; 32],
    #[serde(with = "serde_array48")]
    cumulative_work: [u8; 48],
    supply_digest: u128,
    tx_count: u32,
    #[serde(default)]
    action_bytes: Vec<Vec<u8>>,
}

/// Exact pre-DA-metadata signed native block schema. It remains decode-only so
/// operators get a precise fresh-genesis migration failure instead of an
/// ambiguous wire error.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct LegacySignedNativeBlockMetaV1 {
    chain_id: [u8; 32],
    rules_hash: [u8; 32],
    height: u64,
    hash: [u8; 32],
    parent_hash: [u8; 32],
    #[serde(with = "serde_array48")]
    state_root: [u8; 48],
    #[serde(with = "serde_array48")]
    kernel_root: [u8; 48],
    #[serde(with = "serde_array48")]
    nullifier_root: [u8; 48],
    extrinsics_root: [u8; 32],
    #[serde(with = "serde_array48")]
    message_root: [u8; 48],
    message_count: u32,
    header_mmr_root: [u8; 32],
    header_mmr_len: u64,
    timestamp_ms: u64,
    pow_bits: u32,
    nonce: [u8; 32],
    work_hash: [u8; 32],
    #[serde(with = "serde_array48")]
    cumulative_work: [u8; 48],
    supply_digest: u128,
    tx_count: u32,
    #[serde(default)]
    action_bytes: Vec<Vec<u8>>,
    #[serde(default = "native_empty_digest48_default", with = "serde_array48")]
    miner_commitment: [u8; 48],
    #[serde(default)]
    miner_public_key: Vec<u8>,
    #[serde(default)]
    miner_signature: Vec<u8>,
}

/// Exact identity-bearing native V2 schema used by the unreleased interim
/// implementation. It is decode-only so startup and peers receive an
/// actionable fresh-genesis error; it is never upgraded into active metadata.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct LegacyIdentityNativeBlockMetaV2 {
    chain_id: [u8; 32],
    rules_hash: [u8; 32],
    height: u64,
    hash: [u8; 32],
    parent_hash: [u8; 32],
    #[serde(with = "serde_array48")]
    state_root: [u8; 48],
    #[serde(with = "serde_array48")]
    kernel_root: [u8; 48],
    #[serde(with = "serde_array48")]
    nullifier_root: [u8; 48],
    extrinsics_root: [u8; 32],
    #[serde(with = "serde_array48")]
    message_root: [u8; 48],
    message_count: u32,
    header_mmr_root: [u8; 32],
    header_mmr_len: u64,
    timestamp_ms: u64,
    pow_bits: u32,
    nonce: [u8; 32],
    work_hash: [u8; 32],
    #[serde(with = "serde_array48")]
    cumulative_work: [u8; 48],
    supply_digest: u128,
    tx_count: u32,
    #[serde(default)]
    action_bytes: Vec<Vec<u8>>,
    #[serde(default = "native_empty_digest48_default", with = "serde_array48")]
    miner_commitment: [u8; 48],
    #[serde(default)]
    miner_public_key: Vec<u8>,
    #[serde(default)]
    miner_signature: Vec<u8>,
    #[serde(default = "native_empty_digest48_default", with = "serde_array48")]
    da_root: [u8; 48],
    #[serde(default)]
    da_chunk_size: u32,
    #[serde(default)]
    da_sample_count: u32,
    #[serde(default)]
    da_blob_len: u64,
    #[serde(default)]
    da_chunk_count: u32,
}

#[derive(Clone, Debug)]
pub(crate) struct NativeWork {
    height: u64,
    parent_hash: [u8; 32],
    pre_hash: [u8; 32],
    state_root: [u8; 48],
    kernel_root: [u8; 48],
    nullifier_root: [u8; 48],
    extrinsics_root: [u8; 32],
    message_root: [u8; 48],
    message_count: u32,
    header_mmr_root: [u8; 32],
    header_mmr_len: u64,
    cumulative_work: [u8; 48],
    supply_digest: u128,
    tx_count: u32,
    da_root: [u8; 48],
    da_chunk_size: u32,
    da_sample_count: u32,
    da_blob_len: u64,
    da_chunk_count: u32,
    timestamp_ms: u64,
    pow_bits: u32,
    prepared_actions: Option<Arc<Vec<PendingAction>>>,
}

#[derive(Clone, Debug)]
pub(crate) struct NativeSeal {
    nonce: [u8; 32],
    work_hash: [u8; 32],
}

#[derive(Clone, Debug)]
pub(crate) struct NativeMiningRoundResult {
    seal: Option<NativeSeal>,
    hashes: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) enum NativeSyncMessage {
    Announce(Box<NativeBlockMeta>),
    Request {
        from_height: u64,
        to_height: u64,
    },
    Response {
        best_height: u64,
        blocks: Vec<NativeBlockMeta>,
    },
    PendingAction {
        action: Vec<u8>,
    },
    /// Schema-3 large-block announcement. The canonical bincode body is requested
    /// separately and is accepted only when it reproduces this locator.
    AnnounceLocator {
        locator: NativeBlockBodyLocator,
    },
    /// Schema-3 range response. Bodies are requested one at a time so a peer cannot
    /// reserve an entire response range's maximum block bytes in memory.
    ResponseLocators {
        best_height: u64,
        blocks: Vec<NativeBlockBodyLocator>,
    },
    BlockBodyRequest {
        block_hash: [u8; 32],
    },
    BlockBodyChunk {
        chunk: NativeBlockBodyChunk,
    },
    /// PR 203 bounded-record chunk fallback. These variants are additive to
    /// the V3 locator/body grammar above; they must not rewrite or upgrade a
    /// stored V3 record or its separately bound canonical action body.
    RequestBlockChunk(NativeSyncBlockChunkRequest),
    BlockChunk(NativeSyncBlockChunk),
    AnnounceTip(NativeSyncTipAnnouncement),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct NativeBlockBodyLocator {
    schema_version: u16,
    chain_id: [u8; 32],
    rules_hash: [u8; 32],
    height: u64,
    block_hash: [u8; 32],
    parent_hash: [u8; 32],
    #[serde(with = "serde_array48")]
    cumulative_work: [u8; 48],
    total_len: u64,
    body_hash: [u8; 32],
    chunk_count: u32,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct NativeBlockBodyChunk {
    block_hash: [u8; 32],
    total_len: u64,
    body_hash: [u8; 32],
    chunk_index: u32,
    chunk_count: u32,
    chunk_len: u32,
    #[serde(with = "serde_native_block_body_chunk_bytes")]
    bytes: Vec<u8>,
}

/// Fresh V3 body locator grammar. These typed widths stay separate from the
/// interim 32-byte structs above until the metadata/Pow/transport atomic
/// cutover; after that cutover, the earlier wire-era tags reject before serde
/// or reservation rather than adapting mixed-width identities.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct NativeBlockBodyLocatorV3 {
    schema_version: u16,
    chain_id: [u8; 32],
    rules_hash: RulesHash48,
    height: u64,
    block_hash: BlockId48,
    parent_hash: BlockId48,
    cumulative_work: Work64,
    total_len: u64,
    body_hash: BodyHash48,
    chunk_count: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct NativeBlockBodyRequestV3 {
    block_hash: BlockId48,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct NativeBlockBodyChunkV3 {
    block_hash: BlockId48,
    total_len: u64,
    body_hash: BodyHash48,
    chunk_index: u32,
    chunk_count: u32,
    chunk_len: u32,
    #[serde(with = "serde_native_block_body_chunk_bytes")]
    bytes: Vec<u8>,
}

pub(crate) mod serde_native_block_body_chunk_bytes {
    use super::MAX_NATIVE_BLOCK_BODY_CHUNK_BYTES;
    use serde::de::{Error, SeqAccess, Visitor};
    use serde::{Deserializer, Serialize, Serializer};
    use std::fmt;

    pub fn serialize<S>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serde_bytes::Bytes::new(bytes).serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_bytes(BoundedChunkBytesVisitor)
    }

    struct BoundedChunkBytesVisitor;

    impl<'de> Visitor<'de> for BoundedChunkBytesVisitor {
        type Value = Vec<u8>;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(
                formatter,
                "at most {MAX_NATIVE_BLOCK_BODY_CHUNK_BYTES} native block body chunk bytes"
            )
        }

        fn visit_borrowed_bytes<E>(self, value: &'de [u8]) -> Result<Self::Value, E>
        where
            E: Error,
        {
            self.visit_bytes(value)
        }

        fn visit_bytes<E>(self, value: &[u8]) -> Result<Self::Value, E>
        where
            E: Error,
        {
            if value.len() > MAX_NATIVE_BLOCK_BODY_CHUNK_BYTES {
                return Err(E::custom("native block body chunk bytes exceed limit"));
            }
            Ok(value.to_vec())
        }

        fn visit_byte_buf<E>(self, value: Vec<u8>) -> Result<Self::Value, E>
        where
            E: Error,
        {
            if value.len() > MAX_NATIVE_BLOCK_BODY_CHUNK_BYTES {
                return Err(E::custom("native block body chunk bytes exceed limit"));
            }
            Ok(value)
        }

        fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
        where
            A: SeqAccess<'de>,
        {
            if sequence
                .size_hint()
                .is_some_and(|hint| hint > MAX_NATIVE_BLOCK_BODY_CHUNK_BYTES)
            {
                return Err(A::Error::custom(
                    "native block body chunk bytes exceed limit",
                ));
            }
            let mut bytes = Vec::with_capacity(
                sequence
                    .size_hint()
                    .unwrap_or(0)
                    .min(MAX_NATIVE_BLOCK_BODY_CHUNK_BYTES),
            );
            while let Some(byte) = sequence.next_element::<u8>()? {
                if bytes.len() >= MAX_NATIVE_BLOCK_BODY_CHUNK_BYTES {
                    return Err(A::Error::custom(
                        "native block body chunk bytes exceed limit",
                    ));
                }
                bytes.push(byte);
            }
            Ok(bytes)
        }
    }
}

#[derive(Clone, Debug, Encode, Decode)]
pub(crate) struct PendingAction {
    tx_hash: ActionId48,
    binding: KernelVersionBinding,
    family_id: u16,
    action_id: u16,
    anchor: [u8; 48],
    nullifiers: Vec<[u8; 48]>,
    commitments: Vec<[u8; 48]>,
    ciphertext_hashes: Vec<[u8; 48]>,
    ciphertext_sizes: Vec<u32>,
    public_args: Vec<u8>,
    fee: u64,
    candidate_artifact: Option<CandidateArtifact>,
}

/// Exact pre-V3 action grammar. It is decode-only and must never be upgraded
/// into an active action because the 32-byte self identifier and consensus
/// arrival timestamp are outside the V3 identity model.
#[derive(Clone, Debug, Encode, Decode)]
pub(crate) struct LegacyPendingActionV1 {
    tx_hash: [u8; 32],
    binding: KernelVersionBinding,
    family_id: u16,
    action_id: u16,
    anchor: [u8; 48],
    nullifiers: Vec<[u8; 48]>,
    commitments: Vec<[u8; 48]>,
    ciphertext_hashes: Vec<[u8; 48]>,
    ciphertext_sizes: Vec<u32>,
    public_args: Vec<u8>,
    fee: u64,
    candidate_artifact: Option<CandidateArtifact>,
    received_ms: u64,
}

/// Exact unreleased interim action grammar with a 48-byte identifier but the
/// retired consensus arrival timestamp. It is identify-and-reject only.
#[derive(Clone, Debug, Encode, Decode)]
pub(crate) struct LegacyPendingActionV2 {
    tx_hash: ActionId48,
    binding: KernelVersionBinding,
    family_id: u16,
    action_id: u16,
    anchor: [u8; 48],
    nullifiers: Vec<[u8; 48]>,
    commitments: Vec<[u8; 48]>,
    ciphertext_hashes: Vec<[u8; 48]>,
    ciphertext_sizes: Vec<u32>,
    public_args: Vec<u8>,
    fee: u64,
    candidate_artifact: Option<CandidateArtifact>,
    received_ms: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct NativeSyncRange {
    from_height: u64,
    to_height: u64,
}

pub(crate) fn native_sync_ranges_overlap(left: NativeSyncRange, right: NativeSyncRange) -> bool {
    left.from_height <= right.to_height && right.from_height <= left.to_height
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct NativeSyncResponseRangeInput {
    from_height: u64,
    to_height: u64,
    best_height: u64,
    max_blocks: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct NativeSyncMissingRequestInput {
    best_height: u64,
    announced_height: u64,
    max_blocks: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct NativeSyncResponseCountAdmissionInput {
    block_count: usize,
    max_blocks: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct NativeSyncRequestRateAdmissionInput {
    requests_in_window: u32,
    max_requests: u32,
    window_elapsed_ms: u64,
    window_ms: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct NativeSyncBlockRangePublicationAdmissionInput {
    range_admitted: bool,
    served_count_matches_range: bool,
    first_height_matches_range: bool,
    last_height_matches_range: bool,
    served_heights_contiguous: bool,
    previous_parent_anchor_verified: bool,
    parent_hashes_contiguous: bool,
    canonical_rows_verified: bool,
    action_bodies_verified: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum NativeSyncAdmissionRejection {
    ResponseBlockCountTooLarge,
    RequestRateLimited,
}

impl NativeSyncAdmissionRejection {
    fn label(self) -> &'static str {
        match self {
            Self::ResponseBlockCountTooLarge => "response_block_count_too_large",
            Self::RequestRateLimited => "request_rate_limited",
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct NativeSyncRequestRateState {
    window_start: Instant,
    requests: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum NativeSyncResponseStart {
    Started,
    DuplicateRange,
    AtCapacity,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum NativeOutboundSyncRequestState {
    InFlight,
    Paced,
    Cooldown,
    ChunkFallback,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct NativeOutboundSyncRequestContext {
    recovery_page: bool,
    expected_parent_hash: Option<[u8; 32]>,
    target_tip: Option<(u64, [u8; 32])>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct NativeOutboundSyncRequest {
    range: NativeSyncRange,
    requested_at: Instant,
    state: NativeOutboundSyncRequestState,
    context: NativeOutboundSyncRequestContext,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct NativeSyncTargetSnapshot {
    height: u64,
    peer_id: Option<PeerId>,
    hash: Option<[u8; 32]>,
    unverified_peer_hint: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct NativeCompletedSyncRequest {
    request_target: Option<PeerId>,
    range: NativeSyncRange,
    context: NativeOutboundSyncRequestContext,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct NativeSyncRecoveryCursor {
    peer_id: Option<PeerId>,
    target_height: u64,
    target_hash: Option<[u8; 32]>,
    range: NativeSyncRange,
    expected_parent_hash: Option<[u8; 32]>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct NativeMiningSyncEvidenceInput {
    verified_new_progress: bool,
    verified_known_at_or_below_local_best: bool,
    local_best_height: u64,
    peer_best_height: u64,
    stopped_on_error: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct NativeMiningGateInput {
    has_seeds: bool,
    dev: bool,
    bootstrap_mining_authoring: bool,
    observed_gate_open: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum NativeAnnouncedBlockImportOutcome {
    CanonicalAdvanced,
    StoredNoncanonical,
    AlreadyKnown,
    MissingParent,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum NativeSuppliedBlockRecordStatus {
    KnownExact,
    Missing,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct NativeSuppliedBlockRecordClassificationInput {
    stored_record_present: bool,
    stored_record_exact: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum NativeSuppliedBlockRecordClassificationRejection {
    KnownRecordMismatch,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum NativeSyncResponseImportOutcome {
    Imported,
    StoredNoncanonical,
    AlreadyKnown,
    MissingParent,
    Error,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct NativeSyncResponseImportProgress {
    had_blocks: bool,
    response_block_count: usize,
    attempted_blocks: usize,
    imported_blocks: u64,
    stored_noncanonical_blocks: u64,
    stopped_on_missing_parent: bool,
    stopped_on_error: bool,
}

impl NativeSyncResponseImportProgress {
    fn new(response_block_count: usize) -> Self {
        Self {
            had_blocks: response_block_count > 0,
            response_block_count,
            attempted_blocks: 0,
            imported_blocks: 0,
            stored_noncanonical_blocks: 0,
            stopped_on_missing_parent: false,
            stopped_on_error: false,
        }
    }

    fn record(&mut self, outcome: NativeSyncResponseImportOutcome) -> bool {
        if self.stopped_on_error
            || self.stopped_on_missing_parent
            || self.attempted_blocks >= self.response_block_count
        {
            return false;
        }
        self.attempted_blocks += 1;
        match outcome {
            NativeSyncResponseImportOutcome::Imported => {
                self.imported_blocks = self.imported_blocks.saturating_add(1);
                true
            }
            NativeSyncResponseImportOutcome::StoredNoncanonical => {
                self.stored_noncanonical_blocks = self.stored_noncanonical_blocks.saturating_add(1);
                true
            }
            NativeSyncResponseImportOutcome::AlreadyKnown => true,
            NativeSyncResponseImportOutcome::MissingParent => {
                self.stopped_on_missing_parent = true;
                false
            }
            NativeSyncResponseImportOutcome::Error => {
                self.stopped_on_error = true;
                false
            }
        }
    }

    fn record_terminal_error(&mut self) {
        let _ = self.record(NativeSyncResponseImportOutcome::Error);
        // Errors discovered after every response row was classified (for
        // example while reconstructing an all-known winning branch) must
        // still be terminal even though `record` cannot consume another row.
        self.stopped_on_error = true;
    }

    fn record_missing_parent_after_classification(&mut self) -> bool {
        if !self.had_blocks
            || self.attempted_blocks != self.response_block_count
            || self.imported_blocks != 0
            || self.stored_noncanonical_blocks != 0
            || self.stopped_on_error
            || self.stopped_on_missing_parent
        {
            return false;
        }
        self.stopped_on_missing_parent = true;
        true
    }

    fn should_request_more(self, local_best_height: u64, peer_best_height: u64) -> bool {
        self.had_blocks
            && !self.stopped_on_missing_parent
            && !self.stopped_on_error
            && !self.completed_without_canonical_progress()
            && local_best_height < peer_best_height
    }

    fn completed_without_canonical_progress(self) -> bool {
        self.had_blocks
            && self.attempted_blocks == self.response_block_count
            && self.imported_blocks == 0
            && !self.stopped_on_missing_parent
            && !self.stopped_on_error
    }

    fn completed_with_only_known_blocks(self) -> bool {
        self.completed_without_canonical_progress() && self.stored_noncanonical_blocks == 0
    }
}

pub(crate) fn native_sync_response_should_escalate_reorg_backfill(
    progress: NativeSyncResponseImportProgress,
    local_best_height: u64,
    peer_best_height: u64,
) -> bool {
    !progress.stopped_on_error
        && (progress.stopped_on_missing_parent || progress.completed_without_canonical_progress())
        && local_best_height <= peer_best_height
}

pub(crate) fn native_mining_sync_observed_peer_height(
    input: NativeMiningSyncEvidenceInput,
) -> Option<u64> {
    if input.stopped_on_error {
        return None;
    }
    if input.verified_new_progress {
        return Some(input.peer_best_height);
    }
    if input.verified_known_at_or_below_local_best
        && input.peer_best_height <= input.local_best_height
    {
        return Some(input.local_best_height);
    }
    None
}

pub(crate) fn native_mining_gate_allows_work(input: NativeMiningGateInput) -> bool {
    if input.has_seeds {
        input.observed_gate_open
    } else {
        input.dev || input.bootstrap_mining_authoring
    }
}

pub(crate) fn native_sync_catch_up_target(
    best_height: u64,
    sync_target_observed: bool,
    sync_target_height: u64,
) -> Option<(u64, u64)> {
    if sync_target_observed && sync_target_height > best_height {
        Some((best_height, sync_target_height))
    } else {
        None
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct NativeActionHashAdmissionInput {
    action_count_matches: bool,
    action_hashes_match: bool,
    action_hashes_unique: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct NativePendingActionReloadInput {
    key_well_formed: bool,
    embedded_hash_matches_key: bool,
    recomputed_hash_matches_embedded: bool,
    action_hash_unique: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum NativeActionHashAdmissionRejection {
    ActionCountMismatch,
    ActionHashMismatch,
    DuplicateActionHash,
}

impl NativeActionHashAdmissionRejection {
    #[cfg(test)]
    fn label(self) -> &'static str {
        match self {
            Self::ActionCountMismatch => "action_count_mismatch",
            Self::ActionHashMismatch => "action_hash_mismatch",
            Self::DuplicateActionHash => "duplicate_action_hash",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct NativeAnnouncedBlockAdmissionInput {
    parent_height: u64,
    announced_height: u64,
    parent_hash_matches: bool,
    parent_timestamp_ms: u64,
    announced_timestamp_ms: u64,
    now_ms: u64,
    max_future_skew_ms: u64,
    hash_matches_work_hash: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct NativeBlockIndexReloadInput {
    chain_reconstructed: bool,
    chain_nonempty: bool,
    genesis_matches_expected: bool,
    best_metadata_matches_chain: bool,
    canonical_heights_contiguous: bool,
    canonical_chain_ids_match: bool,
    canonical_rules_hashes_match: bool,
    canonical_hashes_match_work_hashes: bool,
    canonical_parent_hashes_contiguous: bool,
    height_keys_well_formed: bool,
    height_values_well_formed: bool,
    no_extra_height_indexes: bool,
    height_index_heights_match_chain: bool,
    height_index_hashes_match_chain: bool,
    all_canonical_heights_indexed: bool,
    genesis_marker_present: bool,
    genesis_marker_length_valid: bool,
    genesis_marker_matches_expected: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct NativeBlockIndexReloadAdmission {
    repair_missing_genesis_marker: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct NativeCanonicalStateReloadInput {
    nullifier_keys_well_formed: bool,
    nullifier_markers_valid: bool,
    commitment_keys_well_formed: bool,
    commitment_values_well_formed: bool,
    commitment_indexes_contiguous: bool,
    commitment_tree_rebuilt: bool,
    commitment_root_matches_best: bool,
    nullifier_root_matches_best: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct NativeBridgeReplayReloadInput {
    replay_keys_well_formed: bool,
    replay_markers_valid: bool,
    canonical_replay_keys_unique: bool,
    no_missing_loaded_replay_keys: bool,
    no_extra_loaded_replay_keys: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct NativeStagedCiphertextReloadInput {
    key_well_formed: bool,
    ciphertext_within_limit: bool,
    ciphertext_hash_matches_key: bool,
    capacity_available: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct NativeStagedProofReloadInput {
    key_well_formed: bool,
    proof_nonempty: bool,
    proof_within_limit: bool,
    capacity_available: bool,
    byte_capacity_available: bool,
    proof_binding_hash_matches_key: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct NativeMinedWorkAdmissionInput {
    best_height: u64,
    work_height: u64,
    parent_hash_matches: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct NativeWorkTemplateAdmissionInput {
    best_height: u64,
    cumulative_work_advances: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct NativeRecursiveArtifactContextAdmissionInput {
    best_height: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum NativeAnnouncedBlockAdmissionRejection {
    HeightNotNext,
    ParentHashMismatch,
    TimestampDidNotAdvance,
    FutureSkew,
    HashWorkHashMismatch,
}

impl NativeAnnouncedBlockAdmissionRejection {
    fn label(self) -> &'static str {
        match self {
            Self::HeightNotNext => "height_not_next",
            Self::ParentHashMismatch => "parent_hash_mismatch",
            Self::TimestampDidNotAdvance => "timestamp_did_not_advance",
            Self::FutureSkew => "future_skew",
            Self::HashWorkHashMismatch => "hash_work_hash_mismatch",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum NativeBlockIndexReloadRejection {
    ChainReconstructionFailed,
    ChainEmpty,
    GenesisMismatch,
    BestMetadataMismatch,
    CanonicalHeightMismatch,
    ChainIdMismatch,
    RulesHashMismatch,
    HashWorkHashMismatch,
    ParentHashMismatch,
    MalformedHeightKey,
    MalformedHeightValue,
    ExtraHeightIndex,
    HeightIndexMismatch,
    HeightHashMismatch,
    MissingHeightIndex,
    GenesisMarkerInvalidLength,
    GenesisMarkerMismatch,
}

impl NativeBlockIndexReloadRejection {
    fn label(self) -> &'static str {
        match self {
            Self::ChainReconstructionFailed => "chain_reconstruction_failed",
            Self::ChainEmpty => "chain_empty",
            Self::GenesisMismatch => "genesis_mismatch",
            Self::BestMetadataMismatch => "best_metadata_mismatch",
            Self::CanonicalHeightMismatch => "canonical_height_mismatch",
            Self::ChainIdMismatch => "chain_id_mismatch",
            Self::RulesHashMismatch => "rules_hash_mismatch",
            Self::HashWorkHashMismatch => "hash_work_hash_mismatch",
            Self::ParentHashMismatch => "parent_hash_mismatch",
            Self::MalformedHeightKey => "malformed_height_key",
            Self::MalformedHeightValue => "malformed_height_value",
            Self::ExtraHeightIndex => "extra_height_index",
            Self::HeightIndexMismatch => "height_index_mismatch",
            Self::HeightHashMismatch => "height_hash_mismatch",
            Self::MissingHeightIndex => "missing_height_index",
            Self::GenesisMarkerInvalidLength => "genesis_marker_invalid_length",
            Self::GenesisMarkerMismatch => "genesis_marker_mismatch",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum NativeCanonicalStateReloadRejection {
    MalformedNullifierKey,
    InvalidNullifierMarker,
    MalformedCommitmentKey,
    MalformedCommitmentValue,
    CommitmentIndexGap,
    CommitmentTreeRebuildFailed,
    CommitmentRootMismatch,
    NullifierRootMismatch,
}

impl NativeCanonicalStateReloadRejection {
    fn label(self) -> &'static str {
        match self {
            Self::MalformedNullifierKey => "malformed_nullifier_key",
            Self::InvalidNullifierMarker => "invalid_nullifier_marker",
            Self::MalformedCommitmentKey => "malformed_commitment_key",
            Self::MalformedCommitmentValue => "malformed_commitment_value",
            Self::CommitmentIndexGap => "commitment_index_gap",
            Self::CommitmentTreeRebuildFailed => "commitment_tree_rebuild_failed",
            Self::CommitmentRootMismatch => "commitment_root_mismatch",
            Self::NullifierRootMismatch => "nullifier_root_mismatch",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum NativeBridgeReplayReloadRejection {
    MalformedReplayKey,
    InvalidReplayMarker,
    CanonicalReplayDuplicate,
    MissingConsumedReplayKey,
    ExtraConsumedReplayKey,
}

impl NativeBridgeReplayReloadRejection {
    fn label(self) -> &'static str {
        match self {
            Self::MalformedReplayKey => "malformed_replay_key",
            Self::InvalidReplayMarker => "invalid_replay_marker",
            Self::CanonicalReplayDuplicate => "canonical_replay_duplicate",
            Self::MissingConsumedReplayKey => "missing_consumed_replay_key",
            Self::ExtraConsumedReplayKey => "extra_consumed_replay_key",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum NativePendingActionReloadRejection {
    MalformedActionKey,
    KeyHashMismatch,
    RecomputedHashMismatch,
    DuplicatePendingAction,
}

impl NativePendingActionReloadRejection {
    fn label(self) -> &'static str {
        match self {
            Self::MalformedActionKey => "malformed_action_key",
            Self::KeyHashMismatch => "key_hash_mismatch",
            Self::RecomputedHashMismatch => "recomputed_hash_mismatch",
            Self::DuplicatePendingAction => "duplicate_pending_action",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum NativeStagedCiphertextReloadRejection {
    MalformedCiphertextKey,
    OversizedCiphertext,
    CiphertextHashMismatch,
    StagedCiphertextCapacityReached,
}

impl NativeStagedCiphertextReloadRejection {
    #[cfg(test)]
    fn label(self) -> &'static str {
        match self {
            Self::MalformedCiphertextKey => "malformed_ciphertext_key",
            Self::OversizedCiphertext => "oversized_ciphertext",
            Self::CiphertextHashMismatch => "ciphertext_hash_mismatch",
            Self::StagedCiphertextCapacityReached => "staged_ciphertext_capacity_reached",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum NativeStagedProofReloadRejection {
    MalformedProofKey,
    EmptyProof,
    OversizedProof,
    StagedProofCapacityReached,
    StagedProofByteCapacityReached,
    ProofBindingHashMismatch,
}

impl NativeStagedProofReloadRejection {
    #[cfg(test)]
    fn label(self) -> &'static str {
        match self {
            Self::MalformedProofKey => "malformed_proof_key",
            Self::EmptyProof => "empty_proof",
            Self::OversizedProof => "oversized_proof",
            Self::StagedProofCapacityReached => "staged_proof_capacity_reached",
            Self::StagedProofByteCapacityReached => "staged_proof_byte_capacity_reached",
            Self::ProofBindingHashMismatch => "proof_binding_hash_mismatch",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum NativeMinedWorkAdmissionRejection {
    ParentHashMismatch,
    HeightNotNext,
}

impl NativeMinedWorkAdmissionRejection {
    #[cfg(test)]
    fn label(self) -> &'static str {
        match self {
            Self::ParentHashMismatch => "parent_hash_mismatch",
            Self::HeightNotNext => "height_not_next",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum NativeWorkTemplateAdmissionRejection {
    HeightNotNext,
    CumulativeWorkOverflow,
}

impl NativeWorkTemplateAdmissionRejection {
    fn label(self) -> &'static str {
        match self {
            Self::HeightNotNext => "height_not_next",
            Self::CumulativeWorkOverflow => "cumulative_work_overflow",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum NativeRecursiveArtifactContextAdmissionRejection {
    HeightNotNext,
}

impl NativeRecursiveArtifactContextAdmissionRejection {
    fn label(self) -> &'static str {
        match self {
            Self::HeightNotNext => "height_not_next",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct NativeActionScopeAdmissionInput {
    candidate_artifact_payload_scoped: bool,
    bridge_route: bool,
    bridge_scope_valid: bool,
    candidate_artifact_route: bool,
    candidate_scope_valid: bool,
    candidate_payload_present: bool,
    coinbase_route: bool,
    coinbase_scope_valid: bool,
    transfer_route: bool,
    transfer_scope_valid: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum NativeActionScopeAdmissionRoute {
    Bridge,
    CandidateArtifact,
    Coinbase,
    Transfer,
}

impl NativeActionScopeAdmissionRoute {
    #[cfg(test)]
    fn label(self) -> &'static str {
        match self {
            Self::Bridge => "bridge",
            Self::CandidateArtifact => "candidate_artifact",
            Self::Coinbase => "coinbase",
            Self::Transfer => "transfer",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum NativeActionScopeAdmissionRejection {
    CandidateArtifactPayloadWrongRoute,
    BridgeScopeInvalid,
    CandidateScopeInvalid,
    CandidatePayloadMissing,
    CoinbaseScopeInvalid,
    UnsupportedActionRoute,
    TransferScopeInvalid,
}

impl NativeActionScopeAdmissionRejection {
    #[cfg(test)]
    fn label(self) -> &'static str {
        match self {
            Self::CandidateArtifactPayloadWrongRoute => "candidate_artifact_payload_wrong_route",
            Self::BridgeScopeInvalid => "bridge_scope_invalid",
            Self::CandidateScopeInvalid => "candidate_scope_invalid",
            Self::CandidatePayloadMissing => "candidate_payload_missing",
            Self::CoinbaseScopeInvalid => "coinbase_scope_invalid",
            Self::UnsupportedActionRoute => "unsupported_action_route",
            Self::TransferScopeInvalid => "transfer_scope_invalid",
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct NativeBlockActionValidationState {
    bridge_replay_state: InboundReplayState,
    previous_transfer_key: Option<[u8; 32]>,
    validated_action_count: usize,
    imported_bridge_replay_count: usize,
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct NativeBlockActionValidationStep {
    scope_input: NativeActionScopeAdmissionInput,
    payload_valid: bool,
    /// Historical 48-byte transfers retain canonical key ordering. V8 order is
    /// committed by the block action root and verified against typed state.
    enforce_legacy_transfer_order: bool,
    transfer_key: [u8; 32],
    transfer_state_input: NativeTransferStateAdmissionInput,
    bridge_replay_key: Option<[u8; 48]>,
}

#[cfg(test)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct NativeBlockActionValidationSummary {
    validated_action_count: usize,
    imported_bridge_replay_count: usize,
    last_transfer_key: Option<[u8; 32]>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum NativeBlockActionValidationRejection {
    ActionCountMismatch,
    ActionHashMismatch,
    DuplicateActionHash,
    CandidateArtifactPayloadWrongRoute,
    BridgeScopeInvalid,
    CandidateScopeInvalid,
    CandidatePayloadMissing,
    CoinbaseScopeInvalid,
    UnsupportedActionRoute,
    TransferScopeInvalid,
    BridgePayloadInvalid,
    CandidatePayloadInvalid,
    CoinbasePayloadInvalid,
    TransferPayloadInvalid,
    BridgeReplayDuplicate,
    TransferOrderInvalid,
    TransferUnknownAnchor,
    TransferNullifierZero,
    TransferNullifierAlreadySpent,
    TransferDuplicateNullifier,
    TransferNullifierAlreadyPending,
    TransferCommitmentZero,
    TransferStablecoinPolicyUnauthorized,
    TransferSidecarCiphertextMissing,
    TransferSidecarCiphertextSizeMissing,
    TransferSidecarCiphertextSizeMismatch,
}

impl NativeBlockActionValidationRejection {
    fn label(self) -> &'static str {
        match self {
            Self::ActionCountMismatch => "action_count_mismatch",
            Self::ActionHashMismatch => "action_hash_mismatch",
            Self::DuplicateActionHash => "duplicate_action_hash",
            Self::CandidateArtifactPayloadWrongRoute => "candidate_artifact_payload_wrong_route",
            Self::BridgeScopeInvalid => "bridge_scope_invalid",
            Self::CandidateScopeInvalid => "candidate_scope_invalid",
            Self::CandidatePayloadMissing => "candidate_payload_missing",
            Self::CoinbaseScopeInvalid => "coinbase_scope_invalid",
            Self::UnsupportedActionRoute => "unsupported_action_route",
            Self::TransferScopeInvalid => "transfer_scope_invalid",
            Self::BridgePayloadInvalid => "bridge_payload_invalid",
            Self::CandidatePayloadInvalid => "candidate_payload_invalid",
            Self::CoinbasePayloadInvalid => "coinbase_payload_invalid",
            Self::TransferPayloadInvalid => "transfer_payload_invalid",
            Self::BridgeReplayDuplicate => "bridge_replay_duplicate",
            Self::TransferOrderInvalid => "transfer_order_invalid",
            Self::TransferUnknownAnchor => "transfer_unknown_anchor",
            Self::TransferNullifierZero => "transfer_nullifier_zero",
            Self::TransferNullifierAlreadySpent => "transfer_nullifier_already_spent",
            Self::TransferDuplicateNullifier => "transfer_duplicate_nullifier",
            Self::TransferNullifierAlreadyPending => "transfer_nullifier_already_pending",
            Self::TransferCommitmentZero => "transfer_commitment_zero",
            Self::TransferStablecoinPolicyUnauthorized => "transfer_stablecoin_policy_unauthorized",
            Self::TransferSidecarCiphertextMissing => "transfer_sidecar_ciphertext_missing",
            Self::TransferSidecarCiphertextSizeMissing => {
                "transfer_sidecar_ciphertext_size_missing"
            }
            Self::TransferSidecarCiphertextSizeMismatch => {
                "transfer_sidecar_ciphertext_size_mismatch"
            }
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct NativeBridgeActionPayloadAdmissionInput {
    bridge_route: bool,
    state_deltas_absent: bool,
    action_kind: NativeBridgeActionPayloadKind,
    outbound_payload_nonempty: bool,
    inbound_proof_receipt_nonempty: bool,
    inbound_replay_key_matches: bool,
    inbound_destination_matches: bool,
    inbound_payload_hash_matches: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct NativeBridgeActionResourceAdmissionInput {
    raw_byte_cap: usize,
    decoded_byte_cap: usize,
    item_count_cap: usize,
    item_byte_cap: usize,
    aggregate_byte_cap: usize,
    work_unit_cap: usize,
    action_kind: NativeBridgeActionPayloadKind,
    public_args_bytes: usize,
    outbound_payload_bytes: usize,
    inbound_proof_receipt_bytes: usize,
    inbound_message_payload_bytes: usize,
}

#[derive(Clone, Debug)]
pub(crate) struct NativeBridgeMintReplayPolicyInput {
    inbound_bridge_mint: bool,
    state_deltas_absent: bool,
    receipt_envelope_present: bool,
    receipt_verified: bool,
    receipt_payload_matches: bool,
    replay_state: InboundReplayState,
    replay_key: [u8; 48],
    mint_authorized: bool,
    amount_matches_receipt: bool,
    amount_within_bound: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct NativeBridgeMintPayloadAdmissionInput {
    payload_decoded: bool,
    payload_hash_matches: bool,
    receipt_message_hash_matches: bool,
    version_matches: bool,
    source_app_family_matches: bool,
    destination_matches: bool,
    mint_nonce_matches: bool,
    recipient_commitment_nonzero: bool,
    amount_nonzero: bool,
    amount_within_bound: bool,
    asset_non_native: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct NativeBridgeVerifierRegistrationPolicyInput {
    bridge_verifier_registration: bool,
    state_deltas_absent: bool,
    registration_decoded: bool,
    descriptor_matches_release: bool,
    activation_height_reached: bool,
    pq_clean_verifier_bound: bool,
    external_verifier_soundness_accepted: bool,
    positive_minting_enabled: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct NativeBridgeVerifierRegistrationPolicyEffect {
    registration_observed: bool,
    production_mint_verifier_enabled: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct NativeBridgeWitnessExportAdmissionInput {
    block_hash_parameter_valid: bool,
    explicit_block_hash: bool,
    block_known: bool,
    canonical_height_present: bool,
    block_is_canonical: bool,
    block_actions_decoded: bool,
    message_index_in_bounds: bool,
    parent_known: bool,
    best_height: u64,
    message_height: u64,
    max_explicit_history: u64,
    max_materialized_history: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct NativeInboundBridgeReceiptAdmissionInput {
    source_chain_matches: bool,
    rules_hash_matches: bool,
    message_nonce_matches: bool,
    message_hash_matches: bool,
    checkpoint_height: u64,
    canonical_tip_height: u64,
    canonical_tip_work: [u8; 48],
    confirmations_checked: u32,
    min_confirmations: u32,
    min_work_checked: [u8; 48],
    min_tip_work: [u8; 48],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct NativeBridgeWitnessBackscanEntry {
    height: u64,
    canonical_hash_present: bool,
    block_known: bool,
    block_actions_decoded: bool,
    message_index_in_bounds: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum NativeBridgeActionPayloadKind {
    Outbound,
    Inbound,
    Register,
    Unsupported,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum NativeBridgeActionPayloadAdmissionRejection {
    NotBridgeAction,
    StateDeltasPresent,
    UnsupportedBridgeAction,
    OutboundPayloadEmpty,
    InboundProofReceiptEmpty,
    InboundReplayKeyMismatch,
    InboundDestinationMismatch,
    InboundPayloadHashMismatch,
}

impl NativeBridgeActionPayloadAdmissionRejection {
    #[cfg(test)]
    fn label(self) -> &'static str {
        match self {
            Self::NotBridgeAction => "not_bridge_action",
            Self::StateDeltasPresent => "state_deltas_present",
            Self::UnsupportedBridgeAction => "unsupported_bridge_action",
            Self::OutboundPayloadEmpty => "outbound_payload_empty",
            Self::InboundProofReceiptEmpty => "inbound_proof_receipt_empty",
            Self::InboundReplayKeyMismatch => "inbound_replay_key_mismatch",
            Self::InboundDestinationMismatch => "inbound_destination_mismatch",
            Self::InboundPayloadHashMismatch => "inbound_payload_hash_mismatch",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum NativeBridgeMintReplayPolicyRejection {
    NotInboundBridgeMint,
    StateDeltaMintPresent,
    ReceiptEnvelopeMissing,
    ReceiptNotVerified,
    ReceiptPayloadMismatch,
    ReplayAlreadyConsumed,
    MintNotAuthorized,
    AmountDoesNotMatchReceipt,
    AmountOutOfBounds,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum NativeBridgeMintPayloadAdmissionRejection {
    PayloadDecodeFailed,
    PayloadHashMismatch,
    ReceiptMessageHashMismatch,
    VersionMismatch,
    SourceAppFamilyMismatch,
    DestinationMismatch,
    MintNonceMismatch,
    RecipientCommitmentZero,
    AmountZero,
    AmountOutOfBounds,
    NativeAssetNotAllowed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum NativeBridgeVerifierRegistrationPolicyRejection {
    NotBridgeVerifierRegistration,
    StateDeltasPresent,
    RegistrationDecodeFailed,
}

impl NativeBridgeMintPayloadAdmissionRejection {
    fn label(self) -> &'static str {
        match self {
            Self::PayloadDecodeFailed => "payload_decode_failed",
            Self::PayloadHashMismatch => "payload_hash_mismatch",
            Self::ReceiptMessageHashMismatch => "receipt_message_hash_mismatch",
            Self::VersionMismatch => "version_mismatch",
            Self::SourceAppFamilyMismatch => "source_app_family_mismatch",
            Self::DestinationMismatch => "destination_mismatch",
            Self::MintNonceMismatch => "mint_nonce_mismatch",
            Self::RecipientCommitmentZero => "recipient_commitment_zero",
            Self::AmountZero => "amount_zero",
            Self::AmountOutOfBounds => "amount_out_of_bounds",
            Self::NativeAssetNotAllowed => "native_asset_not_allowed",
        }
    }
}

impl NativeBridgeVerifierRegistrationPolicyRejection {
    fn label(self) -> &'static str {
        match self {
            Self::NotBridgeVerifierRegistration => "not_bridge_verifier_registration",
            Self::StateDeltasPresent => "state_deltas_present",
            Self::RegistrationDecodeFailed => "registration_decode_failed",
        }
    }
}

impl NativeBridgeMintReplayPolicyRejection {
    fn label(self) -> &'static str {
        match self {
            Self::NotInboundBridgeMint => "not_inbound_bridge_mint",
            Self::StateDeltaMintPresent => "state_delta_mint_present",
            Self::ReceiptEnvelopeMissing => "receipt_envelope_missing",
            Self::ReceiptNotVerified => "receipt_not_verified",
            Self::ReceiptPayloadMismatch => "receipt_payload_mismatch",
            Self::ReplayAlreadyConsumed => "replay_already_consumed",
            Self::MintNotAuthorized => "mint_not_authorized",
            Self::AmountDoesNotMatchReceipt => "amount_does_not_match_receipt",
            Self::AmountOutOfBounds => "amount_out_of_bounds",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum NativeBridgeWitnessExportAdmissionRejection {
    MalformedBlockHash,
    UnknownBlock,
    MissingCanonicalHeight,
    NoncanonicalBlock,
    BlockActionsDecodeFailed,
    MessageIndexOutOfBounds,
    MissingParent,
    TipBeforeMessage,
    ExplicitHistoryTooLong,
    MaterializedHistoryTooLong,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum NativeInboundBridgeReceiptAdmissionRejection {
    SourceChainMismatch,
    RulesHashMismatch,
    MessageNonceMismatch,
    MessageHashMismatch,
    TipBeforeMessage,
    ConfirmationsOverflow,
    ConfirmationsOverstated,
    Underconfirmed,
    WorkPolicyMismatch,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum NativeBridgeWitnessBackscanRejection {
    BlockActionsDecodeFailed,
    NoBridgeMessageInBackscan,
}

impl NativeBridgeWitnessExportAdmissionRejection {
    fn label(self) -> &'static str {
        match self {
            Self::MalformedBlockHash => "malformed_block_hash",
            Self::UnknownBlock => "unknown_block",
            Self::MissingCanonicalHeight => "missing_canonical_height",
            Self::NoncanonicalBlock => "noncanonical_block",
            Self::BlockActionsDecodeFailed => "block_actions_decode_failed",
            Self::MessageIndexOutOfBounds => "message_index_out_of_bounds",
            Self::MissingParent => "missing_parent",
            Self::TipBeforeMessage => "tip_before_message",
            Self::ExplicitHistoryTooLong => "explicit_history_too_long",
            Self::MaterializedHistoryTooLong => "materialized_history_too_long",
        }
    }
}

impl NativeInboundBridgeReceiptAdmissionRejection {
    #[cfg(test)]
    fn label(self) -> &'static str {
        match self {
            Self::SourceChainMismatch => "source_chain_mismatch",
            Self::RulesHashMismatch => "rules_hash_mismatch",
            Self::MessageNonceMismatch => "message_nonce_mismatch",
            Self::MessageHashMismatch => "message_hash_mismatch",
            Self::TipBeforeMessage => "tip_before_message",
            Self::ConfirmationsOverflow => "confirmations_overflow",
            Self::ConfirmationsOverstated => "confirmations_overstated",
            Self::Underconfirmed => "underconfirmed",
            Self::WorkPolicyMismatch => "work_policy_mismatch",
        }
    }
}

impl NativeBridgeWitnessBackscanRejection {
    fn label(self) -> &'static str {
        match self {
            Self::BlockActionsDecodeFailed => "block_actions_decode_failed",
            Self::NoBridgeMessageInBackscan => "no_bridge_message_in_backscan",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct NativeRisc0ReleaseVerifierInput {
    image_id_matches: bool,
    journal_decodes: bool,
    verifier_enabled: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum NativeRisc0ReleaseVerifierRejection {
    ImageIdMismatch,
    JournalDecodeFailed,
    VerifierDisabled,
}

impl NativeRisc0ReleaseVerifierRejection {
    #[cfg(test)]
    fn label(self) -> &'static str {
        match self {
            Self::ImageIdMismatch => "image_id_mismatch",
            Self::JournalDecodeFailed => "journal_decode_failed",
            Self::VerifierDisabled => "verifier_disabled",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct NativeTransferPayloadAdmissionInput {
    proof_bytes: usize,
    max_proof_bytes: usize,
    anchor_matches: bool,
    commitments_match: bool,
    inline_ciphertext_bytes: usize,
    max_ciphertext_bytes: usize,
    ciphertext_hashes_match: bool,
    ciphertext_sizes_match: bool,
    binding_hash_matches: bool,
    proof_binding_hash_matches_key: bool,
    fee_matches: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct NativeInlineTransferCiphertextResourceInput {
    raw_byte_cap: usize,
    decoded_byte_cap: usize,
    item_count_cap: usize,
    item_byte_cap: usize,
    aggregate_byte_cap: usize,
    work_unit_cap: usize,
    route_payload_bytes: usize,
    proof_bytes: usize,
    ciphertext_count: usize,
    max_ciphertext_bytes_observed: usize,
    aggregate_ciphertext_bytes: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum NativeTransferPayloadRoute {
    Inline,
    Sidecar,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum NativeTransferPayloadAdmissionRejection {
    ProofMissing,
    ProofTooLarge,
    AnchorMismatch,
    CommitmentsMismatch,
    InlineCiphertextTooLarge,
    CiphertextHashesMismatch,
    CiphertextSizesMismatch,
    BindingHashMismatch,
    ProofBindingHashMismatch,
    FeeMismatch,
}

impl NativeTransferPayloadAdmissionRejection {
    #[cfg(test)]
    fn label(self) -> &'static str {
        match self {
            Self::ProofMissing => "proof_missing",
            Self::ProofTooLarge => "proof_too_large",
            Self::AnchorMismatch => "anchor_mismatch",
            Self::CommitmentsMismatch => "commitments_mismatch",
            Self::InlineCiphertextTooLarge => "inline_ciphertext_too_large",
            Self::CiphertextHashesMismatch => "ciphertext_hashes_mismatch",
            Self::CiphertextSizesMismatch => "ciphertext_sizes_mismatch",
            Self::BindingHashMismatch => "binding_hash_mismatch",
            Self::ProofBindingHashMismatch => "proof_binding_hash_mismatch",
            Self::FeeMismatch => "fee_mismatch",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct NativeTransferStateAdmissionInput {
    anchor_known: bool,
    nullifier_state: NativeTransferNullifierAdmissionState,
    commitments_nonzero: bool,
    stablecoin_policy_authorized: bool,
    sidecar_route: bool,
    sidecar_ciphertexts_available: bool,
    sidecar_ciphertext_sizes_present: bool,
    sidecar_ciphertext_sizes_match: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum NativeTransferNullifierAdmissionState {
    Valid,
    Zero,
    AlreadySpent,
    Duplicate,
    AlreadyPending,
}

impl NativeTransferNullifierAdmissionState {
    #[cfg(test)]
    fn label(self) -> &'static str {
        match self {
            Self::Valid => "valid",
            Self::Zero => "zero",
            Self::AlreadySpent => "already_spent",
            Self::Duplicate => "duplicate",
            Self::AlreadyPending => "already_pending",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum NativeTransferStateAdmissionContext {
    Mempool,
    Block,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum NativeTransferStateAdmissionRejection {
    UnknownAnchor,
    NullifierZero,
    NullifierAlreadySpent,
    DuplicateNullifier,
    NullifierAlreadyPending,
    CommitmentZero,
    StablecoinPolicyUnauthorized,
    SidecarCiphertextMissing,
    SidecarCiphertextSizeMissing,
    SidecarCiphertextSizeMismatch,
}

impl NativeTransferStateAdmissionRejection {
    #[cfg(test)]
    fn label(self) -> &'static str {
        match self {
            Self::UnknownAnchor => "unknown_anchor",
            Self::NullifierZero => "nullifier_zero",
            Self::NullifierAlreadySpent => "nullifier_already_spent",
            Self::DuplicateNullifier => "duplicate_nullifier",
            Self::NullifierAlreadyPending => "nullifier_already_pending",
            Self::CommitmentZero => "commitment_zero",
            Self::StablecoinPolicyUnauthorized => "stablecoin_policy_unauthorized",
            Self::SidecarCiphertextMissing => "sidecar_ciphertext_missing",
            Self::SidecarCiphertextSizeMissing => "sidecar_ciphertext_size_missing",
            Self::SidecarCiphertextSizeMismatch => "sidecar_ciphertext_size_mismatch",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct NativeStablecoinPolicyAuthorizationInput {
    stablecoin_present: bool,
    policy_known: bool,
    policy_active: bool,
    policy_lifecycle_open: bool,
    asset_matches: bool,
    policy_hash_matches: bool,
    policy_version_matches: bool,
    oracle_commitment_matches: bool,
    attestation_commitment_matches: bool,
    attestation_not_disputed: bool,
    oracle_fresh: bool,
    issuance_nonzero: bool,
    issuance_within_limit: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum NativeStablecoinPolicyAuthorizationRejection {
    PolicyMissing,
    PolicyInactive,
    PolicyNotLive,
    AssetMismatch,
    PolicyHashMismatch,
    PolicyVersionMismatch,
    OracleCommitmentMismatch,
    AttestationCommitmentMismatch,
    AttestationDisputed,
    OracleStale,
    IssuanceZero,
    IssuanceOverLimit,
}

impl NativeStablecoinPolicyAuthorizationRejection {
    #[cfg(test)]
    fn label(self) -> &'static str {
        match self {
            Self::PolicyMissing => "policy_missing",
            Self::PolicyInactive => "policy_inactive",
            Self::PolicyNotLive => "policy_not_live",
            Self::AssetMismatch => "asset_mismatch",
            Self::PolicyHashMismatch => "policy_hash_mismatch",
            Self::PolicyVersionMismatch => "policy_version_mismatch",
            Self::OracleCommitmentMismatch => "oracle_commitment_mismatch",
            Self::AttestationCommitmentMismatch => "attestation_commitment_mismatch",
            Self::AttestationDisputed => "attestation_disputed",
            Self::OracleStale => "oracle_stale",
            Self::IssuanceZero => "issuance_zero",
            Self::IssuanceOverLimit => "issuance_over_limit",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct NativeActionStateEffect {
    next_leaf_count: u64,
    imported_nullifier_count: usize,
    imported_bridge_replay: bool,
}

#[derive(Clone, Debug)]
pub(crate) struct NativePlannedActionEffect {
    commitment_start: u64,
    ciphertexts: Vec<Vec<u8>>,
    replay_key: Option<[u8; 48]>,
}

#[derive(Clone, Debug)]
pub(crate) struct NativeMaterializedActionPayload {
    ciphertexts: Vec<Vec<u8>>,
    replay_key: Option<[u8; 48]>,
}

#[derive(Clone, Debug)]
pub(crate) struct NativeCanonicalIndexPlan {
    commitment_entries: Vec<(u64, [u8; 48])>,
    nullifier_entries: Vec<(u64, [u8; 48])>,
    bridge_replay_entries: Vec<[u8; 48]>,
    ciphertext_index_entries: Vec<([u8; 48], Vec<u8>)>,
    ciphertext_archive_entries: Vec<(u64, Vec<u8>)>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct NativeCanonicalReorgPersistence {
    pub(crate) prestored_block_records: usize,
    pub(crate) canonical_transaction_block_record_writes: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct NativeNoncanonicalSyncBatchPersistence {
    pub(crate) newly_stored: usize,
    pub(crate) already_known: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct NativeCanonicalReorgPersistenceAdmissionInput {
    replacement_block_count: usize,
    known_block_count: usize,
    classified_missing_block_count: usize,
    supplied_missing_block_count: usize,
    connected_exact_known_rows: bool,
    suffix_fully_validated: bool,
    noncanonical_batch_block_record_writes: usize,
    noncanonical_batch_durability_flushed: bool,
    durable_records_match_replacement: bool,
    canonical_transaction_block_record_writes: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum NativeCanonicalReorgPersistenceAdmissionRejection {
    KnownCountExceedsReplacement,
    ClassifiedMissingCountMismatch,
    SuppliedMissingCountMismatch,
    ConnectedExactKnownRowsMissing,
    SuffixNotFullyValidated,
    NoncanonicalBatchWriteCountMismatch,
    NoncanonicalBatchNotDurable,
    DurableRecordsMismatchReplacement,
    CanonicalTransactionWritesBlockRecords,
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct NativeActionStreamStep<'a> {
    commitment_count: usize,
    ciphertext_count: usize,
    nullifiers: &'a [[u8; 48]],
    replay_key: Option<[u8; 48]>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct NativeActionStreamEffect {
    next_leaf_count: u64,
    imported_nullifier_count: usize,
    imported_bridge_replay_count: usize,
    planned_starts: Vec<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct NativeActionPlanApplicationSummary {
    next_leaf_count: u64,
    applied_action_count: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum NativeActionPlanApplicationAdmissionRejection {
    PlanLengthMismatch,
    PlannedStartMismatch,
    CommitmentIndexOverflow,
}

impl NativeActionPlanApplicationAdmissionRejection {
    fn label(self) -> &'static str {
        match self {
            Self::PlanLengthMismatch => "plan_length_mismatch",
            Self::PlannedStartMismatch => "planned_start_mismatch",
            Self::CommitmentIndexOverflow => "commitment_index_overflow",
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct NativeActionWireReplayProjectionStep {
    ciphertext_hash_count: usize,
    ciphertext_size_count: usize,
    planned_ciphertext_count: usize,
    ciphertext_hashes_match: bool,
    ciphertext_sizes_match: bool,
    planned_replay_present: bool,
    replay_key_matches: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct NativeActionWireReplayProjectionSummary {
    projected_action_count: usize,
    projected_ciphertext_row_count: usize,
    projected_bridge_replay_row_count: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum NativeActionWireReplayProjectionAdmissionRejection {
    PlanLength,
    CiphertextCount,
    CiphertextHash,
    CiphertextSize,
    ReplayKey,
}

impl NativeActionWireReplayProjectionAdmissionRejection {
    fn label(self) -> &'static str {
        match self {
            Self::PlanLength => "plan_length_mismatch",
            Self::CiphertextCount => "ciphertext_count_mismatch",
            Self::CiphertextHash => "ciphertext_hash_mismatch",
            Self::CiphertextSize => "ciphertext_size_mismatch",
            Self::ReplayKey => "replay_key_mismatch",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum NativeActionStateEffectRejection {
    CiphertextCountMismatch,
    CommitmentIndexOverflow,
    NullifierZero,
    DuplicateNullifier,
    BridgeReplayDuplicate,
}

impl NativeActionStateEffectRejection {
    fn label(self) -> &'static str {
        match self {
            Self::CiphertextCountMismatch => "ciphertext_count_mismatch",
            Self::CommitmentIndexOverflow => "commitment_index_overflow",
            Self::NullifierZero => "nullifier_zero",
            Self::DuplicateNullifier => "duplicate_nullifier",
            Self::BridgeReplayDuplicate => "bridge_replay_duplicate",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct NativeCoinbaseActionPayloadAdmissionInput {
    amount_nonzero: bool,
    commitment_matches: bool,
    commitment_nonzero: bool,
    ciphertext_bytes: usize,
    max_ciphertext_bytes: usize,
    ciphertext_hash_matches: bool,
    ciphertext_size_matches: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum NativeCoinbaseActionPayloadAdmissionRejection {
    AmountZero,
    CommitmentMismatch,
    CommitmentZero,
    CiphertextTooLarge,
    CiphertextHashMismatch,
    CiphertextSizeMismatch,
}

impl NativeCoinbaseActionPayloadAdmissionRejection {
    #[cfg(test)]
    fn label(self) -> &'static str {
        match self {
            Self::AmountZero => "amount_zero",
            Self::CommitmentMismatch => "commitment_mismatch",
            Self::CommitmentZero => "commitment_zero",
            Self::CiphertextTooLarge => "ciphertext_too_large",
            Self::CiphertextHashMismatch => "ciphertext_hash_mismatch",
            Self::CiphertextSizeMismatch => "ciphertext_size_mismatch",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct NativeCandidateArtifactAdmissionInput {
    state_deltas_absent: bool,
    route_payload_decodes_exactly: bool,
    route_payload_matches_artifact: bool,
    artifact_present: bool,
    schema_matches: bool,
    tx_count: u32,
    max_tx_count: u32,
    da_chunk_count: u32,
    proof_mode_recursive_block: bool,
    proof_kind_recursive_block_v2: bool,
    verifier_profile_matches: bool,
    commitment_proof_empty: bool,
    receipt_root_absent: bool,
    recursive_payload_present: bool,
    recursive_proof_bytes: usize,
    max_recursive_proof_bytes: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct NativeCandidateArtifactResourceProjectionInput {
    raw_byte_cap: usize,
    decoded_byte_cap: usize,
    item_count_cap: usize,
    item_byte_cap: usize,
    aggregate_byte_cap: usize,
    work_unit_cap: usize,
    declared_bytes: usize,
    proof_bytes: usize,
    receipt_bytes: usize,
    recursive_bytes: usize,
    tx_count: usize,
    da_chunk_count: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum NativeCandidateArtifactAdmissionRejection {
    StateDeltasPresent,
    RoutePayloadDecodeFailed,
    RoutePayloadArtifactMismatch,
    ArtifactMissing,
    SchemaMismatch,
    TxCountZero,
    TxCountTooLarge,
    DaChunkCountZero,
    WrongProofMode,
    WrongProofKind,
    VerifierProfileMismatch,
    CommitmentProofPresent,
    ReceiptRootPresent,
    RecursivePayloadMissing,
    RecursiveProofEmpty,
    RecursiveProofTooLarge,
}

impl NativeCandidateArtifactAdmissionRejection {
    #[cfg(test)]
    fn label(self) -> &'static str {
        match self {
            Self::StateDeltasPresent => "state_deltas_present",
            Self::RoutePayloadDecodeFailed => "route_payload_decode_failed",
            Self::RoutePayloadArtifactMismatch => "route_payload_artifact_mismatch",
            Self::ArtifactMissing => "artifact_missing",
            Self::SchemaMismatch => "schema_mismatch",
            Self::TxCountZero => "tx_count_zero",
            Self::TxCountTooLarge => "tx_count_too_large",
            Self::DaChunkCountZero => "da_chunk_count_zero",
            Self::WrongProofMode => "wrong_proof_mode",
            Self::WrongProofKind => "wrong_proof_kind",
            Self::VerifierProfileMismatch => "verifier_profile_mismatch",
            Self::CommitmentProofPresent => "commitment_proof_present",
            Self::ReceiptRootPresent => "receipt_root_present",
            Self::RecursivePayloadMissing => "recursive_payload_missing",
            Self::RecursiveProofEmpty => "recursive_proof_empty",
            Self::RecursiveProofTooLarge => "recursive_proof_too_large",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg(test)]
pub(crate) struct NativeCandidateArtifactCouplingAdmissionInput {
    transfer_count: usize,
    candidate_artifact_count: usize,
    candidate_tx_count_matches: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg(test)]
pub(crate) enum NativeCandidateArtifactCouplingAdmissionRejection {
    CandidateWithoutTransfers,
    MissingOrMultipleCandidateArtifact,
    CandidateTxCountMismatch,
}

#[cfg(test)]
impl NativeCandidateArtifactCouplingAdmissionRejection {
    #[cfg(test)]
    fn label(self) -> &'static str {
        match self {
            Self::CandidateWithoutTransfers => "candidate_without_transfers",
            Self::MissingOrMultipleCandidateArtifact => "missing_or_multiple_candidate_artifact",
            Self::CandidateTxCountMismatch => "candidate_tx_count_mismatch",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct NativeMineableActionAdmissionInput {
    candidate_artifact_route: bool,
    candidate_artifact_selected: bool,
    sidecar_transfer_route: bool,
    sidecar_ciphertexts_available: bool,
    sidecar_ciphertext_sizes_present: bool,
    sidecar_ciphertext_sizes_match: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum NativeMineableActionAdmissionRejection {
    RetiredCandidateArtifact,
    SidecarCiphertextMissing,
    SidecarCiphertextSizeMissing,
    SidecarCiphertextSizeMismatch,
}

impl NativeMineableActionAdmissionRejection {
    #[cfg(test)]
    fn label(self) -> &'static str {
        match self {
            Self::RetiredCandidateArtifact => "retired_candidate_artifact",
            Self::SidecarCiphertextMissing => "sidecar_ciphertext_missing",
            Self::SidecarCiphertextSizeMissing => "sidecar_ciphertext_size_missing",
            Self::SidecarCiphertextSizeMismatch => "sidecar_ciphertext_size_mismatch",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct NativeTxLeafActionBindingAdmissionInput {
    nullifiers_match: bool,
    commitments_match: bool,
    ciphertext_hashes_match: bool,
    input_count_matches: bool,
    output_count_matches: bool,
    version_matches: bool,
    merkle_root_matches_anchor: bool,
    fee_matches: bool,
    stablecoin_payload_matches: bool,
    balance_tag_matches: bool,
    receipt_statement_hash_matches: bool,
    public_inputs_digest_matches: bool,
    proof_digest_matches: bool,
    proof_backend_matches: bool,
    ciphertext_payload_hashes_match: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum NativeTxLeafActionBindingAdmissionRejection {
    Nullifiers,
    Commitments,
    CiphertextHashes,
    InputCount,
    OutputCount,
    Version,
    MerkleRootMismatch,
    Fee,
    StablecoinPayload,
    BalanceTag,
    ReceiptStatementHash,
    PublicInputsDigest,
    ProofDigest,
    ProofBackend,
    CiphertextPayloadHash,
}

impl NativeTxLeafActionBindingAdmissionRejection {
    #[cfg(test)]
    fn label(self) -> &'static str {
        match self {
            Self::Nullifiers => "nullifiers_mismatch",
            Self::Commitments => "commitments_mismatch",
            Self::CiphertextHashes => "ciphertext_hashes_mismatch",
            Self::InputCount => "input_count_mismatch",
            Self::OutputCount => "output_count_mismatch",
            Self::Version => "version_mismatch",
            Self::MerkleRootMismatch => "merkle_root_mismatch",
            Self::Fee => "fee_mismatch",
            Self::StablecoinPayload => "stablecoin_payload_mismatch",
            Self::BalanceTag => "balance_tag_mismatch",
            Self::ReceiptStatementHash => "receipt_statement_hash_mismatch",
            Self::PublicInputsDigest => "public_inputs_digest_mismatch",
            Self::ProofDigest => "proof_digest_mismatch",
            Self::ProofBackend => "proof_backend_mismatch",
            Self::CiphertextPayloadHash => "ciphertext_payload_hash_mismatch",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct NativeCandidateArtifactBindingAdmissionInput {
    da_root_matches: bool,
    da_chunk_count_matches: bool,
    tx_statements_commitment_matches: bool,
    recursive_state_root_matches: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum NativeCandidateArtifactBindingAdmissionRejection {
    DaRoot,
    DaChunkCount,
    TxStatementCommitment,
    RecursiveStateRoot,
}

impl NativeCandidateArtifactBindingAdmissionRejection {
    #[cfg(test)]
    fn label(self) -> &'static str {
        match self {
            Self::DaRoot => "da_root_mismatch",
            Self::DaChunkCount => "da_chunk_count_mismatch",
            Self::TxStatementCommitment => "tx_statement_commitment_mismatch",
            Self::RecursiveStateRoot => "recursive_state_root_mismatch",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct NativeCoinbaseAccountingAdmissionInput {
    coinbase_count: usize,
    height: u64,
    transfer_fee_total: Option<u64>,
    observed_coinbase_amount: Option<u64>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum NativeCoinbaseAccountingAdmissionRejection {
    MultipleCoinbase,
    FeeTotalOverflow,
    RewardOverflow,
    CoinbaseAmountMissing,
    AmountMismatch,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct NativeCoinbasePlacementAdmissionInput {
    coinbase_count: usize,
    require_coinbase: bool,
    single_coinbase_is_final: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum NativeCoinbasePlacementAdmissionRejection {
    MissingRequiredCoinbase,
    MultipleCoinbase,
    CoinbaseNotFinal,
}

impl NativeCoinbasePlacementAdmissionRejection {
    fn label(self) -> &'static str {
        match self {
            Self::MissingRequiredCoinbase => "missing_required_coinbase",
            Self::MultipleCoinbase => "multiple_coinbase",
            Self::CoinbaseNotFinal => "coinbase_not_final",
        }
    }
}

impl NativeCoinbaseAccountingAdmissionRejection {
    #[cfg(test)]
    fn label(self) -> &'static str {
        match self {
            Self::MultipleCoinbase => "multiple_coinbase",
            Self::FeeTotalOverflow => "fee_total_overflow",
            Self::RewardOverflow => "reward_overflow",
            Self::CoinbaseAmountMissing => "coinbase_amount_missing",
            Self::AmountMismatch => "amount_mismatch",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct NativeBlockCommitmentAdmissionInput {
    tx_count_matches: bool,
    state_root_matches: bool,
    kernel_root_matches: bool,
    nullifier_root_matches: bool,
    extrinsics_root_matches: bool,
    message_root_matches: bool,
    message_count_matches: bool,
    header_mmr_root_matches: bool,
    header_mmr_len_matches: bool,
    supply_digest_matches: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct NativeDaMetadataAdmissionInput {
    da_root_matches: bool,
    da_chunk_size_matches: bool,
    da_sample_count_matches: bool,
    da_blob_len_matches: bool,
    da_chunk_count_matches: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum NativeDaMetadataAdmissionRejection {
    DaRoot,
    DaChunkSize,
    DaSampleCount,
    DaBlobLen,
    DaChunkCount,
}

impl NativeDaMetadataAdmissionRejection {
    fn label(self) -> &'static str {
        match self {
            Self::DaRoot => "da_root_mismatch",
            Self::DaChunkSize => "da_chunk_size_mismatch",
            Self::DaSampleCount => "da_sample_count_mismatch",
            Self::DaBlobLen => "da_blob_len_mismatch",
            Self::DaChunkCount => "da_chunk_count_mismatch",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct NativeBlockReplayRefinementInput {
    leaf_start: u64,
    parent_supply: u128,
    height: u64,
    fee_total: u64,
    has_coinbase: bool,
    claimed_supply: u128,
    tx_count_matches: bool,
    state_root_matches: bool,
    kernel_root_matches: bool,
    nullifier_root_matches: bool,
    extrinsics_root_matches: bool,
    message_root_matches: bool,
    message_count_matches: bool,
    header_mmr_root_matches: bool,
    header_mmr_len_matches: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct NativeBlockReplayRefinementSummary {
    next_leaf_count: u64,
    imported_nullifier_count: usize,
    imported_bridge_replay_count: usize,
    planned_starts: Vec<u64>,
    expected_supply: u128,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct NativeCanonicalReorgChainAdmissionInput {
    chain_nonempty: bool,
    genesis_matches_expected: bool,
    best_metadata_matches_chain: bool,
    canonical_heights_contiguous: bool,
    canonical_chain_ids_match: bool,
    canonical_rules_hashes_match: bool,
    canonical_hashes_match_work_hashes: bool,
    canonical_parent_hashes_contiguous: bool,
    block_record_count_matches_chain: bool,
    block_records_match_chain: bool,
    height_entry_count_matches_chain: bool,
    height_entries_match_chain: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum NativeCanonicalReorgChainAdmissionRejection {
    ChainEmpty,
    GenesisMismatch,
    BestMetadataMismatch,
    CanonicalHeightMismatch,
    ChainIdMismatch,
    RulesHashMismatch,
    HashWorkHashMismatch,
    ParentHashMismatch,
    BlockRecordCountMismatch,
    BlockRecordMismatch,
    HeightEntryCountMismatch,
    HeightEntryMismatch,
}

impl NativeCanonicalReorgChainAdmissionRejection {
    fn label(self) -> &'static str {
        match self {
            Self::ChainEmpty => "chain_empty",
            Self::GenesisMismatch => "genesis_mismatch",
            Self::BestMetadataMismatch => "best_metadata_mismatch",
            Self::CanonicalHeightMismatch => "canonical_height_mismatch",
            Self::ChainIdMismatch => "chain_id_mismatch",
            Self::RulesHashMismatch => "rules_hash_mismatch",
            Self::HashWorkHashMismatch => "hash_work_hash_mismatch",
            Self::ParentHashMismatch => "parent_hash_mismatch",
            Self::BlockRecordCountMismatch => "block_record_count_mismatch",
            Self::BlockRecordMismatch => "block_record_mismatch",
            Self::HeightEntryCountMismatch => "height_entry_count_mismatch",
            Self::HeightEntryMismatch => "height_entry_mismatch",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum NativeBlockCommitmentAdmissionRejection {
    TxCount,
    StateRoot,
    KernelRoot,
    NullifierRoot,
    ExtrinsicsRoot,
    MessageRoot,
    MessageCount,
    HeaderMmrRoot,
    HeaderMmrLen,
    SupplyDigest,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum NativeAtomicCommitKind {
    MinedBlockCommit,
    TipExtensionBatchCommit,
    CanonicalReorgCommit,
    CanonicalSuffixReorgCommit,
    CanonicalIndexRepair,
    NoncanonicalBlockRecord,
}

/// Admission summary for shared canonical rows and the historical 48-byte
/// commitment/nullifier/DA indexes only.
///
/// This is deliberately not an exhaustive manifest of every sled mutation:
/// the separate Poseidon2 V8 tree is authorized by a source-verified immutable
/// `Poseidon2V8CanonicalPlan`, applied in the same tuple transaction, and
/// checked by its own compare-and-swap/readback contract. Do not add V8 rows to
/// these legacy counts or cite this summary as V8-plan authority.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct NativeAtomicCommitManifestAdmissionInput {
    kind: NativeAtomicCommitKind,
    action_count: usize,
    planned_action_count: usize,
    chain_block_count: usize,
    height_entry_count: usize,
    pending_entry_count: usize,
    source_commitment_count: usize,
    source_nullifier_count: usize,
    source_bridge_replay_count: usize,
    source_ciphertext_index_count: usize,
    source_ciphertext_archive_count: usize,
    source_staged_ciphertext_removal_count: usize,
    source_poseidon2_v8_plan_count: usize,
    block_record_writes: usize,
    height_index_writes: usize,
    best_pointer_writes: usize,
    canonical_index_cleared: bool,
    pending_tree_cleared: bool,
    pending_action_removals: usize,
    pending_action_writes: usize,
    commitment_writes: usize,
    nullifier_writes: usize,
    bridge_replay_writes: usize,
    ciphertext_index_writes: usize,
    ciphertext_archive_writes: usize,
    staged_ciphertext_removals: usize,
    poseidon2_v8_plan_application_count: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum NativeAtomicCommitManifestAdmissionRejection {
    MinedPlanLength,
    BlockRecordWrites,
    HeightIndexWrites,
    BestPointerWrites,
    CanonicalIndexClear,
    PendingTreeClear,
    PendingActionRemoval,
    PendingActionWrite,
    CommitmentWrite,
    NullifierWrite,
    BridgeReplayWrite,
    CiphertextIndexWrite,
    CiphertextArchiveWrite,
    StagedCiphertextRemoval,
    Poseidon2V8PlanCardinality,
    Poseidon2V8PlanApplication,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum NativeStorageDurabilityOperation {
    MinedBlockCommit,
    CanonicalReorgCommit,
    CanonicalIndexRepair,
    NoncanonicalBlockRecord,
    PendingActionStage,
    CiphertextSidecarStage,
    ProofSidecarStage,
    GenesisBootstrap,
    GenesisMarkerRepair,
    StartupStagedCiphertextRepair,
    StartupStagedProofRepair,
    StartupPendingActionRepair,
    ShutdownFlush,
}

impl NativeStorageDurabilityOperation {
    fn label(self) -> &'static str {
        match self {
            Self::MinedBlockCommit => "mined_block_commit",
            Self::CanonicalReorgCommit => "canonical_reorg_commit",
            Self::CanonicalIndexRepair => "canonical_index_repair",
            Self::NoncanonicalBlockRecord => "noncanonical_block_record",
            Self::PendingActionStage => "pending_action_stage",
            Self::CiphertextSidecarStage => "ciphertext_sidecar_stage",
            Self::ProofSidecarStage => "proof_sidecar_stage",
            Self::GenesisBootstrap => "genesis_bootstrap",
            Self::GenesisMarkerRepair => "genesis_marker_repair",
            Self::StartupStagedCiphertextRepair => "startup_staged_ciphertext_repair",
            Self::StartupStagedProofRepair => "startup_staged_proof_repair",
            Self::StartupPendingActionRepair => "startup_pending_action_repair",
            Self::ShutdownFlush => "shutdown_flush",
        }
    }

    #[cfg(test)]
    fn from_label(label: &str) -> Option<Self> {
        match label {
            "mined_block_commit" => Some(Self::MinedBlockCommit),
            "canonical_reorg_commit" => Some(Self::CanonicalReorgCommit),
            "canonical_index_repair" => Some(Self::CanonicalIndexRepair),
            "noncanonical_block_record" => Some(Self::NoncanonicalBlockRecord),
            "pending_action_stage" => Some(Self::PendingActionStage),
            "ciphertext_sidecar_stage" => Some(Self::CiphertextSidecarStage),
            "proof_sidecar_stage" => Some(Self::ProofSidecarStage),
            "genesis_bootstrap" => Some(Self::GenesisBootstrap),
            "genesis_marker_repair" => Some(Self::GenesisMarkerRepair),
            "startup_staged_ciphertext_repair" => Some(Self::StartupStagedCiphertextRepair),
            "startup_staged_proof_repair" => Some(Self::StartupStagedProofRepair),
            "startup_pending_action_repair" => Some(Self::StartupPendingActionRepair),
            "shutdown_flush" => Some(Self::ShutdownFlush),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct NativeStorageDurabilityAdmissionInput {
    operation_supported: bool,
    transaction_accepted: bool,
    durability_flushed: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum NativeStorageDurabilityAdmissionRejection {
    UnsupportedOperation,
    TransactionRejected,
    DurabilityFlushFailed,
}

impl NativeStorageDurabilityAdmissionRejection {
    fn label(self) -> &'static str {
        match self {
            Self::UnsupportedOperation => "unsupported_operation",
            Self::TransactionRejected => "transaction_rejected",
            Self::DurabilityFlushFailed => "durability_flush_failed",
        }
    }
}

impl NativeAtomicCommitManifestAdmissionRejection {
    fn label(self) -> &'static str {
        match self {
            Self::MinedPlanLength => "mined_plan_length_mismatch",
            Self::BlockRecordWrites => "block_record_writes_mismatch",
            Self::HeightIndexWrites => "height_index_writes_mismatch",
            Self::BestPointerWrites => "best_pointer_writes_mismatch",
            Self::CanonicalIndexClear => "canonical_index_clear_mismatch",
            Self::PendingTreeClear => "pending_tree_clear_mismatch",
            Self::PendingActionRemoval => "pending_action_removal_mismatch",
            Self::PendingActionWrite => "pending_action_write_mismatch",
            Self::CommitmentWrite => "commitment_write_mismatch",
            Self::NullifierWrite => "nullifier_write_mismatch",
            Self::BridgeReplayWrite => "bridge_replay_write_mismatch",
            Self::CiphertextIndexWrite => "ciphertext_index_write_mismatch",
            Self::CiphertextArchiveWrite => "ciphertext_archive_write_mismatch",
            Self::StagedCiphertextRemoval => "staged_ciphertext_removal_mismatch",
            Self::Poseidon2V8PlanCardinality => "poseidon2_v8_plan_cardinality",
            Self::Poseidon2V8PlanApplication => "poseidon2_v8_plan_application_mismatch",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum NativeBlockReplayRefinementRejection {
    CiphertextCountMismatch,
    CommitmentIndexOverflow,
    NullifierZero,
    DuplicateNullifier,
    BridgeReplayDuplicate,
    SupplyDeltaInvalid,
    TxCountMismatch,
    StateRootMismatch,
    KernelRootMismatch,
    NullifierRootMismatch,
    ExtrinsicsRootMismatch,
    MessageRootMismatch,
    MessageCountMismatch,
    HeaderMmrRootMismatch,
    HeaderMmrLenMismatch,
    SupplyDigestMismatch,
}

impl NativeBlockReplayRefinementRejection {
    fn label(self) -> &'static str {
        match self {
            Self::CiphertextCountMismatch => "ciphertext_count_mismatch",
            Self::CommitmentIndexOverflow => "commitment_index_overflow",
            Self::NullifierZero => "nullifier_zero",
            Self::DuplicateNullifier => "duplicate_nullifier",
            Self::BridgeReplayDuplicate => "bridge_replay_duplicate",
            Self::SupplyDeltaInvalid => "supply_delta_invalid",
            Self::TxCountMismatch => "tx_count_mismatch",
            Self::StateRootMismatch => "state_root_mismatch",
            Self::KernelRootMismatch => "kernel_root_mismatch",
            Self::NullifierRootMismatch => "nullifier_root_mismatch",
            Self::ExtrinsicsRootMismatch => "extrinsics_root_mismatch",
            Self::MessageRootMismatch => "message_root_mismatch",
            Self::MessageCountMismatch => "message_count_mismatch",
            Self::HeaderMmrRootMismatch => "header_mmr_root_mismatch",
            Self::HeaderMmrLenMismatch => "header_mmr_len_mismatch",
            Self::SupplyDigestMismatch => "supply_digest_mismatch",
        }
    }
}

impl NativeBlockCommitmentAdmissionRejection {
    fn label(self) -> &'static str {
        match self {
            Self::TxCount => "tx_count_mismatch",
            Self::StateRoot => "state_root_mismatch",
            Self::KernelRoot => "kernel_root_mismatch",
            Self::NullifierRoot => "nullifier_root_mismatch",
            Self::ExtrinsicsRoot => "extrinsics_root_mismatch",
            Self::MessageRoot => "message_root_mismatch",
            Self::MessageCount => "message_count_mismatch",
            Self::HeaderMmrRoot => "header_mmr_root_mismatch",
            Self::HeaderMmrLen => "header_mmr_len_mismatch",
            Self::SupplyDigest => "supply_digest_mismatch",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct NativeMempoolByteBudgetAdmissionInput {
    pending_bytes: usize,
    candidate_bytes: usize,
    max_bytes: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct NativeStagedProofByteBudgetAdmissionInput {
    staged_bytes: usize,
    existing_bytes: usize,
    proof_bytes: usize,
    max_bytes: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum NativeResourceBudgetAdmissionRejection {
    MempoolByteBudgetExceeded,
    StagedProofByteBudgetExceeded,
}

impl NativeResourceBudgetAdmissionRejection {
    #[cfg(test)]
    fn label(self) -> &'static str {
        match self {
            Self::MempoolByteBudgetExceeded => "mempool_byte_budget_exceeded",
            Self::StagedProofByteBudgetExceeded => "staged_proof_byte_budget_exceeded",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct NativeBoundedRequestAdmissionInput {
    raw_byte_cap: usize,
    decoded_byte_cap: usize,
    item_count_cap: usize,
    item_byte_cap: usize,
    aggregate_byte_cap: usize,
    work_unit_cap: usize,
    raw_bytes: usize,
    decoded_bytes: usize,
    item_count: usize,
    max_item_bytes: usize,
    aggregate_bytes: usize,
    work_units: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum NativeBoundedRequestAdmissionRejection {
    RawBytes,
    DecodedBytes,
    ItemCount,
    ItemBytes,
    AggregateBytes,
    WorkUnits,
}

impl NativeBoundedRequestAdmissionRejection {
    #[cfg(test)]
    fn label(self) -> &'static str {
        match self {
            Self::RawBytes => "raw_bytes_exceeded",
            Self::DecodedBytes => "decoded_bytes_exceeded",
            Self::ItemCount => "item_count_exceeded",
            Self::ItemBytes => "item_bytes_exceeded",
            Self::AggregateBytes => "aggregate_bytes_exceeded",
            Self::WorkUnits => "work_units_exceeded",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum NativeSyncBlockRangePublicationAdmissionRejection {
    RangeNotAdmitted,
    ServedCountMismatch,
    FirstHeightMismatch,
    LastHeightMismatch,
    HeightContinuityMismatch,
    ParentHashMismatch,
    CanonicalRowsUnverified,
    ActionBodiesUnverified,
}

impl NativeSyncBlockRangePublicationAdmissionRejection {
    fn label(self) -> &'static str {
        match self {
            Self::RangeNotAdmitted => "range_not_admitted",
            Self::ServedCountMismatch => "served_count_mismatch",
            Self::FirstHeightMismatch => "first_height_mismatch",
            Self::LastHeightMismatch => "last_height_mismatch",
            Self::HeightContinuityMismatch => "height_continuity_mismatch",
            Self::ParentHashMismatch => "parent_hash_mismatch",
            Self::CanonicalRowsUnverified => "canonical_rows_unverified",
            Self::ActionBodiesUnverified => "action_bodies_unverified",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct NativeSidecarRequestCountAdmissionInput {
    item_count: usize,
    max_items: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct NativeSidecarCapacityAdmissionInput {
    staged_count: usize,
    max_staged_count: usize,
    replaces_existing: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct NativeProofSidecarMetadataAdmissionInput {
    binding_hash_present: bool,
    binding_hash_valid: bool,
    proof_present: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct NativeProofSidecarDecodedAdmissionInput {
    proof_bytes: usize,
    max_proof_bytes: usize,
    proof_binding_hash_matches_key: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum NativeSidecarUploadAdmissionRejection {
    TooManyCiphertexts,
    TooManyProofs,
    StagedCiphertextCapacityReached,
    StagedProofCapacityReached,
    ProofBindingHashMissing,
    InvalidBindingHash,
    ProofMissing,
    ProofEmpty,
    ProofTooLarge,
    ProofBindingHashMismatch,
}

impl NativeSidecarUploadAdmissionRejection {
    #[cfg(test)]
    fn label(self) -> &'static str {
        match self {
            Self::TooManyCiphertexts => "too_many_ciphertexts",
            Self::TooManyProofs => "too_many_proofs",
            Self::StagedCiphertextCapacityReached => "staged_ciphertext_capacity_reached",
            Self::StagedProofCapacityReached => "staged_proof_capacity_reached",
            Self::ProofBindingHashMissing => "proof_binding_hash_missing",
            Self::InvalidBindingHash => "invalid_binding_hash",
            Self::ProofMissing => "proof_missing",
            Self::ProofEmpty => "proof_empty",
            Self::ProofTooLarge => "proof_too_large",
            Self::ProofBindingHashMismatch => "proof_binding_hash_mismatch",
        }
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SubmitActionRpcRequest {
    binding_circuit: u16,
    binding_crypto: u16,
    family_id: u16,
    action_id: u16,
    #[serde(default)]
    object_refs: Vec<SubmitActionObjectRef>,
    #[serde(default)]
    new_nullifiers: Vec<String>,
    public_args: String,
    #[serde(default)]
    authorization_proof: Option<String>,
    #[serde(default)]
    authorization_signatures: Vec<SubmitActionSignature>,
    #[serde(default)]
    aux_data: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(dead_code)]
pub(crate) struct SubmitActionObjectRef {
    family_id: u16,
    object_id: String,
    expected_root: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(dead_code)]
pub(crate) struct SubmitActionSignature {
    key_id: String,
    signature_scheme: u16,
    signature_bytes: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SubmitCiphertextsRpcRequest {
    #[serde(default)]
    ciphertexts: Option<Vec<Value>>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SubmitProofsRpcRequest {
    #[serde(default)]
    proofs: Option<Vec<SubmitProofsRpcItem>>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SubmitProofsRpcItem {
    #[serde(default)]
    binding_hash: Option<String>,
    #[serde(default)]
    proof: Option<Value>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum NativeActionRequestProjectionAdmissionRejection {
    JsonDecodeRejected,
    KernelEnvelopeFieldsPresent,
    UnsupportedRoute,
    NonTransferNullifiers,
    TooManyNullifiers,
    InvalidNullifierHex,
    PublicArgsTooLarge,
    PublicArgsBase64Rejected,
    DecodedPublicArgsTooLarge,
    RoutePayloadDecodeNotExact,
}

#[cfg(test)]
impl NativeActionRequestProjectionAdmissionRejection {
    fn label(self) -> &'static str {
        match self {
            Self::JsonDecodeRejected => "json_decode_rejected",
            Self::KernelEnvelopeFieldsPresent => "kernel_envelope_fields_present",
            Self::UnsupportedRoute => "unsupported_route",
            Self::NonTransferNullifiers => "non_transfer_nullifiers",
            Self::TooManyNullifiers => "too_many_nullifiers",
            Self::InvalidNullifierHex => "invalid_nullifier_hex",
            Self::PublicArgsTooLarge => "public_args_too_large",
            Self::PublicArgsBase64Rejected => "public_args_base64_rejected",
            Self::DecodedPublicArgsTooLarge => "decoded_public_args_too_large",
            Self::RoutePayloadDecodeNotExact => "route_payload_decode_not_exact",
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct NativeActionRequestProjectionAdmissionInput {
    json_decode_accepts: bool,
    kernel_envelope_fields_absent: bool,
    route_supported: bool,
    nullifier_scope_valid: bool,
    nullifier_count_within_limit: bool,
    nullifier_hex_valid: bool,
    public_args_encoded_within_limit: bool,
    public_args_base64_decodes: bool,
    public_args_decoded_within_limit: bool,
    route_payload_decodes_exactly: bool,
}

pub(crate) fn evaluate_native_action_request_projection_admission(
    input: NativeActionRequestProjectionAdmissionInput,
) -> std::result::Result<(), NativeActionRequestProjectionAdmissionRejection> {
    if !input.json_decode_accepts {
        Err(NativeActionRequestProjectionAdmissionRejection::JsonDecodeRejected)
    } else if !input.kernel_envelope_fields_absent {
        Err(NativeActionRequestProjectionAdmissionRejection::KernelEnvelopeFieldsPresent)
    } else if !input.route_supported {
        Err(NativeActionRequestProjectionAdmissionRejection::UnsupportedRoute)
    } else if !input.nullifier_scope_valid {
        Err(NativeActionRequestProjectionAdmissionRejection::NonTransferNullifiers)
    } else if !input.nullifier_count_within_limit {
        Err(NativeActionRequestProjectionAdmissionRejection::TooManyNullifiers)
    } else if !input.nullifier_hex_valid {
        Err(NativeActionRequestProjectionAdmissionRejection::InvalidNullifierHex)
    } else if !input.public_args_encoded_within_limit {
        Err(NativeActionRequestProjectionAdmissionRejection::PublicArgsTooLarge)
    } else if !input.public_args_base64_decodes {
        Err(NativeActionRequestProjectionAdmissionRejection::PublicArgsBase64Rejected)
    } else if !input.public_args_decoded_within_limit {
        Err(NativeActionRequestProjectionAdmissionRejection::DecodedPublicArgsTooLarge)
    } else if !input.route_payload_decodes_exactly {
        Err(NativeActionRequestProjectionAdmissionRejection::RoutePayloadDecodeNotExact)
    } else {
        Ok(())
    }
}

pub(crate) fn native_action_request_projection_error(
    rejection: NativeActionRequestProjectionAdmissionRejection,
) -> anyhow::Error {
    match rejection {
        NativeActionRequestProjectionAdmissionRejection::JsonDecodeRejected => {
            anyhow!("native action request JSON decode rejected")
        }
        NativeActionRequestProjectionAdmissionRejection::KernelEnvelopeFieldsPresent => anyhow!(
            "native action request contains non-empty kernel envelope fields not implemented by native consensus"
        ),
        NativeActionRequestProjectionAdmissionRejection::UnsupportedRoute => {
            anyhow!("unsupported native action route")
        }
        NativeActionRequestProjectionAdmissionRejection::NonTransferNullifiers => {
            anyhow!("new_nullifiers must be empty for non-transfer actions")
        }
        NativeActionRequestProjectionAdmissionRejection::TooManyNullifiers => anyhow!(
            "new_nullifiers length exceeds MAX_INPUTS {}",
            transaction_core::constants::MAX_INPUTS
        ),
        NativeActionRequestProjectionAdmissionRejection::InvalidNullifierHex => {
            anyhow!("invalid nullifier hex")
        }
        NativeActionRequestProjectionAdmissionRejection::PublicArgsTooLarge => anyhow!(
            "public_args exceeds native action limit of {MAX_NATIVE_RPC_ACTION_BYTES} bytes"
        ),
        NativeActionRequestProjectionAdmissionRejection::PublicArgsBase64Rejected => {
            anyhow!("decode public_args failed")
        }
        NativeActionRequestProjectionAdmissionRejection::DecodedPublicArgsTooLarge => anyhow!(
            "decoded public_args exceeds native action limit of {MAX_NATIVE_RPC_ACTION_BYTES} bytes"
        ),
        NativeActionRequestProjectionAdmissionRejection::RoutePayloadDecodeNotExact => anyhow!(
            "native action request route payload decode not exact: trailing bytes or non-canonical payload"
        ),
    }
}

pub(crate) fn decode_submit_action_rpc_request(request: Value) -> Result<SubmitActionRpcRequest> {
    serde_json::from_value(request).context("decode submit action request")
}

pub(crate) fn decode_submit_ciphertexts_rpc_request(
    request: Value,
) -> Result<SubmitCiphertextsRpcRequest> {
    serde_json::from_value(request).context("decode da ciphertext upload request")
}

pub(crate) fn decode_submit_proofs_rpc_request(request: Value) -> Result<SubmitProofsRpcRequest> {
    serde_json::from_value(request).context("decode da proof upload request")
}

pub(crate) fn native_submit_action_is_transfer_route(family_id: u16, action_id: u16) -> bool {
    family_id == FAMILY_SHIELDED_POOL
        && matches!(
            action_id,
            ACTION_SHIELDED_TRANSFER_INLINE
                | ACTION_SHIELDED_TRANSFER_SIDECAR
                | ACTION_SMALLWOOD_POSEIDON2_PRODUCTION_INLINE
        )
}

/// Only the historical 48-byte transfer grammars carry nullifiers in the
/// outer RPC envelope. V8 nullifiers are seven canonical field limbs and are
/// derived exclusively from the exact HGV8 public statement.
pub(crate) fn native_submit_action_uses_outer_nullifiers(family_id: u16, action_id: u16) -> bool {
    family_id == FAMILY_SHIELDED_POOL
        && matches!(
            action_id,
            ACTION_SHIELDED_TRANSFER_INLINE | ACTION_SHIELDED_TRANSFER_SIDECAR
        )
}

pub(crate) fn native_submit_action_route_supported(family_id: u16, action_id: u16) -> bool {
    matches!(
        (family_id, action_id),
        (FAMILY_BRIDGE, ACTION_BRIDGE_OUTBOUND)
            | (FAMILY_BRIDGE, ACTION_BRIDGE_INBOUND)
            | (FAMILY_BRIDGE, ACTION_REGISTER_BRIDGE_VERIFIER)
            | (FAMILY_SHIELDED_POOL, ACTION_SHIELDED_TRANSFER_INLINE)
            | (FAMILY_SHIELDED_POOL, ACTION_SHIELDED_TRANSFER_SIDECAR)
            | (FAMILY_SHIELDED_POOL, SMALLWOOD_V5_TRANSPORT_ACTION_ID)
            | (
                FAMILY_SHIELDED_POOL,
                ACTION_SMALLWOOD_POSEIDON2_PRODUCTION_INLINE
            )
            | (FAMILY_SHIELDED_POOL, ACTION_SUBMIT_CANDIDATE_ARTIFACT)
            | (FAMILY_SHIELDED_POOL, ACTION_MINT_COINBASE)
    )
}

pub(crate) fn native_action_request_kernel_fields_absent(request: &SubmitActionRpcRequest) -> bool {
    request.object_refs.is_empty()
        && request.authorization_proof.is_none()
        && request.authorization_signatures.is_empty()
        && request.aux_data.is_none()
}

pub(crate) fn native_action_request_nullifiers_decode(
    request: &SubmitActionRpcRequest,
    transfer_route: bool,
) -> bool {
    !transfer_route
        || request
            .new_nullifiers
            .iter()
            .all(|raw| parse_hex48(raw).is_some())
}

pub(crate) fn native_action_request_route_payload_decodes_exactly(
    request: &SubmitActionRpcRequest,
    public_args: &[u8],
) -> bool {
    match (request.family_id, request.action_id) {
        (FAMILY_BRIDGE, ACTION_BRIDGE_OUTBOUND) => decode_scale_exact::<OutboundBridgeArgsV1>(
            public_args,
            "native outbound bridge action request args",
        )
        .is_ok(),
        (FAMILY_BRIDGE, ACTION_BRIDGE_INBOUND) => decode_scale_exact::<InboundBridgeArgsV1>(
            public_args,
            "native inbound bridge action request args",
        )
        .is_ok(),
        (FAMILY_BRIDGE, ACTION_REGISTER_BRIDGE_VERIFIER) => {
            decode_scale_exact::<BridgeVerifierRegistrationV1>(
                public_args,
                "native bridge verifier registration request args",
            )
            .is_ok()
        }
        (FAMILY_SHIELDED_POOL, ACTION_SHIELDED_TRANSFER_INLINE) => {
            decode_scale_exact::<ShieldedTransferInlineArgs>(
                public_args,
                "native shielded inline action request args",
            )
            .is_ok()
        }
        (FAMILY_SHIELDED_POOL, ACTION_SHIELDED_TRANSFER_SIDECAR) => {
            decode_scale_exact::<ShieldedTransferSidecarArgs>(
                public_args,
                "native shielded sidecar action request args",
            )
            .is_ok()
        }
        (FAMILY_SHIELDED_POOL, SMALLWOOD_V5_TRANSPORT_ACTION_ID) => {
            decode_smallwood_v5_inline_args_exact(public_args)
                .is_ok_and(|args| decode_envelope_exact(&args.envelope).is_ok())
        }
        (FAMILY_SHIELDED_POOL, ACTION_SMALLWOOD_POSEIDON2_PRODUCTION_INLINE) => {
            // Shape-only syntax preflight is safe while the fixed route gate
            // remains closed. It is never verification authority: an enabled
            // route must use contextual decode with the source-owned network
            // id and V8 relation digest before proof verification.
            preflight_poseidon2_production_smz9_inline_args_exact(public_args).is_ok()
        }
        (FAMILY_SHIELDED_POOL, ACTION_SUBMIT_CANDIDATE_ARTIFACT) => {
            decode_scale_exact::<SubmitCandidateArtifactArgs>(
                public_args,
                "native candidate artifact action request args",
            )
            .is_ok()
        }
        (FAMILY_SHIELDED_POOL, ACTION_MINT_COINBASE) => decode_scale_exact::<MintCoinbaseArgs>(
            public_args,
            "native coinbase action request args",
        )
        .is_ok(),
        _ => false,
    }
}

/// Route-specific decoded public-argument ceiling used before base64 decode.
///
/// The compact Poseidon2 route must never inherit the generic two-MiB action
/// budget. Keeping this projection live while authority is false prevents a
/// later activation from accidentally moving the allocation boundary.
pub(crate) const fn native_action_request_public_args_cap(family_id: u16, action_id: u16) -> usize {
    if family_id == FAMILY_SHIELDED_POOL
        && action_id == ACTION_SMALLWOOD_POSEIDON2_PRODUCTION_INLINE
    {
        transaction_circuit::smallwood_poseidon2_v8_security::SMALLWOOD_POSEIDON2_V8_MAX_ACTION_BYTES
            as usize
    } else if family_id == FAMILY_SHIELDED_POOL && action_id == ACTION_MINT_POSEIDON2_V8_COINBASE {
        POSEIDON2_V8_COINBASE_ARGS_SCALE_BYTES
    } else {
        MAX_NATIVE_RPC_ACTION_BYTES
    }
}

pub(crate) fn evaluate_native_action_request_projection(
    request: &SubmitActionRpcRequest,
) -> std::result::Result<Vec<u8>, NativeActionRequestProjectionAdmissionRejection> {
    let outer_nullifier_route =
        native_submit_action_uses_outer_nullifiers(request.family_id, request.action_id);
    let route_supported =
        native_submit_action_route_supported(request.family_id, request.action_id);
    let public_args_cap =
        native_action_request_public_args_cap(request.family_id, request.action_id);
    let public_args_encoded_within_limit =
        request.public_args.len() <= encoded_len_limit(public_args_cap);
    let decoded_public_args = if public_args_encoded_within_limit {
        decode_base64(&request.public_args).ok()
    } else {
        None
    };
    let public_args_base64_decodes = decoded_public_args.is_some();
    let public_args_decoded_within_limit = decoded_public_args
        .as_ref()
        .map(|public_args| public_args.len() <= public_args_cap)
        .unwrap_or(false);
    let route_payload_decodes_exactly = if route_supported && public_args_decoded_within_limit {
        decoded_public_args
            .as_ref()
            .map(|public_args| {
                native_action_request_route_payload_decodes_exactly(request, public_args)
            })
            .unwrap_or(false)
    } else {
        false
    };

    let input = NativeActionRequestProjectionAdmissionInput {
        json_decode_accepts: true,
        kernel_envelope_fields_absent: native_action_request_kernel_fields_absent(request),
        route_supported,
        nullifier_scope_valid: outer_nullifier_route || request.new_nullifiers.is_empty(),
        nullifier_count_within_limit: request.new_nullifiers.len()
            <= transaction_core::constants::MAX_INPUTS,
        nullifier_hex_valid: native_action_request_nullifiers_decode(
            request,
            outer_nullifier_route,
        ),
        public_args_encoded_within_limit,
        public_args_base64_decodes,
        public_args_decoded_within_limit,
        route_payload_decodes_exactly,
    };
    evaluate_native_action_request_projection_admission(input)?;
    decoded_public_args
        .ok_or(NativeActionRequestProjectionAdmissionRejection::PublicArgsBase64Rejected)
}

pub(crate) fn admit_native_action_request_projection(
    request: &SubmitActionRpcRequest,
) -> Result<Vec<u8>> {
    evaluate_native_action_request_projection(request)
        .map_err(native_action_request_projection_error)
}

#[derive(Clone, Copy, Debug, Deserialize)]
pub(crate) struct NativePagination {
    #[serde(default)]
    start: u64,
    #[serde(default = "default_native_wallet_page_limit")]
    limit: u64,
}

#[derive(Clone, Debug)]
pub(crate) struct NativeState {
    best: NativeBlockMeta,
    header_mmr_peaks: Vec<Hash32>,
    pending_actions: BTreeMap<ActionId48, PendingAction>,
    /// Domain-separated semantic action identity to its canonical action id.
    /// Active V3 has no arrival-time field, so both identities cover the same
    /// canonical body while remaining distinct types/domains. Admission uses
    /// this index so a full
    /// mempool does not require re-encoding and hashing every proof twice for
    /// each new action.
    pending_action_semantic_index: BTreeMap<ActionSemanticId48, ActionId48>,
    /// Canonical mining-order key and transaction hash for every pending
    /// action. Iterating this set yields the exact deterministic template
    /// order without re-decoding large transfer payloads inside a sort.
    pending_action_order_index: BTreeSet<([u8; 32], ActionId48)>,
    /// Exact union of nullifiers carried by pending actions.  Canonical spent
    /// nullifiers remain in `nullifiers`; keeping the pending half indexed
    /// avoids cloning/scanning the whole mempool for every admission.
    pending_nullifiers: BTreeSet<[u8; 48]>,
    /// Exact replay-key set for pending inbound bridge actions. The persistent
    /// trie makes per-admission snapshots O(1) while preserving exact-key
    /// membership (no probabilistic filter or hash-collision assumption).
    pending_bridge_replay_keys: PersistentKeySet48,
    /// Exact canonical SCALE byte total for `pending_actions`.
    pending_mempool_bytes: usize,
    commitment_tree: CommitmentTreeState,
    nullifiers: PersistentKeySet48,
    nullifier_accumulator: NullifierAccumulator,
    consumed_bridge_messages: PersistentKeySet48,
    stablecoin_policy_authorizations: BTreeSet<Vec<u8>>,
    staged_ciphertexts: BTreeMap<String, u32>,
    staged_proofs: BTreeMap<String, Vec<u8>>,
}

/// Compact, block-bound canonical state needed to start fork replay at a
/// common ancestor without rebuilding the shared prefix. Exact nullifier and
/// bridge membership are obtained by removing the bounded orphan suffix from
/// the structurally shared live sets; the Merkle/MMR append frontiers cannot
/// be reversed and are therefore checkpointed explicitly.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub(crate) struct NativeCanonicalStateCheckpointV1 {
    schema_version: u16,
    rules_hash: [u8; 32],
    height: u64,
    block_hash: [u8; 32],
    block_body_digest: [u8; 32],
    commitment_depth: u32,
    commitment_history_limit: u32,
    commitment_leaf_count: u64,
    commitment_root: [u8; 48],
    commitment_frontier: Vec<[u8; 48]>,
    commitment_root_history: Vec<[u8; 48]>,
    nullifier_accumulator: Vec<u8>,
    header_mmr_peaks: Vec<[u8; 32]>,
    checkpoint_digest: [u8; 32],
}

pub(crate) type NativeCanonicalCheckpointRows = (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>);

pub(crate) struct NativeVerifiedSuffixReplay {
    pub(crate) state: NativeState,
    pub(crate) checkpoint_rows: Vec<NativeCanonicalCheckpointRows>,
}

#[derive(Debug, Default)]
pub(crate) struct NativeVerifiedBlockCache {
    entries: BTreeMap<[u8; 32], [u8; 48]>,
    order: VecDeque<[u8; 32]>,
}

#[derive(Debug, Default)]
pub(crate) struct NativeCanonicalCheckpointCache {
    entries: BTreeMap<[u8; 32], NativeCanonicalStateCheckpointV1>,
    order: VecDeque<[u8; 32]>,
}

#[derive(Clone, Debug, Default)]
pub(crate) struct RejectedPendingActionCache {
    entries: BTreeMap<NativePendingRejectionKey, Instant>,
    order: VecDeque<(NativePendingRejectionKey, Instant)>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct NativePendingRejectionKey {
    parent_hash: [u8; 32],
    semantic_id: ActionSemanticId48,
}

#[derive(Debug, Default)]
pub(crate) struct NativeDaEncodingCache {
    entries: BTreeMap<[u8; 32], Arc<state_da::DaEncoding>>,
    order: VecDeque<[u8; 32]>,
}

#[derive(Clone, Debug)]
pub(crate) struct NativeWorkTemplateCacheEntry {
    work: NativeWork,
    built_at: Instant,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum NativePendingActionStageDisposition {
    Inserted,
    Duplicate,
    TipChanged,
}

pub(crate) struct NativePendingActionCommitCompletion {
    result: Mutex<Option<std::result::Result<NativePendingActionStageDisposition, String>>>,
}

impl NativePendingActionCommitCompletion {
    fn new() -> Self {
        Self {
            result: Mutex::new(None),
        }
    }
}

pub(crate) struct NativePendingActionCommitRequest {
    pending: PendingAction,
    pending_encoded: Vec<u8>,
    pending_semantic_hash: ActionSemanticId48,
    verified_tip: Option<(u64, [u8; 32])>,
    consumed_staged_proof: Option<([u8; 64], Vec<u8>)>,
    ignore_duplicate: bool,
    #[cfg(test)]
    bypass_active_route_for_group_engine_test: bool,
    completion: Arc<NativePendingActionCommitCompletion>,
}

#[derive(Default)]
pub(crate) struct NativePendingActionGroupCommitState {
    active: bool,
    queued_bytes: usize,
    queue: VecDeque<NativePendingActionCommitRequest>,
}

pub(crate) struct NativePendingActionGroupCommit {
    state: Mutex<NativePendingActionGroupCommitState>,
    wake: Condvar,
}

impl Default for NativePendingActionGroupCommit {
    fn default() -> Self {
        Self {
            state: Mutex::new(NativePendingActionGroupCommitState::default()),
            wake: Condvar::new(),
        }
    }
}

#[cfg(test)]
pub(crate) struct NativePendingActionGroupCommitTestControl {
    hold_before_drain: AtomicBool,
    before_drain_entered: AtomicBool,
    hold_before_flush: AtomicBool,
    before_flush_entered: AtomicBool,
    fail_next_transaction: AtomicBool,
    fail_next_flush: AtomicBool,
    panic_after_drain: AtomicBool,
    flush_invocations: AtomicU64,
    wait_lock: Mutex<()>,
    wake: Condvar,
}

#[cfg(test)]
impl Default for NativePendingActionGroupCommitTestControl {
    fn default() -> Self {
        Self {
            hold_before_drain: AtomicBool::new(false),
            before_drain_entered: AtomicBool::new(false),
            hold_before_flush: AtomicBool::new(false),
            before_flush_entered: AtomicBool::new(false),
            fail_next_transaction: AtomicBool::new(false),
            fail_next_flush: AtomicBool::new(false),
            panic_after_drain: AtomicBool::new(false),
            flush_invocations: AtomicU64::new(0),
            wait_lock: Mutex::new(()),
            wake: Condvar::new(),
        }
    }
}

pub struct NativeNode {
    config: NativeConfig,
    db: sled::Db,
    meta_tree: sled::Tree,
    height_tree: sled::Tree,
    block_tree: sled::Tree,
    action_tree: sled::Tree,
    nullifier_tree: sled::Tree,
    commitment_tree: sled::Tree,
    bridge_inbound_tree: sled::Tree,
    ciphertext_index_tree: sled::Tree,
    ciphertext_archive_tree: sled::Tree,
    da_ciphertext_tree: sled::Tree,
    da_proof_tree: sled::Tree,
    poseidon2_v8_tree: sled::Tree,
    state: RwLock<NativeState>,
    start_instant: Instant,
    mining: AtomicBool,
    mining_threads: AtomicU32,
    mining_round: AtomicU64,
    mining_hashes: AtomicU64,
    blocks_found: AtomicU64,
    canonical_state_generation: AtomicU64,
    last_announce_height: AtomicU64,
    pending_action_rebroadcast_cursor: AtomicU64,
    sync_target_height: AtomicU64,
    sync_target_observed: AtomicBool,
    sync_target_peer: Mutex<Option<PeerId>>,
    sync_target_hash: Mutex<Option<[u8; 32]>>,
    sync_target_unverified_peer_hint: AtomicBool,
    sync_unverified_target_deferred_during_import: Mutex<Option<NativeSyncTargetSnapshot>>,
    sync_unverified_target_cooldowns: Mutex<BTreeMap<PeerId, Instant>>,
    sync_reorg_backfill_blocks: AtomicU64,
    mining_sync_gate_open: AtomicBool,
    sync_import_in_flight: AtomicBool,
    network_peer_count: Arc<AtomicUsize>,
    network_local_peer_id: Arc<StdRwLock<Option<PeerId>>>,
    network_peer_snapshot: Arc<StdRwLock<Vec<ConnectedPeerSnapshot>>>,
    sync_request_rate_limits: Mutex<BTreeMap<PeerId, NativeSyncRequestRateState>>,
    outbound_sync_request_rate_limits: Mutex<BTreeMap<PeerId, NativeSyncRequestRateState>>,
    sync_response_in_flight_peers: Mutex<BTreeMap<PeerId, NativeSyncRange>>,
    outbound_sync_requests: Mutex<BTreeMap<Option<PeerId>, NativeOutboundSyncRequest>>,
    sync_recovery_cursor: Mutex<Option<NativeSyncRecoveryCursor>>,
    sync_chunk_sessions: Mutex<NativeSyncChunkSessions>,
    sync_chunk_receive_in_flight_peers: Mutex<BTreeSet<PeerId>>,
    mining_tasks: Mutex<Vec<JoinHandle<()>>>,
    sync_tx: Mutex<Option<ProtocolSender>>,
    pending_proof_admission_semaphore: Arc<Semaphore>,
    peer_pending_proof_admission_semaphore: Arc<Semaphore>,
    local_pending_proof_admission_semaphore: Arc<Semaphore>,
    work_template_proof_semaphore: Arc<Semaphore>,
    block_import_semaphore: Arc<Semaphore>,
    /// Serializes canonical-chain commits while allowing all expensive proof,
    /// payload, and replay validation to run against an immutable snapshot
    /// without holding `state`'s writer lock.
    canonical_import_lock: Mutex<()>,
    /// Serializes every durable `action_tree` mutation and its matching
    /// in-memory publication. Global order is this persistence epoch first,
    /// then `block_store_persistence_lock` when required, then
    /// `canonical_import_lock`, then a short `state` guard.
    /// A contender never holds the canonical guard while waiting for the
    /// epoch, and no `state` guard spans a sled transaction or durability
    /// barrier.
    pending_action_persistence_lock: Mutex<()>,
    /// Serializes content-addressed block-body/refcount and fork-retention
    /// mutation. Canonical writers acquire `pending_action_persistence_lock`,
    /// then this block-store epoch, then `canonical_import_lock`, then a short
    /// `state` guard. Noncanonical writers acquire only this epoch. Neither
    /// canonical nor state guards are held while waiting for it or across I/O.
    block_store_persistence_lock: Mutex<()>,
    /// Advances only when a durable pending-action epoch is published to RAM.
    /// Callers snapshot it under `state` and compare again before publication.
    pending_action_generation: AtomicU64,
    /// Fail-stop gate set when a durability barrier or post-commit readback
    /// leaves canonical storage health uncertain. A restart performs the
    /// authoritative sled reload before mutation resumes.
    native_storage_poisoned: AtomicBool,
    work_template_build_lock: Mutex<()>,
    work_template_cache: Mutex<Option<NativeWorkTemplateCacheEntry>>,
    pending_action_group_commit: NativePendingActionGroupCommit,
    pending_proof_admissions_in_flight: Arc<Mutex<BTreeSet<ActionSemanticId48>>>,
    rejected_pending_actions: Mutex<RejectedPendingActionCache>,
    block_body_send_cache: Mutex<NativeBlockBodySendCache>,
    da_encoding_cache: Mutex<NativeDaEncodingCache>,
    da_encoding_build_lock: Mutex<()>,
    in_process_verified_blocks: Mutex<NativeVerifiedBlockCache>,
    in_process_canonical_checkpoints: Mutex<NativeCanonicalCheckpointCache>,
    #[cfg(test)]
    best_meta_clone_invocations: AtomicU64,
    #[cfg(test)]
    full_block_body_load_invocations: AtomicU64,
    #[cfg(test)]
    independent_proof_backend_invocations: AtomicU64,
    #[cfg(test)]
    work_template_build_invocations: AtomicU64,
    #[cfg(test)]
    pending_action_group_commit_test: NativePendingActionGroupCommitTestControl,
    #[cfg(test)]
    header_history_rebuild_invocations: AtomicU64,
    #[cfg(test)]
    historical_block_proof_replay_invocations: AtomicU64,
    #[cfg(test)]
    fail_next_canonical_readback: AtomicBool,
    #[cfg(test)]
    reorg_suffix_blocks_examined: AtomicU64,
    #[cfg(test)]
    reorg_suffix_body_bytes_examined: AtomicU64,
    #[cfg(test)]
    reorg_index_mutations: AtomicU64,
    // PR 203 bounded-sync instrumentation. These counters describe storage
    // work only and never act as proof-validity authority.
    #[cfg(test)]
    block_meta_load_count: AtomicU64,
    #[cfg(test)]
    block_meta_decode_count: AtomicU64,
    #[cfg(test)]
    chain_reconstruction_count: AtomicU64,
    #[cfg(test)]
    streaming_replay_live_stored_meta_count: AtomicU64,
    #[cfg(test)]
    streaming_replay_peak_stored_meta_count: AtomicU64,
    #[cfg(test)]
    sync_chunk_record_load_count: AtomicU64,
    #[cfg(test)]
    sync_chunk_record_decode_count: AtomicU64,
}

mod admission;
mod block_flow;
mod block_store_v3;
mod canonical_membership;
mod fork_retention;
pub mod hx512_lifecycle;
mod inactive_smallwood_v7;
mod mining;
mod node_impl;
mod nullifier_accumulator;
mod poseidon2_v8_pending;
pub(crate) mod poseidon2_v8_state;
pub(crate) mod poseidon2_v8_verifier;
mod pow;
mod reorg_wal;
mod rpc;
mod service;
pub(crate) mod smallwood_v8_lifetime;
mod storage;
mod sync_chunks;
mod util;

pub(crate) use admission::*;
pub(crate) use block_flow::*;
pub(crate) use canonical_membership::*;
pub(crate) use mining::*;
pub(crate) use node_impl::NativePendingProofAdmissionGuard;
#[cfg(test)]
pub(crate) use node_impl::{
    apply_poseidon2_v8_plan_and_admit_atomic_manifest_in_transaction,
    classify_native_da_single_transfer, empty_canonical_suffix_manifest_before_v8_observation,
    native_canonical_state_checkpoint, native_canonical_state_checkpoint_digest,
    native_da_transfer_blob_contribution, native_proof_error_is_deterministic,
    native_retarget_anchor_timestamp_from_parent, select_native_da_action_prefix,
    select_native_da_capacity_prefix, validate_native_canonical_state_checkpoint,
    NativeDaCapacitySelectionError, NativeDaSingleTransferDecision,
};
pub(crate) use nullifier_accumulator::*;
pub(crate) use pow::*;
pub(crate) use rpc::*;
pub use service::run;
pub(crate) use service::*;
pub(crate) use storage::*;
pub(crate) use sync_chunks::*;
pub(crate) use util::*;

#[cfg(test)]
mod pending_action_canonicality_tests;
#[cfg(test)]
mod poseidon2_v8_coinbase_tests;
#[cfg(test)]
mod tests;
#[cfg(test)]
mod transport_tests;
