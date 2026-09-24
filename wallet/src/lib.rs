pub mod address;
#[cfg(feature = "rpc-client")]
pub mod async_sync;
#[cfg(feature = "rpc-client")]
pub mod consolidate;
pub mod disclosure;
pub mod error;
pub mod hx512_lifecycle;
pub mod inactive_smallwood_v7;
pub mod keys;
pub mod multisig;
#[cfg(feature = "rpc-client")]
pub mod node_rpc;
pub mod notes;
#[cfg(feature = "rpc-client")]
pub mod poseidon2_v8;
pub mod poseidon2_v8_coinbase;
pub mod poseidon2_v8_sync;
#[cfg(feature = "prospective-full-m4")]
pub mod prospective_full_m4;
pub mod prover;
pub mod recipients;
pub mod rpc;
pub mod scanner;
mod serde_bytes48;
pub mod shielded_tx;
pub mod store;
pub mod submission;
pub mod sync;
pub mod tx_builder;
pub mod viewing;

pub use address::ShieldedAddress;
#[cfg(feature = "rpc-client")]
pub use async_sync::{AsyncWalletSyncEngine, SharedSyncEngine};
#[cfg(feature = "rpc-client")]
pub use consolidate::{execute_consolidation, ConsolidationPlan, MAX_INPUTS};
pub use error::WalletError;
pub use hegemon_hash384::ActionId48;
pub use keys::{
    ml_dsa_account_id_from_seed, AddressKeyMaterial, DerivedKeys, RootSecret, SpendKey, ViewKey,
};
pub use multisig::{
    approval_circuit_hooks_available, create_account_record, create_approval,
    create_final_spend_package, intent_digest, signer_tag_from_spend_key, MultisigAccountPublic,
    MultisigAccountRecord, MultisigApprovalPackage, MultisigFinalSpendPackage,
    MultisigIntentRecipient, MultisigIntentState, MultisigSpendIntent, MultisigStoredApproval,
    VerifiedApproval,
};
#[cfg(all(feature = "rpc-client", feature = "poseidon2-v8-retained-test-support"))]
pub use node_rpc::prepare_poseidon2_smza_submit_request_json_for_retained_test;
#[cfg(feature = "rpc-client")]
pub use node_rpc::{BlockingNodeRpcClient, ChainMetadata, NodeRpcClient, NodeRpcConfig};
pub use notes::{MemoPlaintext, NoteCiphertext, NotePlaintext};
#[cfg(all(feature = "rpc-client", feature = "poseidon2-v8-retained-test-support"))]
pub use poseidon2_v8::{
    prepare_poseidon2_v8_smza_request_for_retained_test,
    prepare_poseidon2_v8_smza_wallet_self_spend_request_for_retained_test,
};
#[cfg(feature = "rpc-client")]
pub use poseidon2_v8::{
    Poseidon2ProductionExpectedContext, SmallwoodPoseidon2V8InlineCiphertexts,
    SmallwoodPoseidon2V8PublicStatement, SmallwoodPoseidon2V8Witness,
    SMALLWOOD_POSEIDON2_V8_WALLET_MAX_ACTION_BYTES,
};
pub use poseidon2_v8_coinbase::{
    build_poseidon2_v8_wallet_self_spend, Poseidon2V8SpendMaterial, Poseidon2V8WalletSpend,
};
pub use poseidon2_v8_sync::{
    Poseidon2V8CanonicalBlock, Poseidon2V8CanonicalTip, Poseidon2V8Digest,
    Poseidon2V8OwnedNoteView, Poseidon2V8Path, Poseidon2V8SpendContext,
};
pub use prover::{
    LocalProofSelfCheckPolicy, ProofResult, ProverStats, StarkProver, StarkProverConfig,
};
pub use recipients::{parse_recipients, transfer_recipients_from_specs, RecipientSpec};
pub use rpc::TransactionBundle;
pub use scanner::{
    NoteScanner, PositionedNote, ScanResult, ScannedNote, ScannerConfig, ScannerStats,
    SharedScanner,
};
pub use shielded_tx::{BuiltShieldedTx, ProofStats, ShieldedOutput, ShieldedTxBuilder};
pub use store::{
    LocalMultisigAccumulatorOpening, LocalNoteOpeningRecord, NoteSource, OutgoingDisclosureDraft,
    OutgoingDisclosureRecord, PendingStatus, PendingTransaction, RecentTransaction, SpendableNote,
    TrackedNoteView, TransferRecipient, WalletMode, WalletStore, WalletTransactionId,
};
pub use submission::{
    is_ambiguous_submission_error, provisional_pending_tx_id, ProvisionalActionId48,
};
pub use sync::SyncOutcome;
pub use tx_builder::{
    build_multisig_approval_transaction, build_multisig_final_transaction_from_plan,
    build_multisig_initial_accumulator_transaction, build_multisig_value_lock_transaction,
    build_stablecoin_burn, build_transaction, build_transaction_with_binding,
    prepare_multisig_final_plan, BuiltMultisigValueLock, BuiltTransaction,
    PreparedMultisigFinalPlan, Recipient,
};
#[cfg(feature = "rpc-client")]
pub use tx_builder::{precheck_nullifiers, precheck_nullifiers_with_binding};
pub use viewing::{FullViewingKey, IncomingViewingKey, OutgoingViewingKey, RecoveredNote};
