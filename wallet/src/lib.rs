pub mod address;
#[cfg(feature = "rpc-client")]
pub mod async_sync;
#[cfg(feature = "rpc-client")]
pub mod consolidate;
pub mod disclosure;
pub mod error;
pub mod keys;
pub mod multisig;
#[cfg(feature = "rpc-client")]
pub mod node_rpc;
pub mod notes;
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
pub use keys::{
    ml_dsa_account_id_from_seed, AddressKeyMaterial, DerivedKeys, RootSecret, SpendKey, ViewKey,
};
pub use multisig::{
    approval_circuit_hooks_available, create_account_record, create_approval,
    create_final_spend_package, intent_digest, signer_commitment_from_spend_key,
    MultisigAccountPublic, MultisigAccountRecord, MultisigApprovalPackage,
    MultisigFinalSpendPackage, MultisigIntentRecipient, MultisigIntentState, MultisigSpendIntent,
    MultisigStoredApproval, VerifiedApproval,
};
#[cfg(feature = "rpc-client")]
pub use node_rpc::{BlockingNodeRpcClient, ChainMetadata, NodeRpcClient, NodeRpcConfig};
pub use notes::{MemoPlaintext, NoteCiphertext, NotePlaintext};
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
    OutgoingDisclosureDraft, OutgoingDisclosureRecord, PendingStatus, PendingTransaction,
    RecentTransaction, SpendableNote, TrackedNoteView, TransferRecipient, WalletMode, WalletStore,
};
pub use submission::{is_ambiguous_submission_error, provisional_pending_tx_id};
pub use sync::SyncOutcome;
pub use tx_builder::{
    build_stablecoin_burn, build_transaction, build_transaction_with_binding, BuiltTransaction,
    Recipient,
};
#[cfg(feature = "rpc-client")]
pub use tx_builder::{precheck_nullifiers, precheck_nullifiers_with_binding};
pub use viewing::{FullViewingKey, IncomingViewingKey, OutgoingViewingKey, RecoveredNote};
