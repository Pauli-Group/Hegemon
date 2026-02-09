pub mod address;
pub mod async_sync;
pub mod consolidate;
pub mod disclosure;
pub mod error;
pub mod extrinsic;
pub mod keys;
pub mod metadata;
pub mod notes;
pub mod prover;
pub mod recipients;
pub mod rpc;
pub mod scanner;
mod serde_bytes48;
pub mod shielded_tx;
pub mod store;
pub mod substrate_rpc;
pub mod sync;
pub mod tx_builder;
pub mod viewing;

pub use address::ShieldedAddress;
pub use async_sync::{AsyncWalletSyncEngine, SharedSyncEngine};
pub use consolidate::{execute_consolidation, ConsolidationPlan, MAX_INPUTS};
pub use error::WalletError;
pub use extrinsic::{
    ChainMetadata, Era, ExtrinsicBuilder, ShieldedTransferCall, SlhDsaExtrinsicBuilder,
};
pub use keys::{AddressKeyMaterial, DerivedKeys, RootSecret, SpendKey, ViewKey};
pub use notes::{MemoPlaintext, NoteCiphertext, NotePlaintext};
pub use prover::{ProofResult, ProverStats, StarkProver, StarkProverConfig};
pub use recipients::{parse_recipients, transfer_recipients_from_specs, RecipientSpec};
pub use rpc::TransactionBundle;
pub use scanner::{
    NoteScanner, PositionedNote, ScanResult, ScannedNote, ScannerConfig, ScannerStats,
    SharedScanner,
};
pub use shielded_tx::{BuiltShieldedTx, ProofStats, ShieldedOutput, ShieldedTxBuilder};
pub use store::{
    OutgoingDisclosureDraft, OutgoingDisclosureRecord, PendingStatus, PendingTransaction,
    SpendableNote, TrackedNoteView, TransferRecipient, WalletMode, WalletStore,
};
pub use substrate_rpc::{BlockingSubstrateRpcClient, SubstrateRpcClient, SubstrateRpcConfig};
pub use sync::SyncOutcome;
pub use tx_builder::{
    build_stablecoin_burn, build_transaction, build_transaction_with_binding, precheck_nullifiers,
    precheck_nullifiers_with_binding, BuiltTransaction, Recipient,
};
pub use viewing::{FullViewingKey, IncomingViewingKey, OutgoingViewingKey, RecoveredNote};
