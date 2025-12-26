pub mod address;
pub mod api;
pub mod async_sync;
pub mod consolidate;
pub mod disclosure;
pub mod error;
pub mod extrinsic;
pub mod keys;
pub mod metadata;
pub mod notes;
pub mod prover;
pub mod rpc;
pub mod scanner;
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
pub use rpc::TransactionBundle;
pub use scanner::{
    NoteScanner, PositionedNote, ScanResult, ScannedNote, ScannerConfig, ScannerStats,
    SharedScanner,
};
pub use shielded_tx::{BuiltShieldedTx, ProofStats, ShieldedOutput, ShieldedTxBuilder};
pub use store::{
    OutgoingDisclosureDraft, OutgoingDisclosureRecord, PendingStatus, PendingTransaction,
    SpendableNote, TransferRecipient, WalletMode, WalletStore,
};
pub use substrate_rpc::{BlockingSubstrateRpcClient, SubstrateRpcClient, SubstrateRpcConfig};
pub use sync::{SyncOutcome, WalletSyncEngine};
pub use tx_builder::{
    build_stablecoin_burn, build_transaction, build_transaction_with_binding, precheck_nullifiers,
    precheck_nullifiers_with_binding, BuiltTransaction, Recipient,
};
pub use viewing::{FullViewingKey, IncomingViewingKey, OutgoingViewingKey, RecoveredNote};
