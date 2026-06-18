import Hegemon.Transaction.PublicInputs
import Hegemon.Wallet.NoteCiphertextWire

set_option maxRecDepth 10000

namespace Hegemon
namespace Privacy
namespace Observer

open Hegemon.Transaction.PublicInputs
open Hegemon.Wallet.NoteCiphertextWire

structure ObserverView where
  publicInputs : PublicInputShape
  ciphertextBytes : List (List Byte)
  ciphertextSummaries : List NoteCiphertextSummary
  blockHeight : Nat
  actionIndex : Nat
deriving DecidableEq, Repr

structure PublicMetadataView where
  publicInputs : PublicInputShape
  ciphertextSummaries : List NoteCiphertextSummary
  blockHeight : Nat
  actionIndex : Nat
deriving DecidableEq, Repr

structure BatchTimingView where
  activeOutputCount : Nat
  ciphertextCount : Nat
  summaryCount : Nat
  blockHeight : Nat
  actionIndex : Nat
deriving DecidableEq, Repr

structure PrivateWitness where
  spendSecretSeeds : List Nat
  inputNoteValues : List Nat
  inputAssetIds : List Nat
  outputNoteValues : List Nat
  outputAssetIds : List Nat
  noteRandomnessSeeds : List Nat
  notePlaintextSeeds : List Nat
  memoPlaintextSeeds : List Nat
deriving DecidableEq, Repr

structure LocalActionMetadata where
  receivedMs : Nat
  mempoolOrdinal : Nat
  peerTag : Nat
  storageGeneration : Nat
deriving DecidableEq, Repr

structure LocalAddressMetadata where
  nextAddressIndex : Nat
  reservedInternalAddressCount : Nat
  addressBookGeneration : Nat
deriving DecidableEq, Repr

structure LocalWalletBookkeepingMetadata where
  syncHeight : Nat
  syncBlockHashTag : Nat
  ciphertextCursor : Nat
  trackedNoteGeneration : Nat
  pendingStatusTag : Nat
  pendingRecipientMemoTag : Nat
  submissionTimestampMs : Nat
deriving DecidableEq, Repr

structure LocalNetworkMetadata where
  remotePeerTag : Nat
  connectionEpoch : Nat
  bytesSent : Nat
  bytesReceived : Nat
  gossipHopCount : Nat
deriving DecidableEq, Repr

structure ShieldedTransactionWorld where
  publicInputs : PublicInputShape
  ciphertextBytes : List (List Byte)
  ciphertextSummaries : List NoteCiphertextSummary
  blockHeight : Nat
  actionIndex : Nat
  localActionMetadata : LocalActionMetadata
  localAddressMetadata : LocalAddressMetadata
  localWalletBookkeepingMetadata : LocalWalletBookkeepingMetadata
  localNetworkMetadata : LocalNetworkMetadata
  privateWitness : PrivateWitness
  proverRandomnessSeed : Nat
deriving DecidableEq, Repr

def observerView (world : ShieldedTransactionWorld) : ObserverView :=
  { publicInputs := world.publicInputs
    ciphertextBytes := world.ciphertextBytes
    ciphertextSummaries := world.ciphertextSummaries
    blockHeight := world.blockHeight
    actionIndex := world.actionIndex }

def publicMetadataView
    (world : ShieldedTransactionWorld) : PublicMetadataView :=
  { publicInputs := world.publicInputs
    ciphertextSummaries := world.ciphertextSummaries
    blockHeight := world.blockHeight
    actionIndex := world.actionIndex }

def parsedChainCiphertextSummaries :
    List (List Byte) -> Option (List NoteCiphertextSummary)
  | [] => some []
  | wire :: rest => do
      let summary ← parseChainNoteCiphertext wire
      let summaries ← parsedChainCiphertextSummaries rest
      some (summary :: summaries)

def summariesMatchChainWire (world : ShieldedTransactionWorld) : Prop :=
  parsedChainCiphertextSummaries world.ciphertextBytes =
    some world.ciphertextSummaries

def activeFlagCount : List Nat -> Nat
  | [] => 0
  | flag :: rest =>
      (if flag = 1 then 1 else 0) + activeFlagCount rest

def activeOutputCount (shape : PublicInputShape) : Nat :=
  activeFlagCount shape.outputFlags

def batchTimingView
    (world : ShieldedTransactionWorld) : BatchTimingView :=
  { activeOutputCount := activeOutputCount world.publicInputs
    ciphertextCount := world.ciphertextBytes.length
    summaryCount := world.ciphertextSummaries.length
    blockHeight := world.blockHeight
    actionIndex := world.actionIndex }

def activeFlagCountBefore : List Nat -> Nat -> Nat
  | [], _ => 0
  | _ :: _, 0 => 0
  | flag :: rest, index + 1 =>
      (if flag = 1 then 1 else 0) + activeFlagCountBefore rest index

theorem output_slot_active_flag_count_nonzero
    {flags : List Nat}
    {commitments ciphertextHashes : List Digest}
    {index : Nat}
    {publicCommitment publicCiphertextHash : Digest}
    (slot :
      OutputSlotAt
        flags
        commitments
        ciphertextHashes
        index
        1
        publicCommitment
        publicCiphertextHash) :
    activeFlagCount flags ≠ 0 := by
  induction flags generalizing commitments ciphertextHashes index with
  | nil =>
      cases commitments <;> cases ciphertextHashes <;> cases index <;>
        simp [OutputSlotAt] at slot
  | cons flag rest ih =>
      cases commitments with
      | nil =>
          cases ciphertextHashes <;> cases index <;>
            simp [OutputSlotAt] at slot
      | cons commitment commitmentsTail =>
          cases ciphertextHashes with
          | nil =>
              cases index <;> simp [OutputSlotAt] at slot
          | cons ciphertextHash ciphertextHashesTail =>
              cases index with
              | zero =>
                  have active : flag = 1 := by
                    exact slot.left.symm
                  simp [activeFlagCount, active]
              | succ indexTail =>
                  have tailNonzero :
                      activeFlagCount rest ≠ 0 :=
                    ih
                      (commitments := commitmentsTail)
                      (ciphertextHashes := ciphertextHashesTail)
                      (index := indexTail)
                      slot
                  unfold activeFlagCount
                  by_cases active : flag = 1
                  · simp [active]
                  · simp [active, tailNonzero]

theorem output_slot_active_rank_lt_count
    {flags : List Nat}
    {commitments ciphertextHashes : List Digest}
    {index : Nat}
    {publicCommitment publicCiphertextHash : Digest}
    (slot :
      OutputSlotAt
        flags
        commitments
        ciphertextHashes
        index
        1
        publicCommitment
        publicCiphertextHash) :
    activeFlagCountBefore flags index < activeFlagCount flags := by
  induction flags generalizing commitments ciphertextHashes index with
  | nil =>
      cases commitments <;> cases ciphertextHashes <;> cases index <;>
        simp [OutputSlotAt] at slot
  | cons flag rest ih =>
      cases commitments with
      | nil =>
          cases ciphertextHashes <;> cases index <;>
            simp [OutputSlotAt] at slot
      | cons commitment commitmentsTail =>
          cases ciphertextHashes with
          | nil =>
              cases index <;> simp [OutputSlotAt] at slot
          | cons ciphertextHash ciphertextHashesTail =>
              cases index with
              | zero =>
                  have active : flag = 1 := by
                    exact slot.left.symm
                  dsimp [activeFlagCountBefore, activeFlagCount]
                  rw [if_pos active]
                  rw [Nat.add_comm]
                  exact Nat.zero_lt_succ (activeFlagCount rest)
              | succ indexTail =>
                  have tailLt :
                      activeFlagCountBefore rest indexTail <
                        activeFlagCount rest :=
                    ih
                      (commitments := commitmentsTail)
                      (ciphertextHashes := ciphertextHashesTail)
                      (index := indexTail)
                      slot
                  dsimp [activeFlagCountBefore, activeFlagCount]
                  by_cases active : flag = 1
                  · simpa [active] using Nat.add_lt_add_left tailLt 1
                  · simpa [active] using tailLt

def validObserverChainSurface
    (world : ShieldedTransactionWorld) : Prop :=
  validPublicInputShape world.publicInputs = true
    ∧ summariesMatchChainWire world
    ∧ world.ciphertextBytes.length =
        activeOutputCount world.publicInputs

def summaryHasChainCiphertextFormat
    (summary : NoteCiphertextSummary) : Prop :=
  summary.cryptoSuite = cryptoSuiteGamma
    ∧ summary.kemLen = mlKemCiphertextLen

def summariesHaveChainCiphertextFormat
    (summaries : List NoteCiphertextSummary) : Prop :=
  ∀ summary, summary ∈ summaries -> summaryHasChainCiphertextFormat summary

def sameAllowedLeakage
    (left right : ShieldedTransactionWorld) : Prop :=
  observerView left = observerView right

def samePublicMetadataLeakage
    (left right : ShieldedTransactionWorld) : Prop :=
  publicMetadataView left = publicMetadataView right

def sameBatchTimingLeakage
    (left right : ShieldedTransactionWorld) : Prop :=
  batchTimingView left = batchTimingView right

def samePublicInputs
    (left right : ShieldedTransactionWorld) : Prop :=
  left.publicInputs = right.publicInputs

def sameCiphertextWire
    (left right : ShieldedTransactionWorld) : Prop :=
  left.ciphertextBytes = right.ciphertextBytes
    ∧ left.ciphertextSummaries = right.ciphertextSummaries

def samePlacement
    (left right : ShieldedTransactionWorld) : Prop :=
  left.blockHeight = right.blockHeight
    ∧ left.actionIndex = right.actionIndex

def sampleLocalActionMetadata : LocalActionMetadata :=
  {
    receivedMs := 0,
    mempoolOrdinal := 0,
    peerTag := 0,
    storageGeneration := 0
  }

def sampleLocalAddressMetadata : LocalAddressMetadata :=
  {
    nextAddressIndex := 0,
    reservedInternalAddressCount := 0,
    addressBookGeneration := 0
  }

def sampleLocalWalletBookkeepingMetadata : LocalWalletBookkeepingMetadata :=
  {
    syncHeight := 0,
    syncBlockHashTag := 0,
    ciphertextCursor := 0,
    trackedNoteGeneration := 0,
    pendingStatusTag := 0,
    pendingRecipientMemoTag := 0,
    submissionTimestampMs := 0
  }

def sampleLocalNetworkMetadata : LocalNetworkMetadata :=
  {
    remotePeerTag := 0,
    connectionEpoch := 0,
    bytesSent := 0,
    bytesReceived := 0,
    gossipHopCount := 0
  }

def samplePrivateWitness : PrivateWitness :=
  {
    spendSecretSeeds := [],
    inputNoteValues := [],
    inputAssetIds := [],
    outputNoteValues := [],
    outputAssetIds := [],
    noteRandomnessSeeds := [],
    notePlaintextSeeds := [],
    memoPlaintextSeeds := []
  }

def publicRawWireSplitLeftWorld : ShieldedTransactionWorld :=
  {
    publicInputs := validShape,
    ciphertextBytes := [validChainWire],
    ciphertextSummaries := [sampleChainCiphertextSummary],
    blockHeight := 42,
    actionIndex := 7,
    localActionMetadata := sampleLocalActionMetadata,
    localAddressMetadata := sampleLocalAddressMetadata,
    localWalletBookkeepingMetadata := sampleLocalWalletBookkeepingMetadata,
    localNetworkMetadata := sampleLocalNetworkMetadata,
    privateWitness := samplePrivateWitness,
    proverRandomnessSeed := 0
  }

def publicRawWireSplitRightWorld : ShieldedTransactionWorld :=
  {
    publicInputs := validShape,
    ciphertextBytes := [alternateValidChainWire],
    ciphertextSummaries := [sampleChainCiphertextSummary],
    blockHeight := 42,
    actionIndex := 7,
    localActionMetadata := sampleLocalActionMetadata,
    localAddressMetadata := sampleLocalAddressMetadata,
    localWalletBookkeepingMetadata := sampleLocalWalletBookkeepingMetadata,
    localNetworkMetadata := sampleLocalNetworkMetadata,
    privateWitness := samplePrivateWitness,
    proverRandomnessSeed := 1
  }

theorem observer_view_ignores_private_witness
    (world : ShieldedTransactionWorld)
    (privateWitness : PrivateWitness) :
    observerView { world with privateWitness := privateWitness } =
      observerView world := by
  rfl

theorem public_metadata_view_ignores_private_witness
    (world : ShieldedTransactionWorld)
    (privateWitness : PrivateWitness) :
    publicMetadataView { world with privateWitness := privateWitness } =
      publicMetadataView world := by
  rfl

theorem batch_timing_view_ignores_private_witness
    (world : ShieldedTransactionWorld)
    (privateWitness : PrivateWitness) :
    batchTimingView { world with privateWitness := privateWitness } =
      batchTimingView world := by
  rfl

theorem observer_view_ignores_prover_randomness
    (world : ShieldedTransactionWorld)
    (proverRandomnessSeed : Nat) :
    observerView { world with proverRandomnessSeed := proverRandomnessSeed } =
      observerView world := by
  rfl

theorem public_metadata_view_ignores_prover_randomness
    (world : ShieldedTransactionWorld)
    (proverRandomnessSeed : Nat) :
    publicMetadataView { world with proverRandomnessSeed := proverRandomnessSeed } =
      publicMetadataView world := by
  rfl

theorem batch_timing_view_ignores_prover_randomness
    (world : ShieldedTransactionWorld)
    (proverRandomnessSeed : Nat) :
    batchTimingView { world with proverRandomnessSeed := proverRandomnessSeed } =
      batchTimingView world := by
  rfl

theorem observer_view_ignores_local_action_metadata
    (world : ShieldedTransactionWorld)
    (localActionMetadata : LocalActionMetadata) :
    observerView { world with localActionMetadata := localActionMetadata } =
      observerView world := by
  rfl

theorem public_metadata_view_ignores_local_action_metadata
    (world : ShieldedTransactionWorld)
    (localActionMetadata : LocalActionMetadata) :
    publicMetadataView { world with localActionMetadata := localActionMetadata } =
      publicMetadataView world := by
  rfl

theorem batch_timing_view_ignores_local_action_metadata
    (world : ShieldedTransactionWorld)
    (localActionMetadata : LocalActionMetadata) :
    batchTimingView { world with localActionMetadata := localActionMetadata } =
      batchTimingView world := by
  rfl

theorem observer_view_ignores_local_address_metadata
    (world : ShieldedTransactionWorld)
    (localAddressMetadata : LocalAddressMetadata) :
    observerView { world with localAddressMetadata := localAddressMetadata } =
      observerView world := by
  rfl

theorem public_metadata_view_ignores_local_address_metadata
    (world : ShieldedTransactionWorld)
    (localAddressMetadata : LocalAddressMetadata) :
    publicMetadataView { world with localAddressMetadata := localAddressMetadata } =
      publicMetadataView world := by
  rfl

theorem batch_timing_view_ignores_local_address_metadata
    (world : ShieldedTransactionWorld)
    (localAddressMetadata : LocalAddressMetadata) :
    batchTimingView { world with localAddressMetadata := localAddressMetadata } =
      batchTimingView world := by
  rfl

theorem observer_view_ignores_local_wallet_bookkeeping_metadata
    (world : ShieldedTransactionWorld)
    (localWalletBookkeepingMetadata : LocalWalletBookkeepingMetadata) :
    observerView
        { world with
          localWalletBookkeepingMetadata := localWalletBookkeepingMetadata } =
      observerView world := by
  rfl

theorem public_metadata_view_ignores_local_wallet_bookkeeping_metadata
    (world : ShieldedTransactionWorld)
    (localWalletBookkeepingMetadata : LocalWalletBookkeepingMetadata) :
    publicMetadataView
        { world with
          localWalletBookkeepingMetadata := localWalletBookkeepingMetadata } =
      publicMetadataView world := by
  rfl

theorem batch_timing_view_ignores_local_wallet_bookkeeping_metadata
    (world : ShieldedTransactionWorld)
    (localWalletBookkeepingMetadata : LocalWalletBookkeepingMetadata) :
    batchTimingView
        { world with
          localWalletBookkeepingMetadata := localWalletBookkeepingMetadata } =
      batchTimingView world := by
  rfl

theorem observer_view_ignores_local_network_metadata
    (world : ShieldedTransactionWorld)
    (localNetworkMetadata : LocalNetworkMetadata) :
    observerView { world with localNetworkMetadata := localNetworkMetadata } =
      observerView world := by
  rfl

theorem public_metadata_view_ignores_local_network_metadata
    (world : ShieldedTransactionWorld)
    (localNetworkMetadata : LocalNetworkMetadata) :
    publicMetadataView { world with localNetworkMetadata := localNetworkMetadata } =
      publicMetadataView world := by
  rfl

theorem batch_timing_view_ignores_local_network_metadata
    (world : ShieldedTransactionWorld)
    (localNetworkMetadata : LocalNetworkMetadata) :
    batchTimingView { world with localNetworkMetadata := localNetworkMetadata } =
      batchTimingView world := by
  rfl

theorem observer_view_ignores_private_witness_and_randomness
    (world : ShieldedTransactionWorld)
    (privateWitness : PrivateWitness)
    (proverRandomnessSeed : Nat) :
    observerView
        { world with
          privateWitness := privateWitness
          proverRandomnessSeed := proverRandomnessSeed } =
      observerView world := by
  rfl

theorem public_metadata_view_ignores_private_witness_and_randomness
    (world : ShieldedTransactionWorld)
    (privateWitness : PrivateWitness)
    (proverRandomnessSeed : Nat) :
    publicMetadataView
        { world with
          privateWitness := privateWitness
          proverRandomnessSeed := proverRandomnessSeed } =
      publicMetadataView world := by
  rfl

theorem batch_timing_view_ignores_private_witness_and_randomness
    (world : ShieldedTransactionWorld)
    (privateWitness : PrivateWitness)
    (proverRandomnessSeed : Nat) :
    batchTimingView
        { world with
          privateWitness := privateWitness
          proverRandomnessSeed := proverRandomnessSeed } =
      batchTimingView world := by
  rfl

theorem observer_view_ignores_private_witness_randomness_and_local_metadata
    (world : ShieldedTransactionWorld)
    (privateWitness : PrivateWitness)
    (proverRandomnessSeed : Nat)
    (localActionMetadata : LocalActionMetadata) :
    observerView
        { world with
          privateWitness := privateWitness
          proverRandomnessSeed := proverRandomnessSeed
          localActionMetadata := localActionMetadata } =
      observerView world := by
  rfl

theorem public_metadata_view_ignores_private_witness_randomness_and_local_metadata
    (world : ShieldedTransactionWorld)
    (privateWitness : PrivateWitness)
    (proverRandomnessSeed : Nat)
    (localActionMetadata : LocalActionMetadata) :
    publicMetadataView
        { world with
          privateWitness := privateWitness
          proverRandomnessSeed := proverRandomnessSeed
          localActionMetadata := localActionMetadata } =
      publicMetadataView world := by
  rfl

theorem batch_timing_view_ignores_private_witness_randomness_and_local_metadata
    (world : ShieldedTransactionWorld)
    (privateWitness : PrivateWitness)
    (proverRandomnessSeed : Nat)
    (localActionMetadata : LocalActionMetadata) :
    batchTimingView
        { world with
          privateWitness := privateWitness
          proverRandomnessSeed := proverRandomnessSeed
          localActionMetadata := localActionMetadata } =
      batchTimingView world := by
  rfl

theorem observer_view_ignores_private_witness_randomness_and_local_network_metadata
    (world : ShieldedTransactionWorld)
    (privateWitness : PrivateWitness)
    (proverRandomnessSeed : Nat)
    (localNetworkMetadata : LocalNetworkMetadata) :
    observerView
        { world with
          privateWitness := privateWitness
          proverRandomnessSeed := proverRandomnessSeed
          localNetworkMetadata := localNetworkMetadata } =
      observerView world := by
  rfl

theorem public_metadata_view_ignores_private_witness_randomness_and_local_network_metadata
    (world : ShieldedTransactionWorld)
    (privateWitness : PrivateWitness)
    (proverRandomnessSeed : Nat)
    (localNetworkMetadata : LocalNetworkMetadata) :
    publicMetadataView
        { world with
          privateWitness := privateWitness
          proverRandomnessSeed := proverRandomnessSeed
          localNetworkMetadata := localNetworkMetadata } =
      publicMetadataView world := by
  rfl

theorem batch_timing_view_ignores_private_witness_randomness_and_local_network_metadata
    (world : ShieldedTransactionWorld)
    (privateWitness : PrivateWitness)
    (proverRandomnessSeed : Nat)
    (localNetworkMetadata : LocalNetworkMetadata) :
    batchTimingView
        { world with
          privateWitness := privateWitness
          proverRandomnessSeed := proverRandomnessSeed
          localNetworkMetadata := localNetworkMetadata } =
      batchTimingView world := by
  rfl

theorem observer_view_ignores_private_witness_randomness_and_local_wallet_bookkeeping_metadata
    (world : ShieldedTransactionWorld)
    (privateWitness : PrivateWitness)
    (proverRandomnessSeed : Nat)
    (localWalletBookkeepingMetadata : LocalWalletBookkeepingMetadata) :
    observerView
        { world with
          privateWitness := privateWitness
          proverRandomnessSeed := proverRandomnessSeed
          localWalletBookkeepingMetadata := localWalletBookkeepingMetadata } =
      observerView world := by
  rfl

theorem public_metadata_view_ignores_private_witness_randomness_and_local_wallet_bookkeeping_metadata
    (world : ShieldedTransactionWorld)
    (privateWitness : PrivateWitness)
    (proverRandomnessSeed : Nat)
    (localWalletBookkeepingMetadata : LocalWalletBookkeepingMetadata) :
    publicMetadataView
        { world with
          privateWitness := privateWitness
          proverRandomnessSeed := proverRandomnessSeed
          localWalletBookkeepingMetadata := localWalletBookkeepingMetadata } =
      publicMetadataView world := by
  rfl

theorem batch_timing_view_ignores_private_witness_randomness_and_local_wallet_bookkeeping_metadata
    (world : ShieldedTransactionWorld)
    (privateWitness : PrivateWitness)
    (proverRandomnessSeed : Nat)
    (localWalletBookkeepingMetadata : LocalWalletBookkeepingMetadata) :
    batchTimingView
        { world with
          privateWitness := privateWitness
          proverRandomnessSeed := proverRandomnessSeed
          localWalletBookkeepingMetadata := localWalletBookkeepingMetadata } =
      batchTimingView world := by
  rfl

theorem observer_view_ignores_private_witness_randomness_and_all_local_metadata
    (world : ShieldedTransactionWorld)
    (privateWitness : PrivateWitness)
    (proverRandomnessSeed : Nat)
    (localActionMetadata : LocalActionMetadata)
    (localAddressMetadata : LocalAddressMetadata)
    (localNetworkMetadata : LocalNetworkMetadata) :
    observerView
        { world with
          privateWitness := privateWitness
          proverRandomnessSeed := proverRandomnessSeed
          localActionMetadata := localActionMetadata
          localAddressMetadata := localAddressMetadata
          localNetworkMetadata := localNetworkMetadata } =
      observerView world := by
  rfl

theorem public_metadata_view_ignores_private_witness_randomness_and_all_local_metadata
    (world : ShieldedTransactionWorld)
    (privateWitness : PrivateWitness)
    (proverRandomnessSeed : Nat)
    (localActionMetadata : LocalActionMetadata)
    (localAddressMetadata : LocalAddressMetadata)
    (localNetworkMetadata : LocalNetworkMetadata) :
    publicMetadataView
        { world with
          privateWitness := privateWitness
          proverRandomnessSeed := proverRandomnessSeed
          localActionMetadata := localActionMetadata
          localAddressMetadata := localAddressMetadata
          localNetworkMetadata := localNetworkMetadata } =
      publicMetadataView world := by
  rfl

theorem batch_timing_view_ignores_private_witness_randomness_and_all_local_metadata
    (world : ShieldedTransactionWorld)
    (privateWitness : PrivateWitness)
    (proverRandomnessSeed : Nat)
    (localActionMetadata : LocalActionMetadata)
    (localAddressMetadata : LocalAddressMetadata)
    (localNetworkMetadata : LocalNetworkMetadata) :
    batchTimingView
        { world with
          privateWitness := privateWitness
          proverRandomnessSeed := proverRandomnessSeed
          localActionMetadata := localActionMetadata
          localAddressMetadata := localAddressMetadata
          localNetworkMetadata := localNetworkMetadata } =
      batchTimingView world := by
  rfl

theorem observer_view_ignores_private_witness_randomness_and_all_wallet_local_metadata
    (world : ShieldedTransactionWorld)
    (privateWitness : PrivateWitness)
    (proverRandomnessSeed : Nat)
    (localActionMetadata : LocalActionMetadata)
    (localAddressMetadata : LocalAddressMetadata)
    (localWalletBookkeepingMetadata : LocalWalletBookkeepingMetadata)
    (localNetworkMetadata : LocalNetworkMetadata) :
    observerView
        { world with
          privateWitness := privateWitness
          proverRandomnessSeed := proverRandomnessSeed
          localActionMetadata := localActionMetadata
          localAddressMetadata := localAddressMetadata
          localWalletBookkeepingMetadata := localWalletBookkeepingMetadata
          localNetworkMetadata := localNetworkMetadata } =
      observerView world := by
  rfl

theorem public_metadata_view_ignores_private_witness_randomness_and_all_wallet_local_metadata
    (world : ShieldedTransactionWorld)
    (privateWitness : PrivateWitness)
    (proverRandomnessSeed : Nat)
    (localActionMetadata : LocalActionMetadata)
    (localAddressMetadata : LocalAddressMetadata)
    (localWalletBookkeepingMetadata : LocalWalletBookkeepingMetadata)
    (localNetworkMetadata : LocalNetworkMetadata) :
    publicMetadataView
        { world with
          privateWitness := privateWitness
          proverRandomnessSeed := proverRandomnessSeed
          localActionMetadata := localActionMetadata
          localAddressMetadata := localAddressMetadata
          localWalletBookkeepingMetadata := localWalletBookkeepingMetadata
          localNetworkMetadata := localNetworkMetadata } =
      publicMetadataView world := by
  rfl

theorem batch_timing_view_ignores_private_witness_randomness_and_all_wallet_local_metadata
    (world : ShieldedTransactionWorld)
    (privateWitness : PrivateWitness)
    (proverRandomnessSeed : Nat)
    (localActionMetadata : LocalActionMetadata)
    (localAddressMetadata : LocalAddressMetadata)
    (localWalletBookkeepingMetadata : LocalWalletBookkeepingMetadata)
    (localNetworkMetadata : LocalNetworkMetadata) :
    batchTimingView
        { world with
          privateWitness := privateWitness
          proverRandomnessSeed := proverRandomnessSeed
          localActionMetadata := localActionMetadata
          localAddressMetadata := localAddressMetadata
          localWalletBookkeepingMetadata := localWalletBookkeepingMetadata
          localNetworkMetadata := localNetworkMetadata } =
      batchTimingView world := by
  rfl

theorem same_public_metadata_leakage_of_public_summaries_and_placement
    {left right : ShieldedTransactionWorld}
    (publicInputs : samePublicInputs left right)
    (summaries : left.ciphertextSummaries = right.ciphertextSummaries)
    (placement : samePlacement left right) :
    samePublicMetadataLeakage left right := by
  cases left
  cases right
  simp [samePublicMetadataLeakage, publicMetadataView, samePublicInputs,
    samePlacement] at publicInputs summaries placement ⊢
  exact ⟨publicInputs, summaries, placement.left, placement.right⟩

theorem same_allowed_leakage_of_public_wire_and_placement
    {left right : ShieldedTransactionWorld}
    (publicInputs : samePublicInputs left right)
    (ciphertexts : sameCiphertextWire left right)
    (placement : samePlacement left right) :
    sameAllowedLeakage left right := by
  cases left
  cases right
  simp [sameAllowedLeakage, observerView, samePublicInputs, sameCiphertextWire,
    samePlacement] at publicInputs ciphertexts placement ⊢
  exact ⟨publicInputs, ciphertexts.left, ciphertexts.right,
    placement.left, placement.right⟩

theorem parsed_chain_ciphertext_summaries_length
    {wires : List (List Byte)}
    {summaries : List NoteCiphertextSummary}
    (parsed : parsedChainCiphertextSummaries wires = some summaries) :
    summaries.length = wires.length := by
  induction wires generalizing summaries with
  | nil =>
      simp [parsedChainCiphertextSummaries] at parsed
      cases parsed
      rfl
  | cons wire rest ih =>
      unfold parsedChainCiphertextSummaries at parsed
      cases parsedWire : parseChainNoteCiphertext wire with
      | none =>
          simp [parsedWire] at parsed
      | some summary =>
          simp [parsedWire] at parsed
          cases parsedRest : parsedChainCiphertextSummaries rest with
          | none =>
              simp [parsedRest] at parsed
          | some restSummaries =>
              simp [parsedRest] at parsed
              cases parsed
              simp [ih parsedRest]

theorem parsed_chain_ciphertext_summaries_have_chain_format
    {wires : List (List Byte)}
    {summaries : List NoteCiphertextSummary}
    (parsed : parsedChainCiphertextSummaries wires = some summaries) :
    summariesHaveChainCiphertextFormat summaries := by
  induction wires generalizing summaries with
  | nil =>
      simp [parsedChainCiphertextSummaries,
        summariesHaveChainCiphertextFormat] at parsed ⊢
      cases parsed
      simp
  | cons wire rest ih =>
      unfold parsedChainCiphertextSummaries at parsed
      cases parsedWire : parseChainNoteCiphertext wire with
      | none =>
          simp [parsedWire] at parsed
      | some summary =>
          simp [parsedWire] at parsed
          cases parsedRest : parsedChainCiphertextSummaries rest with
          | none =>
              simp [parsedRest] at parsed
          | some restSummaries =>
              simp [parsedRest] at parsed
              cases parsed
              intro parsedSummary inSummaries
              simp [summariesHaveChainCiphertextFormat] at ih
              simp at inSummaries
              cases inSummaries with
              | inl sameSummary =>
                  cases sameSummary
                  exact parsed_chain_ciphertext_has_gamma_suite_and_fixed_kem
                    parsedWire
              | inr inRest =>
                  exact ih parsedRest parsedSummary inRest

theorem parsed_chain_ciphertext_summary_at_rank
    {wires : List (List Byte)}
    {summaries : List NoteCiphertextSummary}
    {rank : Nat}
    {wire : List Byte}
    (parsed : parsedChainCiphertextSummaries wires = some summaries)
    (wireAt : wires[rank]? = some wire) :
    ∃ summary,
      summaries[rank]? = some summary
        ∧ parseChainNoteCiphertext wire = some summary
        ∧ summaryHasChainCiphertextFormat summary := by
  induction wires generalizing summaries rank with
  | nil =>
      simp at wireAt
  | cons wireHead rest ih =>
      cases rank with
      | zero =>
          unfold parsedChainCiphertextSummaries at parsed
          cases parsedWire : parseChainNoteCiphertext wireHead with
          | none =>
              simp [parsedWire] at parsed
          | some summary =>
              simp [parsedWire] at parsed
              cases parsedRest : parsedChainCiphertextSummaries rest with
              | none =>
                  simp [parsedRest] at parsed
              | some restSummaries =>
                  simp [parsedRest] at parsed
                  cases parsed
                  cases wireAt
                  exact
                    ⟨summary,
                      by simp,
                      parsedWire,
                      parsed_chain_ciphertext_has_gamma_suite_and_fixed_kem
                        parsedWire⟩
      | succ rankTail =>
          unfold parsedChainCiphertextSummaries at parsed
          cases parsedWire : parseChainNoteCiphertext wireHead with
          | none =>
              simp [parsedWire] at parsed
          | some summaryHead =>
              simp [parsedWire] at parsed
              cases parsedRest : parsedChainCiphertextSummaries rest with
              | none =>
                  simp [parsedRest] at parsed
              | some restSummaries =>
                  simp [parsedRest] at parsed
                  cases parsed
                  have tailWireAt : rest[rankTail]? = some wire := by
                    simpa using wireAt
                  rcases ih parsedRest tailWireAt with
                    ⟨summary, summaryAt, parsedSummary, format⟩
                  exact
                    ⟨summary,
                      by simpa using summaryAt,
                      parsedSummary,
                      format⟩

theorem observer_view_summaries_have_chain_format
    {world : ShieldedTransactionWorld}
    (parsed : summariesMatchChainWire world) :
    summariesHaveChainCiphertextFormat world.ciphertextSummaries :=
  parsed_chain_ciphertext_summaries_have_chain_format parsed

theorem valid_observer_chain_surface_summaries_have_chain_format
    {world : ShieldedTransactionWorld}
    (valid : validObserverChainSurface world) :
    summariesHaveChainCiphertextFormat world.ciphertextSummaries :=
  observer_view_summaries_have_chain_format valid.right.left

theorem valid_observer_chain_surface_ciphertext_count
    {world : ShieldedTransactionWorld}
    (valid : validObserverChainSurface world) :
    world.ciphertextSummaries.length =
      activeOutputCount world.publicInputs := by
  exact
    (parsed_chain_ciphertext_summaries_length
      valid.right.left).trans
      valid.right.right

theorem valid_observer_chain_surface_ciphertext_at_rank
    {world : ShieldedTransactionWorld}
    {rank : Nat}
    (valid : validObserverChainSurface world)
    (rankLt : rank < world.ciphertextBytes.length) :
    ∃ wire summary,
      world.ciphertextBytes[rank]? = some wire
        ∧ world.ciphertextSummaries[rank]? = some summary
        ∧ parseChainNoteCiphertext wire = some summary
        ∧ summaryHasChainCiphertextFormat summary := by
  let wire := world.ciphertextBytes[rank]
  have wireAt :
      world.ciphertextBytes[rank]? = some wire := by
    exact
      List.getElem?_eq_getElem
        (l := world.ciphertextBytes)
        rankLt
  rcases
      parsed_chain_ciphertext_summary_at_rank
        valid.right.left
        wireAt with
    ⟨summary, summaryAt, parsedSummary, format⟩
  exact ⟨wire, summary, wireAt, summaryAt, parsedSummary, format⟩

theorem same_public_inputs_active_output_count
    {left right : ShieldedTransactionWorld}
    (publicInputs : samePublicInputs left right) :
    activeOutputCount left.publicInputs =
      activeOutputCount right.publicInputs :=
  congrArg activeOutputCount publicInputs

theorem same_batch_timing_leakage_of_valid_public_inputs_and_placement
    {left right : ShieldedTransactionWorld}
    (leftValid : validObserverChainSurface left)
    (rightValid : validObserverChainSurface right)
    (publicInputs : samePublicInputs left right)
    (placement : samePlacement left right) :
    sameBatchTimingLeakage left right := by
  have activeEq :
      activeOutputCount left.publicInputs =
        activeOutputCount right.publicInputs :=
    same_public_inputs_active_output_count publicInputs
  have ciphertextCountEq :
      left.ciphertextBytes.length = right.ciphertextBytes.length := by
    calc
      left.ciphertextBytes.length =
          activeOutputCount left.publicInputs :=
        leftValid.right.right
      _ = activeOutputCount right.publicInputs :=
        activeEq
      _ = right.ciphertextBytes.length :=
        rightValid.right.right.symm
  have summaryCountEq :
      left.ciphertextSummaries.length =
        right.ciphertextSummaries.length := by
    calc
      left.ciphertextSummaries.length =
          activeOutputCount left.publicInputs :=
        valid_observer_chain_surface_ciphertext_count leftValid
      _ = activeOutputCount right.publicInputs :=
        activeEq
      _ = right.ciphertextSummaries.length :=
        (valid_observer_chain_surface_ciphertext_count rightValid).symm
  cases placement with
  | intro heightEq actionEq =>
      unfold sameBatchTimingLeakage batchTimingView
      simp [activeEq, ciphertextCountEq, summaryCountEq, heightEq, actionEq]

theorem same_allowed_leakage_preserves_active_output_count
    {left right : ShieldedTransactionWorld}
    (same : sameAllowedLeakage left right) :
    activeOutputCount left.publicInputs =
      activeOutputCount right.publicInputs := by
  exact
    congrArg
      (fun view : ObserverView =>
        activeOutputCount view.publicInputs)
      same

theorem same_public_valid_observer_surfaces_ciphertext_count
    {left right : ShieldedTransactionWorld}
    (leftValid : validObserverChainSurface left)
    (rightValid : validObserverChainSurface right)
    (publicInputs : samePublicInputs left right) :
    left.ciphertextSummaries.length =
      right.ciphertextSummaries.length := by
  calc
    left.ciphertextSummaries.length =
        activeOutputCount left.publicInputs :=
      valid_observer_chain_surface_ciphertext_count leftValid
    _ = activeOutputCount right.publicInputs :=
      same_public_inputs_active_output_count publicInputs
    _ = right.ciphertextSummaries.length := by
      exact
        (valid_observer_chain_surface_ciphertext_count
          rightValid).symm

theorem same_allowed_leakage_of_public_chain_wire_and_placement
    {left right : ShieldedTransactionWorld}
    (leftParsed : summariesMatchChainWire left)
    (rightParsed : summariesMatchChainWire right)
    (publicInputs : samePublicInputs left right)
    (ciphertextBytes : left.ciphertextBytes = right.ciphertextBytes)
    (placement : samePlacement left right) :
    sameAllowedLeakage left right := by
  have summaries :
      left.ciphertextSummaries = right.ciphertextSummaries := by
    have parsedEq :
        some left.ciphertextSummaries =
          some right.ciphertextSummaries := by
      rw [← leftParsed, ← rightParsed, ciphertextBytes]
    exact Option.some.inj parsedEq
  exact
    same_allowed_leakage_of_public_wire_and_placement
      publicInputs
      ⟨ciphertextBytes, summaries⟩
      placement

theorem same_allowed_leakage_of_valid_observer_chain_surfaces
    {left right : ShieldedTransactionWorld}
    (leftValid : validObserverChainSurface left)
    (rightValid : validObserverChainSurface right)
    (publicInputs : samePublicInputs left right)
    (ciphertextBytes : left.ciphertextBytes = right.ciphertextBytes)
    (placement : samePlacement left right) :
    sameAllowedLeakage left right :=
  same_allowed_leakage_of_public_chain_wire_and_placement
    leftValid.right.left
    rightValid.right.left
    publicInputs
    ciphertextBytes
    placement

theorem same_allowed_leakage_iff_observer_view_eq
    {left right : ShieldedTransactionWorld} :
    sameAllowedLeakage left right ↔ observerView left = observerView right := by
  rfl

theorem same_allowed_leakage_stable_under_local_action_metadata
    {left right : ShieldedTransactionWorld}
    (same : sameAllowedLeakage left right)
    (leftLocal rightLocal : LocalActionMetadata) :
    sameAllowedLeakage
      { left with localActionMetadata := leftLocal }
      { right with localActionMetadata := rightLocal } := by
  exact same

theorem same_public_metadata_leakage_stable_under_local_action_metadata
    {left right : ShieldedTransactionWorld}
    (same : samePublicMetadataLeakage left right)
    (leftLocal rightLocal : LocalActionMetadata) :
    samePublicMetadataLeakage
      { left with localActionMetadata := leftLocal }
      { right with localActionMetadata := rightLocal } := by
  exact same

theorem same_batch_timing_leakage_stable_under_local_action_metadata
    {left right : ShieldedTransactionWorld}
    (same : sameBatchTimingLeakage left right)
    (leftLocal rightLocal : LocalActionMetadata) :
    sameBatchTimingLeakage
      { left with localActionMetadata := leftLocal }
      { right with localActionMetadata := rightLocal } := by
  exact same

theorem same_allowed_leakage_stable_under_local_address_metadata
    {left right : ShieldedTransactionWorld}
    (same : sameAllowedLeakage left right)
    (leftAddress rightAddress : LocalAddressMetadata) :
    sameAllowedLeakage
      { left with localAddressMetadata := leftAddress }
      { right with localAddressMetadata := rightAddress } := by
  exact same

theorem same_public_metadata_leakage_stable_under_local_address_metadata
    {left right : ShieldedTransactionWorld}
    (same : samePublicMetadataLeakage left right)
    (leftAddress rightAddress : LocalAddressMetadata) :
    samePublicMetadataLeakage
      { left with localAddressMetadata := leftAddress }
      { right with localAddressMetadata := rightAddress } := by
  exact same

theorem same_batch_timing_leakage_stable_under_local_address_metadata
    {left right : ShieldedTransactionWorld}
    (same : sameBatchTimingLeakage left right)
    (leftAddress rightAddress : LocalAddressMetadata) :
    sameBatchTimingLeakage
      { left with localAddressMetadata := leftAddress }
      { right with localAddressMetadata := rightAddress } := by
  exact same

theorem same_allowed_leakage_stable_under_local_wallet_bookkeeping_metadata
    {left right : ShieldedTransactionWorld}
    (same : sameAllowedLeakage left right)
    (leftWallet rightWallet : LocalWalletBookkeepingMetadata) :
    sameAllowedLeakage
      { left with localWalletBookkeepingMetadata := leftWallet }
      { right with localWalletBookkeepingMetadata := rightWallet } := by
  exact same

theorem same_public_metadata_leakage_stable_under_local_wallet_bookkeeping_metadata
    {left right : ShieldedTransactionWorld}
    (same : samePublicMetadataLeakage left right)
    (leftWallet rightWallet : LocalWalletBookkeepingMetadata) :
    samePublicMetadataLeakage
      { left with localWalletBookkeepingMetadata := leftWallet }
      { right with localWalletBookkeepingMetadata := rightWallet } := by
  exact same

theorem same_batch_timing_leakage_stable_under_local_wallet_bookkeeping_metadata
    {left right : ShieldedTransactionWorld}
    (same : sameBatchTimingLeakage left right)
    (leftWallet rightWallet : LocalWalletBookkeepingMetadata) :
    sameBatchTimingLeakage
      { left with localWalletBookkeepingMetadata := leftWallet }
      { right with localWalletBookkeepingMetadata := rightWallet } := by
  exact same

theorem same_allowed_leakage_stable_under_local_network_metadata
    {left right : ShieldedTransactionWorld}
    (same : sameAllowedLeakage left right)
    (leftNetwork rightNetwork : LocalNetworkMetadata) :
    sameAllowedLeakage
      { left with localNetworkMetadata := leftNetwork }
      { right with localNetworkMetadata := rightNetwork } := by
  exact same

theorem same_public_metadata_leakage_stable_under_local_network_metadata
    {left right : ShieldedTransactionWorld}
    (same : samePublicMetadataLeakage left right)
    (leftNetwork rightNetwork : LocalNetworkMetadata) :
    samePublicMetadataLeakage
      { left with localNetworkMetadata := leftNetwork }
      { right with localNetworkMetadata := rightNetwork } := by
  exact same

theorem same_batch_timing_leakage_stable_under_local_network_metadata
    {left right : ShieldedTransactionWorld}
    (same : sameBatchTimingLeakage left right)
    (leftNetwork rightNetwork : LocalNetworkMetadata) :
    sameBatchTimingLeakage
      { left with localNetworkMetadata := leftNetwork }
      { right with localNetworkMetadata := rightNetwork } := by
  exact same

theorem same_allowed_leakage_stable_under_all_local_metadata
    {left right : ShieldedTransactionWorld}
    (same : sameAllowedLeakage left right)
    (leftLocal rightLocal : LocalActionMetadata)
    (leftAddress rightAddress : LocalAddressMetadata)
    (leftNetwork rightNetwork : LocalNetworkMetadata) :
    sameAllowedLeakage
      { left with
        localActionMetadata := leftLocal
        localAddressMetadata := leftAddress
        localNetworkMetadata := leftNetwork }
      { right with
        localActionMetadata := rightLocal
        localAddressMetadata := rightAddress
        localNetworkMetadata := rightNetwork } := by
  exact same

theorem same_public_metadata_leakage_stable_under_all_local_metadata
    {left right : ShieldedTransactionWorld}
    (same : samePublicMetadataLeakage left right)
    (leftLocal rightLocal : LocalActionMetadata)
    (leftAddress rightAddress : LocalAddressMetadata)
    (leftNetwork rightNetwork : LocalNetworkMetadata) :
    samePublicMetadataLeakage
      { left with
        localActionMetadata := leftLocal
        localAddressMetadata := leftAddress
        localNetworkMetadata := leftNetwork }
      { right with
        localActionMetadata := rightLocal
        localAddressMetadata := rightAddress
        localNetworkMetadata := rightNetwork } := by
  exact same

theorem same_batch_timing_leakage_stable_under_all_local_metadata
    {left right : ShieldedTransactionWorld}
    (same : sameBatchTimingLeakage left right)
    (leftLocal rightLocal : LocalActionMetadata)
    (leftAddress rightAddress : LocalAddressMetadata)
    (leftNetwork rightNetwork : LocalNetworkMetadata) :
    sameBatchTimingLeakage
      { left with
        localActionMetadata := leftLocal
        localAddressMetadata := leftAddress
        localNetworkMetadata := leftNetwork }
      { right with
        localActionMetadata := rightLocal
        localAddressMetadata := rightAddress
        localNetworkMetadata := rightNetwork } := by
  exact same

theorem same_allowed_leakage_stable_under_all_wallet_local_metadata
    {left right : ShieldedTransactionWorld}
    (same : sameAllowedLeakage left right)
    (leftLocal rightLocal : LocalActionMetadata)
    (leftAddress rightAddress : LocalAddressMetadata)
    (leftWallet rightWallet : LocalWalletBookkeepingMetadata)
    (leftNetwork rightNetwork : LocalNetworkMetadata) :
    sameAllowedLeakage
      { left with
        localActionMetadata := leftLocal
        localAddressMetadata := leftAddress
        localWalletBookkeepingMetadata := leftWallet
        localNetworkMetadata := leftNetwork }
      { right with
        localActionMetadata := rightLocal
        localAddressMetadata := rightAddress
        localWalletBookkeepingMetadata := rightWallet
        localNetworkMetadata := rightNetwork } := by
  exact same

theorem same_public_metadata_leakage_stable_under_all_wallet_local_metadata
    {left right : ShieldedTransactionWorld}
    (same : samePublicMetadataLeakage left right)
    (leftLocal rightLocal : LocalActionMetadata)
    (leftAddress rightAddress : LocalAddressMetadata)
    (leftWallet rightWallet : LocalWalletBookkeepingMetadata)
    (leftNetwork rightNetwork : LocalNetworkMetadata) :
    samePublicMetadataLeakage
      { left with
        localActionMetadata := leftLocal
        localAddressMetadata := leftAddress
        localWalletBookkeepingMetadata := leftWallet
        localNetworkMetadata := leftNetwork }
      { right with
        localActionMetadata := rightLocal
        localAddressMetadata := rightAddress
        localWalletBookkeepingMetadata := rightWallet
        localNetworkMetadata := rightNetwork } := by
  exact same

theorem same_batch_timing_leakage_stable_under_all_wallet_local_metadata
    {left right : ShieldedTransactionWorld}
    (same : sameBatchTimingLeakage left right)
    (leftLocal rightLocal : LocalActionMetadata)
    (leftAddress rightAddress : LocalAddressMetadata)
    (leftWallet rightWallet : LocalWalletBookkeepingMetadata)
    (leftNetwork rightNetwork : LocalNetworkMetadata) :
    sameBatchTimingLeakage
      { left with
        localActionMetadata := leftLocal
        localAddressMetadata := leftAddress
        localWalletBookkeepingMetadata := leftWallet
        localNetworkMetadata := leftNetwork }
      { right with
        localActionMetadata := rightLocal
        localAddressMetadata := rightAddress
        localWalletBookkeepingMetadata := rightWallet
        localNetworkMetadata := rightNetwork } := by
  exact same

theorem valid_observer_chain_surface_stable_under_local_action_metadata
    {world : ShieldedTransactionWorld}
    (valid : validObserverChainSurface world)
    (localActionMetadata : LocalActionMetadata) :
    validObserverChainSurface
      { world with localActionMetadata := localActionMetadata } := by
  simpa [validObserverChainSurface, summariesMatchChainWire] using valid

theorem valid_observer_chain_surface_stable_under_local_address_metadata
    {world : ShieldedTransactionWorld}
    (valid : validObserverChainSurface world)
    (localAddressMetadata : LocalAddressMetadata) :
    validObserverChainSurface
      { world with localAddressMetadata := localAddressMetadata } := by
  simpa [validObserverChainSurface, summariesMatchChainWire] using valid

theorem valid_observer_chain_surface_stable_under_local_wallet_bookkeeping_metadata
    {world : ShieldedTransactionWorld}
    (valid : validObserverChainSurface world)
    (localWalletBookkeepingMetadata : LocalWalletBookkeepingMetadata) :
    validObserverChainSurface
      { world with
        localWalletBookkeepingMetadata := localWalletBookkeepingMetadata } := by
  simpa [validObserverChainSurface, summariesMatchChainWire] using valid

theorem valid_observer_chain_surface_stable_under_local_network_metadata
    {world : ShieldedTransactionWorld}
    (valid : validObserverChainSurface world)
    (localNetworkMetadata : LocalNetworkMetadata) :
    validObserverChainSurface
      { world with localNetworkMetadata := localNetworkMetadata } := by
  simpa [validObserverChainSurface, summariesMatchChainWire] using valid

theorem valid_observer_chain_surface_stable_under_all_local_metadata
    {world : ShieldedTransactionWorld}
    (valid : validObserverChainSurface world)
    (localActionMetadata : LocalActionMetadata)
    (localAddressMetadata : LocalAddressMetadata)
    (localNetworkMetadata : LocalNetworkMetadata) :
    validObserverChainSurface
      { world with
        localActionMetadata := localActionMetadata
        localAddressMetadata := localAddressMetadata
        localNetworkMetadata := localNetworkMetadata } := by
  simpa [validObserverChainSurface, summariesMatchChainWire] using valid

theorem valid_observer_chain_surface_stable_under_all_wallet_local_metadata
    {world : ShieldedTransactionWorld}
    (valid : validObserverChainSurface world)
    (localActionMetadata : LocalActionMetadata)
    (localAddressMetadata : LocalAddressMetadata)
    (localWalletBookkeepingMetadata : LocalWalletBookkeepingMetadata)
    (localNetworkMetadata : LocalNetworkMetadata) :
    validObserverChainSurface
      { world with
        localActionMetadata := localActionMetadata
        localAddressMetadata := localAddressMetadata
        localWalletBookkeepingMetadata := localWalletBookkeepingMetadata
        localNetworkMetadata := localNetworkMetadata } := by
  simpa [validObserverChainSurface, summariesMatchChainWire] using valid

theorem public_raw_wire_split_left_world_valid :
    validObserverChainSurface publicRawWireSplitLeftWorld := by
  constructor
  · exact validPublicInputShape_accepts_valid
  · constructor
    · unfold summariesMatchChainWire publicRawWireSplitLeftWorld
        parsedChainCiphertextSummaries
      simp [chain_valid_accepts, parsedChainCiphertextSummaries]
    · simp [publicRawWireSplitLeftWorld, activeOutputCount,
        activeFlagCount, validShape]

theorem public_raw_wire_split_right_world_valid :
    validObserverChainSurface publicRawWireSplitRightWorld := by
  constructor
  · exact validPublicInputShape_accepts_valid
  · constructor
    · unfold summariesMatchChainWire publicRawWireSplitRightWorld
        parsedChainCiphertextSummaries
      simp [alternate_chain_valid_accepts, parsedChainCiphertextSummaries]
    · simp [publicRawWireSplitRightWorld, activeOutputCount,
        activeFlagCount, validShape]

theorem public_raw_wire_split_worlds_same_public_metadata :
    samePublicMetadataLeakage
      publicRawWireSplitLeftWorld
      publicRawWireSplitRightWorld := by
  rfl

theorem public_raw_wire_split_worlds_same_batch_timing :
    sameBatchTimingLeakage
      publicRawWireSplitLeftWorld
      publicRawWireSplitRightWorld := by
  rfl

theorem public_raw_wire_split_worlds_different_raw_ciphertext_bytes :
    publicRawWireSplitLeftWorld.ciphertextBytes ≠
      publicRawWireSplitRightWorld.ciphertextBytes := by
  intro same
  apply valid_and_alternate_chain_wires_differ
  simpa [publicRawWireSplitLeftWorld, publicRawWireSplitRightWorld] using same

theorem public_raw_wire_split_worlds_not_same_allowed_leakage :
    ¬ sameAllowedLeakage
        publicRawWireSplitLeftWorld
        publicRawWireSplitRightWorld := by
  intro same
  have bytesEq :
      publicRawWireSplitLeftWorld.ciphertextBytes =
        publicRawWireSplitRightWorld.ciphertextBytes := by
    exact congrArg ObserverView.ciphertextBytes same
  exact public_raw_wire_split_worlds_different_raw_ciphertext_bytes bytesEq

theorem public_metadata_equal_with_different_raw_chain_wire :
    validObserverChainSurface publicRawWireSplitLeftWorld
      ∧ validObserverChainSurface publicRawWireSplitRightWorld
      ∧ samePublicMetadataLeakage
          publicRawWireSplitLeftWorld
          publicRawWireSplitRightWorld
      ∧ sameBatchTimingLeakage
          publicRawWireSplitLeftWorld
          publicRawWireSplitRightWorld
      ∧ publicRawWireSplitLeftWorld.ciphertextBytes ≠
          publicRawWireSplitRightWorld.ciphertextBytes
      ∧ ¬ sameAllowedLeakage
          publicRawWireSplitLeftWorld
          publicRawWireSplitRightWorld := by
  exact
    ⟨public_raw_wire_split_left_world_valid,
      public_raw_wire_split_right_world_valid,
      public_raw_wire_split_worlds_same_public_metadata,
      public_raw_wire_split_worlds_same_batch_timing,
      public_raw_wire_split_worlds_different_raw_ciphertext_bytes,
      public_raw_wire_split_worlds_not_same_allowed_leakage⟩

end Observer
end Privacy
end Hegemon
