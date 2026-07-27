import Hegemon.Consensus.Supply
import Hegemon.Transaction.CanonicalVerifierBoundary
import Hegemon.Transaction.SmallWoodProductionConstraintRefinement

set_option maxRecDepth 10000

namespace Hegemon
namespace Consensus
namespace AcceptedSmallWoodBlockComposition

open Hegemon.Transaction
open Hegemon.Transaction.AcceptedTransactionSoundness
open Hegemon.Transaction.CanonicalVerifierBoundary
open Hegemon.Transaction.ProofWrapperAdmission
open Hegemon.Transaction.SmallWoodProductionConstraintRefinement
open Hegemon.Transaction.SmallWoodSemanticClosure
open Hegemon.Transaction.SpendAuthorization

def activeSmallWoodCircuitVersion : Nat := 3

def activeSmallWoodCryptoSuite : Nat := 2

def activeSmallWoodVersionAccepts (circuitVersion cryptoSuite : Nat) : Bool :=
  circuitVersion == activeSmallWoodCircuitVersion
    && cryptoSuite == activeSmallWoodCryptoSuite

theorem active_smallwood_version_accepts_iff
    (circuitVersion cryptoSuite : Nat) :
    activeSmallWoodVersionAccepts circuitVersion cryptoSuite = true ↔
      circuitVersion = activeSmallWoodCircuitVersion
        ∧ cryptoSuite = activeSmallWoodCryptoSuite := by
  simp [activeSmallWoodVersionAccepts]

structure CanonicalTxIdentity where
  transactionNullifiers : List (List Byte)
  transactionCommitments : List (List Byte)
  transactionCiphertextHashes : List (List Byte)
  transactionBalanceTag : List Byte
  statementBytes : List Byte
  bindingBytes : List Byte
  statementHash : Digest
  proofDigest : Digest
  publicInputsDigest : Digest
  verifierProfile : Digest
  anchorRoot : Digest
  fee : Nat
  bindingCircuitVersion : Nat
  transactionCircuitVersion : Nat
  transactionCryptoSuite : Nat
  ciphertexts : List (List Byte)
deriving DecidableEq, Repr

structure CanonicalTxClaim where
  statementHash : Digest
  proofDigest : Digest
  publicInputsDigest : Digest
  verifierProfile : Digest
  anchorRoot : Digest
  fee : Nat
  bindingCircuitVersion : Nat
deriving DecidableEq, Repr

structure CanonicalBlockIdentityProjection where
  txCount : Nat
  orderedTxIds : List (List Byte)
  orderedStatementHashes : List Digest
  orderedProofDigests : List Digest
  orderedPublicInputsDigests : List Digest
  orderedVerifierProfiles : List Digest
  orderedAnchorRoots : List Digest
  orderedFees : List Nat
  orderedBindingCircuitVersions : List Nat
  orderedTransactionCircuitVersions : List Nat
  orderedTransactionCryptoSuites : List Nat
  txStatementsCommitment : Digest
  daRoot : Digest
  daChunkCount : Nat
deriving DecidableEq, Repr

structure CanonicalProvenBatchBinding where
  txCount : Nat
  txStatementsCommitment : Digest
  daRoot : Digest
  daChunkCount : Nat
deriving DecidableEq, Repr

structure ProductionIdentityFunctions where
  txId : List Byte -> List Byte
  ciphertextHash : List Byte -> List Byte
  statementHash : List Byte -> Digest
  proofDigest : List Byte -> Digest
  publicInputsDigest : List Byte -> Digest
  statementCommitment : List Digest -> Digest
  daRoot : List Byte -> Digest
  daChunkCount : List Byte -> Nat

structure DeployedSmallWoodProof where
  exactMap : ProductionConstraintMap
  noteHashSpec : ProductionNoteHashSpec
  wrapper : ProofWrapperInput
  shape : PublicInputs.PublicInputShape
  publicFields : PublicInputBinding.PublicFields
  serializedFields : PublicInputBinding.SerializedFields
  bound : PublicInputBinding.BoundPublicInputs
  statementFields : StatementHash.StatementFields
  statementBytes : List Byte
  bindingFields : ProofStatementBinding.BindingFields
  bindingBytes : List Byte
  merkleRoot : Digest
  ciphertexts : List (List Byte)
  proofBytes : List Byte
  serializedPublicInputBytes : List Byte
  verifierProfile : Digest

def activeDigests : List Nat -> List Digest -> List Digest
  | flag :: flags, value :: values =>
      if flag = 1 then value :: activeDigests flags values
      else activeDigests flags values
  | _, _ => []

structure DeployedSmallWoodProofAccepted
    (verifier : ProductionSmallWoodProofVerifier)
    (hashes : ProductionIdentityFunctions)
    (proof : DeployedSmallWoodProof) : Prop where
  exactArtifactAccepted :
    verifier.accepts proof.proofBytes proof.serializedPublicInputBytes
      proof.verifierProfile proof.wrapper = true
  activeCircuitVersion :
    proof.statementFields.circuitVersion = activeSmallWoodCircuitVersion
  activeCryptoSuite :
    proof.statementFields.cryptoSuite = activeSmallWoodCryptoSuite
  constraintMapBound : ProductionConstraintMapBound proof.exactMap
  constraintPublicValuesBound :
    proof.exactMap.publicValues =
      productionVerifierPublicValues proof.bound proof.statementFields
  canonicalSurface :
    CanonicalTxStatementSurface proof.wrapper proof.shape proof.publicFields
      proof.serializedFields proof.bound proof.statementFields proof.statementBytes
      proof.bindingFields proof.bindingBytes proof.merkleRoot
  ciphertextPayloadHashes :
    proof.ciphertexts.map hashes.ciphertextHash =
      (activeDigests proof.shape.outputFlags proof.shape.ciphertextHashes).map
        StatementHash.digestBytes

def digestSequenceBytes (digests : List (List Byte)) : List Byte :=
  digests.flatten

def transactionHashPreimage (tx : CanonicalTxIdentity) : List Byte :=
  u16le tx.transactionCircuitVersion
    ++ u16le tx.transactionCryptoSuite
    ++ digestSequenceBytes tx.transactionNullifiers
    ++ digestSequenceBytes tx.transactionCommitments
    ++ digestSequenceBytes tx.transactionCiphertextHashes
    ++ tx.transactionBalanceTag

def canonicalTransactionId
    (hashes : ProductionIdentityFunctions)
    (tx : CanonicalTxIdentity) : List Byte :=
  hashes.txId (transactionHashPreimage tx)

def transactionDaBlobBytes (tx : CanonicalTxIdentity) : List Byte :=
  u32le tx.ciphertexts.length
    ++ (tx.ciphertexts.map fun ciphertext =>
      u32le ciphertext.length ++ ciphertext).flatten

def canonicalBlockDaBlob (transactions : List CanonicalTxIdentity) : List Byte :=
  u32le transactions.length ++ (transactions.map transactionDaBlobBytes).flatten

def DeployedSmallWoodProof.identity
    (hashes : ProductionIdentityFunctions)
    (proof : DeployedSmallWoodProof) : CanonicalTxIdentity :=
  { transactionNullifiers :=
      (activeDigests proof.shape.inputFlags proof.shape.nullifiers).map
        StatementHash.digestBytes
    transactionCommitments :=
      (activeDigests proof.shape.outputFlags proof.shape.commitments).map
        StatementHash.digestBytes
    transactionCiphertextHashes :=
      (activeDigests proof.shape.outputFlags proof.shape.ciphertextHashes).map
        StatementHash.digestBytes
    transactionBalanceTag :=
      StatementHash.digestBytes proof.statementFields.balanceTagSeed
    statementBytes := proof.statementBytes
    bindingBytes := proof.bindingBytes
    statementHash := hashes.statementHash proof.statementBytes
    proofDigest := hashes.proofDigest proof.proofBytes
    publicInputsDigest :=
      hashes.publicInputsDigest proof.serializedPublicInputBytes
    verifierProfile := proof.verifierProfile
    anchorRoot := proof.bindingFields.anchorSeed
    fee := proof.bindingFields.fee
    bindingCircuitVersion := proof.statementFields.circuitVersion
    transactionCircuitVersion := proof.statementFields.circuitVersion
    transactionCryptoSuite := proof.statementFields.cryptoSuite
    ciphertexts := proof.ciphertexts }

theorem deployed_smallwood_identity_uses_exact_transaction_hash_preimage
    (hashes : ProductionIdentityFunctions)
    (proof : DeployedSmallWoodProof) :
    transactionHashPreimage (proof.identity hashes) =
      u16le proof.statementFields.circuitVersion
        ++ u16le proof.statementFields.cryptoSuite
        ++ digestSequenceBytes
          ((activeDigests proof.shape.inputFlags proof.shape.nullifiers).map
            StatementHash.digestBytes)
        ++ digestSequenceBytes
          ((activeDigests proof.shape.outputFlags proof.shape.commitments).map
            StatementHash.digestBytes)
        ++ digestSequenceBytes
          ((activeDigests proof.shape.outputFlags proof.shape.ciphertextHashes).map
            StatementHash.digestBytes)
        ++ StatementHash.digestBytes proof.statementFields.balanceTagSeed := by
  rfl

theorem deployed_smallwood_identity_binds_ciphertext_payload_hashes
    (verifier : ProductionSmallWoodProofVerifier)
    (hashes : ProductionIdentityFunctions)
    (proof : DeployedSmallWoodProof)
    (accepted : DeployedSmallWoodProofAccepted verifier hashes proof) :
    proof.ciphertexts.map hashes.ciphertextHash =
      (activeDigests proof.shape.outputFlags proof.shape.ciphertextHashes).map
        StatementHash.digestBytes :=
  accepted.ciphertextPayloadHashes

def CanonicalTxIdentity.claim (tx : CanonicalTxIdentity) : CanonicalTxClaim :=
  { statementHash := tx.statementHash
    proofDigest := tx.proofDigest
    publicInputsDigest := tx.publicInputsDigest
    verifierProfile := tx.verifierProfile
    anchorRoot := tx.anchorRoot
    fee := tx.fee
    bindingCircuitVersion := tx.bindingCircuitVersion }

def expectedClaims (transactions : List CanonicalTxIdentity) : List CanonicalTxClaim :=
  transactions.map CanonicalTxIdentity.claim

def expectedIdentityProjection
    (hashes : ProductionIdentityFunctions)
    (transactions : List CanonicalTxIdentity) : CanonicalBlockIdentityProjection :=
  { txCount := transactions.length
    orderedTxIds := transactions.map (canonicalTransactionId hashes)
    orderedStatementHashes := transactions.map (fun tx => tx.statementHash)
    orderedProofDigests := transactions.map (fun tx => tx.proofDigest)
    orderedPublicInputsDigests :=
      transactions.map (fun tx => tx.publicInputsDigest)
    orderedVerifierProfiles := transactions.map (fun tx => tx.verifierProfile)
    orderedAnchorRoots := transactions.map (fun tx => tx.anchorRoot)
    orderedFees := transactions.map (fun tx => tx.fee)
    orderedBindingCircuitVersions :=
      transactions.map (fun tx => tx.bindingCircuitVersion)
    orderedTransactionCircuitVersions :=
      transactions.map (fun tx => tx.transactionCircuitVersion)
    orderedTransactionCryptoSuites :=
      transactions.map (fun tx => tx.transactionCryptoSuite)
    txStatementsCommitment :=
      hashes.statementCommitment (transactions.map (fun tx => tx.statementHash))
    daRoot := hashes.daRoot (canonicalBlockDaBlob transactions)
    daChunkCount := hashes.daChunkCount (canonicalBlockDaBlob transactions) }

def expectedProvenBatchBinding
    (projection : CanonicalBlockIdentityProjection) : CanonicalProvenBatchBinding :=
  { txCount := projection.txCount
    txStatementsCommitment := projection.txStatementsCommitment
    daRoot := projection.daRoot
    daChunkCount := projection.daChunkCount }

inductive CanonicalAction (Transfer : Type) where
  | transfer (value : Transfer)
  | coinbase (amount : Nat)

structure ProductionActionCodec (Transfer : Type) where
  decodeExact : List Byte -> Option (CanonicalAction Transfer)

def decodeCanonicalActionStream
    {Transfer : Type}
    (codec : ProductionActionCodec Transfer) :
    List (List Byte) -> Option (List (CanonicalAction Transfer))
  | [] => some []
  | bytes :: rest =>
      match codec.decodeExact bytes, decodeCanonicalActionStream codec rest with
      | some action, some actions => some (action :: actions)
      | _, _ => none

def canonicalTransfers {Transfer : Type} : List (CanonicalAction Transfer) -> List Transfer
  | [] => []
  | .transfer transfer :: actions => transfer :: canonicalTransfers actions
  | .coinbase _ :: actions => canonicalTransfers actions

def canonicalCoinbaseAmounts {Transfer : Type} : List (CanonicalAction Transfer) -> List Nat
  | [] => []
  | .transfer _ :: actions => canonicalCoinbaseAmounts actions
  | .coinbase amount :: actions => amount :: canonicalCoinbaseAmounts actions

def canonicalTransactions
    {Transfer : Type}
    (toIdentity : Transfer -> CanonicalTxIdentity)
    (actions : List (CanonicalAction Transfer)) : List CanonicalTxIdentity :=
  (canonicalTransfers actions).map toIdentity

structure CanonicalSupplyTransition where
  height : Nat
  parentBlockHash : Digest
  parentSupply : Nat
  orderedFees : List Nat
  exactFeeTotal : Nat
  checkedFeeTotal : Option Nat
  acceptedBurns : List Nat
  coinbaseCount : Nat
  observedCoinbaseAmount : Option Nat
  expectedCoinbaseAmount : Option Nat
  hasCoinbase : Bool
  supplyDelta : Nat
  claimedSupply : Nat
deriving DecidableEq, Repr

structure CanonicalBlockHeaderIdentity where
  height : Nat
  parentBlockHash : Digest
  actionCount : Nat
  txStatementsCommitment : Digest
  daRoot : Digest
  daChunkCount : Nat
  claimedSupply : Nat
deriving DecidableEq, Repr

structure AcceptedParentState where
  blockHash : Digest
  height : Nat
  supply : Nat
deriving DecidableEq, Repr

structure AcceptedCanonicalBlock where
  parent : AcceptedParentState
  header : CanonicalBlockHeaderIdentity
  actionBytes : List (List Byte)
  claims : List CanonicalTxClaim
  identityProjection : CanonicalBlockIdentityProjection
  provenBatch : CanonicalProvenBatchBinding
  supply : CanonicalSupplyTransition
deriving DecidableEq, Repr

def canonicalFeeAmounts (transactions : List CanonicalTxIdentity) : List Nat :=
  transactions.map (fun tx => tx.fee)

def canonicalFeeTotal (transactions : List CanonicalTxIdentity) : Nat :=
  (canonicalFeeAmounts transactions).sum

def expectedCheckedFeeTotal (transactions : List CanonicalTxIdentity) : Option Nat :=
  let feeTotal := canonicalFeeTotal transactions
  if feeTotal <= maxU64 then some feeTotal else none

-- The deployed native action grammar has no independent burn action.
def canonicalAcceptedBurns (_transactions : List CanonicalTxIdentity) : List Nat :=
  []

def observedCoinbaseAmount (coinbaseAmounts : List Nat) : Option Nat :=
  match coinbaseAmounts with
  | [amount] => some amount
  | _ => none

def expectedCoinbaseAmount
    (transactions : List CanonicalTxIdentity)
    (coinbaseAmounts : List Nat)
    (supply : CanonicalSupplyTransition) : Option Nat :=
  if coinbaseAmounts.length = 1 then
    nativeCoinbaseAmount supply.height (canonicalFeeTotal transactions)
  else
    none

def expectedClaimedSupply
    (transactions : List CanonicalTxIdentity)
    (coinbaseAmounts : List Nat)
    (supply : CanonicalSupplyTransition) : Option Nat :=
  advanceNativeSupplyDigest supply.parentSupply supply.height
    (canonicalFeeTotal transactions) (coinbaseAmounts.length = 1)

def expectedSupplyDelta
    (transactions : List CanonicalTxIdentity)
    (coinbaseAmounts : List Nat)
    (supply : CanonicalSupplyTransition) : Nat :=
  (nativeSupplyDelta supply.height (canonicalFeeTotal transactions)
    (coinbaseAmounts.length = 1)).getD 0

def canonicalSupplyAccepts
    (transactions : List CanonicalTxIdentity)
    (coinbaseAmounts : List Nat)
    (supply : CanonicalSupplyTransition) : Bool :=
  supply.orderedFees = canonicalFeeAmounts transactions
    && supply.exactFeeTotal = canonicalFeeTotal transactions
    && supply.checkedFeeTotal = expectedCheckedFeeTotal transactions
    && supply.acceptedBurns = canonicalAcceptedBurns transactions
    && supply.coinbaseCount = coinbaseAmounts.length
    && supply.coinbaseCount <= 1
    && supply.hasCoinbase = (coinbaseAmounts.length = 1)
    && supply.observedCoinbaseAmount = observedCoinbaseAmount coinbaseAmounts
    && supply.expectedCoinbaseAmount = expectedCoinbaseAmount transactions coinbaseAmounts supply
    && supply.observedCoinbaseAmount = supply.expectedCoinbaseAmount
    && supply.supplyDelta = expectedSupplyDelta transactions coinbaseAmounts supply
    && expectedClaimedSupply transactions coinbaseAmounts supply = some supply.claimedSupply

def canonicalHeaderAccepts
    (acceptedParent : AcceptedParentState)
    (block : AcceptedCanonicalBlock) : Bool :=
  block.parent = acceptedParent
    && block.header.parentBlockHash = acceptedParent.blockHash
    && block.supply.parentBlockHash = acceptedParent.blockHash
    && block.header.height = acceptedParent.height + 1
    && block.supply.height = acceptedParent.height + 1
    && block.supply.parentSupply = acceptedParent.supply
    && block.header.height = block.supply.height
    && block.header.parentBlockHash = block.supply.parentBlockHash
    && block.header.actionCount = block.actionBytes.length
    && block.header.txStatementsCommitment = block.identityProjection.txStatementsCommitment
    && block.header.daRoot = block.identityProjection.daRoot
    && block.header.daChunkCount = block.identityProjection.daChunkCount
    && block.header.claimedSupply = block.supply.claimedSupply

def canonicalBlockAcceptsDecoded
    {Transfer : Type}
    (hashes : ProductionIdentityFunctions)
    (toIdentity : Transfer -> CanonicalTxIdentity)
    (acceptedParent : AcceptedParentState)
    (actions : List (CanonicalAction Transfer))
    (block : AcceptedCanonicalBlock) : Bool :=
  let transactions := canonicalTransactions toIdentity actions
  let coinbaseAmounts := canonicalCoinbaseAmounts actions
  canonicalHeaderAccepts acceptedParent block
    && block.claims = expectedClaims transactions
    && block.identityProjection = expectedIdentityProjection hashes transactions
    && block.provenBatch = expectedProvenBatchBinding block.identityProjection
    && canonicalSupplyAccepts transactions coinbaseAmounts block.supply

def canonicalBlockAccepts
    {Transfer : Type}
    (codec : ProductionActionCodec Transfer)
    (hashes : ProductionIdentityFunctions)
    (toIdentity : Transfer -> CanonicalTxIdentity)
    (acceptedParent : AcceptedParentState)
    (block : AcceptedCanonicalBlock) : Bool :=
  match decodeCanonicalActionStream codec block.actionBytes with
  | some actions =>
      canonicalBlockAcceptsDecoded hashes toIdentity acceptedParent actions block
  | none => false

structure AcceptedDeployedSmallWoodBlock
    (codec : ProductionActionCodec DeployedSmallWoodProof)
    (verifier : ProductionSmallWoodProofVerifier)
    (hashes : ProductionIdentityFunctions)
    (acceptedParent : AcceptedParentState)
    (block : AcceptedCanonicalBlock) : Prop where
  canonicalBlockAccepted :
    canonicalBlockAccepts codec hashes (DeployedSmallWoodProof.identity hashes)
      acceptedParent block = true
  decodedProofsAccepted :
    forall actions,
      decodeCanonicalActionStream codec block.actionBytes = some actions ->
      forall proof, proof ∈ canonicalTransfers actions ->
        DeployedSmallWoodProofAccepted verifier hashes proof

def DeployedSmallWoodBlockKnowledgeSoundnessEvidence
    (codec : ProductionActionCodec DeployedSmallWoodProof)
    (verifier : ProductionSmallWoodProofVerifier)
    (block : AcceptedCanonicalBlock) : Type :=
  forall actions,
    decodeCanonicalActionStream codec block.actionBytes = some actions ->
    forall proof, proof ∈ canonicalTransfers actions ->
      DeployedSmallWoodKnowledgeSoundnessEvidence verifier proof.exactMap
        proof.proofBytes proof.serializedPublicInputBytes proof.verifierProfile proof.wrapper

def DeployedSmallWoodBlockPoseidon2HashCollisionResistance
    (codec : ProductionActionCodec DeployedSmallWoodProof)
    (block : AcceptedCanonicalBlock) : Prop :=
  forall actions,
    decodeCanonicalActionStream codec block.actionBytes = some actions ->
    forall proof, proof ∈ canonicalTransfers actions ->
      ProductionPoseidon2HashCollisionResistance proof.noteHashSpec

structure RecursiveCrossObjectIdentityFacts
    (hashes : ProductionIdentityFunctions)
    (transactions : List CanonicalTxIdentity)
    (acceptedParent : AcceptedParentState)
    (block : AcceptedCanonicalBlock) : Prop where
  exactHeaderIdentity :
    block.parent = acceptedParent
      ∧ block.header.parentBlockHash = acceptedParent.blockHash
      ∧ block.supply.parentBlockHash = acceptedParent.blockHash
      ∧ block.header.height = acceptedParent.height + 1
      ∧ block.supply.height = acceptedParent.height + 1
      ∧ block.supply.parentSupply = acceptedParent.supply
      ∧ block.header.height = block.supply.height
      ∧ block.header.parentBlockHash = block.supply.parentBlockHash
      ∧ block.header.actionCount = block.actionBytes.length
      ∧ block.header.txStatementsCommitment = block.identityProjection.txStatementsCommitment
      ∧ block.header.daRoot = block.identityProjection.daRoot
      ∧ block.header.daChunkCount = block.identityProjection.daChunkCount
      ∧ block.header.claimedSupply = block.supply.claimedSupply
  exactClaims : block.claims = expectedClaims transactions
  exactIdentityProjection :
    block.identityProjection = expectedIdentityProjection hashes transactions
  exactProvenBatchBinding :
    block.provenBatch = expectedProvenBatchBinding block.identityProjection
  orderedTransactionCompleteness :
    block.identityProjection.txCount = transactions.length
      ∧ block.identityProjection.orderedTxIds =
        transactions.map (canonicalTransactionId hashes)
  orderedRecursiveClaims :
    block.identityProjection.orderedStatementHashes = transactions.map (fun tx => tx.statementHash)
      ∧ block.identityProjection.orderedProofDigests = transactions.map (fun tx => tx.proofDigest)
      ∧ block.identityProjection.orderedPublicInputsDigests =
        transactions.map (fun tx => tx.publicInputsDigest)
  orderedBindingFields :
    block.identityProjection.orderedVerifierProfiles = transactions.map (fun tx => tx.verifierProfile)
      ∧ block.identityProjection.orderedAnchorRoots = transactions.map (fun tx => tx.anchorRoot)
      ∧ block.identityProjection.orderedFees = transactions.map (fun tx => tx.fee)
      ∧ block.identityProjection.orderedBindingCircuitVersions =
        transactions.map (fun tx => tx.bindingCircuitVersion)
  transactionVersionBinding :
    block.identityProjection.orderedTransactionCircuitVersions =
        transactions.map (fun tx => tx.transactionCircuitVersion)
      ∧ block.identityProjection.orderedTransactionCryptoSuites =
        transactions.map (fun tx => tx.transactionCryptoSuite)
  recursiveAndDaBinding :
    block.identityProjection.txStatementsCommitment =
        hashes.statementCommitment (transactions.map (fun tx => tx.statementHash))
      ∧ block.identityProjection.daRoot = hashes.daRoot (canonicalBlockDaBlob transactions)
      ∧ block.identityProjection.daChunkCount =
        hashes.daChunkCount (canonicalBlockDaBlob transactions)
      ∧ block.provenBatch.txCount = block.identityProjection.txCount
      ∧ block.provenBatch.txStatementsCommitment = block.identityProjection.txStatementsCommitment
      ∧ block.provenBatch.daRoot = block.identityProjection.daRoot
      ∧ block.provenBatch.daChunkCount = block.identityProjection.daChunkCount

theorem recursive_identity_facts_of_decoded_acceptance
    {hashes : ProductionIdentityFunctions}
    {transactions : List CanonicalTxIdentity}
    {acceptedParent : AcceptedParentState}
    {block : AcceptedCanonicalBlock}
    (accepted :
      canonicalHeaderAccepts acceptedParent block = true
        ∧ block.claims = expectedClaims transactions
        ∧ block.identityProjection = expectedIdentityProjection hashes transactions
        ∧ block.provenBatch = expectedProvenBatchBinding block.identityProjection) :
    RecursiveCrossObjectIdentityFacts hashes transactions acceptedParent block := by
  rcases accepted with ⟨header, claims, projection, batch⟩
  refine
    { exactHeaderIdentity := by
        simp only [canonicalHeaderAccepts, Bool.and_eq_true] at header
        rcases header with
          ⟨⟨⟨⟨⟨⟨⟨⟨⟨⟨⟨⟨acceptedParentBound, parentHeader⟩,
            parentSupplyHash⟩, headerHeight⟩, supplyHeight⟩, parentSupply⟩,
            equalHeight⟩,
            equalParent⟩, actionCount⟩, statementCommitment⟩, daRoot⟩,
            daChunkCount⟩, claimedSupply⟩
        exact
          ⟨of_decide_eq_true acceptedParentBound, of_decide_eq_true parentHeader,
            of_decide_eq_true parentSupplyHash,
            of_decide_eq_true headerHeight, of_decide_eq_true supplyHeight,
            of_decide_eq_true parentSupply, of_decide_eq_true equalHeight,
            of_decide_eq_true equalParent, of_decide_eq_true actionCount,
            of_decide_eq_true statementCommitment, of_decide_eq_true daRoot,
            of_decide_eq_true daChunkCount, of_decide_eq_true claimedSupply⟩
      exactClaims := claims
      exactIdentityProjection := projection
      exactProvenBatchBinding := batch
      orderedTransactionCompleteness := ?_
      orderedRecursiveClaims := ?_
      orderedBindingFields := ?_
      transactionVersionBinding := ?_
      recursiveAndDaBinding := ?_ }
  · rw [projection]
    simp [expectedIdentityProjection]
  · rw [projection]
    simp [expectedIdentityProjection]
  · rw [projection]
    simp [expectedIdentityProjection]
  · rw [projection]
    simp [expectedIdentityProjection]
  · rw [batch, projection]
    simp [expectedIdentityProjection, expectedProvenBatchBinding]

theorem accepted_recursive_cross_object_identity_refines_one_canonical_block
    {Transfer : Type}
    {codec : ProductionActionCodec Transfer}
    {hashes : ProductionIdentityFunctions}
    {toIdentity : Transfer -> CanonicalTxIdentity}
    {acceptedParent : AcceptedParentState}
    {block : AcceptedCanonicalBlock}
    (accepted : canonicalBlockAccepts codec hashes toIdentity acceptedParent block = true) :
    exists actions,
      decodeCanonicalActionStream codec block.actionBytes = some actions
        ∧ RecursiveCrossObjectIdentityFacts hashes
          (canonicalTransactions toIdentity actions) acceptedParent block := by
  unfold canonicalBlockAccepts at accepted
  generalize decoded : decodeCanonicalActionStream codec block.actionBytes = result at accepted
  cases result with
  | none => simp at accepted
  | some actions =>
      refine ⟨actions, rfl, ?_⟩
      simp [canonicalBlockAcceptsDecoded] at accepted
      exact recursive_identity_facts_of_decoded_acceptance
        ⟨accepted.1.1.1.1, accepted.1.1.1.2, accepted.1.1.2, accepted.1.2⟩

structure CanonicalSupplyCompositionFacts
    (parent : AcceptedParentState)
    (transactions : List CanonicalTxIdentity)
    (coinbaseAmounts : List Nat)
    (supply : CanonicalSupplyTransition) : Prop where
  acceptedParentHash : supply.parentBlockHash = parent.blockHash
  acceptedNextHeight : supply.height = parent.height + 1
  acceptedParentSupply : supply.parentSupply = parent.supply
  orderedFees : supply.orderedFees = canonicalFeeAmounts transactions
  exactFeeTotal : supply.exactFeeTotal = canonicalFeeTotal transactions
  checkedFeeTotal : supply.checkedFeeTotal = expectedCheckedFeeTotal transactions
  acceptedBurns : supply.acceptedBurns = []
  coinbaseCount : supply.coinbaseCount = coinbaseAmounts.length
  atMostOneCoinbase : supply.coinbaseCount <= 1
  hasCoinbase : supply.hasCoinbase = decide (coinbaseAmounts.length = 1)
  observedCoinbase : supply.observedCoinbaseAmount = observedCoinbaseAmount coinbaseAmounts
  expectedCoinbase :
    supply.expectedCoinbaseAmount = expectedCoinbaseAmount transactions coinbaseAmounts supply
  exactCoinbase : supply.observedCoinbaseAmount = supply.expectedCoinbaseAmount
  supplyDelta : supply.supplyDelta = expectedSupplyDelta transactions coinbaseAmounts supply
  claimedSupply :
    expectedClaimedSupply transactions coinbaseAmounts supply = some supply.claimedSupply

theorem supply_facts_of_decoded_acceptance
    {parent : AcceptedParentState}
    {transactions : List CanonicalTxIdentity}
    {coinbaseAmounts : List Nat}
    {supply : CanonicalSupplyTransition}
    (parentHash : supply.parentBlockHash = parent.blockHash)
    (nextHeight : supply.height = parent.height + 1)
    (parentSupply : supply.parentSupply = parent.supply)
    (accepted : canonicalSupplyAccepts transactions coinbaseAmounts supply = true) :
    CanonicalSupplyCompositionFacts parent transactions coinbaseAmounts supply := by
  simp [canonicalSupplyAccepts, canonicalAcceptedBurns] at accepted
  rcases accepted with
    ⟨⟨⟨⟨⟨⟨⟨⟨⟨⟨⟨fees, exactFees⟩, checkedFees⟩, burns⟩, coinbaseCount⟩,
      atMostOne⟩, hasCoinbase⟩, observedCoinbase⟩, expectedCoinbase⟩,
      exactCoinbase⟩, supplyDelta⟩, claimedSupply⟩
  exact
    { acceptedParentHash := parentHash
      acceptedNextHeight := nextHeight
      acceptedParentSupply := parentSupply
      orderedFees := fees
      exactFeeTotal := exactFees
      checkedFeeTotal := checkedFees
      acceptedBurns := burns
      coinbaseCount := coinbaseCount
      atMostOneCoinbase := atMostOne
      hasCoinbase := hasCoinbase
      observedCoinbase := observedCoinbase
      expectedCoinbase := expectedCoinbase
      exactCoinbase := exactCoinbase
      supplyDelta := supplyDelta
      claimedSupply := claimedSupply }

theorem consensus_accepted_chain_supply_composition
    {Transfer : Type}
    {codec : ProductionActionCodec Transfer}
    {hashes : ProductionIdentityFunctions}
    {toIdentity : Transfer -> CanonicalTxIdentity}
    {acceptedParent : AcceptedParentState}
    {block : AcceptedCanonicalBlock}
    (accepted : canonicalBlockAccepts codec hashes toIdentity acceptedParent block = true) :
    exists actions,
      decodeCanonicalActionStream codec block.actionBytes = some actions
        ∧ CanonicalSupplyCompositionFacts
          acceptedParent
          (canonicalTransactions toIdentity actions)
          (canonicalCoinbaseAmounts actions)
          block.supply := by
  unfold canonicalBlockAccepts at accepted
  generalize decoded : decodeCanonicalActionStream codec block.actionBytes = result at accepted
  cases result with
  | none => simp at accepted
  | some actions =>
      refine ⟨actions, rfl, ?_⟩
      simp [canonicalBlockAcceptsDecoded] at accepted
      have header := accepted.1.1.1.1
      simp only [canonicalHeaderAccepts, Bool.and_eq_true] at header
      rcases header with
        ⟨⟨⟨⟨⟨⟨⟨⟨⟨⟨⟨⟨_, _⟩, parentHash⟩, _⟩, nextHeight⟩,
          parentSupply⟩, _⟩, _⟩, _⟩, _⟩, _⟩, _⟩, _⟩
      exact supply_facts_of_decoded_acceptance (of_decide_eq_true parentHash)
        (of_decide_eq_true nextHeight) (of_decide_eq_true parentSupply) accepted.2

theorem deployed_smallwood_proof_yields_transaction_relation
    (verifier : ProductionSmallWoodProofVerifier)
    (hashes : ProductionIdentityFunctions)
    (proof : DeployedSmallWoodProof)
    (accepted : DeployedSmallWoodProofAccepted verifier hashes proof)
    (knowledgeSoundness :
      DeployedSmallWoodKnowledgeSoundnessEvidence verifier proof.exactMap
        proof.proofBytes proof.serializedPublicInputBytes proof.verifierProfile proof.wrapper) :
    ProductionAcceptedTransactionRelation verifier proof.exactMap
      (productionVerifierPublicValues proof.bound proof.statementFields)
      proof.proofBytes proof.serializedPublicInputBytes proof.verifierProfile proof.wrapper := by
  exact accepted_smallwood_proof_yields_transaction_relation
    accepted.canonicalSurface.accepted accepted.exactArtifactAccepted
      accepted.constraintMapBound
      accepted.constraintPublicValuesBound knowledgeSoundness

structure DeployedNoCounterfeitCriticalPathCertificate
    (hashes : ProductionIdentityFunctions)
    (codec : ProductionActionCodec DeployedSmallWoodProof)
    (verifier : ProductionSmallWoodProofVerifier)
    (acceptedParent : AcceptedParentState)
    (block : AcceptedCanonicalBlock) : Prop where
  completeComposition :
    exists decodedActions,
      decodeCanonicalActionStream codec block.actionBytes = some decodedActions
        ∧ RecursiveCrossObjectIdentityFacts hashes
          (canonicalTransactions (DeployedSmallWoodProof.identity hashes) decodedActions)
          acceptedParent block
        ∧ CanonicalSupplyCompositionFacts
          acceptedParent
          (canonicalTransactions (DeployedSmallWoodProof.identity hashes) decodedActions)
          (canonicalCoinbaseAmounts decodedActions)
          block.supply
        ∧ (forall proof, proof ∈ canonicalTransfers decodedActions ->
          ProductionAcceptedTransactionRelation verifier proof.exactMap
            (productionVerifierPublicValues proof.bound proof.statementFields)
            proof.proofBytes proof.serializedPublicInputBytes proof.verifierProfile proof.wrapper)
        ∧ (forall proof, proof ∈ canonicalTransfers decodedActions ->
          exists witnessValues,
            ExactProductionConstraintMapEvaluates proof.exactMap witnessValues
              ∧ ProductionSpendAuthorizationConstraintRelation proof.exactMap witnessValues
              ∧ ProductionOutputValidityConstraintRelation proof.exactMap witnessValues
              ∧ ProductionBalanceConservationConstraintRelation proof.exactMap witnessValues)
        ∧ (forall proof, proof ∈ canonicalTransfers decodedActions ->
          forall witnessValues,
            ProductionSmallWoodSemanticConstraintsSatisfied proof.exactMap witnessValues ->
            forall output,
              output < 2 ->
              publicValueAt proof.exactMap.publicValues (2 + output) = 1 ->
              ProductionAcceptedOutputHashImage proof.exactMap witnessValues output
                ∧ forall alternateWitness,
                  ProductionAcceptedOutputHashImage proof.exactMap alternateWitness output ->
                  productionOutputValue proof.exactMap witnessValues
                      (productionOutputCommitmentLane proof.exactMap output 0) output =
                      productionOutputValue proof.exactMap alternateWitness
                        (productionOutputCommitmentLane proof.exactMap output 0) output
                    ∧ productionOutputAsset proof.exactMap witnessValues
                      (productionOutputCommitmentLane proof.exactMap output 0) output =
                      productionOutputAsset proof.exactMap alternateWitness
                        (productionOutputCommitmentLane proof.exactMap output 0) output)
        ∧ (forall proof, proof ∈ canonicalTransfers decodedActions ->
          transactionHashPreimage (proof.identity hashes) =
            u16le proof.statementFields.circuitVersion
              ++ u16le proof.statementFields.cryptoSuite
              ++ digestSequenceBytes
                ((activeDigests proof.shape.inputFlags proof.shape.nullifiers).map
                  StatementHash.digestBytes)
              ++ digestSequenceBytes
                ((activeDigests proof.shape.outputFlags proof.shape.commitments).map
                  StatementHash.digestBytes)
              ++ digestSequenceBytes
                ((activeDigests proof.shape.outputFlags proof.shape.ciphertextHashes).map
                  StatementHash.digestBytes)
              ++ StatementHash.digestBytes proof.statementFields.balanceTagSeed)
        ∧ (forall proof, proof ∈ canonicalTransfers decodedActions ->
          proof.ciphertexts.map hashes.ciphertextHash =
            (activeDigests proof.shape.outputFlags proof.shape.ciphertextHashes).map
              StatementHash.digestBytes)
  activeV3Transactions :
    forall decodedActions,
      decodeCanonicalActionStream codec block.actionBytes = some decodedActions ->
      forall proof, proof ∈ canonicalTransfers decodedActions ->
        proof.statementFields.circuitVersion = activeSmallWoodCircuitVersion
          ∧ proof.statementFields.cryptoSuite = activeSmallWoodCryptoSuite

theorem accepted_deployed_smallwood_block_yields_no_counterfeit_critical_path
    {hashes : ProductionIdentityFunctions}
    {codec : ProductionActionCodec DeployedSmallWoodProof}
    {verifier : ProductionSmallWoodProofVerifier}
    {acceptedParent : AcceptedParentState}
    {block : AcceptedCanonicalBlock}
    (accepted :
      AcceptedDeployedSmallWoodBlock codec verifier hashes acceptedParent block)
    (knowledgeSoundness :
      DeployedSmallWoodBlockKnowledgeSoundnessEvidence codec verifier block)
    (poseidon2HashCollisionResistance :
      DeployedSmallWoodBlockPoseidon2HashCollisionResistance codec block) :
    DeployedNoCounterfeitCriticalPathCertificate hashes codec verifier acceptedParent block := by
  obtain ⟨actions, decoded, identityFacts⟩ :=
    accepted_recursive_cross_object_identity_refines_one_canonical_block
      accepted.canonicalBlockAccepted
  obtain ⟨supplyActions, supplyDecoded, supplyFacts⟩ :=
    consensus_accepted_chain_supply_composition accepted.canonicalBlockAccepted
  have sameActions : supplyActions = actions := by
    rw [decoded] at supplyDecoded
    exact Option.some.inj supplyDecoded.symm
  subst supplyActions
  constructor
  · exact
      ⟨actions, decoded, identityFacts, supplyFacts, by
        intro proof membership
        exact deployed_smallwood_proof_yields_transaction_relation verifier hashes proof
          (accepted.decodedProofsAccepted actions decoded proof membership)
          (knowledgeSoundness actions decoded proof membership), by
        intro proof membership
        exact production_accepted_transaction_relation_exposes_same_witness_semantics
          (deployed_smallwood_proof_yields_transaction_relation verifier hashes proof
            (accepted.decodedProofsAccepted actions decoded proof membership)
            (knowledgeSoundness actions decoded proof membership)), by
        intro proof membership
        intro witnessValues semanticConstraints output outputBound active
        have acceptedImage := production_concrete_output_yields_accepted_hash_image
          semanticConstraints.mapBound
          semanticConstraints.outputValidity output outputBound active
        refine ⟨acceptedImage, ?_⟩
        intro alternateWitness alternateImage
        exact production_poseidon2_collision_resistance_binds_accepted_output_value_and_asset
          (poseidon2HashCollisionResistance actions decoded proof membership)
          acceptedImage alternateImage, by
        intro proof _
        exact deployed_smallwood_identity_uses_exact_transaction_hash_preimage hashes proof, by
        intro proof membership
        exact deployed_smallwood_identity_binds_ciphertext_payload_hashes verifier hashes proof
          (accepted.decodedProofsAccepted actions decoded proof membership)⟩
  · intro decodedActions decodedAgain proof membership
    have sameDecodedActions : decodedActions = actions := by
      rw [decoded] at decodedAgain
      exact Option.some.inj decodedAgain.symm
    subst decodedActions
    let proofAccepted := accepted.decodedProofsAccepted actions decoded proof membership
    exact ⟨proofAccepted.activeCircuitVersion, proofAccepted.activeCryptoSuite⟩

def productionCompositionFieldMap : List String :=
  [ "transaction_hash_preimage_nullifiers",
    "transaction_hash_preimage_commitments",
    "transaction_hash_preimage_ciphertext_hashes",
    "transaction_hash_preimage_balance_tag",
    "transaction_hash_preimage_circuit_version",
    "transaction_hash_preimage_crypto_suite",
    "transaction_hash",
    "transaction_ciphertext_payload_hash_binding",
    "claim_receipt_statement_hash",
    "claim_receipt_proof_digest", "claim_receipt_public_inputs_digest",
    "claim_receipt_verifier_profile", "claim_binding_anchor",
    "claim_binding_fee", "claim_binding_circuit_version",
    "transaction_circuit_version", "transaction_crypto_suite",
    "transaction_ciphertexts", "exact_proof_artifact_verifier_acceptance",
    "output_note_hash_preimage_18_words",
    "output_note_hash_initial_value_asset_bindings",
    "output_note_hash_fresh_frame_bindings",
    "output_note_hash_continuation_bindings",
    "output_note_hash_authorization_key_bindings",
    "output_note_hash_public_commitment_bindings",
    "output_note_hash_poseidon_transition_relation",
    "output_note_hash_collision_resistance_boundary",
    "claim_order", "identity_tx_count",
    "identity_ordered_tx_ids", "identity_ordered_statement_hashes",
    "identity_ordered_proof_digests", "identity_ordered_public_inputs_digests",
    "identity_ordered_verifier_profiles", "identity_ordered_anchor_roots",
    "identity_ordered_fees", "identity_ordered_binding_circuit_versions",
    "identity_ordered_transaction_circuit_versions",
    "identity_ordered_transaction_crypto_suites",
    "canonical_da_blob_bytes", "identity_tx_statements_commitment", "identity_da_root",
    "identity_da_chunk_count", "proven_batch_tx_count",
    "proven_batch_tx_statements_commitment", "proven_batch_da_root",
    "proven_batch_da_chunk_count", "accepted_parent_hash",
    "accepted_parent_height", "accepted_parent_supply",
    "block_height", "block_parent_hash",
    "block_action_count", "header_tx_statements_commitment", "header_da_root",
    "header_da_chunk_count", "header_claimed_supply", "supply_height",
    "supply_parent_block_hash", "parent_supply",
    "ordered_transfer_fees", "exact_transfer_fee_total",
    "checked_transfer_fee_total", "accepted_burn_amounts", "coinbase_count",
    "observed_coinbase_amount", "expected_coinbase_amount", "has_coinbase",
    "supply_delta", "claimed_supply" ]

theorem production_composition_field_map_is_complete :
    productionCompositionFieldMap.length = 70 := by
  decide

def vectorCiphertextHashA : List Byte :=
  [78, 206, 202, 233, 109, 238, 246, 250, 196, 190, 61, 220,
    165, 221, 250, 98, 140, 220, 78, 189, 82, 89, 51, 58,
    46, 234, 104, 146, 163, 223, 119, 40, 169, 192, 109, 249,
    101, 58, 76, 4, 92, 229, 95, 231, 81, 242, 35, 119]

def vectorCiphertextHashB : List Byte :=
  [137, 222, 168, 247, 204, 153, 33, 4, 122, 123, 68, 145,
    154, 164, 21, 49, 101, 35, 132, 146, 195, 254, 18, 72,
    12, 15, 19, 206, 71, 200, 244, 191, 193, 246, 223, 150,
    75, 169, 2, 81, 163, 103, 7, 63, 174, 183, 44, 165]

def vectorTxIdA : List Byte :=
  [174, 97, 160, 89, 23, 48, 182, 152, 214, 42, 105, 220, 10, 210, 147, 188,
    120, 165, 46, 170, 232, 33, 74, 124, 162, 189, 239, 111, 53, 148, 9, 117]

def vectorTxIdB : List Byte :=
  [18, 118, 223, 107, 17, 189, 110, 77, 97, 39, 215, 243, 51, 26, 6, 188,
    228, 186, 8, 106, 155, 15, 225, 119, 159, 88, 68, 68, 144, 33, 198, 73]

def vectorTxAPreimage : List Byte :=
  u16le 3 ++ u16le 2
    ++ StatementHash.digestBytes 1
    ++ StatementHash.digestBytes 2
    ++ vectorCiphertextHashA
    ++ StatementHash.digestBytes 3

def vectorTxBPreimage : List Byte :=
  u16le 3 ++ u16le 2
    ++ StatementHash.digestBytes 6
    ++ StatementHash.digestBytes 7
    ++ vectorCiphertextHashB
    ++ StatementHash.digestBytes 8

def vectorHashes : ProductionIdentityFunctions :=
  { txId := fun bytes =>
      if bytes = vectorTxAPreimage then vectorTxIdA
      else if bytes = vectorTxBPreimage then vectorTxIdB
      else []
    ciphertextHash := fun bytes =>
      if bytes = [8, 9] then vectorCiphertextHashA
      else if bytes = [16] then vectorCiphertextHashB
      else []
    statementHash := List.sum
    proofDigest := List.sum
    publicInputsDigest := List.sum
    statementCommitment := List.sum
    daRoot := List.sum
    daChunkCount := fun _ => 2 }

def vectorProofVerifier : ProductionSmallWoodProofVerifier :=
  { accepts := fun proofBytes publicInputBytes profile wrapper =>
      decide (proofBytes = [1, 2, 3]
        ∧ publicInputBytes = [4, 5]
        ∧ profile = 6
        ∧ wrapper = ProofWrapperAdmission.validWrapper) }

theorem exact_proof_artifact_verifier_binds_every_identity_input :
    vectorProofVerifier.accepts [1, 2, 3] [4, 5] 6
        ProofWrapperAdmission.validWrapper = true
      ∧ vectorProofVerifier.accepts [1, 2, 4] [4, 5] 6
        ProofWrapperAdmission.validWrapper = false
      ∧ vectorProofVerifier.accepts [1, 2, 3] [4, 6] 6
        ProofWrapperAdmission.validWrapper = false
      ∧ vectorProofVerifier.accepts [1, 2, 3] [4, 5] 7
        ProofWrapperAdmission.validWrapper = false := by
  native_decide

def vectorTxA : CanonicalTxIdentity :=
  { transactionNullifiers := [StatementHash.digestBytes 1]
    transactionCommitments := [StatementHash.digestBytes 2]
    transactionCiphertextHashes := [vectorCiphertextHashA]
    transactionBalanceTag := StatementHash.digestBytes 3
    statementBytes := [1, 2], bindingBytes := [3],
    statementHash := 3, proofDigest := 4, publicInputsDigest := 5,
    verifierProfile := 6, anchorRoot := 7, fee := 3, bindingCircuitVersion := 3,
    transactionCircuitVersion := 3, transactionCryptoSuite := 2,
    ciphertexts := [[8, 9]] }

def vectorTxB : CanonicalTxIdentity :=
  { transactionNullifiers := [StatementHash.digestBytes 6]
    transactionCommitments := [StatementHash.digestBytes 7]
    transactionCiphertextHashes := [vectorCiphertextHashB]
    transactionBalanceTag := StatementHash.digestBytes 8
    statementBytes := [10], bindingBytes := [11, 12],
    statementHash := 10, proofDigest := 13, publicInputsDigest := 14,
    verifierProfile := 6, anchorRoot := 15, fee := 5, bindingCircuitVersion := 3,
    transactionCircuitVersion := 3, transactionCryptoSuite := 2,
    ciphertexts := [[16]] }

def vectorTransactions : List CanonicalTxIdentity := [vectorTxA, vectorTxB]

def vectorActionBytes : List (List Byte) := [[1], [2], [3]]

def vectorCodec : ProductionActionCodec CanonicalTxIdentity :=
  { decodeExact := fun bytes =>
      if bytes = [1] then some (.transfer vectorTxA)
      else if bytes = [2] then some (.transfer vectorTxB)
      else if bytes = [3] then some (.coinbase (initialSubsidy + 8))
      else none }

def validVectorSupply : CanonicalSupplyTransition :=
  { height := 1
    parentBlockHash := 99
    parentSupply := 100
    orderedFees := [3, 5]
    exactFeeTotal := 8
    checkedFeeTotal := some 8
    acceptedBurns := []
    coinbaseCount := 1
    observedCoinbaseAmount := nativeCoinbaseAmount 1 8
    expectedCoinbaseAmount := nativeCoinbaseAmount 1 8
    hasCoinbase := true
    supplyDelta := initialSubsidy + 8
    claimedSupply := 100 + initialSubsidy + 8 }

def validVectorParent : AcceptedParentState :=
  { blockHash := 99
    height := 0
    supply := 100 }

def validVectorBlock : AcceptedCanonicalBlock :=
  { parent := validVectorParent
    header :=
      { height := validVectorSupply.height
        parentBlockHash := validVectorSupply.parentBlockHash
        actionCount := vectorActionBytes.length
        txStatementsCommitment :=
          (expectedIdentityProjection vectorHashes vectorTransactions).txStatementsCommitment
        daRoot := (expectedIdentityProjection vectorHashes vectorTransactions).daRoot
        daChunkCount := (expectedIdentityProjection vectorHashes vectorTransactions).daChunkCount
        claimedSupply := validVectorSupply.claimedSupply }
    actionBytes := vectorActionBytes
    claims := expectedClaims vectorTransactions
    identityProjection := expectedIdentityProjection vectorHashes vectorTransactions
    provenBatch :=
      expectedProvenBatchBinding (expectedIdentityProjection vectorHashes vectorTransactions)
    supply := validVectorSupply }

def vectorCanonicalBlockAccepts (block : AcceptedCanonicalBlock) : Bool :=
  canonicalBlockAccepts vectorCodec vectorHashes id validVectorParent block

def balanceTagSubstitutedVectorTxA : CanonicalTxIdentity :=
  { vectorTxA with transactionBalanceTag := StatementHash.digestBytes 4 }

def transactionPreimageSubstitutedVectorBlock : AcceptedCanonicalBlock :=
  { validVectorBlock with
    identityProjection :=
      { validVectorBlock.identityProjection with
            orderedTxIds :=
              canonicalTransactionId vectorHashes balanceTagSubstitutedVectorTxA
                :: validVectorBlock.identityProjection.orderedTxIds.tail } }

def shiftedEmbeddedParentAndSupplyVectorBlock : AcceptedCanonicalBlock :=
  { validVectorBlock with
    parent := { validVectorParent with supply := validVectorParent.supply + 1 }
    header :=
      { validVectorBlock.header with
        claimedSupply := validVectorBlock.header.claimedSupply + 1 }
    supply :=
      { validVectorSupply with
        parentSupply := validVectorSupply.parentSupply + 1
        claimedSupply := validVectorSupply.claimedSupply + 1 } }

theorem vector_transaction_hash_preimage_is_exact :
    transactionHashPreimage vectorTxA = vectorTxAPreimage
      ∧ transactionHashPreimage vectorTxB = vectorTxBPreimage := by
  native_decide

theorem transaction_hash_preimage_balance_tag_substitution_changes_bytes :
    transactionHashPreimage balanceTagSubstitutedVectorTxA ≠
      transactionHashPreimage vectorTxA := by
  native_decide

theorem canonical_da_blob_ciphertext_substitution_changes_bytes :
    canonicalBlockDaBlob
        ({ vectorTxA with ciphertexts := [[8, 10]] } :: vectorTransactions.tail) ≠
      canonicalBlockDaBlob vectorTransactions := by
  native_decide

theorem valid_canonical_block_accepts :
    vectorCanonicalBlockAccepts validVectorBlock = true := by
  decide

theorem omitted_claim_rejects :
    vectorCanonicalBlockAccepts
      { validVectorBlock with claims := validVectorBlock.claims.tail } = false := by
  decide

theorem reordered_claim_rejects :
    vectorCanonicalBlockAccepts
      { validVectorBlock with claims := validVectorBlock.claims.reverse } = false := by
  decide

theorem substituted_claim_rejects :
    vectorCanonicalBlockAccepts
      { validVectorBlock with
        claims := { vectorTxA.claim with fee := 4 } :: validVectorBlock.claims.tail } = false := by
  decide

theorem duplicated_claim_rejects :
    vectorCanonicalBlockAccepts
      { validVectorBlock with claims := vectorTxA.claim :: validVectorBlock.claims } = false := by
  decide

theorem wrapped_recursive_identity_rejects :
    vectorCanonicalBlockAccepts
      { validVectorBlock with
        identityProjection :=
          { validVectorBlock.identityProjection with
            orderedTxIds := [] :: validVectorBlock.identityProjection.orderedTxIds } } = false := by
  decide

theorem substituted_transaction_preimage_rejects :
    vectorCanonicalBlockAccepts
      transactionPreimageSubstitutedVectorBlock = false := by
  native_decide

theorem truncated_recursive_identity_rejects :
    vectorCanonicalBlockAccepts
      { validVectorBlock with
        identityProjection :=
          { validVectorBlock.identityProjection with
            orderedProofDigests := validVectorBlock.identityProjection.orderedProofDigests.tail } } =
      false := by
  decide

theorem mismatched_da_identity_rejects :
    vectorCanonicalBlockAccepts
      { validVectorBlock with
        provenBatch := { validVectorBlock.provenBatch with daRoot := 0 } } = false := by
  decide

theorem mismatched_header_parent_rejects :
    vectorCanonicalBlockAccepts
      { validVectorBlock with
        header := { validVectorBlock.header with parentBlockHash := 0 } } = false := by
  decide

theorem mismatched_header_action_count_rejects :
    vectorCanonicalBlockAccepts
      { validVectorBlock with
        header := { validVectorBlock.header with actionCount := 4 } } = false := by
  decide

theorem mismatched_header_da_root_rejects :
    vectorCanonicalBlockAccepts
      { validVectorBlock with
        header := { validVectorBlock.header with daRoot := 0 } } = false := by
  decide

theorem mismatched_supply_parent_rejects :
    vectorCanonicalBlockAccepts
      { validVectorBlock with
        supply := { validVectorSupply with parentBlockHash := 0 } } = false := by
  decide

theorem mismatched_fee_order_rejects :
    vectorCanonicalBlockAccepts
      { validVectorBlock with
        supply := { validVectorSupply with orderedFees := [5, 3] } } = false := by
  decide

theorem mismatched_coinbase_amount_rejects :
    vectorCanonicalBlockAccepts
      { validVectorBlock with
        supply := { validVectorSupply with observedCoinbaseAmount := some 0 } } = false := by
  decide

theorem mismatched_claimed_supply_rejects :
    vectorCanonicalBlockAccepts
      { validVectorBlock with
        supply := { validVectorSupply with claimedSupply := validVectorSupply.claimedSupply + 1 } } =
      false := by
  decide

theorem paired_parent_and_claimed_supply_shift_rejects_against_accepted_parent :
    vectorCanonicalBlockAccepts shiftedEmbeddedParentAndSupplyVectorBlock = false := by
  decide

end AcceptedSmallWoodBlockComposition
end Consensus
end Hegemon
