import Hegemon.Native.MaterializedSidecarDaBlobPublication
import Hegemon.Privacy.NativeObserverSurface

namespace Hegemon
namespace Privacy
namespace NativeSidecarObserverSurface

open Hegemon.Native.ActionHashAdmission
open Hegemon.Native.ActionWireReplayProjectionAdmission
open Hegemon.Native.AcceptedChain
open Hegemon.Native.AtomicCommitManifestAdmission
open Hegemon.Native.BlockActionValidation
open Hegemon.Native.BlockArtifactBindingAdmission
open Hegemon.Native.BlockIndexReload
open Hegemon.Native.BlockReplayInputProjection
open Hegemon.Native.CanonicalReorgChainAdmission
open Hegemon.Native.CanonicalStateReload
open Hegemon.Native.CodecAdmission
open Hegemon.Native.MaterializedSidecarDaBlobPublication
open Hegemon.Native.PendingActionByteParserRefinement
open Hegemon.Native.RawIngressSidecarReplayRecoverability
open Hegemon.Native.StorageDurabilityAdmission
open Hegemon.Native.TxLeafArtifact
open Hegemon.Native.TxLeafCanonicalSurface
open Hegemon.Privacy.CiphertextPrivacy
open Hegemon.Privacy.NativeObserverSurface
open Hegemon.Privacy.Observer
open Hegemon.Transaction.CanonicalVerifierBoundary
open Hegemon.Transaction.ProofWrapperAdmission
open Hegemon.Transaction.PublicInputs

theorem materialized_sidecar_ciphertext_privacy_game_all_active_outputs_projected_da_boundary
    {sidecarSurface : RawIngressSidecarReplaySurface}
    {pendingDecode : ExactDecodeInput}
    {blockActionDecode : BlockActionDecodeInput}
    {actionHash : AdmissionInput}
    {wireOutput : ActionWireReplayProjectionOutput}
    {semanticFields :
      Consensus.RecursiveSemanticInputs.RecursiveSemanticFields}
    {blockIndex : BlockIndexReloadInput}
    {canonicalState : CanonicalStateReloadInput}
    {reorgChain : CanonicalReorgChainInput}
    {commitManifest : AtomicCommitManifestInput}
    {durability : StorageDurabilityInput}
    {initial final : Hegemon.Native.AcceptedChain.NativeLedgerTreeReplayState}
    {blocks : List RawDecodedNativeTreeReplayBlock}
    {artifactBytes : List Byte}
    {summary : TxLeafSummary}
    {txLeaf : TxLeafActionBindingInput}
    {wrapper : ProofWrapperInput}
    {shape : PublicInputShape}
    {publicFields :
      Hegemon.Transaction.PublicInputBinding.PublicFields}
    {serializedFields :
      Hegemon.Transaction.PublicInputBinding.SerializedFields}
    {bound : Hegemon.Transaction.PublicInputBinding.BoundPublicInputs}
    {statementFields : Hegemon.Transaction.StatementHash.StatementFields}
    {statementBytes : List Byte}
    {bindingFields :
      Hegemon.Transaction.ProofStatementBinding.BindingFields}
    {bindingBytes : List Byte}
    {merkleRoot : Digest}
    {materializedRowsFeedTransactionNew
      transactionNewFeedsConsensusDaBlob
      daRootHashSecurityEquivalence
      daAvailability
      proofSystemSoundness
      completeNativeNodeEquivalence : Prop}
    {left right : ShieldedTransactionWorld}
    (mlKemIndistinguishability
      aeadCiphertextConfidentiality
      kdfDomainSeparation
      rngFreshness : Prop)
    (mlKemAssumption : mlKemIndistinguishability)
    (aeadAssumption : aeadCiphertextConfidentiality)
    (kdfAssumption : kdfDomainSeparation)
    (rngAssumption : rngFreshness)
    (facts :
      MaterializedSidecarDaBlobPublicationFacts
        sidecarSurface
        pendingDecode
        blockActionDecode
        actionHash
        wireOutput
        semanticFields
        blockIndex
        canonicalState
        reorgChain
        commitManifest
        durability
        initial
        final
        blocks
        artifactBytes
        summary
        txLeaf
        wrapper
        shape
        publicFields
        serializedFields
        bound
        statementFields
        statementBytes
        bindingFields
        bindingBytes
        merkleRoot
        materializedRowsFeedTransactionNew
        transactionNewFeedsConsensusDaBlob
        daRootHashSecurityEquivalence
        daAvailability
        proofSystemSoundness
        completeNativeNodeEquivalence)
    (canonicalSurface :
      CanonicalTxStatementSurface
        wrapper
        shape
        publicFields
        serializedFields
        bound
        statementFields
        statementBytes
        bindingFields
        bindingBytes
        merkleRoot)
    (game : CiphertextPrivacyGame left right)
    (leftShape : left.publicInputs = shape)
    (leftObserverBytesBounded :
      ∀ wire,
        wire ∈ left.ciphertextBytes ->
          Hegemon.Wallet.NoteCiphertextWire.bytesBounded wire)
    (rightObserverBytesBounded :
      ∀ wire,
        wire ∈ right.ciphertextBytes ->
          Hegemon.Wallet.NoteCiphertextWire.bytesBounded wire) :
    (sidecarSurface.transferState.sidecarCiphertextsAvailable = true
      ∧ sidecarSurface.transferState.sidecarCiphertextSizesPresent = true
      ∧ sidecarSurface.transferState.sidecarCiphertextSizesMatch = true)
      ∧ (actionWireReplayProjectionPreconditions
          sidecarSurface.daSidecarReplay.wireReplayProjection = true
        ∧ sidecarSurface.daSidecarReplay.wireReplayProjection.actionCount =
          sidecarSurface.daSidecarReplay.wireReplayProjection.plannedCount
        ∧ sidecarSurface.daSidecarReplay.wireReplayProjection.actionCount =
          sidecarSurface.daSidecarReplay.wireReplayProjection.actions.length
        ∧ wireOutput.projectedActionCount =
          blockActionDecode.actualActionPayloadCount)
      ∧ (txLeaf.ciphertextHashesMatch = true
        ∧ txLeaf.ciphertextPayloadHashesMatch = true)
      ∧ (shape.ciphertextHashes = statementFields.ciphertextHashSeeds
        ∧ bindingFields.ciphertextHashSeeds =
          statementFields.ciphertextHashSeeds)
      ∧ ∀ index publicCommitment publicCiphertextHash,
        OutputSlotAt
          shape.outputFlags
          shape.commitments
          shape.ciphertextHashes
          index
          1
          publicCommitment
          publicCiphertextHash ->
          mlKemIndistinguishability
            ∧ aeadCiphertextConfidentiality
            ∧ kdfDomainSeparation
            ∧ rngFreshness
            ∧ samePublicMetadataLeakage left right
            ∧ sameBatchTimingLeakage left right
            ∧ game.wireIndistinguishable
            ∧ ∃ leftWire rightWire summary leftDaBytes rightDaBytes,
              left.ciphertextBytes[
                  activeFlagCountBefore shape.outputFlags index]? =
                some leftWire
                ∧ right.ciphertextBytes[
                    activeFlagCountBefore shape.outputFlags index]? =
                  some rightWire
                ∧ left.ciphertextSummaries[
                    activeFlagCountBefore shape.outputFlags index]? =
                  some summary
                ∧ right.ciphertextSummaries[
                    activeFlagCountBefore shape.outputFlags index]? =
                  some summary
                ∧ Hegemon.Wallet.NoteCiphertextWire.parseChainNoteCiphertext
                  leftWire = some summary
                ∧ Hegemon.Wallet.NoteCiphertextWire.parseChainNoteCiphertext
                  rightWire = some summary
                ∧ Hegemon.Wallet.NoteCiphertextWire.projectChainDaBytes
                  leftWire = some leftDaBytes
                ∧ Hegemon.Wallet.NoteCiphertextWire.projectChainDaBytes
                  rightWire = some rightDaBytes
                ∧ leftDaBytes.length =
                  Hegemon.Wallet.NoteCiphertextWire.chainCiphertextSize
                    + Hegemon.Wallet.NoteCiphertextWire.mlKemCiphertextLen
                ∧ rightDaBytes.length =
                  Hegemon.Wallet.NoteCiphertextWire.chainCiphertextSize
                    + Hegemon.Wallet.NoteCiphertextWire.mlKemCiphertextLen
                ∧ summaryHasChainCiphertextFormat summary
                ∧ Hegemon.Wallet.NoteCiphertextWire.bytesBounded leftWire
                ∧ Hegemon.Wallet.NoteCiphertextWire.bytesBounded rightWire
                ∧ leftWire.length =
                  Hegemon.Wallet.NoteCiphertextWire.chainCiphertextSize
                    + Hegemon.Wallet.NoteCiphertextWire.chainCompactKemLen.length
                    + Hegemon.Wallet.NoteCiphertextWire.mlKemCiphertextLen
                ∧ rightWire.length =
                  Hegemon.Wallet.NoteCiphertextWire.chainCiphertextSize
                    + Hegemon.Wallet.NoteCiphertextWire.chainCompactKemLen.length
                    + Hegemon.Wallet.NoteCiphertextWire.mlKemCiphertextLen
                ∧ shape.outputFlags[index]? = some 1
                ∧ shape.commitments[index]? = some publicCommitment
                ∧ shape.ciphertextHashes[index]? = some publicCiphertextHash
                ∧ statementFields.commitmentSeeds[index]? =
                  some publicCommitment
                ∧ statementFields.ciphertextHashSeeds[index]? =
                  some publicCiphertextHash
                ∧ bindingFields.commitmentSeeds[index]? =
                  some publicCommitment
                ∧ bindingFields.ciphertextHashSeeds[index]? =
                  some publicCiphertextHash
                ∧ txLeaf.ciphertextHashesMatch = true
                ∧ txLeaf.ciphertextPayloadHashesMatch = true
                ∧ txLeaf.outputCountMatches = true
                ∧ OutputSlotFacts
                  1
                  publicCommitment
                  publicCiphertextHash
                ∧ TxLeafActionBindingFacts txLeaf
                ∧ ActiveOutputPublicMetadataBoundary
                  txLeaf
                  shape
                  bound
                  statementFields
                  bindingFields
                  left
                  right
                  index
                  publicCommitment
                  publicCiphertextHash := by
  exact
    ⟨facts.materializedSidecarRows,
      facts.wireReplayDaRowBinding,
      facts.txLeafCiphertextPublication,
      facts.statementCiphertextVectorPublication,
      native_tx_leaf_ciphertext_privacy_game_all_active_outputs_projected_da_boundary
        mlKemIndistinguishability
        aeadCiphertextConfidentiality
        kdfDomainSeparation
        rngFreshness
        mlKemAssumption
        aeadAssumption
        kdfAssumption
        rngAssumption
        facts.fullBytePublication.txLeafAccepted
        canonicalSurface
        game
        leftShape
        leftObserverBytesBounded
        rightObserverBytesBounded⟩

end NativeSidecarObserverSurface
end Privacy
end Hegemon
