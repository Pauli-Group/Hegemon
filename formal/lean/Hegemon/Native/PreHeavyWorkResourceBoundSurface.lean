import Hegemon.Native.ActionRequestProjectionAdmission
import Hegemon.Native.BridgeActionResourceAdmission
import Hegemon.Native.CandidateArtifactAdmission
import Hegemon.Native.CodecAdmission
import Hegemon.Native.MineableActionAdmission
import Hegemon.Native.ReceiptRoot
import Hegemon.Native.ResourceBudgetAdmission
import Hegemon.Native.RpcAdmission
import Hegemon.Native.SidecarUploadAdmission
import Hegemon.Native.SyncAdmission
import Hegemon.Native.TransferActionPayloadAdmission
import Hegemon.Native.TxLeafArtifactProjectionRefinement

namespace Hegemon
namespace Native
namespace PreHeavyWorkResourceBoundSurface

open Hegemon.Native.MineableActionAdmission
open Hegemon.Native.ActionRequestProjectionAdmission
open Hegemon.Native.BridgeActionResourceAdmission
open Hegemon.Native.CandidateArtifactAdmission
open Hegemon.Native.CodecAdmission
open Hegemon.Native.ReceiptRoot
open Hegemon.Native.ResourceBudgetAdmission
open Hegemon.Native.RpcAdmission
open Hegemon.Native.SidecarUploadAdmission
open Hegemon.Native.SyncAdmission
open Hegemon.Native.TransferActionPayloadAdmission
open Hegemon.Native.TxLeafArtifact
open Hegemon.Native.TxLeafArtifactProjectionRefinement
open Hegemon.Resource.BoundedRequestAdmission

structure PreHeavyWorkResourceBoundSurface where
  mempoolBudget : MempoolBudgetInput
  stagedProofBudget : StagedProofBudgetInput
  rpcRawPolicy : RawRpcPolicy
  rpcExternal : Bool
  rpcPolicy : RpcPolicy
  rpcMethod : RpcMethod
  timestampRange : TimestampRangeInput
  hexRawTextBytes : Nat
  hexDecodedBytes : Nat
  hexMaxDecodedBytes : Nat
  base64RawTextBytes : Nat
  base64DecodedBytes : Nat
  base64MaxDecodedBytes : Nat
  rpcBatch : BatchInput
  ciphertextRequest : RequestCountInput
  proofRequest : RequestCountInput
  ciphertextCapacity : CapacityInput
  proofCapacity : CapacityInput
  proofMetadata : ProofMetadataInput
  proofDecoded : ProofDecodedInput
  mineableAction : MineableActionInput
deriving DecidableEq, Repr

def hexByteParseInput
    (surface : PreHeavyWorkResourceBoundSurface) : ByteParseInput :=
  {
    encoding := ByteEncoding.hex,
    rawTextBytes := surface.hexRawTextBytes,
    decodedBytes := surface.hexDecodedBytes,
    maxDecodedBytes := surface.hexMaxDecodedBytes
  }

def base64ByteParseInput
    (surface : PreHeavyWorkResourceBoundSurface) : ByteParseInput :=
  {
    encoding := ByteEncoding.base64,
    rawTextBytes := surface.base64RawTextBytes,
    decodedBytes := surface.base64DecodedBytes,
    maxDecodedBytes := surface.base64MaxDecodedBytes
  }

structure AcceptedPreHeavyWorkResourceBoundInputs
    (surface : PreHeavyWorkResourceBoundSurface) : Prop where
  mempoolBudgetAccepted :
    evaluateMempoolBudgetRejection surface.mempoolBudget = none
  stagedProofBudgetAccepted :
    evaluateStagedProofBudgetRejection surface.stagedProofBudget = none
  rpcPolicyResolved :
    resolveRpcPolicy surface.rpcRawPolicy surface.rpcExternal =
      Except.ok surface.rpcPolicy
  rpcMethodAccepted :
    evaluateRpcMethodGate surface.rpcPolicy surface.rpcMethod = none
  timestampRangeAccepted :
    evaluateTimestampRangeRejection surface.timestampRange = none
  hexByteParseAccepted :
    byteParseAccepts (hexByteParseInput surface) = true
  base64ByteParseAccepted :
    byteParseAccepts (base64ByteParseInput surface) = true
  rpcBatchAccepted :
    evaluateBatchRejection surface.rpcBatch = none
  ciphertextRequestAccepted :
    evaluateCiphertextRequest surface.ciphertextRequest = Except.ok ()
  proofRequestAccepted :
    evaluateProofRequest surface.proofRequest = Except.ok ()
  ciphertextCapacityAccepted :
    evaluateCiphertextCapacity surface.ciphertextCapacity = Except.ok ()
  proofCapacityAccepted :
    evaluateProofCapacity surface.proofCapacity = Except.ok ()
  proofMetadataAccepted :
    evaluateProofMetadata surface.proofMetadata = Except.ok ()
  proofDecodedAccepted :
    evaluateProofDecoded surface.proofDecoded = Except.ok ()
  mineableActionAccepted :
    evaluateMineableAction surface.mineableAction = Except.ok ()

structure AcceptedPreHeavyWorkResourceBoundFacts
    (surface : PreHeavyWorkResourceBoundSurface) : Prop where
  mempoolBudgetAccepted :
    evaluateMempoolBudgetRejection surface.mempoolBudget = none
  mempoolWithinBudget :
    ¬ surface.mempoolBudget.maxBytes <
      mempoolBudgetTotal surface.mempoolBudget
  stagedProofBudgetAccepted :
    evaluateStagedProofBudgetRejection surface.stagedProofBudget = none
  stagedProofWithinBudget :
    ¬ surface.stagedProofBudget.maxBytes <
      stagedProofBudgetTotal surface.stagedProofBudget
  rpcPolicyResolved :
    resolveRpcPolicy surface.rpcRawPolicy surface.rpcExternal =
      Except.ok surface.rpcPolicy
  rpcMethodAccepted :
    evaluateRpcMethodGate surface.rpcPolicy surface.rpcMethod = none
  timestampRangeAccepted :
    evaluateTimestampRangeRejection surface.timestampRange = none
  timestampRowsWithinCap :
    ∃ rows,
      timestampRangeRequestedRows surface.timestampRange = Except.ok rows
        ∧ ¬ surface.timestampRange.maxRows < rows
  hexByteParseAccepted :
    byteParseAccepts (hexByteParseInput surface) = true
  hexByteCapsHold :
    ¬ hexLenLimit surface.hexMaxDecodedBytes < surface.hexRawTextBytes
      ∧ ¬ surface.hexMaxDecodedBytes < surface.hexDecodedBytes
  base64ByteParseAccepted :
    byteParseAccepts (base64ByteParseInput surface) = true
  base64ByteCapsHold :
    ¬ encodedLenLimit surface.base64MaxDecodedBytes <
        surface.base64RawTextBytes
      ∧ ¬ surface.base64MaxDecodedBytes < surface.base64DecodedBytes
  rpcBatchAccepted :
    evaluateBatchRejection surface.rpcBatch = none
  rpcBatchNonemptyWithinCap :
    surface.rpcBatch.requestCount ≠ 0
      ∧ ¬ surface.rpcBatch.maxRequests < surface.rpcBatch.requestCount
  ciphertextRequestAccepted :
    evaluateCiphertextRequest surface.ciphertextRequest = Except.ok ()
  ciphertextRequestWithinCap :
    ¬ surface.ciphertextRequest.itemCount >
      surface.ciphertextRequest.maxItems
  proofRequestAccepted :
    evaluateProofRequest surface.proofRequest = Except.ok ()
  proofRequestWithinCap :
    ¬ surface.proofRequest.itemCount > surface.proofRequest.maxItems
  ciphertextCapacityAccepted :
    evaluateCiphertextCapacity surface.ciphertextCapacity = Except.ok ()
  ciphertextCapacityPreconditions :
    capacityPreconditions surface.ciphertextCapacity = true
  proofCapacityAccepted :
    evaluateProofCapacity surface.proofCapacity = Except.ok ()
  proofCapacityPreconditions :
    capacityPreconditions surface.proofCapacity = true
  proofMetadataAccepted :
    evaluateProofMetadata surface.proofMetadata = Except.ok ()
  proofMetadataPreconditions :
    proofMetadataPreconditions surface.proofMetadata = true
  proofDecodedAccepted :
    evaluateProofDecoded surface.proofDecoded = Except.ok ()
  proofDecodedPreconditions :
    proofDecodedPreconditions surface.proofDecoded = true
  mineableActionAccepted :
    evaluateMineableAction surface.mineableAction = Except.ok ()
  mineableActionPreconditions :
    mineableActionPreconditions surface.mineableAction = true

theorem accepted_preheavy_resource_bound_surface_exposes_bounds
    {surface : PreHeavyWorkResourceBoundSurface}
    (accepted : AcceptedPreHeavyWorkResourceBoundInputs surface) :
    AcceptedPreHeavyWorkResourceBoundFacts surface := by
  have mempoolAccepts :
      mempoolBudgetAccepts surface.mempoolBudget = true := by
    simp [mempoolBudgetAccepts, accepted.mempoolBudgetAccepted]
  have stagedProofAccepts :
      stagedProofBudgetAccepts surface.stagedProofBudget = true := by
    simp [stagedProofBudgetAccepts, accepted.stagedProofBudgetAccepted]
  have timestampRowsWithinCap :
      ∃ rows,
        timestampRangeRequestedRows surface.timestampRange = Except.ok rows
          ∧ ¬ surface.timestampRange.maxRows < rows :=
    timestamp_range_accepts_iff_requested_within_limit.mp
      accepted.timestampRangeAccepted
  have rpcBatchAccepts :
      batchAccepts surface.rpcBatch = true := by
    simp [batchAccepts, accepted.rpcBatchAccepted]
  have ciphertextRequestAccepts :
      accepts (evaluateCiphertextRequest surface.ciphertextRequest) =
        true := by
    simp [accepts, accepted.ciphertextRequestAccepted]
  have proofRequestAccepts :
      accepts (evaluateProofRequest surface.proofRequest) = true := by
    simp [accepts, accepted.proofRequestAccepted]
  have ciphertextCapacityAccepts :
      accepts (evaluateCiphertextCapacity surface.ciphertextCapacity) =
        true := by
    simp [accepts, accepted.ciphertextCapacityAccepted]
  have proofCapacityAccepts :
      accepts (evaluateProofCapacity surface.proofCapacity) = true := by
    simp [accepts, accepted.proofCapacityAccepted]
  have proofMetadataAccepts :
      accepts (evaluateProofMetadata surface.proofMetadata) = true := by
    simp [accepts, accepted.proofMetadataAccepted]
  have proofDecodedAccepts :
      accepts (evaluateProofDecoded surface.proofDecoded) = true := by
    simp [accepts, accepted.proofDecodedAccepted]
  have mineableAccepts :
      mineableActionAccepts surface.mineableAction = true := by
    simp [mineableActionAccepts, accepted.mineableActionAccepted]
  have ciphertextCapacityPreconditions :
      capacityPreconditions surface.ciphertextCapacity = true := by
    have eq := ciphertext_capacity_accepts_iff_preconditions
      surface.ciphertextCapacity
    rw [eq] at ciphertextCapacityAccepts
    exact ciphertextCapacityAccepts
  have proofCapacityPreconditions :
      capacityPreconditions surface.proofCapacity = true := by
    have eq := proof_capacity_accepts_iff_preconditions
      surface.proofCapacity
    rw [eq] at proofCapacityAccepts
    exact proofCapacityAccepts
  have proofMetadataPreconditions :
      proofMetadataPreconditions surface.proofMetadata = true := by
    have eq := proof_metadata_accepts_iff_preconditions
      surface.proofMetadata
    rw [eq] at proofMetadataAccepts
    exact proofMetadataAccepts
  have proofDecodedPreconditions :
      proofDecodedPreconditions surface.proofDecoded = true := by
    have eq := proof_decoded_accepts_iff_preconditions
      surface.proofDecoded
    rw [eq] at proofDecodedAccepts
    exact proofDecodedAccepts
  have mineablePreconditions :
      mineableActionPreconditions surface.mineableAction = true := by
    have eq := accepts_iff_mineable_preconditions surface.mineableAction
    rw [eq] at mineableAccepts
    exact mineableAccepts
  exact {
    mempoolBudgetAccepted := accepted.mempoolBudgetAccepted,
    mempoolWithinBudget :=
      mempool_accepts_iff_not_over_limit.mp mempoolAccepts,
    stagedProofBudgetAccepted := accepted.stagedProofBudgetAccepted,
    stagedProofWithinBudget :=
      staged_proof_accepts_iff_not_over_limit.mp stagedProofAccepts,
    rpcPolicyResolved := accepted.rpcPolicyResolved,
    rpcMethodAccepted := accepted.rpcMethodAccepted,
    timestampRangeAccepted := accepted.timestampRangeAccepted,
    timestampRowsWithinCap := timestampRowsWithinCap,
    hexByteParseAccepted := accepted.hexByteParseAccepted,
    hexByteCapsHold :=
      hex_byte_parse_accepts_iff_caps_hold.mp accepted.hexByteParseAccepted,
    base64ByteParseAccepted := accepted.base64ByteParseAccepted,
    base64ByteCapsHold :=
      base64_byte_parse_accepts_iff_caps_hold.mp
        accepted.base64ByteParseAccepted,
    rpcBatchAccepted := accepted.rpcBatchAccepted,
    rpcBatchNonemptyWithinCap :=
      batch_accepts_iff_nonempty_within_limit.mp rpcBatchAccepts,
    ciphertextRequestAccepted := accepted.ciphertextRequestAccepted,
    ciphertextRequestWithinCap :=
      ciphertext_request_accepts_iff_not_over_limit.mp
        ciphertextRequestAccepts,
    proofRequestAccepted := accepted.proofRequestAccepted,
    proofRequestWithinCap :=
      proof_request_accepts_iff_not_over_limit.mp proofRequestAccepts,
    ciphertextCapacityAccepted := accepted.ciphertextCapacityAccepted,
    ciphertextCapacityPreconditions := ciphertextCapacityPreconditions,
    proofCapacityAccepted := accepted.proofCapacityAccepted,
    proofCapacityPreconditions := proofCapacityPreconditions,
    proofMetadataAccepted := accepted.proofMetadataAccepted,
    proofMetadataPreconditions := proofMetadataPreconditions,
    proofDecodedAccepted := accepted.proofDecodedAccepted,
    proofDecodedPreconditions := proofDecodedPreconditions,
    mineableActionAccepted := accepted.mineableActionAccepted,
    mineableActionPreconditions := mineablePreconditions
  }

structure AcceptedTransferPayloadPreHeavyBounds
    (input : TransferPayloadInput) : Prop where
  transferPayloadAccepted :
    transferPayloadAccepts input = true
  transferPayloadPreconditions :
    transferPayloadPreconditions input = true
  proofPresent :
    input.proofBytes ≠ 0
  proofWithinCap :
    ¬ input.proofBytes > input.maxProofBytes
  inlineCiphertextWithinCap :
    ¬ input.inlineCiphertextBytes > input.maxCiphertextBytes
  bindingFacts :
    TransferPayloadBindingFacts input

theorem transfer_payload_accepts_implies_preheavy_bounds
    {input : TransferPayloadInput}
    (accepted : transferPayloadAccepts input = true) :
    AcceptedTransferPayloadPreHeavyBounds input := by
  have preconditionsEq :=
    transfer_payload_accepts_implies_preconditions accepted
  have bindingFacts :=
    transfer_payload_accepts_implies_binding_facts accepted
  cases input with
  | mk proofBytes maxProofBytes anchorMatches commitmentsMatch
      inlineCiphertextBytes maxCiphertextBytes ciphertextHashesMatch
      ciphertextSizesMatch bindingHashMatches proofBindingHashMatchesKey
      feeMatches =>
      have preconditionsFacts := preconditionsEq
      simp [transferPayloadPreconditions] at preconditionsFacts
      exact {
        transferPayloadAccepted := accepted,
        transferPayloadPreconditions := preconditionsEq,
        proofPresent := preconditionsFacts.1,
        proofWithinCap := Nat.not_lt.mpr preconditionsFacts.2.1,
        inlineCiphertextWithinCap :=
          Nat.not_lt.mpr preconditionsFacts.2.2.2.2.1,
        bindingFacts := bindingFacts
      }

structure AcceptedCandidateArtifactPreHeavyBounds
    (input : CandidateArtifactInput) : Prop where
  candidateArtifactAccepted :
    evaluateCandidateArtifact input = Except.ok ()
  stateDeltasAbsent :
    input.stateDeltasAbsent = true
  routePayloadDecodesExactly :
    input.routePayloadDecodesExactly = true
  routePayloadMatchesArtifact :
    input.routePayloadMatchesArtifact = true
  artifactPresent :
    input.artifactPresent = true
  schemaMatches :
    input.schemaMatches = true
  txCountNonzero :
    input.txCount ≠ 0
  txCountWithinCap :
    ¬ input.txCount > input.maxTxCount
  daChunkCountNonzero :
    input.daChunkCount ≠ 0
  proofModeRecursiveBlock :
    input.proofModeRecursiveBlock = true
  proofKindRecursiveBlockV2 :
    input.proofKindRecursiveBlockV2 = true
  verifierProfileMatches :
    input.verifierProfileMatches = true
  commitmentProofEmpty :
    input.commitmentProofEmpty = true
  receiptRootAbsent :
    input.receiptRootAbsent = true
  recursivePayloadPresent :
    input.recursivePayloadPresent = true
  recursiveProofNonempty :
    input.recursiveProofBytes ≠ 0
  recursiveProofWithinCap :
    ¬ input.recursiveProofBytes > input.maxRecursiveProofBytes

theorem candidate_artifact_accepts_implies_preheavy_bounds
    {input : CandidateArtifactInput}
    (accepted : evaluateCandidateArtifact input = Except.ok ()) :
    AcceptedCandidateArtifactPreHeavyBounds input := by
  have stateDeltasAbsent : input.stateDeltasAbsent = true := by
    cases h : input.stateDeltasAbsent <;>
      simp [evaluateCandidateArtifact, h] at accepted ⊢
  have routePayloadDecodesExactly :
      input.routePayloadDecodesExactly = true := by
    cases h : input.routePayloadDecodesExactly <;>
      simp [evaluateCandidateArtifact, stateDeltasAbsent, h] at accepted ⊢
  have routePayloadMatchesArtifact :
      input.routePayloadMatchesArtifact = true := by
    cases h : input.routePayloadMatchesArtifact <;>
      simp [
        evaluateCandidateArtifact,
        stateDeltasAbsent,
        routePayloadDecodesExactly,
        h
      ] at accepted ⊢
  have artifactPresent : input.artifactPresent = true := by
    cases h : input.artifactPresent <;>
      simp [
        evaluateCandidateArtifact,
        stateDeltasAbsent,
        routePayloadDecodesExactly,
        routePayloadMatchesArtifact,
        h
      ] at accepted ⊢
  have schemaMatches : input.schemaMatches = true := by
    cases h : input.schemaMatches <;>
      simp [
        evaluateCandidateArtifact,
        stateDeltasAbsent,
        routePayloadDecodesExactly,
        routePayloadMatchesArtifact,
        artifactPresent,
        h
      ] at accepted ⊢
  have txCountNonzero : input.txCount ≠ 0 := by
    intro h
    simp [
      evaluateCandidateArtifact,
      stateDeltasAbsent,
      routePayloadDecodesExactly,
      routePayloadMatchesArtifact,
      artifactPresent,
      schemaMatches,
      h
    ] at accepted
  have txCountWithinCap : ¬ input.txCount > input.maxTxCount := by
    intro h
    simp [
      evaluateCandidateArtifact,
      stateDeltasAbsent,
      routePayloadDecodesExactly,
      routePayloadMatchesArtifact,
      artifactPresent,
      schemaMatches,
      txCountNonzero,
      h
    ] at accepted
  have daChunkCountNonzero : input.daChunkCount ≠ 0 := by
    intro h
    simp [
      evaluateCandidateArtifact,
      stateDeltasAbsent,
      routePayloadDecodesExactly,
      routePayloadMatchesArtifact,
      artifactPresent,
      schemaMatches,
      txCountNonzero,
      txCountWithinCap,
      h
    ] at accepted
  have proofModeRecursiveBlock : input.proofModeRecursiveBlock = true := by
    cases h : input.proofModeRecursiveBlock <;>
      simp [
        evaluateCandidateArtifact,
        stateDeltasAbsent,
        routePayloadDecodesExactly,
        routePayloadMatchesArtifact,
        artifactPresent,
        schemaMatches,
        txCountNonzero,
        txCountWithinCap,
        daChunkCountNonzero,
        h
      ] at accepted ⊢
  have proofKindRecursiveBlockV2 :
      input.proofKindRecursiveBlockV2 = true := by
    cases h : input.proofKindRecursiveBlockV2 <;>
      simp [
        evaluateCandidateArtifact,
        stateDeltasAbsent,
        routePayloadDecodesExactly,
        routePayloadMatchesArtifact,
        artifactPresent,
        schemaMatches,
        txCountNonzero,
        txCountWithinCap,
        daChunkCountNonzero,
        proofModeRecursiveBlock,
        h
      ] at accepted ⊢
  have verifierProfileMatches : input.verifierProfileMatches = true := by
    cases h : input.verifierProfileMatches <;>
      simp [
        evaluateCandidateArtifact,
        stateDeltasAbsent,
        routePayloadDecodesExactly,
        routePayloadMatchesArtifact,
        artifactPresent,
        schemaMatches,
        txCountNonzero,
        txCountWithinCap,
        daChunkCountNonzero,
        proofModeRecursiveBlock,
        proofKindRecursiveBlockV2,
        h
      ] at accepted ⊢
  have commitmentProofEmpty : input.commitmentProofEmpty = true := by
    cases h : input.commitmentProofEmpty <;>
      simp [
        evaluateCandidateArtifact,
        stateDeltasAbsent,
        routePayloadDecodesExactly,
        routePayloadMatchesArtifact,
        artifactPresent,
        schemaMatches,
        txCountNonzero,
        txCountWithinCap,
        daChunkCountNonzero,
        proofModeRecursiveBlock,
        proofKindRecursiveBlockV2,
        verifierProfileMatches,
        h
      ] at accepted ⊢
  have receiptRootAbsent : input.receiptRootAbsent = true := by
    cases h : input.receiptRootAbsent <;>
      simp [
        evaluateCandidateArtifact,
        stateDeltasAbsent,
        routePayloadDecodesExactly,
        routePayloadMatchesArtifact,
        artifactPresent,
        schemaMatches,
        txCountNonzero,
        txCountWithinCap,
        daChunkCountNonzero,
        proofModeRecursiveBlock,
        proofKindRecursiveBlockV2,
        verifierProfileMatches,
        commitmentProofEmpty,
        h
      ] at accepted ⊢
  have recursivePayloadPresent :
      input.recursivePayloadPresent = true := by
    cases h : input.recursivePayloadPresent <;>
      simp [
        evaluateCandidateArtifact,
        stateDeltasAbsent,
        routePayloadDecodesExactly,
        routePayloadMatchesArtifact,
        artifactPresent,
        schemaMatches,
        txCountNonzero,
        txCountWithinCap,
        daChunkCountNonzero,
        proofModeRecursiveBlock,
        proofKindRecursiveBlockV2,
        verifierProfileMatches,
        commitmentProofEmpty,
        receiptRootAbsent,
        h
      ] at accepted ⊢
  have recursiveProofNonempty : input.recursiveProofBytes ≠ 0 := by
    intro h
    simp [
      evaluateCandidateArtifact,
      stateDeltasAbsent,
      routePayloadDecodesExactly,
      routePayloadMatchesArtifact,
      artifactPresent,
      schemaMatches,
      txCountNonzero,
      txCountWithinCap,
      daChunkCountNonzero,
      proofModeRecursiveBlock,
      proofKindRecursiveBlockV2,
      verifierProfileMatches,
      commitmentProofEmpty,
      receiptRootAbsent,
      recursivePayloadPresent,
      h
    ] at accepted
  have recursiveProofWithinCap :
      ¬ input.recursiveProofBytes > input.maxRecursiveProofBytes := by
    intro h
    simp [
      evaluateCandidateArtifact,
      stateDeltasAbsent,
      routePayloadDecodesExactly,
      routePayloadMatchesArtifact,
      artifactPresent,
      schemaMatches,
      txCountNonzero,
      txCountWithinCap,
      daChunkCountNonzero,
      proofModeRecursiveBlock,
      proofKindRecursiveBlockV2,
      verifierProfileMatches,
      commitmentProofEmpty,
      receiptRootAbsent,
      recursivePayloadPresent,
      recursiveProofNonempty,
      h
    ] at accepted
  exact {
    candidateArtifactAccepted := accepted,
    stateDeltasAbsent := stateDeltasAbsent,
    routePayloadDecodesExactly := routePayloadDecodesExactly,
    routePayloadMatchesArtifact := routePayloadMatchesArtifact,
    artifactPresent := artifactPresent,
    schemaMatches := schemaMatches,
    txCountNonzero := txCountNonzero,
    txCountWithinCap := txCountWithinCap,
    daChunkCountNonzero := daChunkCountNonzero,
    proofModeRecursiveBlock := proofModeRecursiveBlock,
    proofKindRecursiveBlockV2 := proofKindRecursiveBlockV2,
    verifierProfileMatches := verifierProfileMatches,
    commitmentProofEmpty := commitmentProofEmpty,
    receiptRootAbsent := receiptRootAbsent,
    recursivePayloadPresent := recursivePayloadPresent,
    recursiveProofNonempty := recursiveProofNonempty,
    recursiveProofWithinCap := recursiveProofWithinCap
  }

structure AcceptedActionRequestProjectionPreHeavyBounds
    (input : ActionRequestProjectionInput) : Prop where
  actionRequestAccepted :
    actionRequestProjectionAccepts input = true
  actionRequestPreconditions :
    actionRequestProjectionPreconditions input = true
  jsonDecodeAccepts :
    input.jsonDecodeAccepts = true
  kernelEnvelopeFieldsAbsent :
    input.kernelEnvelopeFieldsAbsent = true
  routeSupported :
    input.routeSupported = true
  nullifierScopeValid :
    input.nullifierScopeValid = true
  nullifierCountWithinLimit :
    input.nullifierCountWithinLimit = true
  nullifierHexValid :
    input.nullifierHexValid = true
  publicArgsEncodedWithinLimit :
    input.publicArgsEncodedWithinLimit = true
  publicArgsBase64Decodes :
    input.publicArgsBase64Decodes = true
  publicArgsDecodedWithinLimit :
    input.publicArgsDecodedWithinLimit = true
  routePayloadDecodesExactly :
    input.routePayloadDecodesExactly = true

theorem action_request_projection_accepts_implies_preheavy_bounds
    {input : ActionRequestProjectionInput}
    (accepted : actionRequestProjectionAccepts input = true) :
    AcceptedActionRequestProjectionPreHeavyBounds input := by
  have preconditions :
      actionRequestProjectionPreconditions input = true :=
    (accepts_iff_action_request_projection_preconditions).mp accepted
  cases input with
  | mk jsonDecodeAccepts kernelEnvelopeFieldsAbsent routeSupported
      nullifierScopeValid nullifierCountWithinLimit nullifierHexValid
      publicArgsEncodedWithinLimit publicArgsBase64Decodes
      publicArgsDecodedWithinLimit routePayloadDecodesExactly =>
      have jsonDecodeAcceptsFact : jsonDecodeAccepts = true := by
        cases h : jsonDecodeAccepts <;>
          simp [actionRequestProjectionPreconditions, h] at preconditions ⊢
      have kernelEnvelopeFieldsAbsentFact :
          kernelEnvelopeFieldsAbsent = true := by
        cases h : kernelEnvelopeFieldsAbsent <;>
          simp [actionRequestProjectionPreconditions, h] at preconditions ⊢
      have routeSupportedFact : routeSupported = true := by
        cases h : routeSupported <;>
          simp [actionRequestProjectionPreconditions, h] at preconditions ⊢
      have nullifierScopeValidFact : nullifierScopeValid = true := by
        cases h : nullifierScopeValid <;>
          simp [actionRequestProjectionPreconditions, h] at preconditions ⊢
      have nullifierCountWithinLimitFact :
          nullifierCountWithinLimit = true := by
        cases h : nullifierCountWithinLimit <;>
          simp [actionRequestProjectionPreconditions, h] at preconditions ⊢
      have nullifierHexValidFact : nullifierHexValid = true := by
        cases h : nullifierHexValid <;>
          simp [actionRequestProjectionPreconditions, h] at preconditions ⊢
      have publicArgsEncodedWithinLimitFact :
          publicArgsEncodedWithinLimit = true := by
        cases h : publicArgsEncodedWithinLimit <;>
          simp [actionRequestProjectionPreconditions, h] at preconditions ⊢
      have publicArgsBase64DecodesFact :
          publicArgsBase64Decodes = true := by
        cases h : publicArgsBase64Decodes <;>
          simp [actionRequestProjectionPreconditions, h] at preconditions ⊢
      have publicArgsDecodedWithinLimitFact :
          publicArgsDecodedWithinLimit = true := by
        cases h : publicArgsDecodedWithinLimit <;>
          simp [actionRequestProjectionPreconditions, h] at preconditions ⊢
      have routePayloadDecodesExactlyFact :
          routePayloadDecodesExactly = true := by
        cases h : routePayloadDecodesExactly <;>
          simp [actionRequestProjectionPreconditions, h] at preconditions ⊢
      exact {
        actionRequestAccepted := accepted,
        actionRequestPreconditions := preconditions,
        jsonDecodeAccepts := jsonDecodeAcceptsFact,
        kernelEnvelopeFieldsAbsent := kernelEnvelopeFieldsAbsentFact,
        routeSupported := routeSupportedFact,
        nullifierScopeValid := nullifierScopeValidFact,
        nullifierCountWithinLimit := nullifierCountWithinLimitFact,
        nullifierHexValid := nullifierHexValidFact,
        publicArgsEncodedWithinLimit :=
          publicArgsEncodedWithinLimitFact,
        publicArgsBase64Decodes := publicArgsBase64DecodesFact,
        publicArgsDecodedWithinLimit :=
          publicArgsDecodedWithinLimitFact,
        routePayloadDecodesExactly :=
          routePayloadDecodesExactlyFact
      }

structure PreHeavyWorkSyncPathSurface where
  syncDecode : SyncDecodeInput
  responseRangeInput : SyncResponseRangeInput
  responseRange : Nat × Nat
  responseCount : SyncResponseCountInput
  resourcePolicy : ResourcePolicy
  resourceRequest : ResourceRequest
deriving DecidableEq, Repr

structure AcceptedPreHeavyWorkSyncPathInputs
    (surface : PreHeavyWorkSyncPathSurface) : Prop where
  syncDecodeAccepted :
    syncDecodeAccepts surface.syncDecode = true
  responseRangeAccepted :
    responseRange surface.responseRangeInput =
      some surface.responseRange
  responseCountAccepted :
    responseCountAccepts surface.responseCount = true
  syncResourceAccepted :
    evaluateBoundedRequest
      surface.resourcePolicy
      surface.resourceRequest = none
  responseRangeCountMatchesResponseCount :
    responseRangeBlockCount surface.responseRange =
      surface.responseCount.blockCount
  resourceItemCountMatchesResponseCount :
    surface.resourceRequest.itemCount =
      surface.responseCount.blockCount

structure AcceptedPreHeavyWorkSyncPathBounds
    (surface : PreHeavyWorkSyncPathSurface) : Prop where
  syncDecodeAccepted :
    syncDecodeAccepts surface.syncDecode = true
  syncDecodePreconditions :
    syncDecodePreconditions surface.syncDecode = true
  syncDecodeExact :
    surface.syncDecode.boundedWireDecodeAccepts = true
      ∧ surface.syncDecode.consumedAllBytes = true
  responseRangeAccepted :
    responseRange surface.responseRangeInput =
      some surface.responseRange
  responseRangeBoundedFacts :
    AcceptedBoundedRequestFacts
      (responseRangeBoundedPolicy surface.responseRangeInput)
      (responseRangeBoundedRequest surface.responseRange)
  responseRangeItemCountWithinMaxBlocks :
    ¬ surface.responseRangeInput.maxBlocks <
      responseRangeBlockCount surface.responseRange
  responseCountAccepted :
    responseCountAccepts surface.responseCount = true
  responseCountWithinLimit :
    surface.responseCount.blockCount ≤ surface.responseCount.maxBlocks
  responseRangeCountMatchesResponseCount :
    responseRangeBlockCount surface.responseRange =
      surface.responseCount.blockCount
  syncResourceAccepted :
    evaluateBoundedRequest
      surface.resourcePolicy
      surface.resourceRequest = none
  syncResourceFacts :
    AcceptedBoundedRequestFacts
      surface.resourcePolicy
      surface.resourceRequest
  resourceItemCountMatchesResponseCount :
    surface.resourceRequest.itemCount =
      surface.responseCount.blockCount
  responseCountWithinResourceCap :
    ¬ surface.resourcePolicy.itemCountCap <
      surface.responseCount.blockCount

theorem sync_path_accepts_implies_preheavy_bounds
    {surface : PreHeavyWorkSyncPathSurface}
    (accepted : AcceptedPreHeavyWorkSyncPathInputs surface) :
    AcceptedPreHeavyWorkSyncPathBounds surface := by
  have syncPreconditions :
      syncDecodePreconditions surface.syncDecode = true :=
    (sync_accepts_iff_preconditions
      (input := surface.syncDecode)).mp accepted.syncDecodeAccepted
  have syncExact :
      surface.syncDecode.boundedWireDecodeAccepts = true
        ∧ surface.syncDecode.consumedAllBytes = true :=
    sync_decode_acceptance_excludes_malleability
      accepted.syncDecodeAccepted
  have responseRangeFacts :
      AcceptedBoundedRequestFacts
        (responseRangeBoundedPolicy surface.responseRangeInput)
        (responseRangeBoundedRequest surface.responseRange) :=
    accepted_response_range_exposes_bounded_request_facts
      accepted.responseRangeAccepted
  have responseRangeWithinMaxBlocks :
      ¬ surface.responseRangeInput.maxBlocks <
        responseRangeBlockCount surface.responseRange := by
    simpa [responseRangeBoundedPolicy, responseRangeBoundedRequest] using
      responseRangeFacts.itemCountWithinCap
  have responseWithinLimit :
      surface.responseCount.blockCount ≤
        surface.responseCount.maxBlocks :=
    (response_count_accepts_iff_within_limit
      (input := surface.responseCount)).mp
        accepted.responseCountAccepted
  have resourceFacts :
      AcceptedBoundedRequestFacts
        surface.resourcePolicy
        surface.resourceRequest :=
    accepted_bounded_request_exposes_all_caps
      accepted.syncResourceAccepted
  have responseCountWithinResourceCap :
      ¬ surface.resourcePolicy.itemCountCap <
        surface.responseCount.blockCount := by
    simpa [accepted.resourceItemCountMatchesResponseCount] using
      resourceFacts.itemCountWithinCap
  exact {
    syncDecodeAccepted := accepted.syncDecodeAccepted,
    syncDecodePreconditions := syncPreconditions,
    syncDecodeExact := syncExact,
    responseRangeAccepted := accepted.responseRangeAccepted,
    responseRangeBoundedFacts := responseRangeFacts,
    responseRangeItemCountWithinMaxBlocks :=
      responseRangeWithinMaxBlocks,
    responseCountAccepted := accepted.responseCountAccepted,
    responseCountWithinLimit := responseWithinLimit,
    responseRangeCountMatchesResponseCount :=
      accepted.responseRangeCountMatchesResponseCount,
    syncResourceAccepted := accepted.syncResourceAccepted,
    syncResourceFacts := resourceFacts,
    resourceItemCountMatchesResponseCount :=
      accepted.resourceItemCountMatchesResponseCount,
    responseCountWithinResourceCap := responseCountWithinResourceCap
  }

structure PreHeavyWorkVerificationPathSurface where
  resourceSurface : PreHeavyWorkResourceBoundSurface
  syncPath : PreHeavyWorkSyncPathSurface
  actionRequest : ActionRequestProjectionInput
  transferPayload : TransferPayloadInput
  bridgeResourcePolicy : ResourcePolicy
  bridgeResource : BridgeActionResourceInput
  candidateArtifact : CandidateArtifactInput
  txLeafArtifactBytes : List Byte
  txLeafArtifactSummary : TxLeafSummary
  receiptRootExpectedLeafCount : Nat
  receiptRootArtifactBytes : List Byte
  receiptRootSummary : ReceiptRootSummary
deriving DecidableEq, Repr

structure AcceptedPreHeavyWorkVerificationPathInputs
    (surface : PreHeavyWorkVerificationPathSurface)
    (parserCorrectness benchmarkCaps : Prop) : Prop where
  resourceAccepted :
    AcceptedPreHeavyWorkResourceBoundInputs surface.resourceSurface
  syncAccepted :
    AcceptedPreHeavyWorkSyncPathInputs surface.syncPath
  actionRequestAccepted :
    actionRequestProjectionAccepts surface.actionRequest = true
  transferPayloadAccepted :
    transferPayloadAccepts surface.transferPayload = true
  bridgeResourceAccepted :
    evaluateBoundedRequest
        surface.bridgeResourcePolicy
        (bridgeActionResourceRequest surface.bridgeResource) = none
  candidateArtifactAccepted :
    evaluateCandidateArtifact surface.candidateArtifact = Except.ok ()
  txLeafArtifactParsed :
    parseNativeTxLeafArtifact surface.txLeafArtifactBytes =
      some surface.txLeafArtifactSummary
  receiptRootArtifactParsed :
    parseNativeReceiptRootArtifact surface.receiptRootArtifactBytes =
      some surface.receiptRootSummary
  receiptRootScheduleAccepted :
    receiptRootScheduleAccepts
        surface.receiptRootExpectedLeafCount
        surface.receiptRootArtifactBytes = true
  parserCorrectnessAssumption :
    parserCorrectness
  benchmarkCapsAssumption :
    benchmarkCaps

structure AcceptedPreHeavyWorkVerificationPathBounds
    (surface : PreHeavyWorkVerificationPathSurface)
    (parserCorrectness benchmarkCaps : Prop) : Prop where
  resourceFacts :
    AcceptedPreHeavyWorkResourceBoundFacts surface.resourceSurface
  syncBounds :
    AcceptedPreHeavyWorkSyncPathBounds surface.syncPath
  actionRequestAccepted :
    actionRequestProjectionAccepts surface.actionRequest = true
  actionRequestPreconditions :
    actionRequestProjectionPreconditions surface.actionRequest = true
  actionRequestBounds :
    AcceptedActionRequestProjectionPreHeavyBounds surface.actionRequest
  transferBounds :
    AcceptedTransferPayloadPreHeavyBounds surface.transferPayload
  bridgeResourceFacts :
    AcceptedBridgeActionResourceFacts
      surface.bridgeResourcePolicy
      surface.bridgeResource
  candidateBounds :
    AcceptedCandidateArtifactPreHeavyBounds surface.candidateArtifact
  txLeafArtifactByteShapeFacts :
    AcceptedNativeTxLeafArtifactByteShapeFacts
      surface.txLeafArtifactBytes
      surface.txLeafArtifactSummary
  receiptRootScheduleFacts :
    ReceiptRootScheduleFacts
      surface.receiptRootExpectedLeafCount
      surface.receiptRootArtifactBytes
      surface.receiptRootSummary
  parserCorrectnessAssumption :
    parserCorrectness
  benchmarkCapsAssumption :
    benchmarkCaps

theorem accepted_preheavy_public_input_parser_admission_bounds_verification_paths
    {surface : PreHeavyWorkVerificationPathSurface}
    {parserCorrectness benchmarkCaps : Prop}
    (accepted :
      AcceptedPreHeavyWorkVerificationPathInputs
        surface
        parserCorrectness
        benchmarkCaps) :
    AcceptedPreHeavyWorkVerificationPathBounds
      surface
      parserCorrectness
      benchmarkCaps := by
  exact {
    resourceFacts :=
      accepted_preheavy_resource_bound_surface_exposes_bounds
        accepted.resourceAccepted,
    syncBounds :=
      sync_path_accepts_implies_preheavy_bounds
        accepted.syncAccepted,
    actionRequestAccepted := accepted.actionRequestAccepted,
    actionRequestPreconditions :=
      (action_request_projection_accepts_implies_preheavy_bounds
        accepted.actionRequestAccepted).actionRequestPreconditions,
    actionRequestBounds :=
      action_request_projection_accepts_implies_preheavy_bounds
        accepted.actionRequestAccepted,
    transferBounds :=
      transfer_payload_accepts_implies_preheavy_bounds
        accepted.transferPayloadAccepted,
    bridgeResourceFacts :=
      accepted_bridge_action_resource_exposes_bounds
        accepted.bridgeResourceAccepted,
    candidateBounds :=
      candidate_artifact_accepts_implies_preheavy_bounds
        accepted.candidateArtifactAccepted,
    txLeafArtifactByteShapeFacts :=
      accepted_native_tx_leaf_artifact_bytes_expose_shape_facts
        accepted.txLeafArtifactParsed,
    receiptRootScheduleFacts :=
      receipt_root_schedule_accepts_implies_facts
        accepted.receiptRootArtifactParsed
        accepted.receiptRootScheduleAccepted,
    parserCorrectnessAssumption :=
      accepted.parserCorrectnessAssumption,
    benchmarkCapsAssumption :=
      accepted.benchmarkCapsAssumption
  }

structure AcceptedPreHeavyWorkDoSBoundCertificate
    (surface : PreHeavyWorkVerificationPathSurface)
    (parserCorrectness benchmarkCaps : Prop) : Prop where
  rpcAndSidecarResourceBounds :
    AcceptedPreHeavyWorkResourceBoundFacts surface.resourceSurface
  syncBounds :
    AcceptedPreHeavyWorkSyncPathBounds surface.syncPath
  actionRequestBounds :
    AcceptedActionRequestProjectionPreHeavyBounds surface.actionRequest
  transferBounds :
    AcceptedTransferPayloadPreHeavyBounds surface.transferPayload
  bridgeResourceFacts :
    AcceptedBridgeActionResourceFacts
      surface.bridgeResourcePolicy
      surface.bridgeResource
  candidateArtifactBounds :
    AcceptedCandidateArtifactPreHeavyBounds surface.candidateArtifact
  txLeafArtifactByteShapeFacts :
    AcceptedNativeTxLeafArtifactByteShapeFacts
      surface.txLeafArtifactBytes
      surface.txLeafArtifactSummary
  receiptRootScheduleFacts :
    ReceiptRootScheduleFacts
      surface.receiptRootExpectedLeafCount
      surface.receiptRootArtifactBytes
      surface.receiptRootSummary
  parserCorrectnessAssumption :
    parserCorrectness
  benchmarkCapsAssumption :
    benchmarkCaps

theorem accepted_preheavy_work_dos_bound_certificate
    {surface : PreHeavyWorkVerificationPathSurface}
    {parserCorrectness benchmarkCaps : Prop}
    (accepted :
      AcceptedPreHeavyWorkVerificationPathInputs
        surface
        parserCorrectness
        benchmarkCaps) :
    AcceptedPreHeavyWorkDoSBoundCertificate
      surface
      parserCorrectness
      benchmarkCaps := by
  have pathBounds :
      AcceptedPreHeavyWorkVerificationPathBounds
        surface
        parserCorrectness
        benchmarkCaps :=
    accepted_preheavy_public_input_parser_admission_bounds_verification_paths
      accepted
  exact {
    rpcAndSidecarResourceBounds := pathBounds.resourceFacts,
    syncBounds := pathBounds.syncBounds,
    actionRequestBounds := pathBounds.actionRequestBounds,
    transferBounds := pathBounds.transferBounds,
    bridgeResourceFacts := pathBounds.bridgeResourceFacts,
    candidateArtifactBounds := pathBounds.candidateBounds,
    txLeafArtifactByteShapeFacts :=
      pathBounds.txLeafArtifactByteShapeFacts,
    receiptRootScheduleFacts := pathBounds.receiptRootScheduleFacts,
    parserCorrectnessAssumption :=
      pathBounds.parserCorrectnessAssumption,
    benchmarkCapsAssumption :=
      pathBounds.benchmarkCapsAssumption
  }

end PreHeavyWorkResourceBoundSurface
end Native
end Hegemon
