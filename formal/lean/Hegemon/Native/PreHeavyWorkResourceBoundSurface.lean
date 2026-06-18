import Hegemon.Consensus.RecursiveBlockAdmission
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
open Hegemon.Consensus.RecursiveBlockAdmission
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

structure StagedProofUploadPreHeavyInput where
  proofMetadata : ProofMetadataInput
  stagedProofBudget : StagedProofBudgetInput
  proofDecoded : ProofDecodedInput
deriving DecidableEq, Repr

inductive StagedProofUploadPreHeavyReject where
  | metadata : SidecarUploadReject -> StagedProofUploadPreHeavyReject
  | stagedProofBudget : BudgetReject -> StagedProofUploadPreHeavyReject
  | decoded : SidecarUploadReject -> StagedProofUploadPreHeavyReject
deriving DecidableEq, Repr

def evaluateStagedProofUploadPreHeavy
    (input : StagedProofUploadPreHeavyInput) :
    Except StagedProofUploadPreHeavyReject Unit :=
  match evaluateProofMetadata input.proofMetadata with
  | Except.error reject =>
      Except.error (StagedProofUploadPreHeavyReject.metadata reject)
  | Except.ok _ =>
      match evaluateStagedProofBudgetRejection input.stagedProofBudget with
      | some reject =>
          Except.error
            (StagedProofUploadPreHeavyReject.stagedProofBudget reject)
      | none =>
          match evaluateProofDecoded input.proofDecoded with
          | Except.error reject =>
              Except.error (StagedProofUploadPreHeavyReject.decoded reject)
          | Except.ok _ => Except.ok ()

structure AcceptedStagedProofUploadPreHeavyFacts
    (input : StagedProofUploadPreHeavyInput) : Prop where
  proofMetadataAccepted :
    evaluateProofMetadata input.proofMetadata = Except.ok ()
  proofMetadataPreconditions :
    proofMetadataPreconditions input.proofMetadata = true
  stagedProofBudgetAccepted :
    evaluateStagedProofBudgetRejection input.stagedProofBudget = none
  stagedProofWithinBudget :
    ¬ input.stagedProofBudget.maxBytes <
      stagedProofBudgetTotal input.stagedProofBudget
  proofDecodedAccepted :
    evaluateProofDecoded input.proofDecoded = Except.ok ()
  proofDecodedPreconditions :
    proofDecodedPreconditions input.proofDecoded = true

theorem accepted_staged_proof_upload_preheavy_exposes_bounds
    {input : StagedProofUploadPreHeavyInput}
    (accepted :
      evaluateStagedProofUploadPreHeavy input = Except.ok ()) :
    AcceptedStagedProofUploadPreHeavyFacts input := by
  unfold evaluateStagedProofUploadPreHeavy at accepted
  cases hMetadata : evaluateProofMetadata input.proofMetadata with
  | error reject =>
      simp [hMetadata] at accepted
  | ok metadataUnit =>
      cases hBudget :
          evaluateStagedProofBudgetRejection input.stagedProofBudget with
      | some budgetReject =>
          simp [hMetadata, hBudget] at accepted
      | none =>
          cases hDecoded : evaluateProofDecoded input.proofDecoded with
          | error decodedReject =>
              simp [hMetadata, hBudget, hDecoded] at accepted
          | ok decodedUnit =>
              cases metadataUnit
              cases decodedUnit
              have metadataAccepts :
                  accepts (evaluateProofMetadata input.proofMetadata) =
                    true := by
                simp [accepts, hMetadata]
              have budgetAccepts :
                  stagedProofBudgetAccepts input.stagedProofBudget =
                    true := by
                simp [stagedProofBudgetAccepts, hBudget]
              have decodedAccepts :
                  accepts (evaluateProofDecoded input.proofDecoded) =
                    true := by
                simp [accepts, hDecoded]
              exact {
                proofMetadataAccepted := hMetadata,
                proofMetadataPreconditions := by
                  have eq := proof_metadata_accepts_iff_preconditions
                    input.proofMetadata
                  rw [eq] at metadataAccepts
                  exact metadataAccepts,
                stagedProofBudgetAccepted := hBudget,
                stagedProofWithinBudget :=
                  staged_proof_accepts_iff_not_over_limit.mp
                    budgetAccepts,
                proofDecodedAccepted := hDecoded,
                proofDecodedPreconditions := by
                  have eq := proof_decoded_accepts_iff_preconditions
                    input.proofDecoded
                  rw [eq] at decodedAccepts
                  exact decodedAccepts
              }

theorem staged_proof_upload_metadata_rejects_before_budget
    {input : StagedProofUploadPreHeavyInput}
    {reject : SidecarUploadReject}
    (metadataReject :
      evaluateProofMetadata input.proofMetadata =
        Except.error reject) :
    evaluateStagedProofUploadPreHeavy input =
      Except.error (StagedProofUploadPreHeavyReject.metadata reject) := by
  unfold evaluateStagedProofUploadPreHeavy
  rw [metadataReject]

theorem staged_proof_upload_budget_rejects_before_decoded
    {input : StagedProofUploadPreHeavyInput}
    {reject : BudgetReject}
    (metadataAccepted :
      evaluateProofMetadata input.proofMetadata = Except.ok ())
    (budgetReject :
      evaluateStagedProofBudgetRejection input.stagedProofBudget =
        some reject) :
    evaluateStagedProofUploadPreHeavy input =
      Except.error
        (StagedProofUploadPreHeavyReject.stagedProofBudget reject) := by
  unfold evaluateStagedProofUploadPreHeavy
  rw [metadataAccepted, budgetReject]

theorem staged_proof_upload_decoded_rejects_after_budget_accepts
    {input : StagedProofUploadPreHeavyInput}
    {reject : SidecarUploadReject}
    (metadataAccepted :
      evaluateProofMetadata input.proofMetadata = Except.ok ())
    (budgetAccepted :
      evaluateStagedProofBudgetRejection input.stagedProofBudget = none)
    (decodedReject :
      evaluateProofDecoded input.proofDecoded = Except.error reject) :
    evaluateStagedProofUploadPreHeavy input =
      Except.error (StagedProofUploadPreHeavyReject.decoded reject) := by
  unfold evaluateStagedProofUploadPreHeavy
  rw [metadataAccepted, budgetAccepted, decodedReject]

def validStagedProofUploadPreHeavyInput :
    StagedProofUploadPreHeavyInput :=
  {
    proofMetadata := validProofMetadata,
    stagedProofBudget := stagedProofReplacementInput,
    proofDecoded := validProofDecoded
  }

def stagedProofBudgetPrecedesBindingMismatchInput :
    StagedProofUploadPreHeavyInput :=
  {
    validStagedProofUploadPreHeavyInput with
    stagedProofBudget := stagedProofOverLimitInput,
    proofDecoded := {
      validProofDecoded with
      proofBindingHashMatchesKey := false
    }
  }

def stagedProofBudgetPrecedesDecodedOversizeInput :
    StagedProofUploadPreHeavyInput :=
  {
    validStagedProofUploadPreHeavyInput with
    stagedProofBudget := stagedProofOverLimitInput,
    proofDecoded := {
      validProofDecoded with
      proofBytes := validProofDecoded.maxProofBytes + 1
    }
  }

theorem valid_staged_proof_upload_preheavy_accepts :
    evaluateStagedProofUploadPreHeavy
      validStagedProofUploadPreHeavyInput = Except.ok () := by
  rfl

theorem staged_proof_budget_precedes_binding_mismatch :
    evaluateStagedProofUploadPreHeavy
      stagedProofBudgetPrecedesBindingMismatchInput =
        Except.error
          (StagedProofUploadPreHeavyReject.stagedProofBudget
            BudgetReject.stagedProofByteBudgetExceeded) := by
  rfl

theorem staged_proof_budget_precedes_decoded_oversize :
    evaluateStagedProofUploadPreHeavy
      stagedProofBudgetPrecedesDecodedOversizeInput =
        Except.error
          (StagedProofUploadPreHeavyReject.stagedProofBudget
            BudgetReject.stagedProofByteBudgetExceeded) := by
  rfl

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
  txLeafArtifactResourcePolicy : ResourcePolicy
  recursiveBlockArtifact : ArtifactAdmissionInput
  receiptRootExpectedLeafCount : Nat
  receiptRootArtifactBytes : List Byte
  receiptRootSummary : ReceiptRootSummary
  receiptRootResourcePolicy : ResourcePolicy
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
  txLeafArtifactResourceAccepted :
    evaluateBoundedRequest
        surface.txLeafArtifactResourcePolicy
        (txLeafArtifactResourceRequest
          surface.txLeafArtifactBytes
          surface.txLeafArtifactSummary) = none
  recursiveBlockArtifactAccepted :
    artifactAccepts surface.recursiveBlockArtifact = true
  receiptRootArtifactParsed :
    parseNativeReceiptRootArtifact surface.receiptRootArtifactBytes =
      some surface.receiptRootSummary
  receiptRootScheduleAccepted :
    receiptRootScheduleAccepts
        surface.receiptRootExpectedLeafCount
        surface.receiptRootArtifactBytes = true
  receiptRootResourceAccepted :
    evaluateBoundedRequest
        surface.receiptRootResourcePolicy
        (receiptRootArtifactResourceRequest
          surface.receiptRootArtifactBytes
          surface.receiptRootSummary) = none
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
  txLeafArtifactResourceFacts :
    AcceptedNativeTxLeafArtifactResourceFacts
      surface.txLeafArtifactResourcePolicy
      surface.txLeafArtifactBytes
      surface.txLeafArtifactSummary
  recursiveBlockArtifactResourceFacts :
    AcceptedBoundedRequestFacts
      (recursiveBlockArtifactResourcePolicy
        surface.recursiveBlockArtifact)
      (recursiveBlockArtifactResourceRequest
        surface.recursiveBlockArtifact)
  receiptRootScheduleFacts :
    ReceiptRootScheduleFacts
      surface.receiptRootExpectedLeafCount
      surface.receiptRootArtifactBytes
      surface.receiptRootSummary
  receiptRootResourceFacts :
    ReceiptRootResourceFacts
      surface.receiptRootResourcePolicy
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
    txLeafArtifactResourceFacts :=
      accepted_native_tx_leaf_artifact_resource_exposes_bounds
        accepted.txLeafArtifactParsed
        accepted.txLeafArtifactResourceAccepted,
    recursiveBlockArtifactResourceFacts :=
      recursive_block_artifact_accepts_implies_bounded_request_facts
        accepted.recursiveBlockArtifactAccepted,
    receiptRootScheduleFacts :=
      receipt_root_schedule_accepts_implies_facts
        accepted.receiptRootArtifactParsed
        accepted.receiptRootScheduleAccepted,
    receiptRootResourceFacts :=
      accepted_receipt_root_resource_exposes_bounds
        accepted.receiptRootResourceAccepted,
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
  txLeafArtifactResourceFacts :
    AcceptedNativeTxLeafArtifactResourceFacts
      surface.txLeafArtifactResourcePolicy
      surface.txLeafArtifactBytes
      surface.txLeafArtifactSummary
  recursiveBlockArtifactResourceFacts :
    AcceptedBoundedRequestFacts
      (recursiveBlockArtifactResourcePolicy
        surface.recursiveBlockArtifact)
      (recursiveBlockArtifactResourceRequest
        surface.recursiveBlockArtifact)
  receiptRootScheduleFacts :
    ReceiptRootScheduleFacts
      surface.receiptRootExpectedLeafCount
      surface.receiptRootArtifactBytes
      surface.receiptRootSummary
  receiptRootResourceFacts :
    ReceiptRootResourceFacts
      surface.receiptRootResourcePolicy
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
    txLeafArtifactResourceFacts :=
      pathBounds.txLeafArtifactResourceFacts,
    recursiveBlockArtifactResourceFacts :=
      pathBounds.recursiveBlockArtifactResourceFacts,
    receiptRootScheduleFacts := pathBounds.receiptRootScheduleFacts,
    receiptRootResourceFacts := pathBounds.receiptRootResourceFacts,
    parserCorrectnessAssumption :=
      pathBounds.parserCorrectnessAssumption,
    benchmarkCapsAssumption :=
      pathBounds.benchmarkCapsAssumption
  }

inductive PublicInputCostFamily where
  | mempoolAdmission
  | stagedProofAdmission
  | rpcHexBytes
  | rpcBase64Bytes
  | rpcBatch
  | sidecarCiphertextRequest
  | sidecarProofRequest
  | sidecarCiphertextCapacity
  | sidecarProofCapacity
  | sidecarProofMetadata
  | sidecarProofDecoded
  | mineableAction
  | syncWireDecode
  | syncResponseRange
  | syncResponseCount
  | syncResponseImport
  | submitActionRequest
  | transferPayload
  | bridgeActionPayload
  | candidateArtifact
  | nativeTxLeafArtifact
  | receiptRootArtifact
deriving DecidableEq, Repr

def productionPublicInputCostFamilies : List PublicInputCostFamily := [
  PublicInputCostFamily.mempoolAdmission,
  PublicInputCostFamily.stagedProofAdmission,
  PublicInputCostFamily.rpcHexBytes,
  PublicInputCostFamily.rpcBase64Bytes,
  PublicInputCostFamily.rpcBatch,
  PublicInputCostFamily.sidecarCiphertextRequest,
  PublicInputCostFamily.sidecarProofRequest,
  PublicInputCostFamily.sidecarCiphertextCapacity,
  PublicInputCostFamily.sidecarProofCapacity,
  PublicInputCostFamily.sidecarProofMetadata,
  PublicInputCostFamily.sidecarProofDecoded,
  PublicInputCostFamily.mineableAction,
  PublicInputCostFamily.syncWireDecode,
  PublicInputCostFamily.syncResponseRange,
  PublicInputCostFamily.syncResponseCount,
  PublicInputCostFamily.syncResponseImport,
  PublicInputCostFamily.submitActionRequest,
  PublicInputCostFamily.transferPayload,
  PublicInputCostFamily.bridgeActionPayload,
  PublicInputCostFamily.candidateArtifact,
  PublicInputCostFamily.nativeTxLeafArtifact,
  PublicInputCostFamily.receiptRootArtifact
]

def publicInputCostFamilyCovered
    (surface : PreHeavyWorkVerificationPathSurface)
    (family : PublicInputCostFamily) : Prop :=
  match family with
  | PublicInputCostFamily.mempoolAdmission =>
      evaluateMempoolBudgetRejection
          surface.resourceSurface.mempoolBudget = none
        ∧ ¬ surface.resourceSurface.mempoolBudget.maxBytes <
          mempoolBudgetTotal surface.resourceSurface.mempoolBudget
  | PublicInputCostFamily.stagedProofAdmission =>
      evaluateStagedProofBudgetRejection
          surface.resourceSurface.stagedProofBudget = none
        ∧ ¬ surface.resourceSurface.stagedProofBudget.maxBytes <
          stagedProofBudgetTotal surface.resourceSurface.stagedProofBudget
  | PublicInputCostFamily.rpcHexBytes =>
      byteParseAccepts (hexByteParseInput surface.resourceSurface) = true
        ∧ (¬ hexLenLimit surface.resourceSurface.hexMaxDecodedBytes <
            surface.resourceSurface.hexRawTextBytes
          ∧ ¬ surface.resourceSurface.hexMaxDecodedBytes <
            surface.resourceSurface.hexDecodedBytes)
  | PublicInputCostFamily.rpcBase64Bytes =>
      byteParseAccepts (base64ByteParseInput surface.resourceSurface) =
          true
        ∧ (¬ encodedLenLimit
              surface.resourceSurface.base64MaxDecodedBytes <
            surface.resourceSurface.base64RawTextBytes
          ∧ ¬ surface.resourceSurface.base64MaxDecodedBytes <
            surface.resourceSurface.base64DecodedBytes)
  | PublicInputCostFamily.rpcBatch =>
      evaluateBatchRejection surface.resourceSurface.rpcBatch = none
        ∧ surface.resourceSurface.rpcBatch.requestCount ≠ 0
        ∧ ¬ surface.resourceSurface.rpcBatch.maxRequests <
          surface.resourceSurface.rpcBatch.requestCount
  | PublicInputCostFamily.sidecarCiphertextRequest =>
      evaluateCiphertextRequest
          surface.resourceSurface.ciphertextRequest = Except.ok ()
        ∧ ¬ surface.resourceSurface.ciphertextRequest.itemCount >
          surface.resourceSurface.ciphertextRequest.maxItems
  | PublicInputCostFamily.sidecarProofRequest =>
      evaluateProofRequest
          surface.resourceSurface.proofRequest = Except.ok ()
        ∧ ¬ surface.resourceSurface.proofRequest.itemCount >
          surface.resourceSurface.proofRequest.maxItems
  | PublicInputCostFamily.sidecarCiphertextCapacity =>
      evaluateCiphertextCapacity
          surface.resourceSurface.ciphertextCapacity = Except.ok ()
        ∧ capacityPreconditions
          surface.resourceSurface.ciphertextCapacity = true
  | PublicInputCostFamily.sidecarProofCapacity =>
      evaluateProofCapacity
          surface.resourceSurface.proofCapacity = Except.ok ()
        ∧ capacityPreconditions
          surface.resourceSurface.proofCapacity = true
  | PublicInputCostFamily.sidecarProofMetadata =>
      evaluateProofMetadata
          surface.resourceSurface.proofMetadata = Except.ok ()
        ∧ proofMetadataPreconditions
          surface.resourceSurface.proofMetadata = true
  | PublicInputCostFamily.sidecarProofDecoded =>
      evaluateProofDecoded
          surface.resourceSurface.proofDecoded = Except.ok ()
        ∧ proofDecodedPreconditions
          surface.resourceSurface.proofDecoded = true
  | PublicInputCostFamily.mineableAction =>
      evaluateMineableAction
          surface.resourceSurface.mineableAction = Except.ok ()
        ∧ mineableActionPreconditions
          surface.resourceSurface.mineableAction = true
  | PublicInputCostFamily.syncWireDecode =>
      syncDecodeAccepts surface.syncPath.syncDecode = true
        ∧ surface.syncPath.syncDecode.boundedWireDecodeAccepts = true
        ∧ surface.syncPath.syncDecode.consumedAllBytes = true
  | PublicInputCostFamily.syncResponseRange =>
      responseRange surface.syncPath.responseRangeInput =
          some surface.syncPath.responseRange
        ∧ ¬ surface.syncPath.responseRangeInput.maxBlocks <
          responseRangeBlockCount surface.syncPath.responseRange
  | PublicInputCostFamily.syncResponseCount =>
      responseCountAccepts surface.syncPath.responseCount = true
        ∧ surface.syncPath.responseCount.blockCount ≤
          surface.syncPath.responseCount.maxBlocks
  | PublicInputCostFamily.syncResponseImport =>
      evaluateBoundedRequest
          surface.syncPath.resourcePolicy
          surface.syncPath.resourceRequest = none
        ∧ surface.syncPath.resourceRequest.itemCount =
          surface.syncPath.responseCount.blockCount
        ∧ ¬ surface.syncPath.resourcePolicy.itemCountCap <
          surface.syncPath.responseCount.blockCount
  | PublicInputCostFamily.submitActionRequest =>
      actionRequestProjectionAccepts surface.actionRequest = true
        ∧ actionRequestProjectionPreconditions surface.actionRequest =
          true
  | PublicInputCostFamily.transferPayload =>
      transferPayloadAccepts surface.transferPayload = true
        ∧ transferPayloadPreconditions surface.transferPayload = true
        ∧ surface.transferPayload.proofBytes ≠ 0
        ∧ ¬ surface.transferPayload.proofBytes >
          surface.transferPayload.maxProofBytes
        ∧ ¬ surface.transferPayload.inlineCiphertextBytes >
          surface.transferPayload.maxCiphertextBytes
  | PublicInputCostFamily.bridgeActionPayload =>
      evaluateBoundedRequest
          surface.bridgeResourcePolicy
          (bridgeActionResourceRequest surface.bridgeResource) = none
        ∧ ¬ surface.bridgeResourcePolicy.rawByteCap <
          surface.bridgeResource.publicArgsBytes
        ∧ ¬ surface.bridgeResourcePolicy.decodedByteCap <
          surface.bridgeResource.publicArgsBytes
        ∧ ¬ surface.bridgeResourcePolicy.aggregateByteCap <
          bridgeActionResourceAggregateBytes surface.bridgeResource
        ∧ ¬ surface.bridgeResourcePolicy.workUnitCap <
          bridgeActionResourcePayloadWorkUnits surface.bridgeResource
  | PublicInputCostFamily.candidateArtifact =>
      evaluateCandidateArtifact surface.candidateArtifact =
          Except.ok ()
        ∧ surface.candidateArtifact.txCount ≠ 0
        ∧ ¬ surface.candidateArtifact.txCount >
          surface.candidateArtifact.maxTxCount
        ∧ surface.candidateArtifact.daChunkCount ≠ 0
        ∧ surface.candidateArtifact.recursiveProofBytes ≠ 0
        ∧ ¬ surface.candidateArtifact.recursiveProofBytes >
          surface.candidateArtifact.maxRecursiveProofBytes
  | PublicInputCostFamily.nativeTxLeafArtifact =>
      parseNativeTxLeafArtifact surface.txLeafArtifactBytes =
          some surface.txLeafArtifactSummary
        ∧ evaluateBoundedRequest
          surface.txLeafArtifactResourcePolicy
          (txLeafArtifactResourceRequest
            surface.txLeafArtifactBytes
            surface.txLeafArtifactSummary) = none
        ∧ ¬ surface.txLeafArtifactResourcePolicy.rawByteCap <
          surface.txLeafArtifactBytes.length
        ∧ ¬ surface.txLeafArtifactResourcePolicy.decodedByteCap <
          surface.txLeafArtifactBytes.length
        ∧ ¬ surface.txLeafArtifactResourcePolicy.itemCountCap <
          txLeafArtifactDynamicItemCount
            surface.txLeafArtifactSummary
        ∧ ¬ surface.txLeafArtifactResourcePolicy.itemByteCap <
          surface.txLeafArtifactSummary.starkProofLen
        ∧ ¬ surface.txLeafArtifactResourcePolicy.aggregateByteCap <
          txLeafArtifactAggregateBytes
            surface.txLeafArtifactSummary
        ∧ ¬ surface.txLeafArtifactResourcePolicy.workUnitCap <
          txLeafArtifactWorkUnits
            surface.txLeafArtifactSummary
        ∧ surface.txLeafArtifactSummary.serialized.inputFlagCount ≤
          TxLeafArtifact.maxInputs
        ∧ surface.txLeafArtifactSummary.serialized.outputFlagCount ≤
          TxLeafArtifact.maxOutputs
        ∧ surface.txLeafArtifactSummary.serialized.balanceSlotCount ≤
          TxLeafArtifact.balanceSlots
        ∧ surface.txLeafArtifactSummary.publicTx.nullifierCount ≤
          TxLeafArtifact.maxInputs
        ∧ surface.txLeafArtifactSummary.publicTx.commitmentCount ≤
          TxLeafArtifact.maxOutputs
        ∧ surface.txLeafArtifactSummary.publicTx.ciphertextHashCount ≤
          TxLeafArtifact.maxOutputs
        ∧ surface.txLeafArtifactSummary.starkProofLen ≤
          TxLeafArtifact.maxNativeTxStarkProofBytes
        ∧ surface.txLeafArtifactSummary.commitment.rowCount ≤
          TxLeafArtifact.matrixRows
  | PublicInputCostFamily.receiptRootArtifact =>
      parseNativeReceiptRootArtifact
          surface.receiptRootArtifactBytes =
        some surface.receiptRootSummary
        ∧ evaluateBoundedRequest
          surface.receiptRootResourcePolicy
          (receiptRootArtifactResourceRequest
            surface.receiptRootArtifactBytes
            surface.receiptRootSummary) = none
        ∧ ¬ surface.receiptRootResourcePolicy.rawByteCap <
          surface.receiptRootArtifactBytes.length
        ∧ ¬ surface.receiptRootResourcePolicy.decodedByteCap <
          surface.receiptRootArtifactBytes.length
        ∧ ¬ surface.receiptRootResourcePolicy.itemCountCap <
          receiptRootDynamicItemCount surface.receiptRootSummary
        ∧ ¬ surface.receiptRootResourcePolicy.itemByteCap <
          receiptRootMaxItemBytes surface.receiptRootSummary
        ∧ ¬ surface.receiptRootResourcePolicy.aggregateByteCap <
          receiptRootAggregateBytes surface.receiptRootSummary
        ∧ ¬ surface.receiptRootResourcePolicy.workUnitCap <
          receiptRootWorkUnits surface.receiptRootSummary
        ∧ receiptRootScheduleAccepts
          surface.receiptRootExpectedLeafCount
          surface.receiptRootArtifactBytes = true
        ∧ 0 < surface.receiptRootExpectedLeafCount
        ∧ surface.receiptRootSummary.leafCount =
          surface.receiptRootExpectedLeafCount
        ∧ surface.receiptRootSummary.foldCount =
          expectedFoldCount surface.receiptRootExpectedLeafCount
        ∧ allFoldShapesExact surface.receiptRootSummary.folds = true

theorem preheavy_certificate_covers_public_input_cost_family
    {surface : PreHeavyWorkVerificationPathSurface}
    {parserCorrectness benchmarkCaps : Prop}
    (certificate :
      AcceptedPreHeavyWorkDoSBoundCertificate
        surface
        parserCorrectness
        benchmarkCaps)
    (family : PublicInputCostFamily) :
    publicInputCostFamilyCovered surface family := by
  cases family <;> unfold publicInputCostFamilyCovered
  · exact ⟨
      certificate.rpcAndSidecarResourceBounds.mempoolBudgetAccepted,
      certificate.rpcAndSidecarResourceBounds.mempoolWithinBudget⟩
  · exact ⟨
      certificate.rpcAndSidecarResourceBounds.stagedProofBudgetAccepted,
      certificate.rpcAndSidecarResourceBounds.stagedProofWithinBudget⟩
  · exact ⟨
      certificate.rpcAndSidecarResourceBounds.hexByteParseAccepted,
      certificate.rpcAndSidecarResourceBounds.hexByteCapsHold⟩
  · exact ⟨
      certificate.rpcAndSidecarResourceBounds.base64ByteParseAccepted,
      certificate.rpcAndSidecarResourceBounds.base64ByteCapsHold⟩
  · exact ⟨
      certificate.rpcAndSidecarResourceBounds.rpcBatchAccepted,
      certificate.rpcAndSidecarResourceBounds.rpcBatchNonemptyWithinCap⟩
  · exact ⟨
      certificate.rpcAndSidecarResourceBounds.ciphertextRequestAccepted,
      certificate.rpcAndSidecarResourceBounds.ciphertextRequestWithinCap⟩
  · exact ⟨
      certificate.rpcAndSidecarResourceBounds.proofRequestAccepted,
      certificate.rpcAndSidecarResourceBounds.proofRequestWithinCap⟩
  · exact ⟨
      certificate.rpcAndSidecarResourceBounds.ciphertextCapacityAccepted,
      certificate.rpcAndSidecarResourceBounds.ciphertextCapacityPreconditions⟩
  · exact ⟨
      certificate.rpcAndSidecarResourceBounds.proofCapacityAccepted,
      certificate.rpcAndSidecarResourceBounds.proofCapacityPreconditions⟩
  · exact ⟨
      certificate.rpcAndSidecarResourceBounds.proofMetadataAccepted,
      certificate.rpcAndSidecarResourceBounds.proofMetadataPreconditions⟩
  · exact ⟨
      certificate.rpcAndSidecarResourceBounds.proofDecodedAccepted,
      certificate.rpcAndSidecarResourceBounds.proofDecodedPreconditions⟩
  · exact ⟨
      certificate.rpcAndSidecarResourceBounds.mineableActionAccepted,
      certificate.rpcAndSidecarResourceBounds.mineableActionPreconditions⟩
  · exact ⟨
      certificate.syncBounds.syncDecodeAccepted,
      certificate.syncBounds.syncDecodeExact⟩
  · exact ⟨
      certificate.syncBounds.responseRangeAccepted,
      certificate.syncBounds.responseRangeItemCountWithinMaxBlocks⟩
  · exact ⟨
      certificate.syncBounds.responseCountAccepted,
      certificate.syncBounds.responseCountWithinLimit⟩
  · exact ⟨
      certificate.syncBounds.syncResourceAccepted,
      certificate.syncBounds.resourceItemCountMatchesResponseCount,
      certificate.syncBounds.responseCountWithinResourceCap⟩
  · exact ⟨
      certificate.actionRequestBounds.actionRequestAccepted,
      certificate.actionRequestBounds.actionRequestPreconditions⟩
  · exact ⟨
      certificate.transferBounds.transferPayloadAccepted,
      certificate.transferBounds.transferPayloadPreconditions,
      certificate.transferBounds.proofPresent,
      certificate.transferBounds.proofWithinCap,
      certificate.transferBounds.inlineCiphertextWithinCap⟩
  · exact ⟨
      certificate.bridgeResourceFacts.boundedFacts.accepted,
      certificate.bridgeResourceFacts.publicArgsWithinRawCap,
      certificate.bridgeResourceFacts.publicArgsWithinDecodedCap,
      certificate.bridgeResourceFacts.dynamicAggregateWithinCap,
      certificate.bridgeResourceFacts.payloadWorkWithinCap⟩
  · exact ⟨
      certificate.candidateArtifactBounds.candidateArtifactAccepted,
      certificate.candidateArtifactBounds.txCountNonzero,
      certificate.candidateArtifactBounds.txCountWithinCap,
      certificate.candidateArtifactBounds.daChunkCountNonzero,
      certificate.candidateArtifactBounds.recursiveProofNonempty,
      certificate.candidateArtifactBounds.recursiveProofWithinCap⟩
  · exact ⟨
      certificate.txLeafArtifactByteShapeFacts.parsed,
      certificate.txLeafArtifactResourceFacts.boundedFacts.accepted,
      certificate.txLeafArtifactResourceFacts.artifactRawBytesWithinCap,
      certificate.txLeafArtifactResourceFacts.artifactDecodedBytesWithinCap,
      certificate.txLeafArtifactResourceFacts.dynamicItemCountWithinCap,
      certificate.txLeafArtifactResourceFacts.starkProofBytesWithinItemByteCap,
      certificate.txLeafArtifactResourceFacts.aggregateBytesWithinCap,
      certificate.txLeafArtifactResourceFacts.workUnitsWithinCap,
      certificate.txLeafArtifactByteShapeFacts.serializedInputFlagCountBound,
      certificate.txLeafArtifactByteShapeFacts.serializedOutputFlagCountBound,
      certificate.txLeafArtifactByteShapeFacts.serializedBalanceSlotCountBound,
      certificate.txLeafArtifactByteShapeFacts.publicNullifierCountBound,
      certificate.txLeafArtifactByteShapeFacts.publicCommitmentCountBound,
      certificate.txLeafArtifactByteShapeFacts.publicCiphertextHashCountBound,
      certificate.txLeafArtifactByteShapeFacts.starkProofLenBound,
      certificate.txLeafArtifactByteShapeFacts.commitmentRowCountBound⟩
  · exact ⟨
      certificate.receiptRootScheduleFacts.parsed,
      certificate.receiptRootResourceFacts.boundedFacts.accepted,
      certificate.receiptRootResourceFacts.artifactRawBytesWithinCap,
      certificate.receiptRootResourceFacts.artifactDecodedBytesWithinCap,
      certificate.receiptRootResourceFacts.dynamicItemCountWithinCap,
      certificate.receiptRootResourceFacts.maxItemBytesWithinCap,
      certificate.receiptRootResourceFacts.aggregateBytesWithinCap,
      certificate.receiptRootResourceFacts.workUnitsWithinCap,
      certificate.receiptRootScheduleFacts.scheduleAccepted,
      certificate.receiptRootScheduleFacts.expectedLeafCountPositive,
      certificate.receiptRootScheduleFacts.leafCountMatches,
      certificate.receiptRootScheduleFacts.foldCountMatches,
      certificate.receiptRootScheduleFacts.foldShapesExact⟩

structure PublicInputCostClassCoverageCertificate
    (surface : PreHeavyWorkVerificationPathSurface)
    (parserCorrectness benchmarkCaps : Prop) : Prop where
  preHeavyDoSBoundCertificate :
    AcceptedPreHeavyWorkDoSBoundCertificate
      surface
      parserCorrectness
      benchmarkCaps
  coveredFamilies :
    ∀ family,
      family ∈ productionPublicInputCostFamilies ->
        publicInputCostFamilyCovered
          surface
          family
  familyCount :
    productionPublicInputCostFamilies.length = 22

theorem accepted_preheavy_dos_certificate_covers_all_public_input_cost_classes
    {surface : PreHeavyWorkVerificationPathSurface}
    {parserCorrectness benchmarkCaps : Prop}
    (certificate :
      AcceptedPreHeavyWorkDoSBoundCertificate
        surface
        parserCorrectness
        benchmarkCaps) :
    PublicInputCostClassCoverageCertificate
      surface
      parserCorrectness
      benchmarkCaps := by
  exact {
    preHeavyDoSBoundCertificate := certificate,
    coveredFamilies := by
      intro family _membership
      exact preheavy_certificate_covers_public_input_cost_family
        certificate
        family,
    familyCount := by
      rfl
  }

end PreHeavyWorkResourceBoundSurface
end Native
end Hegemon
