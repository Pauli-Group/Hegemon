import Hegemon.Native.MineableActionAdmission
import Hegemon.Native.ResourceBudgetAdmission
import Hegemon.Native.RpcAdmission
import Hegemon.Native.SidecarUploadAdmission

namespace Hegemon
namespace Native
namespace PreHeavyWorkResourceBoundSurface

open Hegemon.Native.MineableActionAdmission
open Hegemon.Native.ResourceBudgetAdmission
open Hegemon.Native.RpcAdmission
open Hegemon.Native.SidecarUploadAdmission

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

end PreHeavyWorkResourceBoundSurface
end Native
end Hegemon
