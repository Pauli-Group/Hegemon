import Hegemon.Native.CandidateArtifactAdmission
import Hegemon.Resource.BoundedRequestAdmission

namespace Hegemon
namespace Native
namespace CandidateArtifactResourceAdmission

open Hegemon.Native.CandidateArtifactAdmission
open Hegemon.Resource.BoundedRequestAdmission

structure CandidateArtifactResourceInput where
  declaredBytes : Nat
  proofBytes : Nat
  receiptBytes : Nat
  recursiveBytes : Nat
  txCount : Nat
  daChunkCount : Nat
deriving DecidableEq, Repr

def candidateArtifactVariableBytes
    (input : CandidateArtifactResourceInput) : Nat :=
  input.proofBytes + input.receiptBytes + input.recursiveBytes

def candidateArtifactTotalBytes
    (input : CandidateArtifactResourceInput) : Nat :=
  input.declaredBytes + candidateArtifactVariableBytes input

def candidateArtifactMaxPayloadBytes
    (input : CandidateArtifactResourceInput) : Nat :=
  max input.proofBytes (max input.receiptBytes input.recursiveBytes)

def candidateArtifactResourceRequest
    (input : CandidateArtifactResourceInput) : ResourceRequest :=
  {
    rawBytes := input.declaredBytes,
    decodedBytes := candidateArtifactTotalBytes input,
    itemCount := input.txCount,
    maxItemBytes := candidateArtifactMaxPayloadBytes input,
    aggregateBytes := candidateArtifactVariableBytes input,
    workUnits := input.daChunkCount
  }

inductive CandidateArtifactResourceFirstReject where
  | resource : ResourceReject -> CandidateArtifactResourceFirstReject
  | candidate : CandidateArtifactReject -> CandidateArtifactResourceFirstReject
deriving DecidableEq, Repr

def evaluateCandidateArtifactAfterResource
    (policy : ResourcePolicy)
    (resourceInput : CandidateArtifactResourceInput)
    (candidateInput : CandidateArtifactInput) :
    Except CandidateArtifactResourceFirstReject Unit :=
  match evaluateBoundedRequest policy
      (candidateArtifactResourceRequest resourceInput) with
  | some reject =>
      Except.error (CandidateArtifactResourceFirstReject.resource reject)
  | none =>
      match evaluateCandidateArtifact candidateInput with
      | Except.ok _ => Except.ok ()
      | Except.error reject =>
          Except.error (CandidateArtifactResourceFirstReject.candidate reject)

structure AcceptedCandidateArtifactResourceFacts
    (policy : ResourcePolicy)
    (input : CandidateArtifactResourceInput) : Prop where
  boundedFacts :
    AcceptedBoundedRequestFacts policy
      (candidateArtifactResourceRequest input)
  declaredBytesWithinRawCap :
    ¬ policy.rawByteCap < input.declaredBytes
  totalBytesWithinDecodedCap :
    ¬ policy.decodedByteCap < candidateArtifactTotalBytes input
  txCountWithinItemCap :
    ¬ policy.itemCountCap < input.txCount
  proofBytesWithinItemByteCap :
    ¬ policy.itemByteCap < input.proofBytes
  receiptBytesWithinItemByteCap :
    ¬ policy.itemByteCap < input.receiptBytes
  recursiveBytesWithinItemByteCap :
    ¬ policy.itemByteCap < input.recursiveBytes
  proofLikeAggregateWithinCap :
    ¬ policy.aggregateByteCap < candidateArtifactVariableBytes input
  daChunkCountWithinWorkCap :
    ¬ policy.workUnitCap < input.daChunkCount

theorem accepted_candidate_artifact_resource_exposes_byte_caps
    {policy : ResourcePolicy}
    {input : CandidateArtifactResourceInput}
    (accepted :
      evaluateBoundedRequest policy
        (candidateArtifactResourceRequest input) = none) :
    AcceptedCandidateArtifactResourceFacts policy input := by
  let facts :=
    accepted_bounded_request_exposes_all_caps
      (policy := policy)
      (request := candidateArtifactResourceRequest input)
      accepted
  have maxWithin :
      ¬ policy.itemByteCap < candidateArtifactMaxPayloadBytes input := by
    simpa [candidateArtifactResourceRequest] using facts.itemBytesWithinCap
  have proofWithin :
      ¬ policy.itemByteCap < input.proofBytes := by
    intro proofOver
    exact maxWithin
      (Nat.lt_of_lt_of_le proofOver
        (Nat.le_max_left input.proofBytes
          (max input.receiptBytes input.recursiveBytes)))
  have receiptWithin :
      ¬ policy.itemByteCap < input.receiptBytes := by
    intro receiptOver
    exact maxWithin
      (Nat.lt_of_lt_of_le receiptOver
        (Nat.le_trans
          (Nat.le_max_left input.receiptBytes input.recursiveBytes)
          (Nat.le_max_right input.proofBytes
            (max input.receiptBytes input.recursiveBytes))))
  have recursiveWithin :
      ¬ policy.itemByteCap < input.recursiveBytes := by
    intro recursiveOver
    exact maxWithin
      (Nat.lt_of_lt_of_le recursiveOver
        (Nat.le_trans
          (Nat.le_max_right input.receiptBytes input.recursiveBytes)
          (Nat.le_max_right input.proofBytes
            (max input.receiptBytes input.recursiveBytes))))
  exact {
    boundedFacts := facts,
    declaredBytesWithinRawCap := by
      simpa [candidateArtifactResourceRequest] using facts.rawBytesWithinCap,
    totalBytesWithinDecodedCap := by
      simpa [candidateArtifactResourceRequest] using
        facts.decodedBytesWithinCap,
    txCountWithinItemCap := by
      simpa [candidateArtifactResourceRequest] using facts.itemCountWithinCap,
    proofBytesWithinItemByteCap := proofWithin,
    receiptBytesWithinItemByteCap := receiptWithin,
    recursiveBytesWithinItemByteCap := recursiveWithin,
    proofLikeAggregateWithinCap := by
      simpa [candidateArtifactResourceRequest] using
        facts.aggregateBytesWithinCap,
    daChunkCountWithinWorkCap := by
      simpa [candidateArtifactResourceRequest] using facts.workUnitsWithinCap
  }

theorem accepted_candidate_artifact_after_resource_exposes_byte_caps
    {policy : ResourcePolicy}
    {resourceInput : CandidateArtifactResourceInput}
    {candidateInput : CandidateArtifactInput}
    (accepted :
      evaluateCandidateArtifactAfterResource policy resourceInput candidateInput =
        Except.ok ()) :
    AcceptedCandidateArtifactResourceFacts policy resourceInput := by
  unfold evaluateCandidateArtifactAfterResource at accepted
  cases h :
      evaluateBoundedRequest policy
        (candidateArtifactResourceRequest resourceInput) with
  | none =>
      exact accepted_candidate_artifact_resource_exposes_byte_caps h
  | some reject =>
      simp [h] at accepted

theorem accepted_candidate_artifact_after_resource_exposes_candidate_acceptance
    {policy : ResourcePolicy}
    {resourceInput : CandidateArtifactResourceInput}
    {candidateInput : CandidateArtifactInput}
    (accepted :
      evaluateCandidateArtifactAfterResource policy resourceInput candidateInput =
        Except.ok ()) :
    evaluateCandidateArtifact candidateInput = Except.ok () := by
  unfold evaluateCandidateArtifactAfterResource at accepted
  cases h :
      evaluateBoundedRequest policy
        (candidateArtifactResourceRequest resourceInput) with
  | none =>
      cases hc : evaluateCandidateArtifact candidateInput with
      | ok value =>
          cases value
          rfl
      | error reject =>
          simp [h, hc] at accepted
  | some reject =>
      simp [h] at accepted

def exampleCandidateArtifactResourcePolicy : ResourcePolicy :=
  {
    rawByteCap := 200,
    decodedByteCap := 600000,
    itemCountCap := 32,
    itemByteCap := 523736,
    aggregateByteCap := 523736,
    workUnitCap := 1000
  }

def exampleCandidateArtifactResourceInput : CandidateArtifactResourceInput :=
  {
    declaredBytes := 158,
    proofBytes := 0,
    receiptBytes := 0,
    recursiveBytes := 32,
    txCount := 1,
    daChunkCount := 1
  }

theorem example_candidate_artifact_resource_accepts :
    evaluateBoundedRequest exampleCandidateArtifactResourcePolicy
      (candidateArtifactResourceRequest exampleCandidateArtifactResourceInput) =
        none := by
  decide

theorem example_candidate_artifact_after_resource_accepts :
    evaluateCandidateArtifactAfterResource
      exampleCandidateArtifactResourcePolicy
      exampleCandidateArtifactResourceInput
      validCandidateArtifact = Except.ok () := by
  rfl

end CandidateArtifactResourceAdmission
end Native
end Hegemon
