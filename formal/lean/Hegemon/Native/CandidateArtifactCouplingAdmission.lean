namespace Hegemon
namespace Native
namespace CandidateArtifactCouplingAdmission

inductive CandidateArtifactCouplingReject where
  | candidateWithoutTransfers
  | missingOrMultipleCandidateArtifact
  | candidateTxCountMismatch
deriving DecidableEq, Repr

structure CandidateArtifactCouplingInput where
  transferCount : Nat
  candidateArtifactCount : Nat
  candidateTxCountMatches : Bool
deriving DecidableEq, Repr

def evaluateCandidateArtifactCoupling
    (input : CandidateArtifactCouplingInput) :
    Except CandidateArtifactCouplingReject Unit :=
  if input.transferCount = 0 then
    if input.candidateArtifactCount = 0 then
      Except.ok ()
    else
      Except.error CandidateArtifactCouplingReject.candidateWithoutTransfers
  else if input.candidateArtifactCount = 1 then
    if input.candidateTxCountMatches then
      Except.ok ()
    else
      Except.error CandidateArtifactCouplingReject.candidateTxCountMismatch
  else
    Except.error CandidateArtifactCouplingReject.missingOrMultipleCandidateArtifact

def candidateArtifactCouplingAccepts
    (input : CandidateArtifactCouplingInput) : Bool :=
  match evaluateCandidateArtifactCoupling input with
  | Except.ok _ => true
  | Except.error _ => false

def candidateArtifactCouplingRejection
    (input : CandidateArtifactCouplingInput) :
    Option CandidateArtifactCouplingReject :=
  match evaluateCandidateArtifactCoupling input with
  | Except.ok _ => none
  | Except.error rejection => some rejection

def candidateArtifactCouplingPreconditions
    (input : CandidateArtifactCouplingInput) : Bool :=
  if input.transferCount = 0 then
    input.candidateArtifactCount = 0
  else
    input.candidateArtifactCount = 1 && input.candidateTxCountMatches

theorem accepts_iff_coupling_preconditions
    {input : CandidateArtifactCouplingInput} :
    candidateArtifactCouplingAccepts input = true ↔
      candidateArtifactCouplingPreconditions input = true := by
  cases input with
  | mk transferCount candidateArtifactCount candidateTxCountMatches =>
      by_cases noTransfers : transferCount = 0
      · by_cases noCandidates : candidateArtifactCount = 0
        · simp [
            candidateArtifactCouplingAccepts,
            candidateArtifactCouplingPreconditions,
            evaluateCandidateArtifactCoupling,
            noTransfers,
            noCandidates
          ]
        · simp [
            candidateArtifactCouplingAccepts,
            candidateArtifactCouplingPreconditions,
            evaluateCandidateArtifactCoupling,
            noTransfers,
            noCandidates
          ]
      · by_cases oneCandidate : candidateArtifactCount = 1
        · cases candidateTxCountMatches <;>
            simp [
              candidateArtifactCouplingAccepts,
              candidateArtifactCouplingPreconditions,
              evaluateCandidateArtifactCoupling,
              noTransfers,
              oneCandidate
            ]
        · simp [
            candidateArtifactCouplingAccepts,
            candidateArtifactCouplingPreconditions,
            evaluateCandidateArtifactCoupling,
            noTransfers,
            oneCandidate
          ]

def emptyBlock : CandidateArtifactCouplingInput :=
  {
    transferCount := 0,
    candidateArtifactCount := 0,
    candidateTxCountMatches := false
  }

def matchedCandidate : CandidateArtifactCouplingInput :=
  {
    transferCount := 1,
    candidateArtifactCount := 1,
    candidateTxCountMatches := true
  }

theorem empty_block_accepts :
    evaluateCandidateArtifactCoupling emptyBlock = Except.ok () := by
  rfl

theorem matched_candidate_accepts :
    evaluateCandidateArtifactCoupling matchedCandidate = Except.ok () := by
  rfl

theorem candidate_without_transfers_rejects
    {input : CandidateArtifactCouplingInput}
    (noTransfers : input.transferCount = 0)
    (candidatePresent : input.candidateArtifactCount ≠ 0) :
    evaluateCandidateArtifactCoupling input =
      Except.error CandidateArtifactCouplingReject.candidateWithoutTransfers := by
  unfold evaluateCandidateArtifactCoupling
  simp [noTransfers, candidatePresent]

theorem missing_candidate_rejects
    {input : CandidateArtifactCouplingInput}
    (hasTransfers : input.transferCount ≠ 0)
    (missing : input.candidateArtifactCount = 0) :
    evaluateCandidateArtifactCoupling input =
      Except.error CandidateArtifactCouplingReject.missingOrMultipleCandidateArtifact := by
  unfold evaluateCandidateArtifactCoupling
  simp [hasTransfers, missing]

theorem multiple_candidates_rejects
    {input : CandidateArtifactCouplingInput}
    (hasTransfers : input.transferCount ≠ 0)
    (multiple : input.candidateArtifactCount ≠ 1) :
    evaluateCandidateArtifactCoupling input =
      Except.error CandidateArtifactCouplingReject.missingOrMultipleCandidateArtifact := by
  unfold evaluateCandidateArtifactCoupling
  simp [hasTransfers, multiple]

theorem candidate_tx_count_mismatch_rejects
    {input : CandidateArtifactCouplingInput}
    (hasTransfers : input.transferCount ≠ 0)
    (oneCandidate : input.candidateArtifactCount = 1)
    (mismatch : input.candidateTxCountMatches = false) :
    evaluateCandidateArtifactCoupling input =
      Except.error CandidateArtifactCouplingReject.candidateTxCountMismatch := by
  unfold evaluateCandidateArtifactCoupling
  simp [hasTransfers, oneCandidate, mismatch]

theorem no_transfers_precedes_tx_count_mismatch
    {input : CandidateArtifactCouplingInput}
    (noTransfers : input.transferCount = 0)
    (candidatePresent : input.candidateArtifactCount ≠ 0) :
    evaluateCandidateArtifactCoupling input =
      Except.error CandidateArtifactCouplingReject.candidateWithoutTransfers := by
  exact candidate_without_transfers_rejects noTransfers candidatePresent

theorem candidate_count_precedes_tx_count_mismatch
    {input : CandidateArtifactCouplingInput}
    (hasTransfers : input.transferCount ≠ 0)
    (notOneCandidate : input.candidateArtifactCount ≠ 1) :
    evaluateCandidateArtifactCoupling input =
      Except.error CandidateArtifactCouplingReject.missingOrMultipleCandidateArtifact := by
  exact multiple_candidates_rejects hasTransfers notOneCandidate

end CandidateArtifactCouplingAdmission
end Native
end Hegemon
