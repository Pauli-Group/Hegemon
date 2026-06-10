namespace Hegemon
namespace Native
namespace NativeBackendReleasePosture

inductive ReleasePostureReject where
  | candidateReviewStateMismatch
  | candidateMaturityMismatch
  | candidateExternalReviewComplete
  | acceptedReviewStateMismatch
  | acceptedExternalReviewIncomplete
  | acceptedMissingArtifact
  | acceptedMalformedArtifact
deriving DecidableEq, Repr

structure ReleasePostureInput where
  requireAccepted : Bool
  reviewStateCandidateUnderReview : Bool
  reviewStateAccepted : Bool
  maturityStructuralCandidate : Bool
  externalReviewKnown : Bool
  externalReviewCompleted : Bool
  acceptanceArtifactPresent : Bool
  acceptanceArtifactMentionsAccepted : Bool
  acceptanceArtifactMentionsExternal : Bool
deriving DecidableEq, Repr

def candidateExternalReviewAllowed (input : ReleasePostureInput) : Bool :=
  input.externalReviewKnown = false || input.externalReviewCompleted = false

def acceptedExternalReviewAllowed (input : ReleasePostureInput) : Bool :=
  input.externalReviewKnown = false || input.externalReviewCompleted = true

def acceptedArtifactValid (input : ReleasePostureInput) : Bool :=
  input.acceptanceArtifactPresent
    && input.acceptanceArtifactMentionsAccepted
    && input.acceptanceArtifactMentionsExternal

def candidatePreconditions (input : ReleasePostureInput) : Bool :=
  input.reviewStateCandidateUnderReview
    && input.maturityStructuralCandidate
    && candidateExternalReviewAllowed input

def acceptedPreconditions (input : ReleasePostureInput) : Bool :=
  input.reviewStateAccepted
    && acceptedExternalReviewAllowed input
    && acceptedArtifactValid input

def releasePosturePreconditions (input : ReleasePostureInput) : Bool :=
  if input.requireAccepted then
    acceptedPreconditions input
  else
    candidatePreconditions input

def evaluateReleasePosture
    (input : ReleasePostureInput) : Except ReleasePostureReject Unit :=
  if input.requireAccepted then
    if input.reviewStateAccepted = false then
      Except.error ReleasePostureReject.acceptedReviewStateMismatch
    else if acceptedExternalReviewAllowed input = false then
      Except.error ReleasePostureReject.acceptedExternalReviewIncomplete
    else if input.acceptanceArtifactPresent = false then
      Except.error ReleasePostureReject.acceptedMissingArtifact
    else if (input.acceptanceArtifactMentionsAccepted
        && input.acceptanceArtifactMentionsExternal) = false then
      Except.error ReleasePostureReject.acceptedMalformedArtifact
    else
      Except.ok ()
  else
    if input.reviewStateCandidateUnderReview = false then
      Except.error ReleasePostureReject.candidateReviewStateMismatch
    else if input.maturityStructuralCandidate = false then
      Except.error ReleasePostureReject.candidateMaturityMismatch
    else if candidateExternalReviewAllowed input = false then
      Except.error ReleasePostureReject.candidateExternalReviewComplete
    else
      Except.ok ()

def releasePostureAccepts (input : ReleasePostureInput) : Bool :=
  match evaluateReleasePosture input with
  | Except.ok _ => true
  | Except.error _ => false

def releasePostureRejection
    (input : ReleasePostureInput) : Option ReleasePostureReject :=
  match evaluateReleasePosture input with
  | Except.ok _ => none
  | Except.error rejection => some rejection

theorem accepts_iff_release_posture_preconditions
    (input : ReleasePostureInput) :
    releasePostureAccepts input = releasePosturePreconditions input := by
  unfold releasePostureAccepts
    releasePosturePreconditions evaluateReleasePosture
    candidatePreconditions acceptedPreconditions
    acceptedArtifactValid
  cases hRequire : input.requireAccepted <;>
    cases hCandidate : input.reviewStateCandidateUnderReview <;>
    cases hAccepted : input.reviewStateAccepted <;>
    cases hMaturity : input.maturityStructuralCandidate <;>
    cases hCandidateExternal : candidateExternalReviewAllowed input <;>
    cases hAcceptedExternal : acceptedExternalReviewAllowed input <;>
    cases hArtifactPresent : input.acceptanceArtifactPresent <;>
    cases hArtifactAccepted : input.acceptanceArtifactMentionsAccepted <;>
    cases hArtifactExternal : input.acceptanceArtifactMentionsExternal <;>
    simp_all

def candidatePackageInput : ReleasePostureInput :=
  {
    requireAccepted := false,
    reviewStateCandidateUnderReview := true,
    reviewStateAccepted := false,
    maturityStructuralCandidate := true,
    externalReviewKnown := true,
    externalReviewCompleted := false,
    acceptanceArtifactPresent := false,
    acceptanceArtifactMentionsAccepted := false,
    acceptanceArtifactMentionsExternal := false
  }

def candidateWithoutManifestInput : ReleasePostureInput :=
  { candidatePackageInput with externalReviewKnown := false }

def candidateWrongReviewStateInput : ReleasePostureInput :=
  { candidatePackageInput with reviewStateCandidateUnderReview := false }

def candidateWrongMaturityInput : ReleasePostureInput :=
  { candidatePackageInput with maturityStructuralCandidate := false }

def candidateExternalCompleteInput : ReleasePostureInput :=
  { candidatePackageInput with externalReviewCompleted := true }

def acceptedPackageInput : ReleasePostureInput :=
  {
    requireAccepted := true,
    reviewStateCandidateUnderReview := false,
    reviewStateAccepted := true,
    maturityStructuralCandidate := false,
    externalReviewKnown := true,
    externalReviewCompleted := true,
    acceptanceArtifactPresent := true,
    acceptanceArtifactMentionsAccepted := true,
    acceptanceArtifactMentionsExternal := true
  }

def acceptedWrongReviewStateInput : ReleasePostureInput :=
  { acceptedPackageInput with reviewStateAccepted := false }

def acceptedExternalIncompleteInput : ReleasePostureInput :=
  { acceptedPackageInput with externalReviewCompleted := false }

def acceptedMissingArtifactInput : ReleasePostureInput :=
  { acceptedPackageInput with acceptanceArtifactPresent := false }

def acceptedMalformedArtifactInput : ReleasePostureInput :=
  { acceptedPackageInput with acceptanceArtifactMentionsExternal := false }

theorem candidate_package_accepts :
    evaluateReleasePosture candidatePackageInput = Except.ok () := by
  rfl

theorem candidate_without_manifest_accepts :
    evaluateReleasePosture candidateWithoutManifestInput = Except.ok () := by
  rfl

theorem candidate_wrong_review_state_rejects :
    evaluateReleasePosture candidateWrongReviewStateInput =
      Except.error ReleasePostureReject.candidateReviewStateMismatch := by
  rfl

theorem candidate_wrong_maturity_rejects :
    evaluateReleasePosture candidateWrongMaturityInput =
      Except.error ReleasePostureReject.candidateMaturityMismatch := by
  rfl

theorem candidate_external_complete_rejects :
    evaluateReleasePosture candidateExternalCompleteInput =
      Except.error ReleasePostureReject.candidateExternalReviewComplete := by
  rfl

theorem accepted_package_accepts :
    evaluateReleasePosture acceptedPackageInput = Except.ok () := by
  rfl

theorem accepted_wrong_review_state_rejects :
    evaluateReleasePosture acceptedWrongReviewStateInput =
      Except.error ReleasePostureReject.acceptedReviewStateMismatch := by
  rfl

theorem accepted_external_incomplete_rejects :
    evaluateReleasePosture acceptedExternalIncompleteInput =
      Except.error ReleasePostureReject.acceptedExternalReviewIncomplete := by
  rfl

theorem accepted_missing_artifact_rejects :
    evaluateReleasePosture acceptedMissingArtifactInput =
      Except.error ReleasePostureReject.acceptedMissingArtifact := by
  rfl

theorem accepted_malformed_artifact_rejects :
    evaluateReleasePosture acceptedMalformedArtifactInput =
      Except.error ReleasePostureReject.acceptedMalformedArtifact := by
  rfl

end NativeBackendReleasePosture
end Native
end Hegemon
