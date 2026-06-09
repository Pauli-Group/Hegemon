namespace Hegemon
namespace Native
namespace MineableActionAdmission

inductive MineableActionReject where
  | unselectedCandidateArtifact
  | sidecarCiphertextMissing
  | sidecarCiphertextSizeMissing
  | sidecarCiphertextSizeMismatch
deriving DecidableEq, Repr

structure MineableActionInput where
  candidateArtifactRoute : Bool
  candidateArtifactSelected : Bool
  sidecarTransferRoute : Bool
  sidecarCiphertextsAvailable : Bool
  sidecarCiphertextSizesPresent : Bool
  sidecarCiphertextSizesMatch : Bool
deriving DecidableEq, Repr

def evaluateMineableAction
    (input : MineableActionInput) : Except MineableActionReject Unit :=
  if input.candidateArtifactRoute then
    if input.candidateArtifactSelected then
      Except.ok ()
    else
      Except.error MineableActionReject.unselectedCandidateArtifact
  else if input.sidecarTransferRoute then
    if input.sidecarCiphertextsAvailable = false then
      Except.error MineableActionReject.sidecarCiphertextMissing
    else if input.sidecarCiphertextSizesPresent = false then
      Except.error MineableActionReject.sidecarCiphertextSizeMissing
    else if input.sidecarCiphertextSizesMatch = false then
      Except.error MineableActionReject.sidecarCiphertextSizeMismatch
    else
      Except.ok ()
  else
    Except.ok ()

def mineableActionAccepts (input : MineableActionInput) : Bool :=
  match evaluateMineableAction input with
  | Except.ok _ => true
  | Except.error _ => false

def mineableActionRejection
    (input : MineableActionInput) : Option MineableActionReject :=
  match evaluateMineableAction input with
  | Except.ok _ => none
  | Except.error rejection => some rejection

def mineableActionPreconditions (input : MineableActionInput) : Bool :=
  if input.candidateArtifactRoute then
    input.candidateArtifactSelected
  else if input.sidecarTransferRoute then
    input.sidecarCiphertextsAvailable
      && input.sidecarCiphertextSizesPresent
      && input.sidecarCiphertextSizesMatch
  else
    true

theorem accepts_iff_mineable_preconditions (input : MineableActionInput) :
    mineableActionAccepts input = mineableActionPreconditions input := by
  cases input with
  | mk candidateArtifactRoute candidateArtifactSelected sidecarTransferRoute
      sidecarCiphertextsAvailable sidecarCiphertextSizesPresent
      sidecarCiphertextSizesMatch =>
      unfold mineableActionAccepts mineableActionPreconditions evaluateMineableAction
      cases candidateArtifactRoute <;> cases candidateArtifactSelected <;>
        cases sidecarTransferRoute <;> cases sidecarCiphertextsAvailable <;>
        cases sidecarCiphertextSizesPresent <;> cases sidecarCiphertextSizesMatch <;> rfl

def selectedCandidate : MineableActionInput :=
  {
    candidateArtifactRoute := true,
    candidateArtifactSelected := true,
    sidecarTransferRoute := false,
    sidecarCiphertextsAvailable := true,
    sidecarCiphertextSizesPresent := true,
    sidecarCiphertextSizesMatch := true
  }

def validSidecarTransfer : MineableActionInput :=
  {
    candidateArtifactRoute := false,
    candidateArtifactSelected := false,
    sidecarTransferRoute := true,
    sidecarCiphertextsAvailable := true,
    sidecarCiphertextSizesPresent := true,
    sidecarCiphertextSizesMatch := true
  }

def plainAction : MineableActionInput :=
  {
    candidateArtifactRoute := false,
    candidateArtifactSelected := false,
    sidecarTransferRoute := false,
    sidecarCiphertextsAvailable := false,
    sidecarCiphertextSizesPresent := false,
    sidecarCiphertextSizesMatch := false
  }

theorem selected_candidate_accepts :
    evaluateMineableAction selectedCandidate = Except.ok () := by
  rfl

theorem valid_sidecar_transfer_accepts :
    evaluateMineableAction validSidecarTransfer = Except.ok () := by
  rfl

theorem plain_action_accepts :
    evaluateMineableAction plainAction = Except.ok () := by
  rfl

theorem unselected_candidate_rejects
    {input : MineableActionInput}
    (candidate : input.candidateArtifactRoute = true)
    (unselected : input.candidateArtifactSelected = false) :
    evaluateMineableAction input =
      Except.error MineableActionReject.unselectedCandidateArtifact := by
  unfold evaluateMineableAction
  simp [candidate, unselected]

theorem sidecar_ciphertext_missing_rejects
    {input : MineableActionInput}
    (notCandidate : input.candidateArtifactRoute = false)
    (sidecar : input.sidecarTransferRoute = true)
    (missing : input.sidecarCiphertextsAvailable = false) :
    evaluateMineableAction input =
      Except.error MineableActionReject.sidecarCiphertextMissing := by
  unfold evaluateMineableAction
  simp [notCandidate, sidecar, missing]

theorem sidecar_ciphertext_size_missing_rejects
    {input : MineableActionInput}
    (notCandidate : input.candidateArtifactRoute = false)
    (sidecar : input.sidecarTransferRoute = true)
    (available : input.sidecarCiphertextsAvailable = true)
    (missing : input.sidecarCiphertextSizesPresent = false) :
    evaluateMineableAction input =
      Except.error MineableActionReject.sidecarCiphertextSizeMissing := by
  unfold evaluateMineableAction
  simp [notCandidate, sidecar, available, missing]

theorem sidecar_ciphertext_size_mismatch_rejects
    {input : MineableActionInput}
    (notCandidate : input.candidateArtifactRoute = false)
    (sidecar : input.sidecarTransferRoute = true)
    (available : input.sidecarCiphertextsAvailable = true)
    (present : input.sidecarCiphertextSizesPresent = true)
    (mismatch : input.sidecarCiphertextSizesMatch = false) :
    evaluateMineableAction input =
      Except.error MineableActionReject.sidecarCiphertextSizeMismatch := by
  unfold evaluateMineableAction
  simp [notCandidate, sidecar, available, present, mismatch]

theorem candidate_precedes_sidecar_ciphertext_missing :
    evaluateMineableAction
      { selectedCandidate with
        candidateArtifactSelected := false,
        sidecarTransferRoute := true,
        sidecarCiphertextsAvailable := false } =
      Except.error MineableActionReject.unselectedCandidateArtifact := by
  rfl

theorem plain_action_ignores_sidecar_metadata :
    evaluateMineableAction plainAction = Except.ok () := by
  rfl

end MineableActionAdmission
end Native
end Hegemon
