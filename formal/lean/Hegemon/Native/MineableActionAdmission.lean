namespace Hegemon
namespace Native
namespace MineableActionAdmission

inductive MineableActionReject where
  | retiredCandidateArtifact
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
    Except.error MineableActionReject.retiredCandidateArtifact
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
    false
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

theorem candidate_artifact_is_retired_even_if_marked_selected :
    evaluateMineableAction selectedCandidate =
      Except.error MineableActionReject.retiredCandidateArtifact := by
  rfl

theorem valid_sidecar_transfer_accepts :
    evaluateMineableAction validSidecarTransfer = Except.ok () := by
  rfl

theorem plain_action_accepts :
    evaluateMineableAction plainAction = Except.ok () := by
  rfl

theorem candidate_artifact_rejects
    {input : MineableActionInput}
    (candidate : input.candidateArtifactRoute = true) :
    evaluateMineableAction input =
      Except.error MineableActionReject.retiredCandidateArtifact := by
  unfold evaluateMineableAction
  simp [candidate]

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
      Except.error MineableActionReject.retiredCandidateArtifact := by
  rfl

theorem plain_action_ignores_sidecar_metadata :
    evaluateMineableAction plainAction = Except.ok () := by
  rfl

structure MineableSelectionAction where
  actionId : Nat
  transferRoute : Bool
  transferMineable : Bool
  candidateArtifactRoute : Bool
  candidateTxCount : Nat
deriving DecidableEq, Repr

def mineableTransferCount : List MineableSelectionAction -> Nat
  | [] => 0
  | action :: rest =>
      (if action.transferRoute && action.transferMineable then 1 else 0)
        + mineableTransferCount rest

def selectedCandidateForOrderedActions
    (_actions : List MineableSelectionAction) : Option Nat :=
  none

def selectionActionAccepts
    (_actions : List MineableSelectionAction)
    (action : MineableSelectionAction) : Bool :=
  if action.candidateArtifactRoute then
    false
  else if action.transferRoute then
    action.transferMineable
  else
    true

def pendingTransferPresent : List MineableSelectionAction -> Bool
  | [] => false
  | action :: rest =>
      action.transferRoute || pendingTransferPresent rest

def survivesCandidatePruneWhenTransfersPending
    (actions : List MineableSelectionAction)
    (action : MineableSelectionAction) : Bool :=
  if pendingTransferPresent actions && action.candidateArtifactRoute then
    false
  else
    true

structure MineableSelectionFacts
    (actions : List MineableSelectionAction) where
  transferCount : Nat
  selectedCandidate : Option Nat
  transferCountMatches :
    transferCount = mineableTransferCount actions
  selectedCandidateMatches :
    selectedCandidate = selectedCandidateForOrderedActions actions
  candidateArtifactsRejected :
    ∀ action,
      action.candidateArtifactRoute = true ->
      selectionActionAccepts actions action = false
  transferAcceptanceMatchesMineability :
    ∀ action,
      action.candidateArtifactRoute = false ->
      action.transferRoute = true ->
      selectionActionAccepts actions action = action.transferMineable
  plainActionAccepted :
    ∀ action,
      action.candidateArtifactRoute = false ->
      action.transferRoute = false ->
      selectionActionAccepts actions action = true

theorem selected_candidate_always_none
    (actions : List MineableSelectionAction) :
    selectedCandidateForOrderedActions actions = none := by
  rfl

theorem selection_rejects_candidate
    (actions : List MineableSelectionAction)
    (action : MineableSelectionAction)
    (candidate : action.candidateArtifactRoute = true) :
    selectionActionAccepts actions action = false := by
  unfold selectionActionAccepts
  simp [candidate]

theorem selection_accepts_transfer_iff_mineable
    (actions : List MineableSelectionAction)
    (action : MineableSelectionAction)
    (notCandidate : action.candidateArtifactRoute = false)
    (transfer : action.transferRoute = true) :
    selectionActionAccepts actions action = action.transferMineable := by
  unfold selectionActionAccepts
  simp [notCandidate, transfer]

theorem selection_accepts_plain_action
    (actions : List MineableSelectionAction)
    (action : MineableSelectionAction)
    (notCandidate : action.candidateArtifactRoute = false)
    (notTransfer : action.transferRoute = false) :
    selectionActionAccepts actions action = true := by
  unfold selectionActionAccepts
  simp [notCandidate, notTransfer]

theorem candidate_prune_drops_candidates_when_transfer_pending
    (actions : List MineableSelectionAction)
    (action : MineableSelectionAction)
    (pendingTransfer : pendingTransferPresent actions = true)
    (candidate : action.candidateArtifactRoute = true) :
    survivesCandidatePruneWhenTransfersPending actions action = false := by
  unfold survivesCandidatePruneWhenTransfersPending
  simp [pendingTransfer, candidate]

theorem candidate_prune_keeps_non_candidates
    (actions : List MineableSelectionAction)
    (action : MineableSelectionAction)
    (notCandidate : action.candidateArtifactRoute = false) :
    survivesCandidatePruneWhenTransfersPending actions action = true := by
  unfold survivesCandidatePruneWhenTransfersPending
  simp [notCandidate]

theorem candidate_prune_keeps_candidates_without_transfer
    (actions : List MineableSelectionAction)
    (action : MineableSelectionAction)
    (noPendingTransfer : pendingTransferPresent actions = false) :
    survivesCandidatePruneWhenTransfersPending actions action = true := by
  unfold survivesCandidatePruneWhenTransfersPending
  simp [noPendingTransfer]

def ordered_mineable_selection_facts
    (actions : List MineableSelectionAction) :
    MineableSelectionFacts actions := by
  refine
    {
      transferCount := mineableTransferCount actions,
      selectedCandidate := selectedCandidateForOrderedActions actions,
      transferCountMatches := rfl,
      selectedCandidateMatches := rfl,
      candidateArtifactsRejected := ?_,
      transferAcceptanceMatchesMineability := ?_,
      plainActionAccepted := ?_
    }
  · intro action candidate
    exact selection_rejects_candidate actions action candidate
  · intro action notCandidate transfer
    exact selection_accepts_transfer_iff_mineable actions action notCandidate transfer
  · intro action notCandidate notTransfer
    exact selection_accepts_plain_action actions action notCandidate notTransfer

end MineableActionAdmission
end Native
end Hegemon
