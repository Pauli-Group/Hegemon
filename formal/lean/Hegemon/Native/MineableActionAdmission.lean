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

def firstMatchingCandidate
    (transferCount : Nat) : List MineableSelectionAction -> Option Nat
  | [] => none
  | action :: rest =>
      if action.candidateArtifactRoute && decide (action.candidateTxCount = transferCount) then
        some action.actionId
      else
        firstMatchingCandidate transferCount rest

def selectedCandidateForOrderedActions
    (actions : List MineableSelectionAction) : Option Nat :=
  let transferCount := mineableTransferCount actions
  if transferCount = 0 then
    none
  else
    firstMatchingCandidate transferCount actions

def selectionActionAccepts
    (actions : List MineableSelectionAction)
    (action : MineableSelectionAction) : Bool :=
  if action.candidateArtifactRoute then
    selectedCandidateForOrderedActions actions = some action.actionId
  else if action.transferRoute then
    action.transferMineable
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
  acceptedCandidateRequiresSelected :
    ∀ action,
      action.candidateArtifactRoute = true ->
      selectionActionAccepts actions action = true ->
      selectedCandidate = some action.actionId
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

theorem selected_candidate_none_when_no_mineable_transfers
    {actions : List MineableSelectionAction}
    (noTransfers : mineableTransferCount actions = 0) :
    selectedCandidateForOrderedActions actions = none := by
  unfold selectedCandidateForOrderedActions
  simp [noTransfers]

theorem first_matching_candidate_head_matches
    {transferCount : Nat}
    {action : MineableSelectionAction}
    {rest : List MineableSelectionAction}
    (candidate : action.candidateArtifactRoute = true)
    (countMatches : action.candidateTxCount = transferCount) :
    firstMatchingCandidate transferCount (action :: rest) =
      some action.actionId := by
  unfold firstMatchingCandidate
  simp [candidate, countMatches]

theorem first_matching_candidate_skips_nonmatching_head
    {transferCount : Nat}
    {action : MineableSelectionAction}
    {rest : List MineableSelectionAction}
    (notMatch :
      (action.candidateArtifactRoute && decide (action.candidateTxCount = transferCount)) =
        false) :
    firstMatchingCandidate transferCount (action :: rest) =
      firstMatchingCandidate transferCount rest := by
  change
    (if action.candidateArtifactRoute && decide (action.candidateTxCount = transferCount) then
      some action.actionId
    else
      firstMatchingCandidate transferCount rest) =
      firstMatchingCandidate transferCount rest
  simp [notMatch]

theorem selection_accepts_candidate_iff_selected
    (actions : List MineableSelectionAction)
    (action : MineableSelectionAction)
    (candidate : action.candidateArtifactRoute = true) :
    selectionActionAccepts actions action =
      (selectedCandidateForOrderedActions actions = some action.actionId) := by
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

def ordered_mineable_selection_facts
    (actions : List MineableSelectionAction) :
    MineableSelectionFacts actions := by
  refine
    {
      transferCount := mineableTransferCount actions,
      selectedCandidate := selectedCandidateForOrderedActions actions,
      transferCountMatches := rfl,
      selectedCandidateMatches := rfl,
      acceptedCandidateRequiresSelected := ?_,
      transferAcceptanceMatchesMineability := ?_,
      plainActionAccepted := ?_
    }
  · intro action candidate accepted
    rw [selection_accepts_candidate_iff_selected actions action candidate] at accepted
    exact accepted
  · intro action notCandidate transfer
    exact selection_accepts_transfer_iff_mineable actions action notCandidate transfer
  · intro action notCandidate notTransfer
    exact selection_accepts_plain_action actions action notCandidate notTransfer

end MineableActionAdmission
end Native
end Hegemon
