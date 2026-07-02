namespace Hegemon
namespace Consensus
namespace StatementAnchorAdmission

inductive StatementAnchorAdmissionReject where
  | bindingCountMismatch
  | unknownAnchor
deriving DecidableEq, Repr

structure StatementAnchorAdmissionInput where
  txCount : Nat
  bindingCount : Nat
  anchorKnownChecks : List Bool
deriving DecidableEq, Repr

def anchorsKnown (input : StatementAnchorAdmissionInput) : Bool :=
  input.anchorKnownChecks.all (fun known => known)

def evaluateStatementAnchorAdmission
    (input : StatementAnchorAdmissionInput) :
    Option StatementAnchorAdmissionReject :=
  if input.bindingCount = input.txCount then
    if anchorsKnown input then
      none
    else
      some StatementAnchorAdmissionReject.unknownAnchor
  else
    some StatementAnchorAdmissionReject.bindingCountMismatch

def statementAnchorAdmissionPreconditions
    (input : StatementAnchorAdmissionInput) : Bool :=
  decide (input.bindingCount = input.txCount) && anchorsKnown input

def statementAnchorAdmissionAccepts
    (input : StatementAnchorAdmissionInput) : Bool :=
  evaluateStatementAnchorAdmission input = none

theorem accepts_iff_statement_anchor_preconditions
    (input : StatementAnchorAdmissionInput) :
    statementAnchorAdmissionAccepts input =
      statementAnchorAdmissionPreconditions input := by
  unfold statementAnchorAdmissionAccepts
    statementAnchorAdmissionPreconditions
    evaluateStatementAnchorAdmission
  by_cases hCount : input.bindingCount = input.txCount
  · simp [hCount]
  · simp [hCount]

def validInput : StatementAnchorAdmissionInput :=
  {
    txCount := 2,
    bindingCount := 2,
    anchorKnownChecks := [true, true]
  }

theorem valid_accepts :
    evaluateStatementAnchorAdmission validInput = none := by
  decide

theorem binding_count_mismatch_rejects :
    evaluateStatementAnchorAdmission { validInput with bindingCount := 1 } =
      some StatementAnchorAdmissionReject.bindingCountMismatch := by
  decide

theorem unknown_anchor_rejects :
    evaluateStatementAnchorAdmission
        { validInput with anchorKnownChecks := [true, false] } =
      some StatementAnchorAdmissionReject.unknownAnchor := by
  decide

theorem binding_count_mismatch_precedes_unknown_anchor :
    evaluateStatementAnchorAdmission
        { validInput with
          bindingCount := 1,
          anchorKnownChecks := [false]
        } =
      some StatementAnchorAdmissionReject.bindingCountMismatch := by
  decide

theorem same_block_anchor_rejects :
    evaluateStatementAnchorAdmission
        {
          txCount := 2,
          bindingCount := 2,
          anchorKnownChecks := [true, false]
        } =
      some StatementAnchorAdmissionReject.unknownAnchor := by
  decide

theorem empty_statement_anchor_admission_accepts :
    evaluateStatementAnchorAdmission
        {
          txCount := 0,
          bindingCount := 0,
          anchorKnownChecks := []
        } = none := by
  decide

theorem accepted_implies_all_anchors_known
    (input : StatementAnchorAdmissionInput)
    (h : statementAnchorAdmissionAccepts input = true) :
    anchorsKnown input = true := by
  by_cases hKnown : anchorsKnown input
  · exact hKnown
  unfold statementAnchorAdmissionAccepts
    evaluateStatementAnchorAdmission at h
  by_cases hCount : input.bindingCount = input.txCount
  · simp [hCount] at h
    simp [hKnown] at h
  · simp [hCount] at h

theorem accepted_implies_binding_count_matches
    (input : StatementAnchorAdmissionInput)
    (h : statementAnchorAdmissionAccepts input = true) :
    input.bindingCount = input.txCount := by
  unfold statementAnchorAdmissionAccepts
    evaluateStatementAnchorAdmission at h
  by_cases hCount : input.bindingCount = input.txCount
  · exact hCount
  · simp [hCount] at h

end StatementAnchorAdmission
end Consensus
end Hegemon
