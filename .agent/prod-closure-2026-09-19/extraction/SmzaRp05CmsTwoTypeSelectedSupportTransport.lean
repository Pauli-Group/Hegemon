import SmzaRp05CmsEventEqualityTransport

/-! Simultaneous input/workspace transport for a selected CMS coefficient.
This is deterministic type naturality, not a security or probability premise.
-/

namespace HegemonCrypto.SmallWood.SmzaRp05CmsTwoTypeSelectedSupportTransport

open HegemonCrypto.FiniteOracleDatabase
open HegemonCrypto.CmsCompressedOracle
open HegemonCrypto.CmsAdaptiveClaimBridge
open scoped Classical

noncomputable section
set_option autoImplicit false
set_option linter.unusedSectionVars false

variable {InputLeft InputRight Output Phase WorkspaceLeft WorkspaceRight : Type}
variable [fintypeInputLeft : Fintype InputLeft] [decEqInputLeft : DecidableEq InputLeft]
variable [fintypeInputRight : Fintype InputRight] [decEqInputRight : DecidableEq InputRight]
variable [Fintype Output] [DecidableEq Output] [AddCommGroup Output]
variable [Fintype Phase] [DecidableEq Phase]
variable [fintypeWorkLeft : Fintype WorkspaceLeft] [decEqWorkLeft : DecidableEq WorkspaceLeft]
variable [fintypeWorkRight : Fintype WorkspaceRight] [decEqWorkRight : DecidableEq WorkspaceRight]

theorem basisTypeEq2 (sameInput : InputLeft = InputRight)
    (sameWork : WorkspaceLeft = WorkspaceRight) :
    Basis InputLeft Output Phase WorkspaceLeft =
      Basis InputRight Output Phase WorkspaceRight :=
  (congrArg (fun input => Basis input Output Phase WorkspaceLeft) sameInput).trans
    (congrArg (fun workspace => Basis InputRight Output Phase workspace) sameWork)

theorem stateTypeEq2 (sameInput : InputLeft = InputRight)
    (sameWork : WorkspaceLeft = WorkspaceRight) :
    State InputLeft Output Phase WorkspaceLeft =
      State InputRight Output Phase WorkspaceRight :=
  (congrArg (fun input => State input Output Phase WorkspaceLeft) sameInput).trans
    (congrArg (fun workspace => State InputRight Output Phase workspace) sameWork)

/-- The target coefficient is the source coefficient on the canonically
cast basis. Both selectors are checked at that very basis; no equality of
unrelated prepared states or selector-stability assumption is used. -/
theorem selected_projection_coefficient_eq_at_basis_two_types
    (sameInput : InputLeft = InputRight)
    (sameWork : WorkspaceLeft = WorkspaceRight)
    (eventLeft : WorkspaceLeft → Database InputLeft Output → Prop)
    (eventRight : WorkspaceRight → Database InputRight Output → Prop)
    (stateLeft : State InputLeft Output Phase WorkspaceLeft)
    (stateRight : State InputRight Output Phase WorkspaceRight)
    (stateEq : cast (stateTypeEq2 sameInput sameWork) stateLeft = stateRight)
    (basis : Basis InputLeft Output Phase WorkspaceLeft)
    (sourceSelected : eventLeft basis.workspace basis.database)
    (targetSelected : eventRight (cast sameWork basis.workspace)
      (cast (SmzaRp05CmsEventEqualityTransport.databaseTypeEq sameInput) basis.database)) :
    (workspaceEventProjection eventRight stateRight)
        (cast (basisTypeEq2 sameInput sameWork) basis) =
      (workspaceEventProjection eventLeft stateLeft) basis := by
  classical
  cases sameInput
  cases sameWork
  have sameFintypeInput : fintypeInputLeft = fintypeInputRight := Subsingleton.elim _ _
  cases sameFintypeInput
  have sameDecEqInput : decEqInputLeft = decEqInputRight := Subsingleton.elim _ _
  cases sameDecEqInput
  have sameFintypeWork : fintypeWorkLeft = fintypeWorkRight := Subsingleton.elim _ _
  cases sameFintypeWork
  have sameDecEqWork : decEqWorkLeft = decEqWorkRight := Subsingleton.elim _ _
  cases sameDecEqWork
  have stateEq' : stateLeft = stateRight := by
    simpa [stateTypeEq2] using stateEq
  have targetSelected' : eventRight basis.workspace basis.database := by
    simpa [SmzaRp05CmsEventEqualityTransport.databaseTypeEq] using targetSelected
  have coefficientEq : stateRight basis = stateLeft basis := by
    exact (congrArg (fun state => state basis) stateEq').symm
  simpa [basisTypeEq2, workspaceEventProjection, sourceSelected, targetSelected']
    using coefficientEq

theorem selected_projection_support_cast_at_basis_two_types
    (sameInput : InputLeft = InputRight)
    (sameWork : WorkspaceLeft = WorkspaceRight)
    (eventLeft : WorkspaceLeft → Database InputLeft Output → Prop)
    (eventRight : WorkspaceRight → Database InputRight Output → Prop)
    (stateLeft : State InputLeft Output Phase WorkspaceLeft)
    (stateRight : State InputRight Output Phase WorkspaceRight)
    (stateEq : cast (stateTypeEq2 sameInput sameWork) stateLeft = stateRight)
    (basis : Basis InputLeft Output Phase WorkspaceLeft)
    (sourceSelected : eventLeft basis.workspace basis.database)
    (targetSelected : eventRight (cast sameWork basis.workspace)
      (cast (SmzaRp05CmsEventEqualityTransport.databaseTypeEq sameInput) basis.database))
    (sourceNonzero : (workspaceEventProjection eventLeft stateLeft) basis ≠ 0) :
    (workspaceEventProjection eventRight stateRight)
      (cast (basisTypeEq2 sameInput sameWork) basis) ≠ 0 := by
  rw [selected_projection_coefficient_eq_at_basis_two_types sameInput sameWork
    eventLeft eventRight stateLeft stateRight stateEq basis sourceSelected targetSelected]
  exact sourceNonzero

end
end HegemonCrypto.SmallWood.SmzaRp05CmsTwoTypeSelectedSupportTransport
