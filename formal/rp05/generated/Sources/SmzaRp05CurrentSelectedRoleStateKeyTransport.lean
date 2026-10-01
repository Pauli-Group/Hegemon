import SmzaRp05CmsEventEqualityTransport
import SmzaRp05CurrentSelectedChallengeClaims
import SmzaRp05CurrentAdaptiveExecution
import SmzaRoleDomainConditioning
import SmzaChallengeStageTargets

/-! # Selected-role coefficient transport across a finite-key cast

This file records only deterministic naturality of the selected-state
projector.  Callers supply the concrete one-way classifier implication and
the equality of the mixed states produced by their actual replay argument;
there is no probability, selector-stability, or security premise.
-/

namespace HegemonCrypto.SmallWood.SmzaRp05CurrentSelectedRoleStateKeyTransport

open HegemonCrypto.FiniteOracleDatabase
open HegemonCrypto.CmsCompressedOracle
open HegemonCrypto.CmsAdaptiveClaimBridge
open SmzaRp05CurrentAdaptiveExecution (Context)
open SmzaRoleDomainConditioning (ActiveKey)
open scoped Classical

noncomputable section
set_option autoImplicit false
set_option linter.unusedSectionVars false

variable {KeyLeft KeyRight Counter BaseWork : Type}
variable [fintypeKeyLeft : Fintype KeyLeft] [decEqKeyLeft : DecidableEq KeyLeft]
variable [fintypeKeyRight : Fintype KeyRight] [decEqKeyRight : DecidableEq KeyRight]
variable [Fintype Counter] [DecidableEq Counter]
variable [Fintype BaseWork] [DecidableEq BaseWork]

/-- Context equality after the canonical Key cast induces equality of the
role-active finite key types.  Fintype/DecidableEq witnesses are aligned only
by their canonical subsingleton proofs. -/
theorem active_key_type_eq_of_context_cast
    (sameKey : KeyLeft = KeyRight)
    (ctxLeft : Context (Key := KeyLeft) (Counter := Counter) (BaseWork := BaseWork))
    (ctxRight : Context (Key := KeyRight) (Counter := Counter) (BaseWork := BaseWork))
    (contextEq : cast (congrArg (fun key =>
      Context (Key := key) (Counter := Counter) (BaseWork := BaseWork)) sameKey)
        ctxLeft = ctxRight)
    (blockCap : SmzaChallengeStageTargets.Role → Nat) :
    ActiveKey ctxLeft.role blockCap ctxLeft.keyBytes =
      ActiveKey ctxRight.role blockCap ctxRight.keyBytes := by
  cases sameKey
  have sameFintype : fintypeKeyLeft = fintypeKeyRight := Subsingleton.elim _ _
  cases sameFintype
  have sameDecEq : decEqKeyLeft = decEqKeyRight := Subsingleton.elim _ _
  cases sameDecEq
  have sameContext : ctxLeft = ctxRight := by simpa using contextEq
  exact congrArg (fun ctx : Context (Key := KeyLeft)
      (Counter := Counter) (BaseWork := BaseWork) =>
        ActiveKey ctx.role blockCap ctx.keyBytes) sameContext

variable {Output Phase Workspace : Type}
variable [Fintype Output] [DecidableEq Output] [AddCommGroup Output]
variable [Fintype Phase] [DecidableEq Phase]
variable [Fintype Workspace] [DecidableEq Workspace]

/-- On a source-selected coefficient, a one-way deterministic selector
implication plus equality of the actual mixed-state vectors transports the
coefficient exactly to the cast basis. -/
theorem selected_projection_coefficient_eq_of_implication
    (sameInput : KeyLeft = KeyRight)
    (eventLeft : Workspace → Database KeyLeft Output → Prop)
    (eventRight : Workspace → Database KeyRight Output → Prop)
    (stateLeft : State KeyLeft Output Phase Workspace)
    (stateRight : State KeyRight Output Phase Workspace)
    (stateEq : cast (SmzaRp05CmsEventEqualityTransport.stateTypeEq sameInput)
      stateLeft = stateRight)
    (basis : Basis KeyLeft Output Phase Workspace)
    (selectedLeft : eventLeft basis.workspace basis.database)
    (selectedRight : eventRight basis.workspace
      (cast (SmzaRp05CmsEventEqualityTransport.databaseTypeEq sameInput)
        basis.database)) :
    (workspaceEventProjection eventRight stateRight)
        (cast (SmzaRp05CmsEventEqualityTransport.basisTypeEq sameInput) basis) =
      (workspaceEventProjection eventLeft stateLeft) basis := by
  classical
  cases sameInput
  have sameFintype : fintypeKeyLeft = fintypeKeyRight := Subsingleton.elim _ _
  cases sameFintype
  have sameDecEq : decEqKeyLeft = decEqKeyRight := Subsingleton.elim _ _
  cases sameDecEq
  have stateEq' : stateLeft = stateRight := by
    simpa [SmzaRp05CmsEventEqualityTransport.stateTypeEq] using stateEq
  have eventRightTrue : eventRight basis.workspace basis.database := by
    simpa [SmzaRp05CmsEventEqualityTransport.databaseTypeEq] using selectedRight
  have sameCoefficient : stateRight basis = stateLeft basis := by
    have coeff := congrArg (fun state => state basis) stateEq'
    exact coeff.symm
  simp [workspaceEventProjection, selectedLeft, eventRightTrue, sameCoefficient]

/- The support corollary is deliberately pointwise: a caller proves the
target selector at the exact basis where its history witness was obtained. -/
theorem selected_projection_support_cast_at_basis
    (sameInput : KeyLeft = KeyRight)
    (eventLeft : Workspace → Database KeyLeft Output → Prop)
    (eventRight : Workspace → Database KeyRight Output → Prop)
    (stateLeft : State KeyLeft Output Phase Workspace)
    (stateRight : State KeyRight Output Phase Workspace)
    (stateEq : cast (SmzaRp05CmsEventEqualityTransport.stateTypeEq sameInput)
      stateLeft = stateRight)
    (basis : Basis KeyLeft Output Phase Workspace)
    (sourceSelected : eventLeft basis.workspace basis.database)
    (targetSelected : eventRight basis.workspace
      (cast (SmzaRp05CmsEventEqualityTransport.databaseTypeEq sameInput)
        basis.database))
    (sourceNonzero : (workspaceEventProjection eventLeft stateLeft) basis ≠ 0) :
    (workspaceEventProjection eventRight stateRight)
        (cast (SmzaRp05CmsEventEqualityTransport.basisTypeEq sameInput) basis) ≠ 0 := by
  rw [selected_projection_coefficient_eq_of_implication sameInput eventLeft eventRight
    stateLeft stateRight stateEq basis sourceSelected targetSelected]
  exact sourceNonzero

end
end HegemonCrypto.SmallWood.SmzaRp05CurrentSelectedRoleStateKeyTransport
