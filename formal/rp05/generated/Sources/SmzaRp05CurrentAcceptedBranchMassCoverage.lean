import SmzaRp05CurrentSelectedCurrentAdviceEventMass
import SmzaRoleDomainConditioning

/-! # Accepted physical-branch mass coverage

This converts deterministic support coverage into an unnormalised physical
branch mass inequality. It makes no claim about the probability of the
classifier event or the branch selector.
-/
namespace HegemonCrypto.SmallWood.SmzaRp05CurrentAcceptedBranchMassCoverage

open scoped Classical BigOperators
open HegemonCrypto.CmsCompressedOracle
open HegemonCrypto.CmsOracleSimulation
open HegemonCrypto.CmsOracleDatabaseBridge
open HegemonCrypto.CmsAdaptiveClaimBridge
open HegemonCrypto.FiniteOracleDatabase
open SmzaRp05ConditionedExecution
open SmzaRp05CurrentSelectedCurrentAdviceEventMass
open SmzaRoleDomainConditioning (same_execution_workspace_event_union_bound)

noncomputable section
set_option autoImplicit false
set_option linter.unusedSectionVars false

/-- If every supported accepted-branch basis is either a same-branch
collision, one of the role-indexed X-view selectors, or missing a recorded
claim, its original mass is bounded by those three physical projections.
This is the raw physical-branch form; later fixed-fiber transport must retain
these exact Born weights. -/
theorem accepted_branch_mass_le_selector_collision_missing
    {Index Input Output Phase Work : Type}
    [Fintype Index] [Fintype Input] [DecidableEq Input]
    [Fintype Output] [DecidableEq Output] [AddCommGroup Output]
    [Fintype Phase] [DecidableEq Phase]
    [Fintype Work] [DecidableEq Work]
    (accepted : Prop)
    (state : State Input Output Phase Work)
    (claims : List (Input × Output))
    (collision : Work → Database Input Output → Prop)
    (selector : Index → Work → Database Input Output → Prop)
    (covered : ∀ basis : Basis Input Output Phase Work,
      state basis ≠ 0 → accepted →
        ClaimsDatabaseEvent claims basis.database →
        collision basis.workspace basis.database ∨
          ∃ index, selector index basis.workspace basis.database) :
    (if accepted then normSquared state else 0) ≤
      normSquared (workspaceEventProjection collision state) +
        (∑ index : Index,
          normSquared (workspaceEventProjection (selector index) state)) +
        normSquared (databaseEventProjection
          (fun database => ¬ ClaimsDatabaseEvent claims database) state) := by
  classical
  let unionEvent : Work → Database Input Output → Prop :=
    fun work database => collision work database ∨
      ∃ index, selector index work database
  let indexedEvent : Option Index → Work → Database Input Output → Prop :=
    fun option work database =>
      match option with
      | none => collision work database
      | some index => selector index work database
  have unionEq : (fun work database => ∃ option : Option Index,
      indexedEvent option work database) = unionEvent := by
    funext work database
    apply propext
    constructor
    · rintro ⟨option, selected⟩
      cases option with
      | none => exact Or.inl selected
      | some index => exact Or.inr ⟨index, selected⟩
    · rintro (collisionAt | ⟨index, selected⟩)
      · exact ⟨none, collisionAt⟩
      · exact ⟨some index, selected⟩
  have unionBound : normSquared (workspaceEventProjection unionEvent state) ≤
      normSquared (workspaceEventProjection collision state) +
        ∑ index : Index,
          normSquared (workspaceEventProjection (selector index) state) := by
    have h := same_execution_workspace_event_union_bound indexedEvent state
    rw [unionEq] at h
    rw [Fintype.sum_option] at h
    simpa only [indexedEvent] using h
  have collisionNonnegative : 0 ≤
      normSquared (workspaceEventProjection collision state) := by
    unfold normSquared
    exact Finset.sum_nonneg fun basis _ => Complex.normSq_nonneg _
  have selectorNonnegative : 0 ≤
      ∑ index : Index,
        normSquared (workspaceEventProjection (selector index) state) :=
    Finset.sum_nonneg fun index _ => by
      unfold normSquared
      exact Finset.sum_nonneg fun basis _ => Complex.normSq_nonneg _
  have missingNonnegative : 0 ≤ normSquared
      (databaseEventProjection
        (fun database => ¬ ClaimsDatabaseEvent claims database) state) := by
    unfold normSquared
    exact Finset.sum_nonneg fun basis _ => Complex.normSq_nonneg _
  by_cases acceptedTrue : accepted
  · have included : ∀ basis : Basis Input Output Phase Work,
        state basis ≠ 0 →
          unionEvent basis.workspace basis.database ∨
            ¬ ClaimsDatabaseEvent claims basis.database := by
      intro basis support
      by_cases fullClaims : ClaimsDatabaseEvent claims basis.database
      · exact Or.inl (covered basis support acceptedTrue fullClaims)
      · exact Or.inr fullClaims
    have stateSplit := norm_squared_le_workspace_event_add_missing_claim_mass
      unionEvent claims state included
    simpa [acceptedTrue] using
      (stateSplit.trans (add_le_add_left unionBound
        (normSquared (databaseEventProjection
          (fun database => ¬ ClaimsDatabaseEvent claims database) state))))
  · simp only [if_neg acceptedTrue]
    linarith

end

end HegemonCrypto.SmallWood.SmzaRp05CurrentAcceptedBranchMassCoverage
