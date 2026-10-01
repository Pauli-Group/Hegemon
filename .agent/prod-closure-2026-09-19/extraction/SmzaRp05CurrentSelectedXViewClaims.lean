import SmzaRp05CurrentSelectedChallengeClaims
import SmzaRp05CurrentSelectedCurrentAdviceEventMass
import SmzaRp05CurrentNonchallengeSelectorTransport

/-! # Selected mixed support supplies its X-view and full branch claims

On a nonzero selected component, the literal selector predicate holds on the
active database view.  If the selected basis also carries its recognized
challenge claims, those and the X-view's nonchallenge answers reconstruct the
whole branch claim event on the same fixed/active completion.
-/
namespace HegemonCrypto.SmallWood.SmzaRp05CurrentSelectedXViewClaims

open scoped Classical
open HegemonCrypto.FiniteOracleDatabase (Database)
open HegemonCrypto.CmsCompressedOracle (Basis)
open HegemonCrypto.CmsOracleDatabaseBridge (ClaimsDatabaseEvent)
open HegemonCrypto.CmsAdaptiveClaimBridge (workspaceEventProjection)
open SmzaChallengeStageTargets (Role parseStageQuery)
open SmzaRoleDomainConditioning
open SmzaRp05ConditionedExecution
  (ActiveMemory ActiveState FixedTable XKey xView activeXView
    restrictActive mergeFixedActive restrict_merge_fixed_active)
open SmzaRp05CurrentAdaptiveExecution (Context)
open SmzaRp05ExecutableMerkleVerifier (Program)
open SmzaRp05PhysicalAcceptedReplayLite (Branches branchClaims branchKeys branchAnswers)
open SmzaRp05CurrentSelectedChallengeClaims
  (SelectedWork nonchallengeRawKeySet recognizedActiveChallengeClaims
    branchXRoleSelector nonchallenge_raw_key_set_unrecognized
    actual_all_x_and_challenge_claims_supply_full_branch_claims)
open SmzaRp05CurrentSelectedCurrentAdviceEventMass (selectedRoleState)
open SmzaRp05CurrentNonchallengeSelectorTransport (active_nonchallenge_view_eq)
open V8SmzaOracleParser (RawInput RawDigest)
open V8Smz9CoherentVectorMerkle (VectorOutput)

noncomputable section
set_option autoImplicit false
set_option maxRecDepth 12000
set_option linter.unusedSectionVars false

variable {Key Counter BaseWork Result : Type}
  [Fintype Key] [DecidableEq Key]
  [Fintype Counter] [DecidableEq Counter]
  [Fintype BaseWork] [DecidableEq BaseWork]

/-- Nonzero selected support forces the exact X/workspace selector predicate
on that basis.  With the basis's recognized challenge claims, the mixed
branch's complete claim event holds on its literal fixed-table completion.
The final equality exposes that the completion's global X-view is precisely
the selected active view. -/
theorem selected_support_supplies_full_branch_claims
    (ctx : Context (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (blockCap : Role → Nat)
    (encode : RawInput → Key)
    (decode : RawInput → VectorOutput Counter → RawDigest)
    (program : Program Result)
    (branch : Branches decode program)
    (fixed : FixedTable ctx blockCap)
    (initial : ActiveState ctx blockCap)
    (select : (XKey (nonchallengeRawKeySet ctx) → Option (VectorOutput Counter)) →
      SelectedWork (Counter := Counter) (BaseWork := BaseWork) → Prop)
    (basis : Basis (ActiveKey ctx.role blockCap ctx.keyBytes)
      (VectorOutput Counter) (VectorOutput Counter) (ActiveMemory ctx))
    (selectedNonzero : selectedRoleState ctx blockCap encode decode program branch
      fixed initial select basis ≠ 0)
    (challengeClaims : ClaimsDatabaseEvent
      (recognizedActiveChallengeClaims ctx blockCap encode decode program branch)
      basis.database) :
    branchXRoleSelector ctx blockCap encode decode program branch
      (nonchallengeRawKeySet ctx)
      (by
        intro claim member
        exact Finset.mem_filter.mpr ⟨Finset.mem_univ _,
          of_decide_eq_true (List.mem_filter.mp member).2⟩)
      select
      (activeXView ctx blockCap (nonchallengeRawKeySet ctx)
        (nonchallenge_raw_key_set_unrecognized ctx) basis.database)
      basis.workspace.original.2.2 ∧
    ClaimsDatabaseEvent
      (branchClaims (branchKeys encode decode program branch)
        (branchAnswers encode decode program branch))
      (mergeFixedActive ctx blockCap fixed basis.database) ∧
    xView (nonchallengeRawKeySet ctx)
        (mergeFixedActive ctx blockCap fixed basis.database) =
      activeXView ctx blockCap (nonchallengeRawKeySet ctx)
        (nonchallenge_raw_key_set_unrecognized ctx) basis.database := by
  let keys := nonchallengeRawKeySet ctx
  let unrecognized := nonchallenge_raw_key_set_unrecognized ctx
  let covers : ∀ claim ∈
      SmzaRp05CurrentSelectedChallengeClaims.unrecognizedActiveBranchClaims
        ctx blockCap encode decode program branch, claim.1.val ∈ keys := by
    intro claim member
    exact Finset.mem_filter.mpr ⟨Finset.mem_univ _,
      of_decide_eq_true (List.mem_filter.mp member).2⟩
  have selected : branchXRoleSelector ctx blockCap encode decode program branch
      keys covers select (activeXView ctx blockCap keys unrecognized basis.database)
      basis.workspace.original.2.2 := by
    by_contra notSelected
    have zero : selectedRoleState ctx blockCap encode decode program branch
        fixed initial select basis = 0 := by
      simp [selectedRoleState, workspaceEventProjection, keys, notSelected]
    exact selectedNonzero zero
  have claims := actual_all_x_and_challenge_claims_supply_full_branch_claims
    ctx blockCap fixed encode decode program branch initial basis select selected
    selectedNonzero challengeClaims
  have viewEq : xView keys (mergeFixedActive ctx blockCap fixed basis.database) =
      activeXView ctx blockCap keys unrecognized basis.database := by
    have h := active_nonchallenge_view_eq ctx blockCap keys unrecognized
      (mergeFixedActive ctx blockCap fixed basis.database)
    rw [restrict_merge_fixed_active] at h
    exact h.symm
  exact ⟨by simpa [keys, covers, unrecognized] using selected,
    claims, by simpa [keys, unrecognized] using viewEq⟩

end
end HegemonCrypto.SmallWood.SmzaRp05CurrentSelectedXViewClaims
