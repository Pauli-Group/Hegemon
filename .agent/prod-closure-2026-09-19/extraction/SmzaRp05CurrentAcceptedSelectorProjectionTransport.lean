import SmzaRp05CurrentNonchallengeSelectorTransport
import SmzaRp05CurrentSelectedChallengeClaims

/-! # Accepted X-view selector mass through role conditioning

The accepted classifier's selector depends only on the nonchallenge view and
the retained workspace.  Once its witness supplies the actual branch claims,
it also satisfies the claim-consistency side of the ordinary selected-state
projection.  This lemma transports that mass through the existing
other-role transform without changing its norm.
-/
namespace HegemonCrypto.SmallWood.SmzaRp05CurrentAcceptedSelectorProjectionTransport

open scoped Classical
open HegemonCrypto.FiniteOracleDatabase
open HegemonCrypto.CmsCompressedOracle
open HegemonCrypto.CmsOracleSimulation
open HegemonCrypto.CmsAdaptiveClaimBridge
open SmzaChallengeStageTargets (Role parseStageQuery)
open SmzaRp05ConditionedExecution
open SmzaRp05CurrentAdaptiveExecution
open SmzaRp05CurrentSelectedChallengeClaims
open SmzaRp05CurrentNonchallengeSelectorTransport
open SmzaRp05PhysicalAcceptedReplayLite
open SmzaRp05ExecutableMerkleVerifier (Program)
open V8Smz9CoherentVectorMerkle (VectorOutput)
open V8SmzaOracleParser (RawInput RawDigest)

noncomputable section
set_option autoImplicit false
set_option maxRecDepth 12000
set_option linter.unusedSectionVars false

variable {Key Counter BaseWork Result : Type}
  [Fintype Key] [DecidableEq Key]
  [Fintype Counter] [DecidableEq Counter]
  [Fintype BaseWork] [DecidableEq BaseWork]

/-- A selector chosen from a nonchallenge X-view and workspace, when it
already implies the same branch's unrecognized claims, is bounded by the
branchXRoleSelector projection on the corresponding partially decompressed
physical state. -/
theorem accepted_xview_selector_mass_le_branch_selector_mass
    (ctx : Context (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (blockCap : Role → Nat)
    (encode : RawInput → Key)
    (decode : RawInput → VectorOutput Counter → RawDigest)
    (program : Program Result)
    (branch : Branches decode program)
    (selector : (XKey (nonchallengeRawKeySet ctx) →
        Option (VectorOutput Counter)) →
      SmzaRp05CurrentAdaptiveExecution.Work
        (Counter := Counter) (BaseWork := BaseWork) → Prop)
    (state : State Key (VectorOutput Counter) (VectorOutput Counter)
      (SmzaRp05CurrentAdaptiveExecution.Work
        (Counter := Counter) (BaseWork := BaseWork)))
    (selectorClaims : ∀ view work, selector view work →
      ∀ claim (member : claim ∈ unrecognizedActiveBranchClaims ctx blockCap
        encode decode program branch),
        view ⟨claim.1.val,
          by
            apply Finset.mem_filter.mpr
            exact ⟨Finset.mem_univ _, of_decide_eq_true
              (List.mem_filter.mp member).2⟩⟩ =
          some claim.2)
    (outside : ∀ key, key ∈ fixedOtherKeys ctx blockCap →
      key ∉ nonchallengeRawKeySet ctx) :
    normSquared (workspaceEventProjection
      (fun work database => selector (xView (nonchallengeRawKeySet ctx) database) work)
      state) ≤
    normSquared (nonchallengeSelectorProjection (nonchallengeRawKeySet ctx)
      (branchXRoleSelector ctx blockCap encode decode program branch
        (nonchallengeRawKeySet ctx)
        (by
          intro claim member
          apply Finset.mem_filter.mpr
          exact ⟨Finset.mem_univ _, of_decide_eq_true
            (List.mem_filter.mp member).2⟩)
        selector)
      (otherRoleTransform ctx blockCap state)) := by
  classical
  let xKeys := nonchallengeRawKeySet ctx
  let covers : ∀ claim ∈ unrecognizedActiveBranchClaims ctx blockCap encode
      decode program branch, claim.1.val ∈ xKeys := by
    intro claim member
    apply Finset.mem_filter.mpr
    exact ⟨Finset.mem_univ _, of_decide_eq_true (List.mem_filter.mp member).2⟩
  let branchSelector : (XKey xKeys → Option (VectorOutput Counter)) →
      SmzaRp05CurrentAdaptiveExecution.Work
        (Counter := Counter) (BaseWork := BaseWork) → Prop :=
    branchXRoleSelector ctx blockCap encode decode program branch xKeys covers selector
  have pointwise : ∀ basis : Basis Key (VectorOutput Counter)
      (VectorOutput Counter) (SmzaRp05CurrentAdaptiveExecution.Work
        (Counter := Counter) (BaseWork := BaseWork)),
      (fun work database => selector (xView xKeys database) work)
          basis.workspace basis.database →
      branchSelector (xView xKeys basis.database) basis.workspace := by
    intro basis selected
    exact ⟨selected, fun claim member =>
      selectorClaims (xView xKeys basis.database) basis.workspace selected
        claim member⟩
  have massMono : normSquared (workspaceEventProjection
      (fun work database => selector (xView xKeys database) work) state) ≤
      normSquared (workspaceEventProjection
        (fun work database => branchSelector (xView xKeys database) work) state) := by
    unfold normSquared workspaceEventProjection
    apply Finset.sum_le_sum
    intro basis _
    by_cases selected : selector (xView xKeys basis.database) basis.workspace
    · have branchSelected := pointwise basis selected
      simp [selected, branchSelected]
    · simp only [selected, ↓reduceIte]
      by_cases branchSelected : branchSelector (xView xKeys basis.database)
          basis.workspace
      · simp [branchSelected]
        exact Complex.normSq_nonneg _
      · simp [branchSelected]
  have commute := nonchallenge_selector_projection_other_role_transform
    ctx blockCap xKeys branchSelector state outside
  calc
    normSquared (workspaceEventProjection
        (fun work database => selector (xView xKeys database) work) state) ≤
        normSquared (workspaceEventProjection
          (fun work database => branchSelector (xView xKeys database) work) state) :=
      massMono
    _ = normSquared (otherRoleTransform ctx blockCap
          (workspaceEventProjection
            (fun work database => branchSelector (xView xKeys database) work) state)) := by
      rw [other_role_transform_norm_squared]
    _ = normSquared (nonchallengeSelectorProjection xKeys branchSelector
          (otherRoleTransform ctx blockCap state)) := by
      rw [commute]
      rfl

end

end HegemonCrypto.SmallWood.SmzaRp05CurrentAcceptedSelectorProjectionTransport
