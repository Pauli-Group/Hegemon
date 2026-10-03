import Q38SelectionFeedback

/-! Generic selection lifting, separated to bound serial proof elaboration.
Declaration names, statements, and proofs are unchanged. -/
namespace HegemonCrypto.SmallWood.V8SmzaAdaptiveOpening
open V8Smz9HiddenLeafQrom V8Smz9HiddenPatch V8Smz9RuntimeDistribution
open V8Smz9CurrentPrivacyGame V8Smz9CurrentPrivacyComposition V8Smz9HonestWholeViewGames
open V8Smz9MeasuredRunContinuity V8Smz9MeasuredOracleHybrid V8Smz9MeasuredSourceHiddenPatch
open V8SmzaSelectionFeedback
open scoped BigOperators Classical
noncomputable section
set_option autoImplicit false
set_option Elab.async false
set_option maxHeartbeats 2000000
set_option maxRecDepth 10000
set_option linter.unusedSectionVars false

section SelectionLifting
variable {Input Work Job Secret : Type}
variable [Fintype Input] [DecidableEq Input] [Fintype Work] [Fintype Secret] [Nonempty Secret]

/-- The tape-independent reference selecPrefix permits exact averaging through
all complete instrument branches, with no renormalization or conditioning. -/
theorem execute_average (selecPrefix : Selection Input Work Job)
    (next : Secret → Kernel (Input := Input) (Work := Work) (Job := Job))
    (oracle : Input → DigestRegister) (state : GameState (Input := Input) (Work := Work)) :
    uniformAverage (fun hidden => execute selecPrefix (next hidden) oracle state) =
      execute selecPrefix (fun job state => uniformAverage fun hidden => next hidden job state) oracle state := by
  induction selecPrefix generalizing state with
  | reveal job => rfl
  | gate operation tail ih => exact ih (operation state)
  | quantumQuery tail ih => exact ih (query oracle state)
  | honestRead input tail ih => exact ih (oracle input) state
  | instrument operation tail ih =>
      simp only [execute, average_sum]
      exact Finset.sum_congr rfl fun branch _ => ih branch (operation.branch branch state)
  | random source tail ih =>
      simp only [execute]
      rw [uniform_average_comm]
      exact congrArg uniformAverage (funext fun coin => ih coin state)

theorem execute_pivot_bound (selecPrefix : Selection Input Work Job)
    (left right : Kernel (Input := Input) (Work := Work) (Job := Job)) (loss : ℝ)
    (bounded : ∀ job state, |left job state - right job state| ≤ loss * ‖state‖ ^ 2)
    (oracle : Input → DigestRegister) (state : GameState (Input := Input) (Work := Work)) :
    |execute selecPrefix left oracle state - execute selecPrefix right oracle state| ≤ loss * ‖state‖ ^ 2 := by
  induction selecPrefix generalizing state with
  | reveal job => exact bounded job state
  | gate operation tail ih => simpa only [execute, operation.norm_map] using ih (operation state)
  | quantumQuery tail ih => simpa only [execute, (query oracle).norm_map] using ih (query oracle state)
  | honestRead input tail ih => exact ih (oracle input) state
  | instrument operation tail ih =>
      simp only [execute, ← Finset.sum_sub_distrib]
      exact (Finset.abs_sum_le_sum_abs _ _).trans ((Finset.sum_le_sum
        fun branch _ => ih branch (operation.branch branch state)).trans_eq
          (by rw [← Finset.mul_sum, operation.complete]))
  | random source tail ih =>
      exact (average_difference_abs_le _ _).trans (average_le_const _ _ fun coin => ih coin state)
end SelectionLifting
end
end HegemonCrypto.SmallWood.V8SmzaAdaptiveOpening
