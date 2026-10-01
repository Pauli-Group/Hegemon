import Q38SelectionFeedback

/-! Abstract feedback-to-probability operator. The complete oracle carrier,
secret type, and physical kernel stay abstract while composing continuity
with the preselection theorem; no concrete leaf enumeration is elaborated. -/
namespace HegemonCrypto.SmallWood.V8SmzaAdaptiveOpening

open V8Smz9HiddenLeafQrom V8Smz9HiddenPatch V8Smz9RuntimeDistribution
open V8Smz9CurrentPrivacyGame V8Smz9HonestWholeViewGames
open V8Smz9MeasuredRunContinuity V8Smz9MeasuredOracleHybrid
open V8SmzaSelectionFeedback
open scoped Classical

noncomputable section
set_option autoImplicit false
set_option Elab.async false
set_option maxHeartbeats 2000000
set_option maxRecDepth 10000

theorem selection_feedback_probability_bound
    {Input Work Job Secret : Type}
    [Fintype Input] [DecidableEq Input] [Fintype Work]
    [Fintype Secret] [Nonempty Secret]
    (selecPrefix : Selection Input Work Job)
    (next : Secret → PhysicalKernel (Input := Input) (Work := Work) Job)
    (support : Secret → Finset Input) (p : ℝ)
    (nonnegative : 0 ≤ p) (atMostOne : p ≤ 1)
    (bounded : ∀ input, supportCount support input ≤ (Fintype.card Secret : ℝ) * p)
    (old : Input → DigestRegister) (patched : Secret → Input → DigestRegister)
    (same : ∀ secret input, input ∉ support secret → old input = patched secret input)
    (state : GameState (Input := Input) (Work := Work)) :
    |uniformAverage (fun secret => execute selecPrefix (next secret).observe (patched secret) state) -
      uniformAverage (fun secret => execute selecPrefix (next secret).observe old state)| ≤
      queryLoss p (exposures selecPrefix) state := by
  have feedback := remove_preselection_feedback
    (Input := Input) (Work := Work) (Job := Job) (Secret := Secret)
    selecPrefix next support p nonnegative atMostOne bounded old patched same state
  exact (average_difference_abs_le
    (fun secret => execute selecPrefix (next secret).observe (patched secret) state)
    (fun secret => execute selecPrefix (next secret).observe old state)).trans feedback

end
end HegemonCrypto.SmallWood.V8SmzaAdaptiveOpening
