import HegemonCrypto.SmallWoodV8Smz9HonestWholeViewGames
import Mathlib.Analysis.Real.Sqrt

namespace HegemonCrypto.SmallWood.V8Smz9MeasuredRunContinuity

open V8Smz9HiddenLeafQrom V8Smz9HiddenPatch V8Smz9RuntimeDistribution
open V8Smz9CurrentPrivacyGame V8Smz9CurrentPrivacyComposition
open V8Smz9HonestWholeViewGames
open scoped BigOperators Classical ENNReal

noncomputable section
set_option maxHeartbeats 2000000
set_option maxRecDepth 10000
set_option Elab.async false

variable {Input Work : Type} [Fintype Input] [DecidableEq Input] [Fintype Work]

theorem average_mono {Coins : Type} [Fintype Coins] [Nonempty Coins]
    (left right : Coins → ℝ) (bounded : ∀ coin, left coin ≤ right coin) :
    uniformAverage left ≤ uniformAverage right := by
  apply Finset.sum_le_sum
  intro coin _
  exact mul_le_mul_of_nonneg_left (bounded coin) ENNReal.toReal_nonneg

theorem average_add {Coins : Type} [Fintype Coins] [Nonempty Coins]
    (left right : Coins → ℝ) :
    uniformAverage (fun coin => left coin + right coin) =
      uniformAverage left + uniformAverage right := by
  simp only [uniformAverage, mul_add, Finset.sum_add_distrib]

theorem average_sub {Coins : Type} [Fintype Coins] [Nonempty Coins]
    (left right : Coins → ℝ) :
    uniformAverage (fun coin => left coin - right coin) =
      uniformAverage left - uniformAverage right := by
  simp only [uniformAverage, mul_sub, Finset.sum_sub_distrib]

theorem average_mul_left {Coins : Type} [Fintype Coins] [Nonempty Coins]
    (scalar : ℝ) (value : Coins → ℝ) :
    uniformAverage (fun coin => scalar * value coin) = scalar * uniformAverage value := by
  unfold uniformAverage
  rw [Finset.mul_sum]
  apply Finset.sum_congr rfl
  intro coin _
  ring

theorem average_mul_right {Coins : Type} [Fintype Coins] [Nonempty Coins]
    (value : Coins → ℝ) (scalar : ℝ) :
    uniformAverage (fun coin => value coin * scalar) = uniformAverage value * scalar := by
  simp only [uniformAverage, mul_assoc, Finset.sum_mul]

theorem average_sum {Coins Branch : Type} [Fintype Coins] [Nonempty Coins] [Fintype Branch]
    (value : Coins → Branch → ℝ) :
    uniformAverage (fun coin => ∑ branch, value coin branch) =
      ∑ branch, uniformAverage (fun coin => value coin branch) := by
  simp only [uniformAverage, Finset.mul_sum]
  rw [Finset.sum_comm]

theorem average_abs_le {Coins : Type} [Fintype Coins] [Nonempty Coins]
    (value : Coins → ℝ) :
    |uniformAverage value| ≤ uniformAverage (fun coin => |value coin|) := by
  unfold uniformAverage
  calc
    _ ≤ ∑ coin, |(uniformFintypePMF Coins coin).toReal * value coin| :=
      Finset.abs_sum_le_sum_abs _ _
    _ = _ := by
      apply Finset.sum_congr rfl
      intro coin _
      rw [abs_mul, abs_of_nonneg ENNReal.toReal_nonneg]

theorem average_difference_abs_le {Coins : Type} [Fintype Coins] [Nonempty Coins]
    (left right : Coins → ℝ) :
    |uniformAverage left - uniformAverage right| ≤
      uniformAverage (fun coin => |left coin - right coin|) := by
  rw [← average_sub]
  exact average_abs_le _

theorem average_le_const {Coins : Type} [Fintype Coins] [Nonempty Coins]
    (value : Coins → ℝ) (bound : ℝ) (bounded : ∀ coin, value coin ≤ bound) :
    uniformAverage value ≤ bound := by
  exact (average_mono value (fun _ => bound) bounded).trans_eq (uniform_average_const bound)

/-- The Born event estimate without normalization or postselection. -/
theorem born_difference_subnormalized
    (event : Finset (QueryBasis Input DigestRegister Work))
    (left right : GameState (Input := Input) (Work := Work)) :
    |born event left - born event right| ≤ (‖left‖ + ‖right‖) * ‖left - right‖ := by
  have leftBound := event_projection_norm_le event left
  have rightBound := event_projection_norm_le event right
  have reverse := abs_norm_sub_norm_le (eventProjection event left) (eventProjection event right)
  have projected : ‖eventProjection event left - eventProjection event right‖ ≤ ‖left - right‖ := by
    rw [← map_sub]
    exact event_projection_norm_le event _
  calc
    _ = |‖eventProjection event left‖ - ‖eventProjection event right‖| *
        (‖eventProjection event left‖ + ‖eventProjection event right‖) := by
      unfold born
      rw [sq_sub_sq, abs_mul, abs_of_nonneg (add_nonneg (norm_nonneg _) (norm_nonneg _))]
      ring
    _ ≤ ‖left - right‖ * (‖left‖ + ‖right‖) :=
      mul_le_mul (reverse.trans projected) (add_le_add leftBound rightBound)
        (add_nonneg (norm_nonneg _) (norm_nonneg _)) (norm_nonneg _)
    _ = _ := mul_comm _ _

omit [DecidableEq Input] in
theorem instrument_norm_products_le {count : Nat} (operation : Instrument Input Work count)
    (left right : GameState (Input := Input) (Work := Work)) :
    (∑ branch, ‖operation.branch branch left‖ * ‖operation.branch branch right‖) ≤
      ‖left‖ * ‖right‖ := by
  have cauchy := Real.sum_mul_le_sqrt_mul_sqrt (Finset.univ : Finset (Fin count))
    (fun branch => ‖operation.branch branch left‖)
    (fun branch => ‖operation.branch branch right‖)
  simpa only [operation.complete, Real.sqrt_sq_eq_abs, abs_of_nonneg (norm_nonneg _)] using cauchy

/-- Any complete measured continuation is a nonexpansive event test on
subnormalized states. Every measurement branch remains in the sum. -/
theorem run_difference_subnormalized (randomized : Bool) (program : Program Input Work)
    (oracle : Input → DigestRegister)
    (left right : GameState (Input := Input) (Work := Work)) :
    |V8Smz9HonestWholeViewGames.run randomized program oracle left -
        V8Smz9HonestWholeViewGames.run randomized program oracle right| ≤
      (‖left‖ + ‖right‖) * ‖left - right‖ := by
  induction program generalizing oracle left right with
  | finish event => exact born_difference_subnormalized event left right
  | gate operation next ih =>
      simpa only [V8Smz9HonestWholeViewGames.run, ← map_sub, operation.norm_map] using
        ih oracle (operation left) (operation right)
  | quantumQuery next ih =>
      simpa only [V8Smz9HonestWholeViewGames.run, ← map_sub, (query oracle).norm_map] using
        ih oracle (query oracle left) (query oracle right)
  | honestRead input next ih => exact ih (oracle input) oracle left right
  | instrument operation next ih =>
      simp only [V8Smz9HonestWholeViewGames.run, ← Finset.sum_sub_distrib]
      calc
        _ ≤ ∑ branch, |V8Smz9HonestWholeViewGames.run randomized (next branch) oracle
              (operation.branch branch left) -
            V8Smz9HonestWholeViewGames.run randomized (next branch) oracle
              (operation.branch branch right)| := Finset.abs_sum_le_sum_abs _ _
        _ ≤ ∑ branch, (‖operation.branch branch left‖ + ‖operation.branch branch right‖) *
              ‖operation.branch branch (left - right)‖ := by
          apply Finset.sum_le_sum
          intro branch _
          simpa only [map_sub] using ih branch oracle
            (operation.branch branch left) (operation.branch branch right)
        _ = (∑ branch, ‖operation.branch branch left‖ * ‖operation.branch branch (left-right)‖) +
            ∑ branch, ‖operation.branch branch right‖ * ‖operation.branch branch (left-right)‖ := by
          simp only [add_mul, Finset.sum_add_distrib]
        _ ≤ ‖left‖ * ‖left-right‖ + ‖right‖ * ‖left-right‖ :=
          add_le_add (instrument_norm_products_le operation left (left-right))
            (instrument_norm_products_le operation right (left-right))
        _ = _ := by ring
  | random source next ih =>
      exact (average_difference_abs_le _ _).trans
        (average_le_const _ _ fun coin => ih coin oracle left right)
  | freshInput sampler next ih =>
      apply (average_difference_abs_le _ _).trans
      apply average_le_const
      intro coins
      apply (average_difference_abs_le _ _).trans
      apply average_le_const
      intro output
      exact ih coins _ _ left right


end
end HegemonCrypto.SmallWood.V8Smz9MeasuredRunContinuity
