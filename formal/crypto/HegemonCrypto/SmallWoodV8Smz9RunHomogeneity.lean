import HegemonCrypto.SmallWoodV8Smz9MeasuredRunContinuity
import HegemonCrypto.SmallWoodV8Smz9MixedMaskSemantics

/-! Quadratic scaling of the full measured interpreter and a generic
normalized-to-arbitrary-state lift. Instrument outcomes keep their original
Born weights; no branch is conditioned on or renormalized. -/

namespace HegemonCrypto.SmallWood.V8Smz9RunHomogeneity

open V8Smz9HiddenLeafQrom V8Smz9HiddenPatch V8Smz9RuntimeDistribution V8Smz9CurrentPrivacyGame
open V8Smz9HonestWholeViewGames V8Smz9MeasuredRunContinuity
open scoped BigOperators Classical

noncomputable section
set_option maxHeartbeats 500000
set_option maxRecDepth 10000
set_option Elab.async false

section Interpreter

variable {Input Work : Type} [Fintype Input] [DecidableEq Input] [Fintype Work]

theorem born_smul (event : Finset (QueryBasis Input DigestRegister Work))
    (scalar : ℂ) (state : GameState (Input := Input) (Work := Work)) :
    born event (scalar • state) = Complex.normSq scalar * born event state := by
  simp only [born, map_smul, norm_smul, mul_pow, Complex.normSq_eq_norm_sq]

/-- All seven constructors, including complete instruments and persistent
fresh-input updates, preserve exact quadratic scaling of the input state. -/
theorem run_smul (randomized : Bool) (program : Program Input Work)
    (oracle : Input → DigestRegister) (scalar : ℂ)
    (state : GameState (Input := Input) (Work := Work)) :
    V8Smz9HonestWholeViewGames.run randomized program oracle (scalar • state) =
      Complex.normSq scalar * V8Smz9HonestWholeViewGames.run randomized program oracle state := by
  induction program generalizing oracle state with
  | finish event => exact born_smul event scalar state
  | gate operation next ih =>
      simpa only [V8Smz9HonestWholeViewGames.run, map_smul] using ih oracle (operation state)
  | quantumQuery next ih =>
      simpa only [V8Smz9HonestWholeViewGames.run, map_smul] using ih oracle (query oracle state)
  | honestRead input next ih => exact ih (oracle input) oracle state
  | instrument operation next ih =>
      simp only [V8Smz9HonestWholeViewGames.run, map_smul, ih, Finset.mul_sum]
  | random source next ih =>
      simp only [V8Smz9HonestWholeViewGames.run, ih, average_mul_left]
  | freshInput sampler next ih =>
      simp only [V8Smz9HonestWholeViewGames.run, ih, average_mul_left]

theorem run_zero (randomized : Bool) (program : Program Input Work)
    (oracle : Input → DigestRegister) :
    V8Smz9HonestWholeViewGames.run randomized program oracle
      (0 : GameState (Input := Input) (Work := Work)) = 0 := by
  have scaled := run_smul randomized program oracle (0 : ℂ) (0 : GameState (Input := Input) (Work := Work))
  simpa only [zero_smul, Complex.normSq_zero, zero_mul] using scaled

end Interpreter

section GenericObservation

variable {Space : Type*} [NormedAddCommGroup Space] [NormedSpace ℂ Space]

def QuadraticallyHomogeneous (observe : Space → ℝ) : Prop :=
  ∀ (scalar : ℂ) (state : Space), observe (scalar • state) = Complex.normSq scalar * observe state

theorem quadratically_homogeneous_zero (observe : Space → ℝ)
    (homogeneous : QuadraticallyHomogeneous observe) : observe 0 = 0 := by
  simpa only [zero_smul, Complex.normSq_zero, zero_mul] using homogeneous (0 : ℂ) (0 : Space)

theorem uniform_average_quadratically_homogeneous {Coins : Type} [Fintype Coins] [Nonempty Coins]
    (observe : Coins → Space → ℝ) (homogeneous : ∀ coin, QuadraticallyHomogeneous (observe coin)) :
    QuadraticallyHomogeneous (fun state => uniformAverage fun coin => observe coin state) := by
  intro scalar state
  have scaled (coin : Coins) := homogeneous coin scalar state
  simp only [scaled, average_mul_left]

theorem sum_quadratically_homogeneous {Branch : Type} [Fintype Branch]
    (observe : Branch → Space → ℝ) (homogeneous : ∀ branch, QuadraticallyHomogeneous (observe branch)) :
    QuadraticallyHomogeneous (fun state => ∑ branch, observe branch state) := by
  intro scalar state
  have scaled (branch : Branch) := homogeneous branch scalar state
  simp only [scaled, Finset.mul_sum]

/-- A normalized comparison extends with exactly the input Born mass. This
holds for every state, even above unit norm; no postselection is performed. -/
theorem normalized_comparison_lifts_to_all_states
    (left right : Space → ℝ)
    (leftHomogeneous : QuadraticallyHomogeneous left)
    (rightHomogeneous : QuadraticallyHomogeneous right)
    (loss : ℝ) (normalizedBound : ∀ state, ‖state‖ = 1 → |left state - right state| ≤ loss)
    (state : Space) : |left state - right state| ≤ loss * ‖state‖ ^ 2 := by
  by_cases zeroState : state = 0
  · subst state
    simp only [quadratically_homogeneous_zero left leftHomogeneous,
      quadratically_homogeneous_zero right rightHomogeneous, sub_self, abs_zero,
      norm_zero, zero_pow (by decide : 2 ≠ 0), mul_zero, le_refl]
  · have normNonzero : ‖state‖ ≠ 0 := norm_ne_zero_iff.mpr zeroState
    let unitState : Space := ((‖state‖⁻¹ : ℝ) : ℂ) • state
    have unitNorm : ‖unitState‖ = 1 := by
      simp only [unitState, norm_smul, Complex.norm_real, norm_inv, norm_norm,
        inv_mul_cancel₀ normNonzero]
    have restore : (‖state‖ : ℂ) • unitState = state := by
      simp only [unitState, smul_smul, ← Complex.ofReal_mul, mul_inv_cancel₀ normNonzero,
        Complex.ofReal_one, one_smul]
    have mass : Complex.normSq (‖state‖ : ℂ) = ‖state‖ ^ 2 := by
      rw [Complex.normSq_eq_norm_sq, Complex.norm_real, norm_norm]
    have leftScaled : left state = ‖state‖ ^ 2 * left unitState := by
      simpa only [restore, mass] using leftHomogeneous (‖state‖ : ℂ) unitState
    have rightScaled : right state = ‖state‖ ^ 2 * right unitState := by
      simpa only [restore, mass] using rightHomogeneous (‖state‖ : ℂ) unitState
    rw [leftScaled, rightScaled, ← mul_sub, abs_mul, abs_of_nonneg (sq_nonneg _)]
    exact (mul_le_mul_of_nonneg_left (normalizedBound unitState unitNorm) (sq_nonneg _)).trans_eq
      (mul_comm _ _)

theorem normalized_comparison_lifts_to_subnormalized_states
    (left right : Space → ℝ)
    (leftHomogeneous : QuadraticallyHomogeneous left)
    (rightHomogeneous : QuadraticallyHomogeneous right)
    (loss : ℝ) (lossNonnegative : 0 ≤ loss)
    (normalizedBound : ∀ state, ‖state‖ = 1 → |left state - right state| ≤ loss)
    (state : Space) (subnormalized : ‖state‖ ≤ 1) : |left state - right state| ≤ loss := by
  have massBound : ‖state‖ ^ 2 ≤ 1 := by nlinarith [norm_nonneg state]
  exact (normalized_comparison_lifts_to_all_states left right leftHomogeneous rightHomogeneous
    loss normalizedBound state).trans
      ((mul_le_mul_of_nonneg_left massBound lossNonnegative).trans_eq (mul_one loss))

end GenericObservation

theorem run_quadratically_homogeneous {Input Work : Type}
    [Fintype Input] [DecidableEq Input] [Fintype Work]
    (randomized : Bool) (program : Program Input Work) (oracle : Input → DigestRegister) :
    QuadraticallyHomogeneous (fun state => V8Smz9HonestWholeViewGames.run randomized program oracle state) :=
  run_smul randomized program oracle

section MixedInterpreter

variable {Input Work : Type} [Fintype Input] [DecidableEq Input] [Fintype Work]

/-- The mixed interpreter, including fixed writes, inherits scaling from
its checked physical compiler started with the empty correction log. -/
theorem mixed_run_smul (randomized : Bool)
    (program : V8Smz9MixedMaskCompiler.MixedProgram Input Work)
    (oracle : Input → DigestRegister) (scalar : ℂ)
    (state : GameState (Input := Input) (Work := Work)) :
    V8Smz9MixedMaskCompiler.run randomized program oracle (scalar • state) =
      Complex.normSq scalar * V8Smz9MixedMaskCompiler.run randomized program oracle state := by
  have scaled := run_smul randomized (V8Smz9MixedMaskCompiler.compile program []) oracle scalar state
  simpa only [V8Smz9MixedMaskCompiler.compile_executes, V8Smz9MixedMaskCompiler.effective_empty] using scaled

theorem mixed_run_zero (randomized : Bool)
    (program : V8Smz9MixedMaskCompiler.MixedProgram Input Work)
    (oracle : Input → DigestRegister) :
    V8Smz9MixedMaskCompiler.run randomized program oracle
      (0 : GameState (Input := Input) (Work := Work)) = 0 := by
  have zero := run_zero randomized (V8Smz9MixedMaskCompiler.compile program []) oracle
  simpa only [V8Smz9MixedMaskCompiler.compile_executes, V8Smz9MixedMaskCompiler.effective_empty] using zero

theorem mixed_run_quadratically_homogeneous (randomized : Bool)
    (program : V8Smz9MixedMaskCompiler.MixedProgram Input Work) (oracle : Input → DigestRegister) :
    QuadraticallyHomogeneous (fun state => V8Smz9MixedMaskCompiler.run randomized program oracle state) :=
  mixed_run_smul randomized program oracle

end MixedInterpreter

end
end HegemonCrypto.SmallWood.V8Smz9RunHomogeneity
