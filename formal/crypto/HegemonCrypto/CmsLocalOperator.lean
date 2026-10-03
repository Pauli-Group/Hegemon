import HegemonCrypto.CmsClassicalDatabase
import Mathlib.Algebra.Order.Chebyshev
import Mathlib.Algebra.Group.AddChar
import Mathlib.Analysis.Complex.Basic
import Mathlib.Analysis.Complex.Norm
import Mathlib.Analysis.Normed.Ring.Finite
import Mathlib.Tactic.Linarith

/-!
# CMS compressed-oracle local-operator inequalities

This file mechanizes the finite scalar inequalities used in Section 5.3 of Chiesa, Manohar, and
Spooner, "Succinct Arguments in the Quantum Random Oracle Model", full version dated
2020-01-14.

The paper decomposes one projected compressed-oracle query into four orthogonal mass classes
`s1`, `s2`, `s3`, and `s4`.  Cauchy--Schwarz gives four component bounds with coefficients
`1`, `1`, `5`, and `6`.  The final theorem below proves that these bounds imply the exact local
operator constant `6`.

This module is intentionally below the BCS application and above the concrete compressed-oracle
kernel.  It contains no cryptographic assumption and no unproved theorem interface.
-/

namespace HegemonCrypto.CmsLocalOperator

open scoped BigOperators

/--
Finite complex Cauchy--Schwarz in the form used repeatedly by the CMS local-operator proof.
-/
theorem normSq_sum_le_card_mul_sum_normSq
    {Index : Type*}
    [DecidableEq Index]
    (indices : Finset Index)
    (coefficient : Index -> ℂ) :
    Complex.normSq (∑ index ∈ indices, coefficient index) <=
      indices.card * ∑ index ∈ indices, Complex.normSq (coefficient index) := by
  have normBound :
      ‖∑ index ∈ indices, coefficient index‖ <=
        ∑ index ∈ indices, ‖coefficient index‖ :=
    norm_sum_le _ _
  have squareBound :
      ‖∑ index ∈ indices, coefficient index‖ ^ 2 <=
        (∑ index ∈ indices, ‖coefficient index‖) ^ 2 := by
    exact (sq_le_sq₀ (norm_nonneg _) (by positivity)).2 normBound
  calc
    Complex.normSq (∑ index ∈ indices, coefficient index) =
        ‖∑ index ∈ indices, coefficient index‖ ^ 2 := by
      rw [Complex.sq_norm]
    _ <= (∑ index ∈ indices, ‖coefficient index‖) ^ 2 := squareBound
    _ <= indices.card * ∑ index ∈ indices, ‖coefficient index‖ ^ 2 := by
      exact sq_sum_le_card_mul_sum_sq
    _ = indices.card * ∑ index ∈ indices,
        Complex.normSq (coefficient index) := by
      congr 1
      apply Finset.sum_congr rfl
      intro index _
      exact Complex.sq_norm (coefficient index)

/--
The exact Fourier coefficient identity behind the paper's bound
`sum_y |1 - phase(w) - phase(y)|^2 <= 5 |Y|`.
-/
theorem beta_square_sum
    {Output : Type*}
    [Fintype Output]
    (phase : Output -> ℝ)
    (fixedPhase : ℝ)
    (phaseSquare : ∀ output, phase output ^ 2 = 1)
    (fixedPhaseSquare : fixedPhase ^ 2 = 1)
    (phaseSum : ∑ output, phase output = 0) :
    (∑ output, (1 - fixedPhase - phase output) ^ 2) =
      (Fintype.card Output : ℝ) * (3 - 2 * fixedPhase) := by
  calc
    (∑ output, (1 - fixedPhase - phase output) ^ 2) =
        ∑ output, (3 - 2 * fixedPhase -
          2 * phase output + 2 * fixedPhase * phase output) := by
      apply Finset.sum_congr rfl
      intro output _
      nlinarith [phaseSquare output, fixedPhaseSquare]
    _ = (Fintype.card Output : ℝ) * (3 - 2 * fixedPhase) := by
      calc
        (∑ output, (3 - 2 * fixedPhase -
            2 * phase output + 2 * fixedPhase * phase output)) =
            (∑ _output : Output, (3 - 2 * fixedPhase)) +
              ∑ output, (-2 + 2 * fixedPhase) * phase output := by
          rw [← Finset.sum_add_distrib]
          apply Finset.sum_congr rfl
          intro output _
          ring
        _ = (Fintype.card Output : ℝ) * (3 - 2 * fixedPhase) := by
          rw [Finset.sum_const, nsmul_eq_mul, ← Finset.mul_sum, phaseSum, mul_zero, add_zero]
          simp

/-- The exact coefficient identity is at most `5 * |Y|` for a binary phase. -/
theorem beta_square_sum_le_five
    {Output : Type*}
    [Fintype Output]
    (phase : Output -> ℝ)
    (fixedPhase : ℝ)
    (phaseSquare : ∀ output, phase output ^ 2 = 1)
    (fixedPhaseSquare : fixedPhase ^ 2 = 1)
    (phaseSum : ∑ output, phase output = 0) :
    (∑ output, (1 - fixedPhase - phase output) ^ 2) <=
      5 * (Fintype.card Output : ℝ) := by
  rw [beta_square_sum phase fixedPhase phaseSquare fixedPhaseSquare phaseSum]
  have fixedLower : -1 <= fixedPhase := by
    nlinarith [sq_nonneg (fixedPhase + 1)]
  have cardNonnegative : (0 : ℝ) <= Fintype.card Output := by positivity
  nlinarith

/-- Every value of a finite additive character has complex norm-square one. -/
theorem addChar_normSq
    {Output : Type*}
    [AddCommGroup Output]
    [Finite Output]
    (phase : AddChar Output ℂ)
    (output : Output) :
    Complex.normSq (phase output) = 1 := by
  calc
    Complex.normSq (phase output) = ‖phase output‖ ^ 2 := by
      symm
      exact Complex.sq_norm (phase output)
    _ = 1 := by
      rw [AddChar.norm_apply phase output]
      norm_num

/-- A nontrivial finite additive character sums to zero. -/
theorem nontrivial_addChar_sum
    {Output : Type*}
    [AddCommGroup Output]
    [Fintype Output]
    (phase : AddChar Output ℂ)
    (nontrivial : phase ≠ 0) :
    ∑ output, phase output = 0 := by
  classical
  rw [AddChar.sum_eq_ite, if_neg nontrivial]

/--
Complex form of the exact CMS Fourier identity.  This is the form used by the compressed phase
oracle, whose phase register is an additive character of the output group.
-/
theorem complex_beta_normSq_sum
    {Output : Type*}
    [Fintype Output]
    (phase : Output -> ℂ)
    (fixedPhase : ℂ)
    (phaseNormSq : ∀ output, Complex.normSq (phase output) = 1)
    (fixedPhaseNormSq : Complex.normSq fixedPhase = 1)
    (phaseSum : ∑ output, phase output = 0) :
    (∑ output, Complex.normSq (1 - fixedPhase - phase output)) =
      (Fintype.card Output : ℝ) * (3 - 2 * fixedPhase.re) := by
  have phaseReSum : ∑ output, (phase output).re = 0 := by
    have mapped := congrArg (fun value : ℂ => Complex.reCLM value) phaseSum
    simpa only [map_sum, Complex.reCLM_apply, map_zero] using mapped
  have phaseImSum : ∑ output, (phase output).im = 0 := by
    have mapped := congrArg (fun value : ℂ => Complex.imCLM value) phaseSum
    simpa only [map_sum, Complex.imCLM_apply, map_zero] using mapped
  calc
    (∑ output, Complex.normSq (1 - fixedPhase - phase output)) =
        ∑ output,
          (3 - 2 * fixedPhase.re - 2 * (phase output).re +
            2 * (fixedPhase.re * (phase output).re +
              fixedPhase.im * (phase output).im)) := by
      apply Finset.sum_congr rfl
      intro output _
      have outputNormSq := phaseNormSq output
      rw [Complex.normSq_apply] at outputNormSq fixedPhaseNormSq ⊢
      simp only [Complex.sub_re, Complex.one_re, Complex.sub_im, Complex.one_im]
      nlinarith [outputNormSq, fixedPhaseNormSq]
    _ = (Fintype.card Output : ℝ) * (3 - 2 * fixedPhase.re) := by
      have pointwise (output : Output) :
          (3 - 2 * fixedPhase.re - 2 * (phase output).re +
              2 * (fixedPhase.re * (phase output).re +
                fixedPhase.im * (phase output).im)) =
            (3 - 2 * fixedPhase.re) +
              (-2 + 2 * fixedPhase.re) * (phase output).re +
              (2 * fixedPhase.im) * (phase output).im := by
        ring
      calc
        (∑ output,
            (3 - 2 * fixedPhase.re - 2 * (phase output).re +
              2 * (fixedPhase.re * (phase output).re +
                fixedPhase.im * (phase output).im))) =
            ∑ output,
              ((3 - 2 * fixedPhase.re) +
                (-2 + 2 * fixedPhase.re) * (phase output).re +
                (2 * fixedPhase.im) * (phase output).im) := by
          apply Finset.sum_congr rfl
          intro output _
          exact pointwise output
        _ = (∑ _output : Output, (3 - 2 * fixedPhase.re)) +
              (-2 + 2 * fixedPhase.re) * ∑ output, (phase output).re +
              (2 * fixedPhase.im) * ∑ output, (phase output).im := by
          rw [Finset.sum_add_distrib, Finset.sum_add_distrib]
          simp_rw [Finset.mul_sum]
        _ = (Fintype.card Output : ℝ) * (3 - 2 * fixedPhase.re) := by
          rw [phaseReSum, phaseImSum, mul_zero, add_zero, Finset.sum_const,
            nsmul_eq_mul]
          simp

/-- The complex Fourier coefficient identity is at most `5 * |Y|`. -/
theorem complex_beta_normSq_sum_le_five
    {Output : Type*}
    [Fintype Output]
    (phase : Output -> ℂ)
    (fixedPhase : ℂ)
    (phaseNormSq : ∀ output, Complex.normSq (phase output) = 1)
    (fixedPhaseNormSq : Complex.normSq fixedPhase = 1)
    (phaseSum : ∑ output, phase output = 0) :
    (∑ output, Complex.normSq (1 - fixedPhase - phase output)) <=
      5 * (Fintype.card Output : ℝ) := by
  rw [complex_beta_normSq_sum phase fixedPhase phaseNormSq fixedPhaseNormSq phaseSum]
  have fixedRealLower : -1 <= fixedPhase.re := by
    rw [Complex.normSq_apply] at fixedPhaseNormSq
    nlinarith [sq_nonneg (fixedPhase.re + 1), sq_nonneg fixedPhase.im]
  have cardNonnegative : (0 : ℝ) <= Fintype.card Output := by positivity
  nlinarith

/-- Four orthogonal source-mass classes from CMS Section 5.3. -/
structure SourceMasses where
  s1 : ℝ
  s2 : ℝ
  s3 : ℝ
  s4 : ℝ
  s1_nonnegative : 0 <= s1
  s2_nonnegative : 0 <= s2
  s3_nonnegative : 0 <= s3
  s4_nonnegative : 0 <= s4
  normalized : s1 + s2 + s3 + s4 <= 1

/--
Squared norms of the four orthogonal projected components in the CMS proof.

The concrete compressed-oracle module constructs these bounds from the query kernel.  Keeping the
four names here makes the coefficient accounting reviewable and prevents a hidden asymptotic
constant from replacing the published `6`.
-/
structure ProjectedComponentBounds (mass : SourceMasses) where
  backwardFlip : ℝ
  forwardFlip : ℝ
  instability : ℝ
  psi4 : ℝ
  xi1 : ℝ
  xi2 : ℝ
  xi3 : ℝ
  backward_nonnegative : 0 <= backwardFlip
  forward_nonnegative : 0 <= forwardFlip
  instability_nonnegative : 0 <= instability
  backward_le_instability : backwardFlip <= instability
  forward_le_instability : forwardFlip <= instability
  psi4_nonnegative : 0 <= psi4
  xi1_nonnegative : 0 <= xi1
  xi2_nonnegative : 0 <= xi2
  xi3_nonnegative : 0 <= xi3
  psi4_le : psi4 <= backwardFlip * mass.s1
  xi1_le : xi1 <= forwardFlip * mass.s2
  xi2_le : xi2 <= 5 * backwardFlip * mass.s1
  xi3_le : xi3 <= 6 * forwardFlip * (mass.s3 + mass.s4)

/--
Exact end of CMS Lemma 5.10: the projected one-query squared norm is at most six times
the classical instability.
-/
theorem projected_component_sum_le_six_instability
    (mass : SourceMasses)
    (bounds : ProjectedComponentBounds mass) :
    bounds.psi4 + bounds.xi1 + bounds.xi2 + bounds.xi3 <=
      6 * bounds.instability := by
  have s1Bound :
      bounds.psi4 + bounds.xi2 <=
        6 * bounds.instability * mass.s1 := by
    calc
      bounds.psi4 + bounds.xi2 <=
          bounds.backwardFlip * mass.s1 +
            5 * bounds.backwardFlip * mass.s1 :=
        add_le_add bounds.psi4_le bounds.xi2_le
      _ = 6 * bounds.backwardFlip * mass.s1 := by ring
      _ <= 6 * bounds.instability * mass.s1 := by
        exact mul_le_mul_of_nonneg_right
          (mul_le_mul_of_nonneg_left bounds.backward_le_instability (by norm_num))
          mass.s1_nonnegative
  have s2Bound :
      bounds.xi1 <= 6 * bounds.instability * mass.s2 := by
    calc
      bounds.xi1 <= bounds.forwardFlip * mass.s2 := bounds.xi1_le
      _ <= bounds.instability * mass.s2 :=
        mul_le_mul_of_nonneg_right bounds.forward_le_instability mass.s2_nonnegative
      _ <= 6 * bounds.instability * mass.s2 := by
        have nonnegative : 0 <= bounds.instability * mass.s2 :=
          mul_nonneg bounds.instability_nonnegative mass.s2_nonnegative
        nlinarith
  have s34Bound :
      bounds.xi3 <=
        6 * bounds.instability * (mass.s3 + mass.s4) := by
    exact bounds.xi3_le.trans
      (mul_le_mul_of_nonneg_right
        (mul_le_mul_of_nonneg_left bounds.forward_le_instability (by norm_num))
        (add_nonneg mass.s3_nonnegative mass.s4_nonnegative))
  calc
    bounds.psi4 + bounds.xi1 + bounds.xi2 + bounds.xi3 =
        (bounds.psi4 + bounds.xi2) + bounds.xi1 + bounds.xi3 := by ring
    _ <=
        6 * bounds.instability * mass.s1 +
          6 * bounds.instability * mass.s2 +
          6 * bounds.instability * (mass.s3 + mass.s4) :=
      add_le_add (add_le_add s1Bound s2Bound) s34Bound
    _ = 6 * bounds.instability *
        (mass.s1 + mass.s2 + mass.s3 + mass.s4) := by ring
    _ <= 6 * bounds.instability * 1 := by
      exact mul_le_mul_of_nonneg_left mass.normalized
        (mul_nonneg (by norm_num) bounds.instability_nonnegative)
    _ = 6 * bounds.instability := by ring

end HegemonCrypto.CmsLocalOperator
