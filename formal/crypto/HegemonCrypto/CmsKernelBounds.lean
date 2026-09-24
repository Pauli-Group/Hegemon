import HegemonCrypto.CmsCompressedOracle
import Mathlib.Algebra.Order.BigOperators.Ring.Finset
import Mathlib.Tactic.Linarith

/-!
# Concrete bounds for the CMS compressed-oracle kernel

This module proves the finite Fourier and database-counting inequalities used to connect the exact
kernel in `CmsCompressedOracle` to the scalar local-operator theorem.  Every denominator is the
actual finite output cardinality.
-/

namespace HegemonCrypto.CmsKernelBounds

open scoped BigOperators
open HegemonCrypto.FiniteOracleDatabase
open HegemonCrypto.CmsClassicalDatabase
open HegemonCrypto.CmsCompressedOracle
open HegemonCrypto.CmsLocalOperator

noncomputable section

variable {Input Output Phase : Type*}
variable [Fintype Input] [DecidableEq Input]
variable [Fintype Output] [DecidableEq Output] [AddCommGroup Output]
variable [Fintype Phase] [DecidableEq Phase]

omit [DecidableEq Output] in
theorem output_card_real_positive :
    (0 : ℝ) < Fintype.card Output := by
  exact_mod_cast Fintype.card_pos

omit [DecidableEq Output] in
/-- The exact squared amplitude of `1 / sqrt |Y|`. -/
theorem normSq_inverseSqrtOutputCard :
    Complex.normSq (inverseSqrtOutputCard (Output := Output)) =
      1 / (Fintype.card Output : ℝ) := by
  have cardNonnegative : (0 : ℝ) <= Fintype.card Output :=
    (output_card_real_positive (Output := Output)).le
  have sqrtSquare :
      Real.sqrt (Fintype.card Output : ℝ) *
          Real.sqrt (Fintype.card Output : ℝ) =
        Fintype.card Output := by
    rw [← pow_two]
    exact Real.sq_sqrt cardNonnegative
  unfold inverseSqrtOutputCard
  rw [Complex.normSq_inv, Complex.normSq_ofReal, sqrtSquare]
  simp [div_eq_mul_inv]

omit [DecidableEq Output] [AddCommGroup Output] in
/-- The exact squared amplitude of `1 / |Y|`. -/
theorem normSq_inverseOutputCard :
    Complex.normSq (inverseOutputCard (Output := Output)) =
      1 / (Fintype.card Output : ℝ) ^ 2 := by
  unfold inverseOutputCard
  rw [Complex.normSq_inv, Complex.normSq_ofReal]
  simp [pow_two, one_div]

omit [DecidableEq Output] in
/--
Finite Fourier Cauchy--Schwarz with the exact `1 / |Y|` normalization.  Unit-norm phases do not
change source mass.
-/
theorem normalized_phase_sum_bound
    {Index : Type*}
    [DecidableEq Index]
    (indices : Finset Index)
    (coefficient : Index -> ℂ)
    (phase : Index -> ℂ)
    (phaseNormSq : ∀ index, Complex.normSq (phase index) = 1) :
    Complex.normSq
        (inverseSqrtOutputCard (Output := Output) *
          ∑ index ∈ indices, coefficient index * phase index) <=
      ((indices.card : ℝ) / Fintype.card Output) *
        ∑ index ∈ indices, Complex.normSq (coefficient index) := by
  have cardPositive := output_card_real_positive (Output := Output)
  have sumBound :=
    normSq_sum_le_card_mul_sum_normSq indices
      (fun index => coefficient index * phase index)
  rw [Complex.normSq_mul, normSq_inverseSqrtOutputCard]
  calc
    (1 / (Fintype.card Output : ℝ)) *
        Complex.normSq
          (∑ index ∈ indices, coefficient index * phase index) <=
        (1 / (Fintype.card Output : ℝ)) *
          (indices.card *
            ∑ index ∈ indices,
              Complex.normSq (coefficient index * phase index)) := by
      exact mul_le_mul_of_nonneg_left sumBound (by positivity)
    _ = ((indices.card : ℝ) / Fintype.card Output) *
          ∑ index ∈ indices, Complex.normSq (coefficient index) := by
      simp_rw [Complex.normSq_mul, phaseNormSq, mul_one]
      field_simp

/-- Finite complex Cauchy--Schwarz for a sum of pointwise products. -/
theorem normSq_sum_mul_le_sum_normSq_mul_sum_normSq
    {Index : Type*}
    [DecidableEq Index]
    (indices : Finset Index)
    (left right : Index -> ℂ) :
    Complex.normSq
        (∑ index ∈ indices, left index * right index) <=
      (∑ index ∈ indices, Complex.normSq (left index)) *
        ∑ index ∈ indices, Complex.normSq (right index) := by
  have normBound :
      ‖∑ index ∈ indices, left index * right index‖ <=
        ∑ index ∈ indices, ‖left index * right index‖ :=
    norm_sum_le _ _
  have squaredNormBound :
      ‖∑ index ∈ indices, left index * right index‖ ^ 2 <=
        (∑ index ∈ indices, ‖left index * right index‖) ^ 2 := by
    exact (sq_le_sq₀ (norm_nonneg _) (by positivity)).2 normBound
  calc
    Complex.normSq
        (∑ index ∈ indices, left index * right index) =
        ‖∑ index ∈ indices, left index * right index‖ ^ 2 := by
      rw [Complex.sq_norm]
    _ <= (∑ index ∈ indices, ‖left index * right index‖) ^ 2 :=
      squaredNormBound
    _ = (∑ index ∈ indices, ‖left index‖ * ‖right index‖) ^ 2 := by
      simp_rw [norm_mul]
    _ <= (∑ index ∈ indices, ‖left index‖ ^ 2) *
          ∑ index ∈ indices, ‖right index‖ ^ 2 :=
      Finset.sum_mul_sq_le_sq_mul_sq indices
        (fun index => ‖left index‖)
        (fun index => ‖right index‖)
    _ = (∑ index ∈ indices, Complex.normSq (left index)) *
          ∑ index ∈ indices, Complex.normSq (right index) := by
      simp_rw [Complex.sq_norm]

/-- Outputs whose insertion into one absent slot produces a database with `property`. -/
def insertionAnswers
    (property : Property Input Output)
    (database : Database Input Output)
    (input : Input) : Finset Output := by
  classical
  exact Finset.univ.filter fun output => property (insert database input output)

omit [Fintype Input] [DecidableEq Output] [AddCommGroup Output] in
theorem insertion_answers_eq_successful_answers_of_absent
    (property : Property Input Output)
    (database : Database Input Output)
    (input : Input)
    (absent : database input = none) :
    insertionAnswers property database input =
      successfulAnswers property database input := by
  classical
  ext output
  simp [insertionAnswers, successfulAnswers, query_of_absent absent]

omit [DecidableEq Output] [AddCommGroup Output] in
/-- A real flip bound is exactly a cardinality bound on valid insertion answers. -/
theorem insertion_answer_ratio_le_of_flip
    {source target : Property Input Output}
    {queryBound : Nat}
    {bound : ℝ}
    (flip : RealFlipBound source target queryBound bound)
    (database : Database Input Output)
    (sourceMembership : source database)
    (sizeBound : size database < queryBound)
    (input : Input)
    (absent : database input = none) :
    ((insertionAnswers target database input).card : ℝ) /
        Fintype.card Output <= bound := by
  rw [insertion_answers_eq_successful_answers_of_absent
    target database input absent]
  exact flip.2 database sourceMembership sizeBound input

omit [Fintype Phase] [DecidableEq Phase] in
/--
The Fourier erasure component (`Psi_4` in CMS Section 5.3) is bounded by one directional
database flip probability times its source mass.
-/
theorem erasure_component_bound
    (system : PhaseSystem Output Phase)
    (phaseValue : Phase)
    (indices : Finset Output)
    (coefficient : Output -> ℂ)
    {bound sourceMass : ℝ}
    (indexRatio : (indices.card : ℝ) / Fintype.card Output <= bound)
    (sourceMassBound :
      ∑ output ∈ indices, Complex.normSq (coefficient output) <= sourceMass)
    (boundNonnegative : 0 <= bound) :
    Complex.normSq
        (inverseSqrtOutputCard (Output := Output) *
          ∑ output ∈ indices,
            coefficient output * system.character phaseValue output) <=
      bound * sourceMass := by
  have phaseNorm :
      ∀ output, Complex.normSq (system.character phaseValue output) = 1 :=
    fun output => addChar_normSq (system.character phaseValue) output
  calc
    Complex.normSq
        (inverseSqrtOutputCard (Output := Output) *
          ∑ output ∈ indices,
            coefficient output * system.character phaseValue output) <=
        ((indices.card : ℝ) / Fintype.card Output) *
          ∑ output ∈ indices, Complex.normSq (coefficient output) :=
      normalized_phase_sum_bound indices coefficient
        (fun output => system.character phaseValue output) phaseNorm
    _ <= bound *
          ∑ output ∈ indices, Complex.normSq (coefficient output) := by
      exact mul_le_mul_of_nonneg_right indexRatio
        (Finset.sum_nonneg fun output _ =>
          Complex.normSq_nonneg (coefficient output))
    _ <= bound * sourceMass :=
      mul_le_mul_of_nonneg_left sourceMassBound boundNonnegative

omit [DecidableEq Output] [Fintype Phase] [DecidableEq Phase] in
/-- Exact norm of one fresh-input Fourier component restricted to selected outputs. -/
theorem insertion_component_norm
    (system : PhaseSystem Output Phase)
    (phaseValue : Phase)
    (indices : Finset Output)
    (coefficient : ℂ) :
    (∑ output ∈ indices,
      Complex.normSq
        (inverseSqrtOutputCard (Output := Output) *
          (system.character phaseValue output * coefficient))) =
      ((indices.card : ℝ) / Fintype.card Output) *
        Complex.normSq coefficient := by
  simp_rw [Complex.normSq_mul, normSq_inverseSqrtOutputCard,
    addChar_normSq, one_mul]
  rw [Finset.sum_const, nsmul_eq_mul]
  ring

omit [DecidableEq Output] [Fintype Phase] [DecidableEq Phase] in
/-- A directional flip ratio bounds one fresh-input Fourier component. -/
theorem insertion_component_bound
    (system : PhaseSystem Output Phase)
    (phaseValue : Phase)
    (indices : Finset Output)
    (coefficient : ℂ)
    {bound : ℝ}
    (indexRatio : (indices.card : ℝ) / Fintype.card Output <= bound) :
    (∑ output ∈ indices,
      Complex.normSq
        (inverseSqrtOutputCard (Output := Output) *
          (system.character phaseValue output * coefficient))) <=
      bound * Complex.normSq coefficient := by
  rw [insertion_component_norm system phaseValue indices coefficient]
  exact mul_le_mul_of_nonneg_right indexRatio
    (Complex.normSq_nonneg coefficient)

omit [Fintype Phase] [DecidableEq Phase] in
/--
For one nonzero phase, the recorded-entry replacement term has the exact CMS coefficient `5`.
This is the `Xi_2` Fourier estimate before the database flip ratio is applied.
-/
theorem replacement_component_five_bound
    (system : PhaseSystem Output Phase)
    (phaseValue : Phase)
    (nonzeroPhase : phaseValue ≠ system.zeroPhase)
    (sourceOutputs targetOutputs : Finset Output)
    (coefficient : Output -> ℂ) :
    (∑ targetOutput ∈ targetOutputs,
      Complex.normSq
        (inverseOutputCard (Output := Output) *
          ∑ sourceOutput ∈ sourceOutputs,
            coefficient sourceOutput *
              (1 - system.character phaseValue sourceOutput -
                system.character phaseValue targetOutput))) <=
      5 * ((sourceOutputs.card : ℝ) / Fintype.card Output) *
        ∑ sourceOutput ∈ sourceOutputs,
          Complex.normSq (coefficient sourceOutput) := by
  have cardPositive := output_card_real_positive (Output := Output)
  have phaseNontrivial :
      system.character phaseValue ≠ 0 :=
    system.character_nonzero phaseValue nonzeroPhase
  have phaseSum :
      ∑ output, system.character phaseValue output = 0 :=
    nontrivial_addChar_sum (system.character phaseValue) phaseNontrivial
  have betaFullBound (sourceOutput : Output) :
      (∑ targetOutput : Output,
        Complex.normSq
          (1 - system.character phaseValue sourceOutput -
            system.character phaseValue targetOutput)) <=
        5 * (Fintype.card Output : ℝ) := by
    exact complex_beta_normSq_sum_le_five
      (fun output => system.character phaseValue output)
      (system.character phaseValue sourceOutput)
      (fun output => addChar_normSq (system.character phaseValue) output)
      (addChar_normSq (system.character phaseValue) sourceOutput)
      phaseSum
  have betaSubsetBound (sourceOutput : Output) :
      (∑ targetOutput ∈ targetOutputs,
        Complex.normSq
          (1 - system.character phaseValue sourceOutput -
            system.character phaseValue targetOutput)) <=
        5 * (Fintype.card Output : ℝ) := by
    calc
      (∑ targetOutput ∈ targetOutputs,
        Complex.normSq
          (1 - system.character phaseValue sourceOutput -
            system.character phaseValue targetOutput)) <=
          ∑ targetOutput : Output,
            Complex.normSq
              (1 - system.character phaseValue sourceOutput -
                system.character phaseValue targetOutput) := by
        exact Finset.sum_le_sum_of_subset_of_nonneg
          (Finset.subset_univ targetOutputs)
          (fun output _ _ => Complex.normSq_nonneg _)
      _ <= 5 * (Fintype.card Output : ℝ) := betaFullBound sourceOutput
  have pointwiseBound (targetOutput : Output) :
      Complex.normSq
          (inverseOutputCard (Output := Output) *
            ∑ sourceOutput ∈ sourceOutputs,
              coefficient sourceOutput *
                (1 - system.character phaseValue sourceOutput -
                  system.character phaseValue targetOutput)) <=
        (1 / (Fintype.card Output : ℝ) ^ 2) *
          (sourceOutputs.card *
            ∑ sourceOutput ∈ sourceOutputs,
              Complex.normSq
                (coefficient sourceOutput *
                  (1 - system.character phaseValue sourceOutput -
                    system.character phaseValue targetOutput))) := by
    rw [Complex.normSq_mul, normSq_inverseOutputCard]
    exact mul_le_mul_of_nonneg_left
      (normSq_sum_le_card_mul_sum_normSq sourceOutputs
        (fun sourceOutput =>
          coefficient sourceOutput *
            (1 - system.character phaseValue sourceOutput -
              system.character phaseValue targetOutput)))
      (by positivity)
  calc
    (∑ targetOutput ∈ targetOutputs,
      Complex.normSq
        (inverseOutputCard (Output := Output) *
          ∑ sourceOutput ∈ sourceOutputs,
            coefficient sourceOutput *
              (1 - system.character phaseValue sourceOutput -
                system.character phaseValue targetOutput))) <=
        ∑ targetOutput ∈ targetOutputs,
          (1 / (Fintype.card Output : ℝ) ^ 2) *
            (sourceOutputs.card *
              ∑ sourceOutput ∈ sourceOutputs,
                Complex.normSq
                  (coefficient sourceOutput *
                    (1 - system.character phaseValue sourceOutput -
                      system.character phaseValue targetOutput))) := by
      exact Finset.sum_le_sum fun targetOutput _ => pointwiseBound targetOutput
    _ = ((sourceOutputs.card : ℝ) /
          (Fintype.card Output : ℝ) ^ 2) *
        ∑ sourceOutput ∈ sourceOutputs,
          Complex.normSq (coefficient sourceOutput) *
            (∑ targetOutput ∈ targetOutputs,
              Complex.normSq
                (1 - system.character phaseValue sourceOutput -
                  system.character phaseValue targetOutput)) := by
      simp_rw [Complex.normSq_mul]
      calc
        (∑ targetOutput ∈ targetOutputs,
          (1 / (Fintype.card Output : ℝ) ^ 2) *
            (sourceOutputs.card *
              ∑ sourceOutput ∈ sourceOutputs,
                Complex.normSq (coefficient sourceOutput) *
                  Complex.normSq
                    (1 - system.character phaseValue sourceOutput -
                      system.character phaseValue targetOutput))) =
            ((sourceOutputs.card : ℝ) /
              (Fintype.card Output : ℝ) ^ 2) *
              ∑ targetOutput ∈ targetOutputs,
                ∑ sourceOutput ∈ sourceOutputs,
                  Complex.normSq (coefficient sourceOutput) *
                    Complex.normSq
                      (1 - system.character phaseValue sourceOutput -
                        system.character phaseValue targetOutput) := by
          rw [Finset.mul_sum]
          apply Finset.sum_congr rfl
          intro targetOutput _
          ring
        _ = ((sourceOutputs.card : ℝ) /
              (Fintype.card Output : ℝ) ^ 2) *
              ∑ sourceOutput ∈ sourceOutputs,
                ∑ targetOutput ∈ targetOutputs,
                  Complex.normSq (coefficient sourceOutput) *
                    Complex.normSq
                      (1 - system.character phaseValue sourceOutput -
                        system.character phaseValue targetOutput) := by
          rw [Finset.sum_comm]
        _ = ((sourceOutputs.card : ℝ) /
              (Fintype.card Output : ℝ) ^ 2) *
            ∑ sourceOutput ∈ sourceOutputs,
              Complex.normSq (coefficient sourceOutput) *
                (∑ targetOutput ∈ targetOutputs,
                  Complex.normSq
                    (1 - system.character phaseValue sourceOutput -
                      system.character phaseValue targetOutput)) := by
          congr 1
          apply Finset.sum_congr rfl
          intro sourceOutput _
          rw [Finset.mul_sum]
    _ <= ((sourceOutputs.card : ℝ) /
          (Fintype.card Output : ℝ) ^ 2) *
        ∑ sourceOutput ∈ sourceOutputs,
          Complex.normSq (coefficient sourceOutput) *
            (5 * (Fintype.card Output : ℝ)) := by
      apply mul_le_mul_of_nonneg_left
      · exact Finset.sum_le_sum fun sourceOutput _ =>
          mul_le_mul_of_nonneg_left
            (betaSubsetBound sourceOutput)
            (Complex.normSq_nonneg (coefficient sourceOutput))
      · positivity
    _ = 5 * ((sourceOutputs.card : ℝ) / Fintype.card Output) *
        ∑ sourceOutput ∈ sourceOutputs,
          Complex.normSq (coefficient sourceOutput) := by
      have weightedMass :
          (∑ sourceOutput ∈ sourceOutputs,
            Complex.normSq (coefficient sourceOutput) *
              (5 * (Fintype.card Output : ℝ))) =
            (5 * (Fintype.card Output : ℝ)) *
              ∑ sourceOutput ∈ sourceOutputs,
                Complex.normSq (coefficient sourceOutput) := by
        rw [Finset.mul_sum]
        apply Finset.sum_congr rfl
        intro sourceOutput _
        ring
      rw [weightedMass]
      field_simp

omit [Fintype Phase] [DecidableEq Phase] in
/--
Symmetric replacement estimate controlled by the target-output ratio.  CMS uses this form for
`Xi_3`; the source-ratio form above is used for `Xi_2`.
-/
theorem replacement_component_five_target_bound
    (system : PhaseSystem Output Phase)
    (phaseValue : Phase)
    (nonzeroPhase : phaseValue ≠ system.zeroPhase)
    (sourceOutputs targetOutputs : Finset Output)
    (coefficient : Output -> ℂ) :
    (∑ targetOutput ∈ targetOutputs,
      Complex.normSq
        (inverseOutputCard (Output := Output) *
          ∑ sourceOutput ∈ sourceOutputs,
            coefficient sourceOutput *
              (1 - system.character phaseValue sourceOutput -
                system.character phaseValue targetOutput))) <=
      5 * ((targetOutputs.card : ℝ) / Fintype.card Output) *
        ∑ sourceOutput ∈ sourceOutputs,
          Complex.normSq (coefficient sourceOutput) := by
  have cardPositive := output_card_real_positive (Output := Output)
  have phaseNontrivial :
      system.character phaseValue ≠ 0 :=
    system.character_nonzero phaseValue nonzeroPhase
  have phaseSum :
      ∑ output, system.character phaseValue output = 0 :=
    nontrivial_addChar_sum (system.character phaseValue) phaseNontrivial
  have betaSourceBound (targetOutput : Output) :
      (∑ sourceOutput ∈ sourceOutputs,
        Complex.normSq
          (1 - system.character phaseValue sourceOutput -
            system.character phaseValue targetOutput)) <=
        5 * (Fintype.card Output : ℝ) := by
    calc
      (∑ sourceOutput ∈ sourceOutputs,
        Complex.normSq
          (1 - system.character phaseValue sourceOutput -
            system.character phaseValue targetOutput)) <=
          ∑ sourceOutput : Output,
            Complex.normSq
              (1 - system.character phaseValue sourceOutput -
                system.character phaseValue targetOutput) := by
        exact Finset.sum_le_sum_of_subset_of_nonneg
          (Finset.subset_univ sourceOutputs)
          (fun sourceOutput _ _ =>
            Complex.normSq_nonneg
              (1 - system.character phaseValue sourceOutput -
                system.character phaseValue targetOutput))
      _ = ∑ sourceOutput : Output,
            Complex.normSq
              (1 - system.character phaseValue targetOutput -
                system.character phaseValue sourceOutput) := by
        apply Finset.sum_congr rfl
        intro sourceOutput _
        congr 1
        ring
      _ <= 5 * (Fintype.card Output : ℝ) := by
        exact complex_beta_normSq_sum_le_five
          (fun output => system.character phaseValue output)
          (system.character phaseValue targetOutput)
          (fun output => addChar_normSq (system.character phaseValue) output)
          (addChar_normSq (system.character phaseValue) targetOutput)
          phaseSum
  have sourceMassNonnegative :
      0 <= ∑ sourceOutput ∈ sourceOutputs,
        Complex.normSq (coefficient sourceOutput) :=
    Finset.sum_nonneg fun sourceOutput _ => Complex.normSq_nonneg _
  have pointwiseBound (targetOutput : Output) :
      Complex.normSq
          (inverseOutputCard (Output := Output) *
            ∑ sourceOutput ∈ sourceOutputs,
              coefficient sourceOutput *
                (1 - system.character phaseValue sourceOutput -
                  system.character phaseValue targetOutput)) <=
        (5 / (Fintype.card Output : ℝ)) *
          ∑ sourceOutput ∈ sourceOutputs,
            Complex.normSq (coefficient sourceOutput) := by
    calc
      Complex.normSq
          (inverseOutputCard (Output := Output) *
            ∑ sourceOutput ∈ sourceOutputs,
              coefficient sourceOutput *
                (1 - system.character phaseValue sourceOutput -
                  system.character phaseValue targetOutput)) =
          (1 / (Fintype.card Output : ℝ) ^ 2) *
            Complex.normSq
              (∑ sourceOutput ∈ sourceOutputs,
                coefficient sourceOutput *
                  (1 - system.character phaseValue sourceOutput -
                    system.character phaseValue targetOutput)) := by
        rw [Complex.normSq_mul, normSq_inverseOutputCard]
      _ <= (1 / (Fintype.card Output : ℝ) ^ 2) *
            ((∑ sourceOutput ∈ sourceOutputs,
                Complex.normSq (coefficient sourceOutput)) *
              ∑ sourceOutput ∈ sourceOutputs,
                Complex.normSq
                  (1 - system.character phaseValue sourceOutput -
                    system.character phaseValue targetOutput)) := by
        exact mul_le_mul_of_nonneg_left
          (normSq_sum_mul_le_sum_normSq_mul_sum_normSq
            sourceOutputs coefficient
            (fun sourceOutput =>
              1 - system.character phaseValue sourceOutput -
                system.character phaseValue targetOutput))
          (by positivity)
      _ <= (1 / (Fintype.card Output : ℝ) ^ 2) *
            ((∑ sourceOutput ∈ sourceOutputs,
                Complex.normSq (coefficient sourceOutput)) *
              (5 * (Fintype.card Output : ℝ))) := by
        apply mul_le_mul_of_nonneg_left
        · exact mul_le_mul_of_nonneg_left
            (betaSourceBound targetOutput) sourceMassNonnegative
        · positivity
      _ = (5 / (Fintype.card Output : ℝ)) *
            ∑ sourceOutput ∈ sourceOutputs,
              Complex.normSq (coefficient sourceOutput) := by
        field_simp
  calc
    (∑ targetOutput ∈ targetOutputs,
      Complex.normSq
        (inverseOutputCard (Output := Output) *
          ∑ sourceOutput ∈ sourceOutputs,
            coefficient sourceOutput *
              (1 - system.character phaseValue sourceOutput -
                system.character phaseValue targetOutput))) <=
        ∑ targetOutput ∈ targetOutputs,
          (5 / (Fintype.card Output : ℝ)) *
            ∑ sourceOutput ∈ sourceOutputs,
              Complex.normSq (coefficient sourceOutput) := by
      exact Finset.sum_le_sum fun targetOutput _ => pointwiseBound targetOutput
    _ = 5 * ((targetOutputs.card : ℝ) / Fintype.card Output) *
        ∑ sourceOutput ∈ sourceOutputs,
          Complex.normSq (coefficient sourceOutput) := by
      rw [Finset.sum_const, nsmul_eq_mul]
      ring

omit [Fintype Phase] [DecidableEq Phase] in
/-- Applying a directional flip ratio turns the replacement coefficient into `5 * bound`. -/
theorem replacement_component_bound
    (system : PhaseSystem Output Phase)
    (phaseValue : Phase)
    (nonzeroPhase : phaseValue ≠ system.zeroPhase)
    (sourceOutputs targetOutputs : Finset Output)
    (coefficient : Output -> ℂ)
    {bound sourceMass : ℝ}
    (sourceRatio : (sourceOutputs.card : ℝ) / Fintype.card Output <= bound)
    (sourceMassBound :
      ∑ sourceOutput ∈ sourceOutputs,
        Complex.normSq (coefficient sourceOutput) <= sourceMass)
    (boundNonnegative : 0 <= bound) :
    (∑ targetOutput ∈ targetOutputs,
      Complex.normSq
        (inverseOutputCard (Output := Output) *
          ∑ sourceOutput ∈ sourceOutputs,
            coefficient sourceOutput *
              (1 - system.character phaseValue sourceOutput -
                system.character phaseValue targetOutput))) <=
      5 * bound * sourceMass := by
  calc
    (∑ targetOutput ∈ targetOutputs,
      Complex.normSq
        (inverseOutputCard (Output := Output) *
          ∑ sourceOutput ∈ sourceOutputs,
            coefficient sourceOutput *
              (1 - system.character phaseValue sourceOutput -
                system.character phaseValue targetOutput))) <=
        5 * ((sourceOutputs.card : ℝ) / Fintype.card Output) *
          ∑ sourceOutput ∈ sourceOutputs,
            Complex.normSq (coefficient sourceOutput) :=
      replacement_component_five_bound
        system phaseValue nonzeroPhase sourceOutputs targetOutputs coefficient
    _ <= 5 * bound *
          ∑ sourceOutput ∈ sourceOutputs,
            Complex.normSq (coefficient sourceOutput) := by
      have massNonnegative :
          0 <= ∑ sourceOutput ∈ sourceOutputs,
            Complex.normSq (coefficient sourceOutput) :=
        Finset.sum_nonneg fun sourceOutput _ => Complex.normSq_nonneg _
      nlinarith
    _ <= 5 * bound * sourceMass := by
      exact mul_le_mul_of_nonneg_left sourceMassBound
        (mul_nonneg (by norm_num) boundNonnegative)

omit [Fintype Phase] [DecidableEq Phase] in
/-- Target-ratio form after applying a directional flip bound. -/
theorem replacement_component_target_bound
    (system : PhaseSystem Output Phase)
    (phaseValue : Phase)
    (nonzeroPhase : phaseValue ≠ system.zeroPhase)
    (sourceOutputs targetOutputs : Finset Output)
    (coefficient : Output -> ℂ)
    {bound sourceMass : ℝ}
    (targetRatio : (targetOutputs.card : ℝ) / Fintype.card Output <= bound)
    (sourceMassBound :
      ∑ sourceOutput ∈ sourceOutputs,
        Complex.normSq (coefficient sourceOutput) <= sourceMass)
    (boundNonnegative : 0 <= bound) :
    (∑ targetOutput ∈ targetOutputs,
      Complex.normSq
        (inverseOutputCard (Output := Output) *
          ∑ sourceOutput ∈ sourceOutputs,
            coefficient sourceOutput *
              (1 - system.character phaseValue sourceOutput -
                system.character phaseValue targetOutput))) <=
      5 * bound * sourceMass := by
  calc
    (∑ targetOutput ∈ targetOutputs,
      Complex.normSq
        (inverseOutputCard (Output := Output) *
          ∑ sourceOutput ∈ sourceOutputs,
            coefficient sourceOutput *
              (1 - system.character phaseValue sourceOutput -
                system.character phaseValue targetOutput))) <=
        5 * ((targetOutputs.card : ℝ) / Fintype.card Output) *
          ∑ sourceOutput ∈ sourceOutputs,
            Complex.normSq (coefficient sourceOutput) :=
      replacement_component_five_target_bound
        system phaseValue nonzeroPhase sourceOutputs targetOutputs coefficient
    _ <= 5 * bound *
          ∑ sourceOutput ∈ sourceOutputs,
            Complex.normSq (coefficient sourceOutput) := by
      have massNonnegative :
          0 <= ∑ sourceOutput ∈ sourceOutputs,
            Complex.normSq (coefficient sourceOutput) :=
        Finset.sum_nonneg fun sourceOutput _ => Complex.normSq_nonneg _
      nlinarith
    _ <= 5 * bound * sourceMass := by
      exact mul_le_mul_of_nonneg_left sourceMassBound
        (mul_nonneg (by norm_num) boundNonnegative)

/--
A weighted triangle inequality tuned to the CMS direct/replacement split.

The coefficients are chosen so a direct component bounded by `bound * s3` and a replacement
component bounded by `5 * bound * s4` combine to at most `6 * bound * (s3 + s4)`.
-/
theorem normSq_add_le_six_and_six_fifths
    (direct replacement : ℂ) :
    Complex.normSq (direct + replacement) <=
      6 * Complex.normSq direct +
        (6 / 5 : ℝ) * Complex.normSq replacement := by
  have triangle := norm_add_le direct replacement
  have directNormNonnegative : 0 <= ‖direct‖ := norm_nonneg direct
  have replacementNormNonnegative : 0 <= ‖replacement‖ := norm_nonneg replacement
  have sumNormNonnegative : 0 <= ‖direct + replacement‖ :=
    norm_nonneg (direct + replacement)
  have squaredTriangle :
      ‖direct + replacement‖ ^ 2 <=
        (‖direct‖ + ‖replacement‖) ^ 2 := by
    nlinarith
  have weightedYoung :
      (‖direct‖ + ‖replacement‖) ^ 2 <=
        6 * ‖direct‖ ^ 2 + (6 / 5 : ℝ) * ‖replacement‖ ^ 2 := by
    nlinarith [sq_nonneg (5 * ‖direct‖ - ‖replacement‖)]
  rw [Complex.sq_norm] at squaredTriangle
  rw [Complex.sq_norm, Complex.sq_norm] at weightedYoung
  exact squaredTriangle.trans weightedYoung

/-- The CMS `Xi_3` direct and replacement pieces combine with coefficient exactly `6`. -/
theorem combined_component_six_bound
    {Index : Type*}
    [DecidableEq Index]
    (indices : Finset Index)
    (direct replacement : Index -> ℂ)
    {bound directMass replacementMass : ℝ}
    (directBound :
      ∑ index ∈ indices, Complex.normSq (direct index) <=
        bound * directMass)
    (replacementBound :
      ∑ index ∈ indices, Complex.normSq (replacement index) <=
        5 * bound * replacementMass) :
    (∑ index ∈ indices,
      Complex.normSq (direct index + replacement index)) <=
      6 * bound * (directMass + replacementMass) := by
  calc
    (∑ index ∈ indices,
      Complex.normSq (direct index + replacement index)) <=
        ∑ index ∈ indices,
          (6 * Complex.normSq (direct index) +
            (6 / 5 : ℝ) * Complex.normSq (replacement index)) := by
      exact Finset.sum_le_sum fun index _ =>
        normSq_add_le_six_and_six_fifths (direct index) (replacement index)
    _ = 6 * (∑ index ∈ indices, Complex.normSq (direct index)) +
          (6 / 5 : ℝ) *
            (∑ index ∈ indices, Complex.normSq (replacement index)) := by
      rw [Finset.sum_add_distrib, Finset.mul_sum, Finset.mul_sum]
    _ <= 6 * (bound * directMass) +
          (6 / 5 : ℝ) * (5 * bound * replacementMass) := by
      exact add_le_add
        (mul_le_mul_of_nonneg_left directBound (by norm_num))
        (mul_le_mul_of_nonneg_left replacementBound (by norm_num))
    _ = 6 * bound * (directMass + replacementMass) := by ring

end

end HegemonCrypto.CmsKernelBounds
