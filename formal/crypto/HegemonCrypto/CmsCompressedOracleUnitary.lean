import HegemonCrypto.CmsFullOperatorProof
import Mathlib.Analysis.InnerProductSpace.PiL2
import Mathlib.Analysis.InnerProductSpace.Projection.Reflection

/-!
# Unitarity of the finite CMS compressed oracle

The explicit three-case kernel in `CmsCompressedOracle` is factored as `Dec · Phase · Dec`, exactly
as in the proof of CMS Lemma 3.2.  On each one-input database fiber, `Dec` is the Householder
reflection that swaps the absent coordinate with the uniform superposition of recorded outputs.
The middle phase map is diagonal with unit-modulus entries.  This supplies the algebraic
norm-preservation premise used by the finite query-sequence theorem.
-/

namespace HegemonCrypto.CmsCompressedOracleUnitary

open scoped BigOperators
open HegemonCrypto.FiniteOracleDatabase
open HegemonCrypto.DatabaseFiber
open HegemonCrypto.CmsCompressedOracle
open HegemonCrypto.CmsKernelBounds
open HegemonCrypto.CmsLocalOperator
open HegemonCrypto.CmsLocalOperatorProof

noncomputable section

set_option linter.unusedSectionVars false
set_option linter.unusedSimpArgs false

variable {Input Output Phase Workspace : Type*}
variable [Fintype Input] [DecidableEq Input]
variable [Fintype Output] [DecidableEq Output] [AddCommGroup Output]
variable [Fintype Phase] [DecidableEq Phase]
variable [Fintype Workspace] [DecidableEq Workspace]

/-- Hilbert space of one absent/recorded database fiber. -/
abbrev FiberState (Output : Type*) [Fintype Output] :=
  EuclideanSpace ℂ (Option Output)

/-- Ket for the absent database coordinate. -/
def absentKet : FiberState Output :=
  EuclideanSpace.single none 1

/-- Uniform superposition of every recorded-output coordinate. -/
def uniformKet : FiberState Output :=
  ∑ output : Output,
    EuclideanSpace.single (some output)
      (inverseSqrtOutputCard (Output := Output))

/-- Householder direction whose reflection swaps `absentKet` and `uniformKet`. -/
def decompressionDirection : FiberState Output :=
  absentKet - uniformKet

/-- Exact CMS decompression operator on one database fiber. -/
def decompressFiber : FiberState Output ≃ₗᵢ[ℂ] FiberState Output :=
  (ℂ ∙ decompressionDirection (Output := Output))ᗮ.reflection

@[simp]
theorem absent_ket_apply_none :
    absentKet (Output := Output) none = 1 := by
  simp [absentKet]

@[simp]
theorem absent_ket_apply_some (output : Output) :
    absentKet (Output := Output) (some output) = 0 := by
  simp [absentKet]

@[simp]
theorem uniform_ket_apply_none :
    uniformKet (Output := Output) none = 0 := by
  simp [uniformKet]

@[simp]
theorem uniform_ket_apply_some (output : Output) :
    uniformKet (Output := Output) (some output) =
      inverseSqrtOutputCard (Output := Output) := by
  simp [uniformKet, PiLp.single_apply, Pi.single_apply]

/-- The two normalization constants agree exactly. -/
theorem inverse_sqrt_output_card_mul_self :
    inverseSqrtOutputCard (Output := Output) *
        inverseSqrtOutputCard (Output := Output) =
      inverseOutputCard (Output := Output) := by
  unfold inverseSqrtOutputCard inverseOutputCard
  norm_cast
  rw [← mul_inv, Real.mul_self_sqrt
    (show 0 <= (Fintype.card Output : ℝ) by positivity)]

/-- The Householder direction has squared norm exactly two. -/
theorem decompression_direction_norm_sq :
    ‖decompressionDirection (Output := Output)‖ ^ 2 = 2 := by
  rw [EuclideanSpace.norm_sq_eq]
  rw [Fintype.sum_option]
  simp only [decompressionDirection, PiLp.sub_apply, absent_ket_apply_none,
    uniform_ket_apply_none, absent_ket_apply_some, uniform_ket_apply_some,
    sub_zero, zero_sub, norm_one, one_pow, norm_neg]
  have inverseNorm :
      ‖inverseSqrtOutputCard (Output := Output)‖ ^ 2 =
        1 / (Fintype.card Output : ℝ) := by
    calc
      ‖inverseSqrtOutputCard (Output := Output)‖ ^ 2 =
          Complex.normSq (inverseSqrtOutputCard (Output := Output)) :=
        Complex.sq_norm _
      _ = 1 / (Fintype.card Output : ℝ) :=
        normSq_inverseSqrtOutputCard (Output := Output)
  rw [inverseNorm, Finset.sum_const, nsmul_eq_mul]
  have cardPositive : (0 : ℝ) < Fintype.card Output :=
    output_card_real_positive (Output := Output)
  field_simp
  rw [Finset.card_univ]
  ring

/-- The decompression direction's inner product with an arbitrary fiber state. -/
theorem inner_decompression_direction
    (state : FiberState Output) :
    inner ℂ (decompressionDirection (Output := Output)) state =
      state none -
        inverseSqrtOutputCard (Output := Output) *
          ∑ output : Output, state (some output) := by
  unfold decompressionDirection absentKet uniformKet
  rw [inner_sub_left, EuclideanSpace.inner_single_left]
  simp only [map_one, one_mul, sum_inner]
  simp_rw [EuclideanSpace.inner_single_left]
  rw [← Finset.mul_sum]
  simp [inverseSqrtOutputCard]

/-- Coordinate formula for the CMS decompression reflection at the absent coordinate. -/
theorem decompress_fiber_apply_none
    (state : FiberState Output) :
    decompressFiber state none =
      inverseSqrtOutputCard (Output := Output) *
        ∑ output : Output, state (some output) := by
  unfold decompressFiber
  rw [Submodule.reflection_orthogonal_apply,
    Submodule.reflection_singleton_apply]
  have directionNormSqComplex :
      ((‖decompressionDirection (Output := Output)‖ : ℂ) ^ 2) = 2 := by
    exact_mod_cast decompression_direction_norm_sq (Output := Output)
  simp only [PiLp.neg_apply, PiLp.sub_apply, PiLp.smul_apply, smul_eq_mul,
    nsmul_eq_mul, neg_sub]
  change
    state none -
        (2 : ℂ) *
          (inner ℂ (decompressionDirection (Output := Output)) state /
              ((‖decompressionDirection (Output := Output)‖ : ℂ) ^ 2) *
            decompressionDirection (Output := Output) none) =
      _
  rw [directionNormSqComplex]
  rw [inner_decompression_direction]
  simp only [decompressionDirection, PiLp.sub_apply, absent_ket_apply_none,
    uniform_ket_apply_none, sub_zero]
  norm_num
  ring

/-- Coordinate formula for the CMS decompression reflection at a recorded output. -/
theorem decompress_fiber_apply_some
    (state : FiberState Output)
    (output : Output) :
    decompressFiber state (some output) =
      state (some output) +
        inverseSqrtOutputCard (Output := Output) * state none -
        inverseOutputCard (Output := Output) *
          ∑ recorded : Output, state (some recorded) := by
  unfold decompressFiber
  rw [Submodule.reflection_orthogonal_apply,
    Submodule.reflection_singleton_apply]
  have directionNormSqComplex :
      ((‖decompressionDirection (Output := Output)‖ : ℂ) ^ 2) = 2 := by
    exact_mod_cast decompression_direction_norm_sq (Output := Output)
  simp only [PiLp.neg_apply, PiLp.sub_apply, PiLp.smul_apply, smul_eq_mul,
    nsmul_eq_mul, neg_sub]
  change
    state (some output) -
        (2 : ℂ) *
          (inner ℂ (decompressionDirection (Output := Output)) state /
              ((‖decompressionDirection (Output := Output)‖ : ℂ) ^ 2) *
            decompressionDirection (Output := Output) (some output)) =
      _
  rw [directionNormSqComplex]
  rw [inner_decompression_direction]
  simp only [decompressionDirection, PiLp.sub_apply, absent_ket_apply_some,
    uniform_ket_apply_some, zero_sub]
  norm_num
  rw [← inverse_sqrt_output_card_mul_self (Output := Output)]
  ring

/-- Decompression preserves the exact finite `l₂` norm. -/
theorem decompress_fiber_preserves_norm
    (state : FiberState Output) :
    ‖decompressFiber state‖ = ‖state‖ :=
  (decompressFiber (Output := Output)).norm_map state

/-- Diagonal phase-oracle action between the two decompression reflections. -/
def phaseFiber
    (system : PhaseSystem Output Phase)
    (phaseValue : Phase)
    (state : FiberState Output) :
    FiberState Output :=
  WithLp.toLp 2 fun coordinate =>
    match coordinate with
    | none => state none
    | some output => system.character phaseValue output * state (some output)

@[simp]
theorem phase_fiber_apply_none
    (system : PhaseSystem Output Phase)
    (phaseValue : Phase)
    (state : FiberState Output) :
    phaseFiber system phaseValue state none = state none := by
  rfl

@[simp]
theorem phase_fiber_apply_some
    (system : PhaseSystem Output Phase)
    (phaseValue : Phase)
    (state : FiberState Output)
    (output : Output) :
    phaseFiber system phaseValue state (some output) =
      system.character phaseValue output * state (some output) := by
  rfl

/-- The diagonal character phase preserves the exact finite `l₂` norm. -/
theorem phase_fiber_preserves_norm
    (system : PhaseSystem Output Phase)
    (phaseValue : Phase)
    (state : FiberState Output) :
    ‖phaseFiber system phaseValue state‖ = ‖state‖ := by
  have squared :
      ‖phaseFiber system phaseValue state‖ ^ 2 = ‖state‖ ^ 2 := by
    rw [EuclideanSpace.norm_sq_eq, EuclideanSpace.norm_sq_eq]
    rw [Fintype.sum_option, Fintype.sum_option]
    apply congrArg (‖state none‖ ^ 2 + ·)
    apply Finset.sum_congr rfl
    intro output _
    rw [phase_fiber_apply_some, norm_mul, mul_pow]
    have phaseNorm :
        ‖system.character phaseValue output‖ ^ 2 = 1 := by
      rw [Complex.sq_norm]
      exact addChar_normSq (system.character phaseValue) output
    rw [phaseNorm, one_mul]
  nlinarith [norm_nonneg (phaseFiber system phaseValue state), norm_nonneg state]

/-- Exact active compressed phase-oracle transform on one database fiber. -/
def activeFiberQuery
    (system : PhaseSystem Output Phase)
    (phaseValue : Phase)
    (state : FiberState Output) :
    FiberState Output :=
  decompressFiber
    (phaseFiber system phaseValue (decompressFiber state))

/-- The active one-fiber query is an isometry. -/
theorem active_fiber_query_preserves_norm
    (system : PhaseSystem Output Phase)
    (phaseValue : Phase)
    (state : FiberState Output) :
    ‖activeFiberQuery system phaseValue state‖ = ‖state‖ := by
  unfold activeFiberQuery
  rw [decompress_fiber_preserves_norm, phase_fiber_preserves_norm,
    decompress_fiber_preserves_norm]

/-- The diagonal phase action is additive. -/
theorem phase_fiber_add
    (system : PhaseSystem Output Phase)
    (phaseValue : Phase)
    (left right : FiberState Output) :
    phaseFiber system phaseValue (left + right) =
      phaseFiber system phaseValue left +
        phaseFiber system phaseValue right := by
  ext coordinate
  cases coordinate with
  | none => rfl
  | some output =>
      simp [phaseFiber]
      ring

/-- The diagonal phase action commutes with complex scalar multiplication. -/
theorem phase_fiber_smul
    (system : PhaseSystem Output Phase)
    (phaseValue : Phase)
    (scalar : ℂ)
    (state : FiberState Output) :
    phaseFiber system phaseValue (scalar • state) =
      scalar • phaseFiber system phaseValue state := by
  ext coordinate
  cases coordinate with
  | none => rfl
  | some output =>
      simp [phaseFiber]
      ring

/-- Bundled complex-linear form of the active one-fiber query. -/
def activeFiberQueryLinear
    (system : PhaseSystem Output Phase)
    (phaseValue : Phase) :
    FiberState Output →ₗ[ℂ] FiberState Output where
  toFun := activeFiberQuery system phaseValue
  map_add' left right := by
    unfold activeFiberQuery
    rw [map_add, phase_fiber_add, map_add]
  map_smul' scalar state := by
    unfold activeFiberQuery
    rw [map_smul, phase_fiber_smul, map_smul]
    rfl

/-- The active one-fiber query maps the zero state to zero. -/
@[simp]
theorem active_fiber_query_zero_state
    (system : PhaseSystem Output Phase)
    (phaseValue : Phase) :
    activeFiberQuery system phaseValue (0 : FiberState Output) = 0 := by
  simpa [activeFiberQueryLinear] using
    (activeFiberQueryLinear (Output := Output) system phaseValue).map_zero

/-- One computational-basis ket in the absent/recorded fiber. -/
def fiberBasisKet (coordinate : Option Output) : FiberState Output :=
  EuclideanSpace.single coordinate 1

@[simp]
theorem fiber_basis_ket_apply
    (source target : Option Output) :
    fiberBasisKet (Output := Output) source target =
      if target = source then 1 else 0 := by
  simp [fiberBasisKet, PiLp.single_apply]

/-- Every finite fiber state is its exact computational-basis expansion. -/
theorem fiber_state_eq_sum_basis
    (state : FiberState Output) :
    state =
      ∑ coordinate : Option Output,
        state coordinate • fiberBasisKet (Output := Output) coordinate := by
  ext target
  rw [Fintype.sum_option]
  cases target with
  | none =>
      simp [fiberBasisKet, PiLp.single_apply, Pi.single_apply]
  | some selected =>
      simp [fiberBasisKet, PiLp.single_apply, Pi.single_apply]

/-- Matrix expansion of the active one-fiber query. -/
theorem active_fiber_query_eq_sum_basis
    (system : PhaseSystem Output Phase)
    (phaseValue : Phase)
    (state : FiberState Output)
    (target : Option Output) :
    activeFiberQuery system phaseValue state target =
      ∑ source : Option Output,
        state source *
          activeFiberQuery system phaseValue
            (fiberBasisKet (Output := Output) source) target := by
  have expansion :
      activeFiberQueryLinear (Output := Output) system phaseValue state =
        ∑ source : Option Output,
          activeFiberQueryLinear (Output := Output) system phaseValue
            (state source • fiberBasisKet (Output := Output) source) := by
    rw [← map_sum]
    exact congrArg
      (activeFiberQueryLinear (Output := Output) system phaseValue)
      (fiber_state_eq_sum_basis state)
  simp_rw [map_smul] at expansion
  have atTarget := congrArg (fun value : FiberState Output => value target) expansion
  simpa [
    activeFiberQueryLinear,
    Finset.sum_apply,
    PiLp.smul_apply,
    smul_eq_mul
  ] using atTarget

/-- Matrix kernel of the active decompression-phase-decompression transform. -/
def activeFiberKernel
    (system : PhaseSystem Output Phase)
    (phaseValue : Phase)
    (source target : Option Output) : ℂ :=
  activeFiberQuery system phaseValue
    (fiberBasisKet (Output := Output) source) target

/-- The first decompression maps an absent ket to the uniform recorded-output ket. -/
theorem decompress_absent_ket :
    decompressFiber (absentKet (Output := Output)) =
      uniformKet (Output := Output) := by
  ext coordinate
  cases coordinate with
  | none =>
      rw [decompress_fiber_apply_none]
      simp
  | some output =>
      rw [decompress_fiber_apply_some]
      simp

/-- The decompression reflection is involutive. -/
theorem decompress_fiber_involutive
    (state : FiberState Output) :
    decompressFiber (decompressFiber state) = state :=
  (decompressFiber (Output := Output)).left_inv state

/-- The second decompression maps the uniform ket back to the absent ket. -/
theorem decompress_uniform_ket :
    decompressFiber (uniformKet (Output := Output)) =
      absentKet (Output := Output) := by
  rw [← decompress_absent_ket (Output := Output)]
  exact decompress_fiber_involutive (absentKet (Output := Output))

/-- The trivial character makes the middle phase operator the identity. -/
theorem phase_fiber_zero
    (system : PhaseSystem Output Phase)
    (state : FiberState Output) :
    phaseFiber system system.zeroPhase state = state := by
  ext coordinate
  cases coordinate with
  | none => rfl
  | some output =>
      simp [phaseFiber, system.character_zero]

/-- The complete active fiber query is the identity at trivial Fourier phase. -/
theorem active_fiber_query_zero
    (system : PhaseSystem Output Phase)
    (state : FiberState Output) :
    activeFiberQuery system system.zeroPhase state = state := by
  unfold activeFiberQuery
  rw [phase_fiber_zero]
  exact decompress_fiber_involutive state

/-- At zero phase, the active fiber kernel is the identity matrix. -/
theorem active_fiber_kernel_zero
    (system : PhaseSystem Output Phase)
    (source target : Option Output) :
    activeFiberKernel system system.zeroPhase source target =
      if target = source then 1 else 0 := by
  unfold activeFiberKernel
  rw [active_fiber_query_zero]
  exact fiber_basis_ket_apply source target

/-- Fourier image of the uniform recorded-output ket. -/
def fourierKet
    (system : PhaseSystem Output Phase)
    (phaseValue : Phase) : FiberState Output :=
  phaseFiber system phaseValue (uniformKet (Output := Output))

@[simp]
theorem fourier_ket_apply_none
    (system : PhaseSystem Output Phase)
    (phaseValue : Phase) :
    fourierKet system phaseValue none = 0 := by
  simp [fourierKet]

@[simp]
theorem fourier_ket_apply_some
    (system : PhaseSystem Output Phase)
    (phaseValue : Phase)
    (output : Output) :
    fourierKet system phaseValue (some output) =
      inverseSqrtOutputCard (Output := Output) *
        system.character phaseValue output := by
  simp [fourierKet]
  ring

/-- A nontrivial Fourier ket has zero recorded-coordinate sum. -/
theorem fourier_ket_sum_zero
    (system : PhaseSystem Output Phase)
    (phaseValue : Phase)
    (nonzeroPhase : phaseValue ≠ system.zeroPhase) :
    ∑ output : Output, fourierKet system phaseValue (some output) = 0 := by
  simp_rw [fourier_ket_apply_some]
  rw [← Finset.mul_sum]
  rw [nontrivial_addChar_sum
    (system.character phaseValue) (system.character_nonzero phaseValue nonzeroPhase)]
  simp

/-- A nontrivial Fourier ket is fixed by decompression. -/
theorem decompress_fourier_ket
    (system : PhaseSystem Output Phase)
    (phaseValue : Phase)
    (nonzeroPhase : phaseValue ≠ system.zeroPhase) :
    decompressFiber (fourierKet system phaseValue) =
      fourierKet system phaseValue := by
  ext coordinate
  cases coordinate with
  | none =>
      rw [decompress_fiber_apply_none, fourier_ket_sum_zero
        system phaseValue nonzeroPhase]
      simp
  | some output =>
      rw [decompress_fiber_apply_some, fourier_ket_sum_zero
        system phaseValue nonzeroPhase]
      simp

/-- Nontrivial-phase action on the absent source ket. -/
theorem active_fiber_query_absent_nonzero
    (system : PhaseSystem Output Phase)
    (phaseValue : Phase)
    (nonzeroPhase : phaseValue ≠ system.zeroPhase) :
    activeFiberQuery system phaseValue (absentKet (Output := Output)) =
      fourierKet system phaseValue := by
  unfold activeFiberQuery fourierKet
  rw [decompress_absent_ket]
  exact decompress_fourier_ket system phaseValue nonzeroPhase

theorem active_fiber_kernel_absent_none_nonzero
    (system : PhaseSystem Output Phase)
    (phaseValue : Phase)
    (nonzeroPhase : phaseValue ≠ system.zeroPhase) :
    activeFiberKernel system phaseValue none none = 0 := by
  unfold activeFiberKernel
  rw [show fiberBasisKet (Output := Output) none =
      absentKet (Output := Output) by rfl]
  rw [active_fiber_query_absent_nonzero system phaseValue nonzeroPhase]
  exact fourier_ket_apply_none system phaseValue

theorem active_fiber_kernel_absent_some_nonzero
    (system : PhaseSystem Output Phase)
    (phaseValue : Phase)
    (nonzeroPhase : phaseValue ≠ system.zeroPhase)
    (target : Output) :
    activeFiberKernel system phaseValue none (some target) =
      inverseSqrtOutputCard (Output := Output) *
        system.character phaseValue target := by
  unfold activeFiberKernel
  rw [show fiberBasisKet (Output := Output) none =
      absentKet (Output := Output) by rfl]
  rw [active_fiber_query_absent_nonzero system phaseValue nonzeroPhase]
  exact fourier_ket_apply_some system phaseValue target

/-- First decompression coordinate of one recorded-output basis ket. -/
theorem decompress_recorded_ket_apply_none
    (recorded : Output) :
    decompressFiber (fiberBasisKet (Output := Output) (some recorded)) none =
      inverseSqrtOutputCard (Output := Output) := by
  rw [decompress_fiber_apply_none]
  simp [fiberBasisKet, PiLp.single_apply, Pi.single_apply]

/-- Recorded coordinates after the first decompression of one recorded-output basis ket. -/
theorem decompress_recorded_ket_apply_some
    (recorded target : Output) :
    decompressFiber (fiberBasisKet (Output := Output) (some recorded)) (some target) =
      (if target = recorded then 1 else 0) -
        inverseOutputCard (Output := Output) := by
  rw [decompress_fiber_apply_some]
  simp [fiberBasisKet, PiLp.single_apply, Pi.single_apply,
    inverse_sqrt_output_card_mul_self (Output := Output)]

/-- Character-weighted sum after first decompression of a recorded ket. -/
theorem phase_decompressed_recorded_sum
    (system : PhaseSystem Output Phase)
    (phaseValue : Phase)
    (nonzeroPhase : phaseValue ≠ system.zeroPhase)
    (recorded : Output) :
    ∑ output : Output,
        phaseFiber system phaseValue
          (decompressFiber (fiberBasisKet (Output := Output) (some recorded)))
          (some output) =
      system.character phaseValue recorded := by
  simp_rw [phase_fiber_apply_some, decompress_recorded_ket_apply_some]
  simp_rw [mul_sub]
  rw [Finset.sum_sub_distrib]
  have phaseSum :
      ∑ output : Output, system.character phaseValue output = 0 :=
    nontrivial_addChar_sum
      (system.character phaseValue)
      (system.character_nonzero phaseValue nonzeroPhase)
  calc
    (∑ output : Output,
        system.character phaseValue output *
          (if output = recorded then 1 else 0)) -
        ∑ output : Output,
          system.character phaseValue output *
            inverseOutputCard (Output := Output) =
      system.character phaseValue recorded -
        (∑ output : Output, system.character phaseValue output) *
          inverseOutputCard (Output := Output) := by
        congr 1
        · simp
        · rw [Finset.sum_mul]
    _ = system.character phaseValue recorded := by
      rw [phaseSum]
      simp

/-- Nontrivial-phase recorded source to absent target amplitude. -/
theorem active_fiber_query_recorded_apply_none
    (system : PhaseSystem Output Phase)
    (phaseValue : Phase)
    (nonzeroPhase : phaseValue ≠ system.zeroPhase)
    (recorded : Output) :
    activeFiberQuery system phaseValue
        (fiberBasisKet (Output := Output) (some recorded)) none =
      system.character phaseValue recorded *
        inverseSqrtOutputCard (Output := Output) := by
  unfold activeFiberQuery
  rw [decompress_fiber_apply_none,
    phase_decompressed_recorded_sum system phaseValue nonzeroPhase recorded]
  ring

theorem active_fiber_kernel_recorded_none_nonzero
    (system : PhaseSystem Output Phase)
    (phaseValue : Phase)
    (nonzeroPhase : phaseValue ≠ system.zeroPhase)
    (recorded : Output) :
    activeFiberKernel system phaseValue (some recorded) none =
      system.character phaseValue recorded *
        inverseSqrtOutputCard (Output := Output) := by
  exact active_fiber_query_recorded_apply_none
    system phaseValue nonzeroPhase recorded

/-- Nontrivial-phase recorded source to recorded target amplitude. -/
theorem active_fiber_query_recorded_apply_some
    (system : PhaseSystem Output Phase)
    (phaseValue : Phase)
    (nonzeroPhase : phaseValue ≠ system.zeroPhase)
    (recorded target : Output) :
    activeFiberQuery system phaseValue
        (fiberBasisKet (Output := Output) (some recorded)) (some target) =
      (if target = recorded then system.character phaseValue recorded else 0) +
        inverseOutputCard (Output := Output) *
          (1 - system.character phaseValue target -
            system.character phaseValue recorded) := by
  unfold activeFiberQuery
  rw [decompress_fiber_apply_some,
    phase_decompressed_recorded_sum system phaseValue nonzeroPhase recorded]
  rw [phase_fiber_apply_some, decompress_recorded_ket_apply_some,
    phase_fiber_apply_none, decompress_recorded_ket_apply_none]
  rw [inverse_sqrt_output_card_mul_self]
  split_ifs with same
  · subst target
    ring
  · ring

theorem active_fiber_kernel_recorded_some_nonzero
    (system : PhaseSystem Output Phase)
    (phaseValue : Phase)
    (nonzeroPhase : phaseValue ≠ system.zeroPhase)
    (recorded target : Output) :
    activeFiberKernel system phaseValue (some recorded) (some target) =
      (if target = recorded then system.character phaseValue recorded else 0) +
        inverseOutputCard (Output := Output) *
          (1 - system.character phaseValue target -
            system.character phaseValue recorded) := by
  exact active_fiber_query_recorded_apply_some
    system phaseValue nonzeroPhase recorded target

/--
On a strict pre-query state, every weighted entry of the published capped kernel agrees with the
unitary decompression-phase-decompression kernel.  The only raw matrix entries that differ are
columns at the query cap, and strict support makes their coefficients zero.
-/
theorem strict_weighted_explicit_kernel_eq_active
    (system : PhaseSystem Output Phase)
    (queryBound : Nat)
    (input : Input)
    (phaseValue : Phase)
    (base : AbsentDatabase (Output := Output) input)
    (coefficient : FiberState Output)
    (strictAbsent :
      queryBound <= size base.1 -> coefficient none = 0)
    (strictRecorded :
      ∀ output, queryBound <= size base.1 + 1 ->
        coefficient (some output) = 0)
    (source target : Option Output) :
    coefficient source *
        explicitFiberKernel system queryBound input phaseValue
          (base, source) (base, target) =
      coefficient source *
        activeFiberKernel system phaseValue source target := by
  by_cases baseAtOrAbove : queryBound <= size base.1
  · have sourceZero : coefficient source = 0 := by
      cases source with
      | none => exact strictAbsent baseAtOrAbove
      | some output =>
          exact strictRecorded output
            (baseAtOrAbove.trans (Nat.le_add_right _ _))
    simp [sourceZero]
  · have baseBelow : size base.1 < queryBound :=
      Nat.lt_of_not_ge baseAtOrAbove
    have baseNotCapped : size base.1 ≠ queryBound :=
      Nat.ne_of_lt baseBelow
    by_cases zeroPhase : phaseValue = system.zeroPhase
    · subst phaseValue
      rw [active_fiber_kernel_zero]
      cases source <;> cases target <;>
        simp [explicitFiberKernel, baseNotCapped, system.character_zero]
    · cases source with
      | none =>
          cases target with
          | none =>
              rw [active_fiber_kernel_absent_none_nonzero
                system phaseValue zeroPhase]
              simp [explicitFiberKernel, baseNotCapped, zeroPhase]
          | some targetOutput =>
              rw [active_fiber_kernel_absent_some_nonzero
                system phaseValue zeroPhase targetOutput]
              simp [explicitFiberKernel, baseNotCapped, zeroPhase]
      | some sourceOutput =>
          by_cases edge : size base.1 + 1 = queryBound
          · have sourceZero : coefficient (some sourceOutput) = 0 :=
              strictRecorded sourceOutput (le_of_eq edge.symm)
            simp [sourceZero]
          · cases target with
            | none =>
                rw [active_fiber_kernel_recorded_none_nonzero
                  system phaseValue zeroPhase sourceOutput]
                simp [explicitFiberKernel, edge, zeroPhase]
            | some targetOutput =>
                rw [active_fiber_kernel_recorded_some_nonzero
                  system phaseValue zeroPhase sourceOutput targetOutput]
                simp [explicitFiberKernel, edge, zeroPhase]

/-- Strict weighted capped-kernel action equals the exact active unitary fiber action. -/
theorem strict_explicit_kernel_sum_eq_active
    (system : PhaseSystem Output Phase)
    (queryBound : Nat)
    (input : Input)
    (phaseValue : Phase)
    (base : AbsentDatabase (Output := Output) input)
    (coefficient : FiberState Output)
    (strictAbsent :
      queryBound <= size base.1 -> coefficient none = 0)
    (strictRecorded :
      ∀ output, queryBound <= size base.1 + 1 ->
        coefficient (some output) = 0)
    (target : Option Output) :
    (∑ source : Option Output,
      coefficient source *
        explicitFiberKernel system queryBound input phaseValue
          (base, source) (base, target)) =
      activeFiberQuery system phaseValue coefficient target := by
  rw [active_fiber_query_eq_sum_basis]
  apply Finset.sum_congr rfl
  intro source _
  exact strict_weighted_explicit_kernel_eq_active
    system queryBound input phaseValue base coefficient
      strictAbsent strictRecorded source target

/-- A pre-query state has no amplitude on databases at or above the total query cap. -/
def StrictSupport
    (queryBound : Nat)
    (state : State Input Output Phase Workspace) : Prop :=
  ∀ basis, queryBound <= size basis.database -> state basis = 0

/-- One canonical absent-base fiber cut out of a full compressed-oracle state. -/
def stateFiber
    (state : State Input Output Phase Workspace)
    (input : Input)
    (phaseValue : Phase)
    (workspace : Workspace)
    (base : AbsentDatabase (Output := Output) input) :
    FiberState Output :=
  WithLp.toLp 2 fun coordinate =>
    state
      { input := input
        phase := phaseValue
        workspace := workspace
        database :=
          (databaseEquiv (Output := Output) input).symm (base, coordinate) }

@[simp]
theorem state_fiber_apply
    (state : State Input Output Phase Workspace)
    (input : Input)
    (phaseValue : Phase)
    (workspace : Workspace)
    (base : AbsentDatabase (Output := Output) input)
    (coordinate : Option Output) :
    stateFiber state input phaseValue workspace base coordinate =
      state
        { input := input
          phase := phaseValue
          workspace := workspace
          database :=
            (databaseEquiv (Output := Output) input).symm (base, coordinate) } := by
  rfl

set_option linter.unusedSimpArgs false
/-- The full kernel sum reduces to the one database block with unchanged adversary registers. -/
theorem query_state_apply_database_block
    (system : PhaseSystem Output Phase)
    (queryBound : Nat)
    (state : State Input Output Phase Workspace)
    (target : Basis Input Output Phase Workspace) :
    queryState system queryBound state target =
      ∑ sourceDatabase : Database Input Output,
        state
            { input := target.input
              phase := target.phase
              workspace := target.workspace
              database := sourceDatabase } *
          databaseKernel system queryBound target.input target.phase
            sourceDatabase target.database := by
  unfold queryState
  rw [← (basisEquiv (Input := Input) (Output := Output) (Phase := Phase)
    (Workspace := Workspace)).sum_comp
      (fun source => state source * kernel system queryBound source target)]
  rw [Fintype.sum_prod_type]
  rw [Finset.sum_eq_single target.input]
  · rw [Fintype.sum_prod_type]
    rw [Finset.sum_eq_single target.phase]
    · rw [Fintype.sum_prod_type]
      rw [Finset.sum_eq_single target.workspace]
      · apply Finset.sum_congr rfl
        intro sourceDatabase _
        simp [kernel, basisEquiv]
      · intro sourceWorkspace _ differentWorkspace
        have targetDifferent : target.workspace ≠ sourceWorkspace :=
          Ne.symm differentWorkspace
        simp [kernel, basisEquiv, targetDifferent]
      · simp
    · intro sourcePhase _ differentPhase
      have targetDifferent : target.phase ≠ sourcePhase :=
        Ne.symm differentPhase
      simp [kernel, basisEquiv, targetDifferent]
    · simp
  · intro sourceInput _ differentInput
    have targetDifferent : target.input ≠ sourceInput :=
      Ne.symm differentInput
    simp [kernel, basisEquiv, targetDifferent]
  · simp
set_option linter.unusedSimpArgs true

/--
On strict pre-query support, every full-state output coordinate is exactly the corresponding active
unitary fiber output.
-/
theorem query_state_apply_eq_active_fiber
    (system : PhaseSystem Output Phase)
    (queryBound : Nat)
    (state : State Input Output Phase Workspace)
    (strict : StrictSupport queryBound state)
    (input : Input)
    (phaseValue : Phase)
    (workspace : Workspace)
    (base : AbsentDatabase (Output := Output) input)
    (target : Option Output) :
    queryState system queryBound state
        { input := input
          phase := phaseValue
          workspace := workspace
          database :=
            (databaseEquiv (Output := Output) input).symm (base, target) } =
      activeFiberQuery system phaseValue
        (stateFiber state input phaseValue workspace base) target := by
  rw [query_state_apply_database_block]
  rw [← (databaseEquiv (Output := Output) input).symm.sum_comp
    (fun sourceDatabase =>
      state
          { input := input
            phase := phaseValue
            workspace := workspace
            database := sourceDatabase } *
        databaseKernel system queryBound input phaseValue sourceDatabase
          ((databaseEquiv (Output := Output) input).symm (base, target)))]
  rw [Fintype.sum_prod_type]
  rw [Finset.sum_eq_single base]
  · change
      (∑ source : Option Output,
        stateFiber state input phaseValue workspace base source *
          fiberKernel system queryBound input phaseValue
            (base, source) (base, target)) =
        activeFiberQuery system phaseValue
          (stateFiber state input phaseValue workspace base) target
    simp_rw [fiberKernel_eq_explicit]
    apply strict_explicit_kernel_sum_eq_active
    · intro atCap
      exact strict
        { input := input
          phase := phaseValue
          workspace := workspace
          database := base.1 }
        atCap
    · intro output atCap
      apply strict
        { input := input
          phase := phaseValue
          workspace := workspace
          database := insert base.1 input output }
      rw [size_insert_of_absent base.1 input output base.2]
      exact atCap
  · intro sourceBase _ differentBase
    apply Finset.sum_eq_zero
    intro source _
    change
      state
          { input := input
            phase := phaseValue
            workspace := workspace
            database :=
              (databaseEquiv (Output := Output) input).symm
                (sourceBase, source) } *
          fiberKernel system queryBound input phaseValue
            (sourceBase, source) (base, target) =
        0
    rw [fiberKernel_eq_explicit]
    simp [explicitFiberKernel, Ne.symm differentBase]
  · simp

/--
The squared norm of a full compressed-oracle state is exactly the sum of the squared Euclidean
norms of its canonical one-input database fibers.
-/
theorem norm_squared_eq_sum_state_fiber_norm
    (state : State Input Output Phase Workspace) :
    normSquared state =
      ∑ input : Input,
        ∑ phaseValue : Phase,
          ∑ workspace : Workspace,
            ∑ base : AbsentDatabase (Output := Output) input,
              ‖stateFiber state input phaseValue workspace base‖ ^ 2 := by
  unfold normSquared
  rw [← (basisEquiv (Input := Input) (Output := Output) (Phase := Phase)
    (Workspace := Workspace)).sum_comp
      (fun basis => Complex.normSq (state basis))]
  rw [Fintype.sum_prod_type]
  apply Finset.sum_congr rfl
  intro input _
  rw [Fintype.sum_prod_type]
  apply Finset.sum_congr rfl
  intro phaseValue _
  rw [Fintype.sum_prod_type]
  apply Finset.sum_congr rfl
  intro workspace _
  rw [sum_database_eq_sum_fibers]
  apply Finset.sum_congr rfl
  intro base _
  rw [EuclideanSpace.norm_sq_eq, Fintype.sum_option]
  simp [state_fiber_apply, Complex.sq_norm, basisEquiv,
    databaseEquiv_symm_none, databaseEquiv_symm_some]

/--
On strict pre-query support, the implemented capped compressed-oracle query preserves the exact
full-state squared norm.  This is the reachable-subspace isometry needed by the query telescope;
no cryptographic assumption is used.
-/
theorem query_state_preserves_norm_squared_of_strict_support
    (system : PhaseSystem Output Phase)
    (queryBound : Nat)
    (state : State Input Output Phase Workspace)
    (strict : StrictSupport queryBound state) :
    normSquared (queryState system queryBound state) = normSquared state := by
  rw [norm_squared_eq_sum_state_fiber_norm,
    norm_squared_eq_sum_state_fiber_norm]
  apply Finset.sum_congr rfl
  intro input _
  apply Finset.sum_congr rfl
  intro phaseValue _
  apply Finset.sum_congr rfl
  intro workspace _
  apply Finset.sum_congr rfl
  intro base _
  have fiberEquality :
      stateFiber (queryState system queryBound state)
          input phaseValue workspace base =
        activeFiberQuery system phaseValue
          (stateFiber state input phaseValue workspace base) := by
    ext target
    exact query_state_apply_eq_active_fiber
      system queryBound state strict input phaseValue workspace base target
  rw [fiberEquality, active_fiber_query_preserves_norm]

/-- The implemented query is contractive, in fact isometric, on strict reachable support. -/
theorem query_state_contractive_of_strict_support
    (system : PhaseSystem Output Phase)
    (queryBound : Nat)
    (state : State Input Output Phase Workspace)
    (strict : StrictSupport queryBound state) :
    normSquared (queryState system queryBound state) <= normSquared state := by
  exact le_of_eq
    (query_state_preserves_norm_squared_of_strict_support
      system queryBound state strict)

end

end HegemonCrypto.CmsCompressedOracleUnitary
