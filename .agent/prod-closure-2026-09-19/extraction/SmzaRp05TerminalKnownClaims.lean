import HegemonCrypto.CmsAdaptiveClaimBridge

/-!
# Terminal retention of known full-output claims

After the last ordinary oracle query, every claimed full-vector value is
retained in classical workspace.  On each orthogonal workspace/rest fiber the
total-oracle tuple is therefore a single known tuple.  The exact CMS
decompression row keeps the same recorded tuple with amplitude
`(1 - 1 / |Y|)^C`.  Norm preservation of decompression and one final database
measurement then give failure at most `2*C/|Y|`.

`Rest` below is the tensor product of every register other than the selected
claim coordinates: adversary workspace, phase/query registers, unclaimed
oracle coordinates, and arbitrary purification.  Its amplitudes are not
assumed to factor.  Summing its orthogonal fibers is therefore the actual
entangled-state calculation, not a normalized or postselected branch
argument.

The connection to global CMS compression uses the already checked facts that
unclaimed-coordinate decompressions preserve the claim-event norm
(`claims_event_projection_norm_global_decompress_eq_selected`) and that the
selected-coordinate matrix is exactly `recordedTupleRowCoefficient`
(`selected_decompression_kernel_eq_recorded_row`).
-/
namespace HegemonCrypto.SmallWood.SmzaRp05TerminalKnownClaims

open scoped BigOperators Classical
open HegemonCrypto.FiniteOracleDatabase
open HegemonCrypto.CmsCompressedOracle
open HegemonCrypto.CmsOracleSimulation
open HegemonCrypto.CmsOracleDatabaseBridge
open HegemonCrypto.CmsAdaptiveClaimBridge

noncomputable section
set_option autoImplicit false
set_option maxRecDepth 10000
set_option linter.unusedSectionVars false

variable {Output Rest Coordinate : Type*}
variable [Fintype Output] [DecidableEq Output] [AddCommGroup Output]
variable [Fintype Rest] [DecidableEq Rest]

def inverseCard : ℝ := 1 / (Fintype.card Output : ℝ)

def retainedAmplitude (arity : Nat) : ℝ :=
  (1 - inverseCard (Output := Output)) ^ arity

/-- A known total-oracle tuple has only its retained classical value in the
selected tuple fiber.  All entanglement remains in `coefficient`. -/
def knownTupleCoefficient {arity : Nat}
    (target : Fin arity → Output) (coefficient : ℂ)
    (source : Fin arity → Output) : ℂ :=
  if source = target then coefficient else 0

theorem known_tuple_selected_decompression_amplitude
    {arity : Nat} (target : Fin arity → Output) (coefficient : ℂ) :
    recordedTupleAmplitude target
        (knownTupleCoefficient target coefficient) =
      coefficient * retainedAmplitude (Output := Output) arity := by
  unfold recordedTupleAmplitude knownTupleCoefficient retainedAmplitude inverseCard
  rw [Finset.sum_eq_single target]
  · simp [recorded_tuple_row_coefficient_self]
  · intro source _ different
    simp [different]
  · simp

/-- The preceding amplitude is the literal selected-coordinate CMS matrix
coefficient, not an abstract Bernoulli surrogate. -/
theorem known_tuple_selected_kernel_amplitude
    {arity : Nat} (target : Fin arity → Output) (coefficient : ℂ) :
    (∑ source : Fin arity → Output,
      knownTupleCoefficient target coefficient source *
        selectedDecompressionKernel target source) =
      coefficient * retainedAmplitude (Output := Output) arity := by
  rw [← recorded_tuple_amplitude_eq_selected_decompression]
  exact known_tuple_selected_decompression_amplitude target coefficient

theorem retained_amplitude_nonnegative (arity : Nat) :
    0 ≤ retainedAmplitude (Output := Output) arity := by
  apply pow_nonneg
  unfold inverseCard
  have cardAtLeastOne : (1 : ℝ) ≤ Fintype.card Output := by
    exact_mod_cast Fintype.card_pos (α := Output)
  have cardPositive : (0 : ℝ) < Fintype.card Output := by positivity
  exact sub_nonneg.mpr ((div_le_one cardPositive).2 cardAtLeastOne)

theorem retained_amplitude_sq
    (arity : Nat) :
    retainedAmplitude (Output := Output) arity ^ 2 =
      (1 - inverseCard (Output := Output)) ^ (2 * arity) := by
  unfold retainedAmplitude
  rw [pow_two, ← pow_add]
  congr 1
  omega

/-- Exact failure mass of the terminal claims measurement on one arbitrary
rest fiber.  Norm preservation supplies the total `normSq coefficient`; the
known recorded outcome has the self-row amplitude proved above. -/
def fiberFailureMass (arity : Nat) (coefficient : ℂ) : ℝ :=
  (1 - retainedAmplitude (Output := Output) arity ^ 2) *
    Complex.normSq coefficient

theorem fiber_failure_mass_nonnegative
    (arity : Nat) (coefficient : ℂ) :
    0 ≤ fiberFailureMass (Output := Output) arity coefficient := by
  apply mul_nonneg
  · rw [retained_amplitude_sq]
    apply sub_nonneg.mpr
    apply pow_le_one₀
    · unfold inverseCard
      have cardAtLeastOne : (1 : ℝ) ≤ Fintype.card Output := by
        exact_mod_cast Fintype.card_pos (α := Output)
      have cardPositive : (0 : ℝ) < Fintype.card Output := by positivity
      exact sub_nonneg.mpr ((div_le_one cardPositive).2 cardAtLeastOne)
    · unfold inverseCard
      have invNonnegative : 0 ≤ (1 : ℝ) / Fintype.card Output := by positivity
      exact sub_le_self 1 invNonnegative
  · exact Complex.normSq_nonneg coefficient

theorem fiber_failure_mass_le
    (arity cap : Nat) (bounded : arity ≤ cap) (coefficient : ℂ) :
    fiberFailureMass (Output := Output) arity coefficient ≤
      ((2 * cap : Nat) : ℝ) / Fintype.card Output *
        Complex.normSq coefficient := by
  have cardPositive : (0 : ℝ) < Fintype.card Output := by positivity
  have inverseNonnegative : 0 ≤ inverseCard (Output := Output) := by
    unfold inverseCard
    positivity
  have inverseAtMostOne : inverseCard (Output := Output) ≤ 1 := by
    unfold inverseCard
    have cardAtLeastOne : (1 : ℝ) ≤ Fintype.card Output := by
      exact_mod_cast Fintype.card_pos (α := Output)
    exact (div_le_one cardPositive).2 cardAtLeastOne
  have bernoulli :
      1 - retainedAmplitude (Output := Output) arity ^ 2 ≤
        ((2 * arity : Nat) : ℝ) * inverseCard (Output := Output) := by
    rw [retained_amplitude_sq]
    exact one_sub_one_sub_pow_le
      (inverseCard (Output := Output)) inverseNonnegative inverseAtMostOne
      (2 * arity)
  unfold fiberFailureMass
  apply (mul_le_mul_of_nonneg_right bernoulli
    (Complex.normSq_nonneg coefficient)).trans
  apply mul_le_mul_of_nonneg_right _ (Complex.normSq_nonneg coefficient)
  unfold inverseCard
  rw [mul_one_div]
  apply div_le_div_of_nonneg_right
  · exact_mod_cast Nat.mul_le_mul_left 2 bounded
  · exact le_of_lt cardPositive

/-- Workspace-selected, deduplicated tuples may have different lengths.  This
is their exact orthogonal failure weight after global compression and one
terminal claims measurement. -/
def terminalFailureMass
    (arity : Rest → Nat) (coefficient : Rest → ℂ) : ℝ :=
  ∑ rest : Rest,
    fiberFailureMass (Output := Output) (arity rest) (coefficient rest)

def restNormSquared (coefficient : Rest → ℂ) : ℝ :=
  ∑ rest : Rest, Complex.normSq (coefficient rest)

/-- Squared norm of the literal retained outcome obtained from the exact CMS
selected-coordinate kernels on every orthogonal rest fiber. -/
def knownTupleRetainedMass
    (arity : Rest → Nat)
    (target : (rest : Rest) → Fin (arity rest) → Output)
    (coefficient : Rest → ℂ) : ℝ :=
  ∑ rest : Rest,
    Complex.normSq
      (recordedTupleAmplitude (target rest)
        (knownTupleCoefficient (target rest) (coefficient rest)))

theorem known_tuple_retained_mass_exact
    (arity : Rest → Nat)
    (target : (rest : Rest) → Fin (arity rest) → Output)
    (coefficient : Rest → ℂ) :
    knownTupleRetainedMass (Output := Output) arity target coefficient =
      ∑ rest : Rest,
        retainedAmplitude (Output := Output) (arity rest) ^ 2 *
          Complex.normSq (coefficient rest) := by
  unfold knownTupleRetainedMass
  apply Finset.sum_congr rfl
  intro rest _
  rw [known_tuple_selected_decompression_amplitude]
  rw [Complex.normSq_mul, Complex.normSq_ofReal]
  ring

/-- Exact orthogonal decomposition: total norm minus the retained known-tuple
measurement outcome is precisely `terminalFailureMass`. -/
theorem terminal_failure_eq_total_sub_retained
    (arity : Rest → Nat)
    (target : (rest : Rest) → Fin (arity rest) → Output)
    (coefficient : Rest → ℂ) :
    terminalFailureMass (Output := Output) arity coefficient =
      restNormSquared coefficient -
        knownTupleRetainedMass (Output := Output) arity target coefficient := by
  rw [known_tuple_retained_mass_exact]
  unfold terminalFailureMass fiberFailureMass restNormSquared
  rw [← Finset.sum_sub_distrib]
  apply Finset.sum_congr rfl
  intro rest _
  ring

/-- No branch normalization occurs: every branch is weighted by its original
`normSq`, and the complete arbitrary entangled rest norm appears on the
right. -/
theorem terminal_known_claims_failure_le
    (arity : Rest → Nat) (coefficient : Rest → ℂ) (cap : Nat)
    (bounded : ∀ rest, arity rest ≤ cap) :
    terminalFailureMass (Output := Output) arity coefficient ≤
      ((2 * cap : Nat) : ℝ) / Fintype.card Output *
        restNormSquared coefficient := by
  unfold terminalFailureMass restNormSquared
  calc
    (∑ rest : Rest,
        fiberFailureMass (Output := Output) (arity rest) (coefficient rest)) ≤
      ∑ rest : Rest,
        (((2 * cap : Nat) : ℝ) / Fintype.card Output) *
          Complex.normSq (coefficient rest) := by
        apply Finset.sum_le_sum
        intro rest _
        exact fiber_failure_mass_le (arity rest) cap (bounded rest)
          (coefficient rest)
    _ = ((2 * cap : Nat) : ℝ) / Fintype.card Output *
        ∑ rest : Rest, Complex.normSq (coefficient rest) := by
      rw [Finset.mul_sum]

theorem terminal_known_claims_failure_le_of_subnormalized
    (arity : Rest → Nat) (coefficient : Rest → ℂ) (cap : Nat)
    (bounded : ∀ rest, arity rest ≤ cap)
    (subnormalized : restNormSquared coefficient ≤ 1) :
    terminalFailureMass (Output := Output) arity coefficient ≤
      ((2 * cap : Nat) : ℝ) / Fintype.card Output := by
  have factorNonnegative :
      0 ≤ ((2 * cap : Nat) : ℝ) / Fintype.card Output := by positivity
  exact (terminal_known_claims_failure_le arity coefficient cap bounded).trans
    (by simpa using mul_le_mul_of_nonneg_left subnormalized factorNonnegative)

/-! ## Full-vector retention and coordinate-only X claims -/

/-- Extraction may consume only one coordinate of a retained full-vector
answer.  The terminal claim remains the complete physical answer. -/
def CoordinateClaimSatisfied
    (project : Output → Coordinate) (expected : Coordinate)
    (fullOutput : Output) : Prop :=
  project fullOutput = expected

theorem retained_full_output_supplies_coordinate
    (project : Output → Coordinate) (expected : Coordinate)
    (fullOutput : Output)
    (projected : project fullOutput = expected) :
    CoordinateClaimSatisfied project expected fullOutput := by
  simpa [CoordinateClaimSatisfied] using projected

/-- A coordinate-only X claim is sound only when the query suffix retained the
entire physical full-vector answer from which this coordinate is projected.
Padding coordinates are not guessed, measured separately, or discarded. -/
structure RetainedPhysicalClaim (Key : Type*) where
  key : Key
  fullOutput : Output
  coordinate : Coordinate
  project : Output → Coordinate
  coordinate_eq : project fullOutput = coordinate

theorem retained_physical_claim_coordinate
    {Key : Type*} (claim : RetainedPhysicalClaim
      (Output := Output) (Coordinate := Coordinate) Key) :
    CoordinateClaimSatisfied claim.project claim.coordinate
      claim.fullOutput := by
  exact claim.coordinate_eq

/-! The query suffix that creates these classical full-output claims must be
included in the global query/support cap.  The theorem above applies only
after the last such read and before any later write to a claimed oracle key.
Those are execution-order premises to be discharged by the concrete RP05
suffix; they are not encoded as a probability assumption here. -/

#print axioms terminal_failure_eq_total_sub_retained
#print axioms terminal_known_claims_failure_le

end
end HegemonCrypto.SmallWood.SmzaRp05TerminalKnownClaims
