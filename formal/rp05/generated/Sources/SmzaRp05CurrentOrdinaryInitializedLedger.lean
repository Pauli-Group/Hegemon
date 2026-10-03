import SmzaRp05CurrentOrdinarySecurityLedger
import SmzaRp05OrdinaryPrefixNorm
import SmzaRp05VectorRetention
import SmzaRp05GroupedSuffix

/-! Concrete initialized scalar closure for the ordinary current-406 bound.
This derives the norm of the actual ordinary prefix internally.  It does not
establish any event inclusion or accepted-execution coverage. -/

namespace HegemonCrypto.SmallWood.SmzaRp05CurrentOrdinaryInitializedLedger

open scoped Classical BigOperators
open HegemonCrypto.CmsCompressedOracle
open HegemonCrypto.CmsOracleSimulation
open HegemonCrypto.CmsQuerySequence (BoundedState)
open SmzaChallengeStageTargets (Role)
open SmzaRp05CurrentAdaptiveExecution (Work)
open SmzaRp05Current406EventSpec (current406Bound)
open SmzaRp05CurrentOrdinarySecurityLedger
open SmzaRp05OrdinarySoundnessExecution (OrdinaryPrefix ordinaryRun)
open SmzaRp05OrdinaryPrefixNorm (ordinary_run_norm_squared_le)
open SmzaRp05VectorRetention (vector_output_cardinality_ge_digest)
open SmzaRp05GroupedSuffix (GroupCounter groupZero)
open V8Smz9CoherentVectorMerkle (VectorOutput)

noncomputable section
set_option autoImplicit false
set_option maxRecDepth 30000
set_option maxHeartbeats 1600000
set_option exponentiation.threshold 1024

variable {Key BaseWork : Type}
  [Fintype Key] [DecidableEq Key]
  [Fintype BaseWork] [DecidableEq BaseWork]

/-- The exact ordinary scalar RHS used by
`ordinary_selected_readout_collision_scalar_bound` is below the closed
130-bit threshold for a normalized empty-database input and a bounded
protocol lifetime.  The empty-database support bound and prefix norm are
derived here; callers provide only input normalization and the ordinary
schedule/lifetime bounds. -/
theorem ordinary_scalar_rhs_below_130
    {cap finish queries : Nat}
    (ordinaryProgram : OrdinaryPrefix (Key := Key) (Counter := GroupCounter)
      (BaseWork := BaseWork) (cap := cap) 0 finish queries)
    (registers : RegisterBasis (Input := Key)
      (Phase := VectorOutput GroupCounter)
      (Workspace := Work (Counter := GroupCounter) (BaseWork := BaseWork)) → ℂ)
    (depth : Nat)
    (incomingUnit : normSquared
      (partialRandomOracleState (Output := VectorOutput GroupCounter) ∅ registers) = 1)
    (capBound : cap ≤ 3 * 2^64)
    (queriesWithin : queries + depth ≤ cap) :
    (∑ role : Role,
      (6 * (cap : ℝ)^2 * current406Bound role cap) *
        normSquared (partialRandomOracleState
          (Output := VectorOutput GroupCounter) ∅ registers)) +
      (16 * (depth : ℝ) / Fintype.card (VectorOutput GroupCounter)) *
        normSquared (ordinaryRun ordinaryProgram
          (partialRandomOracleState (Output := VectorOutput GroupCounter) ∅ registers)) +
      (∑ _role : Role,
        (6 * (cap : ℝ)^2 *
          ((((cap : Rat) / (2 : Rat)^512 : Rat) : ℝ))) *
          normSquared (partialRandomOracleState
            (Output := VectorOutput GroupCounter) ∅ registers)) <
      ((1 / (2 : Rat)^130 : Rat) : ℝ) := by
  let initial := partialRandomOracleState
    (Output := VectorOutput GroupCounter) ∅ registers
  let prefixState := ordinaryRun ordinaryProgram initial
  have initialBounded : BoundedState 0 initial :=
    partial_random_oracle_empty_bounded registers
  have prefixNormLeInitial : normSquared prefixState ≤ normSquared initial :=
    ordinary_run_norm_squared_le ordinaryProgram initial initialBounded
  have prefixNormLeOne : normSquared prefixState ≤ 1 := by
    rw [incomingUnit] at prefixNormLeInitial
    exact prefixNormLeInitial
  have prefixNormNonnegative : 0 ≤ normSquared prefixState := by
    unfold normSquared
    exact Finset.sum_nonneg (fun _ _ => Complex.normSq_nonneg _)
  have outputCardBound : 2^512 ≤ Fintype.card (VectorOutput GroupCounter) :=
    vector_output_cardinality_ge_digest groupZero
  have outputCardBoundReal :
      (2 : ℝ)^512 ≤ (Fintype.card (VectorOutput GroupCounter) : ℝ) := by
    have castBound :
        ((2^512 : Nat) : ℝ) ≤
          ((Fintype.card (VectorOutput GroupCounter) : Nat) : ℝ) :=
      Nat.cast_le.mpr outputCardBound
    simpa only [Nat.cast_pow, Nat.cast_ofNat] using castBound
  have readoutNumeratorNonnegative : 0 ≤ 16 * (depth : ℝ) :=
    mul_nonneg (by norm_num) (Nat.cast_nonneg depth)
  have readoutDenominatorBound :
      16 * (depth : ℝ) / Fintype.card (VectorOutput GroupCounter) ≤
        16 * (depth : ℝ) / (2 : ℝ)^512 :=
    div_le_div_of_nonneg_left readoutNumeratorNonnegative
      (pow_pos (by norm_num : (0 : ℝ) < 2) 512) outputCardBoundReal
  have actualReadoutBound :
      (16 * (depth : ℝ) / Fintype.card (VectorOutput GroupCounter)) *
      normSquared prefixState ≤
        (16 * (depth : ℝ) / (2 : ℝ)^512) * normSquared prefixState :=
    mul_le_mul_of_nonneg_right readoutDenominatorBound prefixNormNonnegative
  have depthWithin : depth ≤ cap := by omega
  have closed := current_ordinary_scalar_below_130_bits cap depth capBound depthWithin
  have closedReal :
      ((currentOrdinaryScalarLoss cap depth : Rat) : ℝ) <
        ((1 / (2 : Rat)^130 : Rat) : ℝ) := by
    exact_mod_cast closed
  have scalarLedger := weighted_current_ordinary_scalar_le cap depth
    (normSquared (partialRandomOracleState
      (Output := VectorOutput GroupCounter) ∅ registers))
    (normSquared (ordinaryRun ordinaryProgram
      (partialRandomOracleState (Output := VectorOutput GroupCounter) ∅ registers))) incomingUnit
    prefixNormNonnegative prefixNormLeOne
  have actualReadoutBound' :
      (16 * (depth : ℝ) / Fintype.card (VectorOutput GroupCounter)) *
        normSquared (ordinaryRun ordinaryProgram
          (partialRandomOracleState (Output := VectorOutput GroupCounter) ∅ registers)) ≤
        (16 * (depth : ℝ) / (2 : ℝ)^512) *
          normSquared (ordinaryRun ordinaryProgram
            (partialRandomOracleState (Output := VectorOutput GroupCounter) ∅ registers)) := by
    simpa only [initial, prefixState] using actualReadoutBound
  have actualToIdeal :
      (∑ role : Role,
        (6 * (cap : ℝ)^2 * current406Bound role cap) *
          normSquared (partialRandomOracleState
            (Output := VectorOutput GroupCounter) ∅ registers)) +
        (16 * (depth : ℝ) / Fintype.card (VectorOutput GroupCounter)) *
          normSquared (ordinaryRun ordinaryProgram
            (partialRandomOracleState (Output := VectorOutput GroupCounter) ∅ registers)) +
        (∑ _role : Role,
          (6 * (cap : ℝ)^2 *
            ((((cap : Rat) / (2 : Rat)^512 : Rat) : ℝ))) *
            normSquared (partialRandomOracleState
              (Output := VectorOutput GroupCounter) ∅ registers)) ≤
      (∑ role : Role,
        (6 * (cap : ℝ)^2 * current406Bound role cap) *
          normSquared (partialRandomOracleState
            (Output := VectorOutput GroupCounter) ∅ registers)) +
        (16 * (depth : ℝ) / (2 : ℝ)^512) *
          normSquared (ordinaryRun ordinaryProgram
            (partialRandomOracleState (Output := VectorOutput GroupCounter) ∅ registers)) +
        (∑ _role : Role,
          (6 * (cap : ℝ)^2 *
            ((((cap : Rat) / (2 : Rat)^512 : Rat) : ℝ))) *
            normSquared (partialRandomOracleState
              (Output := VectorOutput GroupCounter) ∅ registers)) := by
    exact add_le_add (add_le_add le_rfl actualReadoutBound') le_rfl
  calc
    _ ≤ ((currentOrdinaryScalarLoss cap depth : Rat) : ℝ) :=
      le_trans actualToIdeal scalarLedger
    _ < ((1 / (2 : Rat)^130 : Rat) : ℝ) := closedReal

end
end HegemonCrypto.SmallWood.SmzaRp05CurrentOrdinaryInitializedLedger
