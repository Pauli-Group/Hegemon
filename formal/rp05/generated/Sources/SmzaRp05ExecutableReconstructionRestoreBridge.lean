import SmzaRp05ExecutableRestore
import SmzaRp05ExecutableReconstruction
import Mathlib.Logic.Equiv.Fin.Basic

/-!
# Computable restoration and correction inside the proof-connected suffix

SOURCE-ONLY, NOT COMPILED. `linearWords` computes seven-point restoration
with the appended zero point/value and then the actual packing correction.
It returns only coefficients 1..132, as Rust does. `nonlinearWords` calls
the checked six-point restoration on evaluations calculated from the SAME
existing decoded highs/row scalars, statement, matrix and opening.

`final_coefficient_arrays` is the intended exact join to FinalVerifier's
ReconstructedTranscript. No EvaluationTrace, corrected coefficients,
acceptance, or extraction certificate is supplied to that theorem.

Computability boundary remains precise: the restoration/correction kernels
above `noncomputable section` are executable; current relation evaluation
in ExecutableReconstruction.evaluation and the typed admissible challenge
derivation are still mathematical/upstream. Import checking may be blocked
by RawScalarChecks/RelationRefinement dependencies. This file neither proves
Rust machine arithmetic/refinement nor claims full verifier acceptance.
-/

namespace HegemonCrypto.SmallWood.SmzaRp05ExecutableReconstructionRestoreBridge

open Polynomial DecsRestore
open V8Smz9PiopReconstruction V8Smz9PiopSoundness
open V8Smz9AdaptiveFiniteAccounting
open SmzaRp05RelationRefinement SmzaRp05StatementNamespace
open SmzaRp05RawScalarChecks
open SmzaRp05ExecutableChallengeStage (FieldWord)
open V8SmzaOracleParser (RawDigest)
open scoped BigOperators

local notation "Statement" => SmzaRp05StatementNamespace.Statement

set_option autoImplicit false

abbrev E := SmzaRp05ExecutableRestore.Expr

/-- Source order: six opening points followed by zero. -/
def sevenPoints (points : Fin 6 → Goldilocks) (i : Fin 7) : Goldilocks :=
  match finSuccEquivLast i with
  | none => 0
  | some j => points j

def sevenValues (values : Fin 6 → Goldilocks) (i : Fin 7) : Goldilocks :=
  match finSuccEquivLast i with
  | none => 0
  | some j => values j

def linearBase (points values : Fin 6 → Goldilocks) (high : Fin 126 → Goldilocks) : E :=
  SmzaRp05ExecutableRestore.restore (sevenPoints points) (sevenValues values) high

/-- Lagrange polynomial for the appended zero node, in product form. -/
def zeroLagrange (points : Fin 6 → Goldilocks) : E :=
  .mul (SmzaRp05ExecutableRestore.productExpr 6 fun i =>
    .add (.term 1 1) (.term 0 (-points i)))
    (.term 0 ((∏ i, -points i)⁻¹))

def correct (points : Fin 6 → Goldilocks) (packing : Fin 64 → Goldilocks)
    (base : E) (target : Goldilocks) : E :=
  let lag := zeroLagrange points
  let factor := ∑ lane, SmzaRp05ExecutableRestore.eval lag (packing lane)
  let residual := target - ∑ lane, SmzaRp05ExecutableRestore.eval base (packing lane)
  .add base (.mul (.term 0 (residual / factor)) lag)

def linearWords (points values : Fin 6 → Goldilocks) (high : Fin 126 → FieldWord)
    (packing : Fin 64 → Goldilocks) (target : Goldilocks) : Fin 132 → FieldWord :=
  fun i => SmzaRp05ExecutableRestore.toWord
    (SmzaRp05ExecutableRestore.coefficient
      (correct points packing (linearBase points values
        (fun j => SmzaRp05ExecutableRestore.toField (high j))) target) (i.val + 1))

noncomputable section

open SmzaRp05ExecutableRestore

theorem word_roundtrip (value : Goldilocks) : toField (toWord value) = value :=
  toGoldilocks_fromGoldilocks value

theorem appended_zero (points values : Fin 6 → Goldilocks) :
    sevenPoints points (Fin.last 6) = 0 ∧ sevenValues values (Fin.last 6) = 0 := by
  simp only [sevenPoints, sevenValues, finSuccEquivLast_last]
  exact ⟨trivial, trivial⟩

theorem seven_high_eq (high : Fin 126 → Goldilocks) :
    denote (highPart 7 high) = V8Smz9PiopReconstruction.linearHighPart high := by
  simp only [highPart, denote_sum, denote, V8Smz9PiopReconstruction.linearHighPart,
    Polynomial.C_mul_X_pow_eq_monomial]

/-- Reindexing the appended-zero interpolation changes no polynomial. -/
theorem linear_base_eq (opening : Opening) (values : Fin 6 → Goldilocks)
    (high : Fin 126 → Goldilocks) :
    denote (linearBase (points opening) values high) =
      restoredLinearBase opening high values := by
  rw [linearBase, restore_eq, seven_high_eq]
  symm
  apply restore_polynomial_unique
    ((augmented_points_injective opening).comp finSuccEquivLast.injective).injOn
  · intro degree above
    apply restore_polynomial_same_high_coefficients
      (augmented_points_injective opening).injOn
    simpa using above
  · intro i _
    exact restore_polynomial_eval (augmented_points_injective opening).injOn
      (Finset.mem_univ (finSuccEquivLast i))

theorem zero_lagrange_eq (points : Fin 6 → Goldilocks) :
    denote (zeroLagrange points) = LinearPiopExact.normalizedRootPolynomial points := by
  simp only [zeroLagrange, denote, denote_product, Polynomial.monomial_one_one_eq_X,
    Polynomial.monomial_zero_left, map_neg, ← sub_eq_add_neg,
    LinearPiopExact.normalizedRootPolynomial, LinearPiopExact.rootPolynomial,
    LinearPiopExact.rootDenominator]

theorem correction_eq (opening : Opening) (base : E) (target : Goldilocks) :
    denote (correct (points opening) packingPoint base target) =
      correctedLinear opening (denote base) target := by
  simp only [correct, denote, Polynomial.monomial_zero_left, eval_correct,
    zero_lagrange_eq]
  rw [show (∑ lane : Fin 64,
      (LinearPiopExact.normalizedRootPolynomial (points opening)).eval (packingPoint lane)) =
      V8Smz9ZeroKnowledge.linearPiopCorrectionFactor (points opening) from
        correction_packing_sum opening]
  rfl

/-- The existing seven-word-array API computes this same uncorrected base;
the final source correction is deliberately performed only afterwards. -/
theorem seven_words_base (opening : Opening) (values : Fin 6 → Goldilocks)
    (high : Fin 126 → FieldWord) (i : Fin 133) :
    restoreSevenWords (fun j => toWord (sevenPoints (points opening) j))
      (fun j => toWord (sevenValues values j)) high i =
      toWord ((restoredLinearBase opening (fun j => toField (high j)) values).coeff i.val) := by
  simp only [restoreSevenWords, word_roundtrip, coefficient_correct]
  change toWord ((denote (linearBase (points opening) values
    (fun j => toField (high j)))).coeff i.val) = _
  rw [linear_base_eq]

def nonlinearWords (dsl : RelationDsl) (statement : Statement)
    (matrix : Matrix (dsl.width statement)) (opening : Opening)
    (proof : SmzaRp05ExecutableReconstruction.DecodedPiopFields) :
    Fin 5 → Fin 489 → FieldWord :=
  fun row => restoreSixWords (fun j => toWord (points opening j))
    (fun j => toWord ((SmzaRp05ExecutableReconstruction.evaluation
      dsl statement matrix opening proof).nonlinear row j)) (proof.nonlinearHighs row)

def correctedWords (dsl : RelationDsl) (statement : Statement)
    (matrix : Matrix (dsl.width statement)) (opening : Opening)
    (proof : SmzaRp05ExecutableReconstruction.DecodedPiopFields) :
    Fin 5 → Fin 132 → FieldWord :=
  fun row => linearWords (points opening)
    ((SmzaRp05ExecutableReconstruction.evaluation dsl statement matrix opening proof).linear row)
    (proof.linearHighs row) packingPoint (publicBatchedTarget dsl statement matrix row)

/-- Exact final arrays, derived from existing proof fields and computed
relation evaluations, with zero interpolation and public correction included. -/
theorem final_coefficient_arrays (dsl : RelationDsl) (statement : Statement)
    (matrix : Matrix (dsl.width statement)) (opening : Opening)
    (proof : SmzaRp05ExecutableReconstruction.DecodedPiopFields)
    (hashFpp : RawDigest) (pending : Bool) :
    nonlinearWords dsl statement matrix opening proof =
      (SmzaRp05ExecutableReconstruction.reconstruct
        dsl statement matrix opening proof hashFpp pending).nonlinear ∧
    correctedWords dsl statement matrix opening proof =
      (SmzaRp05ExecutableReconstruction.reconstruct
        dsl statement matrix opening proof hashFpp pending).linearHigh := by
  constructor
  · funext row i
    simp only [nonlinearWords, restoreSixWords, word_roundtrip, coefficient_correct,
      six_restore_eq]
    rfl
  · funext row i
    simp only [correctedWords, linearWords, coefficient_correct, correction_eq, linear_base_eq]
    rfl

end
end HegemonCrypto.SmallWood.SmzaRp05ExecutableReconstructionRestoreBridge
