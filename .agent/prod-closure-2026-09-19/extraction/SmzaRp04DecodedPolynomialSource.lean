import HegemonCrypto.SmallWoodV8Smz9McaSourceBinding
import HegemonCrypto.SmallWoodV8Smz9CurrentProgramOpeningBinding
import SmzaRp04PublicContext
import HegemonCrypto.SmallWoodV8Smz9PiopSoundness

/-!
# Arbitrary decoded rows to actual PCS polynomials

The inverse layout consumes the calculated DECS candidate, not honest prover
coins. The source's last-column reconstruction shifts are 419 and 63. Thus
arbitrary degree-69 columns already give degree-488 and degree-132 masks;
no cancellation between presumed honest PCS coins is needed for soundness.
-/

namespace HegemonCrypto.SmallWood.SmzaRp04DecodedPolynomialSource

open Polynomial
open V8Smz9McaDecoder V8Smz9McaDecoder.SourceBinding
open V8Smz9EagerPrivacy V8Smz9EagerSimulator SmzaRp04ProgramPiop
open V8Smz9CurrentProgramOpeningBinding SmzaRp04PublicContext
open V8Smz9ZeroKnowledge
open Hegemon.Transaction.Poseidon2V8RelationProgram
open scoped BigOperators Classical

noncomputable section
set_option maxRecDepth 5000
set_option maxHeartbeats 1000000
set_option backward.isDefEq.respectTransparency false

abbrev SourcePolynomials := DecodedSource Goldilocks (Fin 5) 140

/-- Original rotated head positions 20..387, before the 70-by-736 inverse stack. -/
def rowHead (source : SourcePolynomials) (row : Fin 140) (column : Fin 368) : Goldilocks :=
  (source.data row).eval ((20 + column.val : ℕ) : Goldilocks)

def unstackedCell (source : SourcePolynomials) (coefficient : Fin 70) (column : Fin 736) :
    Goldilocks :=
  let blockAndColumn := (finProdFinEquiv : Fin 2 × Fin 368 ≃ Fin 736).symm column
  rowHead source (finProdFinEquiv (blockAndColumn.1, coefficient)) blockAndColumn.2

/-- Every unstacked column is the coefficient polynomial of its exact 70 cells. -/
def columnPolynomial (source : SourcePolynomials) (column : Fin 736) : Goldilocks[X] :=
  ∑ coefficient : Fin 70, C (unstackedCell source coefficient column) * X ^ coefficient.val

theorem column_polynomial_degree (source : SourcePolynomials) (column : Fin 736) :
    (columnPolynomial source column).natDegree ≤ 69 := by
  unfold columnPolynomial
  apply natDegree_sum_le_of_forall_le
  intro coefficient _
  refine natDegree_mul_le.trans ?_
  simp only [natDegree_C, natDegree_X_pow, zero_add]
  omega

theorem column_polynomial_coefficient (source : SourcePolynomials)
    (column : Fin 736) (coefficient : Fin 70) :
    (columnPolynomial source column).coeff coefficient.val =
      unstackedCell source coefficient column :=
  coefficient_polynomial_coefficient (fun coefficient => unstackedCell source coefficient column)
    coefficient

/-- Inverting the stack and taking coefficients recovers every original head. -/
theorem decoded_heads_roundtrip (source : SourcePolynomials) :
    sourceStackedHeads (fun column coefficient =>
      (columnPolynomial source column).coeff coefficient.val) = rowHead source := by
  funext row column
  obtain ⟨pair, rfl⟩ := (finProdFinEquiv : Fin 2 × Fin 70 ≃ Fin 140).surjective row
  rw [source_stacked_head_at_row_major_index, column_polynomial_coefficient]
  simp only [unstackedCell, Equiv.symm_apply_apply]

def columnLayout (source : SourcePolynomials) : SourceColumnLayout Goldilocks[X] :=
  sourceColumnLayoutEquiv Goldilocks[X] (columnPolynomial source)

def witnessPolynomials (source : SourcePolynomials) : Fin 686 → Goldilocks[X] :=
  (columnLayout source).1

def nonlinearMasks (source : SourcePolynomials) (row : Fin 5) : Goldilocks[X] :=
  sourceNonlinearReconstruction X ((columnLayout source).2.1 row)

def linearMasks (source : SourcePolynomials) (row : Fin 5) : Goldilocks[X] :=
  (columnLayout source).2.2 row 0 + X ^ 63 * (columnLayout source).2.2 row 1

theorem witness_polynomials_degree (source : SourcePolynomials) (row : Fin 686) :
    (witnessPolynomials source row).natDegree ≤ 69 :=
  column_polynomial_degree source _

theorem nonlinear_column_degree (source : SourcePolynomials) (row : Fin 5) (column : Fin 8) :
    ((columnLayout source).2.1 row column).natDegree ≤ 69 :=
  column_polynomial_degree source _

theorem linear_column_degree (source : SourcePolynomials) (row : Fin 5) (column : Fin 2) :
    ((columnLayout source).2.2 row column).natDegree ≤ 69 :=
  column_polynomial_degree source _

theorem shifted_column_degree (column : Goldilocks[X]) (bounded : column.natDegree ≤ 69)
    (shift limit : ℕ) (fits : shift + 69 ≤ limit) :
    (X ^ shift * column).natDegree ≤ limit := by
  exact natDegree_mul_le.trans (by simpa only [natDegree_X_pow] using
    (Nat.add_le_add_left bounded shift).trans fits)

/-- The shortened final source shift, not seven full 64-row shifts. -/
theorem arbitrary_nonlinear_reconstruction_degree (columns : Fin 8 → Goldilocks[X])
    (bounded : ∀ column, (columns column).natDegree ≤ 69) :
    (sourceNonlinearReconstruction X columns).natDegree ≤ 488 := by
  unfold sourceNonlinearReconstruction
  repeat' apply natDegree_add_le_of_degree_le
  · exact (bounded 0).trans (by decide)
  all_goals exact shifted_column_degree _ (bounded _) _ 488 (by decide)

theorem nonlinear_masks_degree (source : SourcePolynomials) (row : Fin 5) :
    (nonlinearMasks source row).natDegree ≤ 488 :=
  arbitrary_nonlinear_reconstruction_degree _ (nonlinear_column_degree source row)

theorem linear_masks_degree (source : SourcePolynomials) (row : Fin 5) :
    (linearMasks source row).natDegree ≤ 132 := by
  apply natDegree_add_le_of_degree_le
  · exact (linear_column_degree source row 0).trans (by decide)
  · exact shifted_column_degree _ (linear_column_degree source row 1) 63 132 (by decide)

theorem nonlinear_masks_evaluate (source : SourcePolynomials) (row : Fin 5) (point : Goldilocks) :
    (nonlinearMasks source row).eval point =
      sourceNonlinearReconstruction point (fun column => ((columnLayout source).2.1 row column).eval point) := by
  simp only [nonlinearMasks, sourceNonlinearReconstruction, eval_add, eval_mul, eval_pow, eval_X]

theorem linear_masks_evaluate (source : SourcePolynomials) (row : Fin 5) (point : Goldilocks) :
    (linearMasks source row).eval point =
      ((columnLayout source).2.2 row 0).eval point +
        point ^ 63 * ((columnLayout source).2.2 row 1).eval point := by
  simp only [linearMasks, eval_add, eval_mul, eval_pow, eval_X]

def packedWitness (source : SourcePolynomials) : List Nat :=
  List.ofFn fun index : Fin 43904 =>
    let rowAndLane := (finProdFinEquiv : Fin 686 × Fin 64 ≃ Fin 43904).symm index
    ((witnessPolynomials source rowAndLane.1).eval (canonicalPacking rowAndLane.2)).val

theorem packed_witness_canonical (source : SourcePolynomials) :
    CanonicalPackedWitness (packedWitness source) := by
  constructor
  · simp only [packedWitness, List.length_ofFn]
    rfl
  · intro word member
    obtain ⟨index, rfl⟩ := List.mem_ofFn.mp member
    exact ZMod.val_lt _

theorem packed_witness_matches_polynomial (source : SourcePolynomials)
    (row : Fin 686) (lane : Fin 64) :
    packingValues (packedWitness source) row lane =
      (witnessPolynomials source row).eval (canonicalPacking lane) := by
  have atIndex (index : Fin 43904) :
      (packedWitness source).getD index.val 0 =
        ((witnessPolynomials source
          ((finProdFinEquiv : Fin 686 × Fin 64 ≃ Fin 43904).symm index).1).eval
          (canonicalPacking
            ((finProdFinEquiv : Fin 686 × Fin 64 ≃ Fin 43904).symm index).2)).val := by
    simp only [packedWitness, List.getD_eq_getElem?_getD,
      List.getElem?_ofFn, Fin.isLt, ↓reduceDIte, Option.getD_some]
  change ((packedWitness source).getD (finProdFinEquiv (row, lane)).val 0 : Goldilocks) = _
  rw [atIndex, Equiv.symm_apply_apply]
  exact ZMod.natCast_zmod_val ((witnessPolynomials source row).eval (canonicalPacking lane))

/-- Genuine data-independent geometry supplies all PIOP degree hypotheses even
for an arbitrary decoded object. No relation-satisfaction claim is made here. -/
theorem decoded_polynomial_degree_contract (source : SourcePolynomials) :
    (∀ row, (witnessPolynomials source row).natDegree ≤ 69) ∧
      (∀ row, (nonlinearMasks source row).natDegree ≤ 488) ∧
      (∀ row, (linearMasks source row).natDegree ≤ 132) ∧
      CanonicalPackedWitness (packedWitness source) :=
  ⟨witness_polynomials_degree source, nonlinear_masks_degree source,
    linear_masks_degree source, packed_witness_canonical source⟩

/-- The candidate retains each actual public CSR row separately, before gamma. -/
def retainedLinearWeights (publicValues : List Nat)
    (index : Fin (retainedAttempts publicValues).length) : Fin 686 → Fin 64 → Goldilocks :=
  fun row lane => normalizedCoefficient publicValues
    (retainedAttempts publicValues)[index.val] (finProdFinEquiv (row, lane))

def retainedLinearPolynomial (publicValues : List Nat) (source : SourcePolynomials)
    (index : Fin (retainedAttempts publicValues).length) : Goldilocks[X] :=
  V8Smz9PiopOpeningRecovery.sourceLinearUnmasked (retainedLinearWeights publicValues index)
    (V8Smz9PiopOpeningRecovery.sourcePackingLagrange canonicalPacking)
    (witnessPolynomials source)

theorem canonical_packing_injective : Function.Injective canonicalPacking :=
  V8Smz9AdaptiveFiniteAccounting.packingPoint_injective

theorem retained_linear_polynomial_degree (publicValues : List Nat) (source : SourcePolynomials)
    (index : Fin (retainedAttempts publicValues).length) :
    (retainedLinearPolynomial publicValues source index).natDegree ≤ 132 :=
  V8Smz9PiopOpeningRecovery.source_linear_unmasked_degree canonicalPacking
    canonical_packing_injective _ _ (witness_polynomials_degree source)

def paddedNonlinear (publicValues : List Nat) (source : SourcePolynomials)
    (index : Fin (batchingWidth publicValues)) : Goldilocks[X] :=
  if bound : index.val < 773 then
    currentConstraints (publicParameters publicValues 0) (witnessPolynomials source) ⟨index.val, bound⟩
  else 0

def paddedLinear (publicValues : List Nat) (source : SourcePolynomials)
    (index : Fin (batchingWidth publicValues)) : Goldilocks[X] :=
  if bound : index.val < (retainedAttempts publicValues).length then
    retainedLinearPolynomial publicValues source ⟨index.val, bound⟩
  else 0

def paddedTarget (publicValues : List Nat) (index : Fin (batchingWidth publicValues)) : Goldilocks :=
  if bound : index.val < (retainedAttempts publicValues).length then
    rowTarget publicValues (retainedAttempts publicValues)[index.val]
  else 0

/-- No degree, valid-relation, honest-coin, or post-gamma witness hypothesis is supplied. -/
def sourcePiopCandidate (publicValues : List Nat) (source : SourcePolynomials) :
    V8Smz9PiopSoundness.Candidate (batchingWidth publicValues) where
  nonlinear := paddedNonlinear publicValues source
  linear := paddedLinear publicValues source
  target := paddedTarget publicValues
  nonlinearMask := nonlinearMasks source
  linearMask := linearMasks source
  nonlinearDegree index := by
    unfold paddedNonlinear
    split
    · exact current_constraint_degree _ _ (witness_polynomials_degree source) _
    · simp only [natDegree_zero]; omega
  linearDegree index := by
    unfold paddedLinear
    split
    · exact retained_linear_polynomial_degree _ _ _
    · simp only [natDegree_zero]; omega
  nonlinearMaskDegree := nonlinear_masks_degree source
  linearMaskDegree := linear_masks_degree source

theorem source_candidate_nonlinear_at (publicValues : List Nat) (source : SourcePolynomials)
    (index : Fin 773) :
    (sourcePiopCandidate publicValues source).nonlinear
      ⟨index.val, index.isLt.trans_le (Nat.le_max_left _ _)⟩ =
      currentConstraints (publicParameters publicValues 0) (witnessPolynomials source) index := by
  simp only [sourcePiopCandidate, paddedNonlinear, dif_pos index.isLt]

theorem source_candidate_linear_at (publicValues : List Nat) (source : SourcePolynomials)
    (index : Fin (retainedAttempts publicValues).length) :
    (sourcePiopCandidate publicValues source).linear
      ⟨index.val, index.isLt.trans_le (Nat.le_max_right _ _)⟩ =
      retainedLinearPolynomial publicValues source index := by
  simp only [sourcePiopCandidate, paddedLinear, dif_pos index.isLt]

theorem source_candidate_target_at (publicValues : List Nat) (source : SourcePolynomials)
    (index : Fin (retainedAttempts publicValues).length) :
    (sourcePiopCandidate publicValues source).target
      ⟨index.val, index.isLt.trans_le (Nat.le_max_right _ _)⟩ =
      rowTarget publicValues (retainedAttempts publicValues)[index.val] := by
  simp only [sourcePiopCandidate, paddedTarget, dif_pos index.isLt]

/-- Unbatched actual nonlinear roots and retained normalized CSR equations,
on the calculated row-major packed projection. -/
def DecodedSourceRelation (publicValues : List Nat) (source : SourcePolynomials) : Prop :=
  (∀ root lane, currentConstraintOpenings (publicParameters publicValues 0)
    (fun row => packingValues (packedWitness source) row lane) root = 0) ∧
  (∀ index : Fin (retainedAttempts publicValues).length,
    (∑ row : Fin 686, ∑ lane : Fin 64,
      retainedLinearWeights publicValues index row lane *
        packingValues (packedWitness source) row lane) =
      rowTarget publicValues (retainedAttempts publicValues)[index.val])

theorem fully_satisfied_candidate_supplies_decoded_source_relation
    (publicValues : List Nat) (source : SourcePolynomials)
    (satisfied : PiopExtraction.FullySatisfied (sourcePiopCandidate publicValues source).system) :
    DecodedSourceRelation publicValues source := by
  constructor
  · intro root lane
    let index : Fin (batchingWidth publicValues) :=
      ⟨root.val, root.isLt.trans_le (Nat.le_max_left _ _)⟩
    have zero := satisfied.1 index lane (Finset.mem_univ _)
    change ((sourcePiopCandidate publicValues source).nonlinear index).eval
      (canonicalPacking lane) = 0 at zero
    rw [source_candidate_nonlinear_at publicValues source root,
      current_constraint_evaluation _ _ (witness_polynomials_degree source)] at zero
    simpa only [packed_witness_matches_polynomial] using zero
  · intro retained
    let index : Fin (batchingWidth publicValues) :=
      ⟨retained.val, retained.isLt.trans_le (Nat.le_max_right _ _)⟩
    have equal := satisfied.2 index
    change V8Smz9PiopOpeningRecovery.packingSum canonicalPacking
      ((sourcePiopCandidate publicValues source).linear index) =
      (sourcePiopCandidate publicValues source).target index at equal
    rw [source_candidate_linear_at publicValues source retained,
      source_candidate_target_at publicValues source retained] at equal
    unfold retainedLinearPolynomial at equal
    rw [V8Smz9PiopOpeningRecovery.source_linear_packing_sum canonicalPacking
      canonical_packing_injective] at equal
    simpa only [packed_witness_matches_polynomial] using equal

/-- The existing finite PIOP bound now takes an arbitrary decoded source object
and its generated public CSR context, not a caller-supplied polynomial system. -/
theorem invalid_decoded_source_piop_probability_le
    (publicValues : List Nat) (source : SourcePolynomials)
    (response : V8Smz9PiopSoundness.Matrix (batchingWidth publicValues) →
      V8Smz9PiopSoundness.ClaimedTranscript)
    (invalid : ¬ DecodedSourceRelation publicValues source) :
    V8Smz9PiopSoundness.soundnessProbability (sourcePiopCandidate publicValues source) response ≤
      ((1 : Rat) / Fintype.card Goldilocks) ^ 5 + V8Smz9PiopSoundness.epsilon3 :=
  V8Smz9PiopSoundness.invalid_candidate_soundness_probability_le _ _
    (fun satisfied => invalid
      (fully_satisfied_candidate_supplies_decoded_source_relation publicValues source satisfied))

end
end HegemonCrypto.SmallWood.SmzaRp04DecodedPolynomialSource
