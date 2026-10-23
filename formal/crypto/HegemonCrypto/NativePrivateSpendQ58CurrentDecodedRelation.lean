import HegemonCrypto.NativePrivateSpendQ58CurrentPublicFactorizationBase
import HegemonCrypto.NativePrivateSpendQ58CurrentRecovery
import HegemonCrypto.SmallWoodV8Smz9PiopSoundness
import SmzaPiopGoodOutcomeR2

/-! Arbitrary current decoded rows to the current packed relation.
The candidate and witness are built without an honest SourceData or a
PackedPolynomials.valid field. Full PIOP satisfaction implies all literal
CSR and multiplication checks. This is a deterministic component, not an
accepted native-wire or QROM-mass theorem. SOURCE PROPOSAL: not typed yet.
-/
namespace HegemonCrypto.SmallWood.NativePrivateSpendQ58CurrentDecodedRelation

open Polynomial
open V8Smz9McaDecoder
open V8Smz9PiopOpeningRecovery
open V8Smz9ZeroKnowledge
open Hegemon.Transaction.SmallWoodProductionConstraintRefinement
open NativePrivateSpendQ58CurrentPublicOpening
open scoped BigOperators Classical
noncomputable section
set_option autoImplicit false
set_option maxHeartbeats 0
set_option maxRecDepth 0
set_option Elab.async false

abbrev Decoded := DecodedSource Goldilocks (Fin 5) 140

/-- Current rotated DECS heads begin after exactly58 tail nodes. -/
def rowHead (source : Decoded) (row : Fin 140) (head : Fin 13115) : Goldilocks :=
  (source.data row).eval ((58 + head.val : Nat) : Goldilocks)

def unstackedCell (source : Decoded) (coefficient : Fin 70)
    (column : Fin 26230) : Goldilocks :=
  let split := (finProdFinEquiv : Fin 2 × Fin 13115 ≃ Fin 26230).symm column
  rowHead source (finProdFinEquiv (split.1, coefficient)) split.2

def columnPolynomial (source : Decoded) (column : Fin 26230) : Goldilocks[X] :=
  ∑ coefficient : Fin 70,
    C (unstackedCell source coefficient column) * X ^ coefficient.val

theorem column_polynomial_degree (source : Decoded) (column : Fin 26230) :
    (columnPolynomial source column).natDegree ≤ 69 := by
  unfold columnPolynomial
  apply natDegree_sum_le_of_forall_le
  intro coefficient _
  refine natDegree_mul_le.trans ?_
  simp only [natDegree_C, natDegree_X_pow, zero_add]
  omega

theorem column_polynomial_coefficient (source : Decoded)
    (column : Fin 26230) (coefficient : Fin 70) :
    (columnPolynomial source column).coeff coefficient.val =
      unstackedCell source coefficient column :=
  V8Smz9EagerSimulator.coefficient_polynomial_coefficient
    (fun coefficient => unstackedCell source coefficient column) coefficient

/-- Inverting both current row-major maps preserves every head. -/
theorem decoded_heads_roundtrip (source : Decoded) :
    NativePrivateSpendQ58Compff01OpeningContinuation.stackedHeads
      (fun column coefficient => (columnPolynomial source column).coeff coefficient.val) =
        rowHead source := by
  funext row head
  obtain ⟨pair, rfl⟩ := (finProdFinEquiv : Fin 2 × Fin 70 ≃ Fin 140).surjective row
  simp only [NativePrivateSpendQ58Compff01OpeningContinuation.stackedHeads,
    Equiv.symm_apply_apply, column_polynomial_coefficient, unstackedCell]

def witness (source : Decoded) (row : Row) : Goldilocks[X] :=
  columnPolynomial source ⟨row.val, row.isLt.trans_le (by decide)⟩

def nonlinearColumn (source : Decoded) (row : Fin 5) (part : Fin 2) : Goldilocks[X] :=
  columnPolynomial source ⟨26210 + 2 * row.val + part.val, by
    have hr := row.isLt
    have hp := part.isLt
    omega⟩

def linearColumn (source : Decoded) (row : Fin 5) (part : Fin 2) : Goldilocks[X] :=
  columnPolynomial source ⟨26220 + 2 * row.val + part.val, by
    have hr := row.isLt
    have hp := part.isLt
    omega⟩

def nonlinearMask (source : Decoded) (row : Fin 5) : Goldilocks[X] :=
  nonlinearColumn source row 0 + X ^ 5 * nonlinearColumn source row 1

def linearMask (source : Decoded) (row : Fin 5) : Goldilocks[X] :=
  linearColumn source row 0 + X ^ 63 * linearColumn source row 1

theorem witness_degree (source : Decoded) (row : Row) :
    (witness source row).natDegree ≤ 69 := column_polynomial_degree source _

theorem nonlinear_mask_degree (source : Decoded) (row : Fin 5) :
    (nonlinearMask source row).natDegree ≤ 74 := by
  apply natDegree_add_le_of_degree_le
  · exact (column_polynomial_degree source _).trans (by decide)
  · exact natDegree_mul_le.trans (by
      simp only [natDegree_X_pow]
      exact Nat.add_le_add_left (column_polynomial_degree source _) 5)

theorem linear_mask_degree (source : Decoded) (row : Fin 5) :
    (linearMask source row).natDegree ≤ 132 := by
  apply natDegree_add_le_of_degree_le
  · exact (column_polynomial_degree source _).trans (by decide)
  · exact natDegree_mul_le.trans (by
      simp only [natDegree_X_pow]
      exact Nat.add_le_add_left (column_polynomial_degree source _) 63)

/-- No validity proof is bundled into this recovered assignment. -/
def decodedValues (source : Decoded) : Values :=
  fun row lane => (witness source row).eval (packing lane)

def nonlinear (relation : NativePrivateSpendQ58CurrentPublicOpening.Relation) (source : Decoded) (check : Check) : Goldilocks[X] :=
  if bound : check.val < 5210 then
    let batch : Batch := ⟨check.val, bound⟩
    witness source (relation.batch batch 0) -
      witness source (relation.batch batch 1) * witness source (relation.batch batch 2)
  else 0

def linear (relation : NativePrivateSpendQ58CurrentPublicOpening.Relation) (source : Decoded) (check : Check) : Goldilocks[X] :=
  sourceLinearUnmasked (csrWeights (relation.csr check))
    (sourcePackingLagrange packing) (witness source)

theorem nonlinear_degree (relation : NativePrivateSpendQ58CurrentPublicOpening.Relation) (source : Decoded) (check : Check) :
    (nonlinear relation source check).natDegree ≤ 138 := by
  unfold nonlinear
  split
  · apply (natDegree_sub_le _ _).trans
    apply max_le
    · exact (witness_degree source _).trans (by decide)
    · exact natDegree_mul_le.trans
        (Nat.add_le_add (witness_degree source _) (witness_degree source _))
  · simp

theorem linear_degree (relation : NativePrivateSpendQ58CurrentPublicOpening.Relation) (source : Decoded) (check : Check) :
    (linear relation source check).natDegree ≤ 132 :=
  source_linear_unmasked_degree packing packing_injective
    (csrWeights (relation.csr check)) (witness source) (witness_degree source)

/-- Existing generic PIOP structure; the sharper current degree facts remain
available separately. Its legacy counting caps must not be relabeled414. -/
def candidate (relation : NativePrivateSpendQ58CurrentPublicOpening.Relation) (source : Decoded) :
    V8Smz9PiopSoundness.Candidate 1344594 where
  nonlinear := nonlinear relation source
  linear := linear relation source
  target := relation.target
  nonlinearMask := nonlinearMask source
  linearMask := linearMask source
  nonlinearDegree := fun check => (nonlinear_degree relation source check).trans (by decide)
  linearDegree := linear_degree relation source
  nonlinearMaskDegree := fun row => (nonlinear_mask_degree source row).trans (by decide)
  linearMaskDegree := linear_mask_degree source

/-- The implication is proved from the actual sparse terms and multiplication
row addresses. It is not a RelationRefinement callback or endpoint premise. -/
theorem fully_satisfied_implies_current_relation
    (relation : NativePrivateSpendQ58CurrentPublicOpening.Relation) (source : Decoded)
    (satisfied : PiopExtraction.FullySatisfied (candidate relation source).system) :
    Satisfies relation (decodedValues source) := by
  with_reducible
    dsimp only [PiopExtraction.FullySatisfied, V8Smz9PiopSoundness.Candidate.system,
      candidate] at satisfied
    constructor
    · intro check
      have equation : packingSum packing (linear relation source check) =
          relation.target check := by
        simpa only [Interactive.nodeSum, packingSum, packing,
          V8Smz9AdaptiveFiniteAccounting.packingPoint] using satisfied.2 check
      rw [linear, source_linear_packing_sum packing packing_injective,
        csr_dense_matches] at equation
      have valuesEq : decodedValues source =
          (fun row lane => (witness source row).eval (packing lane)) := by
        unfold decodedValues
        rfl
      rw [valuesEq]
      exact equation
    · intro batch lane
      let check : Check := ⟨batch.val, batch.isLt.trans_le (by decide)⟩
      have bound : check.val < 5210 := batch.isLt
      have equation : (nonlinear relation source check).eval (packing lane) = 0 := by
        simpa only [packing, V8Smz9AdaptiveFiniteAccounting.packingPoint] using
          satisfied.1 check lane (Finset.mem_univ lane)
      simp only [nonlinear, dif_pos bound, eval_sub, eval_mul] at equation
      simpa only [decodedValues] using sub_eq_zero.mp equation

/-- This composes the retained algebraic good-outcome theorem with the proved
current relation interpretation. Deriving OpeningAccepts and excluding its
named events from current wire acceptance is a separate remaining source join. -/
theorem accepted_piop_outside_named_events_has_current_witness
    (relation : NativePrivateSpendQ58CurrentPublicOpening.Relation) (source : Decoded)
    (matrix : V8Smz9PiopSoundness.Matrix 1344594)
    (response : V8Smz9PiopSoundness.ClaimedTranscript)
    (opening : V8Smz9PiopSoundness.Opening)
    (accepted : V8Smz9PiopSoundness.OpeningAccepts
      (candidate relation source) matrix response opening)
    (rootDetection : SmzaPiopGoodOutcome.DiscrepanciesDetected
      (candidate relation source) matrix response opening)
    (residualDetection : SmzaPiopGoodOutcome.ResidualsDetected
      (candidate relation source) matrix) :
    Satisfies relation (decodedValues source) :=
  fully_satisfied_implies_current_relation relation source
    (SmzaPiopGoodOutcome.accepted_piop_outside_named_algebraic_events_satisfies_candidate
      (candidate relation source) matrix response opening accepted rootDetection residualDetection)

end
end HegemonCrypto.SmallWood.NativePrivateSpendQ58CurrentDecodedRelation
