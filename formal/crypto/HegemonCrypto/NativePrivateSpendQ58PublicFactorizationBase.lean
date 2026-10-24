import HegemonCrypto.NativePrivateSpendQ58OpaqueAdd
import HegemonCrypto.NativePrivateSpendQ58Wpcs
import HegemonCrypto.SmallWoodV8Smz9PiopOpeningRecovery

/-!
Actual degree-two packed equations -> public mask openings at degree74/132.
The sparse CSR lists and multiplication triples are public relation data.
No mask-opening equality, divisibility, target-sum equality, or distributional
security statement is assumed. Rust/byte refinement is a separate obligation.
-/
namespace HegemonCrypto.SmallWood.NativePrivateSpendQ58PublicFactorization
open Polynomial
open Hegemon.Transaction.SmallWoodProductionConstraintRefinement
open V8Smz9RuntimeFieldLayout V8Smz9EagerPrivacy V8Smz9PiopOpeningRecovery
open V8Smz9ZeroKnowledge V8Smz9EagerSimulator
open scoped BigOperators Classical
noncomputable section
set_option autoImplicit false
set_option Elab.async false
set_option maxHeartbeats 0
set_option maxRecDepth 0

abbrev Row := Fin 26203
abbrev Lane := Fin 64
abbrev Check := Fin 1344146
abbrev Batch := Fin 5210
abbrev Values := Row → Lane → Goldilocks
abbrev Witness := Row → Goldilocks[X]
abbrev Gamma := Check → Goldilocks
abbrev Term := (Row × Lane) × Goldilocks

def packing : Lane → Goldilocks := fun lane => (lane.val : Goldilocks)

theorem packing_injective : Function.Injective packing := by
  intro left right same
  have equal : (⟨left.val, by omega⟩ : Fin 13170) = ⟨right.val, by omega⟩ :=
    NativePrivateSpendQ58SimulationAlgebra.q58_nodes_distinct same
  exact Fin.ext (congrArg (@Fin.val 13170) equal)

theorem packing_card_nonzero : (64 : Goldilocks) ≠ 0 := by
  change (64 : ZMod goldilocksModulus) ≠ 0
  exact (CharP.cast_eq_zero_iff (ZMod goldilocksModulus) goldilocksModulus 64).not.mpr
    (by norm_num [goldilocksModulus])

/-- Literal sparse CSR accumulation, with duplicate terms preserved. -/
def csrValue : List Term → Values → Goldilocks
  | [], _ => 0
  | term :: rest, values => term.2 * values term.1.1 term.1.2 + csrValue rest values

def csrWeights : List Term → Row → Lane → Goldilocks
  | [], _, _ => 0
  | term :: rest, row, lane =>
      (if term.1 = (row, lane) then term.2 else 0) + csrWeights rest row lane

/-- Derive dense notation from the source list; do not assume a CSR target in
some independently normalized relation. -/
theorem csr_dense_matches (terms : List Term) (values : Values) :
    (∑ row, ∑ lane, csrWeights terms row lane * values row lane) = csrValue terms values := by
  induction terms with
  | nil => simp [csrWeights, csrValue]
  | cons term rest ih =>
      rcases term with ⟨⟨selectedRow, selectedLane⟩, coefficient⟩
      simp only [csrWeights, csrValue, add_mul, Finset.sum_add_distrib]
      rw [ih]
      simp [Prod.mk.injEq, ite_and, ite_mul]

structure Relation where
  batch : Batch → Fin 3 → Row
  csr : Check → List Term
  target : Check → Goldilocks

/-- Exactly the two families checked by HtlcAdapter::verify_packed_witness. -/
structure Satisfies (relation : Relation) (values : Values) : Prop where
  linear : ∀ check, csrValue (relation.csr check) values = relation.target check
  multiply : ∀ batch lane, values (relation.batch batch 0) lane =
    values (relation.batch batch 1) lane * values (relation.batch batch 2) lane

/-- These are polynomial construction facts, not privacy hypotheses. Source
poly_restore at K64/open6 supplies them; its Rust refinement remains explicit. -/
structure PackedPolynomials (relation : Relation) where
  values : Values
  polynomial : Witness
  atPacking : ∀ row lane, (polynomial row).eval (packing lane) = values row lane
  degree : ∀ row, (polynomial row).natDegree ≤ 69
  valid : Satisfies relation values

/-- Same explicit K64/open6 row polynomial used by the WPCS component. -/
def honestRows (values : Values) (coins : NativePrivateSpendQ58Wpcs.W) : Witness :=
  fun row => sourceWitnessBasePolynomial (values row) + witnessRandomnessPolynomial (coins row)

theorem base_at_packing (values : Lane → Goldilocks) (node : Lane) :
    (sourceWitnessBasePolynomial values).eval (packing node) = values node := by
  change (∑ lane : Lane, C (values lane) * sourcePackingLagrange packing lane).eval (packing node) = _
  simp only [eval_finsetSum, eval_mul, eval_C]
  simp_rw [source_packing_lagrange_evaluation packing packing_injective]
  simp

theorem base_degree63 (values : Lane → Goldilocks) :
    (sourceWitnessBasePolynomial values).natDegree ≤ 63 := by
  change (∑ lane : Lane, C (values lane) * sourcePackingLagrange packing lane).natDegree ≤ 63
  apply natDegree_sum_le_of_forall_le
  intro lane _
  refine natDegree_mul_le.trans ?_
  simp only [natDegree_C, zero_add]
  have degree := Lagrange.natDegree_basis packing_injective.injOn (Finset.mem_univ lane)
  simpa [sourcePackingLagrange] using degree.le

/-- A concrete constructor discharges the polynomial degree and packing facts
from source interpolation coins, keeping only the literal packed checks as input. -/
def fromPacked (relation : Relation) (values : Values) (valid : Satisfies relation values)
    (coins : NativePrivateSpendQ58Wpcs.W) (points : Fin 6 → Goldilocks)
    (admissible : Smz9WitnessInterpolationAdmissible points) : PackedPolynomials relation where
  values := values
  polynomial := honestRows values coins
  atPacking := by
    intro row lane
    rw [honestRows, eval_add, base_at_packing]
    have zero := witness_randomness_polynomial_eval_packing admissible (coins row) lane
    simpa [packing, smz9PackingPoint] using congrArg (fun value => values row lane + value) zero
  degree := by
    intro row
    apply (natDegree_add_le _ _).trans
    apply max_le
    · exact (base_degree63 (values row)).trans (by decide)
    · simpa [packingFactor,
        Hegemon.Transaction.Poseidon2V8ConstraintRefinement.packingFactor,
        piopOpeningCount] using witness_randomness_polynomial_degree_le admissible (coins row)
  valid := valid

theorem wpcs_openings_are_honest_rows (values : Values) (coins : NativePrivateSpendQ58Wpcs.W)
    (points : Fin 6 → Goldilocks) (admissible : Smz9WitnessInterpolationAdmissible points)
    (row : Row) (opening : Fin 6) :
    NativePrivateSpendQ58Wpcs.witnessEquiv values points admissible coins row opening =
      (honestRows values coins row).eval (points opening) := by
  change (sourceWitnessBasePolynomial (values row)).eval (points opening) +
    (witnessRandomnessPolynomial (coins row)).eval (points opening) = _
  simp [honestRows, eval_add]

def nonlinearGamma (gamma : Gamma) (batch : Batch) : Goldilocks :=
  gamma ⟨batch.val, batch.isLt.trans_le (by decide)⟩

def multiplicationPolynomial (relation : Relation) (witness : Witness) (batch : Batch) :
    Goldilocks[X] := witness (relation.batch batch 0) -
      witness (relation.batch batch 1) * witness (relation.batch batch 2)

def batchedNonlinear (relation : Relation) (gamma : Gamma) (witness : Witness) : Goldilocks[X] :=
  nonlinearBatch (nonlinearGamma gamma) (multiplicationPolynomial relation witness)

def publicNonlinearNumerator (relation : Relation) (gamma : Gamma)
    (opened : Row → Goldilocks) : Goldilocks :=
  ∑ batch, nonlinearGamma gamma batch *
    (opened (relation.batch batch 0) -
      opened (relation.batch batch 1) * opened (relation.batch batch 2))

theorem multiplication_valid (relation : Relation) (source : PackedPolynomials relation)
    (batch : Batch) (lane : Lane) :
    (multiplicationPolynomial relation source.polynomial batch).eval (packing lane) = 0 := by
  simp only [multiplicationPolynomial, eval_sub, eval_mul, source.atPacking]
  exact sub_eq_zero.mpr (source.valid.multiply batch lane)

theorem batched_nonlinear_valid (relation : Relation) (source : PackedPolynomials relation)
    (gamma : Gamma) : ∀ lane,
    (batchedNonlinear relation gamma source.polynomial).eval (packing lane) = 0 :=
  nonlinear_batch_valid packing (nonlinearGamma gamma) _ (multiplication_valid relation source)

theorem multiplication_degree138 (relation : Relation) (source : PackedPolynomials relation)
    (batch : Batch) : (multiplicationPolynomial relation source.polynomial batch).natDegree ≤ 138 := by
  apply (natDegree_sub_le _ _).trans
  apply max_le
  · exact (source.degree _).trans (by decide)
  · exact natDegree_mul_le.trans (Nat.add_le_add (source.degree _) (source.degree _))

theorem batched_degree138 (relation : Relation) (source : PackedPolynomials relation)
    (gamma : Gamma) : (batchedNonlinear relation gamma source.polynomial).natDegree ≤ 138 := by
  unfold batchedNonlinear nonlinearBatch
  apply natDegree_sum_le_of_forall_le
  intro batch _
  refine natDegree_mul_le.trans ?_
  simpa using multiplication_degree138 relation source batch

theorem quotient_degree74 (relation : Relation) (source : PackedPolynomials relation)
    (gamma : Gamma) :
    (sourceNonlinearQuotient packing (batchedNonlinear relation gamma source.polynomial)).natDegree ≤ 74 := by
  rw [sourceNonlinearQuotient,
    natDegree_divByMonic _ (packing_vanishing_monic packing), packing_vanishing_degree]
  have bound := batched_degree138 relation source gamma
  omega

/-- Actual139 source interpolation samples suffice for degree-two constraints. -/
theorem source139_interpolation (relation : Relation) (source : PackedPolynomials relation)
    (batch : Batch) (samples : Fin 139 → Goldilocks) (distinct : Function.Injective samples) :
    Lagrange.interpolate Finset.univ samples
      (fun index => (multiplicationPolynomial relation source.polynomial batch).eval (samples index)) =
      multiplicationPolynomial relation source.polynomial batch := by
  apply (Lagrange.eq_interpolate distinct.injOn _).symm
  have degree := multiplication_degree138 relation source batch
  have degree_lt_nat : (multiplicationPolynomial relation source.polynomial batch).natDegree < 139 := by
    omega
  change (multiplicationPolynomial relation source.polynomial batch).degree < (139 : WithBot Nat)
  have degree_lt_withBot :
      ((multiplicationPolynomial relation source.polynomial batch).natDegree : WithBot Nat) <
        (139 : WithBot Nat) :=
    WithBot.coe_lt_coe.mpr degree_lt_nat
  exact degree_le_natDegree.trans_lt degree_lt_withBot

def consecutiveSamples : Fin 139 → Goldilocks := fun index => (index.val : Goldilocks)

theorem consecutive_samples_distinct : Function.Injective consecutiveSamples := by
  intro left right same
  have equal : (⟨left.val, by omega⟩ : Fin 13170) = ⟨right.val, by omega⟩ :=
    NativePrivateSpendQ58SimulationAlgebra.q58_nodes_distinct same
  exact Fin.ext (congrArg (@Fin.val 13170) equal)

theorem source_consecutive_interpolation (relation : Relation) (source : PackedPolynomials relation)
    (batch : Batch) :
    Lagrange.interpolate Finset.univ consecutiveSamples
      (fun index => (multiplicationPolynomial relation source.polynomial batch).eval (consecutiveSamples index)) =
      multiplicationPolynomial relation source.polynomial batch :=
  source139_interpolation relation source batch consecutiveSamples consecutive_samples_distinct

/-- Division by the packing product is derived from the actual multiplication
checks; sequential division has the same result. -/
theorem sequential_division_matches (relation : Relation) (source : PackedPolynomials relation)
    (gamma : Gamma) :
    removePackingFactors (List.ofFn packing) (batchedNonlinear relation gamma source.polynomial) =
      sourceNonlinearQuotient packing (batchedNonlinear relation gamma source.polynomial) :=
  sequential_packing_removal_matches_quotient packing packing_injective _
    (batched_nonlinear_valid relation source gamma)

theorem nonlinear_numerator_matches (relation : Relation) (gamma : Gamma)
    (witness : Witness) (point : Goldilocks) :
    (batchedNonlinear relation gamma witness).eval point =
      publicNonlinearNumerator relation gamma (fun row => (witness row).eval point) := by
  simp [batchedNonlinear, nonlinear_batch_eval, multiplicationPolynomial,
    publicNonlinearNumerator, eval_sub, eval_mul]

def nonlinearTranscript (relation : Relation) (gamma : Gamma) (witness : Witness)
    (coins : Fin 75 → Goldilocks) : Goldilocks[X] :=
  sourceNonlinearTranscript packing (batchedNonlinear relation gamma witness) (coefficientPolynomial coins)

def nonlinearResponse (relation : Relation) (gamma : Gamma) (witness : Witness)
    (coins : Fin 75 → Goldilocks) : Fin 75 → Goldilocks :=
  fun index => (nonlinearTranscript relation gamma witness coins).coeff index.val

def publicNonlinearMask (relation : Relation) (gamma : Gamma) (response : Fin 75 → Goldilocks)
    (opened : Row → Goldilocks) (point : Goldilocks) : Goldilocks :=
  (coefficientPolynomial response).eval point -
    publicNonlinearNumerator relation gamma opened / (packingVanishing packing).eval point

theorem nonlinear_response_reassembles (relation : Relation) (source : PackedPolynomials relation)
    (gamma : Gamma) (coins : Fin 75 → Goldilocks) :
    coefficientPolynomial (nonlinearResponse relation gamma source.polynomial coins) =
      nonlinearTranscript relation gamma source.polynomial coins := by
  apply coefficient_polynomial_of_coefficients
  have low := quotient_degree74 relation source gamma
  have mask : (coefficientPolynomial coins).natDegree ≤ 74 :=
    coefficient_polynomial_nat_degree_le coins
  have degree := (natDegree_add_le
    (sourceNonlinearQuotient packing (batchedNonlinear relation gamma source.polynomial))
    (coefficientPolynomial coins)).trans (max_le low mask)
  change (sourceNonlinearQuotient packing (batchedNonlinear relation gamma source.polynomial) +
    coefficientPolynomial coins).natDegree < 75
  omega

/-- Public-mask equality derived from packed multiplication checks and literal
75 transcript coefficients. No mask evaluation or divisibility equality is input. -/
theorem public_nonlinear_mask_openings_match (relation : Relation)
    (source : PackedPolynomials relation) (gamma : Gamma) (coins : Fin 75 → Goldilocks)
    (point : Goldilocks) (outside : ∀ lane, point ≠ packing lane) :
    publicNonlinearMask relation gamma (nonlinearResponse relation gamma source.polynomial coins)
      (fun row => (source.polynomial row).eval point) point =
      (coefficientPolynomial coins).eval point := by
  unfold publicNonlinearMask
  rw [nonlinear_response_reassembles relation source gamma coins,
    ← nonlinear_numerator_matches relation gamma source.polynomial point]
  exact recover_nonlinear_mask_opening packing packing_injective _ _
    (batched_nonlinear_valid relation source gamma) point outside

def weights (relation : Relation) (gamma : Gamma) : Row → Lane → Goldilocks :=
  batchedLinearWeights gamma (fun check => csrWeights (relation.csr check))

def publicTarget (relation : Relation) (gamma : Gamma) : Goldilocks :=
  ∑ check, gamma check * relation.target check

theorem csr_checks_supply_target (relation : Relation) (source : PackedPolynomials relation)
    (gamma : Gamma) :
    (∑ row, ∑ lane, weights relation gamma row lane *
      (source.polynomial row).eval (packing lane)) = publicTarget relation gamma := by
  simp_rw [source.atPacking]
  apply valid_linear_constraints_supply_batched_target gamma
    (fun check => csrWeights (relation.csr check)) source.values relation.target
  intro check
  rw [csr_dense_matches]
  exact source.valid.linear check

def linearTranscript (relation : Relation) (gamma : Gamma) (witness : Witness)
    (coins : Fin 132 → Goldilocks) : Goldilocks[X] :=
  transcriptAdd
    (sourceLinearUnmasked (weights relation gamma) (sourcePackingLagrange packing) witness)
    (sourceLinearMask packing coins)

def linearResponse (relation : Relation) (gamma : Gamma) (witness : Witness)
    (coins : Fin 132 → Goldilocks) : Fin 132 → Goldilocks :=
  fun index => (linearTranscript relation gamma witness coins).coeff (index.val + 1)

def publicLinearMask (relation : Relation) (gamma : Gamma) (response : Fin 132 → Goldilocks)
    (opened : Row → Goldilocks) (point : Goldilocks) : Goldilocks :=
  recoverLinearMaskOpening packing (publicTarget relation gamma) response
    (weights relation gamma) (sourcePackingLagrange packing) opened point

end
end HegemonCrypto.SmallWood.NativePrivateSpendQ58PublicFactorization
