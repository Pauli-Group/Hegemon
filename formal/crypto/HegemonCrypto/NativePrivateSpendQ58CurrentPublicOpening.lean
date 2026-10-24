import HegemonCrypto.NativePrivateSpendQ58CurrentPublicFactorizationBase
import HegemonCrypto.NativePrivateSpendQ58Compff01SourceColumns
import HegemonCrypto.NativePrivateSpendQ58Compff01ClosedLinearRecovery

/-! Current COMPFF01 transcript-to-mask derivation. The only relation premises
are literal CSR/multiplication checks, not view or simulation equalities.
Current dimensions are26210/1344594/13115/13173. -/
namespace HegemonCrypto.SmallWood.NativePrivateSpendQ58CurrentPublicOpening
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
set_option stderrAsMessages false

#eval IO.eprintln "PUBLIC_OPENING_DECL_START: generic_tail_kernel_transport"
/-- Reindex the initialized kernel with finite types kept abstract throughout
the proof. The inverse still supplies the original tails to the same kernel. -/
private theorem generic_tail_kernel_transport
    {Tail : Type*} {View : Type*} {Branch : Type*} {Value : Type*}
    [Fintype Tail] [Fintype View] [Fintype Branch] [AddCommMonoid Value]
    (e : Branch → Tail ≃ View)
    (kernel : Branch → Tail → View → Value) :
    (∑ tail, ∑ branch, kernel branch tail (e branch tail)) =
      ∑ view, ∑ branch, kernel branch ((e branch).symm view) view := by
  rw [Finset.sum_comm]
  calc
    _ = ∑ branch, ∑ view, kernel branch ((e branch).symm view) view := by
      apply Finset.sum_congr rfl
      intro branch _
      simpa only [Equiv.apply_symm_apply] using
        ((e branch).symm.sum_comp
          (fun tail => kernel branch tail (e branch tail))).symm
    _ = _ := Finset.sum_comm

#eval IO.eprintln "PUBLIC_OPENING_DECL_START: nonlinearGamma"
def nonlinearGamma (gamma : Gamma) (batch : Batch) : Goldilocks :=
  gamma ⟨batch.val, batch.isLt.trans_le (by decide)⟩

#eval IO.eprintln "PUBLIC_OPENING_DECL_START: multiplicationPolynomial"
def multiplicationPolynomial (relation : Relation) (witness : Witness) (batch : Batch) :
    Goldilocks[X] := witness (relation.batch batch 0) -
      witness (relation.batch batch 1) * witness (relation.batch batch 2)

#eval IO.eprintln "PUBLIC_OPENING_DECL_START: batchedNonlinear"
def batchedNonlinear (relation : Relation) (gamma : Gamma) (witness : Witness) : Goldilocks[X] :=
  nonlinearBatch (nonlinearGamma gamma) (multiplicationPolynomial relation witness)

#eval IO.eprintln "PUBLIC_OPENING_DECL_START: publicNonlinearNumerator"
def publicNonlinearNumerator (relation : Relation) (gamma : Gamma)
    (opened : Row → Goldilocks) : Goldilocks :=
  ∑ batch, nonlinearGamma gamma batch *
    (opened (relation.batch batch 0) -
      opened (relation.batch batch 1) * opened (relation.batch batch 2))

#eval IO.eprintln "PUBLIC_OPENING_DECL_START: multiplication_valid"
theorem multiplication_valid (relation : Relation) (source : PackedPolynomials relation)
    (batch : Batch) (lane : Lane) :
    (multiplicationPolynomial relation source.polynomial batch).eval (packing lane) = 0 := by
  simp only [multiplicationPolynomial, eval_sub, eval_mul, source.atPacking]
  exact sub_eq_zero.mpr (source.valid.multiply batch lane)

#eval IO.eprintln "PUBLIC_OPENING_DECL_START: batched_nonlinear_valid"
theorem batched_nonlinear_valid (relation : Relation) (source : PackedPolynomials relation)
    (gamma : Gamma) : ∀ lane,
    (batchedNonlinear relation gamma source.polynomial).eval (packing lane) = 0 :=
  nonlinear_batch_valid packing (nonlinearGamma gamma) _ (multiplication_valid relation source)

#eval IO.eprintln "PUBLIC_OPENING_DECL_START: multiplication_degree138"
theorem multiplication_degree138 (relation : Relation) (source : PackedPolynomials relation)
    (batch : Batch) : (multiplicationPolynomial relation source.polynomial batch).natDegree ≤ 138 := by
  apply (natDegree_sub_le _ _).trans
  apply max_le
  · exact (source.degree _).trans (by decide)
  · exact natDegree_mul_le.trans (Nat.add_le_add (source.degree _) (source.degree _))

#eval IO.eprintln "PUBLIC_OPENING_DECL_START: batched_degree138"
theorem batched_degree138 (relation : Relation) (source : PackedPolynomials relation)
    (gamma : Gamma) : (batchedNonlinear relation gamma source.polynomial).natDegree ≤ 138 := by
  unfold batchedNonlinear nonlinearBatch
  apply natDegree_sum_le_of_forall_le
  intro batch _
  refine natDegree_mul_le.trans ?_
  simpa using multiplication_degree138 relation source batch

#eval IO.eprintln "PUBLIC_OPENING_DECL_START: quotient_degree74"
theorem quotient_degree74 (relation : Relation) (source : PackedPolynomials relation)
    (gamma : Gamma) :
    (sourceNonlinearQuotient packing (batchedNonlinear relation gamma source.polynomial)).natDegree ≤ 74 := by
  rw [sourceNonlinearQuotient,
    natDegree_divByMonic _ (packing_vanishing_monic packing), packing_vanishing_degree]
  have bound := batched_degree138 relation source gamma
  omega

#eval IO.eprintln "PUBLIC_OPENING_DECL_START: source139_interpolation"
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

#eval IO.eprintln "PUBLIC_OPENING_DECL_START: consecutiveSamples"
def consecutiveSamples : Fin 139 → Goldilocks := fun index => (index.val : Goldilocks)

#eval IO.eprintln "PUBLIC_OPENING_DECL_START: consecutive_samples_distinct"
theorem consecutive_samples_distinct : Function.Injective consecutiveSamples := by
  intro left right same
  have equal : (⟨left.val, by omega⟩ : Fin 13173) = ⟨right.val, by omega⟩ :=
    NativePrivateSpendQ58Compff01OpeningContinuation.current_nodes_distinct same
  exact Fin.ext (congrArg (@Fin.val 13173) equal)

#eval IO.eprintln "PUBLIC_OPENING_DECL_START: source_consecutive_interpolation"
theorem source_consecutive_interpolation (relation : Relation) (source : PackedPolynomials relation)
    (batch : Batch) :
    Lagrange.interpolate Finset.univ consecutiveSamples
      (fun index => (multiplicationPolynomial relation source.polynomial batch).eval (consecutiveSamples index)) =
      multiplicationPolynomial relation source.polynomial batch :=
  source139_interpolation relation source batch consecutiveSamples consecutive_samples_distinct

#eval IO.eprintln "PUBLIC_OPENING_DECL_START: sequential_division_matches"
/-- Division by the packing product is derived from the actual multiplication
checks; sequential division has the same result. -/
theorem sequential_division_matches (relation : Relation) (source : PackedPolynomials relation)
    (gamma : Gamma) :
    removePackingFactors (List.ofFn packing) (batchedNonlinear relation gamma source.polynomial) =
      sourceNonlinearQuotient packing (batchedNonlinear relation gamma source.polynomial) :=
  sequential_packing_removal_matches_quotient packing packing_injective _
    (batched_nonlinear_valid relation source gamma)

#eval IO.eprintln "PUBLIC_OPENING_DECL_START: nonlinear_numerator_matches"
theorem nonlinear_numerator_matches (relation : Relation) (gamma : Gamma)
    (witness : Witness) (point : Goldilocks) :
    (batchedNonlinear relation gamma witness).eval point =
      publicNonlinearNumerator relation gamma (fun row => (witness row).eval point) := by
  simp [batchedNonlinear, nonlinear_batch_eval, multiplicationPolynomial,
    publicNonlinearNumerator, eval_sub, eval_mul]

#eval IO.eprintln "PUBLIC_OPENING_DECL_START: nonlinearTranscript"
def nonlinearTranscript (relation : Relation) (gamma : Gamma) (witness : Witness)
    (coins : Fin 75 → Goldilocks) : Goldilocks[X] :=
  sourceNonlinearTranscript packing (batchedNonlinear relation gamma witness) (coefficientPolynomial coins)

#eval IO.eprintln "PUBLIC_OPENING_DECL_START: nonlinearResponse"
def nonlinearResponse (relation : Relation) (gamma : Gamma) (witness : Witness)
    (coins : Fin 75 → Goldilocks) : Fin 75 → Goldilocks :=
  fun index => (nonlinearTranscript relation gamma witness coins).coeff index.val

#eval IO.eprintln "PUBLIC_OPENING_DECL_START: publicNonlinearMask"
def publicNonlinearMask (relation : Relation) (gamma : Gamma) (response : Fin 75 → Goldilocks)
    (opened : Row → Goldilocks) (point : Goldilocks) : Goldilocks :=
  (coefficientPolynomial response).eval point -
    publicNonlinearNumerator relation gamma opened / (packingVanishing packing).eval point

#eval IO.eprintln "PUBLIC_OPENING_DECL_START: nonlinear_response_reassembles"
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

#eval IO.eprintln "PUBLIC_OPENING_DECL_START: public_nonlinear_mask_openings_match"
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

#eval IO.eprintln "PUBLIC_OPENING_DECL_START: restoredWitness"
/-- One nominal restored-witness function for both public fields and packed source. -/
private def restoredWitness (data : NativePrivateSpendQ58Compff01SourceColumns.SourceData) : Witness :=
  fun row => NativePrivateSpendQ58Compff01SourceColumns.restoreWitness
    (data.values row) (data.witnessCoins row)

#eval IO.eprintln "PUBLIC_OPENING_DECL_START: restored_witness_equation"
private theorem restored_witness_equation
    (data : NativePrivateSpendQ58Compff01SourceColumns.SourceData) :
    restoredWitness data =
      (fun row => NativePrivateSpendQ58Compff01SourceColumns.restoreWitness
        (data.values row) (data.witnessCoins row)) := rfl

#eval IO.eprintln "PUBLIC_OPENING_DECL_START: packedSource"
def packedSource (relation : Relation) (data : NativePrivateSpendQ58Compff01SourceColumns.SourceData)
    (valid : Satisfies relation data.values) : PackedPolynomials relation where
  values := data.values
  polynomial := restoredWitness data
  atPacking := fun row lane => NativePrivateSpendQ58Compff01SourceColumns.restore_witness_at_packing
    (data.values row) (data.witnessCoins row) lane
  degree := fun row => NativePrivateSpendQ58Compff01SourceColumns.restore_witness_degree
    (data.values row) (data.witnessCoins row)
  valid := valid

#eval IO.eprintln "PUBLIC_OPENING_DECL_START: Transcript"
abbrev Transcript := (Fin 5 → Fin 75 → Goldilocks) × (Fin 5 → Fin 132 → Goldilocks)
#eval IO.eprintln "PUBLIC_OPENING_DECL_START: Opened"
abbrev Opened := Fin 6 → Row → Goldilocks
#eval IO.eprintln "PUBLIC_OPENING_DECL_START: Partials"
abbrev Partials := Fin 6 → Fin 10 → Goldilocks
#eval IO.eprintln "PUBLIC_OPENING_DECL_START: MaskScalars"
abbrev MaskScalars := (Fin 6 → Fin 5 → Goldilocks) × (Fin 6 → Fin 5 → Goldilocks)

#eval IO.eprintln "PUBLIC_OPENING_DECL_START: PublicFields"
/-- All inputs are available to the verifier; scalar mask openings are computed,
never supplied as hidden witness/coin coordinates. -/
structure PublicFields where
  gamma : Fin 5 → Gamma
  transcript : Transcript
  opened : Opened
  partials : Partials

#eval IO.eprintln "PUBLIC_OPENING_DECL_START: publicMasks"
def publicMasks (relation : Relation) (fields : PublicFields)
    (points : Fin 6 → Goldilocks) : MaskScalars :=
  (fun opening repetition => publicNonlinearMask relation (fields.gamma repetition)
    (fields.transcript.1 repetition) (fields.opened opening) (points opening),
   fun opening repetition => publicLinearMask relation (fields.gamma repetition)
    (fields.transcript.2 repetition) (fields.opened opening) (points opening))

#eval IO.eprintln "PUBLIC_OPENING_DECL_START: sourceFields"
def sourceFields (relation : Relation) (gamma : Fin 5 → Gamma)
    (data : NativePrivateSpendQ58Compff01SourceColumns.SourceData) (points : Fin 6 → Goldilocks) : PublicFields where
  gamma := gamma
  transcript :=
    (fun k => nonlinearResponse relation (gamma k)
      (restoredWitness data) (data.nonlinear k),
     fun k => linearResponse relation (gamma k)
      (restoredWitness data) (data.linearCoins k))
  opened := fun opening row => (restoredWitness data row).eval (points opening)
  partials := fun opening column =>
    if left : column.val < 5 then
      (NativePrivateSpendQ58Compff01SourceColumns.unstackPair (count := 11) 59 (data.nonlinear ⟨column.val, left⟩)
        (data.pcs column) 1).eval (points opening)
    else (NativePrivateSpendQ58Compff01SourceColumns.unstackPair (count := 69) 1
      (NativePrivateSpendQ58Compff01SourceColumns.linearFull (data.linearCoins ⟨column.val - 5, by have _ := column.isLt; omega⟩))
      (data.pcs column) 1).eval (points opening)

#eval IO.eprintln "PUBLIC_OPENING_DECL_START: public_masks_are_source"
theorem public_masks_are_source (relation : Relation) (gamma : Fin 5 → Gamma)
    (data : NativePrivateSpendQ58Compff01SourceColumns.SourceData) (valid : Satisfies relation data.values)
    (points : Fin 6 → Goldilocks) (outside : ∀ opening lane, points opening ≠ packing lane) :
    publicMasks relation (sourceFields relation gamma data points) points =
      (fun opening repetition => (coefficientPolynomial (data.nonlinear repetition)).eval
        (points opening),
       fun opening repetition => (sourceLinearMask packing (data.linearCoins repetition)).eval
        (points opening)) := by
  apply Prod.ext
  · funext opening repetition
    exact public_nonlinear_mask_openings_match relation (packedSource relation data valid)
      (gamma repetition) (data.nonlinear repetition) (points opening) (outside opening)
  · funext opening repetition
    have recovered := public_linear_mask_openings_match relation
      (packedSource relation data valid) (gamma repetition)
      (data.linearCoins repetition) (points opening)
    simpa only [publicMasks, sourceFields, packedSource] using recovered

#eval IO.eprintln "PUBLIC_OPENING_DECL_START: reconstructPair"
def reconstructPair (point scalar partialValue : Goldilocks) (power : Nat) : Fin 2 → Goldilocks :=
  ![scalar - point ^ power * partialValue, partialValue]

#eval IO.eprintln "PUBLIC_OPENING_DECL_START: reconstruct_pair_roundtrip"
theorem reconstruct_pair_roundtrip (point : Goldilocks) (power : Nat)
    (columns : Fin 2 → Goldilocks) :
    reconstructPair point (columns 0 + point ^ power * columns 1) (columns 1) power = columns := by
  funext column
  fin_cases column <;> simp [reconstructPair]

#eval IO.eprintln "PUBLIC_OPENING_DECL_START: nonlinear_pair_recovered"
theorem nonlinear_pair_recovered (mask : Fin 75 → Goldilocks) (coins : Fin 6 → Goldilocks)
    (point : Goldilocks) :
    reconstructPair point ((coefficientPolynomial mask).eval point)
      ((NativePrivateSpendQ58Compff01SourceColumns.unstackPair (count := 11) 59 mask coins 1).eval point) 5 =
      (fun column => (NativePrivateSpendQ58Compff01SourceColumns.unstackPair (count := 11) 59 mask coins column).eval point) := by
  rw [← NativePrivateSpendQ58Compff01SourceColumns.pair_recombines (count := 11) 59 5 (by decide) mask coins point]
  exact reconstruct_pair_roundtrip point 5
    (fun column => (NativePrivateSpendQ58Compff01SourceColumns.unstackPair
      (count := 11) 59 mask coins column).eval point)

#eval IO.eprintln "PUBLIC_OPENING_DECL_START: linear_pair_recovered"
theorem linear_pair_recovered (coins : Fin 132 → Goldilocks) (pcs : Fin 6 → Goldilocks)
    (point : Goldilocks) :
    reconstructPair point ((sourceLinearMask packing coins).eval point)
      ((NativePrivateSpendQ58Compff01SourceColumns.unstackPair (count := 69) 1 (NativePrivateSpendQ58Compff01SourceColumns.linearFull coins) pcs 1).eval point) 63 =
      (fun column => (NativePrivateSpendQ58Compff01SourceColumns.unstackPair (count := 69) 1 (NativePrivateSpendQ58Compff01SourceColumns.linearFull coins) pcs column).eval point) := by
  change reconstructPair point ((sourceLinearMask NativePrivateSpendQ58Compff01SourceColumns.packing coins).eval point) _ 63 = _
  rw [← NativePrivateSpendQ58Compff01SourceColumns.linear_full_reassembles]
  rw [← NativePrivateSpendQ58Compff01SourceColumns.pair_recombines (count := 69) 1 63 (by decide) (NativePrivateSpendQ58Compff01SourceColumns.linearFull coins) pcs point]
  exact reconstruct_pair_roundtrip point 63
    (fun column => (NativePrivateSpendQ58Compff01SourceColumns.unstackPair
      (count := 69) 1 (NativePrivateSpendQ58Compff01SourceColumns.linearFull coins) pcs column).eval point)

#eval IO.eprintln "PUBLIC_OPENING_DECL_START: reconstructedColumns"
def reconstructedColumns (relation : Relation) (fields : PublicFields)
    (points : Fin 6 → Goldilocks) : Fin 6 → Fin 26230 → Goldilocks := fun opening =>
  Fin.append (fields.opened opening) (Fin.append
    (fun column : Fin 10 =>
      let index := (finProdFinEquiv : Fin 5 × Fin 2 ≃ Fin 10).symm column
      reconstructPair (points opening) ((publicMasks relation fields points).1 opening index.1)
        (fields.partials opening (Fin.castAdd 5 index.1)) 5 index.2)
    (fun column : Fin 10 =>
      let index := (finProdFinEquiv : Fin 5 × Fin 2 ≃ Fin 10).symm column
      reconstructPair (points opening) ((publicMasks relation fields points).2 opening index.1)
        (fields.partials opening (Fin.natAdd 5 index.1)) 63 index.2))

#eval IO.eprintln "PUBLIC_OPENING_DECL_START: publicHeads"
def publicHeads (relation : Relation) (fields : PublicFields) (points : Fin 6 → Goldilocks) :
    Fin 12 → Fin 13115 → Goldilocks := fun combination column =>
  let index := (finProdFinEquiv : Fin 6 × Fin 2 ≃ Fin 12).symm combination
  reconstructedColumns relation fields points index.1 (finProdFinEquiv (index.2, column))


#eval IO.eprintln "PUBLIC_OPENING_DECL_START: source_partial_nonlinear"
theorem source_partial_nonlinear (relation : Relation) (gamma : Fin 5 → Gamma)
    (data : NativePrivateSpendQ58Compff01SourceColumns.SourceData) (points : Fin 6 → Goldilocks) (opening : Fin 6) (index : Fin 5) :
    (sourceFields relation gamma data points).partials opening (Fin.castAdd 5 index) =
      (NativePrivateSpendQ58Compff01SourceColumns.unstackPair (count := 11) 59 (data.nonlinear index)
        (data.pcs (Fin.castAdd 5 index)) 1).eval (points opening) := by
  simp only [sourceFields, Fin.val_castAdd, dif_pos index.isLt]

#eval IO.eprintln "PUBLIC_OPENING_DECL_START: source_partial_linear"
theorem source_partial_linear (relation : Relation) (gamma : Fin 5 → Gamma)
    (data : NativePrivateSpendQ58Compff01SourceColumns.SourceData) (points : Fin 6 → Goldilocks) (opening : Fin 6) (index : Fin 5) :
    (sourceFields relation gamma data points).partials opening (Fin.natAdd 5 index) =
      (NativePrivateSpendQ58Compff01SourceColumns.unstackPair (count := 69) 1 (NativePrivateSpendQ58Compff01SourceColumns.linearFull (data.linearCoins index))
        (data.pcs (Fin.natAdd 5 index)) 1).eval (points opening) := by
  have outside : ¬ 5 + index.val < 5 := by omega
  simp only [sourceFields, Fin.val_natAdd, dif_neg outside, Nat.add_sub_cancel_left]

#eval IO.eprintln "PUBLIC_OPENING_DECL_START: reconstructed_columns_are_source"
theorem reconstructed_columns_are_source (relation : Relation) (gamma : Fin 5 → Gamma)
    (data : NativePrivateSpendQ58Compff01SourceColumns.SourceData) (valid : Satisfies relation data.values)
    (points : Fin 6 → Goldilocks) (outside : ∀ opening lane, points opening ≠ packing lane) :
    reconstructedColumns relation (sourceFields relation gamma data points) points =
      (fun opening column => (NativePrivateSpendQ58Compff01SourceColumns.sourcePolynomials data column).eval (points opening)) := by
  funext opening column
  unfold reconstructedColumns
  rw [public_masks_are_source relation gamma data valid points outside]
  refine Fin.addCases (m := 26210) (n := 20) (fun row => ?_) (fun remaining => ?_) column
  · simp only [Fin.append_left, sourceFields, restoredWitness, NativePrivateSpendQ58Compff01SourceColumns.sourcePolynomials, Fin.append_left]
  · refine Fin.addCases (m := 10) (n := 10) (fun nonlinear => ?_) (fun linear => ?_) remaining
    · simp only [Fin.append_right, Fin.append_left, NativePrivateSpendQ58Compff01SourceColumns.sourcePolynomials,
        NativePrivateSpendQ58Compff01SourceColumns.nonlinearColumns, source_partial_nonlinear]
      exact congrFun (nonlinear_pair_recovered _ _ (points opening)) _
    · simp only [Fin.append_right, NativePrivateSpendQ58Compff01SourceColumns.sourcePolynomials, NativePrivateSpendQ58Compff01SourceColumns.linearColumns, source_partial_linear]
      exact congrFun (linear_pair_recovered _ _ (points opening)) _

#eval IO.eprintln "PUBLIC_OPENING_DECL_START: public_heads_are_current_matrix"
theorem public_heads_are_current_matrix (relation : Relation) (gamma : Fin 5 → Gamma)
    (data : NativePrivateSpendQ58Compff01SourceColumns.SourceData) (valid : Satisfies relation data.values)
    (points : Fin 6 → Goldilocks) (outside : ∀ opening lane, points opening ≠ packing lane) :
    publicHeads relation (sourceFields relation gamma data points) points =
      NativePrivateSpendQ58Compff01OpeningContinuation.combinationHeads points (NativePrivateSpendQ58Compff01OpeningContinuation.stackedHeads (NativePrivateSpendQ58Compff01SourceColumns.sourceCurrentColumns data)) := by
  funext combination column
  obtain ⟨⟨opening, block⟩, rfl⟩ :=
    (finProdFinEquiv : Fin 6 × Fin 2 ≃ Fin 12).surjective combination
  simp only [publicHeads, Equiv.symm_apply_apply]
  rw [reconstructed_columns_are_source relation gamma data valid points outside]
  exact (NativePrivateSpendQ58Compff01SourceColumns.source_head_is_polynomial_opening data points opening block column).symm

#eval IO.eprintln "PUBLIC_OPENING_DECL_START: genericDecsPolynomial"
/-- Share the DECS polynomial, coefficient response and public mask heads
before specializing the finite row and coefficient universes. No inverse or
field operation enters this ring-level reconstruction algebra. -/
private def genericDecsPolynomial {F : Type*} [CommRing F]
    {Rows : Type*} [Fintype Rows] {count : Nat}
    (rowWeights : Rows → F) (rowPolynomials : Rows → F[X])
    (maskCoefficients : Fin count → F) : F[X] :=
  (∑ row, C (rowWeights row) * rowPolynomials row) +
    coefficientPolynomial maskCoefficients

#eval IO.eprintln "PUBLIC_OPENING_DECL_START: genericDecsResponse"
private def genericDecsResponse {F : Type*} [CommRing F]
    {Rows : Type*} [Fintype Rows] {count : Nat}
    (rowWeights : Rows → F) (rowPolynomials : Rows → F[X])
    (maskCoefficients : Fin count → F) : Fin count → F :=
  fun coefficient =>
    (genericDecsPolynomial rowWeights rowPolynomials maskCoefficients).coeff coefficient.val

#eval IO.eprintln "PUBLIC_OPENING_DECL_START: genericPublicDecsMask"
private def genericPublicDecsMask {F : Type*} [CommRing F]
    {Rows : Type*} [Fintype Rows] {count : Nat}
    (response : Fin count → F) (rowWeights : Rows → F)
    (openedRows : Rows → F) (point : F) : F :=
  (coefficientPolynomial response).eval point -
    ∑ row, rowWeights row * openedRows row

#eval IO.eprintln "PUBLIC_OPENING_DECL_START: generic_decs_wrapper_formulas"
private theorem generic_decs_wrapper_formulas {F : Type*} [CommRing F]
    {Rows : Type*} [Fintype Rows] {count : Nat}
    (rowWeights : Rows → F) (rowPolynomials : Rows → F[X])
    (maskCoefficients response : Fin count → F)
    (openedRows : Rows → F) (point : F) :
    genericDecsPolynomial rowWeights rowPolynomials maskCoefficients =
      (∑ row, C (rowWeights row) * rowPolynomials row) +
        coefficientPolynomial maskCoefficients ∧
    genericDecsResponse rowWeights rowPolynomials maskCoefficients =
      (fun coefficient =>
        ((∑ row, C (rowWeights row) * rowPolynomials row) +
          coefficientPolynomial maskCoefficients).coeff coefficient.val) ∧
    genericPublicDecsMask response rowWeights openedRows point =
      (coefficientPolynomial response).eval point -
        ∑ row, rowWeights row * openedRows row := by
  exact ⟨rfl, rfl, rfl⟩

#eval IO.eprintln "PUBLIC_OPENING_DECL_START: generic_decs_degree"
private theorem generic_decs_degree {F : Type*} [CommRing F]
    {Rows : Type*} [Fintype Rows] {count : Nat}
    (rowWeights : Rows → F) (rowPolynomials : Rows → F[X])
    (maskCoefficients : Fin count → F) (bound : Nat)
    (rowDegree : ∀ row, (rowPolynomials row).natDegree ≤ bound)
    (maskDegree : (coefficientPolynomial maskCoefficients).natDegree ≤ bound) :
    (genericDecsPolynomial rowWeights rowPolynomials maskCoefficients).natDegree ≤ bound := by
  unfold genericDecsPolynomial
  apply (natDegree_add_le _ _).trans
  apply max_le
  · apply natDegree_sum_le_of_forall_le
    intro row _
    refine natDegree_mul_le.trans ?_
    simp only [natDegree_C, zero_add]
    exact rowDegree row
  · exact maskDegree

#eval IO.eprintln "PUBLIC_OPENING_DECL_START: generic_public_decs_mask_is_source"
private theorem generic_public_decs_mask_is_source {F : Type*} [CommRing F]
    {Rows : Type*} [Fintype Rows] {count : Nat}
    (rowWeights : Rows → F) (rowPolynomials : Rows → F[X])
    (maskCoefficients : Fin count → F) (point : F)
    (degreeBound : (genericDecsPolynomial rowWeights rowPolynomials maskCoefficients).natDegree < count) :
    genericPublicDecsMask
      (genericDecsResponse rowWeights rowPolynomials maskCoefficients) rowWeights
      (fun row => (rowPolynomials row).eval point) point =
      (coefficientPolynomial maskCoefficients).eval point := by
  unfold genericPublicDecsMask genericDecsResponse
  rw [coefficient_polynomial_of_coefficients _ degreeBound]
  simp only [genericDecsPolynomial, eval_add, eval_finsetSum, eval_mul, eval_C]
  exact add_sub_cancel_left _ _

#eval IO.eprintln "PUBLIC_OPENING_DECL_START: generic_decs_response_coefficient"
private theorem generic_decs_response_coefficient {F : Type*} [CommRing F]
    {Rows : Type*} [Fintype Rows] {count : Nat}
    (rowWeights : Rows → F) (rowPolynomials : Rows → F[X])
    (maskCoefficients : Fin count → F) (selected : Fin count) :
    genericDecsResponse rowWeights rowPolynomials maskCoefficients selected =
      (∑ row, C (rowWeights row) * rowPolynomials row).coeff selected.val +
        maskCoefficients selected := by
  have maskSlot : (coefficientPolynomial maskCoefficients).coeff selected.val =
      maskCoefficients selected := by
    unfold coefficientPolynomial
    rw [finsetSum_coeff]
    simp only [coeff_C_mul_X_pow]
    have single : (∑ index : Fin count,
        if selected.val = index.val then maskCoefficients index else 0) =
        (if selected.val = selected.val then maskCoefficients selected else 0) := by
      apply Finset.sum_eq_single selected
      · intro other _ different
        have valuesDiffer : selected.val ≠ other.val := by
          intro same
          exact different (Fin.ext same.symm)
        simp only [if_neg valuesDiffer]
      · intro absent
        exact (absent (Finset.mem_univ selected)).elim
    rw [single]
    simp only [ite_true]
  unfold genericDecsResponse genericDecsPolynomial
  rw [coeff_add, maskSlot]

#eval IO.eprintln "PUBLIC_OPENING_DECL_START: DecsGamma"
abbrev DecsGamma := Fin 5 → Fin 140 → Goldilocks
#eval IO.eprintln "PUBLIC_OPENING_DECL_START: DecsResponse"
abbrev DecsResponse := Fin 5 → Fin 13173 → Goldilocks

#eval IO.eprintln "PUBLIC_OPENING_DECL_START: sourceDecsPolynomial"
def sourceDecsPolynomial (heads : NativePrivateSpendQ58Compff01OpeningContinuation.Heads) (tails : NativePrivateSpendQ58Compff01OpeningContinuation.Tails) (gamma : DecsGamma)
    (masks : DecsResponse) (repetition : Fin 5) : Goldilocks[X] :=
  genericDecsPolynomial (gamma repetition)
    (NativePrivateSpendQ58Compff01SourceColumns.extendedRowPolynomial heads tails)
    (masks repetition)


#eval IO.eprintln "PUBLIC_OPENING_DECL_START: sourceDecsResponse"
def sourceDecsResponse (heads : NativePrivateSpendQ58Compff01OpeningContinuation.Heads) (tails : NativePrivateSpendQ58Compff01OpeningContinuation.Tails) (gamma : DecsGamma)
    (masks : DecsResponse) : DecsResponse :=
  fun repetition => genericDecsResponse (gamma repetition)
    (NativePrivateSpendQ58Compff01SourceColumns.extendedRowPolynomial heads tails)
    (masks repetition)


#eval IO.eprintln "PUBLIC_OPENING_DECL_START: source_decs_response_coefficient"
/-- The coefficient law is derived once over abstract row and mask index types.
This exposes the current constructor without unfolding its private wrappers. -/
theorem source_decs_response_coefficient
    (heads : NativePrivateSpendQ58Compff01OpeningContinuation.Heads)
    (tails : NativePrivateSpendQ58Compff01OpeningContinuation.Tails)
    (gamma : DecsGamma) (masks : DecsResponse)
    (repetition : Fin 5) (coefficient : Fin 13173) :
    sourceDecsResponse heads tails gamma masks repetition coefficient =
      (∑ row : Fin 140, C (gamma repetition row) *
        NativePrivateSpendQ58Compff01SourceColumns.extendedRowPolynomial heads tails row).coeff
          coefficient.val + masks repetition coefficient := by
  exact generic_decs_response_coefficient (gamma repetition)
    (NativePrivateSpendQ58Compff01SourceColumns.extendedRowPolynomial heads tails)
    (masks repetition) coefficient

#eval IO.eprintln "PUBLIC_OPENING_DECL_START: source_decs_degree"
theorem source_decs_degree (heads : NativePrivateSpendQ58Compff01OpeningContinuation.Heads) (tails : NativePrivateSpendQ58Compff01OpeningContinuation.Tails) (gamma : DecsGamma)
    (masks : DecsResponse) (repetition : Fin 5) :
    (sourceDecsPolynomial heads tails gamma masks repetition).natDegree ≤ 13172 := by
  unfold sourceDecsPolynomial
  exact generic_decs_degree (gamma repetition)
    (NativePrivateSpendQ58Compff01SourceColumns.extendedRowPolynomial heads tails)
    (masks repetition) 13172
    (NativePrivateSpendQ58Compff01SourceColumns.extended_row_degree13172 heads tails)
    (NativePrivateSpendQ58Compff01SourceColumns.current_decs_response_degree13172 masks repetition)


#eval IO.eprintln "PUBLIC_OPENING_DECL_START: publicDecsMask"
def publicDecsMask (response : DecsResponse) (gamma : DecsGamma)
    (openedRows : Fin 140 → Goldilocks) (point : Goldilocks) (repetition : Fin 5) : Goldilocks :=
  genericPublicDecsMask (response repetition) (gamma repetition) openedRows point


#eval IO.eprintln "PUBLIC_OPENING_DECL_START: public_decs_mask_is_source"
theorem public_decs_mask_is_source (heads : NativePrivateSpendQ58Compff01OpeningContinuation.Heads) (tails : NativePrivateSpendQ58Compff01OpeningContinuation.Tails) (gamma : DecsGamma)
    (masks : DecsResponse) (point : Goldilocks) (repetition : Fin 5) :
    publicDecsMask (sourceDecsResponse heads tails gamma masks) gamma
      (fun row => (NativePrivateSpendQ58Compff01SourceColumns.extendedRowPolynomial heads tails row).eval point) point repetition =
      (coefficientPolynomial (masks repetition)).eval point := by
  unfold publicDecsMask sourceDecsResponse
  exact generic_public_decs_mask_is_source (gamma repetition)
    (NativePrivateSpendQ58Compff01SourceColumns.extendedRowPolynomial heads tails)
    (masks repetition) point
    (Nat.lt_succ_of_le (source_decs_degree heads tails gamma masks repetition))


#eval IO.eprintln "PUBLIC_OPENING_DECL_START: initialized_tail_kernel_transport"
/-- Authentication state stays in the initialized kernel at inverse ORIGINAL
coins. This exact transport does not claim its dependence has disappeared. -/
theorem initialized_tail_kernel_transport {Branch Value : Type*}
    [Fintype Branch] [AddCommMonoid Value]
    (points : Branch → Fin 6 → Goldilocks) (distinct : ∀ branch, Function.Injective (points branch))
    (heads : Branch → NativePrivateSpendQ58Compff01OpeningContinuation.Heads) (choose : Branch → NativePrivateSpendQ58Compff01OpeningContinuation.Earlier → NativePrivateSpendQ58Compff01OpeningContinuation.Targets)
    (kernel : Branch → NativePrivateSpendQ58Compff01OpeningContinuation.Tails → (NativePrivateSpendQ58Compff01OpeningContinuation.Earlier × NativePrivateSpendQ58Compff01OpeningContinuation.Later) → Value) :
    (∑ tails, ∑ branch, kernel branch tails
      (NativePrivateSpendQ58Compff01OpeningContinuation.feedbackEquiv (points branch) (distinct branch) (heads branch) (choose branch) tails)) =
    ∑ view, ∑ branch, kernel branch
      ((NativePrivateSpendQ58Compff01OpeningContinuation.feedbackEquiv (points branch) (distinct branch) (heads branch) (choose branch)).symm view) view := by
  exact generic_tail_kernel_transport
    (fun branch => NativePrivateSpendQ58Compff01OpeningContinuation.feedbackEquiv
      (points branch) (distinct branch) (heads branch) (choose branch)) kernel

/-- Public transcript projection at the literal restored function. The nominal
witness equality is transported before either response wrapper is unfolded. -/
theorem source_fields_transcript_eq (relation : Relation) (gamma : Fin 5 → Gamma)
    (data : NativePrivateSpendQ58Compff01SourceColumns.SourceData)
    (points : Fin 6 → Goldilocks) :
    (sourceFields relation gamma data points).transcript =
      (fun repetition => nonlinearResponse relation (gamma repetition)
        (fun row => NativePrivateSpendQ58Compff01SourceColumns.restoreWitness
          (data.values row) (data.witnessCoins row)) (data.nonlinear repetition),
       fun repetition => linearResponse relation (gamma repetition)
        (fun row => NativePrivateSpendQ58Compff01SourceColumns.restoreWitness
          (data.values row) (data.witnessCoins row)) (data.linearCoins repetition)) := by
  exact congrArg (fun witness : Witness =>
    (fun repetition => nonlinearResponse relation (gamma repetition)
      witness (data.nonlinear repetition),
     fun repetition => linearResponse relation (gamma repetition)
      witness (data.linearCoins repetition))) (restored_witness_equation data)

end
end HegemonCrypto.SmallWood.NativePrivateSpendQ58CurrentPublicOpening

#eval IO.eprintln "PUBLIC_OPENING_COMPILE_COMPLETE"
