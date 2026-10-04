import Q38Rp05PostFinalCompiler
import Q38Rp05PublicHeadIndexBridge
import SmzaRp05RelationRefinement

/-! Current-DSL q38 mask recovery on an honest accepted witness.  The
nonlinear root set and normalized CSR weights are the RP05 DSL objects; no
historical 773-root response or 388-node mask is used. -/
namespace HegemonCrypto.SmallWood.Q38Rp05MaskRecovery

open Polynomial
open Hegemon.Transaction.Poseidon2V8RelationProgram
open HegemonCrypto.SmallWood.Poseidon2V8ExpressionRootSemantics
open HegemonCrypto.SmallWood.V8Smz9CurrentPublicContext
open HegemonCrypto.SmallWood.V8Smz9SemanticDenseRange
open HegemonCrypto.SmallWood.V8Smz9ZeroKnowledge
open HegemonCrypto.SmallWood.V8Smz9EagerPrivacy
open HegemonCrypto.SmallWood.V8Smz9EagerSimulator
open HegemonCrypto.SmallWood.V8Smz9SingleProofPrivacy
open HegemonCrypto.SmallWood.V8Smz9PiopOpeningRecovery
open HegemonCrypto.SmallWood.V8Smz9ProgramPolynomials
open HegemonCrypto.SmallWood.V8Smz9CurrentProgramOpeningBinding
open HegemonCrypto.SmallWood.V8SmzaMathPrivacy
open HegemonCrypto.SmallWood.Q38Rp05ChronologicalAlgebra
open HegemonCrypto.SmallWood.Q38Rp05WholePrivacy
open HegemonCrypto.SmallWood.Q38Rp05PostFinalCompiler
open HegemonCrypto.SmallWood.SmzaRp05RelationRefinement
open HegemonCrypto.SmallWood.SmzaRp05CsrNormalization
open HegemonCrypto.SmallWood.SmzaRp05StatementNamespace
open scoped BigOperators Classical

local notation "Statement" =>
  HegemonCrypto.SmallWood.SmzaRp05StatementNamespace.Statement

private def rp05PiopPoints (points : Fin 6 → Goldilocks) :
    Fin V8Smz9ZeroKnowledge.piopOpeningCount → Goldilocks :=
  fun opening => points
    (Fin.cast (by rfl : V8Smz9ZeroKnowledge.piopOpeningCount = 6) opening)

noncomputable section
set_option autoImplicit false
set_option maxHeartbeats 2000000

/-- The only acceptance assumptions are the actual current-DSL nonlinear
root zeros and normalized CSR aggregate zeros at the 64 packing points.
These are semantic protocol-validity conditions, not a requested privacy or
mask-recovery equality. -/
structure ValidPackedWitness (dsl : RelationDsl) (statement : Statement)
    (parameters : Parameters dsl statement)
    (witness : Fin 686 → Goldilocks[X]) : Prop where
  nonlinear : ∀ root lane,
    (nonlinearConstraints dsl statement witness root).eval
      (canonicalPacking lane) = 0
  linear : ∀ linearRow : Fin (dsl.linearCount statement),
    (∑ witnessRow : Fin 686, ∑ lane : Fin 64,
      dsl.linearWeights statement linearRow witnessRow lane *
        (witness witnessRow).eval (canonicalPacking lane)) =
      dsl.linearTarget statement linearRow

/-- The RP05 nonlinear expression DAG, evaluated on the actual source
polynomials, has the certified degree and the same opened-row scalar value
used by `publicMaskOpenings`. -/
theorem rp05_nonlinear_degree_and_evaluation
    (dsl : RelationDsl) (certificates : GeneratedCertificates dsl)
    (statement : Statement)
    (witness : Fin 686 → Goldilocks[X])
    (witnessDegree : ∀ row, (witness row).natDegree ≤ 69)
    (root : Fin dsl.nonlinearCount) (point : Goldilocks) :
    (nonlinearConstraints dsl statement witness root).natDegree ≤ 552 ∧
    (nonlinearConstraints dsl statement witness root).eval point =
      nonlinearScalar dsl statement
        (fun row => (witness row).eval point) root := by
  let rows : Nat → Goldilocks[X] := fun row =>
    if bound : row < 686 then witness ⟨row, bound⟩ else 0
  have rowDegree : ∀ row, (rows row).natDegree ≤ 69 := by
    intro row
    unfold rows
    split
    · exact witnessDegree _
    · simp
  have scalarRows : (fun row => (rows row).eval point) =
      witnessFieldAtNat (fun row => (witness row).eval point) := by
    funext row
    unfold rows witnessFieldAtNat V8Smz9EagerSimulator.openedWitnessAtNat
    split <;> simp_all
  constructor
  · have degree := polynomialAt_degree
      dsl.components.nonlinearExecutable.expressions dsl.nodeDegree
      certificates.nonlinear.degreeCertificate (publicFieldAtNat statement)
      rows 69 rowDegree (dsl.nonlinearRoot root)
    change (polynomialAt dsl.components.nonlinearExecutable.expressions
      (publicFieldAtNat statement) rows (dsl.nonlinearRoot root)).natDegree ≤ 552
    exact degree.trans (by
      have rootDegree := certificates.nonlinear.rootDegree root
      omega)
  · change (polynomialAt dsl.components.nonlinearExecutable.expressions
      (publicFieldAtNat statement) rows (dsl.nonlinearRoot root)).eval point = _
    rw [polynomialAt_commutes
      dsl.components.nonlinearExecutable.expressions dsl.nodeDegree
      certificates.nonlinear.degreeCertificate (publicFieldAtNat statement)
      rows 69 rowDegree (dsl.nonlinearRoot root) point]
    rw [nonlinearScalar, scalarRows]

set_option maxRecDepth 12000 in
/-- Source q38 Q coefficients recover their five nonlinear mask openings and
five linear mask openings from the current DSL response.  The validity
premise is exactly `ValidPackedWitness`; no opened mask value is assumed. -/
theorem rp05_public_masks_are_source_masks
    (dsl : RelationDsl) (statement : Statement)
    (parameters : Parameters dsl statement)
    (points : Fin 6 → Goldilocks)
    (packingInjective : Function.Injective canonicalPacking)
    (packingCardNonzero : (64 : Goldilocks) ≠ 0)
    (witness : Fin 686 → Goldilocks[X])
    (witnessDegree : ∀ row, (witness row).natDegree ≤ 69)
    (nonlinearDegree : ∀ root,
      (nonlinearConstraints dsl statement witness root).natDegree ≤ 552)
    (nonlinearEval : ∀ root point,
      (nonlinearConstraints dsl statement witness root).eval point =
        nonlinearScalar dsl statement
          (fun row => (witness row).eval point) root)
    (masks : Q)
    (valid : ValidPackedWitness dsl statement parameters witness)
    (outside : ∀ opening lane, points opening ≠ canonicalPacking lane) :
    Q38Rp05PostFinalCompiler.publicMaskOpenings dsl statement parameters points
        (Q38Rp05ChronologicalAlgebra.response dsl statement parameters witness masks)
        (fun opening row => (witness row).eval (rp05PiopPoints points opening)) =
      sourceMaskEvaluations points masks := by
  apply Prod.ext
  · funext opening polynomial
    have hOpeningCount :
        V8Smz9ZeroKnowledge.piopOpeningCount = 6 := by rfl
    cases hOpeningCount
    have hWitnessCount :
        V8Smz9ZeroKnowledge.witnessPolynomialCount = 686 := by rfl
    cases hWitnessCount
    let point : Goldilocks := points opening
    let batch := currentNonlinearBatch dsl statement parameters witness polynomial
    have batchDegree : batch.natDegree ≤ 552 := by
      exact nonlinear_batch_degree _ _ (fun root => nonlinearDegree root)
    have quotientDegree :
        (sourceNonlinearQuotient canonicalPacking batch).natDegree < 489 :=
      lt_of_le_of_lt (nonlinear_quotient_degree canonicalPacking batch batchDegree)
        (by decide)
    have batchOpening : batch.eval point =
        ∑ root, nonlinearGamma dsl statement parameters polynomial root *
          nonlinearScalar dsl statement
            (fun row : Fin 686 =>
              (witness row).eval point) root := by
      change (nonlinearBatch
        (nonlinearGamma dsl statement parameters polynomial)
        (nonlinearConstraints dsl statement witness)).eval point = _
      rw [V8Smz9PiopOpeningRecovery.nonlinear_batch_eval]
      apply Finset.sum_congr rfl
      intro root _
      rw [nonlinearEval]
    change recoverNonlinearMaskOpening canonicalPacking
      (coefficientPolynomial (fun coefficient : Fin 489 =>
        (sourceNonlinearQuotient canonicalPacking batch).coeff coefficient.val +
          masks.1 polynomial coefficient)) _ point = _
    rw [show (fun coefficient : Fin 489 =>
        (sourceNonlinearQuotient canonicalPacking batch).coeff coefficient.val +
          masks.1 polynomial coefficient) =
        (fun coefficient : Fin 489 =>
          (sourceNonlinearQuotient canonicalPacking batch).coeff coefficient.val) +
          masks.1 polynomial by rfl]
    rw [coefficient_polynomial_add,
      coefficient_polynomial_of_coefficients _ quotientDegree]
    change recoverNonlinearMaskOpening canonicalPacking
      (sourceNonlinearQuotient canonicalPacking batch +
        coefficientPolynomial (masks.1 polynomial))
      (∑ root, nonlinearGamma dsl statement parameters polynomial root *
        nonlinearScalar dsl statement
          (fun row : Fin 686 => (witness row).eval point) root)
      point = _
    have recoverEq := congrArg
      (fun value => recoverNonlinearMaskOpening canonicalPacking
        (sourceNonlinearQuotient canonicalPacking batch +
          coefficientPolynomial (masks.1 polynomial)) value point)
      batchOpening.symm
    exact recoverEq.trans (recover_nonlinear_mask_opening canonicalPacking packingInjective
      batch (coefficientPolynomial (masks.1 polynomial))
      (nonlinear_batch_valid canonicalPacking
        (nonlinearGamma dsl statement parameters polynomial)
        (nonlinearConstraints dsl statement witness)
        valid.nonlinear) point
      (outside opening))
  · funext opening polynomial
    have hOpeningCount :
        V8Smz9ZeroKnowledge.piopOpeningCount = 6 := by rfl
    cases hOpeningCount
    let point : Goldilocks := points opening
    have batchedValid :
        (∑ row : Fin 686, ∑ lane : Fin 64,
          currentLinearWeights dsl statement parameters polynomial row lane *
            (witness row).eval (canonicalPacking lane)) =
        ∑ linearRow, linearGamma dsl statement parameters polynomial linearRow *
          dsl.linearTarget statement linearRow := by
      simpa only [currentLinearWeights, batchedLinearWeights] using
        (valid_linear_constraints_supply_batched_target
          (linearGamma dsl statement parameters polynomial)
          (dsl.linearWeights statement)
          (fun row lane => (witness row).eval (canonicalPacking lane))
          (dsl.linearTarget statement) valid.linear)
    have highEq :
        (Q38Rp05ChronologicalAlgebra.response dsl statement parameters
          witness masks).2 polynomial =
        fun index =>
          (sourceLinearUnmasked
              (currentLinearWeights dsl statement parameters polynomial)
              (sourcePackingLagrange canonicalPacking) witness +
            sourceLinearMask canonicalPacking (masks.2 polynomial)).coeff
              (index.val + 1) := by
      funext index
      simp only [Q38Rp05ChronologicalAlgebra.response, unmaskedResponse,
        Prod.snd_add, Pi.add_apply, coeff_add,
        source_linear_mask_nonconstant_coefficient]
    have recovered := source_linear_coins_recovered_from_opened_rows
      canonicalPacking packingInjective packingCardNonzero
      (currentLinearWeights dsl statement parameters polynomial)
      witness witnessDegree (masks.2 polynomial)
      (∑ linearRow, linearGamma dsl statement parameters polynomial linearRow *
        dsl.linearTarget statement linearRow)
      batchedValid point
    change recoverLinearMaskOpening canonicalPacking _
      ((Q38Rp05ChronologicalAlgebra.response dsl statement parameters
        witness masks).2 polynomial)
      (currentLinearWeights dsl statement parameters polynomial)
      (sourcePackingLagrange canonicalPacking)
      (fun row => (witness row).eval point) point =
      (sourceLinearMask canonicalPacking (masks.2 polynomial)).eval
          point
    rw [highEq]
    exact recovered

/-- The source PCS view and the public q38 mask recovery reconstruct the
very physical 12-by-368 combination heads committed in the leaf payload. -/
theorem rp05_combination_heads_are_physical
    (dsl : RelationDsl) (statement : Statement)
    (parameters : Parameters dsl statement)
    (points : Fin 6 → Goldilocks)
    (packingInjective : Function.Injective canonicalPacking)
    (packingCardNonzero : (64 : Goldilocks) ≠ 0)
    (witness : Fin 686 → Goldilocks[X])
    (witnessDegree : ∀ row, (witness row).natDegree ≤ 69)
    (nonlinearDegree : ∀ root,
      (nonlinearConstraints dsl statement witness root).natDegree ≤ 552)
    (nonlinearEval : ∀ root point,
      (nonlinearConstraints dsl statement witness root).eval point =
        nonlinearScalar dsl statement
          (fun row => (witness row).eval point) root)
    (masks : Q) (pcs : SourcePcsCoins Goldilocks)
    (valid : ValidPackedWitness dsl statement parameters witness)
    (outside : ∀ opening lane, points opening ≠ canonicalPacking lane) :
    combinationHeads dsl statement parameters points
        (Q38Rp05ChronologicalAlgebra.response dsl statement parameters witness masks)
        (fun opening row => (witness row).eval (points opening))
        (sourcePcsFullView points (pcsBase points masks 0) pcs) =
      lvcsPublicCombinationHeads (rp05PiopPoints points)
        (physicalHeads witness masks pcs) := by
  have hOpeningCount : V8Smz9ZeroKnowledge.piopOpeningCount = 6 := by rfl
  cases hOpeningCount
  change reconstructedCombinationHeads points
    (fun opening row => (witness row).eval (points opening))
      (publicMaskOpenings dsl statement parameters points
        (Q38Rp05ChronologicalAlgebra.response dsl statement parameters witness masks)
      (fun opening row => (witness row).eval (rp05PiopPoints points opening)))
    (sourcePcsFullView points (physicalPartialBase points masks) pcs) = _
  rw [rp05_public_masks_are_source_masks dsl statement parameters points
    packingInjective packingCardNonzero witness witnessDegree nonlinearDegree
    nonlinearEval masks valid outside]
  calc
    _ = lvcsPublicCombinationHeads points (physicalHeads witness masks pcs) :=
      physical_combination_heads_are_publicly_reconstructed points witness
        masks pcs (physical_column_degree witness masks pcs witnessDegree)
    _ = lvcsPublicCombinationHeads (rp05PiopPoints points)
        (physicalHeads witness masks pcs) := by
      exact (HegemonCrypto.SmallWood.Q38Rp05PublicHeadIndexBridge.rp05_public_combination_heads_fin6_cast
        points (physicalHeads witness masks pcs)).symm

/-- Direct current-DSL packing-lane acceptance predicates.  These are the
finite 818-root scalar zeros and each normalized CSR row equation against
its actual public target (which need not be zero). -/
structure ValidCurrentDslPackedValues (dsl : RelationDsl) (statement : Statement)
    (values : WitnessPackingValues Goldilocks) : Prop where
  nonlinear : ∀ root lane,
    nonlinearScalar dsl statement (fun row => values row lane) root = 0
  linear : ∀ linearRow : Fin (dsl.linearCount statement),
    (∑ witnessRow : Fin 686, ∑ lane : Fin 64,
      dsl.linearWeights statement linearRow witnessRow lane *
        values witnessRow lane) = dsl.linearTarget statement linearRow

/-- Executable nonlinear acceptance forces all of the current finite DSL
root scalars to vanish on every one of the 64 packed lanes. -/
theorem accepted_packed_supplies_nonlinear_scalars
    (dsl : RelationDsl) (certificates : GeneratedCertificates dsl)
    (statement : Statement) (packed : List Nat)
    (accepted : dsl.components.AcceptsPacked (currentPublicWords statement) packed) :
    ∀ root lane, nonlinearScalar dsl statement
      (fun row => packingValues packed row lane) root = 0 := by
  intro root lane
  let rows := sourcePackingRows (packingValues packed) lane
  have acceptedLane : dsl.components.nonlinearExecutable.Accepts
      (currentPublicWords statement) rows := by
    change dsl.components.nonlinearExecutable.Accepts
      (currentPublicWords statement) (sourcePackingRows (packingValues packed) lane)
    rw [source_packing_rows_match_packed_lane
      (witness := packed) accepted.2.1 lane]
    exact accepted.2.2.1 lane.val lane.isLt
  have member : dsl.nonlinearRoot root ∈
      dsl.components.nonlinearExecutable.roots := by
    rw [certificates.nonlinear.rootsExact]
    exact List.mem_ofFn.mpr ⟨root, rfl⟩
  obtain ⟨trace, evaluated, zero⟩ :=
    acceptance_makes_each_named_root_zero acceptedLane member
  have rootBound := certificates.nonlinear.programCanonical.2
    (dsl.nonlinearRoot root) member
  have sourceEval := fieldAt_refines_source
    dsl.components.nonlinearExecutable (currentPublicWords statement)
    rows trace certificates.nonlinear.programCanonical evaluated
    (dsl.nonlinearRoot root) rootBound
  have zeroField : (trace.getD (dsl.nonlinearRoot root) 0 : Goldilocks) = 0 := by
    simp [List.getD_eq_getElem?_getD, zero]
  have rowValues :
      (fun n => (rows.getD n 0 : Goldilocks)) =
      witnessFieldAtNat (fun row => packingValues packed row lane) := by
    change (fun n => ((sourcePackingRows (packingValues packed) lane).getD n 0 : Goldilocks)) =
      V8Smz9EagerSimulator.openedWitnessAtNat
        (fun row => packingValues packed row lane)
    exact (V8Smz9CurrentSourceAcceptance.source_packing_rows_field_values
      (packingValues packed) lane).symm
  change fieldAt dsl.components.nonlinearExecutable.expressions
      (publicFieldAtNat statement)
      (witnessFieldAtNat (fun row => packingValues packed row lane))
      (dsl.nonlinearRoot root) = 0
  rw [← rowValues]
  exact sourceEval.trans zeroField

/-- Every retained normalized CSR row is a raw accepted attempt.  An empty
raw coefficient vector with nonzero target cannot be accepted, so the
fallback source-cell rewrite does not invent a valid linear equation. -/
theorem accepted_packed_supplies_normalized_csr_rows
    (components : RelationProgramComponents)
    (nonlinearRoot : Fin 818 → Nat) (nodeDegree : Nat → Nat)
    (certificates : GeneratedCertificates
      (normalizedDsl components nonlinearRoot nodeDegree))
    (statement : Statement) (packed : List Nat)
    (accepted : components.AcceptsPacked (currentPublicWords statement) packed) :
    ∀ linearRow : Fin ((normalizedDsl components nonlinearRoot nodeDegree).linearCount statement),
      (∑ witnessRow : Fin 686, ∑ lane : Fin 64,
        (normalizedDsl components nonlinearRoot nodeDegree).linearWeights
          statement linearRow witnessRow lane *
          packingValues packed witnessRow lane) =
        (normalizedDsl components nonlinearRoot nodeDegree).linearTarget
          statement linearRow := by
  intro linearRow
  let attempt := (retained components statement)[linearRow.val]
  have selectedMember : attempt ∈ retained components statement :=
    List.getElem_mem (l := retained components statement) linearRow.isLt
  have selected := (retained_member_iff components statement attempt).mp selectedMember
  obtain ⟨trace, evaluated, acceptedAttempts⟩ := accepted.2.2.2
  have bounded : ∀ term, term ∈ attempt.terms → term.1 < 43904 := by
    intro term member
    exact ((certificates.csr.attemptCoordinates attempt selected.1).1 term member).1
  have rawEq :
      (∑ index : Fin 43904,
        SmzaRp05CsrNormalization.rawCoefficient components statement attempt index *
          packedFieldValues packed index) =
        SmzaRp05CsrNormalization.rawTarget components statement attempt := by
    have equation := accepted_csr_attempt_field_equality
      (acceptedAttempts attempt selected.1)
    rw [← dense_coefficient_dot trace packed attempt.terms bounded] at equation
    have traceEq : SmzaRp05CsrNormalization.values components statement = trace :=
      Option.some.inj
        ((SmzaRp05CsrNormalization.values_evaluation_succeeds components
          certificates.csr.programCanonical statement).symm.trans evaluated)
    simpa only [SmzaRp05CsrNormalization.rawCoefficient,
      SmzaRp05CsrNormalization.rawTarget, traceEq] using equation
  have nonempty : ¬ SmzaRp05CsrNormalization.rawEmpty components statement attempt := by
    intro empty
    have rawZero :
        (∑ index : Fin 43904,
          SmzaRp05CsrNormalization.rawCoefficient components statement attempt index *
            packedFieldValues packed index) = 0 := by
      apply Finset.sum_eq_zero
      intro index _
      rw [empty index, zero_mul]
    exact selected.2 ⟨empty, rawEq.symm.trans rawZero⟩
  have denseEq :
      (∑ index : Fin 43904,
        normalizedRowCoefficient
          (normalizedDsl components nonlinearRoot nodeDegree)
          statement linearRow index * packedFieldValues packed index) =
        (normalizedDsl components nonlinearRoot nodeDegree).linearTarget
          statement linearRow := by
    have coefficients : ∀ index : Fin 43904,
        normalizedRowCoefficient
            (normalizedDsl components nonlinearRoot nodeDegree)
            statement linearRow index =
          SmzaRp05CsrNormalization.rawCoefficient components statement attempt index := by
        intro index
        rw [normalized_row_coefficient_eq]
        change SmzaRp05CsrNormalization.normalizedCoefficient components statement
          attempt index = SmzaRp05CsrNormalization.rawCoefficient components statement
            attempt index
        simp only [SmzaRp05CsrNormalization.normalizedCoefficient,
          if_neg nonempty]
    calc
      _ = ∑ index : Fin 43904,
          SmzaRp05CsrNormalization.rawCoefficient components statement attempt index *
            packedFieldValues packed index := by
        apply Finset.sum_congr rfl
        intro index _
        rw [coefficients]
      _ = SmzaRp05CsrNormalization.rawTarget components statement attempt := rawEq
      _ = (normalizedDsl components nonlinearRoot nodeDegree).linearTarget
          statement linearRow :=
        (normalized_linear_target_eq components nonlinearRoot nodeDegree
          statement linearRow).symm
  rw [← packed_coordinate_sum] at denseEq
  simpa only [normalizedRowCoefficient, packingValues,
    Equiv.symm_apply_apply] using denseEq

/-- The executable accepted packed witness supplies exactly the finite
current-DSL root and normalized-CSR premises consumed by mask recovery. -/
theorem accepted_packed_supplies_valid_current_dsl
    (components : RelationProgramComponents)
    (nonlinearRoot : Fin 818 → Nat) (nodeDegree : Nat → Nat)
    (certificates : GeneratedCertificates
      (normalizedDsl components nonlinearRoot nodeDegree))
    (statement : Statement) (packed : List Nat)
    (accepted : components.AcceptsPacked (currentPublicWords statement) packed) :
    ValidCurrentDslPackedValues
      (normalizedDsl components nonlinearRoot nodeDegree)
      statement (packingValues packed) := by
  constructor
  · exact accepted_packed_supplies_nonlinear_scalars
      (normalizedDsl components nonlinearRoot nodeDegree) certificates
      statement packed accepted
  · exact accepted_packed_supplies_normalized_csr_rows components
      nonlinearRoot nodeDegree certificates statement packed accepted

/-- Canonical row-major encoding of the fixed 686-by-64 field assignment. -/
def rp05PackValues (values : WitnessPackingValues Goldilocks) : List Nat :=
  List.ofFn fun index : Fin 43904 =>
    let coordinate := (finProdFinEquiv : Fin 686 × Fin 64 ≃ Fin 43904).symm index
    (values coordinate.1 coordinate.2).val

theorem packing_values_rp05_pack_values
    (values : WitnessPackingValues Goldilocks) :
    packingValues (rp05PackValues values) = values := by
  funext row lane
  let index : Fin 43904 := finProdFinEquiv (row, lane)
  have packedEntry :
      (rp05PackValues values).getD index.val 0 = (values row lane).val := by
    unfold rp05PackValues
    simp only [List.getD_eq_getElem?_getD, List.getElem?_ofFn, index,
      Fin.isLt, ↓reduceDIte, Option.getD_some, Fin.eta,
      Equiv.symm_apply_apply]
  change ((rp05PackValues values).getD index.val 0 : Goldilocks) = values row lane
  rw [packedEntry]
  exact ZMod.natCast_zmod_val (values row lane)

/-- Final source-state form: validity is stated in the direct finite
current-DSL packing-lane constraints, not as the desired mask or
combination-head equality.  Degree/evaluation facts follow from the
generated DAG certificate and actual six-coin interpolation. -/
theorem rp05_source_combination_heads_are_physical
    (dsl : RelationDsl) (certificates : GeneratedCertificates dsl)
    (statement : Statement) (parameters : Parameters dsl statement)
    (points : Fin 6 → Goldilocks)
    (admissible : Smz9WitnessInterpolationAdmissible points)
    (values : WitnessPackingValues Goldilocks)
    (coins : WitnessInterpolationCoins Goldilocks)
    (masks : Q) (pcs : SourcePcsCoins Goldilocks)
    (valid : ValidCurrentDslPackedValues dsl statement values) :
    combinationHeads dsl statement parameters points
        (Q38Rp05ChronologicalAlgebra.response dsl statement parameters
          (sourceWitnessPolynomials values coins) masks)
        (sourceWitnessOpenings values points coins)
        (sourcePcsFullView points (pcsBase points masks 0) pcs) =
      lvcsPublicCombinationHeads points
        (physicalHeads (sourceWitnessPolynomials values coins) masks pcs) := by
  have witnessDegree := source_witness_polynomials_degree points admissible values coins
  have nonlinearDegree : ∀ root,
      (nonlinearConstraints dsl statement
        (sourceWitnessPolynomials values coins) root).natDegree ≤ 552 := by
    intro root
    exact (rp05_nonlinear_degree_and_evaluation dsl certificates statement
      (sourceWitnessPolynomials values coins) witnessDegree root 0).1
  have nonlinearEval : ∀ root point,
      (nonlinearConstraints dsl statement
        (sourceWitnessPolynomials values coins) root).eval point =
        nonlinearScalar dsl statement
          (fun row => (sourceWitnessPolynomials values coins row).eval point) root := by
    intro root point
    exact (rp05_nonlinear_degree_and_evaluation dsl certificates statement
      (sourceWitnessPolynomials values coins) witnessDegree root point).2
  have sourceValid : ValidPackedWitness dsl statement parameters
      (sourceWitnessPolynomials values coins) := by
    constructor
    · intro root lane
      rw [nonlinearEval root (canonicalPacking lane)]
      have packingRows :
          (fun row => (sourceWitnessPolynomials values coins row).eval
            (canonicalPacking lane)) = (fun row => values row lane) := by
        funext row
        exact source_witness_polynomials_evaluate_at_packing points admissible
          values coins row lane
      rw [packingRows]
      exact valid.nonlinear root lane
    · intro linearRow
      simp_rw [source_witness_polynomials_evaluate_at_packing points admissible
        values coins]
      exact valid.linear linearRow
  exact rp05_combination_heads_are_physical dsl statement parameters points
    admissible.packingPointsInjective (by decide)
    (sourceWitnessPolynomials values coins) witnessDegree nonlinearDegree
    nonlinearEval masks pcs sourceValid admissible.openingsOutsidePacking

/-- Accepted-current-DSL form, with no external validity oracle or mask
equality premise: the canonical packed bytes are accepted by the same
normalized executable components from which the RP05 PIOP parameters and
linear targets are drawn. -/
theorem rp05_accepted_combination_heads_are_physical
    (components : RelationProgramComponents)
    (nonlinearRoot : Fin 818 → Nat) (nodeDegree : Nat → Nat)
    (certificates : GeneratedCertificates
      (normalizedDsl components nonlinearRoot nodeDegree))
    (statement : Statement)
    (parameters : Parameters
      (normalizedDsl components nonlinearRoot nodeDegree) statement)
    (points : Fin 6 → Goldilocks)
    (admissible : Smz9WitnessInterpolationAdmissible points)
    (values : WitnessPackingValues Goldilocks)
    (coins : WitnessInterpolationCoins Goldilocks)
    (masks : Q) (pcs : SourcePcsCoins Goldilocks)
    (accepted : components.AcceptsPacked (currentPublicWords statement)
      (rp05PackValues values)) :
    combinationHeads (normalizedDsl components nonlinearRoot nodeDegree)
        statement parameters points
        (Q38Rp05ChronologicalAlgebra.response
          (normalizedDsl components nonlinearRoot nodeDegree)
          statement parameters (sourceWitnessPolynomials values coins) masks)
        (sourceWitnessOpenings values points coins)
        (sourcePcsFullView points (pcsBase points masks 0) pcs) =
      lvcsPublicCombinationHeads points
        (physicalHeads (sourceWitnessPolynomials values coins) masks pcs) := by
  have valid := accepted_packed_supplies_valid_current_dsl components
    nonlinearRoot nodeDegree certificates statement (rp05PackValues values)
    accepted
  rw [packing_values_rp05_pack_values] at valid
  exact rp05_source_combination_heads_are_physical
    (normalizedDsl components nonlinearRoot nodeDegree) certificates
    statement parameters points admissible values coins masks pcs valid

end
end HegemonCrypto.SmallWood.Q38Rp05MaskRecovery
