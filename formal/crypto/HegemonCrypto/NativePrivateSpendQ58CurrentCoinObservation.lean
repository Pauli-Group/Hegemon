import HegemonCrypto.NativePrivateSpendQ58CurrentChronologicalRequest
set_option stderrAsMessages false
#eval IO.eprintln "COIN_OBSERVATION_MODULE_START"

/-! The6+60 scalar observation bridge used by the single current public join.
Prove source poly_restore equals the retained unit-high basis construction once,
then take its finite product at26210 rows. No per-row refinement family is used.
The PCS bridge keeps the original ten6-coin blocks and exact delta59/1 columns.
-/
namespace HegemonCrypto.SmallWood.NativePrivateSpendQ58CurrentCoinObservation
open Polynomial
open V8Smz9ZeroKnowledge V8Smz9EagerPrivacy V8Smz9PiopOpeningRecovery V8Smz9EagerSimulator
open NativePrivateSpendQ58CurrentChronologicalRequest
open scoped BigOperators Classical
noncomputable section
set_option autoImplicit false
set_option Elab.async false
set_option maxHeartbeats 0
set_option maxRecDepth 0
set_option stderrAsMessages false

#eval IO.eprintln "COIN_OBSERVATION_DECL_START: packingEvaluation"
def packingEvaluation : Goldilocks[X] →ₗ[Goldilocks] (Fin 64 → Goldilocks) :=
  LinearMap.pi fun lane => Polynomial.leval (NativePrivateSpendQ58Compff01SourceColumns.packing lane)

#eval IO.eprintln "COIN_OBSERVATION_DECL_START: removePacking"
def removePacking : Goldilocks[X] →ₗ[Goldilocks] Goldilocks[X] :=
  LinearMap.id - (Lagrange.interpolate (Finset.univ : Finset (Fin 64))
    NativePrivateSpendQ58Compff01SourceColumns.packing).comp packingEvaluation

#eval IO.eprintln "COIN_OBSERVATION_DECL_START: remove_packing_apply"
theorem remove_packing_apply (polynomial : Goldilocks[X]) :
    removePacking polynomial = polynomial -
      Lagrange.interpolate (Finset.univ : Finset (Fin 64))
        NativePrivateSpendQ58Compff01SourceColumns.packing
        (fun lane => polynomial.eval (NativePrivateSpendQ58Compff01SourceColumns.packing lane)) := rfl

#eval IO.eprintln "COIN_OBSERVATION_DECL_START: source_high_part"
theorem source_high_part (coins : Fin 6 → Goldilocks) :
    X ^ 64 * coefficientPolynomial coins = witnessHighPart coins := by
  unfold coefficientPolynomial witnessHighPart
  rw [Finset.mul_sum]
  apply Finset.sum_congr rfl
  intro coefficient _
  change X ^ 64 * (C (coins coefficient) * X ^ coefficient.val) =
    C (coins coefficient) * X ^ (64 + coefficient.val)
  rw [pow_add]
  ring

#eval IO.eprintln "COIN_OBSERVATION_DECL_START: witness_basis_is_remove"
theorem witness_basis_is_remove (coin : Fin 6) :
    witnessBasisPolynomial coin = removePacking (X ^ (64 + coin.val)) := by
  unfold witnessBasisPolynomial DecsRestore.restorePolynomial
  rw [remove_packing_apply]
  change Lagrange.interpolate (Finset.univ : Finset (Fin 64))
      NativePrivateSpendQ58Compff01SourceColumns.packing
      (fun lane => 0 - (X ^ (64 + coin.val)).eval
        (NativePrivateSpendQ58Compff01SourceColumns.packing lane)) + X ^ (64 + coin.val) = _
  simp only [zero_sub]
  have negative_interpolation :
      Lagrange.interpolate (Finset.univ : Finset (Fin 64))
        NativePrivateSpendQ58Compff01SourceColumns.packing
        (fun lane => -(X ^ (64 + coin.val)).eval
          (NativePrivateSpendQ58Compff01SourceColumns.packing lane)) =
      -(Lagrange.interpolate (Finset.univ : Finset (Fin 64))
        NativePrivateSpendQ58Compff01SourceColumns.packing
        (fun lane => (X ^ (64 + coin.val)).eval
          (NativePrivateSpendQ58Compff01SourceColumns.packing lane))) :=
    map_neg (Lagrange.interpolate (Finset.univ : Finset (Fin 64))
      NativePrivateSpendQ58Compff01SourceColumns.packing)
      (fun lane => (X ^ (64 + coin.val)).eval
        (NativePrivateSpendQ58Compff01SourceColumns.packing lane))
  rw [negative_interpolation]
  abel

#eval IO.eprintln "COIN_OBSERVATION_DECL_START: witness_randomness_is_remove"
theorem witness_randomness_is_remove (coins : Fin 6 → Goldilocks) :
    witnessRandomnessPolynomial coins = removePacking (witnessHighPart coins) := by
  unfold witnessRandomnessPolynomial witnessHighPart
  rw [map_sum]
  simp_rw [← smul_eq_C_mul, map_smul]
  apply Finset.sum_congr rfl
  intro coin _
  rw [witness_basis_is_remove]
  rfl

#eval IO.eprintln "COIN_OBSERVATION_DECL_START: restore_witness_is_retained_basis"
/-- Derived source identity, not a refinement equality supplied as an input. -/
theorem restore_witness_is_retained_basis (values : Fin 64 → Goldilocks)
    (coins : Fin 6 → Goldilocks) :
    NativePrivateSpendQ58Compff01SourceColumns.restoreWitness values coins =
      sourceWitnessBasePolynomial values + witnessRandomnessPolynomial coins := by
  fail_if_success
    run_tac (liftM (IO.eprintln "COIN_RESTORE_PHASE: base_sub_statement_start") : Lean.Elab.Tactic.TacticM Unit)
    fail
  -- Keep interpolation abstract while proving its subtraction law.
  have base_sub {F : Type} [Field F] (left right : Fin 64 → F) :
      sourceWitnessBasePolynomial (fun lane => left lane - right lane) =
        sourceWitnessBasePolynomial left - sourceWitnessBasePolynomial right := by
    fail_if_success
      run_tac (liftM (IO.eprintln "COIN_RESTORE_PHASE: base_sub_proof_start") : Lean.Elab.Tactic.TacticM Unit)
      fail
    simp only [sourceWitnessBasePolynomial, map_sub, sub_mul, Finset.sum_sub_distrib]
  fail_if_success
    run_tac (liftM (IO.eprintln "COIN_RESTORE_PHASE: base_sub_done") : Lean.Elab.Tactic.TacticM Unit)
    fail
  -- Fold the source-base interface at an abstract polynomial, before coins.
  fail_if_success
    run_tac (liftM (IO.eprintln "COIN_RESTORE_PHASE: remove_base_start") : Lean.Elab.Tactic.TacticM Unit)
    fail
  have remove_base (polynomial : Goldilocks[X]) :
      removePacking polynomial = polynomial - sourceWitnessBasePolynomial
        (fun lane => polynomial.eval (NativePrivateSpendQ58Compff01SourceColumns.packing lane)) := rfl
  fail_if_success
    run_tac (liftM (IO.eprintln "COIN_RESTORE_PHASE: remove_base_done") : Lean.Elab.Tactic.TacticM Unit)
    fail
  fail_if_success
    run_tac (liftM (IO.eprintln "COIN_RESTORE_PHASE: first_rw_start") : Lean.Elab.Tactic.TacticM Unit)
    fail
  rw [witness_randomness_is_remove, ← source_high_part, remove_base]
  fail_if_success
    run_tac (liftM (IO.eprintln "COIN_RESTORE_PHASE: first_rw_done") : Lean.Elab.Tactic.TacticM Unit)
    fail
  fail_if_success
    run_tac (liftM (IO.eprintln "COIN_RESTORE_PHASE: change_start") : Lean.Elab.Tactic.TacticM Unit)
    fail
  rw [NativePrivateSpendQ58Compff01SourceColumns.restoreWitness]
  fail_if_success
    run_tac (liftM (IO.eprintln "COIN_RESTORE_PHASE: change_done") : Lean.Elab.Tactic.TacticM Unit)
    fail
  fail_if_success
    run_tac (liftM (IO.eprintln "COIN_RESTORE_PHASE: base_sub_rw_start") : Lean.Elab.Tactic.TacticM Unit)
    fail
  have residual := base_sub values (fun lane =>
    (X ^ 64 * coefficientPolynomial coins).eval
      (NativePrivateSpendQ58Compff01SourceColumns.packing lane))
  fail_if_success
    run_tac (liftM (IO.eprintln "COIN_RESTORE_PHASE: base_sub_rw_done") : Lean.Elab.Tactic.TacticM Unit)
    fail
  fail_if_success
    run_tac (liftM (IO.eprintln "COIN_RESTORE_PHASE: abel_start") : Lean.Elab.Tactic.TacticM Unit)
    fail
  have regroup (base correction highPart : Goldilocks[X]) :
      (base - correction) + highPart = base + (highPart - correction) := by
    abel
  exact (congrArg (fun polynomial : Goldilocks[X] =>
    polynomial + X ^ 64 * coefficientPolynomial coins) residual).trans (regroup _ _ _)

#eval IO.eprintln "COIN_OBSERVATION_DECL_START: witness_observation_is_source"
/-- One finite product of the source scalar identity. -/
theorem witness_observation_is_source {rows : Nat}
    (values : NativePrivateSpendQ58CurrentRowBoundary.Values rows)
    (points : Fin 6 → Goldilocks) (admissible : Smz9WitnessInterpolationAdmissible points)
    (coins : NativePrivateSpendQ58CurrentRowBoundary.W rows) :
    NativePrivateSpendQ58CurrentRowBoundary.witnessEquiv values points admissible coins =
      (fun row opening => (NativePrivateSpendQ58Compff01SourceColumns.restoreWitness
        (values row) (coins row)).eval (points opening)) := by
  funext row opening
  rw [restore_witness_is_retained_basis, eval_add]
  change (sourceWitnessBasePolynomial (values row)).eval (points opening) +
      (witnessRandomnessPolynomial (coins row)).eval (points opening) = _
  rfl

#eval IO.eprintln "COIN_OBSERVATION_DECL_START: unstack_second_formula"
/-- Literal second unstacked column. This formula is scalar and generic in
width; the two current instances are count11/delta59 and count69/delta1. -/
theorem unstack_second_formula {count : Nat} (delta : Nat)
    (mask : Fin (64 + count) → Goldilocks) (coins : Fin 6 → Goldilocks) (point : Goldilocks) :
    (NativePrivateSpendQ58Compff01SourceColumns.unstackPair delta mask coins 1).eval point =
      (∑ coefficient : Fin count, mask (Fin.natAdd 64 coefficient) * point ^ (delta + coefficient.val)) -
        point ^ delta * ∑ coefficient : Fin 6, point ^ coefficient.val * coins coefficient := by
  change (X ^ delta * (coefficientPolynomial
      (NativePrivateSpendQ58Compff01SourceColumns.high mask) - coefficientPolynomial coins)).eval point = _
  simp only [eval_mul, eval_pow, eval_X, eval_sub, coefficient_polynomial_evaluation, mul_sub]
  have offset : point ^ delta *
      (∑ coefficient : Fin count, point ^ coefficient.val *
        NativePrivateSpendQ58Compff01SourceColumns.high mask coefficient) =
      ∑ coefficient : Fin count, mask (Fin.natAdd 64 coefficient) * point ^ (delta + coefficient.val) := by
    rw [Finset.mul_sum]
    apply Finset.sum_congr rfl
    intro coefficient _
    rw [pow_add]
    simp only [NativePrivateSpendQ58Compff01SourceColumns.high]
    ring
  rw [offset]

#eval IO.eprintln "COIN_OBSERVATION_DECL_START: linear_high_is_source"
theorem linear_high_is_source (coins : Fin 132 → Goldilocks) (index : Fin 69) :
    NativePrivateSpendQ58Compff01SourceColumns.high
      (NativePrivateSpendQ58Compff01SourceColumns.linearFull coins) index =
      coins ⟨63 + index.val, by have _ := index.isLt; omega⟩ := by
  change (sourceLinearMask NativePrivateSpendQ58Compff01SourceColumns.packing coins).coeff
    (64 + index.val) = _
  have degree : 64 + index.val = (63 + index.val) + 1 := by omega
  rw [degree]
  exact V8Smz9EagerSimulator.source_linear_mask_nonconstant_coefficient
    NativePrivateSpendQ58Compff01SourceColumns.packing coins
    (⟨63 + index.val, by have _ := index.isLt; omega⟩ : Fin 132)

#eval IO.eprintln "COIN_OBSERVATION_DECL_START: sourcePartials"
/-- The source ten partial columns with the SAME original60 PCS coins. -/
def sourcePartials (points : Fin 6 → Goldilocks)
    (masks : NativePrivateSpendQ58CurrentRowBoundary.Q)
    (pcs : NativePrivateSpendQ58CurrentRowBoundary.P) : NativePrivateSpendQ58CurrentRowBoundary.P :=
  fun opening column =>
    if left : column.val < 5 then
      (NativePrivateSpendQ58Compff01SourceColumns.unstackPair (count := 11) 59
        (masks.1 ⟨column.val, left⟩) (fun coefficient => pcs coefficient column) 1).eval (points opening)
    else (NativePrivateSpendQ58Compff01SourceColumns.unstackPair (count := 69) 1
      (NativePrivateSpendQ58Compff01SourceColumns.linearFull
        (masks.2 ⟨column.val - 5, by have _ := column.isLt; omega⟩))
      (fun coefficient => pcs coefficient column) 1).eval (points opening)

#eval IO.eprintln "COIN_OBSERVATION_DECL_START: partial_observation_is_source"
theorem partial_observation_is_source (points : Fin 6 → Goldilocks)
    (distinct : Function.Injective points) (nonzero : ∀ opening, points opening ≠ 0)
    (masks : NativePrivateSpendQ58CurrentRowBoundary.Q)
    (pcs : NativePrivateSpendQ58CurrentRowBoundary.P) :
    NativePrivateSpendQ58Wpcs.partialEquiv points distinct nonzero masks pcs = sourcePartials points masks pcs := by
  funext opening column
  change NativePrivateSpendQ58Wpcs.partialBase points masks opening column +
    NativePrivateSpendQ58Wpcs.partialEffect points pcs opening column = _
  by_cases left : column.val < 5
  · have nonlinearBase : NativePrivateSpendQ58Wpcs.partialBase points masks opening column =
        ∑ coefficient : Fin 11,
          masks.1 ⟨column.val, left⟩ (Fin.natAdd 64 coefficient) *
            points opening ^ (59 + coefficient.val) := by
      calc
        NativePrivateSpendQ58Wpcs.partialBase points masks opening column =
            ∑ coefficient : Fin 11,
              masks.1 ⟨column.val, left⟩
                ⟨64 + coefficient.val, by have _ := coefficient.isLt; omega⟩ *
                  points opening ^ (59 + coefficient.val) := by
          simp only [NativePrivateSpendQ58Wpcs.partialBase, dif_pos left]
        _ = _ := by
          apply Finset.sum_congr rfl
          intro coefficient _
          have index_eq : (⟨64 + coefficient.val, by have _ := coefficient.isLt; omega⟩ : Fin 75) =
              Fin.natAdd 64 coefficient := by
            apply Fin.ext
            rfl
          exact congrArg (fun index : Fin 75 =>
            masks.1 ⟨column.val, left⟩ index * points opening ^ (59 + coefficient.val)) index_eq
    rw [nonlinearBase]
    simp only [sourcePartials, dif_pos left, NativePrivateSpendQ58Wpcs.partialEffect,
      NativePrivateSpendQ58Wpcs.delta, if_pos left]
    rw [unstack_second_formula]
    ring
  · simp only [sourcePartials, dif_neg left, NativePrivateSpendQ58Wpcs.partialBase,
      NativePrivateSpendQ58Wpcs.partialEffect, NativePrivateSpendQ58Wpcs.delta, if_neg left]
    rw [unstack_second_formula]
    have high : ∀ coefficient : Fin 69,
      NativePrivateSpendQ58Compff01SourceColumns.linearFull
        (masks.2 ⟨column.val - 5, by have _ := column.isLt; omega⟩)
        (Fin.natAdd 64 coefficient) =
      masks.2 ⟨column.val - 5, by have _ := column.isLt; omega⟩
        ⟨63 + coefficient.val, by have _ := coefficient.isLt; omega⟩ := by
      intro coefficient
      exact linear_high_is_source _ coefficient
    simp_rw [high]
    ring

#eval IO.eprintln "COIN_OBSERVATION_DECL_START: public_fields_ext"
theorem public_fields_ext (left right : NativePrivateSpendQ58CurrentPublicOpening.PublicFields)
    (gamma : left.gamma = right.gamma) (transcript : left.transcript = right.transcript)
    (opened : left.opened = right.opened) (partials : left.partials = right.partials) : left = right := by
  cases left
  cases right
  cases gamma
  cases transcript
  cases opened
  cases partials
  rfl

#eval IO.eprintln "COIN_OBSERVATION_DECL_START: observedPublicFields"
/-- This representation contains only public fields, with the transformed
witness scalars/PCS partials rather than any original witness or mask coins. -/
def observedPublicFields (gamma : CurrentGamma) (transcript : NativePrivateSpendQ58CurrentRowBoundary.Q)
    (observed : NativePrivateSpendQ58CurrentRowBoundary.W 26210 × NativePrivateSpendQ58CurrentRowBoundary.P) :
    NativePrivateSpendQ58CurrentPublicOpening.PublicFields where
  gamma := gamma
  transcript := transcript
  opened := fun opening row => observed.1 row opening
  partials := observed.2

#eval IO.eprintln "COIN_OBSERVATION_SOURCE_FIELDS_START"
section LinearResponseOpacity
attribute [local irreducible] HegemonCrypto.SmallWood.V8Smz9PiopOpeningRecovery.sourceLinearUnmasked
attribute [local irreducible] HegemonCrypto.SmallWood.NativePrivateSpendQ58CurrentPublicOpening.weights

#eval IO.eprintln "COIN_OBSERVATION_DECL_START: source_fields_are_conditioned_public"
/-- Actual public-field factorization at the response-conditioned original
coins. Its only relation/field ingredients are literal source constructors.
The gamma schedule depends on the prior PUBLIC reply D and raw table; the
1035 transcript coordinates and157260 opened witness coordinates remain shared
with the same source response and coins, never resampled independently. -/
theorem source_fields_are_conditioned_public (bound : Nat) (largeEnough : 527737 ≤ bound)
    (oracle : NativePrivateSpendQ58CurrentLeafInput.CurrentFullRawInput bound →
      V8Smz9HiddenLeafQrom.DigestRegister)
    (relation : NativePrivateSpendQ58CurrentPublicOpening.Relation)
    (values : NativePrivateSpendQ58CurrentRowBoundary.Values 26210)
    (hashMt : V8Smz9HiddenLeafQrom.DigestRegister) (binding : Fin 77 → Goldilocks)
    (decsGamma : NativePrivateSpendQ58CurrentRowBoundary.Gamma) (pending : Bool)
    (response : NativePrivateSpendQ58CurrentRowBoundary.Response)
    (points : Fin 6 → Goldilocks) (admissible : Smz9WitnessInterpolationAdmissible points)
    (nonzero : ∀ opening, points opening ≠ 0)
    (original : NativePrivateSpendQ58CurrentRowBoundary.W 26210 × NativePrivateSpendQ58CurrentRowBoundary.P) :
    let model := currentSourceModel bound largeEnough oracle relation values hashMt binding decsGamma pending
    let gamma := prefixGamma (V8Smz9HonestRequestSchedule.NonleafProgram.interpret
      (fun input => oracle (.inr input)) (piopPrefix bound largeEnough hashMt binding response.1 pending))
    let masks := response.2 - model.piopUnmasked original.1 response.1
    NativePrivateSpendQ58CurrentPublicOpening.sourceFields relation gamma
      (sourceData values original.1 original.2 masks) points =
    observedPublicFields gamma response.2
      (NativePrivateSpendQ58CurrentRowBoundary.conditionedEquiv values points admissible nonzero model response original) := by
  dsimp only
  let model := currentSourceModel bound largeEnough oracle relation values hashMt binding decsGamma pending
  let gamma := prefixGamma (V8Smz9HonestRequestSchedule.NonleafProgram.interpret
    (fun input => oracle (.inr input)) (piopPrefix bound largeEnough hashMt binding response.1 pending))
  let masks := response.2 - model.piopUnmasked original.1 response.1
  have observed : NativePrivateSpendQ58CurrentRowBoundary.conditionedEquiv values points admissible nonzero
      model response original =
    (NativePrivateSpendQ58CurrentRowBoundary.witnessEquiv values points admissible original.1,
      NativePrivateSpendQ58Wpcs.partialEquiv points admissible.openingPointsInjective nonzero masks original.2) := by
    simp [NativePrivateSpendQ58CurrentRowBoundary.conditionedEquiv,
      NativePrivateSpendQ58ChronologicalMasks.fiberEquiv, masks]
  rw [observed]
  have transcript :
      (NativePrivateSpendQ58CurrentPublicOpening.sourceFields relation gamma
        (sourceData values original.1 original.2 masks) points).transcript = response.2 := by
    -- Identify the witness at function level, outside both weighted responses.
    have witness_from_data :
        (fun row : NativePrivateSpendQ58CurrentPublicOpening.Row =>
          NativePrivateSpendQ58Compff01SourceColumns.restoreWitness
            ((sourceData values original.1 original.2 masks).values row)
            ((sourceData values original.1 original.2 masks).witnessCoins row)) =
          sourceWitness values original.1 := rfl
    rw [NativePrivateSpendQ58CurrentPublicOpening.source_fields_transcript_eq]
    simp only [witness_from_data]
    dsimp only [sourceData]
    apply Prod.ext
    · funext repetition coefficient
      change (sourceNonlinearQuotient NativePrivateSpendQ58CurrentPublicOpening.packing
        (NativePrivateSpendQ58CurrentPublicOpening.batchedNonlinear relation (gamma repetition)
          (sourceWitness values original.1)) + coefficientPolynomial (masks.1 repetition)).coeff coefficient.val = _
      rw [coeff_add, NativePrivateSpendQ58Compff01SourceColumns.coefficient_array_at,
        dif_pos coefficient.isLt]
      change _ + (response.2.1 repetition coefficient - _) = _
      exact add_sub_cancel _ _
    · funext repetition coefficient
      fail_if_success
        run_tac (liftM (IO.eprintln "COIN_OBSERVATION_LINEAR_INTERFACE_START") : Lean.Elab.Tactic.TacticM Unit)
        fail
      -- Apply coefficient cancellation before any concrete row specialization.
      have cancel_response
          (batchGamma : NativePrivateSpendQ58CurrentPublicOpening.Gamma)
          (witness : NativePrivateSpendQ58CurrentPublicOpening.Witness)
          (reply : Fin 132 → Goldilocks) (index : Fin 132) :
          NativePrivateSpendQ58CurrentPublicOpening.linearResponse relation batchGamma witness
            (fun selected => reply selected -
              (sourceLinearUnmasked
                (NativePrivateSpendQ58CurrentPublicOpening.weights relation batchGamma)
                (sourcePackingLagrange NativePrivateSpendQ58CurrentPublicOpening.packing)
                witness).coeff (selected.val + 1)) index = reply index := by
        let unmasked : Fin 132 → Goldilocks := fun selected =>
          (sourceLinearUnmasked
            (NativePrivateSpendQ58CurrentPublicOpening.weights relation batchGamma)
            (sourcePackingLagrange NativePrivateSpendQ58CurrentPublicOpening.packing)
            witness).coeff (selected.val + 1)
        have coefficient_eq := NativePrivateSpendQ58CurrentPublicOpening.linear_response_coefficient
          relation batchGamma witness (fun selected => reply selected - unmasked selected) index
        exact coefficient_eq.trans (add_sub_cancel (unmasked index) (reply index))
      fail_if_success
        run_tac (liftM (IO.eprintln "COIN_LINEAR_PHASE: LOCAL_CANCEL_RETURNED") : Lean.Elab.Tactic.TacticM Unit)
        fail
      -- Data and witness projections were resolved before the response wrappers.
      dsimp only [masks, model, currentSourceModel]
      fail_if_success
        run_tac (liftM (IO.eprintln "COIN_LINEAR_PHASE: PROJECTIONS_RETURNED") : Lean.Elab.Tactic.TacticM Unit)
        fail
      exact cancel_response (gamma repetition) (sourceWitness values original.1)
        (response.2.2 repetition) coefficient
  cases response with
  | mk reply coefficients =>
    apply public_fields_ext
    · rfl
    · exact transcript
    · funext opening row
      exact (congrFun (congrFun (witness_observation_is_source values points admissible original.1) row) opening).symm
    · rw [partial_observation_is_source]
      rfl

end LinearResponseOpacity

#eval IO.eprintln "COIN_OBSERVATION_COMPILE_COMPLETE"

end
end HegemonCrypto.SmallWood.NativePrivateSpendQ58CurrentCoinObservation
