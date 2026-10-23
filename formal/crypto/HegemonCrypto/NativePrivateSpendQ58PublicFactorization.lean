import HegemonCrypto.NativePrivateSpendQ58PublicFactorizationBase

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

/-- Definitional wrapper equation, independently kernel checked and opaque. -/
theorem public_mask_wrapper_eq (relation : Relation) (gamma : Gamma)
    (response : Fin 132 → Goldilocks) (opened : Row → Goldilocks) (point : Goldilocks) :
    publicLinearMask relation gamma response opened point =
      recoverLinearMaskOpening packing (publicTarget relation gamma) response
        (weights relation gamma) (sourcePackingLagrange packing) opened point := rfl

/-- Expand only the response wrapper; keep the transcript folded under coeff. -/
theorem response_to_transcript_eq (relation : Relation) (gamma : Gamma)
    (witness : Witness) (coins : Fin 132 → Goldilocks) :
    linearResponse relation gamma witness coins =
      (fun index => (linearTranscript relation gamma witness coins).coeff
        (index.val + 1)) := rfl

/-- Expand only the transcript wrapper at polynomial type, outside coeff. -/
theorem transcript_to_polynomial_eq (relation : Relation) (gamma : Gamma)
    (witness : Witness) (coins : Fin 132 → Goldilocks) :
    linearTranscript relation gamma witness coins =
      sourceLinearUnmasked (weights relation gamma)
        (sourcePackingLagrange packing) witness + sourceLinearMask packing coins  :=
  transcriptAdd_def
    (sourceLinearUnmasked (weights relation gamma) (sourcePackingLagrange packing) witness)
    (sourceLinearMask packing coins)

/-- Definitional coefficient wrapper equation with arbitrary witness input. -/
theorem response_wrapper_eq (relation : Relation) (gamma : Gamma)
    (witness : Witness) (coins : Fin 132 → Goldilocks) :
    linearResponse relation gamma witness coins =
      (fun index => (sourceLinearUnmasked (weights relation gamma)
        (sourcePackingLagrange packing) witness + sourceLinearMask packing coins).coeff
          (index.val + 1)) :=
  (response_to_transcript_eq relation gamma witness coins).trans
    (congrArg
      (fun polynomial : Goldilocks[X] => fun index : Fin 132 =>
        polynomial.coeff (index.val + 1))
      (transcript_to_polynomial_eq relation gamma witness coins))

/-- Closed row/field specialization with weights and target still abstract.
Validity and degree are the original generic theorem premises. -/
theorem row_recovery_specialized
    (witness : Witness) (degree : ∀ row, (witness row).natDegree ≤ 69)
    (coins : Fin 132 → Goldilocks) (genericWeights : Row → Lane → Goldilocks)
    (genericTarget : Goldilocks)
    (valid : (∑ row, ∑ lane : Lane,
      genericWeights row lane * (witness row).eval (packing lane)) = genericTarget)
    (point : Goldilocks) :
    recoverLinearMaskOpening packing genericTarget
      (fun index => (sourceLinearUnmasked genericWeights (sourcePackingLagrange packing)
        witness + sourceLinearMask packing coins).coeff (index.val + 1))
      genericWeights (sourcePackingLagrange packing)
      (fun row => (witness row).eval point) point =
      (sourceLinearMask packing coins).eval point :=
  @V8Smz9PiopOpeningRecovery.source_linear_coins_recovered_from_opened_rows
    Goldilocks
      (@ZMod.instField Hegemon.Transaction.SmallWoodProductionConstraintRefinement.goldilocksModulus
        HegemonCrypto.SmallWood.goldilocksPrimeFact)
    Row (Fin.fintype 26203) packing packing_injective packing_card_nonzero
    genericWeights witness degree coins genericTarget valid point

theorem public_linear_mask_openings_match (relation : Relation)
    (source : PackedPolynomials relation) (gamma : Gamma) (coins : Fin 132 → Goldilocks)
    (point : Goldilocks) :
    publicLinearMask relation gamma (linearResponse relation gamma source.polynomial coins)
      (fun row => (source.polynomial row).eval point) point =
      (sourceLinearMask packing coins).eval point :=
  (public_mask_wrapper_eq relation gamma
    (linearResponse relation gamma source.polynomial coins)
    (fun row => (source.polynomial row).eval point) point).trans
    ((congrArg
      (fun response => recoverLinearMaskOpening packing (publicTarget relation gamma) response
        (weights relation gamma) (sourcePackingLagrange packing)
        (fun row => (source.polynomial row).eval point) point)
      (response_wrapper_eq relation gamma source.polynomial coins)).trans
      (row_recovery_specialized source.polynomial source.degree coins
        (weights relation gamma) (publicTarget relation gamma)
        (csr_checks_supply_target relation source gamma) point))

end
end HegemonCrypto.SmallWood.NativePrivateSpendQ58PublicFactorization
