import HegemonCrypto.NativePrivateSpendQ58PublicFactorization

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

/-- The literal response map for all five repetitions has exactly the affine
shape required by the preceding chronological inverse, with new dimensions. -/
def nativeUnmasked (relation : Relation) (parameters : Fin 5 → Gamma) (witness : Witness) :
    NativePrivateSpendQ58Wpcs.Q :=
  (fun k index => (sourceNonlinearQuotient packing
      (batchedNonlinear relation (parameters k) witness)).coeff index.val,
    fun k index => (sourceLinearUnmasked (weights relation (parameters k))
      (sourcePackingLagrange packing) witness).coeff (index.val + 1))

def nativeResponse (relation : Relation) (parameters : Fin 5 → Gamma) (witness : Witness)
    (masks : NativePrivateSpendQ58Wpcs.Q) : NativePrivateSpendQ58Wpcs.Q :=
  (fun k => nonlinearResponse relation (parameters k) witness (masks.1 k),
    fun k => linearResponse relation (parameters k) witness (masks.2 k))

theorem native_response_affine (relation : Relation) (parameters : Fin 5 → Gamma)
    (witness : Witness) (masks : NativePrivateSpendQ58Wpcs.Q) :
    nativeResponse relation parameters witness masks = nativeUnmasked relation parameters witness + masks := by
  apply Prod.ext
  · funext k index
    change
      (sourceNonlinearQuotient packing (batchedNonlinear relation (parameters k) witness) +
        coefficientPolynomial (masks.1 k)).coeff index.val =
      (sourceNonlinearQuotient packing (batchedNonlinear relation (parameters k) witness)).coeff
        index.val + (masks.1 k) index
    rw [coeff_add, coefficient_polynomial_coefficient]
  · funext k index
    change linearResponse relation (parameters k) witness (masks.2 k) index =
      (sourceLinearUnmasked (weights relation (parameters k))
        (sourcePackingLagrange packing) witness).coeff (index.val + 1) + (masks.2 k) index
    rw [response_wrapper_eq]
    change (sourceLinearUnmasked (weights relation (parameters k))
        (sourcePackingLagrange packing) witness + sourceLinearMask packing (masks.2 k)).coeff
        (index.val + 1) =
      (sourceLinearUnmasked (weights relation (parameters k))
        (sourcePackingLagrange packing) witness).coeff (index.val + 1) + (masks.2 k) index
    rw [coeff_add, source_linear_mask_nonconstant_coefficient]

theorem native_recovered_masks_match (relation : Relation) (parameters : Fin 5 → Gamma)
    (witness : Witness) (masks : NativePrivateSpendQ58Wpcs.Q) :
    nativeResponse relation parameters witness masks - nativeUnmasked relation parameters witness = masks := by
  rw [native_response_affine]
  exact add_sub_cancel_left _ _


end
end HegemonCrypto.SmallWood.NativePrivateSpendQ58PublicFactorization
