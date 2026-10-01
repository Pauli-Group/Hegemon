import SmzaRp05NullifierSourceCsrBase

/-! Generic CSR head/position algebra with the selected branch shape supplied. -/

namespace HegemonCrypto.SmallWood.SmzaRp05NullifierSource

open _root_.Hegemon.Transaction.Poseidon2V8RelationProgram
open _root_.Hegemon.Transaction.Poseidon2V8SemanticSpecification
open _root_.Hegemon.Transaction.Poseidon2V8DecoderRefinement
  (hashInitialIndex)
open _root_.HegemonCrypto.SmallWood.V8Smz9SemanticDenseRange
open _root_.HegemonCrypto.SmallWood.V8Smz9SemanticDecoder
open _root_.HegemonCrypto.SmallWood.SmzaRp05NullifierBinding
open _root_.HegemonCrypto.SmallWood.SmzaRp05TypedRelation
open _root_.Hegemon.Transaction
open scoped Classical

noncomputable section
set_option autoImplicit false
set_option maxHeartbeats 4000000

private theorem add_neg_eq_zero_extract {a p : Goldilocks}
    (h : a + -p = 0) : a = p := by
  calc
    a = a + 0 := (add_zero a).symm
    _ = a + (-p + p) := by rw [neg_add_cancel]
    _ = (a + -p) + p := by rw [add_assoc]
    _ = 0 + p := by rw [h]
    _ = p := zero_add p

/-- A shaped CSR head plus its position tail forces the copied value to be
the position projection. The cell stays symbolic; `shape` is discharged by
the separate branch-selection proof. -/
theorem shaped_csr_head_eq_position
    (values packed : List Nat) (cell : InitialCell)
    (oneNode negativeNode positiveNode : Nat)
    (powerNode : Nat → Nat) (constantNode : InitialCell → Nat)
    (shape : initialTerms oneNode negativeNode positiveNode powerNode cell =
      [(hashInitialIndex (callOf cell) cell.2.2.val, oneNode)] ++
        positionTerms cell.1 powerNode)
    (equation : csrFieldSum values packed
      (initialTerms oneNode negativeNode positiveNode powerNode cell) =
        (values.getD (constantNode cell) 0 : Goldilocks))
    (one : (values.getD oneNode 0 : Goldilocks) = 1)
    (constantZero :
      (values.getD (constantNode cell) 0 : Goldilocks) = 0)
    (position : csrFieldSum values packed (positionTerms cell.1 powerNode) =
      -(projectPosition packed cell.1.val : Goldilocks)) :
    (packed.getD (hashInitialIndex (callOf cell) cell.2.2.val) 0 : Goldilocks) =
      (projectPosition packed cell.1.val : Goldilocks) := by
  rw [shape, csr_sum_append] at equation
  have headSum :
      csrFieldSum values packed
          [(hashInitialIndex (callOf cell) cell.2.2.val, oneNode)] =
        (values.getD oneNode 0 : Goldilocks) *
          (packed.getD (hashInitialIndex (callOf cell) cell.2.2.val) 0 : Goldilocks) := by
    simp only [csrFieldSum, List.map_cons, List.map_nil,
      List.sum_cons, List.sum_nil, add_zero]
  rw [headSum, one, position, constantZero] at equation
  exact add_neg_eq_zero_extract (by simpa only [one_mul] using equation)

end
end HegemonCrypto.SmallWood.SmzaRp05NullifierSource
