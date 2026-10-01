import SmzaRp05ExecutablePcsClosureLvcsAlgebraRows

namespace HegemonCrypto.SmallWood.SmzaRp05ExecutablePcsClosureLvcsAlgebra

open SmzaRp05LvcsWireProjection SmzaRp05PcsWireProjection
open SmzaRp05ExecutableChallengeStage (FieldWord)
open scoped BigOperators

noncomputable section
set_option autoImplicit false
set_option Elab.async false
set_option maxRecDepth 12000

theorem native_coefficient_entry (points : List F) (pointCount : points.length = 6)
    (opening : Fin 6) (block : Fin 2) (column : Fin 140) :
    ((pcsBuildCoefficients points 2 64 140).getD (2 * opening.val + block.val) []).getD
        column.val 0 =
      if 70 * block.val ≤ column.val ∧ column.val < 70 * (block.val + 1) then
        (points.getD opening.val 0) ^ (column.val - 70 * block.val) else 0 := by
  have rowBound : 2 * opening.val + block.val < 12 := by
    have := opening.isLt; have := block.isLt; omega
  have quotient : (2 * opening.val + block.val) / 2 = opening.val := by
    have := block.isLt; omega
  have remainder : (2 * opening.val + block.val) % 2 = block.val := by
    have := block.isLt; omega
  simp [pcsBuildCoefficients, pointCount, List.getD_eq_getElem?_getD,
    rowBound, column.isLt, quotient, remainder, Bool.and_eq_true]

theorem native_dot_block (points : List F) (pointCount : points.length = 6)
    (opening : Fin 6) (block : Fin 2) (values : List F) :
    dot ((pcsBuildCoefficients points 2 64 140).getD (2 * opening.val + block.val) []) values =
      ∑ coefficient : Fin 70, (points.getD opening.val 0) ^ coefficient.val *
        values.getD (70 * block.val + coefficient.val) 0 := by
  have rowBound : 2 * opening.val + block.val < 12 := by
    have := opening.isLt; have := block.isLt; omega
  have rowLength :
      ((pcsBuildCoefficients points 2 64 140).getD (2 * opening.val + block.val) []).length = 140 := by
    simp [pcsBuildCoefficients, pointCount, List.getD_eq_getElem?_getD, rowBound]
  have expanded :
      dot ((pcsBuildCoefficients points 2 64 140).getD (2 * opening.val + block.val) []) values =
      ∑ column ∈ Finset.range 140,
        if 70 * block.val ≤ column ∧ column < 70 * (block.val + 1) then
          (points.getD opening.val 0) ^ (column - 70 * block.val) * values.getD column 0 else 0 := by
    unfold dot
    rw [rowLength]
    apply Finset.sum_congr rfl
    intro column member
    have within : column < 140 := Finset.mem_range.mp member
    rw [native_coefficient_entry points pointCount opening block ⟨column, within⟩]
    split <;> simp_all
  rw [expanded]
  have splitRange : 140 = 70 + 70 := by decide
  rw [splitRange, Finset.sum_range_add]
  fin_cases block
  · simp only [mul_zero, mul_one, zero_le, zero_add, Nat.sub_zero,
      true_and]
    have first :
        (∑ x ∈ Finset.range 70,
          if x < 70 then (points.getD opening.val 0) ^ x * values.getD x 0 else 0) =
        ∑ x ∈ Finset.range 70, (points.getD opening.val 0) ^ x * values.getD x 0 := by
      apply Finset.sum_congr rfl
      intro x member
      simp [Finset.mem_range.mp member]
    rw [first, ← Fin.sum_univ_eq_sum_range]
    simp
  · simp only [mul_one]
    have firstZero :
        (∑ x ∈ Finset.range 70,
          if 70 ≤ x ∧ x < 70 * (1 + 1) then
            (points.getD opening.val 0) ^ (x - 70) * values.getD x 0 else 0) = 0 := by
      apply Finset.sum_eq_zero
      intro x member
      have := Finset.mem_range.mp member
      simp [show ¬70 ≤ x by omega]
    rw [firstZero, zero_add, ← Fin.sum_univ_eq_sum_range]
    apply Finset.sum_congr rfl
    intro x member
    have := x.isLt
    simp [show 70 ≤ 70 + x.val by omega,
      show 70 + x.val < 70 * (1 + 1) by omega]

/-- The native row equation in the exact two-block, seventy-coefficient
shape consumed by `TwelveLvcsChecks`. Leaf decoding and polynomial identity
are intentionally left to the same-execution readback join. -/
theorem reconstructed_rows_twelve_block_equations
    (fields : DecodedPcsFields) (points decsPoints : List F)
    (pointCount : points.length = 6) (rowScalars : List (List FieldWord))
    (widths deltas : List Nat) (rows : FMatrix)
    (success : reconstructRowsFromPcsFields fields points decsPoints rowScalars
      64 widths deltas 2 368 140 38 = some rows) :
    ∃ heads,
      reconstructAllHeads fields points rowScalars 64 widths deltas 2 368 = some heads ∧
      rows.length = decsPoints.length ∧
      ∀ j, j < decsPoints.length → ∀ opening : Fin 6, ∀ block : Fin 2,
        evaluateConsecutive
          (rotateLeft ((heads.getD (2 * opening.val + block.val) []) ++
            ((fields.rcombiTails.map fieldWordsToGoldilocks).getD
              (2 * opening.val + block.val) [])) 368) (decsPoints.getD j 0) =
        ∑ coefficient : Fin 70, (points.getD opening.val 0) ^ coefficient.val *
          (rows.getD j []).getD (70 * block.val + coefficient.val) 0 := by
  obtain ⟨heads, inverse, headsBuilt, _, rowCount, equations⟩ :=
    reconstruct_rows_native_full_dot fields points decsPoints pointCount
      rowScalars widths deltas rows success
  refine ⟨heads, headsBuilt, rowCount, ?_⟩
  intro j within opening block
  have rowBound : 2 * opening.val + block.val < 12 := by
    have := opening.isLt; have := block.isLt; omega
  rw [← equations j within _ rowBound]
  exact native_dot_block points pointCount opening block (rows.getD j [])

end
end HegemonCrypto.SmallWood.SmzaRp05ExecutablePcsClosureLvcsAlgebra
