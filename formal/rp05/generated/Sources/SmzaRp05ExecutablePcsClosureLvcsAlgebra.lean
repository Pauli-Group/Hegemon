import SmzaRp05LvcsWireProjection

/-! # Fixed-profile LVCS split/merge algebra

The pivot columns are the first six positions of each 70-row block. This
module keeps the returned merged row tied to the very residual vector whose
equation the native reconstruction checks.
-/
namespace HegemonCrypto.SmallWood.SmzaRp05ExecutablePcsClosureLvcsAlgebra

open SmzaRp05LvcsWireProjection
open scoped BigOperators

noncomputable section
set_option autoImplicit false
set_option Elab.async false
set_option maxRecDepth 12000

def pivotColumns : List Nat := configuredFullrankCols 2 64 6

theorem pivot_columns_exact :
    pivotColumns = [0, 1, 2, 3, 4, 5, 70, 71, 72, 73, 74, 75] := by decide

/-- Literal final map in `reconstructOne`, with no new decoder or row data. -/
def mergeCoordinates (totalRows : Nat) (columns : List Nat)
    (res subset : List F) : List F :=
  (List.range totalRows).map fun k =>
    let openedBefore := (columns.filter fun selected => decide (selected < k)).length
    if columns[openedBefore]? = some k then res.getD openedBefore 0
    else subset.getD (k - openedBefore) 0

theorem merge_coordinates_length (totalRows : Nat) (columns : List Nat)
    (res subset : List F) :
    (mergeCoordinates totalRows columns res subset).length = totalRows := by
  simp [mergeCoordinates]

theorem list_as_coordinates (row : List F) (shape : row.length = 140) :
    row = List.ofFn (fun index : Fin 140 => row.getD index.val 0) := by
  apply List.ext_getElem (by simp [shape])
  intro index leftBound rightBound
  simp only [List.getElem_ofFn]
  exact (List.getD_eq_getElem row 0 leftBound).symm

set_option maxHeartbeats 1500000 in
/-- Exact fixed-profile dot identity. No length assumption is needed on the
two source vectors: the source's same `getD ... 0` defaults occur on both
sides. The 140 coefficient coordinates are partitioned once each. -/
theorem fixed_split_merge_dot_coordinates
    (coefficients : Fin 140 → F) (res subset : List F) :
    dot (List.ofFn coefficients) (mergeCoordinates 140 pivotColumns res subset) =
      dot (splitCoefficientRow pivotColumns (List.ofFn coefficients)).1 res +
      dot (splitCoefficientRow pivotColumns (List.ofFn coefficients)).2 subset := by
  simp (config := { maxSteps := 1000000 }) [dot, mergeCoordinates,
    pivot_columns_exact, splitCoefficientRow, List.range_succ,
    Finset.sum_range_succ, List.getD_eq_getElem?_getD]
  ring

theorem fixed_split_merge_dot (coefficients res subset : List F)
    (shape : coefficients.length = 140) :
    dot coefficients (mergeCoordinates 140 pivotColumns res subset) =
      dot (splitCoefficientRow pivotColumns coefficients).1 res +
      dot (splitCoefficientRow pivotColumns coefficients).2 subset := by
  rw [list_as_coordinates coefficients shape]
  exact fixed_split_merge_dot_coordinates _ res subset

/-- Unlike an existential residual equation alone, this result also retains
the equality to the row actually returned by `reconstructOne`. -/
theorem reconstruct_one_merge_and_equation
    (fullrank totalRows lvcsCols tailCount : Nat)
    (columns : List Nat) (part1 part2 inverse heads tails : FMatrix)
    (subset : List F) (point : F) (values : List F)
    (success : reconstructOne fullrank totalRows lvcsCols tailCount columns
      part1 part2 inverse heads tails subset point = some values) :
    ∃ res rhs,
      res = matVec inverse rhs ∧
      values = mergeCoordinates totalRows columns res subset ∧
      ∀ k, k < fullrank →
        (matVec part1 res).getD k 0 + (matVec part2 subset).getD k 0 =
          evaluateConsecutive (rotateLeft ((heads.getD k []) ++ (tails.getD k []))
            lvcsCols) point := by
  let q := (List.range fullrank).map fun k =>
    evaluateConsecutive (rotateLeft ((heads.getD k []) ++ (tails.getD k [])) lvcsCols) point
  let rhs := (List.range fullrank).map fun k => q.getD k 0 - (matVec part2 subset).getD k 0
  let res := matVec inverse rhs
  have reduced := success
  simp [reconstructOne] at reduced
  have passed : residualCheckPassed part1 res rhs = true := by
    simpa [q, rhs, res] using reduced.2.2.2.1
  have returned : values = mergeCoordinates totalRows columns res subset := by
    simpa [mergeCoordinates, q, rhs, res] using reduced.2.2.2.2.symm
  refine ⟨res, rhs, rfl, returned, ?_⟩
  intro k bound
  have equation := congrArg (fun row : List F => row.getD k 0)
    (residualCheckPassed_implies_equation part1 res rhs passed)
  have rhsEntry : rhs.getD k 0 =
      evaluateConsecutive (rotateLeft ((heads.getD k []) ++ (tails.getD k [])) lvcsCols)
        point - (matVec part2 subset).getD k 0 := by
    simp [rhs, q, bound]
  rw [equation, rhsEntry]
  ring

private theorem getD_map_at {α β : Type} (values : List α) (f : α → β)
    (index : Nat) (fallback : α) (default : β)
    (bound : index < values.length) :
    (values.map f).getD index default = f (values.getD index fallback) := by
  rw [List.getD_eq_getElem (values.map f) default (by simpa using bound)]
  rw [List.getElem_map]
  rw [List.getD_eq_getElem values fallback bound]

theorem matrix_split_entry (coefficients : FMatrix) (columns : List Nat)
    (k : Nat) (bound : k < coefficients.length) (res subset : List F) :
    (matVec (splitCoefficientMatrix columns coefficients).1 res).getD k 0 +
      (matVec (splitCoefficientMatrix columns coefficients).2 subset).getD k 0 =
      dot (splitCoefficientRow columns (coefficients.getD k [])).1 res +
        dot (splitCoefficientRow columns (coefficients.getD k [])).2 subset := by
  simp only [matVec, splitCoefficientMatrix]
  rw [getD_map_at _ (fun row => dot row res) k [] 0 (by simpa using bound)]
  rw [getD_map_at coefficients (fun row => (splitCoefficientRow columns row).1)
    k [] [] bound]
  rw [getD_map_at _ (fun row => dot row subset) k [] 0 (by simpa using bound)]
  rw [getD_map_at coefficients (fun row => (splitCoefficientRow columns row).2)
    k [] [] bound]

/-- One actual successful native row has the full, unsplit LVCS dot
equation. Neither the row nor the twelve checks are independent inputs. -/
theorem reconstruct_one_full_dot
    (lvcsCols tailCount : Nat) (coefficients inverse heads tails : FMatrix)
    (subset : List F) (point : F) (values : List F)
    (rowCount : coefficients.length = 12)
    (columnCount : ∀ row ∈ coefficients, row.length = 140)
    (success : reconstructOne 12 140 lvcsCols tailCount pivotColumns
      (splitCoefficientMatrix pivotColumns coefficients).1
      (splitCoefficientMatrix pivotColumns coefficients).2
      inverse heads tails subset point = some values) :
    ∀ k, k < 12 →
      dot (coefficients.getD k []) values =
        evaluateConsecutive (rotateLeft ((heads.getD k []) ++ (tails.getD k []))
          lvcsCols) point := by
  obtain ⟨res, rhs, _, returned, equations⟩ :=
    reconstruct_one_merge_and_equation 12 140 lvcsCols tailCount pivotColumns
      (splitCoefficientMatrix pivotColumns coefficients).1
      (splitCoefficientMatrix pivotColumns coefficients).2
      inverse heads tails subset point values success
  intro k bound
  have inRange : k < coefficients.length := by omega
  have selected : coefficients.getD k [] ∈ coefficients := by
    rw [List.getD_eq_getElem coefficients [] inRange]
    exact List.getElem_mem (l := coefficients) (n := k) inRange
  rw [returned, fixed_split_merge_dot _ _ _ (columnCount _ selected)]
  rw [← matrix_split_entry coefficients pivotColumns k inRange res subset]
  exact equations k bound

theorem pcs_coefficients_shape (points : List F) (pointCount : points.length = 6) :
    (pcsBuildCoefficients points 2 64 140).length = 12 ∧
      ∀ row ∈ pcsBuildCoefficients points 2 64 140, row.length = 140 := by
  constructor
  · simp [pcsBuildCoefficients, pointCount]
  · intro row member
    obtain ⟨index, _, rfl⟩ := List.mem_map.mp member
    simp

/-- Native-profile specialization: two 70-row blocks, six pivots per
block, and 368 LVCS columns. -/
theorem native_row_full_dot (points : List F) (pointCount : points.length = 6)
    (inverse heads tails : FMatrix) (subset : List F) (point : F) (values : List F)
    (success : reconstructOne 12 140 368 38 pivotColumns
      (splitCoefficientMatrix pivotColumns (pcsBuildCoefficients points 2 64 140)).1
      (splitCoefficientMatrix pivotColumns (pcsBuildCoefficients points 2 64 140)).2
      inverse heads tails subset point = some values) :
    ∀ k, k < 12 →
      dot ((pcsBuildCoefficients points 2 64 140).getD k []) values =
        evaluateConsecutive (rotateLeft ((heads.getD k []) ++ (tails.getD k [])) 368) point :=
  reconstruct_one_full_dot 368 38 _ inverse heads tails subset point values
    (pcs_coefficients_shape points pointCount).1 (pcs_coefficients_shape points pointCount).2 success

end
end HegemonCrypto.SmallWood.SmzaRp05ExecutablePcsClosureLvcsAlgebra
