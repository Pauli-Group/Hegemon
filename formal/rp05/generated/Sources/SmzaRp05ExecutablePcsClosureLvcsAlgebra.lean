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

private theorem list_as_coordinates_generic {α : Type} {count : Nat}
    (fallback : α) (row : List α) (shape : row.length = count) :
    row = List.ofFn (fun index : Fin count => row.getD index.val fallback) := by
  apply List.ext_getElem (by simp [shape])
  intro index leftBound rightBound
  simp only [List.getElem_ofFn]
  exact (List.getD_eq_getElem row fallback leftBound).symm

theorem list_as_coordinates (row : List F) (shape : row.length = 140) :
    row = List.ofFn (fun index : Fin 140 => row.getD index.val 0) := by
  exact list_as_coordinates_generic 0 row shape

private theorem profile_pivot_indices :
    pivotColumns = List.range 6 ++ (List.range 6).map (70 + ·) := by decide

set_option maxHeartbeats 1500000 in
private theorem profile_free_indices :
    ((List.range 140).filterMap fun k =>
      let previous := (pivotColumns.filter fun selected => decide (selected < k)).length
      if pivotColumns[previous]? = some k then none else some k) =
      (List.range 64).map (6 + ·) ++ (List.range 64).map (76 + ·) := by decide

private theorem profile_first_pivot (i : Nat) (bound : i < 6) :
    (pivotColumns.filter fun selected => decide (selected < i)).length = i ∧
      pivotColumns[i]? = some i := by
  interval_cases i <;> decide

private theorem profile_second_pivot (i : Nat) (bound : i < 6) :
    (pivotColumns.filter fun selected => decide (selected < 70 + i)).length = 6 + i ∧
      pivotColumns[6 + i]? = some (70 + i) := by
  interval_cases i <;> decide

private theorem profile_first_free (i : Nat) (bound : i < 64) :
    (pivotColumns.filter fun selected => decide (selected < 6 + i)).length = 6 ∧
      pivotColumns[6]? ≠ some (6 + i) := by
  have h0 : 0 < 6 + i := by omega
  have h1 : 1 < 6 + i := by omega
  have h2 : 2 < 6 + i := by omega
  have h3 : 3 < 6 + i := by omega
  have h4 : 4 < 6 + i := by omega
  have h5 : 5 < 6 + i := by omega
  have h70 : ¬ 70 < 6 + i := by omega
  have h71 : ¬ 71 < 6 + i := by omega
  have h72 : ¬ 72 < 6 + i := by omega
  have h73 : ¬ 73 < 6 + i := by omega
  have h74 : ¬ 74 < 6 + i := by omega
  have h75 : ¬ 75 < 6 + i := by omega
  constructor
  · simp [pivot_columns_exact, h0, h1, h2, h3, h4, h5, h70, h71, h72, h73, h74, h75]
  · simp only [pivot_columns_exact]
    simp
    omega

private theorem profile_second_free (i : Nat) (bound : i < 64) :
    (pivotColumns.filter fun selected => decide (selected < 76 + i)).length = 12 ∧
      pivotColumns[12]? ≠ some (76 + i) := by
  have h0 : 0 < 76 + i := by omega
  have h1 : 1 < 76 + i := by omega
  have h2 : 2 < 76 + i := by omega
  have h3 : 3 < 76 + i := by omega
  have h4 : 4 < 76 + i := by omega
  have h5 : 5 < 76 + i := by omega
  have h70 : 70 < 76 + i := by omega
  have h71 : 71 < 76 + i := by omega
  have h72 : 72 < 76 + i := by omega
  have h73 : 73 < 76 + i := by omega
  have h74 : 74 < 76 + i := by omega
  have h75 : 75 < 76 + i := by omega
  constructor
  · simp [pivot_columns_exact, h0, h1, h2, h3, h4, h5, h70, h71, h72, h73, h74, h75]
  · simp only [pivot_columns_exact]
    simp

private theorem mapped_range_getD {K : Type} (f : Nat → K) (count i : Nat)
    (fallback : K) (bound : i < count) :
    ((List.range count).map f).getD i fallback = f i := by
  simp [List.getD_eq_getElem?_getD, bound]

private theorem split_rows_profile {K : Type} [Zero K] (row : List K)
    (shape : row.length = 140) :
    (pivotColumns.map (fun k => row.getD k 0),
      (List.range row.length).filterMap fun k =>
        let previous := (pivotColumns.filter fun selected => decide (selected < k)).length
        if pivotColumns[previous]? = some k then none else row[k]?) =
      ((List.range 6).map (fun k => row.getD k 0) ++
          (List.range 6).map (fun k => row.getD (70 + k) 0),
        (List.range 64).map (fun k => row.getD (6 + k) 0) ++
          (List.range 64).map (fun k => row.getD (76 + k) 0)) := by
  apply Prod.ext
  · simp only [profile_pivot_indices, List.map_append, List.map_map, Function.comp_def]
  · dsimp only
    rw [shape]
    have transported :
        ((List.range 140).filterMap fun k =>
          let previous := (pivotColumns.filter fun selected => decide (selected < k)).length
          if pivotColumns[previous]? = some k then none else row[k]?) =
        (((List.range 140).filterMap fun k =>
          let previous := (pivotColumns.filter fun selected => decide (selected < k)).length
          if pivotColumns[previous]? = some k then none else some k).map
            (fun k => row.getD k 0)) := by
      rw [List.map_filterMap]
      apply List.filterMap_congr
      intro k member
      have bound : k < row.length := by simpa [shape] using List.mem_range.mp member
      by_cases selected :
          pivotColumns[(pivotColumns.filter fun selected => decide (selected < k)).length]? = some k
      · simp [selected]
      · simp [selected, bound]
    rw [transported, profile_free_indices]
    simp only [List.map_append, List.map_map, Function.comp_def]

private theorem dot_two_range_maps {K : Type} [CommSemiring K]
    (left right : Nat → K) (n m : Nat) (values : List K) :
    (∑ i ∈ Finset.range (((List.range n).map left ++ (List.range m).map right).length),
      ((List.range n).map left ++ (List.range m).map right).getD i 0 * values.getD i 0) =
      (∑ i ∈ Finset.range n, left i * values.getD i 0) +
        ∑ i ∈ Finset.range m, right i * values.getD (n + i) 0 := by
  simp only [List.length_append, List.length_map, List.length_range]
  rw [Finset.sum_range_add]
  apply congrArg₂ (· + ·)
  · apply Finset.sum_congr rfl
    intro i member
    have bound := Finset.mem_range.mp member
    rw [List.getD_append _ _ 0 i (by simpa using bound),
      mapped_range_getD left n i 0 bound]
  · apply Finset.sum_congr rfl
    intro i member
    have bound := Finset.mem_range.mp member
    rw [List.getD_append_right _ _ 0 (n + i) (by simp)]
    simp only [List.length_map, List.length_range, Nat.add_sub_cancel_left]
    rw [mapped_range_getD right m i 0 bound]

private theorem sum_four_profile_ranges {K : Type} [AddCommMonoid K] (f : Nat → K) :
    (∑ i ∈ Finset.range 140, f i) =
      ((∑ i ∈ Finset.range 6, f i) + (∑ i ∈ Finset.range 64, f (6 + i)) +
        (∑ i ∈ Finset.range 6, f (70 + i))) +
        ∑ i ∈ Finset.range 64, f (76 + i) := by
  have first := Finset.sum_range_add f 76 64
  have second := Finset.sum_range_add f 70 6
  have third := Finset.sum_range_add f 6 64
  exact first.trans (congrArg (fun value => value + ∑ i ∈ Finset.range 64, f (76 + i))
    (second.trans (congrArg (fun value => value + ∑ i ∈ Finset.range 6, f (70 + i)) third)))

private theorem merged_dot_profile {K : Type} [CommSemiring K]
    (row res subset : List K) (shape : row.length = 140) :
    (∑ i ∈ Finset.range row.length, row.getD i 0 *
      ((List.range 140).map fun k =>
        let openedBefore := (pivotColumns.filter fun selected => decide (selected < k)).length
        if pivotColumns[openedBefore]? = some k then res.getD openedBefore 0
        else subset.getD (k - openedBefore) 0).getD i 0) =
      ((∑ i ∈ Finset.range 6, row.getD i 0 * res.getD i 0) +
        (∑ i ∈ Finset.range 64, row.getD (6 + i) 0 * subset.getD i 0) +
        (∑ i ∈ Finset.range 6, row.getD (70 + i) 0 * res.getD (6 + i) 0)) +
        ∑ i ∈ Finset.range 64, row.getD (76 + i) 0 * subset.getD (64 + i) 0 := by
  rw [shape]
  have pointwise :
      (∑ i ∈ Finset.range 140, row.getD i 0 *
        ((List.range 140).map fun k =>
          let openedBefore := (pivotColumns.filter fun selected => decide (selected < k)).length
          if pivotColumns[openedBefore]? = some k then res.getD openedBefore 0
          else subset.getD (k - openedBefore) 0).getD i 0) =
      ∑ i ∈ Finset.range 140, row.getD i 0 *
        (let openedBefore := (pivotColumns.filter fun selected => decide (selected < i)).length
        if pivotColumns[openedBefore]? = some i then res.getD openedBefore 0
        else subset.getD (i - openedBefore) 0) := by
    apply Finset.sum_congr rfl
    intro i member
    rw [mapped_range_getD _ 140 i 0 (Finset.mem_range.mp member)]
  rw [pointwise, sum_four_profile_ranges]
  apply congrArg₂ (· + ·)
  · apply congrArg₂ (· + ·)
    · apply congrArg₂ (· + ·)
      · apply Finset.sum_congr rfl
        intro i member
        have lookup := profile_first_pivot i (Finset.mem_range.mp member)
        simp only [lookup.1, lookup.2, if_true]
      · apply Finset.sum_congr rfl
        intro i member
        have lookup := profile_first_free i (Finset.mem_range.mp member)
        simp only [lookup.1, if_neg lookup.2, Nat.add_sub_cancel_left]
    · apply Finset.sum_congr rfl
      intro i member
      have lookup := profile_second_pivot i (Finset.mem_range.mp member)
      simp only [lookup.1, lookup.2, if_true]
  · apply Finset.sum_congr rfl
    intro i member
    have lookup := profile_second_free i (Finset.mem_range.mp member)
    have shifted : 76 + i - 12 = 64 + i := by omega
    simp only [lookup.1, if_neg lookup.2, shifted]

set_option maxHeartbeats 1500000 in
private theorem fixed_split_merge_dot_coordinates_generic
    {K : Type} [CommSemiring K]
    (coefficients : Fin 140 → K) (res subset : List K) :
    let columns := pivotColumns
    let genericDot := fun (left right : List K) =>
      ∑ i ∈ Finset.range left.length, left.getD i 0 * right.getD i 0
    let merged := (List.range 140).map fun k =>
      let openedBefore := (columns.filter fun selected => decide (selected < k)).length
      if columns[openedBefore]? = some k then res.getD openedBefore 0
      else subset.getD (k - openedBefore) 0
    let row := List.ofFn coefficients
    let split := (columns.map fun k => row.getD k 0,
      (List.range row.length).filterMap fun k =>
        let previous := (columns.filter fun selected => decide (selected < k)).length
        if columns[previous]? = some k then none else row[k]?)
    genericDot row merged = genericDot split.1 res + genericDot split.2 subset := by
  dsimp only
  have splitShape := split_rows_profile (List.ofFn coefficients) (by simp)
  have leftShape := congrArg Prod.fst splitShape
  have rightShape := congrArg Prod.snd splitShape
  dsimp only at leftShape rightShape
  rw [leftShape, rightShape]
  rw [merged_dot_profile _ res subset (by simp), dot_two_range_maps, dot_two_range_maps]
  ac_rfl

set_option maxHeartbeats 1500000 in
/-- Exact fixed-profile dot identity. No length assumption is needed on the
two source vectors: the source's same `getD ... 0` defaults occur on both
sides. The 140 coefficient coordinates are partitioned once each. -/
theorem fixed_split_merge_dot_coordinates
    (coefficients : Fin 140 → F) (res subset : List F) :
    dot (List.ofFn coefficients) (mergeCoordinates 140 pivotColumns res subset) =
      dot (splitCoefficientRow pivotColumns (List.ofFn coefficients)).1 res +
      dot (splitCoefficientRow pivotColumns (List.ofFn coefficients)).2 subset := by
  unfold dot mergeCoordinates splitCoefficientRow
  exact fixed_split_merge_dot_coordinates_generic coefficients res subset

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
