import SmzaRp05CurrentPcsOpeningHeads

/-! A fixed PCS region consumes its own partials and preserves exactly the
following region's partials. This is needed to compose the 35-word nonlinear
region with the five-word linear region of the same opening. -/
namespace HegemonCrypto.SmallWood.SmzaRp05CurrentPcsRegionSuffix

open HegemonCrypto.SmallWood (Goldilocks)
open SmzaRp05CurrentPcsOpeningView (reconstructRepeated)
open SmzaRp05CurrentPcsOpeningHeads (flattenFinRows flattenListRows)
open SmzaRp05PcsWireProjection (reconstructHeadZero)

set_option autoImplicit false

theorem reconstructRepeated_rows_suffix
    (point : Goldilocks) (width delta rows : Nat)
    (widthPositive : 0 < width) (deltaBound : delta ≤ 64)
    (scalars : Fin rows → Goldilocks)
    (partials : Fin rows → Fin (width - 1) → Goldilocks)
    (suffix : List Goldilocks) :
    reconstructRepeated point 64 width delta (List.ofFn scalars)
        (flattenFinRows partials ++ suffix) =
      some (flattenListRows (fun row =>
        reconstructHeadZero point 64 delta (scalars row)
          (List.ofFn (partials row)) :: List.ofFn (partials row)), suffix) := by
  induction rows with
  | zero => simp [flattenFinRows, flattenListRows, reconstructRepeated]
  | succ rows ih =>
      have splitPartials : flattenFinRows partials ++ suffix =
          List.ofFn (partials 0) ++
            (flattenFinRows (fun row => partials row.succ) ++ suffix) := by
        simp only [flattenFinRows, List.ofFn_succ, List.flatten_cons, List.append_assoc]
      rw [List.ofFn_succ, splitPartials]
      let partialRow := List.ofFn (partials 0)
      let remainingRows := flattenFinRows (fun row => partials row.succ) ++ suffix
      have partialRowLength : partialRow.length = width - 1 := by simp [partialRow]
      have takeRow : (partialRow ++ remainingRows).take (width - 1) = partialRow := by
        rw [List.take_append_of_le_length (by omega : width - 1 ≤ partialRow.length)]
        simp [partialRowLength]
      have dropRow : (partialRow ++ remainingRows).drop (width - 1) = remainingRows := by
        rw [List.drop_append_of_le_length (by omega : width - 1 ≤ partialRow.length)]
        simp [partialRowLength]
      have recursive := ih (fun row => scalars row.succ)
        (fun row => partials row.succ)
      have notBad : ¬ (width = 0 ∨ delta > 64) := by omega
      rw [reconstructRepeated]
      simp only [if_neg notBad]
      rw [takeRow, dropRow]
      simp only [partialRowLength]
      rw [recursive]
      simp [partialRow, flattenListRows, List.ofFn_succ]

end HegemonCrypto.SmallWood.SmzaRp05CurrentPcsRegionSuffix
