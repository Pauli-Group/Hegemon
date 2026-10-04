import SmzaRp05CurrentPcsOpeningView
import SmzaRp05CurrentPcsMaskAlgebra

/-!
# Row-major source layout of repeated PCS reconstruction regions

The executable PCS row traversal consumes one `width - 1` partial slice per
opened scalar and emits the head followed by that same slice.  This module
records the exact finite-row flattening equation, which is the list-layout
step needed to identify the nonlinear/linear regions with source opening
columns.
-/

namespace HegemonCrypto.SmallWood.SmzaRp05CurrentPcsOpeningHeads

open HegemonCrypto.SmallWood (Goldilocks)
open SmzaRp05CurrentPcsOpeningView (reconstructRepeated)
open SmzaRp05PcsWireProjection (reconstructHeadZero)

set_option autoImplicit false

/-- Flatten a row-major rectangular family of source partial values. -/
def flattenFinRows {rows columns : Nat}
    (values : Fin rows → Fin columns → Goldilocks) : List Goldilocks :=
  (List.ofFn fun row => List.ofFn (values row)).flatten

def flattenListRows {rows : Nat}
    (values : Fin rows → List Goldilocks) : List Goldilocks :=
  (List.ofFn values).flatten

private theorem flattenFinRows_succ {rows columns : Nat}
    (values : Fin (rows + 1) → Fin columns → Goldilocks) :
    flattenFinRows values = List.ofFn (values 0) ++
      flattenFinRows (fun row => values row.succ) := by
  simp [flattenFinRows, List.ofFn_succ]

private theorem flattenListRows_succ {rows : Nat}
    (values : Fin (rows + 1) → List Goldilocks) :
    flattenListRows values = values 0 ++
      flattenListRows (fun row => values row.succ) := by
  simp [flattenListRows, List.ofFn_succ]

/-- For any fixed-width region, `reconstructRepeated` emits the row-major
source vectors consisting of each reconstructed head followed by its exact
`width - 1` partials.  No generic event or success hypothesis is introduced:
the option result follows from the concrete finite rectangle. -/
theorem reconstructRepeated_rows
    (point : Goldilocks) (width delta rows : Nat)
    (widthPositive : 0 < width) (deltaBound : delta ≤ 64)
    (scalars : Fin rows → Goldilocks)
    (partials : Fin rows → Fin (width - 1) → Goldilocks) :
    reconstructRepeated point 64 width delta (List.ofFn scalars)
        (flattenFinRows partials) =
      some (flattenListRows (fun row =>
        (reconstructHeadZero point 64 delta (scalars row)
          (List.ofFn (partials row))) :: List.ofFn (partials row)), []) := by
  induction rows with
  | zero =>
      simp [flattenFinRows, flattenListRows, reconstructRepeated]
  | succ rows ih =>
      rw [List.ofFn_succ, flattenFinRows_succ]
      let partialRow := List.ofFn (partials 0)
      let remainingRows := flattenFinRows (fun row => partials row.succ)
      have partialRowLength : partialRow.length = width - 1 := by
        simp [partialRow]
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
      rw [flattenListRows_succ]
      simp [partialRow, flattenListRows]

/-- The five source nonlinear groups in `partial_evals` reconstruct the
source's eight-column nonlinear vectors, in exact serialized row-major order. -/
theorem reconstructRepeated_nonlinear_source_columns
    (point : Goldilocks) (masks : Fin 5 → Goldilocks)
    (partials : Fin 5 → Fin 7 → Goldilocks) :
    reconstructRepeated point 64 8 29 (List.ofFn masks) (flattenFinRows partials) =
      some (flattenFinRows (fun polynomial =>
        HegemonCrypto.SmallWood.V8Smz9EagerSimulator.reconstructNonlinearColumns
          point (masks polynomial) (partials polynomial)), []) := by
  rw [reconstructRepeated_rows point 8 29 5 (by decide) (by decide) masks partials]
  apply congrArg (fun output : List Goldilocks => some (output, []))
  unfold flattenListRows flattenFinRows
  apply congrArg List.flatten
  apply congrArg List.ofFn
  funext polynomial
  exact HegemonCrypto.SmallWood.SmzaRp05CurrentPcsMaskAlgebra.nonlinear_column_list_is_source_reconstruction
      point (masks polynomial)
      (partials polynomial)

/-- The five source linear groups likewise reconstruct the exact two-column
vectors, using the serialized single partial value per opening/polynomial. -/
theorem reconstructRepeated_linear_source_columns
    (point : Goldilocks) (masks : Fin 5 → Goldilocks)
    (partials : Fin 5 → Goldilocks) :
    reconstructRepeated point 64 2 1 (List.ofFn masks)
        (flattenFinRows (fun polynomial (_ : Fin 1) => partials polynomial)) =
      some (flattenFinRows (fun polynomial =>
        HegemonCrypto.SmallWood.V8Smz9EagerSimulator.reconstructLinearColumns
          point (masks polynomial) (partials polynomial)), []) := by
  rw [reconstructRepeated_rows point 2 1 5 (by decide) (by decide)
    masks (fun polynomial (_ : Fin 1) => partials polynomial)]
  apply congrArg (fun output : List Goldilocks => some (output, []))
  unfold flattenListRows flattenFinRows
  apply congrArg List.flatten
  apply congrArg List.ofFn
  funext polynomial
  exact HegemonCrypto.SmallWood.SmzaRp05CurrentPcsMaskAlgebra.linear_column_list_is_source_reconstruction
      point (masks polynomial)
      (partials polynomial)

end HegemonCrypto.SmallWood.SmzaRp05CurrentPcsOpeningHeads
