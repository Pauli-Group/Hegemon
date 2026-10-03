import SmzaRp05CurrentPcsOpeningHeads
import SmzaRp05CurrentPcsConfiguredRow
import SmzaRp05CurrentPcsRegionSuffix
import SmzaRp05CurrentPcsMaskAlgebra
import HegemonCrypto.SmallWoodV8Smz9EagerSimulator

/-! # Exact finite-list view of current PCS reconstructed columns

These lemmas expose the source's typed 736-coordinate evaluation as the same
row-major finite lists consumed by the executable PCS reconstruction.  They
are layout identities over the actual `WitnessOpeningView`, masks and
`SourcePcsView`, not an assumed head-binding relation.
-/

namespace HegemonCrypto.SmallWood.SmzaRp05CurrentPcsActualColumns

open HegemonCrypto.SmallWood (Goldilocks)
open HegemonCrypto.SmallWood.V8Smz9ZeroKnowledge (WitnessOpeningView)
open HegemonCrypto.SmallWood.V8Smz9EagerSimulator
open HegemonCrypto.SmallWood.V8Smz9EagerPrivacy (SourcePcsView)
open HegemonCrypto.SmallWood.V8Smz9RuntimeFieldLayout (matrixEquiv matrix_equiv_symm_apply)
open SmzaRp05CurrentPcsOpeningHeads (flattenFinRows flattenListRows)
open SmzaRp05CurrentPcsOpeningView (reconstructRepeated reconstructRepeated_singleton_witness)
open SmzaRp05PcsWireProjection (reconstructUnstackedRow reconstructHeadZero)
open SmzaRp05CurrentPcsConfiguredRow (configuredRowResult reconstruct_configured_row_decomposes)

set_option autoImplicit false
set_option maxRecDepth 10000

private theorem ofFn_append_three {m n k : Nat}
    (left : Fin m → Goldilocks) (middle : Fin n → Goldilocks)
    (right : Fin k → Goldilocks) :
    List.ofFn (Fin.append left (Fin.append middle right)) =
      (List.ofFn left ++ List.ofFn middle) ++ List.ofFn right := by
  rw [List.ofFn_fin_append, List.ofFn_fin_append, List.append_assoc]

private theorem flattened_matrix {rows columns : Nat}
    (values : Fin rows → Fin columns → Goldilocks) :
    List.ofFn ((matrixEquiv rows columns Goldilocks).symm values) =
      flattenFinRows values := by
  rw [List.ofFn_mul]
  apply congrArg List.flatten
  apply congrArg List.ofFn
  funext row
  apply congrArg List.ofFn
  funext column
  have index :
      (⟨row.val * columns + column.val, by
        calc
          row.val * columns + column.val < (row.val + 1) * columns := by
            exact (Nat.add_lt_add_left column.isLt _).trans_eq
              (by rw [Nat.add_mul, Nat.one_mul])
          _ ≤ rows * columns := Nat.mul_le_mul_right columns row.isLt⟩ :
        Fin (rows * columns)) = finProdFinEquiv (row, column) := by
    apply Fin.ext
    change row.val * columns + column.val = column.val + columns * row.val
    rw [Nat.add_comm, Nat.mul_comm columns row.val]
  rw [index, matrix_equiv_symm_apply]

/-- The typed source evaluation row has the verifier's exact serialization:
686 witness entries, then the row-major five-by-eight nonlinear columns,
then the row-major five-by-two linear columns. -/
theorem reconstructed_columns_as_source_row_list
    (points : Fin 6 → Goldilocks) (witness : WitnessOpeningView Goldilocks)
    (masks : MaskOpeningValues Goldilocks) (partials : SourcePcsView Goldilocks)
    (opening : Fin 6) :
    List.ofFn (reconstructedColumnEvaluations points witness masks partials opening) =
      List.ofFn (witness opening) ++
        flattenFinRows (fun polynomial : Fin 5 =>
          reconstructNonlinearColumns (points opening) (masks.1 opening polynomial)
            (partials.1 polynomial opening)) ++
        flattenFinRows (fun polynomial : Fin 5 =>
          reconstructLinearColumns (points opening) (masks.2 opening polynomial)
            (partials.2 polynomial opening)) := by
  exact (ofFn_append_three (witness opening) _ _).trans
    (congrArg₂ List.append
      (congrArg₂ List.append rfl (flattened_matrix _)) (flattened_matrix _))

/-- The source's 40-entry partial row likewise serializes as the 35-entry
nonlinear rectangle followed by the five linear partials. -/
theorem source_partial_row_list
    (partials : SourcePcsView Goldilocks) (opening : Fin 6) :
    List.ofFn (sourcePartialEvaluations partials opening) =
      flattenFinRows (fun polynomial : Fin 5 =>
        fun column : Fin 7 => partials.1 polynomial opening column) ++
        List.ofFn (fun polynomial : Fin 5 => partials.2 polynomial opening) := by
  unfold sourcePartialEvaluations
  erw [List.ofFn_fin_append, flattened_matrix]

/-- The PIOP opened row scalars use the source's exact 686/5/5 finite append
layout. -/
theorem source_row_scalars_as_list
    (witness : WitnessOpeningView Goldilocks) (masks : MaskOpeningValues Goldilocks)
    (opening : Fin 6) :
    List.ofFn (sourceRowScalars witness masks opening) =
      List.ofFn (witness opening) ++
        (List.ofFn (masks.1 opening) ++ List.ofFn (masks.2 opening)) := by
  exact (ofFn_append_three (witness opening) (masks.1 opening) (masks.2 opening)).trans
    (List.append_assoc _ _ _)

private theorem nonlinear_source_group_list
    (point : Goldilocks) (masks : Fin 5 → Goldilocks)
    (partials : Fin 5 → Fin 7 → Goldilocks) :
    flattenListRows (fun polynomial =>
      reconstructHeadZero point 64 29 (masks polynomial)
        (List.ofFn (partials polynomial)) :: List.ofFn (partials polynomial)) =
      flattenFinRows (fun polynomial =>
        reconstructNonlinearColumns point (masks polynomial) (partials polynomial)) := by
  unfold flattenListRows flattenFinRows
  apply congrArg List.flatten
  apply congrArg List.ofFn
  funext polynomial
  exact SmzaRp05CurrentPcsMaskAlgebra.nonlinear_column_list_is_source_reconstruction
    point (masks polynomial) (partials polynomial)

private theorem linear_source_group_list
    (point : Goldilocks) (masks : Fin 5 → Goldilocks)
    (partials : Fin 5 → Goldilocks) :
    flattenListRows (fun polynomial =>
      [reconstructHeadZero point 64 1 (masks polynomial) [partials polynomial],
        partials polynomial]) =
      flattenFinRows (fun polynomial =>
        reconstructLinearColumns point (masks polynomial) (partials polynomial)) := by
  unfold flattenListRows flattenFinRows
  apply congrArg List.flatten
  apply congrArg List.ofFn
  funext polynomial
  exact SmzaRp05CurrentPcsMaskAlgebra.linear_column_list_is_source_reconstruction
    point (masks polynomial) (partials polynomial)

/-- The actual source row traversal over its opened witness, decoded masks,
and 40 partial-evaluation values equals the typed 736-entry column
construction.  The only inputs are the mathematical projections consumed by
the verifier; no row-success or head-binding certificate is supplied. -/
theorem reconstruct_source_columns_row
    (points : Fin 6 → Goldilocks) (witness : WitnessOpeningView Goldilocks)
    (masks : MaskOpeningValues Goldilocks) (partials : SourcePcsView Goldilocks)
    (opening : Fin 6) :
    reconstructUnstackedRow (points opening) 64
      (SmzaRp05ExecutablePcsClosure.widths) (SmzaRp05ExecutablePcsClosure.deltas)
      (List.ofFn (sourceRowScalars witness masks opening))
      (List.ofFn (sourcePartialEvaluations partials opening)) =
      some (List.ofFn (reconstructedColumnEvaluations points witness masks partials opening)) := by
  have scalarLayout := source_row_scalars_as_list witness masks opening
  have partialLayout := source_partial_row_list partials opening
  have witnessResult : reconstructRepeated (points opening) 64 1 0
      (List.ofFn (witness opening)) (List.ofFn (sourcePartialEvaluations partials opening)) =
      some (List.ofFn (witness opening), List.ofFn (sourcePartialEvaluations partials opening)) := by
    exact reconstructRepeated_singleton_witness (points opening) (List.ofFn (witness opening))
      (List.ofFn (sourcePartialEvaluations partials opening))
  have nonlinearResult : reconstructRepeated (points opening) 64 8 29
      (List.ofFn (masks.1 opening)) (List.ofFn (sourcePartialEvaluations partials opening)) =
      some (flattenListRows (fun polynomial =>
        reconstructHeadZero (points opening) 64 29 (masks.1 opening polynomial)
          (List.ofFn (fun column => partials.1 polynomial opening column)) ::
        List.ofFn (fun column => partials.1 polynomial opening column)),
        List.ofFn (fun polynomial => partials.2 polynomial opening)) := by
    rw [partialLayout]
    exact SmzaRp05CurrentPcsRegionSuffix.reconstructRepeated_rows_suffix
      (points opening) 8 29 5 (by decide) (by decide) (masks.1 opening)
      (fun polynomial column => partials.1 polynomial opening column)
      (List.ofFn (fun polynomial => partials.2 polynomial opening))
  have linearResult : reconstructRepeated (points opening) 64 2 1
      (List.ofFn (masks.2 opening))
      (List.ofFn (fun polynomial => partials.2 polynomial opening)) =
      some (flattenListRows (fun polynomial =>
        [reconstructHeadZero (points opening) 64 1 (masks.2 opening polynomial)
          [partials.2 polynomial opening], partials.2 polynomial opening]), []) := by
    simpa [flattenFinRows] using
      (HegemonCrypto.SmallWood.SmzaRp05CurrentPcsOpeningHeads.reconstructRepeated_rows
        (points opening) 2 1 5 (by decide) (by decide) (masks.2 opening)
        (fun polynomial (_ : Fin 1) => partials.2 polynomial opening))
  have configured := reconstruct_configured_row_decomposes (points opening)
    (List.ofFn (witness opening)) (List.ofFn (masks.1 opening))
    (List.ofFn (masks.2 opening)) (List.ofFn (sourcePartialEvaluations partials opening))
    (by
      have counts := V8Smz9ZeroKnowledge.smz9_algebraic_coordinate_counts_are_exact
      simpa only [List.length_ofFn] using counts.2.2.1)
    (by norm_num) (by norm_num)
  have scalarLayout' : List.ofFn (sourceRowScalars witness masks opening) =
      (List.ofFn (witness opening) ++ List.ofFn (masks.1 opening)) ++
        List.ofFn (masks.2 opening) :=
    scalarLayout.trans (List.append_assoc _ _ _).symm
  calc
    _ = reconstructUnstackedRow (points opening) 64
        SmzaRp05ExecutablePcsClosure.widths SmzaRp05ExecutablePcsClosure.deltas
        ((List.ofFn (witness opening) ++ List.ofFn (masks.1 opening)) ++
          List.ofFn (masks.2 opening))
        (List.ofFn (sourcePartialEvaluations partials opening)) :=
      congrArg (fun scalars => reconstructUnstackedRow (points opening) 64
        SmzaRp05ExecutablePcsClosure.widths SmzaRp05ExecutablePcsClosure.deltas
        scalars (List.ofFn (sourcePartialEvaluations partials opening))) scalarLayout'
    _ = configuredRowResult (points opening) (List.ofFn (witness opening))
        (List.ofFn (masks.1 opening)) (List.ofFn (masks.2 opening))
        (List.ofFn (sourcePartialEvaluations partials opening)) := configured
    _ = some ((List.ofFn (witness opening) ++
        flattenFinRows (fun polynomial => reconstructNonlinearColumns
          (points opening) (masks.1 opening polynomial) (partials.1 polynomial opening))) ++
        flattenFinRows (fun polynomial => reconstructLinearColumns
          (points opening) (masks.2 opening polynomial) (partials.2 polynomial opening))) := by
      simp only [configuredRowResult, witnessResult, nonlinearResult, linearResult,
        Option.bind_some, if_true,
        nonlinear_source_group_list, linear_source_group_list]
    _ = _ := congrArg some
      (reconstructed_columns_as_source_row_list points witness masks partials opening).symm

end HegemonCrypto.SmallWood.SmzaRp05CurrentPcsActualColumns
