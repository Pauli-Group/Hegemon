import SmzaRp05CurrentPcsOpeningView
import SmzaRp05CurrentPcsOpeningHeads
import SmzaRp05CurrentPcsRegionSuffix
import HegemonCrypto.SmallWoodV8Smz9RuntimeFieldLayout

/-!
# Current arbitrary-scalar PCS row factorization

The inputs here are arbitrary 26220 opened scalars and ten PCS partials.
The exact executable traversal emits 26230 columns in current source order:
26210 singleton witness columns, five nonlinear pairs, five linear pairs.
No honest SourceData, acceptance certificate, or desired scalar-binding
premise is used. Decoder/stage provenance and the LVCS equality-or-event
join belong to the caller. SOURCE ONLY: actual kernel check is pending.
-/
namespace HegemonCrypto.SmallWood.NativePrivateSpendQ58CurrentScalarRowFactorization

open HegemonCrypto.SmallWood (Goldilocks)
open SmzaRp05PcsWireProjection
  (reconstructUnstackedRow reconstructHeadZero reconstructHeadZero_single_partial
   chunkHeads paddedChunk)
open SmzaRp05CurrentPcsOpeningView
  (reconstructRepeated reconstructRepeated_singleton_witness reconstructUnstackedRow_repeat)
open SmzaRp05CurrentPcsOpeningHeads (flattenFinRows flattenListRows)
open V8Smz9RuntimeFieldLayout (matrixEquiv matrix_equiv_symm_apply)

set_option autoImplicit false

def widths : List Nat := List.replicate 26210 1 ++ List.replicate 10 2
def deltas : List Nat :=
  List.replicate 26210 0 ++ List.replicate 5 59 ++ List.replicate 5 1

def witnessScalar (scalars : Fin 26220 → Goldilocks) (row : Fin 26210) : Goldilocks :=
  scalars (Fin.castAdd 10 row)
def nonlinearScalar (scalars : Fin 26220 → Goldilocks) (row : Fin 5) : Goldilocks :=
  scalars (Fin.natAdd 26210 (Fin.castAdd 5 row))
def linearScalar (scalars : Fin 26220 → Goldilocks) (row : Fin 5) : Goldilocks :=
  scalars (Fin.natAdd 26210 (Fin.natAdd 5 row))

def nonlinearPartial (partials : Fin 10 → Goldilocks) (row : Fin 5) : Goldilocks :=
  partials (Fin.castAdd 5 row)
def linearPartial (partials : Fin 10 → Goldilocks) (row : Fin 5) : Goldilocks :=
  partials (Fin.natAdd 5 row)

def pairRow (point : Goldilocks) (delta : Nat)
    (scalars partials : Fin 5 → Goldilocks) (row : Fin 5) : Fin 2 → Goldilocks :=
  ![reconstructHeadZero point 64 delta (scalars row) [partials row], partials row]

def pairColumns (point : Goldilocks) (delta : Nat)
    (scalars partials : Fin 5 → Goldilocks) : Fin 10 → Goldilocks :=
  (matrixEquiv 5 2 Goldilocks).symm (pairRow point delta scalars partials)

def emittedColumns (point : Goldilocks)
    (scalars : Fin 26220 → Goldilocks) (partials : Fin 10 → Goldilocks) :
    Fin 26230 → Goldilocks :=
  Fin.append (witnessScalar scalars)
    (Fin.append
      (pairColumns point 59 (nonlinearScalar scalars) (nonlinearPartial partials))
      (pairColumns point 1 (linearScalar scalars) (linearPartial partials)))

def nonlinearColumnIndex (row : Fin 5) (part : Fin 2) : Fin 26230 :=
  Fin.natAdd 26210 (Fin.castAdd 10 (finProdFinEquiv (row, part)))
def linearColumnIndex (row : Fin 5) (part : Fin 2) : Fin 26230 :=
  Fin.natAdd 26210 (Fin.natAdd 10 (finProdFinEquiv (row, part)))

private theorem scalar_list (scalars : Fin 26220 → Goldilocks) :
    List.ofFn scalars = List.ofFn (witnessScalar scalars) ++
      (List.ofFn (nonlinearScalar scalars) ++ List.ofFn (linearScalar scalars)) := by
  have maskAppend : Fin.append (nonlinearScalar scalars) (linearScalar scalars) =
      (fun row : Fin 10 => scalars (Fin.natAdd 26210 row)) := by
    unfold nonlinearScalar linearScalar
    exact Fin.append_castAdd_natAdd (m := 5) (n := 5)
      (f := fun row : Fin 10 => scalars (Fin.natAdd 26210 row))
  have scalarAppend : Fin.append (witnessScalar scalars)
      (Fin.append (nonlinearScalar scalars) (linearScalar scalars)) = scalars := by
    rw [maskAppend]
    exact Fin.append_castAdd_natAdd
  calc
    List.ofFn scalars = List.ofFn (Fin.append (witnessScalar scalars)
        (Fin.append (nonlinearScalar scalars) (linearScalar scalars))) :=
      congrArg List.ofFn scalarAppend.symm
    _ = _ := by rw [List.ofFn_fin_append, List.ofFn_fin_append]

private theorem partial_list (partials : Fin 10 → Goldilocks) :
    List.ofFn partials =
      List.ofFn (nonlinearPartial partials) ++ List.ofFn (linearPartial partials) := by
  have partialAppend : Fin.append (nonlinearPartial partials) (linearPartial partials) =
      partials := Fin.append_castAdd_natAdd
  calc
    List.ofFn partials =
        List.ofFn (Fin.append (nonlinearPartial partials) (linearPartial partials)) :=
      congrArg List.ofFn partialAppend.symm
    _ = _ := List.ofFn_fin_append _ _

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

private theorem pair_columns_list (point : Goldilocks) (delta : Nat)
    (scalars partials : Fin 5 → Goldilocks) :
    List.ofFn (pairColumns point delta scalars partials) =
      flattenListRows (fun row =>
        [reconstructHeadZero point 64 delta (scalars row) [partials row], partials row]) := by
  unfold pairColumns
  rw [flattened_matrix]
  unfold flattenFinRows flattenListRows
  apply congrArg List.flatten
  apply congrArg List.ofFn
  funext row
  simp [pairRow, List.ofFn_succ]

/-- The exact finite column vector, in the executable emitted order. -/
theorem current_columns_as_list (point : Goldilocks)
    (scalars : Fin 26220 → Goldilocks) (partials : Fin 10 → Goldilocks) :
    List.ofFn (emittedColumns point scalars partials) =
      List.ofFn (witnessScalar scalars) ++
      flattenListRows (fun row =>
        [reconstructHeadZero point 64 59 (nonlinearScalar scalars row)
          [nonlinearPartial partials row], nonlinearPartial partials row]) ++
      flattenListRows (fun row =>
        [reconstructHeadZero point 64 1 (linearScalar scalars row)
          [linearPartial partials row], linearPartial partials row]) := by
  unfold emittedColumns
  rw [List.ofFn_fin_append, List.ofFn_fin_append,
    pair_columns_list, pair_columns_list]
  exact (List.append_assoc _ _ _).symm

/-- Current configured traversal, calculated from arbitrary input arrays. -/
theorem reconstruct_current_row (point : Goldilocks)
    (scalars : Fin 26220 → Goldilocks) (partials : Fin 10 → Goldilocks) :
    reconstructUnstackedRow point 64 widths deltas
      (List.ofFn scalars) (List.ofFn partials) =
        some (List.ofFn (emittedColumns point scalars partials)) := by
  have witnessSplit := reconstructUnstackedRow_repeat point 64 1 0 26210
    (List.replicate 5 2 ++ List.replicate 5 2)
    (List.replicate 5 59 ++ List.replicate 5 1)
    (List.ofFn (witnessScalar scalars))
    (List.ofFn (nonlinearScalar scalars) ++ List.ofFn (linearScalar scalars))
    (List.ofFn partials) (by simp only [List.length_ofFn])
  have nonlinearSplit := reconstructUnstackedRow_repeat point 64 2 59 5
    (List.replicate 5 2) (List.replicate 5 1)
    (List.ofFn (nonlinearScalar scalars)) (List.ofFn (linearScalar scalars))
    (List.ofFn partials) (by simp only [List.length_ofFn])
  have nonlinearResult : reconstructRepeated point 64 2 59
      (List.ofFn (nonlinearScalar scalars)) (List.ofFn partials) =
      some (flattenListRows (fun row =>
        [reconstructHeadZero point 64 59 (nonlinearScalar scalars row)
          [nonlinearPartial partials row], nonlinearPartial partials row]),
        List.ofFn (linearPartial partials)) := by
    rw [partial_list]
    simpa [flattenFinRows] using
      (SmzaRp05CurrentPcsRegionSuffix.reconstructRepeated_rows_suffix
        point 2 59 5 (by decide) (by decide) (nonlinearScalar scalars)
        (fun row (_ : Fin 1) => nonlinearPartial partials row)
        (List.ofFn (linearPartial partials)))
  have linearSplit : reconstructUnstackedRow point 64
      (List.replicate 5 2) (List.replicate 5 1)
      (List.ofFn (linearScalar scalars)) (List.ofFn (linearPartial partials)) =
      (reconstructRepeated point 64 2 1 (List.ofFn (linearScalar scalars))
        (List.ofFn (linearPartial partials))).bind (fun result =>
          (reconstructUnstackedRow point 64 [] [] [] result.2).map
            (fun suffix => result.1 ++ suffix)) := by
    simpa only [List.append_nil] using
      (reconstructUnstackedRow_repeat point 64 2 1 5 [] []
        (List.ofFn (linearScalar scalars)) [] (List.ofFn (linearPartial partials))
        (by simp only [List.length_ofFn]))
  have linearResult : reconstructRepeated point 64 2 1
      (List.ofFn (linearScalar scalars)) (List.ofFn (linearPartial partials)) =
      some (flattenListRows (fun row =>
        [reconstructHeadZero point 64 1 (linearScalar scalars row)
          [linearPartial partials row], linearPartial partials row]), []) := by
    simpa [flattenFinRows] using
      (SmzaRp05CurrentPcsOpeningHeads.reconstructRepeated_rows
        point 2 1 5 (by decide) (by decide) (linearScalar scalars)
        (fun row (_ : Fin 1) => linearPartial partials row))
  rw [scalar_list]
  unfold widths deltas
  rw [show List.replicate 10 2 = List.replicate 5 2 ++ List.replicate 5 2 from
    List.replicate_add 5 5 2]
  simp only [List.append_assoc]
  rw [witnessSplit, reconstructRepeated_singleton_witness]
  simp only [Option.bind_some]
  rw [nonlinearSplit, nonlinearResult]
  simp only [Option.bind_some]
  rw [linearSplit, linearResult]
  simpa only [Option.bind_some, Option.map_some, reconstructUnstackedRow,
    List.append_nil, List.append_assoc] using
    (congrArg some (current_columns_as_list point scalars partials).symm)

/-- Two exact current chunks read the column array without padding. -/
theorem current_chunk_reads_column (values : Fin 26230 → Goldilocks)
    (block : Fin 2) (column : Fin 13115) :
    ((chunkHeads 2 13115 (List.ofFn values)).getD block.val []).getD column.val 0 =
      values ⟨block.val * 13115 + column.val, by
        have := block.isLt
        have := column.isLt
        omega⟩ := by
  have blockBound := block.isLt
  have columnBound := column.isLt
  have chunkLength :
      ((List.ofFn values).drop (block.val * 13115) |>.take 13115).length = 13115 := by
    simp only [List.length_take, List.length_drop, List.length_ofFn]
    omega
  rw [List.getD_eq_getElem (chunkHeads 2 13115 (List.ofFn values)) [] (by
    simpa only [chunkHeads, List.length_map, List.length_range] using blockBound)]
  simp only [chunkHeads, List.getElem_map, List.getElem_range, paddedChunk]
  rw [chunkLength, Nat.sub_self, List.replicate_zero, List.append_nil]
  rw [List.getD_eq_getElem _ _ (by simpa only [chunkLength] using columnBound)]
  simp only [List.getElem_take, List.getElem_drop, List.getElem_ofFn]

/-- Width-one current columns are the original opened witness scalars. -/
theorem current_witness_scalar_recombines (point : Goldilocks)
    (scalars : Fin 26220 → Goldilocks) (partials : Fin 10 → Goldilocks)
    (row : Fin 26210) :
    emittedColumns point scalars partials (Fin.castAdd 20 row) =
      scalars (Fin.castAdd 10 row) := by
  simp only [emittedColumns, Fin.append_left, witnessScalar]

/-- The two current nonlinear heads recover the actual input scalar. -/
theorem current_nonlinear_scalar_recombines (point : Goldilocks)
    (scalars : Fin 26220 → Goldilocks) (partials : Fin 10 → Goldilocks)
    (row : Fin 5) :
    emittedColumns point scalars partials (nonlinearColumnIndex row 0) +
      point ^ 5 * emittedColumns point scalars partials (nonlinearColumnIndex row 1) =
        scalars (Fin.natAdd 26210 (Fin.castAdd 5 row)) := by
  simp only [emittedColumns, nonlinearColumnIndex, Fin.append_right, Fin.append_left,
    pairColumns, matrix_equiv_symm_apply, pairRow,
    reconstructHeadZero_single_partial, nonlinearScalar]
  norm_num
  ring

/-- The two current linear heads recover the actual input scalar. -/
theorem current_linear_scalar_recombines (point : Goldilocks)
    (scalars : Fin 26220 → Goldilocks) (partials : Fin 10 → Goldilocks)
    (row : Fin 5) :
    emittedColumns point scalars partials (linearColumnIndex row 0) +
      point ^ 63 * emittedColumns point scalars partials (linearColumnIndex row 1) =
        scalars (Fin.natAdd 26210 (Fin.natAdd 5 row)) := by
  simp only [emittedColumns, linearColumnIndex, Fin.append_right,
    pairColumns, matrix_equiv_symm_apply, pairRow,
    reconstructHeadZero_single_partial, linearScalar]
  norm_num
  ring

end HegemonCrypto.SmallWood.NativePrivateSpendQ58CurrentScalarRowFactorization
