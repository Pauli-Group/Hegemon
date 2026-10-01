import SmzaRp05ExecutablePcsClosureLvcsAlgebra

namespace HegemonCrypto.SmallWood.SmzaRp05ExecutablePcsClosureLvcsAlgebra

open SmzaRp05LvcsWireProjection
open SmzaRp05PcsWireProjection
open SmzaRp05ExecutableChallengeStage (FieldWord)

noncomputable section
set_option autoImplicit false
set_option Elab.async false
set_option maxRecDepth 12000

/-- A transparent proof view of the source's private reconstruction kernel.
The public-success bridge below checks definitional equality to that kernel;
this is not a replacement verifier or an assumed simulation. -/
def rowsKernel (totalRows lvcsCols tailCount : Nat)
    (columns : List Nat) (coefficients heads tails subsets : FMatrix)
    (points : List F) : Option FMatrix := do
  let fullrank := columns.length
  if columns.any (fun column => decide (column ≥ totalRows)) then failure
  let (part1, part2) := splitCoefficientMatrix columns coefficients
  let inverse ← gaussInverse fullrank part1
  if !inverseCheckPassed fullrank part1 inverse then failure
  if heads.length ≠ fullrank ∨ tails.length ≠ fullrank then failure
  if subsets.length ≠ points.length then failure
  let mut rows := []
  for j in List.range points.length do
    let row ← reconstructOne fullrank totalRows lvcsCols tailCount columns
      part1 part2 inverse heads tails (subsets.getD j []) (points.getD j 0)
    rows := rows ++ [row]
  pure rows

theorem append_loop_eq_mapM {α β : Type} (xs : List α)
    (initial : List β) (f : α → Option β) :
    (forIn xs initial (fun x acc => do
      let value ← f x
      pure (.yield (acc ++ [value])))) =
      (xs.mapM f).map (fun values => initial ++ values) := by
  induction xs generalizing initial with
  | nil => simp
  | cons x rest ih =>
      rw [List.forIn_cons, List.mapM_cons]
      cases hx : f x with
      | none => simp
      | some value =>
          simp
          simpa [Option.map_eq_bind, List.append_assoc] using ih (initial ++ [value])

theorem mapM_success_entry {α β : Type}
    (xs : List α) (f : α → Option β) (values : List β)
    (sourceFallback : α) (valueFallback : β)
    (success : xs.mapM f = some values) :
    values.length = xs.length ∧
      ∀ index, index < xs.length →
        f (xs.getD index sourceFallback) = some (values.getD index valueFallback) := by
  induction xs generalizing values with
  | nil =>
      simp at success
      subst values
      simp
  | cons x rest ih =>
      cases hx : f x with
      | none => simp [List.mapM_cons, hx] at success
      | some value =>
          cases hrest : rest.mapM f with
          | none => simp [List.mapM_cons, hx, hrest] at success
          | some tail =>
              simp [List.mapM_cons, hx, hrest] at success
              subst values
              obtain ⟨length_eq, entry_eq⟩ := ih tail hrest
              constructor
              · simp [length_eq]
              · intro index hindex
                cases index with
                | zero => simpa using hx
                | succ index =>
                    have htail : index < rest.length := by simpa using hindex
                    simpa using entry_eq index htail

theorem rows_kernel_success_entries
    (totalRows lvcsCols tailCount : Nat)
    (columns : List Nat) (coefficients heads tails subsets : FMatrix)
    (points : List F) (rows : FMatrix)
    (success : rowsKernel totalRows lvcsCols tailCount columns
      coefficients heads tails subsets points = some rows) :
    ∃ inverse,
      gaussInverse columns.length (splitCoefficientMatrix columns coefficients).1 = some inverse ∧
      rows.length = points.length ∧
      ∀ j, j < points.length →
        reconstructOne columns.length totalRows lvcsCols tailCount columns
          (splitCoefficientMatrix columns coefficients).1
          (splitCoefficientMatrix columns coefficients).2 inverse heads tails
          (subsets.getD j []) (points.getD j 0) = some (rows.getD j []) := by
  cases hsplit : splitCoefficientMatrix columns coefficients with
  | mk part1 part2 =>
      cases hcolumns : columns.any (fun column => decide (column ≥ totalRows)) with
      | true => simp [rowsKernel, hcolumns] at success
      | false =>
          cases hinverse : gaussInverse columns.length part1 with
          | none => simp [rowsKernel, hsplit, hcolumns, hinverse] at success
          | some inverse =>
              cases hchecked : inverseCheckPassed columns.length part1 inverse with
              | false => simp [rowsKernel, hsplit, hcolumns, hinverse, hchecked] at success
              | true =>
                  by_cases hheads : heads.length ≠ columns.length ∨ tails.length ≠ columns.length
                  · simp [rowsKernel, hsplit, hcolumns, hinverse, hheads] at success
                  · by_cases hsubsets : subsets.length ≠ points.length
                    · simp [rowsKernel, hsplit, hcolumns, hinverse, hheads, hsubsets] at success
                    · let rowAt : Nat → Option (List F) := fun j =>
                        reconstructOne columns.length totalRows lvcsCols tailCount columns
                          part1 part2 inverse heads tails (subsets.getD j []) (points.getD j 0)
                      have loop :
                          (forIn (List.range points.length) ([] : FMatrix)
                            (fun j acc => do
                              let row ← rowAt j
                              pure (.yield (acc ++ [row])))) = some rows := by
                        simpa [rowsKernel, hsplit, hcolumns, hinverse, hchecked,
                          hheads, hsubsets, rowAt] using success
                      rw [append_loop_eq_mapM] at loop
                      have mapped : (List.range points.length).mapM rowAt = some rows := by
                        simpa using loop
                      obtain ⟨lengthEq, entries⟩ :=
                        mapM_success_entry (List.range points.length) rowAt rows 0 [] mapped
                      refine ⟨inverse, rfl, by simpa using lengthEq, ?_⟩
                      intro j within
                      have entry := entries j (by simpa using within)
                      simpa [rowAt, List.getD_eq_getElem?_getD,
                        List.getElem?_range within] using entry

/-- Public reconstruction yields full dot equations for the actual returned
rows. The heads, inverse, merged row and residual all come from that one
execution; no twelve-checks certificate is supplied. -/
theorem reconstruct_rows_native_full_dot
    (fields : DecodedPcsFields) (points decsPoints : List F)
    (pointCount : points.length = 6) (rowScalars : List (List FieldWord))
    (widths deltas : List Nat) (rows : FMatrix)
    (success : reconstructRowsFromPcsFields fields points decsPoints rowScalars
      64 widths deltas 2 368 140 38 = some rows) :
    ∃ heads inverse,
      reconstructAllHeads fields points rowScalars 64 widths deltas 2 368 = some heads ∧
      gaussInverse 12
        (splitCoefficientMatrix pivotColumns (pcsBuildCoefficients points 2 64 140)).1 =
          some inverse ∧
      rows.length = decsPoints.length ∧
      ∀ j, j < decsPoints.length → ∀ k, k < 12 →
        dot ((pcsBuildCoefficients points 2 64 140).getD k []) (rows.getD j []) =
          evaluateConsecutive
            (rotateLeft ((heads.getD k []) ++
              ((fields.rcombiTails.map fieldWordsToGoldilocks).getD k [])) 368)
            (decsPoints.getD j 0) := by
  cases headsBuilt : reconstructAllHeads fields points rowScalars 64 widths deltas 2 368 with
  | none => simp [reconstructRowsFromPcsFields, pointCount, headsBuilt] at success
  | some heads =>
      have kernel : rowsKernel 140 368 38 pivotColumns
          (pcsBuildCoefficients points 2 64 140) heads
          (fields.rcombiTails.map fieldWordsToGoldilocks)
          (fields.subsetEvals.map fieldWordsToGoldilocks) decsPoints = some rows := by
        have expanded := success
        simp only [reconstructRowsFromPcsFields, pointCount, headsBuilt] at expanded
        change rowsKernel 140 368 38 pivotColumns
          (pcsBuildCoefficients points 2 64 140) heads
          (fields.rcombiTails.map fieldWordsToGoldilocks)
          (fields.subsetEvals.map fieldWordsToGoldilocks) decsPoints = some rows at expanded
        exact expanded
      obtain ⟨inverse, inverseBuilt, rowCount, entries⟩ :=
        rows_kernel_success_entries 140 368 38 pivotColumns
          (pcsBuildCoefficients points 2 64 140) heads
          (fields.rcombiTails.map fieldWordsToGoldilocks)
          (fields.subsetEvals.map fieldWordsToGoldilocks) decsPoints rows kernel
      have pivotCount : pivotColumns.length = 12 := by decide
      refine ⟨heads, inverse, rfl, ?_, rowCount, ?_⟩
      · simpa only [pivotCount] using inverseBuilt
      · intro j within
        apply native_row_full_dot points pointCount inverse heads
          (fields.rcombiTails.map fieldWordsToGoldilocks)
          ((fields.subsetEvals.map fieldWordsToGoldilocks).getD j [])
          (decsPoints.getD j 0) (rows.getD j [])
        simpa only [pivotCount] using entries j within

end
end HegemonCrypto.SmallWood.SmzaRp05ExecutablePcsClosureLvcsAlgebra
