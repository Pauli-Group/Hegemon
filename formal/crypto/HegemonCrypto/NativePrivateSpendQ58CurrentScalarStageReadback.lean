import HegemonCrypto.NativePrivateSpendQ58CurrentExecutableVerifier
import SmzaRp05CurrentPcsPartialLength
import SmzaRp05CurrentPcsStageHeads
import HegemonCrypto.NativePrivateSpendQ58CurrentScalarRowFactorization

/-! Current shared-row readback. Successful native decoding supplies the same
scalar matrix to PCS reconstruction and PIOP. Successful list reconstruction
derives its scalar and partial shapes; no successful-history, algebraic check,
head-binding or scalar-agreement certificate is supplied. Source only. -/
namespace HegemonCrypto.SmallWood.NativePrivateSpendQ58CurrentScalarStageReadback

namespace E
export NativePrivateSpendQ58CurrentExecutableVerifier
  (Wire DecodedFields decodeWire Opening points widths deltas)
end E
namespace RF
export NativePrivateSpendQ58CurrentScalarRowFactorization
  (widths deltas emittedColumns reconstruct_current_row current_chunk_reads_column)
end RF
open SmzaRp05PcsWireProjection
  (reconstructUnstackedRow reconstructedHeadsForRow reconstructDecodedPcsRow
    DecodedPcsFields fieldWordsToGoldilocks decodeFieldMatrix decodePcsFields)
open SmzaRp05DecsResponseProjection (decodeDecsResponseFields)
open SmzaRp05ExecutableChallengeStage (FieldWord zeroWord)
set_option autoImplicit false
set_option maxHeartbeats 0
set_option maxRecDepth 0
set_option Elab.async false
noncomputable section

/-- Both consumers read the same matrix produced by decodeWire. No shape or
new value is supplied to this projection law. -/
theorem decode_wire_rows_are_shared
    (wire : E.Wire) (decoded : E.DecodedFields)
    (success : E.decodeWire wire = some decoded)
    (coordinate : Fin 6) (column : Fin 26220) :
    decoded.piop.rowScalars coordinate column =
      (decoded.rowScalars.getD coordinate.val []).getD column.val zeroWord := by
  unfold E.decodeWire at success
  split at success
  · simp at success
  · change (decodeFieldMatrix wire.piopNonlinearHighs).bind
      (fun nonlinear => (decodeFieldMatrix wire.piopLinearHighs).bind
        (fun linear => (decodeFieldMatrix wire.openedRowScalars).bind
          (fun rows => (decodePcsFields wire.partialEvals wire.rcombiTails wire.subsetEvals).bind
            (fun pcs => (decodeDecsResponseFields wire.decsHighCoeffs wire.decsMaskingEvals).bind
              (fun decs => some {
                pcs := pcs
                decs := decs
                piop := {
                  nonlinearHighs := fun i j => (nonlinear.getD i.val []).getD j.val zeroWord
                  linearHighs := fun i j => (linear.getD i.val []).getD j.val zeroWord
                  rowScalars := fun i j => (rows.getD i.val []).getD j.val zeroWord }
                rowScalars := rows }))))) = some decoded at success
    obtain ⟨nonlinear, _nonlinearEq, success⟩ := Option.bind_eq_some_iff.mp success
    obtain ⟨linear, _linearEq, success⟩ := Option.bind_eq_some_iff.mp success
    obtain ⟨rows, _rowsEq, success⟩ := Option.bind_eq_some_iff.mp success
    obtain ⟨pcs, _pcsEq, success⟩ := Option.bind_eq_some_iff.mp success
    obtain ⟨decs, _decsEq, success⟩ := Option.bind_eq_some_iff.mp success
    rw [← Option.some.inj success]

/-- Each recursive success consumes one scalar per configured polynomial. -/
theorem successful_reconstruction_scalar_length
    (point : Goldilocks) (packingFactor : Nat)
    (widths deltas : List Nat) (scalars partials output : List Goldilocks)
    (success : reconstructUnstackedRow point packingFactor widths deltas
      scalars partials = some output) : scalars.length = widths.length := by
  induction widths generalizing deltas scalars partials output with
  | nil =>
      cases deltas <;> cases scalars <;> cases partials <;>
        simp_all [reconstructUnstackedRow]
  | cons width widths ih =>
      cases deltas with
      | nil => simp [reconstructUnstackedRow] at success
      | cons delta deltas =>
          cases scalars with
          | nil => simp [reconstructUnstackedRow] at success
          | cons scalar scalars =>
              by_cases bad : width = 0 ∨ delta > packingFactor
              · simp [reconstructUnstackedRow, bad] at success
              · by_cases short : (partials.take (width - 1)).length ≠ width - 1
                · simp only [reconstructUnstackedRow, if_neg bad, if_pos short] at success
                  cases success
                · cases remaining : reconstructUnstackedRow point packingFactor
                      widths deltas scalars (partials.drop (width - 1)) with
                  | none =>
                      simp only [reconstructUnstackedRow, if_neg bad, if_neg short,
                        remaining, Option.bind_eq_bind, Option.bind_none] at success
                      cases success
                  | some rest =>
                      simpa only [List.length_cons] using
                        congrArg Nat.succ (ih deltas scalars
                          (partials.drop (width - 1)) rest remaining)

attribute [local irreducible]
  HegemonCrypto.SmallWood.SmzaRp05PcsWireProjection.reconstructUnstackedRow

/-- These are the current26220 scalars and ten partials, derived from the
actual same-row recursion rather than an additional guard. -/
theorem successful_current_row_shapes
    (point : Goldilocks) (scalars partials output : List Goldilocks)
    (success : reconstructUnstackedRow point 64 E.widths E.deltas
      scalars partials = some output) :
    scalars.length = 26220 ∧ partials.length = 10 := by
  have scalarLength := successful_reconstruction_scalar_length point 64
    E.widths E.deltas scalars partials output success
  have partialLength :=
    SmzaRp05CurrentPcsPartialLength.successful_reconstruction_partial_length point 64
      E.widths E.deltas scalars partials output success
  constructor
  · simpa only [E.widths, List.length_append, List.length_replicate] using scalarLength
  · simp only [E.widths, List.map_append, List.map_replicate,
      List.sum_append, List.sum_replicate] at partialLength
    norm_num at partialLength
    exact partialLength

/-- In-bounds getD readback is a typed finite vector of the entire actual list. -/
theorem list_equals_typed_readback {α : Type} {count : Nat}
    (values : List α) (fallback : α) (shape : values.length = count) :
    values = List.ofFn (fun index : Fin count => values.getD index.val fallback) := by
  apply List.ext_getElem (by simpa only [List.length_ofFn] using shape)
  intro index leftBound _rightBound
  simp only [List.getElem_ofFn]
  rw [List.getD_eq_getElem values fallback leftBound]

attribute [local irreducible] List.ofFn

/-- A successful actual row yields its current scalar and partial vectors.
The scalar vector is the piop.rowScalars projection, not a second row. -/
theorem successful_decoded_row_has_current_vectors
    (wire : E.Wire) (decoded : E.DecodedFields) (opening : E.Opening)
    (decodeSuccess : E.decodeWire wire = some decoded)
    (coordinate : Fin 6) (output : List Goldilocks)
    (success : reconstructDecodedPcsRow decoded.pcs (List.ofFn (E.points opening))
      decoded.rowScalars coordinate.val 64 E.widths E.deltas = some output) :
    ∃ partials : Fin 10 → Goldilocks,
      reconstructUnstackedRow (E.points opening coordinate) 64 E.widths E.deltas
        (List.ofFn fun index : Fin 26220 => (decoded.piop.rowScalars coordinate index).val)
        (List.ofFn partials) = some output := by
  have pointAt : (List.ofFn (E.points opening))[coordinate.val]? =
      some (E.points opening coordinate) := by
    rw [List.getElem?_eq_getElem (by simpa only [List.length_ofFn] using coordinate.isLt)]
    simp only [List.getElem_ofFn]
  cases scalarAt : decoded.rowScalars[coordinate.val]? with
  | none => simp only [reconstructDecodedPcsRow, pointAt, scalarAt] at success; cases success
  | some scalars =>
      cases partialAt : decoded.pcs.partialEvals[coordinate.val]? with
      | none =>
          simp only [reconstructDecodedPcsRow, pointAt, scalarAt, partialAt] at success
          cases success
      | some partials =>
          have scalarRead : decoded.rowScalars.getD coordinate.val [] = scalars := by
            rw [List.getD_eq_getElem?_getD, scalarAt]
            rfl
          have reconstructed : reconstructUnstackedRow (E.points opening coordinate) 64
              E.widths E.deltas (fieldWordsToGoldilocks scalars)
                (fieldWordsToGoldilocks partials) = some output := by
            simpa only [reconstructDecodedPcsRow, pointAt, scalarAt, partialAt] using success
          obtain ⟨scalarLength, partialLength⟩ :=
            successful_current_row_shapes _ _ _ _ reconstructed
          have scalarFieldsLength : scalars.length = 26220 := by
            simpa only [fieldWordsToGoldilocks, List.length_map] using scalarLength
          have scalarVector : fieldWordsToGoldilocks scalars =
              List.ofFn (fun index : Fin 26220 =>
                ((decoded.piop.rowScalars coordinate index).val : Goldilocks)) := by
            let readback : Fin 26220 → FieldWord := fun index =>
              scalars.getD index.val zeroWord
            have decodedFields : fieldWordsToGoldilocks scalars =
                fieldWordsToGoldilocks (List.ofFn readback) :=
              congrArg fieldWordsToGoldilocks
                (list_equals_typed_readback scalars zeroWord scalarFieldsLength)
            have decodedValues : fieldWordsToGoldilocks (List.ofFn readback) =
                List.ofFn (fun index : Fin 26220 => ((readback index).val : Goldilocks)) :=
              List.map_ofFn (f := readback)
                (g := fun word : FieldWord => (word.val : Goldilocks))
            have agreement :
                (fun index : Fin 26220 => ((readback index).val : Goldilocks)) =
                (fun index : Fin 26220 =>
                  ((decoded.piop.rowScalars coordinate index).val : Goldilocks)) := by
              funext index
              exact ((congrArg (fun word : FieldWord => (word.val : Goldilocks))
                (decode_wire_rows_are_shared wire decoded decodeSuccess coordinate index)).trans
                (congrArg (fun row : List FieldWord =>
                  ((row.getD index.val zeroWord).val : Goldilocks)) scalarRead)).symm
            exact decodedFields.trans (decodedValues.trans
              (congrArg (fun values : Fin 26220 → Goldilocks => List.ofFn values) agreement))
          let partialVector : Fin 10 → Goldilocks := fun index =>
            (fieldWordsToGoldilocks partials).getD index.val 0
          have partialVectorEq : fieldWordsToGoldilocks partials = List.ofFn partialVector :=
            list_equals_typed_readback _ 0 partialLength
          refine ⟨partialVector, ?_⟩
          exact (congrArg₂ (fun scalars partials : List Goldilocks =>
            reconstructUnstackedRow (E.points opening coordinate) 64 E.widths E.deltas
              scalars partials) scalarVector partialVectorEq).symm.trans reconstructed

/-- The same guarded head construction exposes each successful actual row.
The two height equations are obtained from its own rejection guard. -/
theorem current_heads_expose_decoded_rows
    (decoded : E.DecodedFields) (opening : E.Opening)
    (heads : List (List Goldilocks))
    (success : SmzaRp05PcsWireProjection.reconstructedHeadsAll decoded.pcs
      (List.ofFn (E.points opening)) decoded.rowScalars 64 E.widths E.deltas
      2 13115 = some heads) :
    ∃ rows : List (List (List Goldilocks)),
      heads = rows.flatten ∧ rows.length = 6 ∧
      ∀ coordinate : Fin 6,
        reconstructedHeadsForRow decoded.pcs (List.ofFn (E.points opening))
          decoded.rowScalars coordinate.val 64 E.widths E.deltas 2 13115 =
            some (rows.getD coordinate.val []) := by
  have heights : decoded.rowScalars.length = (List.ofFn (E.points opening)).length ∧
      decoded.pcs.partialEvals.length = (List.ofFn (E.points opening)).length := by
    have pass : ¬ (decoded.rowScalars.length ≠ (List.ofFn (E.points opening)).length ∨
        decoded.pcs.partialEvals.length ≠ (List.ofFn (E.points opening)).length) := by
      intro bad
      have rejected : SmzaRp05PcsWireProjection.reconstructedHeadsAll decoded.pcs
          (List.ofFn (E.points opening)) decoded.rowScalars 64 E.widths E.deltas
          2 13115 = none := by
        simp only [SmzaRp05PcsWireProjection.reconstructedHeadsAll, if_pos bad]
        rfl
      cases (rejected.symm.trans success)
    exact ⟨by omega, by omega⟩
  obtain ⟨rows, same, count, each⟩ :=
    SmzaRp05CurrentPcsStageHeads.reconstructed_heads_all_exposes_row decoded.pcs
      (List.ofFn (E.points opening)) decoded.rowScalars 64 E.widths E.deltas
      2 13115 heads heights success
  refine ⟨rows, same, ?_, ?_⟩
  · simpa only [List.length_ofFn] using count
  · intro coordinate
    exact each coordinate.val (by simpa only [List.length_ofFn] using coordinate.isLt)

/-- Each head row is exactly two chunks of one successful decoded row.
No padding or scalar equation is asserted here; the row result is obtained
from the option computation before the chunk map. -/
theorem successful_current_head_row_exposes_row
    (decoded : E.DecodedFields) (opening : E.Opening) (coordinate : Fin 6)
    (headRow : List (List Goldilocks))
    (success : reconstructedHeadsForRow decoded.pcs (List.ofFn (E.points opening))
      decoded.rowScalars coordinate.val 64 E.widths E.deltas 2 13115 = some headRow) :
    ∃ row : List Goldilocks,
      reconstructDecodedPcsRow decoded.pcs (List.ofFn (E.points opening))
        decoded.rowScalars coordinate.val 64 E.widths E.deltas = some row ∧
      headRow = SmzaRp05PcsWireProjection.chunkHeads 2 13115 row := by
  unfold reconstructedHeadsForRow at success
  change (reconstructDecodedPcsRow decoded.pcs (List.ofFn (E.points opening))
      decoded.rowScalars coordinate.val 64 E.widths E.deltas).bind
      (fun row => some (SmzaRp05PcsWireProjection.chunkHeads 2 13115 row)) =
        some headRow at success
  obtain ⟨row, reconstructed, same⟩ := Option.bind_eq_some_iff.mp success
  exact ⟨row, reconstructed, (Option.some.inj same).symm⟩

/-- The flattened actual head matrix reads the computed arbitrary-scalar
columns. All region shapes and chunk identities come from actual success. -/
theorem current_heads_are_computed_columns
    (wire : E.Wire) (decoded : E.DecodedFields) (opening : E.Opening)
    (decodeSuccess : E.decodeWire wire = some decoded)
    (heads : List (List Goldilocks))
    (headsBuilt : SmzaRp05PcsWireProjection.reconstructedHeadsAll decoded.pcs
      (List.ofFn (E.points opening)) decoded.rowScalars 64 E.widths E.deltas
      2 13115 = some heads) :
    ∀ coordinate : Fin 6, ∃ partials : Fin 10 → Goldilocks,
      ∀ block : Fin 2, ∀ head : Fin 13115,
        (heads.getD (2 * coordinate.val + block.val) []).getD head.val 0 =
          RF.emittedColumns (E.points opening coordinate)
            (fun index : Fin 26220 => (decoded.piop.rowScalars coordinate index).val)
            partials (finProdFinEquiv (block, head)) := by
  obtain ⟨rows, headsSame, rowsLength, each⟩ :=
    current_heads_expose_decoded_rows decoded opening heads headsBuilt
  have rowShape : ∀ entry, entry ∈ rows → entry.length = 2 := by
    intro entry member
    obtain ⟨index, bound, atIndex⟩ := List.mem_iff_getElem.mp member
    let coordinate : Fin 6 := ⟨index, by omega⟩
    obtain ⟨row, _reconstructed, same⟩ := successful_current_head_row_exposes_row
      decoded opening coordinate (rows.getD index []) (each coordinate)
    rw [← atIndex, ← List.getD_eq_getElem rows [] bound, same]
    simp only [SmzaRp05PcsWireProjection.chunkHeads, List.length_map, List.length_range]
  intro coordinate
  obtain ⟨row, reconstructed, sameChunks⟩ := successful_current_head_row_exposes_row
    decoded opening coordinate (rows.getD coordinate.val []) (each coordinate)
  obtain ⟨partials, sameRow⟩ := successful_decoded_row_has_current_vectors
    wire decoded opening decodeSuccess coordinate row reconstructed
  have computed := RF.reconstruct_current_row (E.points opening coordinate)
    (fun index : Fin 26220 => (decoded.piop.rowScalars coordinate index).val) partials
  have rowEq : row = List.ofFn (RF.emittedColumns (E.points opening coordinate)
      (fun index : Fin 26220 => (decoded.piop.rowScalars coordinate index).val) partials) := by
    have widthsEq : E.widths = RF.widths := rfl
    have deltasEq : E.deltas = RF.deltas := rfl
    have configuration :
        reconstructUnstackedRow (E.points opening coordinate) 64 E.widths E.deltas
          (List.ofFn fun index : Fin 26220 => (decoded.piop.rowScalars coordinate index).val)
          (List.ofFn partials) =
        reconstructUnstackedRow (E.points opening coordinate) 64 RF.widths RF.deltas
          (List.ofFn fun index : Fin 26220 => (decoded.piop.rowScalars coordinate index).val)
          (List.ofFn partials) :=
      congrArg₂ (fun widths deltas : List Nat =>
        reconstructUnstackedRow (E.points opening coordinate) 64 widths deltas
          (List.ofFn fun index : Fin 26220 => (decoded.piop.rowScalars coordinate index).val)
          (List.ofFn partials)) widthsEq deltasEq
    exact Option.some.inj (sameRow.symm.trans (configuration.trans computed))
  refine ⟨partials, ?_⟩
  intro block head
  have flatRead := SmzaRp05CurrentPcsStageHeads.rectangular_flatten_getD
    rows 2 coordinate.val block.val [] rowShape (by omega) block.isLt
  rw [headsSame]
  rw [show 2 * coordinate.val + block.val = coordinate.val * 2 + block.val by omega,
    flatRead, sameChunks]
  refine (congrArg (fun values : List Goldilocks =>
    ((SmzaRp05PcsWireProjection.chunkHeads 2 13115 values).getD block.val []).getD head.val 0)
    rowEq).trans ((RF.current_chunk_reads_column
      (RF.emittedColumns (E.points opening coordinate)
        (fun index : Fin 26220 => (decoded.piop.rowScalars coordinate index).val) partials)
      block head).trans ?_)
  apply congrArg (RF.emittedColumns (E.points opening coordinate)
    (fun index : Fin 26220 => (decoded.piop.rowScalars coordinate index).val) partials)
  apply Fin.ext
  change block.val * 13115 + head.val = head.val + 13115 * block.val
  omega

end
end HegemonCrypto.SmallWood.NativePrivateSpendQ58CurrentScalarStageReadback
