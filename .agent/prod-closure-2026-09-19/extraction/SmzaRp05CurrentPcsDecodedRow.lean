import SmzaRp05CurrentPcsActualColumns
import SmzaRp05CurrentPcsPartialLength
import SmzaRp05CurrentPcsPartialReadback
import SmzaRp05CurrentPcsScalarReadback

/-! Successful decoding of an actual shared PCS/PIOP row gives the typed
source reconstruction. Neither row shape nor an independent head certificate
is an input: both are derived from the successful executable row. -/
namespace HegemonCrypto.SmallWood.SmzaRp05CurrentPcsDecodedRow

open SmzaRp05PcsWireProjection
open SmzaRp05PcsToFinalProgram (sameProofRows)
open SmzaRp05ExecutableReconstruction (DecodedPiopFields witness masks)
open SmzaRp05ExecutablePcsClosure (widths deltas)
open SmzaRp05CurrentPcsOpeningView (sourcePcsViewOfDecoded)
open V8Smz9EagerSimulator

set_option autoImplicit false

theorem successful_decoded_row_is_source_columns
    (pcs : DecodedPcsFields) (piop : DecodedPiopFields)
    (points : Fin 6 → Goldilocks) (opening : Fin 6) (row : List Goldilocks)
    (success : reconstructDecodedPcsRow pcs (List.ofFn points)
      (sameProofRows pcs piop).rowScalars opening.val 64 widths deltas = some row) :
    row = List.ofFn (reconstructedColumnEvaluations points (witness piop)
      (masks piop) (sourcePcsViewOfDecoded pcs) opening) := by
  have pointAt : (List.ofFn points)[opening.val]? = some (points opening) := by
    rw [List.getElem?_eq_getElem (by simpa only [List.length_ofFn] using opening.isLt)]
    simp only [List.getElem_ofFn]
  cases scalarAt : (sameProofRows pcs piop).rowScalars[opening.val]? with
  | none => simp only [reconstructDecodedPcsRow, pointAt, scalarAt] at success; cases success
  | some scalars =>
      cases partialAt : pcs.partialEvals[opening.val]? with
      | none =>
          simp only [reconstructDecodedPcsRow, pointAt, scalarAt, partialAt] at success
          cases success
      | some partials =>
          have scalarRead : (sameProofRows pcs piop).rowScalars.getD opening.val [] =
              scalars := by rw [List.getD_eq_getElem?_getD, scalarAt]; rfl
          have partialRead : pcs.partialEvals.getD opening.val [] = partials := by
            rw [List.getD_eq_getElem?_getD, partialAt]; rfl
          have reconstructed : reconstructUnstackedRow (points opening) 64 widths deltas
              (fieldWordsToGoldilocks scalars) (fieldWordsToGoldilocks partials) = some row := by
            simpa only [reconstructDecodedPcsRow, pointAt, scalarAt, partialAt] using success
          have partialLength := SmzaRp05CurrentPcsPartialLength.successful_current_reconstruction_has_forty_partials
              (points opening) _ _ row reconstructed
          have decodedLength : (pcs.partialEvals.getD opening.val []).length = 40 := by
            rw [partialRead]
            simpa only [fieldWordsToGoldilocks, List.length_map] using partialLength
          have scalarSource := SmzaRp05CurrentPcsScalarReadback.same_proof_scalar_row_is_source_row pcs piop opening
          rw [scalarRead] at scalarSource
          have partialSource := SmzaRp05CurrentPcsPartialReadback.source_partial_row_is_decoded_row pcs opening decodedLength
          rw [partialRead] at partialSource
          apply Option.some.inj
          exact reconstructed.symm.trans
            ((congrArg₂ (reconstructUnstackedRow (points opening) 64 widths deltas)
              scalarSource partialSource.symm).trans
              (SmzaRp05CurrentPcsActualColumns.reconstruct_source_columns_row
                points (witness piop) (masks piop) (sourcePcsViewOfDecoded pcs) opening))

end HegemonCrypto.SmallWood.SmzaRp05CurrentPcsDecodedRow
