import SmzaRp05CurrentPcsOpeningView

/-! The typed 35+5 partial-evaluation view is the same decoded 40-word PCS
row. Shape is supplied by successful reconstruction, not by a second row. -/
namespace HegemonCrypto.SmallWood.SmzaRp05CurrentPcsPartialReadback

open SmzaRp05CurrentPcsOpeningView
open SmzaRp05PcsWireProjection (DecodedPcsFields fieldWordsToGoldilocks)
open V8Smz9EagerSimulator (sourcePartialEvaluations)

set_option autoImplicit false

theorem source_partial_coordinate_is_decoded_word
    (pcs : DecodedPcsFields) (opening : Fin 6) (index : Fin 40) :
    sourcePartialEvaluations (sourcePcsViewOfDecoded pcs) opening index =
      (decodedPartialWord pcs opening.val index.val).val := by
  by_cases nonlinear : index.val < 35
  · let polynomial : Fin 5 := ⟨index.val / 7, by omega⟩
    let column : Fin 7 := ⟨index.val % 7, Nat.mod_lt _ (by decide)⟩
    have sameIndex : index = Fin.castAdd 5 (finProdFinEquiv (polynomial, column)) := by
      apply Fin.ext
      change index.val = column.val + 7 * polynomial.val
      dsimp [column, polynomial]
      omega
    have coordinate : 7 * polynomial.val + column.val = index.val := by
      dsimp [column, polynomial]
      omega
    have read := source_partial_nonlinear_readback pcs opening polynomial column
    rw [← sameIndex, coordinate] at read
    exact read
  · let polynomial : Fin 5 := ⟨index.val - 35, by have := index.isLt; omega⟩
    have sameIndex : index = Fin.natAdd 35 polynomial := by
      apply Fin.ext
      change index.val = 35 + polynomial.val
      dsimp [polynomial]
      omega
    have coordinate : 35 + polynomial.val = index.val := by
      dsimp [polynomial]
      omega
    have read := source_partial_linear_readback pcs opening polynomial
    rw [← sameIndex, coordinate] at read
    exact read

theorem source_partial_row_is_decoded_row
    (pcs : DecodedPcsFields) (opening : Fin 6)
    (rowLength : (pcs.partialEvals.getD opening.val []).length = 40) :
    List.ofFn (sourcePartialEvaluations (sourcePcsViewOfDecoded pcs) opening) =
      fieldWordsToGoldilocks (pcs.partialEvals.getD opening.val []) := by
  apply List.ext_getElem (by
    simp only [List.length_ofFn, fieldWordsToGoldilocks, List.length_map]
    exact rowLength.symm)
  intro index leftBound rightBound
  simp only [List.getElem_ofFn, fieldWordsToGoldilocks, List.getElem_map]
  rw [source_partial_coordinate_is_decoded_word]
  unfold decodedPartialWord
  rw [List.getD_eq_getElem _ _ (by simpa only [fieldWordsToGoldilocks,
    List.length_map] using rightBound)]

end HegemonCrypto.SmallWood.SmzaRp05CurrentPcsPartialReadback
