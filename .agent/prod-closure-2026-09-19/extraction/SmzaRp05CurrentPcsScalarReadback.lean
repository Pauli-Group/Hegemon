import SmzaRp05PcsToFinalProgram

/-! The actual shared PCS/PIOP scalar row equals its 686+5+5 typed view.
No new scalar fields or independent opening values are introduced. -/
namespace HegemonCrypto.SmallWood.SmzaRp05CurrentPcsScalarReadback

open SmzaRp05ExecutableReconstruction (DecodedPiopFields witness masks toField)
open SmzaRp05PcsWireProjection (DecodedPcsFields fieldWordsToGoldilocks)
open V8Smz9EagerSimulator

set_option autoImplicit false

theorem source_scalar_coordinate_is_actual
    (piop : DecodedPiopFields) (opening : Fin 6) (index : Fin 696) :
    sourceRowScalars (witness piop) (masks piop) opening index =
      toField (piop.rowScalars opening index) := by
  by_cases inWitness : index.val < 686
  · let row : Fin 686 := ⟨index.val, inWitness⟩
    have same : index = Fin.castAdd 10 row := by apply Fin.ext; rfl
    rw [same, source_row_scalar_witness_index]
    rfl
  · by_cases inNonlinear : index.val < 691
    · let row : Fin 5 := ⟨index.val - 686, by omega⟩
      have same : index = Fin.natAdd 686 (Fin.castAdd 5 row) := by
        apply Fin.ext
        change index.val = 686 + row.val
        dsimp [row]
        omega
      rw [same, source_row_scalar_nonlinear_index]
      rfl
    · let row : Fin 5 := ⟨index.val - 691, by have := index.isLt; omega⟩
      have same : index = Fin.natAdd 686 (Fin.natAdd 5 row) := by
        apply Fin.ext
        change index.val = 686 + (5 + row.val)
        dsimp [row]
        omega
      rw [same, source_row_scalar_linear_index]
      change toField (piop.rowScalars opening ⟨691 + row.val, by omega⟩) =
        toField (piop.rowScalars opening (Fin.natAdd 686 (Fin.natAdd 5 row)))
      apply congrArg (fun coordinate : Fin 696 => toField (piop.rowScalars opening coordinate))
      apply Fin.ext
      change 691 + row.val = 686 + (5 + row.val)
      omega

theorem same_proof_scalar_row_is_source_row
    (pcs : DecodedPcsFields) (piop : DecodedPiopFields) (opening : Fin 6) :
    fieldWordsToGoldilocks
        ((SmzaRp05PcsToFinalProgram.sameProofRows pcs piop).rowScalars.getD
          opening.val []) =
      List.ofFn (sourceRowScalars (witness piop) (masks piop) opening) := by
  simp only [SmzaRp05PcsToFinalProgram.sameProofRows]
  rw [List.getD_eq_getElem _ _ (by simpa only [List.length_ofFn] using opening.isLt)]
  simp only [List.getElem_ofFn, fieldWordsToGoldilocks, List.map_ofFn]
  apply congrArg List.ofFn
  funext index
  exact (source_scalar_coordinate_is_actual piop opening index).symm

end HegemonCrypto.SmallWood.SmzaRp05CurrentPcsScalarReadback
