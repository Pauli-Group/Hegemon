import SmzaRp05PcsToFinalProgram

/-!
# First execution boundary of the accepted PCS-to-final program

This small decomposition exposes the successful execution of the exact
hash-Fpp middle program selected by `finalFromMiddleProgram`. It does not yet
expose the indexed LVCS rows; that requires one further decomposition through
`hashFppMiddleProgram` and `postMerkleWithRowsProgram`.
-/

namespace HegemonCrypto.SmallWood.SmzaRp05FinalProgramMiddleExecution

open SmzaRp05ExecutableMerkleVerifier (Program Oracle)
open SmzaRp05LeafNamespace (Namespace)
open SmzaRp05PcsWireProjection (DecodedPcsFields)
open SmzaRp05DecsResponseProjection (DecodedDecsResponseFields)
open SmzaRp05RelationRefinement (RelationDsl)
open HegemonCrypto.CanonicalBytes
open V8Smz9PiopSoundness (Opening)
open V8SmzaOracleParser (RawDigest)

set_option autoImplicit false

theorem program_bind_success {α β : Type} (oracle : Oracle)
    (program : Program α) (next : α → Program β) (result : β)
    (success : (program.bind next).eval oracle = some result) :
    ∃ value, program.eval oracle = some value ∧
      (next value).eval oracle = some result := by
  rw [Program.eval_bind oracle program next] at success
  cases selected : program.eval oracle with
  | none => simp [selected] at success
  | some value =>
      simp only [selected, Option.bind_some] at success
      exact ⟨value, rfl, success⟩

/-- Successful execution of the selected ordinary final program implies that
the exact hash-Fpp middle program selected by its constructor ran successfully.
No reconstructed rows or intermediate transcript values are premises. -/
theorem final_success_has_middle_execution
    (ns : Namespace) (dsl : RelationDsl)
    (statement : SmzaRp05StatementNamespace.Statement)
    (opening : Opening) (pending : Bool) (hPiop : RawDigest)
    (pcs : DecodedPcsFields) (decs : DecodedDecsResponseFields)
    (piop : SmzaRp05ExecutableReconstruction.DecodedPiopFields)
    (packingFactor : Nat) (widths deltas : List Nat)
    (beta lvcsCols tailCount totalRows : Nat) (salt binding : List Byte)
    (statementBinding : List Nat) (tapes : List (List Byte))
    (paths : List (List RawDigest)) (oracle : Oracle) (final : Program Unit)
    (selected : SmzaRp05PcsToFinalProgram.finalFromMiddleProgram ns dsl
      statement opening pending hPiop pcs decs piop packingFactor widths deltas
      beta lvcsCols tailCount totalRows salt binding statementBinding tapes paths =
        some final)
    (executed : final.eval oracle = some ()) :
    ∃ hashFpp middlePending middle,
      SmzaRp05PcsHashFppMiddle.hashFppMiddleProgram ns pending hPiop
        (SmzaRp05PcsToFinalProgram.sameProofRows pcs piop) (decs)
        (List.ofFn fun j : Fin 6 =>
          HegemonCrypto.SmallWood.V8Smz9PiopReconstruction.points opening j)
        packingFactor widths deltas beta lvcsCols tailCount totalRows salt
        binding statementBinding tapes paths = some middle ∧
      middle.eval oracle = some (hashFpp, middlePending) := by
  let evalPoints : List Goldilocks :=
    List.ofFn fun j : Fin 6 =>
      HegemonCrypto.SmallWood.V8Smz9PiopReconstruction.points opening j
  let next := fun pair : RawDigest × Bool =>
    (SmzaRp05PiopMatrixStage.matrixProgram (dsl.width statement) pair.2 pair.1).bind
      fun (matrix, finalPending) =>
        SmzaRp05ExecutableFinalVerifier.finalize hPiop
          (SmzaRp05ExecutableReconstruction.reconstruct dsl statement matrix
            opening piop pair.1 finalPending)
  have selectedMiddle :
      ∃ middle,
        SmzaRp05PcsHashFppMiddle.hashFppMiddleProgram ns pending hPiop
          (SmzaRp05PcsToFinalProgram.sameProofRows pcs piop) decs evalPoints
          packingFactor widths deltas beta lvcsCols tailCount totalRows salt
          binding statementBinding tapes paths = some middle ∧
        (middle.bind next) = final := by
    have selected' :
        (SmzaRp05PcsHashFppMiddle.hashFppMiddleProgram ns pending hPiop
          (SmzaRp05PcsToFinalProgram.sameProofRows pcs piop) decs evalPoints
          packingFactor widths deltas beta lvcsCols tailCount totalRows salt
          binding statementBinding tapes paths).bind
          (fun middle => some (middle.bind next)) = some final := by
      simpa [evalPoints, SmzaRp05PcsToFinalProgram.finalFromMiddleProgram]
        using selected
    cases hmiddle : SmzaRp05PcsHashFppMiddle.hashFppMiddleProgram ns pending
        hPiop (SmzaRp05PcsToFinalProgram.sameProofRows pcs piop) decs evalPoints
        packingFactor widths deltas beta lvcsCols tailCount totalRows salt
        binding statementBinding tapes paths with
    | none => simp [hmiddle] at selected'
    | some middle =>
        have finalEq : middle.bind next = final := by
          simpa [hmiddle] using selected'
        exact ⟨middle, rfl, finalEq⟩
  rcases selectedMiddle with ⟨middle, middleSelected, finalEq⟩
  subst final
  obtain ⟨pair, middleSuccess, _⟩ :=
    program_bind_success oracle middle next () executed
  exact ⟨pair.1, pair.2, middle, middleSelected, middleSuccess⟩

end HegemonCrypto.SmallWood.SmzaRp05FinalProgramMiddleExecution
