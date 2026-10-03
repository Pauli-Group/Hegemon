import SmzaRp05AcceptedRecordLvcsRows
import SmzaRp05FinalProgramMiddleExecution
import SmzaRp05ExecutableMerklePaths

/-!
# Accepted current proof to its actual final hash comparison

This decomposes the successful selected final program through the PCS hash,
PIoP matrix sampler, and final digest gate. The resulting matrix and digest
input are outputs of that same execution, not caller-supplied values.
-/

namespace HegemonCrypto.SmallWood.SmzaRp05AcceptedRecordFinalHash

open SmzaRp05ExecutableMerkleVerifier (Program Oracle)
open SmzaRp05CurrentProofWireProgram (ExistingProofFieldView)
open SmzaRp05LeafNamespace (Namespace)
open SmzaRp05PcsWireProjection (DecodedPcsFields)
open SmzaRp05DecsResponseProjection (DecodedDecsResponseFields)
open SmzaRp05RelationRefinement (RelationDsl)
open HegemonCrypto.CanonicalBytes
open V8Smz9PiopSoundness (Opening)
open V8SmzaOracleParser (RawDigest)

set_option autoImplicit false

/-- Successful execution of the selected current final program fixes the
derived batching matrix, gives the actual final hash equality, and retains
that AFTER query in this deterministic program's own record. -/
theorem final_success_exposes_final_hash
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
    ∃ middle hashFpp middlePending matrix finalPending,
      SmzaRp05PcsHashFppMiddle.hashFppMiddleProgram ns pending hPiop
        (SmzaRp05PcsToFinalProgram.sameProofRows pcs piop) decs
        (List.ofFn fun j : Fin 6 =>
          HegemonCrypto.SmallWood.V8Smz9PiopReconstruction.points opening j)
        packingFactor widths deltas beta lvcsCols tailCount totalRows salt
        binding statementBinding tapes paths = some middle ∧
      middle.eval oracle = some (hashFpp, middlePending) ∧
      (SmzaRp05PiopMatrixStage.matrixProgram (dsl.width statement)
        middlePending hashFpp).eval oracle = some (matrix, finalPending) ∧
      finalPending = false ∧
      oracle (SmzaRp05ExecutableFinalVerifier.finalInput
        (SmzaRp05ExecutableReconstruction.reconstruct dsl statement matrix
          opening piop hashFpp finalPending)) = hPiop ∧
      (SmzaRp05ExecutableFinalVerifier.finalInput
        (SmzaRp05ExecutableReconstruction.reconstruct dsl statement matrix
          opening piop hashFpp finalPending), hPiop) ∈
        (final.record oracle).2 := by
  let evalPoints : List Goldilocks :=
    List.ofFn fun j : Fin 6 =>
      HegemonCrypto.SmallWood.V8Smz9PiopReconstruction.points opening j
  let next := fun pair : RawDigest × Bool =>
    (SmzaRp05PiopMatrixStage.matrixProgram (dsl.width statement) pair.2
      pair.1).bind fun (matrix, finalPending) =>
        SmzaRp05ExecutableFinalVerifier.finalize hPiop
          (SmzaRp05ExecutableReconstruction.reconstruct dsl statement matrix
            opening piop pair.1 finalPending)
  have selected' :
      (SmzaRp05PcsHashFppMiddle.hashFppMiddleProgram ns pending hPiop
        (SmzaRp05PcsToFinalProgram.sameProofRows pcs piop) decs evalPoints
        packingFactor widths deltas beta lvcsCols tailCount totalRows salt
        binding statementBinding tapes paths).bind
          (fun middle => some (middle.bind next)) = some final := by
    simpa [evalPoints, next, SmzaRp05PcsToFinalProgram.finalFromMiddleProgram]
      using selected
  cases hmiddle : SmzaRp05PcsHashFppMiddle.hashFppMiddleProgram ns pending
      hPiop (SmzaRp05PcsToFinalProgram.sameProofRows pcs piop) decs evalPoints
      packingFactor widths deltas beta lvcsCols tailCount totalRows salt
      binding statementBinding tapes paths with
  | none => simp [hmiddle] at selected'
  | some middle =>
      have finalEq : middle.bind next = final := by
        simpa [hmiddle] using selected'
      subst final
      obtain ⟨pair, middleSuccess, suffixSuccess⟩ :=
        SmzaRp05FinalProgramMiddleExecution.program_bind_success
          oracle middle next () executed
      rcases pair with ⟨hashFpp, middlePending⟩
      obtain ⟨matrixPair, matrixSuccess, finalSuccess⟩ :=
        SmzaRp05FinalProgramMiddleExecution.program_bind_success oracle
          (SmzaRp05PiopMatrixStage.matrixProgram (dsl.width statement)
            middlePending hashFpp)
          (fun pair =>
            SmzaRp05ExecutableFinalVerifier.finalize hPiop
              (SmzaRp05ExecutableReconstruction.reconstruct dsl statement
                pair.1 opening piop hashFpp pair.2)) () suffixSuccess
      rcases matrixPair with ⟨matrix, finalPending⟩
      obtain ⟨clean, same, afterInFinalize⟩ :=
        SmzaRp05ExecutableFinalVerifier.accepted_final_query oracle hPiop
          (SmzaRp05ExecutableReconstruction.reconstruct dsl statement matrix
            opening piop hashFpp finalPending) finalSuccess
      have afterInMatrix :
          (SmzaRp05ExecutableFinalVerifier.finalInput
            (SmzaRp05ExecutableReconstruction.reconstruct dsl statement matrix
              opening piop hashFpp finalPending), hPiop) ∈
            (((SmzaRp05PiopMatrixStage.matrixProgram (dsl.width statement)
                middlePending hashFpp).bind fun (matrix, finalPending) =>
              SmzaRp05ExecutableFinalVerifier.finalize hPiop
                (SmzaRp05ExecutableReconstruction.reconstruct dsl statement
                  matrix opening piop hashFpp finalPending)).record oracle).2 := by
        exact Program.bind_log_right oracle
          (SmzaRp05PiopMatrixStage.matrixProgram (dsl.width statement)
            middlePending hashFpp)
          (fun pair =>
            SmzaRp05ExecutableFinalVerifier.finalize hPiop
              (SmzaRp05ExecutableReconstruction.reconstruct dsl statement
                pair.1 opening piop hashFpp pair.2))
          (matrix, finalPending) matrixSuccess afterInFinalize
      have afterInMiddle :
          (SmzaRp05ExecutableFinalVerifier.finalInput
            (SmzaRp05ExecutableReconstruction.reconstruct dsl statement matrix
              opening piop hashFpp finalPending), hPiop) ∈
            ((middle.bind next).record oracle).2 :=
        Program.bind_log_right oracle middle next (hashFpp, middlePending)
          middleSuccess afterInMatrix
      exact ⟨middle, hashFpp, middlePending, matrix, finalPending,
        rfl, middleSuccess, matrixSuccess, clean, same, afterInMiddle⟩

/-- The final digest equality comes from the same accepted ordinary record
and its selected opening. Neither the matrix nor reconstructed transcript is
an input to this theorem. -/
theorem accepted_record_exposes_final_hash
    (ns : Namespace) (dsl : RelationDsl)
    (statement : SmzaRp05StatementNamespace.Statement)
    (pending : Bool) (packingFactor : Nat) (widths deltas : List Nat)
    (beta lvcsCols tailCount totalRows : Nat) (binding : List Byte)
    (statementBinding : List Nat) (wire : ExistingProofFieldView)
    (oracle : Oracle) (log : List (V8SmzaOracleParser.RawInput × RawDigest))
    (accepted : (SmzaRp05CurrentProofWireProgram.currentProofFieldProgram ns dsl
      statement pending packingFactor widths deltas beta lvcsCols tailCount
      totalRows binding statementBinding wire).record oracle = (some (), log)) :
    ∃ middle decs piop opening hashFpp middlePending matrix finalPending,
      SmzaRp05CurrentProofWireProgram.decodeExistingProofFieldView wire =
        some (middle, decs, piop) ∧
      (SmzaRp05CurrentOpeningProgram.chooseOpeningProgram wire.hPiop).eval
        oracle = some opening ∧
      (SmzaRp05PiopMatrixStage.matrixProgram (dsl.width statement)
        middlePending hashFpp).eval oracle = some (matrix, finalPending) ∧
      finalPending = false ∧
      oracle (SmzaRp05ExecutableFinalVerifier.finalInput
        (SmzaRp05ExecutableReconstruction.reconstruct dsl statement matrix
          opening piop hashFpp finalPending)) = wire.hPiop ∧
      (SmzaRp05ExecutableFinalVerifier.finalInput
        (SmzaRp05ExecutableReconstruction.reconstruct dsl statement matrix
          opening piop hashFpp finalPending), wire.hPiop) ∈ log := by
  obtain ⟨middle, decs, piop, opening, final, indexes, points, rows, sampler,
      decoded, openingSelected, finalSelected, finalExecuted,
      samplerSelected, samplerExecuted, reconstruction⟩ :=
    SmzaRp05AcceptedRecordLvcsRows.accepted_record_exposes_selected_lvcs_rows
      ns dsl statement pending packingFactor widths deltas beta lvcsCols
      tailCount totalRows binding statementBinding wire oracle log accepted
  obtain ⟨middleProgram, hashFpp, middlePending, matrix, finalPending,
      middleSelected, middleExecuted, matrixExecuted, clean, same,
      afterInFinal⟩ :=
    final_success_exposes_final_hash ns dsl statement opening pending wire.hPiop
      middle.pcs decs piop packingFactor widths deltas beta lvcsCols tailCount
      totalRows wire.salt binding statementBinding wire.tapes wire.paths oracle
      final finalSelected finalExecuted
  let afterCall := (SmzaRp05ExecutableFinalVerifier.finalInput
    (SmzaRp05ExecutableReconstruction.reconstruct dsl statement matrix
      opening piop hashFpp finalPending), wire.hPiop)
  have afterInSelectedBranch :
      afterCall ∈
        ((match SmzaRp05PcsToFinalProgram.finalFromMiddleProgram ns dsl
            statement opening pending wire.hPiop middle.pcs decs piop
            packingFactor widths deltas beta lvcsCols tailCount totalRows
            wire.salt binding statementBinding wire.tapes wire.paths with
          | none => Program.done none
          | some selectedFinal => selectedFinal).record oracle).2 := by
    simpa [afterCall, finalSelected] using afterInFinal
  have afterInOpeningProgram :
      afterCall ∈
        ((SmzaRp05CurrentOpeningProgram.currentOpeningFinalProgram ns dsl
            statement pending wire.hPiop middle.pcs decs piop packingFactor
            widths deltas beta lvcsCols tailCount totalRows wire.salt binding
            statementBinding wire.tapes wire.paths).record oracle).2 := by
    exact Program.bind_log_right oracle
      (SmzaRp05CurrentOpeningProgram.chooseOpeningProgram wire.hPiop)
      (fun opening =>
        match SmzaRp05PcsToFinalProgram.finalFromMiddleProgram ns dsl
            statement opening pending wire.hPiop middle.pcs decs piop
            packingFactor widths deltas beta lvcsCols tailCount totalRows
            wire.salt binding statementBinding wire.tapes wire.paths with
        | none => Program.done none
        | some selectedFinal => selectedFinal)
      opening openingSelected afterInSelectedBranch
  have outerLogEq :
      ((SmzaRp05CurrentProofWireProgram.currentProofFieldProgram ns dsl
        statement pending packingFactor widths deltas beta lvcsCols tailCount
        totalRows binding statementBinding wire).record oracle).2 = log :=
    congrArg Prod.snd accepted
  have selectedLogEq :
      ((SmzaRp05CurrentOpeningProgram.currentOpeningFinalProgram ns dsl
        statement pending wire.hPiop middle.pcs decs piop packingFactor
        widths deltas beta lvcsCols tailCount totalRows wire.salt binding
        statementBinding wire.tapes wire.paths).record oracle).2 = log := by
    simpa [SmzaRp05CurrentProofWireProgram.currentProofFieldProgram, decoded]
      using outerLogEq
  have afterInLog : afterCall ∈ log := by
    rw [← selectedLogEq]
    exact afterInOpeningProgram
  exact ⟨middle, decs, piop, opening, hashFpp, middlePending, matrix,
    finalPending, decoded, openingSelected, matrixExecuted, clean, same,
    by simpa [afterCall] using afterInLog⟩

end HegemonCrypto.SmallWood.SmzaRp05AcceptedRecordFinalHash
