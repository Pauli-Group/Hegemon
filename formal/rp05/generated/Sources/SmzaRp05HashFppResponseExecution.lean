import SmzaRp05HashFppPostMerkleExecution
import SmzaRp05AcceptedRecordLvcsRows
import SmzaRp05AcceptedRecordFinalHash

/-!
# Successful hash-Fpp middle exposes response-program execution

Decompose one successful `hashFppMiddleProgram` evaluation. The predecessor,
field points, DECS hash program, and digest all belong to that same oracle run.
No accepted-checks premise or caller-supplied restored response is used.
-/

namespace HegemonCrypto.SmallWood.SmzaRp05HashFppResponseExecution

open SmzaRp05ExecutableMerkleVerifier (Program Oracle)
open SmzaRp05LeafNamespace (Namespace)
open SmzaRp05ExecutableChallengeStage (FieldWord PostMerkle)
open SmzaRp05PcsWireProjection (DecodedMiddleWire)
open SmzaRp05DecsResponseProjection (DecodedDecsResponseFields)
open SmzaRp05CurrentProofWireProgram (ExistingProofFieldView)
open SmzaRp05RelationRefinement (RelationDsl)
open HegemonCrypto.CanonicalBytes
open V8SmzaOracleParser (RawDigest)

set_option autoImplicit false

/-- Forming the response hash program forces the source-shaped restoration
function to return polynomials. This consequence uses only the projection's
Option definitions; the polynomial list is not a premise. -/
theorem selected_hash_program_implies_response_restoration
    (hashMt : RawDigest) (decsFields : DecodedDecsResponseFields)
    (lvcsRows gamma : List (List FieldWord)) (evalPoints : List FieldWord)
    (rowCount highCount : Nat) (statementBinding : List Nat)
    (hashProgram : Program RawDigest)
    (selected : SmzaRp05DecsResponseProjection.hashFppProgram hashMt
      decsFields lvcsRows gamma evalPoints rowCount highCount statementBinding =
        some hashProgram) :
    ∃ polynomials pcsWords,
      SmzaRp05DecsResponseProjection.restoredResponsePolynomials decsFields
        lvcsRows gamma evalPoints rowCount highCount = some polynomials ∧
      SmzaRp05DecsResponseProjection.responseTranscriptWords hashMt decsFields
        lvcsRows gamma evalPoints rowCount highCount = some pcsWords := by
  cases wordsEq : SmzaRp05DecsResponseProjection.responseTranscriptWords
      hashMt decsFields lvcsRows gamma evalPoints rowCount highCount with
  | none =>
      simp [SmzaRp05DecsResponseProjection.hashFppProgram, wordsEq] at selected
  | some pcsWords =>
      unfold SmzaRp05DecsResponseProjection.responseTranscriptWords at wordsEq
      cases restoredEq :
          SmzaRp05DecsResponseProjection.restoredResponsePolynomials decsFields
            lvcsRows gamma evalPoints rowCount highCount with
      | none => simp [restoredEq] at wordsEq
      | some polynomials =>
          exact ⟨polynomials, pcsWords, rfl, rfl⟩

/-- A successful middle evaluation includes a successful evaluation of the
response hash program selected from the very rows and Merkle result produced
by its predecessor. -/
theorem middle_success_exposes_hash_program
    (ns : Namespace) (pending : Bool) (hPiop : RawDigest)
    (wire : DecodedMiddleWire) (decsFields : DecodedDecsResponseFields)
    (evalPoints : List Goldilocks) (packingFactor : Nat)
    (widths deltas : List Nat) (beta lvcsCols tailCount totalRows : Nat)
    (salt binding : List Byte) (statementBinding : List Nat)
    (tapes : List (List Byte)) (paths : List (List RawDigest))
    (oracle : Oracle) (middle : Program (RawDigest × Bool))
    (hashFpp : RawDigest) (middlePending : Bool)
    (selected : SmzaRp05PcsHashFppMiddle.hashFppMiddleProgram ns pending
      hPiop wire decsFields evalPoints packingFactor widths deltas beta
      lvcsCols tailCount totalRows salt binding statementBinding tapes paths =
        some middle)
    (executed : middle.eval oracle = some (hashFpp, middlePending)) :
    ∃ earlier indexes rows post points hashProgram polynomials,
      SmzaRp05PcsMerklePayload.postMerkleWithRowsProgram ns pending hPiop
        wire evalPoints packingFactor widths deltas beta lvcsCols tailCount
        totalRows salt binding decsFields.maskingEvals tapes paths =
          some earlier ∧
      earlier.eval oracle = some (indexes, rows, post) ∧
      SmzaRp05DecsPointProjection.fieldPoints (lvcsCols + tailCount) indexes =
        some points ∧
      SmzaRp05DecsResponseProjection.hashFppProgram post.root decsFields
        (rows.map fun row => row.map SmzaRp05ExecutableRestore.toWord)
        (SmzaRp05PcsHashFppMiddle.gammaRows post)
        (points.map SmzaRp05ExecutableRestore.toWord) totalRows lvcsCols
        statementBinding = some hashProgram ∧
      hashProgram.eval oracle = some hashFpp ∧
      SmzaRp05DecsResponseProjection.restoredResponsePolynomials decsFields
        (rows.map fun row => row.map SmzaRp05ExecutableRestore.toWord)
        (SmzaRp05PcsHashFppMiddle.gammaRows post)
        (points.map SmzaRp05ExecutableRestore.toWord) totalRows lvcsCols =
          some polynomials ∧
      middlePending = post.pending := by
  cases hEarlier : SmzaRp05PcsMerklePayload.postMerkleWithRowsProgram ns pending
      hPiop wire evalPoints packingFactor widths deltas beta lvcsCols tailCount
      totalRows salt binding decsFields.maskingEvals tapes paths with
  | none =>
      simp [SmzaRp05PcsHashFppMiddle.hashFppMiddleProgram, hEarlier] at selected
  | some earlier =>
      simp [SmzaRp05PcsHashFppMiddle.hashFppMiddleProgram, hEarlier] at selected
      subst middle
      obtain ⟨triple, earlierSuccess, continuationSuccess⟩ :=
        SmzaRp05HashFppPostMerkleExecution.program_bind_success oracle earlier
          (fun (indexes, rows, post) =>
            match SmzaRp05DecsPointProjection.fieldPoints
                (lvcsCols + tailCount) indexes with
            | none => Program.done none
            | some points =>
                let rowsAsWords := rows.map fun row =>
                  row.map SmzaRp05ExecutableRestore.toWord
                let pointWords := points.map SmzaRp05ExecutableRestore.toWord
                match SmzaRp05DecsResponseProjection.hashFppProgram post.root
                    decsFields rowsAsWords
                    (SmzaRp05PcsHashFppMiddle.gammaRows post) pointWords
                    totalRows lvcsCols statementBinding with
                | none => Program.done none
                | some hashProgram => hashProgram.bind fun digest =>
                    Program.done (some (digest, post.pending)))
          (hashFpp, middlePending) executed
      rcases triple with ⟨indexes, rows, post⟩
      cases hPoints : SmzaRp05DecsPointProjection.fieldPoints
          (lvcsCols + tailCount) indexes with
      | none =>
          simp [Program.eval, hPoints] at continuationSuccess
      | some points =>
          let rowsAsWords := rows.map fun row =>
            row.map SmzaRp05ExecutableRestore.toWord
          let pointWords := points.map SmzaRp05ExecutableRestore.toWord
          cases hHash : SmzaRp05DecsResponseProjection.hashFppProgram post.root
              decsFields rowsAsWords
              (SmzaRp05PcsHashFppMiddle.gammaRows post) pointWords
              totalRows lvcsCols statementBinding with
          | none =>
              simp [Program.eval, hPoints, rowsAsWords, pointWords, hHash]
                at continuationSuccess
          | some hashProgram =>
              have hashBranchSuccess :
                  (hashProgram.bind fun digest =>
                    Program.done (some (digest, post.pending))).eval oracle =
                      some (hashFpp, middlePending) := by
                simpa [Program.eval, hPoints, rowsAsWords, pointWords, hHash] using
                  continuationSuccess
              obtain ⟨digest, hashSuccess, finishSuccess⟩ :=
                SmzaRp05HashFppPostMerkleExecution.program_bind_success oracle
                  hashProgram
                  (fun digest => Program.done (some (digest, post.pending)))
                  (hashFpp, middlePending) hashBranchSuccess
              have digestAndPending : (digest, post.pending) =
                  (hashFpp, middlePending) := by
                change some (digest, post.pending) =
                  some (hashFpp, middlePending) at finishSuccess
                exact Option.some.inj finishSuccess
              have digestEq : digest = hashFpp := congrArg Prod.fst digestAndPending
              have pendingEq : post.pending = middlePending :=
                congrArg Prod.snd digestAndPending
              obtain ⟨polynomials, _pcsWords, restored, _transcriptWords⟩ :=
                selected_hash_program_implies_response_restoration post.root
                  decsFields
                  (rows.map fun row => row.map
                    SmzaRp05ExecutableRestore.toWord)
                  (SmzaRp05PcsHashFppMiddle.gammaRows post)
                  (points.map SmzaRp05ExecutableRestore.toWord) totalRows
                  lvcsCols statementBinding hashProgram hHash
              subst digest
              exact ⟨earlier, indexes, rows, post, points, hashProgram,
                polynomials, rfl, earlierSuccess,
                hPoints, hHash, hashSuccess, restored, pendingEq.symm⟩

/-- An accepted current proof-field record reaches response restoration and
the final `hashFpp` query through the exact middle program selected by its
ordinary final execution. The response polynomials are consequences of the
selected hash-program definition, not additional accepted-record inputs.
-/
theorem accepted_record_exposes_response_restoration
    (ns : Namespace) (dsl : RelationDsl)
    (statement : SmzaRp05StatementNamespace.Statement)
    (pending : Bool) (packingFactor : Nat) (widths deltas : List Nat)
    (beta lvcsCols tailCount totalRows : Nat) (binding : List Byte)
    (statementBinding : List Nat) (wire : ExistingProofFieldView)
    (oracle : Oracle) (log : List (V8SmzaOracleParser.RawInput × RawDigest))
    (accepted : (SmzaRp05CurrentProofWireProgram.currentProofFieldProgram ns dsl
      statement pending packingFactor widths deltas beta lvcsCols tailCount
      totalRows binding statementBinding wire).record oracle = (some (), log)) :
    ∃ middle decs piop opening final middleProgram hashFpp middlePending
        earlier indexes, ∃ (rows : List (List Goldilocks)),
      ∃ post decsPoints responseProgram polynomials,
      SmzaRp05CurrentProofWireProgram.decodeExistingProofFieldView wire =
        some (middle, decs, piop) ∧
      (SmzaRp05CurrentOpeningProgram.chooseOpeningProgram wire.hPiop).eval
        oracle = some opening ∧
      SmzaRp05PcsToFinalProgram.finalFromMiddleProgram ns dsl statement opening
        pending wire.hPiop middle.pcs decs piop packingFactor widths deltas
        beta lvcsCols tailCount totalRows wire.salt binding statementBinding
        wire.tapes wire.paths = some final ∧
      final.eval oracle = some () ∧
      SmzaRp05PcsHashFppMiddle.hashFppMiddleProgram ns pending wire.hPiop
        (SmzaRp05PcsToFinalProgram.sameProofRows middle.pcs piop) decs
        (List.ofFn fun j : Fin 6 =>
          HegemonCrypto.SmallWood.V8Smz9PiopReconstruction.points opening j)
        packingFactor widths deltas beta lvcsCols tailCount totalRows wire.salt
        binding statementBinding wire.tapes wire.paths = some middleProgram ∧
      middleProgram.eval oracle = some (hashFpp, middlePending) ∧
      SmzaRp05PcsMerklePayload.postMerkleWithRowsProgram ns pending wire.hPiop
        (SmzaRp05PcsToFinalProgram.sameProofRows middle.pcs piop)
        (List.ofFn fun j : Fin 6 =>
          HegemonCrypto.SmallWood.V8Smz9PiopReconstruction.points opening j)
        packingFactor widths deltas beta lvcsCols tailCount totalRows wire.salt
        binding decs.maskingEvals wire.tapes wire.paths = some earlier ∧
      earlier.eval oracle = some (indexes, rows, post) ∧
      SmzaRp05DecsPointProjection.fieldPoints (lvcsCols + tailCount) indexes =
        some decsPoints ∧
      SmzaRp05DecsResponseProjection.hashFppProgram post.root decs
        (rows.map fun row => row.map SmzaRp05ExecutableRestore.toWord)
        (SmzaRp05PcsHashFppMiddle.gammaRows post)
        (decsPoints.map SmzaRp05ExecutableRestore.toWord) totalRows lvcsCols
        statementBinding = some responseProgram ∧
      responseProgram.eval oracle = some hashFpp ∧
      SmzaRp05DecsResponseProjection.restoredResponsePolynomials decs
        (rows.map fun row => row.map SmzaRp05ExecutableRestore.toWord)
        (SmzaRp05PcsHashFppMiddle.gammaRows post)
        (decsPoints.map SmzaRp05ExecutableRestore.toWord) totalRows lvcsCols =
          some polynomials := by
  obtain ⟨middle, decs, piop, opening, final, _indexes, _sampledPoints,
      _sampledRows, _sampler, decoded, openingSelected, finalSelected,
      finalExecuted, _samplerSelected, _samplerExecuted, _reconstruction⟩ :=
    SmzaRp05AcceptedRecordLvcsRows.accepted_record_exposes_selected_lvcs_rows
      ns dsl statement pending packingFactor widths deltas beta lvcsCols
      tailCount totalRows binding statementBinding wire oracle log accepted
  obtain ⟨middleProgram, hashFpp, middlePending, _matrix, _finalPending,
      middleSelected, middleExecuted, _matrixExecuted, _clean, _same,
      _afterInLog⟩ :=
    SmzaRp05AcceptedRecordFinalHash.final_success_exposes_final_hash ns dsl
      statement opening pending wire.hPiop middle.pcs decs piop packingFactor
      widths deltas beta lvcsCols tailCount totalRows wire.salt binding
      statementBinding wire.tapes wire.paths oracle final finalSelected
      finalExecuted
  let evalPoints : List Goldilocks := List.ofFn fun j : Fin 6 =>
    HegemonCrypto.SmallWood.V8Smz9PiopReconstruction.points opening j
  obtain ⟨earlier, indexes, rows, post, decsPoints, responseProgram,
      polynomials, earlierSelected, earlierExecuted, pointsSelected,
      hashSelected, hashExecuted, restored, _pendingSame⟩ :=
    middle_success_exposes_hash_program ns pending wire.hPiop
      (SmzaRp05PcsToFinalProgram.sameProofRows middle.pcs piop) decs evalPoints
      packingFactor widths deltas beta lvcsCols tailCount totalRows wire.salt
      binding statementBinding wire.tapes wire.paths oracle middleProgram
      hashFpp middlePending middleSelected middleExecuted
  exact ⟨middle, decs, piop, opening, final, middleProgram, hashFpp,
    middlePending, earlier, indexes, rows, post, decsPoints, responseProgram,
    polynomials, decoded, openingSelected, finalSelected,
    finalExecuted, by simpa [evalPoints] using middleSelected,
    by simpa using middleExecuted,
    by simpa [evalPoints] using earlierSelected, earlierExecuted,
    pointsSelected, hashSelected, hashExecuted, restored⟩

end HegemonCrypto.SmallWood.SmzaRp05HashFppResponseExecution
