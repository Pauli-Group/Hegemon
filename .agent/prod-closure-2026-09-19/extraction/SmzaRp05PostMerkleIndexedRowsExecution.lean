import SmzaRp05PcsMerklePayload

/-!
# Successful PCS/Merkle execution exposes its exact indexed LVCS predecessor

The ordinary `postMerkleWithRowsProgram` bind retains the indexes and rows
returned by `indexedRowsProgram`. Successful Merkle execution therefore
exposes successful evaluation of that exact program on the same decoded wire
and verifier parameters.
-/

namespace HegemonCrypto.SmallWood.SmzaRp05PostMerkleIndexedRowsExecution

open SmzaRp05ExecutableMerkleVerifier (Program Oracle Input)
open SmzaRp05LeafNamespace (Namespace)
open SmzaRp05ExecutableChallengeStage (PostMerkle)
open SmzaRp05PcsWireProjection (DecodedMiddleWire FieldMatrix)
open HegemonCrypto.CanonicalBytes
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

/-- A successful authenticated PCS/Merkle predecessor has successfully
evaluated the exact `indexedRowsProgram`; its sampled indexes and LVCS rows
are the ones consumed by the existing Merkle input builder. -/
theorem postMerkle_success_has_indexedRows_execution
    (ns : Namespace) (pending : Bool) (hPiop : RawDigest)
    (wire : DecodedMiddleWire) (evalPoints : List Goldilocks)
    (packingFactor : Nat) (widths deltas : List Nat)
    (beta lvcsCols tailCount totalRows : Nat) (salt binding : List Byte)
    (masks : FieldMatrix) (tapes : List (List Byte))
    (paths : List (List RawDigest)) (oracle : Oracle)
    (postProgram : Program (List Nat × List (List Goldilocks) × PostMerkle))
    (indexes : List Nat) (rows : List (List Goldilocks)) (post : PostMerkle)
    (selected : SmzaRp05PcsMerklePayload.postMerkleWithRowsProgram ns pending
      hPiop wire evalPoints packingFactor widths deltas beta lvcsCols tailCount
      totalRows salt binding masks tapes paths = some postProgram)
    (executed : postProgram.eval oracle = some (indexes, rows, post)) :
    ∃ indexedProgram,
      SmzaRp05PcsLvcsMiddle.indexedRowsProgram pending hPiop wire evalPoints
        packingFactor widths deltas beta lvcsCols tailCount totalRows =
        some indexedProgram ∧
      indexedProgram.eval oracle = some (indexes, rows) := by
  cases hindexed : (SmzaRp05PcsLvcsMiddle.indexedRowsProgram pending hPiop wire
      evalPoints packingFactor widths deltas beta lvcsCols tailCount totalRows) with
  | none =>
      simp [SmzaRp05PcsMerklePayload.postMerkleWithRowsProgram, hindexed] at selected
  | some indexedProgram =>
      simp [SmzaRp05PcsMerklePayload.postMerkleWithRowsProgram, hindexed] at selected
      subst postProgram
      obtain ⟨sampled, indexedSuccess, continuationSuccess⟩ :=
        program_bind_success oracle indexedProgram
          (fun (sampledIndexes, sampledRows) =>
            match SmzaRp05PcsMerklePayload.makeMerkleInput salt binding pending
                sampledIndexes sampledRows masks tapes paths with
            | none => Program.done none
            | some input =>
                (SmzaRp05ExecutableChallengeStage.postMerkleProgram ns input).bind
                  fun sampledPost =>
                    Program.done (some (sampledIndexes, sampledRows, sampledPost)))
          (indexes, rows, post) executed
      have sampledEq : sampled = (indexes, rows) := by
        rcases sampled with ⟨sampledIndexes, sampledRows⟩
        cases hinput : SmzaRp05PcsMerklePayload.makeMerkleInput salt binding
            pending sampledIndexes sampledRows masks tapes paths with
        | none => simp [hinput, Program.eval] at continuationSuccess
        | some input =>
            simp only [hinput] at continuationSuccess
            rw [Program.eval_bind] at continuationSuccess
            cases hpost :
                (SmzaRp05ExecutableChallengeStage.postMerkleProgram ns input).eval
                  oracle with
            | none => simp [hpost] at continuationSuccess
            | some sampledPost =>
                simp only [hpost, Option.bind_some, Program.eval]
                  at continuationSuccess
                have tripleEq := Option.some.inj continuationSuccess
                have indexesEq : sampledIndexes = indexes :=
                  congrArg Prod.fst tripleEq
                have rowsEq : sampledRows = rows :=
                  congrArg Prod.fst (congrArg Prod.snd tripleEq)
                exact Prod.ext indexesEq rowsEq
      rw [sampledEq] at indexedSuccess
      exact ⟨indexedProgram, rfl, indexedSuccess⟩

end HegemonCrypto.SmallWood.SmzaRp05PostMerkleIndexedRowsExecution
