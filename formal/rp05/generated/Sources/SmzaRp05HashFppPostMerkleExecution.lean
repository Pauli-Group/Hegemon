import SmzaRp05PcsHashFppMiddle

/-!
# Successful hash-Fpp execution exposes its exact PCS/Merkle predecessor

This boundary follows the ordinary `hashFppMiddleProgram` bind. It recovers
the same `postMerkleWithRowsProgram` and its evaluated indexes, LVCS rows, and
Merkle result. No row data is a caller-supplied witness.
-/

namespace HegemonCrypto.SmallWood.SmzaRp05HashFppPostMerkleExecution

open SmzaRp05ExecutableMerkleVerifier (Program Oracle)
open SmzaRp05LeafNamespace (Namespace)
open SmzaRp05ExecutableChallengeStage (PostMerkle)
open SmzaRp05PcsWireProjection (DecodedMiddleWire)
open SmzaRp05DecsResponseProjection (DecodedDecsResponseFields)
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

/-- Success of `hashFppMiddleProgram` forces the exact prior
`postMerkleWithRowsProgram` to have evaluated successfully, retaining the
same sampled indexes, reconstructed rows, and authenticated Merkle result. -/
theorem hashFpp_success_has_postMerkle_execution
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
    ∃ earlier indexes rows post,
      SmzaRp05PcsMerklePayload.postMerkleWithRowsProgram ns pending hPiop
        wire evalPoints packingFactor widths deltas beta lvcsCols tailCount
        totalRows salt binding decsFields.maskingEvals tapes paths =
      some earlier ∧
      earlier.eval oracle = some (indexes, rows, post) := by
  cases hpost : SmzaRp05PcsMerklePayload.postMerkleWithRowsProgram ns pending
      hPiop wire evalPoints packingFactor widths deltas beta lvcsCols tailCount
      totalRows salt binding decsFields.maskingEvals tapes paths with
  | none =>
      simp [SmzaRp05PcsHashFppMiddle.hashFppMiddleProgram, hpost] at selected
  | some earlier =>
      simp [SmzaRp05PcsHashFppMiddle.hashFppMiddleProgram, hpost] at selected
      subst middle
      obtain ⟨result, earlierSuccess, _⟩ :=
        program_bind_success oracle earlier
          (fun (indexes, rows, post) =>
            match SmzaRp05DecsPointProjection.fieldPoints (lvcsCols + tailCount)
                indexes with
            | none => Program.done none
            | some points =>
                let rowsAsWords :
                    List (List SmzaRp05ExecutableChallengeStage.FieldWord) :=
                  List.map (fun (row : List Goldilocks) =>
                    List.map SmzaRp05ExecutableRestore.toWord row) rows
                let pointWords :
                    List SmzaRp05ExecutableChallengeStage.FieldWord :=
                  List.map SmzaRp05ExecutableRestore.toWord points
                match SmzaRp05DecsResponseProjection.hashFppProgram post.root
                    decsFields rowsAsWords
                    (SmzaRp05PcsHashFppMiddle.gammaRows post) pointWords
                    totalRows lvcsCols statementBinding with
                | none => Program.done none
                | some hashProgram => hashProgram.bind fun digest =>
                    Program.done (some (digest, post.pending)))
          (hashFpp, middlePending) executed
      exact ⟨earlier, result.1, result.2.1, result.2.2, rfl, earlierSuccess⟩

end HegemonCrypto.SmallWood.SmzaRp05HashFppPostMerkleExecution
