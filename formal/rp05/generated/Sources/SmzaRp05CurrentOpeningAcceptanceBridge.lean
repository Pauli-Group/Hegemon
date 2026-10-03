import SmzaRp05CurrentOpeningProgram

/-!
# Acceptance bridge for the current-profile opening program

The generic lemmas below extract successful values from an ordinary Program
bind and from a match on an Option. The composed PCS/final program remains an
opaque Option value in the final theorem; no reduction of its implementation
is needed.
-/

namespace HegemonCrypto.SmallWood.SmzaRp05CurrentOpeningAcceptanceBridge

open SmzaRp05ExecutableMerkleVerifier (Program Oracle)
open HegemonCrypto.CanonicalBytes

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

theorem option_match_program_success {β : Type} (oracle : Oracle)
    (selected : Option (Program β)) (result : β)
    (success : (match selected with
      | none => Program.done none
      | some program => program).eval oracle = some result) :
    ∃ program, selected = some program ∧ program.eval oracle = some result := by
  cases selected with
  | none => simp [Program.eval] at success
  | some program => exact ⟨program, rfl, success⟩

end HegemonCrypto.SmallWood.SmzaRp05CurrentOpeningAcceptanceBridge

namespace HegemonCrypto.SmallWood.SmzaRp05CurrentOpeningProgram

open SmzaRp05CurrentOpeningAcceptanceBridge
open HegemonCrypto.CanonicalBytes
open SmzaRp05RelationRefinement (RelationDsl)
open SmzaRp05PcsWireProjection (DecodedPcsFields)
open SmzaRp05DecsResponseProjection (DecodedDecsResponseFields)
open V8Smz9PiopSoundness (Opening)
open V8SmzaOracleParser (RawDigest)

set_option autoImplicit false

/-- A successful composed run supplies the opening selected from the same
raw oracle and the final program returned by the opaque middle composition. -/
theorem accepted_has_current_opening (ns : SmzaRp05LeafNamespace.Namespace)
    (dsl : RelationDsl) (statement : SmzaRp05StatementNamespace.Statement)
    (pending : Bool) (hPiop : RawDigest)
    (pcs : DecodedPcsFields) (decs : DecodedDecsResponseFields)
    (piop : SmzaRp05ExecutableReconstruction.DecodedPiopFields)
    (packingFactor : Nat) (widths deltas : List Nat)
    (beta lvcsCols tailCount totalRows : Nat) (salt binding : List Byte)
    (statementBinding : List Nat) (tapes : List (List Byte))
    (paths : List (List RawDigest))
    (oracle : SmzaRp05ExecutableMerkleVerifier.Oracle)
    (accepted : (currentOpeningFinalProgram ns dsl statement pending hPiop
      pcs decs piop packingFactor widths deltas beta lvcsCols tailCount
      totalRows salt binding statementBinding tapes paths).eval oracle = some ()) :
    ∃ opening final,
      (chooseOpeningProgram hPiop).eval oracle = some opening ∧
      SmzaRp05PcsToFinalProgram.finalFromMiddleProgram ns dsl statement opening
        pending hPiop pcs decs piop packingFactor widths deltas beta lvcsCols
        tailCount totalRows salt binding statementBinding tapes paths = some final ∧
      final.eval oracle = some () := by
  have bodySuccess :
      ((chooseOpeningProgram hPiop).bind fun opening =>
        match SmzaRp05PcsToFinalProgram.finalFromMiddleProgram ns dsl statement opening
            pending hPiop pcs decs piop packingFactor widths deltas beta lvcsCols
            tailCount totalRows salt binding statementBinding tapes paths with
        | none => SmzaRp05ExecutableMerkleVerifier.Program.done none
        | some final => final).eval oracle = some () := by
    unfold currentOpeningFinalProgram at accepted
    exact accepted
  obtain ⟨opening, openingSuccess, continuationSuccess⟩ :=
    program_bind_success oracle (chooseOpeningProgram hPiop)
      (fun opening =>
        match SmzaRp05PcsToFinalProgram.finalFromMiddleProgram ns dsl statement opening
            pending hPiop pcs decs piop packingFactor widths deltas beta lvcsCols
            tailCount totalRows salt binding statementBinding tapes paths with
        | none => SmzaRp05ExecutableMerkleVerifier.Program.done none
        | some final => final) () bodySuccess
  generalize candidateEq :
    SmzaRp05PcsToFinalProgram.finalFromMiddleProgram ns dsl statement opening
      pending hPiop pcs decs piop packingFactor widths deltas beta lvcsCols
      tailCount totalRows salt binding statementBinding tapes paths = candidate
      at continuationSuccess
  change (match candidate with
    | none => SmzaRp05ExecutableMerkleVerifier.Program.done none
    | some program => program).eval oracle = some () at continuationSuccess
  cases candidate with
  | none =>
      simp [SmzaRp05ExecutableMerkleVerifier.Program.eval] at continuationSuccess
  | some final =>
      change final.eval oracle = some () at continuationSuccess
      exact ⟨opening, final, openingSuccess, candidateEq, continuationSuccess⟩

end HegemonCrypto.SmallWood.SmzaRp05CurrentOpeningProgram
