import SmzaRp05CurrentProofWireProgram
import SmzaRp05CurrentOpeningAcceptanceBridge

/-!
# Acceptance bridge for the current proof-field program

Successful recorded execution of the field-projection program implies that
the exact existing proof-field view canonically decoded, that the same oracle
selected a current-profile opening, and that the opaque downstream final
program produced by `finalFromMiddleProgram` succeeds on those decoded fields.
No decoded PCS/DECS/PIOP values or opening are caller premises.

This bridge begins at `ExistingProofFieldView`, i.e. the existing fields after
the Rust outer proof parser. It does not claim parsing of serialized proof
bytes, which is not modeled by the imported Lean interfaces.
-/

namespace HegemonCrypto.SmallWood.SmzaRp05CurrentProofFieldAcceptanceBridge

open HegemonCrypto.CanonicalBytes
open SmzaRp05ExecutableMerkleVerifier (Program Oracle)
open SmzaRp05CurrentProofWireProgram
open SmzaRp05CurrentOpeningProgram
open SmzaRp05CurrentOpeningAcceptanceBridge
open SmzaRp05PcsWireProjection (DecodedMiddleWire DecodedPcsFields)
open SmzaRp05DecsResponseProjection (DecodedDecsResponseFields)
open SmzaRp05ExecutableReconstruction (DecodedPiopFields)
open SmzaRp05RelationRefinement (RelationDsl)
open SmzaRp05LeafNamespace (Namespace)
open V8SmzaOracleParser (RawDigest)

set_option autoImplicit false

/-- The `record` result fixes the very same oracle execution used below. Its
log is retained as a premise/result; the bridge extracts the corresponding
ordinary evaluation through `Program.record_result`. -/
theorem accepted_record_has_current_opening
    (ns : Namespace) (dsl : RelationDsl)
    (statement : SmzaRp05StatementNamespace.Statement)
    (pending : Bool) (packingFactor : Nat) (widths deltas : List Nat)
    (beta lvcsCols tailCount totalRows : Nat) (binding : List Byte)
    (statementBinding : List Nat) (wire : ExistingProofFieldView)
    (oracle : Oracle) (log : List (V8SmzaOracleParser.RawInput × RawDigest))
    (accepted : (currentProofFieldProgram ns dsl statement pending packingFactor
      widths deltas beta lvcsCols tailCount totalRows binding statementBinding
      wire).record oracle = (some (), log)) :
    ∃ middle decs piop opening final,
      decodeExistingProofFieldView wire = some (middle, decs, piop) ∧
      (chooseOpeningProgram wire.hPiop).eval oracle = some opening ∧
      SmzaRp05PcsToFinalProgram.finalFromMiddleProgram ns dsl statement opening
        pending wire.hPiop middle.pcs decs piop packingFactor widths deltas beta
        lvcsCols tailCount totalRows wire.salt binding statementBinding
        wire.tapes wire.paths = some final ∧
      final.eval oracle = some () := by
  have evalSuccess :
      (currentProofFieldProgram ns dsl statement pending packingFactor widths
        deltas beta lvcsCols tailCount totalRows binding statementBinding
        wire).eval oracle = some () := by
    have first := congrArg Prod.fst accepted
    rw [Program.record_result] at first
    exact first
  let decoded := decodeExistingProofFieldView wire
  generalize decodeChosen : decoded = chosen at evalSuccess
  cases chosen with
  | none =>
      change decodeExistingProofFieldView wire = none at decodeChosen
      unfold currentProofFieldProgram at evalSuccess
      rw [decodeChosen] at evalSuccess
      simp only [Program.eval] at evalSuccess
      cases evalSuccess
  | some fields =>
      rcases fields with ⟨middle, decs, piop⟩
      have decodedOk : decodeExistingProofFieldView wire = some (middle, decs, piop) := by
        simpa [decoded] using decodeChosen
      have programSuccess :
          (SmzaRp05CurrentOpeningProgram.currentOpeningFinalProgram ns dsl statement
            pending wire.hPiop middle.pcs decs piop packingFactor widths deltas
            beta lvcsCols tailCount totalRows wire.salt binding statementBinding
            wire.tapes wire.paths).eval oracle = some () := by
        unfold currentProofFieldProgram at evalSuccess
        rw [decodedOk] at evalSuccess
        exact evalSuccess
      obtain ⟨opening, final, openingSuccess, finalChoice, finalSuccess⟩ :=
        SmzaRp05CurrentOpeningProgram.accepted_has_current_opening ns dsl statement
          pending wire.hPiop middle.pcs decs piop packingFactor widths deltas beta
          lvcsCols tailCount totalRows wire.salt binding statementBinding
          wire.tapes wire.paths oracle programSuccess
      exact ⟨middle, decs, piop, opening, final, decodedOk, openingSuccess,
        finalChoice, finalSuccess⟩

end HegemonCrypto.SmallWood.SmzaRp05CurrentProofFieldAcceptanceBridge
