import SmzaRp05CurrentProofFieldAcceptanceBridge
import SmzaRp05FinalSuccessToLvcsRows

/-!
# Accepted decoded proof to selected-opening LVCS rows

This composes the current proof-field acceptance bridge with the ordinary
final-program execution decomposition. The decoded PIOP fields and selected
opening are extracted from the accepted run; the DECS points and LVCS rows
are then produced by that same final execution.
-/

namespace HegemonCrypto.SmallWood.SmzaRp05AcceptedRecordLvcsRows

open SmzaRp05ExecutableMerkleVerifier (Program Oracle)
open SmzaRp05CurrentProofWireProgram (ExistingProofFieldView)
open SmzaRp05RelationRefinement (RelationDsl)
open HegemonCrypto.CanonicalBytes
open V8SmzaOracleParser (RawDigest)

set_option autoImplicit false

/-- An accepted ordinary current-proof record determines its decoded PIOP,
the selected opening, and the exact LVCS points/rows reconstructed by the
same successful final-program execution. -/
theorem accepted_record_exposes_selected_lvcs_rows
    (ns : SmzaRp05LeafNamespace.Namespace) (dsl : RelationDsl)
    (statement : SmzaRp05StatementNamespace.Statement)
    (pending : Bool) (packingFactor : Nat) (widths deltas : List Nat)
    (beta lvcsCols tailCount totalRows : Nat) (binding : List Byte)
    (statementBinding : List Nat) (wire : ExistingProofFieldView)
    (oracle : Oracle) (log : List (V8SmzaOracleParser.RawInput × RawDigest))
    (accepted : (SmzaRp05CurrentProofWireProgram.currentProofFieldProgram ns dsl
      statement pending packingFactor widths deltas beta lvcsCols tailCount
      totalRows binding statementBinding wire).record oracle = (some (), log)) :
    ∃ middle decs piop opening final indexes points rows sampler,
      SmzaRp05CurrentProofWireProgram.decodeExistingProofFieldView wire =
        some (middle, decs, piop) ∧
      (SmzaRp05CurrentOpeningProgram.chooseOpeningProgram wire.hPiop).eval
        oracle = some opening ∧
      SmzaRp05PcsToFinalProgram.finalFromMiddleProgram ns dsl statement opening
        pending wire.hPiop middle.pcs decs piop packingFactor widths deltas
        beta lvcsCols tailCount totalRows wire.salt binding statementBinding
        wire.tapes wire.paths = some final ∧
      final.eval oracle = some () ∧
      SmzaRp05DecsPointProjection.openingIndexPointProgram pending wire.hPiop
        middle.pcs
        (List.ofFn fun j : Fin 6 =>
          HegemonCrypto.SmallWood.V8Smz9PiopReconstruction.points opening j)
        (SmzaRp05PcsToFinalProgram.sameProofRows middle.pcs piop).rowScalars
        packingFactor widths deltas beta lvcsCols tailCount = some sampler ∧
      sampler.eval oracle = some (indexes, points) ∧
      SmzaRp05LvcsWireProjection.reconstructRowsFromPcsFields middle.pcs
        (List.ofFn fun j : Fin 6 =>
          HegemonCrypto.SmallWood.V8Smz9PiopReconstruction.points opening j)
        points (SmzaRp05PcsToFinalProgram.sameProofRows middle.pcs piop).rowScalars
        packingFactor widths deltas beta lvcsCols totalRows tailCount =
        some rows := by
  obtain ⟨middle, decs, piop, opening, final, decoded, openingSelected,
      finalSelected, finalExecuted⟩ :=
    SmzaRp05CurrentProofFieldAcceptanceBridge.accepted_record_has_current_opening
      ns dsl statement pending packingFactor widths deltas beta lvcsCols
      tailCount totalRows binding statementBinding wire oracle log accepted
  obtain ⟨indexes, points, rows, sampler, samplerSelected, samplerExecuted,
      reconstruction⟩ :=
    SmzaRp05FinalSuccessToLvcsRows.final_success_exposes_lvcs_reconstruction
      ns dsl statement opening pending wire.hPiop middle.pcs decs piop
      packingFactor widths deltas beta lvcsCols tailCount totalRows wire.salt
      binding statementBinding wire.tapes wire.paths oracle final finalSelected
      finalExecuted
  exact ⟨middle, decs, piop, opening, final, indexes, points, rows, sampler,
    decoded, openingSelected, finalSelected, finalExecuted, samplerSelected,
    samplerExecuted, reconstruction⟩

end HegemonCrypto.SmallWood.SmzaRp05AcceptedRecordLvcsRows
