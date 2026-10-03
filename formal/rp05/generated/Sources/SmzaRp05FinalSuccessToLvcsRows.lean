import SmzaRp05FinalProgramMiddleExecution
import SmzaRp05HashFppPostMerkleExecution
import SmzaRp05PostMerkleIndexedRowsExecution
import SmzaRp05IndexedRowsReconstructionExecution

/-!
# Successful current final execution reaches proof-connected LVCS rows

This theorem composes the selected ordinary final program's execution through
its hash-Fpp, authenticated PCS/Merkle, and indexed-row programs. The returned
DECS points and LVCS rows are outputs of the existing sampler and
`reconstructRowsFromPcsFields`; neither is supplied by the caller.
-/

namespace HegemonCrypto.SmallWood.SmzaRp05FinalSuccessToLvcsRows

open SmzaRp05ExecutableMerkleVerifier (Program Oracle)
open SmzaRp05LeafNamespace (Namespace)
open SmzaRp05PcsWireProjection (DecodedPcsFields)
open SmzaRp05DecsResponseProjection (DecodedDecsResponseFields)
open SmzaRp05RelationRefinement (RelationDsl)
open HegemonCrypto.CanonicalBytes
open V8Smz9PiopSoundness (Opening)
open V8SmzaOracleParser (RawDigest)

set_option autoImplicit false

/-- An ordinary successful final-program execution necessarily reached the
same decoded PCS proof's LVCS reconstruction with the sampler-derived DECS
points, and returned precisely those reconstructed rows. -/
theorem final_success_exposes_lvcs_reconstruction
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
    ∃ indexes points rows sampler,
      SmzaRp05DecsPointProjection.openingIndexPointProgram pending hPiop pcs
        (List.ofFn fun j : Fin 6 =>
          HegemonCrypto.SmallWood.V8Smz9PiopReconstruction.points opening j)
        (SmzaRp05PcsToFinalProgram.sameProofRows pcs piop).rowScalars
        packingFactor widths deltas beta lvcsCols tailCount =
        some sampler ∧
      sampler.eval oracle = some (indexes, points) ∧
      SmzaRp05LvcsWireProjection.reconstructRowsFromPcsFields pcs
        (List.ofFn fun j : Fin 6 =>
          HegemonCrypto.SmallWood.V8Smz9PiopReconstruction.points opening j)
        points (SmzaRp05PcsToFinalProgram.sameProofRows pcs piop).rowScalars
        packingFactor widths deltas beta lvcsCols
        totalRows tailCount = some rows := by
  let wire := SmzaRp05PcsToFinalProgram.sameProofRows pcs piop
  let evalPoints : List Goldilocks := List.ofFn fun j : Fin 6 =>
    HegemonCrypto.SmallWood.V8Smz9PiopReconstruction.points opening j
  obtain ⟨hashFpp, middlePending, middle, middleSelected, middleExecuted⟩ :=
    SmzaRp05FinalProgramMiddleExecution.final_success_has_middle_execution
      ns dsl statement opening pending hPiop pcs decs piop packingFactor
      widths deltas beta lvcsCols tailCount totalRows salt binding
      statementBinding tapes paths oracle final selected executed
  obtain ⟨postProgram, indexes, rows, post, postSelected, postExecuted⟩ :=
    SmzaRp05HashFppPostMerkleExecution.hashFpp_success_has_postMerkle_execution
      ns pending hPiop wire decs evalPoints packingFactor widths deltas beta
      lvcsCols tailCount totalRows salt binding statementBinding tapes paths
      oracle middle hashFpp middlePending middleSelected middleExecuted
  obtain ⟨indexedProgram, indexedSelected, indexedExecuted⟩ :=
    SmzaRp05PostMerkleIndexedRowsExecution.postMerkle_success_has_indexedRows_execution
      ns pending hPiop wire evalPoints packingFactor widths deltas beta lvcsCols
      tailCount totalRows salt binding decs.maskingEvals tapes paths oracle
      postProgram indexes rows post postSelected postExecuted
  obtain ⟨sampler, points, samplerSelected, samplerExecuted, reconstruction⟩ :=
    SmzaRp05IndexedRowsReconstructionExecution.indexedRows_success_exposes_reconstruction
      pending hPiop wire evalPoints packingFactor widths deltas beta lvcsCols
      tailCount totalRows oracle indexedProgram indexes rows indexedSelected
      indexedExecuted
  exact ⟨indexes, points, rows, sampler, samplerSelected, samplerExecuted,
    reconstruction⟩

end HegemonCrypto.SmallWood.SmzaRp05FinalSuccessToLvcsRows
