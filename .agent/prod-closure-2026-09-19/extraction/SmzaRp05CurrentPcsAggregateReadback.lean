import SmzaRp05CurrentPcsStageHeads
import SmzaRp05CurrentQueryEventCore

/-! The six actual successful PCS rows reconstruct the exact twelve heads
used in the accepted stage's claim polynomials. No head-binding certificate
is supplied by the caller. -/
namespace HegemonCrypto.SmallWood.SmzaRp05CurrentPcsAggregateReadback

open SmzaRp05CurrentPcsStageHeads
open SmzaRp05PcsWireProjection
open SmzaRp05PcsToFinalProgram (sameProofRows)
open SmzaRp05ExecutableReconstruction (DecodedPiopFields witness masks)
open SmzaRp05ExecutablePcsClosure (widths deltas)
open SmzaRp05CurrentPcsOpeningView (sourcePcsViewOfDecoded)
open SmzaRp05ExecutablePcsClosureStages (PcsStages)
open SmzaRp05CurrentQueryEventCore (currentStageClaims)
open SmzaRp05CurrentTwelveCalculated (currentStageTails)
open SmzaRp05LeafNamespace (Namespace)
open HegemonCrypto.CanonicalBytes (Byte)
open V8SmzaOracleParser (RawDigest)
open V8Smz9EagerSimulator (reconstructedColumnEvaluations)

set_option autoImplicit false
set_option maxRecDepth 10000
noncomputable section

theorem successful_aggregate_reads_source_column
    (pcs : DecodedPcsFields) (piop : DecodedPiopFields)
    (points : Fin 6 → Goldilocks) (heads : List (List Goldilocks))
    (success : reconstructedHeadsAll pcs (List.ofFn points)
      (sameProofRows pcs piop).rowScalars 64 widths deltas 2 368 = some heads)
    (opening : Fin 6) (block : Fin 2) (column : Fin 368) :
    (heads.getD (2 * opening.val + block.val) []).getD column.val 0 =
      reconstructedColumnEvaluations points (witness piop) (masks piop)
        (sourcePcsViewOfDecoded pcs) opening (SmzaQ38LvcsOpening.columnIndex block column) := by
  have height : (sameProofRows pcs piop).rowScalars.length = (List.ofFn points).length ∧
      pcs.partialEvals.length = (List.ofFn points).length := by
    have good : ¬ ((sameProofRows pcs piop).rowScalars.length ≠ (List.ofFn points).length ∨
        pcs.partialEvals.length ≠ (List.ofFn points).length) := by
      intro bad
      simp only [reconstructedHeadsAll, if_pos bad,
        Option.bind_eq_bind, Option.bind_none] at success
      cases success
    exact ⟨by omega, by omega⟩
  obtain ⟨rows, flatEq, lengthEq, entries⟩ := reconstructed_heads_all_exposes_row
    pcs (List.ofFn points) (sameProofRows pcs piop).rowScalars
    64 widths deltas 2 368 heads height success
  have rowsCount : rows.length = 6 := by
    simpa only [List.length_ofFn] using lengthEq
  have sourceRow (index : Fin 6) : rows.getD index.val [] = sourceHeadRow points piop pcs index := by
    exact successful_head_row_is_source_row pcs piop points index.val
      (rows.getD index.val []) index.isLt
      (entries index.val (by simpa only [List.length_ofFn] using index.isLt))
  have shape : ∀ row, row ∈ rows → row.length = 2 := by
    intro row member
    obtain ⟨index, bound, same⟩ := List.mem_iff_getElem.mp member
    have indexBound : index < 6 := by omega
    have read := sourceRow ⟨index, indexBound⟩
    rw [List.getD_eq_getElem rows [] bound, same] at read
    rw [read]
    simp only [sourceHeadRow, chunkHeads, List.length_map, List.length_range]
  have flatRead := rectangular_flatten_getD rows 2 opening.val block.val [] shape
    (by rw [rowsCount]; exact opening.isLt) block.isLt
  rw [← flatEq, sourceRow opening] at flatRead
  have headRead : heads.getD (2 * opening.val + block.val) [] =
      (sourceHeadRow points piop pcs opening).getD block.val [] := by
    simpa only [Nat.mul_comm] using flatRead
  calc
    _ = ((sourceHeadRow points piop pcs opening).getD block.val []).getD column.val 0 :=
      congrArg (fun row : List Goldilocks => row.getD column.val 0) headRead
    _ = _ := SmzaRp05CurrentPcsChunkReadback.actual_chunk_reads_source_column
      (reconstructedColumnEvaluations points (witness piop) (masks piop)
        (sourcePcsViewOfDecoded pcs) opening) block column

theorem actual_stages_have_claimed_heads_reconstructed
    {ns : Namespace} {pending : Bool} {hPiop : RawDigest}
    (pcs : DecodedPcsFields) (piop : DecodedPiopFields)
    {decs : SmzaRp05DecsResponseProjection.DecodedDecsResponseFields}
    {points : Fin 6 → Goldilocks} {salt binding : List Byte}
    {statementBinding : List Nat} {tapes : List (List Byte)}
    {paths : List (List RawDigest)} {oracle : SmzaRp05ExecutableMerkleVerifier.Oracle}
    {hashFpp : RawDigest} {finalPending : Bool}
    (stages : PcsStages ns pending hPiop (sameProofRows pcs piop) decs
      (List.ofFn points) salt binding statementBinding tapes paths oracle hashFpp finalPending) :
    SmzaQ38OpeningFieldReadback.ClaimedHeadsReconstructed points
      (currentStageClaims stages.heads (currentStageTails (sameProofRows pcs piop)))
      (witness piop) (masks piop) (sourcePcsViewOfDecoded pcs) := by
  intro opening block column
  have read := SmzaRp05CurrentStageHeadReadback.current_stage_query_polynomial_reads_head
    stages opening block column
  exact read.trans (successful_aggregate_reads_source_column pcs piop points
    stages.heads stages.headsBuilt opening block column)

end
end HegemonCrypto.SmallWood.SmzaRp05CurrentPcsAggregateReadback
