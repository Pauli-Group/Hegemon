import SmzaRp05CurrentPcsActualColumns
import SmzaRp05CurrentPcsChunkReadback
import SmzaRp05CurrentPcsPartialLength
import SmzaRp05CurrentPcsPartialReadback
import SmzaRp05CurrentPcsScalarReadback
import SmzaRp05CurrentPcsDecodedRow
import SmzaRp05CurrentStageHeadReadback

/-! # Same-stage PCS head values are the decoded source columns

This bridge starts from `PcsStages.headsBuilt`, which is the successful
reconstruction performed by the same accepted PCS execution. It does not
accept a caller-provided head-binding certificate. -/

namespace HegemonCrypto.SmallWood.SmzaRp05CurrentPcsStageHeads

open HegemonCrypto.SmallWood (Goldilocks)
open SmzaRp05ExecutablePcsClosureStages (PcsStages)
open SmzaRp05PcsWireProjection
  (reconstructedHeadsAll reconstructedHeadsForRow reconstructDecodedPcsRow
    fieldWordsToGoldilocks)
open SmzaRp05PcsToFinalProgram (sameProofRows)
open SmzaRp05CurrentPcsOpeningView (sourcePcsViewOfDecoded)
open SmzaRp05CurrentPcsActualColumns (reconstruct_source_columns_row)
open SmzaRp05CurrentPcsPartialLength (successful_current_reconstruction_has_forty_partials)
open SmzaRp05CurrentPcsPartialReadback (source_partial_row_is_decoded_row)
open SmzaRp05CurrentPcsScalarReadback (same_proof_scalar_row_is_source_row)
open SmzaRp05CurrentTwelveCalculated (currentStageTails)
open SmzaRp05CurrentStageHeadReadback (current_stage_query_polynomial_reads_head)
open SmzaRp05CurrentPcsChunkReadback (actual_chunk_reads_source_column)
open SmzaRp05ExecutablePcsClosure (widths deltas)
open SmzaRp05ExecutablePcsClosureLvcsAlgebra (mapM_success_entry)
open SmzaRp05ExecutableReconstruction (DecodedPiopFields witness masks)
open V8Smz9EagerSimulator (sourceRowScalars reconstructedColumnEvaluations)
open SmzaRp05PcsWireProjection (DecodedPcsFields DecodedMiddleWire)
open SmzaRp05DecsResponseProjection (DecodedDecsResponseFields)
open SmzaRp05LeafNamespace (Namespace)
open V8SmzaOracleParser (RawDigest)

set_option autoImplicit false
set_option maxRecDepth 10000

theorem rectangular_flatten_getD {α : Type}
    (rows : List (List α)) (columns row lane : Nat) (fallback : α)
    (shape : ∀ entry, entry ∈ rows → entry.length = columns)
    (rowBound : row < rows.length) (laneBound : lane < columns) :
    rows.flatten.getD (row * columns + lane) fallback =
      (rows.getD row []).getD lane fallback := by
  induction rows generalizing row with
  | nil => simp at rowBound
  | cons head tail ih =>
      have headLength := shape head (by simp)
      have tailShape := fun entry member =>
        shape entry (List.mem_cons_of_mem head member)
      cases row with
      | zero =>
          simp only [Nat.zero_mul, Nat.zero_add, List.flatten_cons,
            List.getD_cons_zero]
          exact List.getD_append head tail.flatten fallback lane (by omega)
      | succ row =>
          have offset : (row + 1) * columns + lane =
              head.length + (row * columns + lane) := by
            rw [headLength, Nat.add_mul, Nat.one_mul]
            omega
          simp only [List.flatten_cons, List.getD_cons_succ, offset]
          rw [List.getD_append_right head tail.flatten fallback _ (by omega)]
          have remaining :
              head.length + (row * columns + lane) - head.length =
                row * columns + lane := by omega
          rw [remaining]
          exact ih row tailShape (by simpa using rowBound)

def sourceHeadRow (points : Fin 6 → Goldilocks)
    (piop : DecodedPiopFields) (pcs : DecodedPcsFields) (opening : Fin 6) :
    List (List Goldilocks) :=
  SmzaRp05PcsWireProjection.chunkHeads 2 368
    (List.ofFn (reconstructedColumnEvaluations points (witness piop) (masks piop)
      (sourcePcsViewOfDecoded pcs) opening))

theorem successful_head_row_is_source_row
    (pcs : DecodedPcsFields) (piop : DecodedPiopFields)
    (points : Fin 6 → Goldilocks) (openingIndex : Nat)
    (headRow : List (List Goldilocks))
    (indexBound : openingIndex < 6)
    (success : reconstructedHeadsForRow pcs (List.ofFn points)
      (sameProofRows pcs piop).rowScalars openingIndex 64 widths deltas 2 368 =
        some headRow) :
    headRow = sourceHeadRow points piop pcs ⟨openingIndex, indexBound⟩ := by
  unfold reconstructedHeadsForRow at success
  change (reconstructDecodedPcsRow pcs (List.ofFn points)
      (sameProofRows pcs piop).rowScalars openingIndex 64 widths deltas).bind
      (fun row => some (SmzaRp05PcsWireProjection.chunkHeads 2 368 row)) =
    some headRow at success
  cases row : reconstructDecodedPcsRow pcs (List.ofFn points)
      (sameProofRows pcs piop).rowScalars openingIndex 64 widths deltas with
  | none =>
      rw [row] at success
      change (none : Option (List (List Goldilocks))) = some headRow at success
      cases success
  | some values =>
      rw [row] at success
      change some (SmzaRp05PcsWireProjection.chunkHeads 2 368 values) =
        some headRow at success
      have headEq : headRow = SmzaRp05PcsWireProjection.chunkHeads 2 368 values :=
        (Option.some.inj success).symm
      have decoded := SmzaRp05CurrentPcsDecodedRow.successful_decoded_row_is_source_columns
        pcs piop points ⟨openingIndex, indexBound⟩ values row
      exact headEq.trans
        (congrArg (SmzaRp05PcsWireProjection.chunkHeads 2 368) decoded)

/-- A successful same-stage head construction exposes the exact output row
at every valid opening index. The flattened list is precisely the list
assembled by the verifier's `mapM` traversal; no second reconstruction is
introduced. -/
theorem reconstructed_heads_all_exposes_row
    (fields : DecodedPcsFields) (evalPoints : List Goldilocks)
    (rowScalars : List (List SmzaRp05ExecutableChallengeStage.FieldWord))
    (packingFactor : Nat) (rowWidths rowDeltas : List Nat)
    (beta lvcsCols : Nat) (heads : List (List Goldilocks))
    (height : rowScalars.length = evalPoints.length ∧
      fields.partialEvals.length = evalPoints.length)
    (success : reconstructedHeadsAll fields evalPoints rowScalars packingFactor
      rowWidths rowDeltas beta lvcsCols = some heads) :
    ∃ rows : List (List (List Goldilocks)),
      heads = rows.flatten ∧
      rows.length = evalPoints.length ∧
      ∀ index, index < evalPoints.length →
        reconstructedHeadsForRow fields evalPoints rowScalars index packingFactor
          rowWidths rowDeltas beta lvcsCols = some (rows.getD index []) := by
  have heightsPass :
      ¬ (rowScalars.length ≠ evalPoints.length ∨
        fields.partialEvals.length ≠ evalPoints.length) := by omega
  unfold reconstructedHeadsAll at success
  simp only [if_neg heightsPass] at success
  change ((List.range evalPoints.length).mapM
      (fun j => reconstructedHeadsForRow fields evalPoints rowScalars j
        packingFactor rowWidths rowDeltas beta lvcsCols)).bind
      (fun rows => some rows.flatten) = some heads at success
  cases mapped : (List.range evalPoints.length).mapM
      (fun j => reconstructedHeadsForRow fields evalPoints rowScalars j
        packingFactor rowWidths rowDeltas beta lvcsCols) with
  | none => simp [mapped] at success
  | some rows =>
      have flatEq : heads = rows.flatten := by
        have equal : some rows.flatten = some heads := by
          simpa [mapped] using success
        exact (Option.some.inj equal).symm
      have entries := mapM_success_entry (List.range evalPoints.length)
        (fun j => reconstructedHeadsForRow fields evalPoints rowScalars j
          packingFactor rowWidths rowDeltas beta lvcsCols)
        rows 0 [] mapped
      have rangeLength : (List.range evalPoints.length).length = evalPoints.length := by simp
      refine ⟨rows, flatEq, ?_, ?_⟩
      · simpa only [rangeLength] using entries.1
      · intro index indexBound
        have indexBound' : index < (List.range evalPoints.length).length := by
          simpa only [rangeLength] using indexBound
        have atIndex := entries.2 index indexBound'
        have rangeAt : (List.range evalPoints.length).getD index 0 = index := by
          rw [List.getD_eq_getElem?_getD, List.getElem?_range indexBound,
            Option.getD_some]
        rw [rangeAt] at atIndex
        exact atIndex

end HegemonCrypto.SmallWood.SmzaRp05CurrentPcsStageHeads
