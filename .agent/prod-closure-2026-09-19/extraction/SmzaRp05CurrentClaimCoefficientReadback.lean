import SmzaRp05CurrentDecsFrameReadback
import SmzaRp05TracePrefixes
import SmzaRp05ExecutablePcsClosureStages
import SmzaRp05CurrentQueryEventCore
import SmzaRp05CurrentResponsePrequeryDecode

set_option autoImplicit false
set_option maxRecDepth 10000
set_option maxHeartbeats 1000000

/-! # Coefficient readback for the stage-generated DECS opening -/

namespace HegemonCrypto.SmallWood.SmzaRp05CurrentClaimCoefficientReadback

noncomputable section

open SmzaRp05ExecutablePcsClosureStages (PcsStages)
open SmzaRp05CurrentDecsFrameReadback (current_decs_opening_edge406)
open SmzaRp05TracePrefixes (Payload)
open SmzaRp04TracePrefixes (queryCoefficients queryPolynomial)
open SmzaRp04ChronologicalAlgebra (claimedPolynomials)
open SmzaRp05PcsWireProjection (DecodedMiddleWire)
open SmzaRp05LeafNamespace (Namespace)
open V8SmzaOracleParser (RawDigest)
open HegemonCrypto.CanonicalBytes (Byte)
open SmzaRp05CurrentTwelveCalculated
open SmzaRp05CurrentQueryEventCore (currentStageClaims)
open SmzaRp05LvcsWireProjection (rotateLeft)

private def openingWordRows (heads : List (List HegemonCrypto.SmallWood.Goldilocks))
    (tails : List (List SmzaRp05ExecutableChallengeStage.FieldWord)) :
    List (List Nat) :=
  List.zipWith (fun head tail =>
    (head.map fun value => value.val) ++ (tail.map fun value => value.val)) heads tails

private theorem opening_rows_success_flatten
    (count cols tailCount : Nat)
    (heads : List (List HegemonCrypto.SmallWood.Goldilocks))
    (tails : List (List SmzaRp05ExecutableChallengeStage.FieldWord)) (words : List Nat)
    (success : SmzaRp05PcsWireProjection.openingRowsWords count cols tailCount
      heads tails = some words) :
    words = (openingWordRows heads tails).flatten ∧
      (openingWordRows heads tails).length = count ∧
      ∀ chunk, chunk ∈ openingWordRows heads tails →
        chunk.length = cols + tailCount := by
  induction count generalizing heads tails words with
  | zero =>
      cases heads with
      | nil =>
          cases tails with
          | nil =>
              have emptyWords : words = [] := by
                simpa [SmzaRp05PcsWireProjection.openingRowsWords] using success
              subst words
              simp [openingWordRows]
          | cons tail tails => simp [SmzaRp05PcsWireProjection.openingRowsWords] at success
      | cons head heads => simp [SmzaRp05PcsWireProjection.openingRowsWords] at success
  | succ count ih =>
      cases heads with
      | nil => simp [SmzaRp05PcsWireProjection.openingRowsWords] at success
      | cons head heads =>
          cases tails with
          | nil => simp [SmzaRp05PcsWireProjection.openingRowsWords] at success
          | cons tail tails =>
              simp only [SmzaRp05PcsWireProjection.openingRowsWords] at success
              by_cases shape : head.length ≠ cols ∨ tail.length ≠ tailCount
              · simp [shape] at success
              · simp only [if_neg shape] at success
                cases restEq : SmzaRp05PcsWireProjection.openingRowsWords
                    count cols tailCount heads tails with
                | none => simp [restEq] at success
                | some rest =>
                    have restEq' := ih heads tails rest restEq
                    have outputEq : words =
                        head.map (fun value => value.val) ++
                          tail.map (fun value => value.val) ++ rest := by
                      exact (Option.some.inj (by simpa [restEq] using success)).symm
                    obtain ⟨restFlatten, restCount, restShape⟩ := restEq'
                    have headShape : head.length = cols := by
                      simp only [not_or] at shape
                      omega
                    have tailShape : tail.length = tailCount := by
                      simp only [not_or] at shape
                      omega
                    refine ⟨?_, ?_, ?_⟩
                    · rw [outputEq, restFlatten]
                      simp [openingWordRows, List.flatten_cons, List.append_assoc]
                    · change (List.zipWith
                        (fun head tail =>
                          (head.map fun value => value.val) ++
                            (tail.map fun value => value.val))
                        (head :: heads) (tail :: tails)).length = count + 1
                      rw [List.zipWith_cons_cons]
                      simp only [List.length_cons]
                      have restLength :
                          (List.zipWith
                            (fun head tail =>
                              (head.map fun value => value.val) ++
                                (tail.map fun value => value.val)) heads tails).length = count := by
                        simpa [openingWordRows] using restCount
                      omega
                    · intro chunk member
                      simp only [openingWordRows, List.zipWith_cons_cons,
                        List.mem_cons] at member
                      rcases member with headChunk | tailChunk
                      · cases headChunk
                        simp [List.length_append, headShape, tailShape]
                      · exact restShape chunk tailChunk

private theorem zipWith_getD_default {α β γ : Type}
    (f : α → β → γ) (xs : List α) (ys : List β) (index : Nat)
    (fallback : γ) (leftFallback : α) (rightFallback : β)
    (leftBound : index < xs.length) (rightBound : index < ys.length) :
    (List.zipWith f xs ys).getD index fallback =
      f (xs.getD index leftFallback) (ys.getD index rightFallback) := by
  induction xs generalizing ys index with
  | nil => simp at leftBound
  | cons x xs ih =>
      cases ys with
      | nil => simp at rightBound
      | cons y ys =>
          cases index with
          | zero => rfl
          | succ index =>
              simp only [List.zipWith_cons_cons, List.getD_cons_succ]
              exact ih ys index (by simpa using leftBound) (by simpa using rightBound)

private theorem map_getD_default {α β : Type} (values : List α) (f : α → β)
    (index : Nat) (fallback : α) :
    (values.map f).getD index (f fallback) = f (values.getD index fallback) := by
  induction values generalizing index with
  | nil => cases index <;> rfl
  | cons head tail ih => cases index <;> simp

private def stageUnrotatedRow
    (heads : List (List HegemonCrypto.SmallWood.Goldilocks))
    (tails : List (List SmzaRp05ExecutableChallengeStage.FieldWord)) (row : Nat) :
    List HegemonCrypto.SmallWood.Goldilocks :=
  (heads.getD row []) ++
    (SmzaRp05PcsWireProjection.fieldWordsToGoldilocks (tails.getD row []))

private theorem fieldWord_toGoldilocks_value
    (word : SmzaRp05ExecutableChallengeStage.FieldWord) :
  (HegemonCrypto.SmallWood.toGoldilocks word.val).val = word.val := by
  change word.val %
    Hegemon.Transaction.SmallWoodProductionConstraintRefinement.goldilocksModulus = word.val
  apply Nat.mod_eq_of_lt
  exact word.isLt

private theorem fieldWords_toGoldilocks_values
    (words : List SmzaRp05ExecutableChallengeStage.FieldWord) :
    (SmzaRp05PcsWireProjection.fieldWordsToGoldilocks words).map
        (fun value : HegemonCrypto.SmallWood.Goldilocks => value.val) =
      words.map (fun word => word.val) := by
  induction words with
  | nil => rfl
  | cons word words ih =>
      change (HegemonCrypto.SmallWood.toGoldilocks word.val).val ::
          (SmzaRp05PcsWireProjection.fieldWordsToGoldilocks words).map
            (fun value : HegemonCrypto.SmallWood.Goldilocks => value.val) =
        word.val :: words.map (fun value => value.val)
      rw [fieldWord_toGoldilocks_value, ih]

private theorem rotate_left_368_getD
    (head tail : List HegemonCrypto.SmallWood.Goldilocks)
    (headLength : head.length = 368) (tailLength : tail.length = 38)
    (index : Fin 406) :
    (rotateLeft (head ++ tail) 368).getD index.val 0 =
      (head ++ tail).getD ((index.val + 368) % 406) 0 := by
  have fullLength : (head ++ tail).length = 406 := by
    simp [headLength, tailLength]
  have rotation : rotateLeft (head ++ tail) 368 = tail ++ head := by
    unfold rotateLeft
    rw [fullLength, Nat.mod_eq_of_lt (by omega : 368 < 406)]
    simp [headLength]
  by_cases inTail : index.val < 38
  · have offset : (index.val + 368) % 406 = index.val + 368 := by omega
    rw [rotation, List.getD_append _ _ _ _ (by omega), offset]
    rw [List.getD_append_right _ _ _ _ (by rw [headLength]; omega)]
    have tailIndex : index.val + 368 - head.length = index.val := by
      rw [headLength]
      omega
    rw [tailIndex]
  · have offset : (index.val + 368) % 406 = index.val - 38 := by omega
    rw [rotation, List.getD_append_right _ _ _ _ (by omega)]
    have rotatedIndex : index.val - 38 < head.length := by
      rw [headLength]
      omega
    have shiftedIndex : index.val - tail.length = index.val - 38 := by
      rw [tailLength]
    have appendAt := List.getD_append head tail 0 (index.val - 38) rotatedIndex
    calc
      head.getD (index.val - tail.length) 0 = head.getD (index.val - 38) 0 := by
        rw [shiftedIndex]
      _ = (head ++ tail).getD (index.val - 38) 0 := appendAt.symm
      _ = (head ++ tail).getD ((index.val + 368) % 406) 0 := by rw [offset]

private theorem generated_opening_evaluation_readback
    {ns : Namespace} {pending : Bool} {hPiop : RawDigest}
    {wire : DecodedMiddleWire}
    {decs : SmzaRp05DecsResponseProjection.DecodedDecsResponseFields}
    {points : List HegemonCrypto.SmallWood.Goldilocks}
    {salt binding : List Byte} {statementBinding : List Nat}
    {tapes : List (List Byte)} {paths : List (List RawDigest)}
    {oracle : SmzaRp05ExecutableMerkleVerifier.Oracle}
    {hashFpp : RawDigest} {finalPending : Bool}
    (stages : PcsStages ns pending hPiop wire decs points salt binding
      statementBinding tapes paths oracle hashFpp finalPending)
    (rows : List Nat)
    (rowsBuilt : SmzaRp05PcsWireProjection.openingRowsWords 12 368 38
      stages.heads wire.pcs.rcombiTails = some rows)
    (combination : SmzaQ38LvcsOpening.Combination) (index : Fin 406) :
    SmzaRp04TracePrefixes.queryEvaluations
        ⟨.decs, (SmzaRp05ExecutableChallengeStage.digestWords hPiop ++ rows).flatMap
          (HegemonCrypto.CanonicalBytes.encodeLE 8)⟩ combination index =
      (currentQueryValues stages.heads (currentStageTails wire)
        combination.1 combination.2).getD index.val 0 := by
  classical
  let wordRows := openingWordRows stages.heads wire.pcs.rcombiTails
  let row := combination.1.val * 2 + combination.2.val
  let offset := (index.val + 368) % 406
  have wellFormed := pcs_stages_query_vector_well_formed stages
  have rowBound : row < 12 := by
    have openingBound := combination.1.isLt
    have blockBound := combination.2.isLt
    omega
  have offsetBound : offset < 406 := Nat.mod_lt _ (by decide)
  have headCount : stages.heads.length = 12 := wellFormed.1
  have tailCount : (currentStageTails wire).length = 12 := wellFormed.2.1
  have tailWireCount : wire.pcs.rcombiTails.length = 12 := by
    simpa [currentStageTails] using tailCount
  have headBound : row < stages.heads.length := by rw [headCount]; exact rowBound
  have tailBound : row < wire.pcs.rcombiTails.length := by
    rw [tailWireCount]
    exact rowBound
  have headLength : (stages.heads.getD row []).length = 368 :=
    wellFormed.2.2.1 row rowBound
  have tailLength : ((currentStageTails wire).getD row []).length = 38 :=
    wellFormed.2.2.2 row rowBound
  have rowsFact := opening_rows_success_flatten 12 368 38 stages.heads
    wire.pcs.rcombiTails rows rowsBuilt
  have wordRowsCount : wordRows.length = 12 := by
    simpa [wordRows] using rowsFact.2.1
  have wordRowsShape : ∀ chunk, chunk ∈ wordRows → chunk.length = 406 := by
    simpa [wordRows] using rowsFact.2.2
  have wordRowsCell : rows.getD (row * 406 + offset) 0 =
      ((currentQueryValues stages.heads (currentStageTails wire)
          combination.1 combination.2).getD index.val 0).val := by
    rw [rowsFact.1]
    rw [HegemonCrypto.SmallWood.V8Smz9HonestHashMaterialization.rectangular_flatten_getD
      wordRows 406 row offset wordRowsShape (by rw [wordRowsCount]; exact rowBound)
      offsetBound]
    have zipped := zipWith_getD_default
      (fun head tail =>
        (head.map fun value : HegemonCrypto.SmallWood.Goldilocks => value.val) ++
          (tail.map fun value : SmzaRp05ExecutableChallengeStage.FieldWord => value.val))
      stages.heads wire.pcs.rcombiTails row [] [] [] headBound tailBound
    have chunkEq : wordRows.getD row [] =
        (stageUnrotatedRow stages.heads wire.pcs.rcombiTails row).map
          (fun value : HegemonCrypto.SmallWood.Goldilocks => value.val) := by
      calc
        wordRows.getD row [] =
            (stages.heads.getD row []).map
                (fun value : HegemonCrypto.SmallWood.Goldilocks => value.val) ++
              (wire.pcs.rcombiTails.getD row []).map
                (fun value : SmzaRp05ExecutableChallengeStage.FieldWord => value.val) := by
          simpa [wordRows, openingWordRows] using zipped
        _ = (stageUnrotatedRow stages.heads wire.pcs.rcombiTails row).map
              (fun value : HegemonCrypto.SmallWood.Goldilocks => value.val) := by
          simp [stageUnrotatedRow, fieldWords_toGoldilocks_values]
    rw [chunkEq]
    change ((stageUnrotatedRow stages.heads wire.pcs.rcombiTails row).map
      (fun value : HegemonCrypto.SmallWood.Goldilocks => value.val)).getD offset
      ((0 : HegemonCrypto.SmallWood.Goldilocks).val) = _
    rw [map_getD_default]
    have rotated := rotate_left_368_getD
      (stages.heads.getD row []) ((currentStageTails wire).getD row [])
      headLength tailLength index
    have tailRowEq : (currentStageTails wire).getD row [] =
        SmzaRp05PcsWireProjection.fieldWordsToGoldilocks
          (wire.pcs.rcombiTails.getD row []) := by
      change (wire.pcs.rcombiTails.map
          SmzaRp05PcsWireProjection.fieldWordsToGoldilocks).getD row
            (SmzaRp05PcsWireProjection.fieldWordsToGoldilocks []) =
        SmzaRp05PcsWireProjection.fieldWordsToGoldilocks
          (wire.pcs.rcombiTails.getD row [])
      exact map_getD_default wire.pcs.rcombiTails
        SmzaRp05PcsWireProjection.fieldWordsToGoldilocks row []
    rw [tailRowEq] at rotated
    have rowEq : 2 * combination.1.val + combination.2.val = row := by
      dsimp [row]
      omega
    simp only [currentQueryValues, rowEq]
    rw [tailRowEq]
    simpa only [stageUnrotatedRow, offset] using congrArg
      (fun value : HegemonCrypto.SmallWood.Goldilocks => value.val) rotated.symm
  have rowWordsLength := SmzaRp05CurrentDecsFrameReadback.openingRowsWords_length
    12 368 38 stages.heads wire.pcs.rcombiTails rows rowsBuilt
  have allWordsLength :
      (SmzaRp05ExecutableChallengeStage.digestWords hPiop ++ rows).length = 4880 := by
    rw [List.length_append]
    have digestLength :
        (SmzaRp05ExecutableChallengeStage.digestWords hPiop).length = 8 := by
      simp [SmzaRp05ExecutableChallengeStage.digestWords]
    rw [digestLength, rowWordsLength]
  have encodedIndexBound :
      8 + row * 406 + offset <
        (SmzaRp05ExecutableChallengeStage.digestWords hPiop ++ rows).length := by
    rw [allWordsLength]
    omega
  have allWordsCell :
      (SmzaRp05ExecutableChallengeStage.digestWords hPiop ++ rows).getD
        (8 + row * 406 + offset) 0 =
          ((currentQueryValues stages.heads (currentStageTails wire)
            combination.1 combination.2).getD index.val 0).val := by
    rw [List.getD_append_right _ _ _ _ (by
      simp [SmzaRp05ExecutableChallengeStage.digestWords]
      omega)]
    have residual : 8 + row * 406 + offset -
        (SmzaRp05ExecutableChallengeStage.digestWords hPiop).length =
        row * 406 + offset := by
      simp [SmzaRp05ExecutableChallengeStage.digestWords]
      omega
    rw [residual]
    exact wordRowsCell
  have selectedWordBound :
      ((SmzaRp05ExecutableChallengeStage.digestWords hPiop ++ rows).getD
        (8 + row * 406 + offset) 0) < 256 ^ 8 := by
    rw [allWordsCell]
    have valueBound :
        ((currentQueryValues stages.heads (currentStageTails wire)
          combination.1 combination.2).getD index.val 0).val <
          SmzaRp05ExecutableChallengeStage.modulus := by
      exact ((currentQueryValues stages.heads (currentStageTails wire)
        combination.1 combination.2).getD index.val 0).val_lt
    exact lt_trans valueBound (by norm_num [SmzaRp05ExecutableChallengeStage.modulus])
  have decodedWord :=
    SmzaRp05CurrentResponsePrequeryDecode.word_at_encoded_words
      (SmzaRp05ExecutableChallengeStage.digestWords hPiop ++ rows)
      (8 + row * 406 + offset) encodedIndexBound selectedWordBound
  change HegemonCrypto.SmallWood.toGoldilocks
      (V8SmzaOracleParser.wordAt
        ((SmzaRp05ExecutableChallengeStage.digestWords hPiop ++ rows).flatMap
          (HegemonCrypto.CanonicalBytes.encodeLE 8))
        (8 + row * 406 + offset)) = _
  rw [← List.flatMap_def] at decodedWord
  rw [decodedWord, allWordsCell]
  exact HegemonCrypto.SmallWood.toGoldilocks_fromGoldilocks _

/-- For the actual payload parsed from a successful `PcsStages` DECS-opening
input, the transmitted coefficients reconstruct exactly the twelve current
head/tail polynomials. The row mapping follows `openingRowsWords`' serialized
head-then-tail order and the verifier's 368-place rotation. -/
theorem generated_opening_claim_coefficients_reconstruct_payload
    {ns : Namespace} {pending : Bool} {hPiop : RawDigest}
    {wire : DecodedMiddleWire}
    {decs : SmzaRp05DecsResponseProjection.DecodedDecsResponseFields}
    {points : List HegemonCrypto.SmallWood.Goldilocks}
    {salt binding : List Byte} {statementBinding : List Nat}
    {tapes : List (List Byte)} {paths : List (List RawDigest)}
    {oracle : SmzaRp05ExecutableMerkleVerifier.Oracle}
    {hashFpp : RawDigest} {finalPending : Bool}
    (stages : PcsStages ns pending hPiop wire decs points salt binding
      statementBinding tapes paths oracle hashFpp finalPending) :
    ∃ payload : V8SmzaOracleParser.Payload,
      V8SmzaOracleParser.parseFramed stages.openingInput =
        some (SmallWoodTranscript.decsOpeningDomain, payload.bytes) ∧
      claimedPolynomials (queryCoefficients payload) =
        currentStageClaims stages.heads (currentStageTails wire) := by
  obtain ⟨rows, _rowsBuilt, parsed, _normalized, _edge⟩ :=
    current_decs_opening_edge406 ns hPiop stages.heads wire.pcs.rcombiTails
      stages.openingInput stages.openingBuilt
  let payload : V8SmzaOracleParser.Payload :=
    ⟨.decs, (SmzaRp05ExecutableChallengeStage.digestWords hPiop ++ rows).flatMap
      (HegemonCrypto.CanonicalBytes.encodeLE 8)⟩
  refine ⟨payload, ?_, ?_⟩
  · exact parsed
  · funext combination
    rw [SmzaRp04TracePrefixes.query_coefficients_reconstruct_interpolation]
    have interpolationEq : queryPolynomial payload combination =
        currentQueryPolynomial stages.heads (currentStageTails wire)
          combination.1 combination.2 := by
      unfold SmzaRp04TracePrefixes.queryPolynomial currentQueryPolynomial
      apply congrArg (fun evaluations : Fin 406 → HegemonCrypto.SmallWood.Goldilocks =>
        Lagrange.interpolate (Finset.univ : Finset (Fin 406))
          (fun index : Fin 406 => (index.val : HegemonCrypto.SmallWood.Goldilocks))
          evaluations)
      funext index
      exact generated_opening_evaluation_readback stages rows _rowsBuilt
        combination index
    exact interpolationEq

end
end HegemonCrypto.SmallWood.SmzaRp05CurrentClaimCoefficientReadback
