import HegemonCrypto.NativePrivateSpendQ58CurrentDecsTraceDensity
import HegemonCrypto.NativePrivateSpendQ58CurrentActualTraceLabel
import SmzaRp05CurrentRawSampleReadback
import SmzaQ38DistinctCollector
import SmzaRp05CurrentResponsePrequeryDecode

/-! Current guarded PCS rows, current28 DECS trace, same actual80-to58 raw query,
and computed small-support/LVCS inclusion. Pure generic parser/collector reuse.
SOURCE ONLY; parent derives active-record coverage and physical mass. -/
namespace HegemonCrypto.SmallWood.NativePrivateSpendQ58CurrentDecsLiteralInclusion

local macro "decs_candidate_some_eq%" : term => do
  let kernelName := Lean.Name.appendCore
    (Lean.Name.num `_private.HegemonCrypto.NativePrivateSpendQ58CurrentDecsTraceDensity 0)
    `HegemonCrypto.SmallWood.NativePrivateSpendQ58CurrentDecsTraceDensity.discrepanciesFromCandidate_some
  pure ⟨(Lean.mkCIdent kernelName).raw⟩


open Polynomial
open HegemonCrypto.CanonicalBytes (Byte encodeLE)
open SmzaRp05ExecutableMerkleVerifier (Program Oracle)
open SmzaRp05ExecutableChallengeStage (FieldWord digestWords returnedWords pendingFailure scan)
open SmzaRp05PcsWireProjection (fieldWordsToGoldilocks)
open SmzaRp05FilteredDecoderInstability (RawRecords)
open SmzaRecordedTracePath (RecordsCollisionFree readPath selected_input_of_recorded)
open V8Smz9CoherentMerkleGeometry (extract)
open V8Smz9CappedRawSampler (RawByteBlock)
open V8Smz9RawCounterCompiler (digestCallCap)
open SmzaRp04RawRoleSampling (rawFieldSample q38CandidateIndex)
open V8Smz9RuntimeRandomness (IdealFieldCoin)
open Hegemon.Transaction.SmallWoodProductionConstraintRefinement (goldilocksModulus)
open scoped Classical
namespace F
export NativePrivateSpendQ58CurrentFullStageEnvelope
 (RawInput RawDigest Trace frame roleName rawPayload rawNext payloadNext payloadBytes raw_payload_frame)
end F
namespace E
export NativePrivateSpendQ58CurrentExecutableVerifier
 (Wire DecodedFields Opening PcsOutput pcsProgram decsInput fieldKeys fieldXof queryProgram queryResult)
end E
namespace P
export NativePrivateSpendQ58CurrentAcceptedPcsFacts
 (pcs_execution_has_actual_facts pcs_execution_heads_are_lvcs_heads)
end P
namespace C
export NativePrivateSpendQ58CurrentChronologicalRequest (collectCurrentIndices sortedCurrentIndices)
end C
namespace U
export NativePrivateSpendQ58CurrentSuccessfulFiber
 (Query CandidateStream firstDistinct selectedSet streamCandidates decoder rawDecoder decoder_eq_some_iff)
end U
namespace O
export NativePrivateSpendQ58CurrentOrdinaryRecovery (Position actualSample PriorBad actualView)
end O
namespace S
export NativePrivateSpendQ58CurrentSourceCandidate
 (SourceLabel labelFromInputs labelView calculatedSupport calculatedCandidate)
end S
namespace D
export NativePrivateSpendQ58CurrentDecsTraceDensity
 (traceBytes traceRowValues tracePolynomial discrepancies traceEvent)
end D
namespace N
export NativePrivateSpendQ58CurrentDecsSampleDensity (mem_sample_event_iff)
end N
namespace V
export NativePrivateSpendQ58CurrentLvcsEventJoin
 (Combination actualCombinationPolynomial combinationPolynomial discrepancy CurrentLvcsRootEvent)
end V
namespace G
export NativePrivateSpendQ58CurrentRecoveryGeometry
 (MatrixBad SmallSupportBad RecoveryGeometry pcs_execution_has_geometry_or_named_bad_event)
end G
namespace A
export NativePrivateSpendQ58CurrentActualTraceLabel
 (sourceRecords pcsRecords current_source_valid_input_is_unparsed)
end A
namespace FL
export NativePrivateSpendQ58CurrentFullLogReadback (pcs_execution_has_actual_log_parts)
end FL
namespace L
export NativePrivateSpendQ58CurrentAcceptedLeafSupport (currentPoint)
end L
noncomputable section
set_option autoImplicit false
set_option Elab.async false
set_option maxHeartbeats 0
set_option maxRecDepth 0
local instance : DecidableEq F.RawInput :=
 @instDecidableEqList HegemonCrypto.CanonicalBytes.Byte
  (inferInstance : DecidableEq HegemonCrypto.CanonicalBytes.Byte)

def literalRows (heads tails : List (List Goldilocks)) : List (List Goldilocks) :=
 (heads.zip tails).map fun pair => pair.1 ++ pair.2

def literalWords (digest : F.RawDigest) (heads tails : List (List Goldilocks)) : List Nat :=
 digestWords digest ++ (literalRows heads tails).flatten.map (fun value => value.val)

def literalBytes (digest : F.RawDigest) (heads tails : List (List Goldilocks)) : List Byte :=
 (literalWords digest heads tails).flatMap (encodeLE 8)

private theorem rows_flatten_words (heads tails : List (List Goldilocks)) :
  (heads.zip tails).flatMap (fun pair => (pair.1 ++ pair.2).map (fun value => value.val)) =
   (literalRows heads tails).flatten.map (fun value => value.val) := by
  simp only [literalRows, List.flatten_eq_flatMap, List.map_flatMap, List.flatMap_map]
  rfl

theorem decs_input_is_literal_frame (digest : F.RawDigest) (heads tails : List (List Goldilocks)) :
  E.decsInput digest heads tails =
   F.frame (F.roleName .decs) (literalWords digest heads tails).length
    (literalBytes digest heads tails) := by
 simp only [E.decsInput, literalWords, literalBytes, rows_flatten_words]

private theorem encoded_length (words : List Nat) :
  (words.flatMap (encodeLE 8)).length = 8 * words.length := by
 induction words with
 | nil => rfl
 | cons head tail ih =>
   simp only [List.flatMap_cons, List.length_append, List.length_cons,
    HegemonCrypto.CanonicalBytes.encodeLE_length, ih]
   omega

private theorem encode_flatten (words : List Nat) :
  words.flatMap (encodeLE 8) = (words.map (encodeLE 8)).flatten := by
 induction words with
 | nil => rfl
 | cons head tail ih => simp only [List.flatMap_cons, List.map_cons, List.flatten_cons, ih]

private theorem literal_rows_shape (heads tails : List (List Goldilocks))
  (headCount : heads.length = 12) (tailCount : tails.length = 12)
  (headShape : ∀ row ∈ heads, row.length = 13115)
  (tailShape : ∀ row ∈ tails, row.length = 58) :
  (literalRows heads tails).length = 12 ∧
   ∀ row ∈ literalRows heads tails, row.length = 13173 := by
 constructor
 · simp [literalRows, headCount, tailCount]
 · intro row member
   obtain ⟨pair, pairMember, rfl⟩ := List.mem_map.mp member
   have left := List.of_mem_zip pairMember
   simp only [List.length_append, headShape pair.1 left.1, tailShape pair.2 left.2]

private theorem literal_row_getD (heads tails : List (List Goldilocks)) (row : Nat)
  (headBound : row < heads.length) (tailBound : row < tails.length) :
  (literalRows heads tails).getD row [] = heads.getD row [] ++ tails.getD row [] := by
 have zipBound : row < (heads.zip tails).length := by simp [List.length_zip]; omega
 rw [List.getD_eq_getElem _ [] (by simpa [literalRows] using zipBound)]
 simp only [literalRows, List.getElem_map, List.getElem_zip]
 rw [List.getD_eq_getElem heads [] headBound, List.getD_eq_getElem tails [] tailBound]

private theorem literal_words_length (digest : F.RawDigest) (heads tails : List (List Goldilocks))
  (shape : (literalRows heads tails).length = 12 ∧
   ∀ row ∈ literalRows heads tails, row.length = 13173) :
  (literalWords digest heads tails).length = 158084 := by
 have rowsNatShape : ∀ row ∈ (literalRows heads tails).map (List.map (fun value : Goldilocks => value.val)),
   row.length = 13173 := by
  intro row member
  obtain ⟨values, present, rfl⟩ := List.mem_map.mp member
  simpa using shape.2 values present
 have len := V8Smz9HonestHashMaterialization.rectangular_flatten_length
  ((literalRows heads tails).map (List.map (fun value : Goldilocks => value.val))) 13173 rowsNatShape
 simp only [← List.map_flatten, List.length_map] at len
 simp only [literalWords, List.length_append, List.length_map, digestWords,
  List.length_map, List.length_range, len, shape.1]

variable (ns : NativePrivateSpendQ58CurrentCompactMerkle.Namespace) (pending : Bool)
 (wire : E.Wire) (decoded : E.DecodedFields) (opening : E.Opening)
 (oracle : Oracle) (output : E.PcsOutput)
 (executed : (E.pcsProgram ns pending wire decoded opening).eval oracle = some output)

include ns pending wire decoded opening oracle output executed in
theorem pcs_current_shape :
  output.heads.length = 12 ∧ decoded.pcs.rcombiTails.length = 12 ∧
   (∀ row ∈ output.heads, row.length = 13115) ∧
   ∀ row ∈ decoded.pcs.rcombiTails, row.length = 58 := by
 obtain ⟨_, _, _, headsBuilt, _⟩ := P.pcs_execution_has_actual_facts
  ns pending wire decoded opening oracle output executed
 have guard : ¬ (output.heads.length ≠ 12 ∨ decoded.pcs.rcombiTails.length ≠ 12 ∨
   output.heads.any (fun row => decide (row.length ≠ 13115)) ∨
   decoded.pcs.rcombiTails.any (fun row => decide (row.length ≠ 58))) := by
  intro bad
  simp only [E.pcsProgram, headsBuilt, if_pos bad, Program.eval] at executed
  cases executed
 have guards := guard
 simp only [not_or, not_not, Bool.not_eq_true, List.any_eq_false,
  decide_eq_false_iff_not, not_not] at guards
 exact guards

include ns pending wire decoded opening oracle output executed in
private theorem actual_rows_shape :
  (literalRows output.heads (decoded.pcs.rcombiTails.map fieldWordsToGoldilocks)).length = 12 ∧
   ∀ row ∈ literalRows output.heads (decoded.pcs.rcombiTails.map fieldWordsToGoldilocks),
    row.length = 13173 := by
 obtain ⟨headCount, tailCount, headShape, tailShape⟩ :=
  pcs_current_shape ns pending wire decoded opening oracle output executed
 apply literal_rows_shape output.heads (decoded.pcs.rcombiTails.map fieldWordsToGoldilocks)
  headCount (by simp [tailCount]) headShape
 intro row member
 obtain ⟨values, present, rfl⟩ := List.mem_map.mp member
 simpa [fieldWordsToGoldilocks] using tailShape values present

include ns pending wire decoded opening oracle output executed in
theorem pcs_literal_payload :
  F.rawPayload (E.decsInput wire.hPiop output.heads
    (decoded.pcs.rcombiTails.map fieldWordsToGoldilocks)) =
   some ⟨.decs, literalBytes wire.hPiop output.heads
    (decoded.pcs.rcombiTails.map fieldWordsToGoldilocks)⟩ ∧
  F.rawNext .decs (E.decsInput wire.hPiop output.heads
    (decoded.pcs.rcombiTails.map fieldWordsToGoldilocks)) = some [(.piop, wire.hPiop)] := by
  have shape := actual_rows_shape ns pending wire decoded opening oracle output executed
  have len := literal_words_length wire.hPiop output.heads _ shape
  have bytesLen := encoded_length (literalWords wire.hPiop output.heads
    (decoded.pcs.rcombiTails.map fieldWordsToGoldilocks))
  rw [len] at bytesLen
  have aligned : (literalBytes wire.hPiop output.heads
      (decoded.pcs.rcombiTails.map fieldWordsToGoldilocks)).length = 8 * 158084 := by
    exact bytesLen
  have payloadLength : (literalBytes wire.hPiop output.heads
      (decoded.pcs.rcombiTails.map fieldWordsToGoldilocks)).length = F.payloadBytes .decs :=
    aligned.trans (by norm_num [F.payloadBytes])
  have parsed := F.raw_payload_frame .decs 158084
    (literalBytes wire.hPiop output.heads (decoded.pcs.rcombiTails.map fieldWordsToGoldilocks))
    (by decide) aligned payloadLength
  rw [decs_input_is_literal_frame, len]
  refine ⟨parsed, ?_⟩
  rw [F.rawNext, parsed, Option.bind_some]
  simp only [F.payloadNext, literalBytes, literalWords, List.flatMap_append,
    SmzaRp05CurrentDecsFrameReadback.digest_words_encode_exact,
    SmzaRp05ExecutableMerkleVerifier.digest_at_ofFn_append]

private theorem literal_word_at (digest : F.RawDigest) (heads tails : List (List Goldilocks))
  (shape : (literalRows heads tails).length = 12 ∧
   ∀ row ∈ literalRows heads tails, row.length = 13173)
  (row : Fin 12) (cell : Fin 13173) :
  V8SmzaOracleParser.wordAt (literalBytes digest heads tails)
    (8 + 13173 * row.val + cell.val) =
   (((literalRows heads tails).getD row.val []).getD cell.val 0).val := by
 let natRows := (literalRows heads tails).map (List.map (fun value : Goldilocks => value.val))
 have rowShape : ∀ values ∈ natRows, values.length = 13173 := by
  intro values member
  obtain ⟨source, present, rfl⟩ := List.mem_map.mp member
  simpa using shape.2 source present
 have rowBound : row.val < natRows.length := by
  simpa only [natRows, List.length_map, shape.1] using row.isLt
 have flatLength := V8Smz9HonestHashMaterialization.rectangular_flatten_length natRows 13173 rowShape
 have cellEq : (literalWords digest heads tails).getD (8 + 13173 * row.val + cell.val) 0 =
   (((literalRows heads tails).getD row.val []).getD cell.val 0).val := by
  simp only [literalWords, List.map_flatten]
  change (digestWords digest ++ natRows.flatten).getD _ 0 = _
  have «prefix» : (digestWords digest).length = 8 := by simp [digestWords]
  rw [List.getD_append_right _ _ _ _ (by rw [«prefix»]; omega)]
  rw [«prefix»]
  have offset : 8 + 13173 * row.val + cell.val - 8 = row.val * 13173 + cell.val := by omega
  rw [offset, V8Smz9HonestHashMaterialization.rectangular_flatten_getD
   natRows 13173 row.val cell.val rowShape rowBound cell.isLt]
  cases rowRead : (literalRows heads tails)[row.val]? with
  | none => simp [natRows, rowRead]
  | some values =>
    cases valueRead : values[cell.val]? <;> simp [natRows, rowRead, valueRead]
 have indexBound : 8 + 13173 * row.val + cell.val < (literalWords digest heads tails).length := by
   rw [literal_words_length digest heads tails shape]
   have := row.isLt
   have := cell.isLt
   omega
 have wordBound : (literalWords digest heads tails).getD (8 + 13173 * row.val + cell.val) 0 < 256 ^ 8 := by
   rw [cellEq]
   exact lt_trans (((literalRows heads tails).getD row.val []).getD cell.val 0).val_lt
     (by norm_num [goldilocksModulus])
 rw [literalBytes, encode_flatten]
 exact (SmzaRp05CurrentResponsePrequeryDecode.word_at_encoded_words
   (literalWords digest heads tails) (8 + 13173 * row.val + cell.val) indexBound wordBound).trans cellEq

include ns pending wire decoded opening oracle output executed in
theorem recorded_decs_trace
  (records : RawRecords) (free : RecordsCollisionFree records)
  (digest : F.RawDigest)
  (recorded : (E.decsInput wire.hPiop output.heads
   (decoded.pcs.rcombiTails.map fieldWordsToGoldilocks), digest) ∈ records) :
  extract F.rawNext records 28 .decs digest =
   .record (E.decsInput wire.hPiop output.heads
    (decoded.pcs.rcombiTails.map fieldWordsToGoldilocks))
    [extract F.rawNext records 27 .piop wire.hPiop] := by
 have edge := (pcs_literal_payload
  ns pending wire decoded opening oracle output executed).2
 have selected := selected_input_of_recorded F.rawNext records free .decs digest
  (E.decsInput wire.hPiop output.heads (decoded.pcs.rcombiTails.map fieldWordsToGoldilocks))
  recorded (by simp [edge])
 simp only [extract, selected, edge, List.map_cons, List.map_nil]

include ns pending wire decoded opening oracle output executed in
theorem trace_rows_are_actual
  (records : RawRecords) (free : RecordsCollisionFree records)
  (digest : F.RawDigest)
  (recorded : (E.decsInput wire.hPiop output.heads
   (decoded.pcs.rcombiTails.map fieldWordsToGoldilocks), digest) ∈ records)
  (combination : V.Combination) :
  D.traceRowValues (extract F.rawNext records 28 .decs digest) combination =
   output.heads.getD (2 * combination.1.val + combination.2.val) [] ++
   (decoded.pcs.rcombiTails.map fieldWordsToGoldilocks).getD
    (2 * combination.1.val + combination.2.val) [] := by
  have shape := actual_rows_shape ns pending wire decoded opening oracle output executed
  obtain ⟨headCount, tailCount, _, _⟩ :=
    pcs_current_shape ns pending wire decoded opening oracle output executed
  let row : Fin 12 := ⟨2 * combination.1.val + combination.2.val,
    by have := combination.1.isLt; have := combination.2.isLt; omega⟩
  have rowEq := literal_row_getD output.heads
    (decoded.pcs.rcombiTails.map fieldWordsToGoldilocks) row.val
    (by rw [headCount]; exact row.isLt) (by simp [tailCount, row.isLt])
  have valuesLength : ((literalRows output.heads
      (decoded.pcs.rcombiTails.map fieldWordsToGoldilocks)).getD row.val []).length = 13173 := by
    rw [List.getD_eq_getElem _ [] (by rw [shape.1]; exact row.isLt)]
    exact shape.2 _ (List.getElem_mem _)
  rw [← rowEq]
  apply List.ext_getElem
  · simp only [D.traceRowValues, List.length_ofFn, valuesLength]
  · intro cell leftBound rightBound
    have cellBound : cell < 13173 := by
      simpa only [D.traceRowValues, List.length_ofFn] using leftBound
    have raw := recorded_decs_trace
      ns pending wire decoded opening oracle output executed records free digest recorded
    have payload := (pcs_literal_payload
      ns pending wire decoded opening oracle output executed).1
    simp only [D.traceRowValues, List.getElem_ofFn, D.traceBytes, raw, readPath,
      Option.bind_some, payload, Option.map_some, Option.getD_some]
    rw [literal_word_at wire.hPiop output.heads _ shape row ⟨cell, cellBound⟩]
    have cellRead := List.getD_eq_getElem
      ((literalRows output.heads (decoded.pcs.rcombiTails.map fieldWordsToGoldilocks)).getD row.val [])
      0 rightBound
    rw [cellRead]
    exact toGoldilocks_fromGoldilocks _

include ns pending wire decoded opening oracle output executed in
theorem trace_polynomial_is_actual
  (records : RawRecords) (free : RecordsCollisionFree records)
  (digest : F.RawDigest)
  (recorded : (E.decsInput wire.hPiop output.heads
   (decoded.pcs.rcombiTails.map fieldWordsToGoldilocks), digest) ∈ records)
  (combination : V.Combination) :
  D.tracePolynomial (extract F.rawNext records 28 .decs digest) combination =
   V.actualCombinationPolynomial decoded.pcs output.heads combination := by
 unfold D.tracePolynomial V.actualCombinationPolynomial
 rw [trace_rows_are_actual
  ns pending wire decoded opening oracle output executed records free digest recorded]

theorem collector_is_filtered
  (candidates : List IdealFieldCoin) (selected : List O.Position) :
  C.collectCurrentIndices candidates selected =
   SmzaQ38DistinctCollector.collectDistinct 58 (candidates.filterMap q38CandidateIndex) selected := by
  have indexLiteral : ∀ candidate : IdealFieldCoin, q38CandidateIndex candidate =
      if candidate.val < (goldilocksModulus / 8388608) * 8388608 then
        some (⟨candidate.val % 8388608, Nat.mod_lt _ (by decide)⟩ : O.Position) else none := by
    intro candidate
    unfold q38CandidateIndex
    rw [SmzaRp04RawRoleSampling.q38_accepted_factor_bound_eq_source]
    rfl
  induction candidates generalizing selected with
  | nil => rfl
  | cons candidate rest ih =>
    erw [C.collectCurrentIndices]
    by_cases full : selected.length = 58
    · erw [if_pos full]
      exact (SmzaQ38DistinctCollector.collectDistinct_full 58 _ selected full).symm
    · erw [if_neg full]
      by_cases accepted : candidate.val < (goldilocksModulus / 8388608) * 8388608
      · have decoded : q38CandidateIndex candidate = some
            (⟨candidate.val % 8388608, Nat.mod_lt _ (by decide)⟩ : O.Position) := by
          erw [indexLiteral, if_pos accepted]
        erw [if_pos accepted, List.filterMap_cons_some decoded]
        unfold SmzaQ38DistinctCollector.collectDistinct
        erw [if_neg full]
        split
        · rename_i duplicate
          erw [if_pos duplicate]
          exact ih selected
        · rename_i fresh
          erw [if_neg fresh]
          exact ih _
      · have decoded : q38CandidateIndex candidate = none := by
          erw [indexLiteral, if_neg accepted]
          rfl
        erw [if_neg accepted, List.filterMap_cons_none decoded]
        exact ih selected

theorem collector_is_first_distinct (candidates : List IdealFieldCoin) :
  C.collectCurrentIndices candidates [] = U.firstDistinct candidates := by
  rw [collector_is_filtered]
  exact SmzaQ38DistinctCollector.collectDistinct_empty (α := O.Position) 58
    (candidates.filterMap q38CandidateIndex)

private theorem sorted_current_indices_nodup (candidates : List IdealFieldCoin) :
    (C.sortedCurrentIndices candidates).Nodup := by
  unfold C.sortedCurrentIndices
  rw [collector_is_first_distinct]
  exact (NativePrivateSpendQ58CurrentSuccessfulFiber.first_distinct_nodup candidates).mergeSort

theorem sorted_support_is_counted (candidates : List IdealFieldCoin) :
  (C.sortedCurrentIndices candidates).toFinset = U.selectedSet candidates := by
 unfold C.sortedCurrentIndices
 have same := List.mergeSort_perm (C.collectCurrentIndices candidates [])
  (fun left right => decide (left.val ≤ right.val))
 rw [List.toFinset_eq_of_perm _ _ same, collector_is_first_distinct]
 rfl

def actualRawBlocks (oracle : Oracle) (digest : F.RawDigest) :
  Fin (digestCallCap 80) → RawByteBlock := fun counter =>
 oracle (NativePrivateSpendQ58CurrentRoleClassifier.canonicalCurrentQueryBytes
  ⟨.decsSample, digest, 0, counter.val⟩)

theorem scan_is_actual_raw_sample (oracle : Oracle) (digest : F.RawDigest) :
  scan oracle 80 [] (E.fieldKeys .decsSample 80 digest) =
   (rawFieldSample (digestCallCap 80) 80 (actualRawBlocks oracle digest)).map List.ofFn := by
 have keys : E.fieldKeys .decsSample 80 digest =
   List.ofFn (fun counter : Fin (digestCallCap 80) =>
    NativePrivateSpendQ58CurrentRoleClassifier.canonicalCurrentQueryBytes
     ⟨.decsSample, digest, 0, counter.val⟩) := by
  unfold E.fieldKeys
  rw [List.ofFn_eq_pmap]
  simp only [List.pmap_eq_map]
  rfl
 rw [keys]
 exact SmzaRp05CurrentRawSampleReadback.source_scan_eq_raw_field_sample 80 _ oracle

private theorem pending_failure_none (pending : Bool) :
    pendingFailure pending (none : Option (List FieldWord)) = true := by
  cases pending <;> rfl

private theorem symbolic_query_result_facts (selected : List Nat) (flag : Bool)
    (indices : List Nat) (out : Bool)
    (result : (if selected.length = 58 then some (selected, flag) else none) = some (indices, out)) :
    selected.length = 58 ∧ indices = selected ∧ flag = out := by
  by_cases enough : selected.length = 58
  · rw [if_pos enough] at result
    have pair := Option.some.inj result
    exact ⟨enough, (congrArg Prod.fst pair).symm, congrArg Prod.snd pair⟩
  · rw [if_neg enough] at result
    cases result

private theorem query_result_facts (pending : Bool) (sampled : Option (List FieldWord))
    (indices : List Nat) (out : Bool)
    (result : E.queryResult pending sampled = some (indices, out)) :
    ((C.sortedCurrentIndices (returnedWords 80 sampled)).map Fin.val).length = 58 ∧
    indices = (C.sortedCurrentIndices (returnedWords 80 sampled)).map Fin.val ∧
    pendingFailure pending sampled = out := by
  exact symbolic_query_result_facts
    ((C.sortedCurrentIndices (returnedWords 80 sampled)).map Fin.val)
    (pendingFailure pending sampled) indices out result

private theorem query_result_pending (pending : Bool) (sampled : Option (List FieldWord))
    (indices : List Nat) (out : Bool)
    (result : E.queryResult pending sampled = some (indices, out)) :
    pendingFailure pending sampled = out :=
  (query_result_facts pending sampled indices out result).2.2

private theorem query_result_some_facts (pending : Bool) (words : List FieldWord)
    (indices : List Nat) (out : Bool)
    (result : E.queryResult pending (some words) = some (indices, out)) :
    (C.sortedCurrentIndices words).length = 58 ∧
    indices = (C.sortedCurrentIndices words).map Fin.val := by
  have facts := query_result_facts pending (some words) indices out result
  have mappedLength : ((C.sortedCurrentIndices words).map Fin.val).length = 58 := facts.1
  have length : (C.sortedCurrentIndices words).length = 58 := by
    simpa only [List.length_map] using mappedLength
  exact ⟨length, facts.2.1⟩

private theorem pending_failure_none_mapped (pending : Bool) :
    pendingFailure pending ((none : Option U.CandidateStream).map List.ofFn) = true := by
  cases pending <;> rfl

private theorem mapped_sample_query_facts (pending : Bool)
    (sampled : Option U.CandidateStream) (indices : List Nat) (out : Bool)
    (result : E.queryResult pending (sampled.map List.ofFn) = some (indices, out))
    (clean : out = false) :
    ∃ stream : U.CandidateStream, sampled = some stream ∧
      (C.sortedCurrentIndices (List.ofFn stream)).length = 58 ∧
      indices = (C.sortedCurrentIndices (List.ofFn stream)).map Fin.val := by
  cases sampled with
  | none =>
    have same := query_result_pending pending
      ((none : Option U.CandidateStream).map List.ofFn) indices out result
    have impossible : true = false :=
      (pending_failure_none_mapped pending).symm.trans (same.trans clean)
    cases impossible
  | some stream =>
    have facts := query_result_facts pending
      ((some stream : Option U.CandidateStream).map List.ofFn) indices out result
    have wordsEq : returnedWords 80 ((some stream : Option U.CandidateStream).map List.ofFn) =
        List.ofFn stream := rfl
    have mappedEq := congrArg
      (fun words : List FieldWord => (C.sortedCurrentIndices words).map Fin.val) wordsEq
    have mappedLength := (congrArg List.length mappedEq).symm.trans facts.1
    have selectedLength : (C.sortedCurrentIndices (List.ofFn stream)).length = 58 := by
      simpa only [List.length_map] using mappedLength
    have indexEq := facts.2.1.trans mappedEq
    exact ⟨stream, rfl, selectedLength, indexEq⟩

theorem clean_query_has_same_raw_query
  (oracle : Oracle) (pending : Bool) (digest : F.RawDigest)
  (indices : List Nat) (sampledPending : Bool)
  (executed : (E.queryProgram pending digest).eval oracle = some (indices, sampledPending))
  (clean : sampledPending = false) :
  ∃ stream : U.CandidateStream, ∃ query : U.Query,
   rawFieldSample (digestCallCap 80) 80 (actualRawBlocks oracle digest) = some stream ∧
   U.rawDecoder (actualRawBlocks oracle digest) = some query ∧
   indices = (C.sortedCurrentIndices (List.ofFn stream)).map Fin.val ∧
   query.val = (C.sortedCurrentIndices (List.ofFn stream)).toFinset := by
  have result : E.queryResult pending (scan oracle 80 [] (E.fieldKeys .decsSample 80 digest)) =
      some (indices, sampledPending) := by
    simpa only [E.queryProgram, E.fieldXof, Program.eval_bind,
      SmzaRp05ExecutableChallengeStage.field_loop_executes_scan, Option.bind_some,
      Program.eval] using executed
  rw [scan_is_actual_raw_sample] at result
  obtain ⟨stream, rawSample, selectedLength, indexEq⟩ := mapped_sample_query_facts pending
    (rawFieldSample (digestCallCap 80) 80 (actualRawBlocks oracle digest))
    indices sampledPending result clean
  have supportEq := sorted_support_is_counted (List.ofFn stream)
  have count : (U.selectedSet (List.ofFn stream)).card = 58 := by
    have supportCard : (C.sortedCurrentIndices (List.ofFn stream)).toFinset.card =
        (U.selectedSet (List.ofFn stream)).card :=
      congrArg (fun support : Finset O.Position => support.card) supportEq
    have listedCard : (C.sortedCurrentIndices (List.ofFn stream)).toFinset.card =
        (C.sortedCurrentIndices (List.ofFn stream)).length :=
      List.toFinset_card_of_nodup (sorted_current_indices_nodup _)
    exact supportCard.symm.trans (listedCard.trans selectedLength)
  let query : U.Query := ⟨U.selectedSet (List.ofFn stream), count⟩
  have decoded : U.decoder stream = some query := (U.decoder_eq_some_iff stream query).2 rfl
  refine ⟨stream, query, rawSample, ?_, indexEq, supportEq.symm⟩
  simp only [U.rawDecoder, rawSample, Option.bind_some, decoded]

theorem coordinates_have_same_query
  (candidates : List IdealFieldCoin) (indices : List Nat) (query : U.Query)
  (indicesEq : indices = (C.sortedCurrentIndices candidates).map Fin.val)
  (queryEq : query.val = (C.sortedCurrentIndices candidates).toFinset)
  (coordinates : Fin 58 → O.Position) (distinct : Function.Injective coordinates)
  (coordinateEq : ∀ j, (coordinates j).val = indices.getD j.val 0) :
  O.actualSample coordinates distinct = query := by
 have length : (C.sortedCurrentIndices candidates).length = 58 := by
  have queryCard : query.val.card = (C.sortedCurrentIndices candidates).toFinset.card :=
   congrArg (fun support : Finset O.Position => support.card) queryEq
  have listedCard : (C.sortedCurrentIndices candidates).toFinset.card =
    (C.sortedCurrentIndices candidates).length :=
   List.toFinset_card_of_nodup (sorted_current_indices_nodup candidates)
  exact listedCard.symm.trans (queryCard.symm.trans query.property)
 have listed : List.ofFn coordinates = C.sortedCurrentIndices candidates := by
  refine no_implicit_lambda% (List.ext_getElem ?_ ?_)
  · simp [length]
  · intro index leftBound rightBound
    have indexBound : index < 58 := by simpa only [List.length_ofFn] using leftBound
    simp only [List.getElem_ofFn]
    refine no_implicit_lambda% (Fin.ext ?_)
    have same := coordinateEq ⟨index, indexBound⟩
    rw [indicesEq, List.getD_eq_getElem _ 0 (by simp [length, indexBound]), List.getElem_map] at same
    exact same
 refine no_implicit_lambda% (Subtype.ext ?_)
 change Finset.univ.image coordinates = query.val
 rw [queryEq, ← listed]
 ext position
 simp only [Finset.mem_image, Finset.mem_univ, true_and, List.mem_toFinset, List.mem_ofFn]

include ns pending wire decoded opening oracle output executed in
theorem pcs_has_same_raw_query
  (clean : output.pending = false) :
  ∃ digest : F.RawDigest, ∃ stream : U.CandidateStream, ∃ query : U.Query,
   oracle (E.decsInput wire.hPiop output.heads
    (decoded.pcs.rcombiTails.map fieldWordsToGoldilocks)) = digest ∧
   rawFieldSample (digestCallCap 80) 80 (actualRawBlocks oracle digest) = some stream ∧
   U.rawDecoder (actualRawBlocks oracle digest) = some query ∧
   output.indexes = (C.sortedCurrentIndices (List.ofFn stream)).map Fin.val ∧
   query.val = (C.sortedCurrentIndices (List.ofFn stream)).toFinset := by
 obtain ⟨digest, sampledPending, sampled, _, hashEq, queryEq, _, _, _, _, _, _, _, _, pendingEq⟩ :=
  P.pcs_execution_has_actual_facts ns pending wire decoded opening oracle output executed
 have queryClean : sampledPending = false := by
  have failed : pendingFailure sampledPending sampled = false := pendingEq.trans clean
  exact (Bool.or_eq_false_iff.mp failed).1
 obtain ⟨stream, query, raw, decodedRaw, indices, querySet⟩ :=
  clean_query_has_same_raw_query oracle pending digest output.indexes
   sampledPending queryEq queryClean
 exact ⟨digest, stream, query, hashEq, raw, decodedRaw, indices, querySet⟩

theorem small_support_is_trace_event
  (records : RawRecords) (output : E.PcsOutput) (opening : E.Opening) (trace : F.Trace)
  (bad : G.SmallSupportBad records output) :
  ∃ coordinates : Fin 58 → O.Position, ∃ distinct : Function.Injective coordinates,
   (∀ j, (coordinates j).val = output.indexes.getD j.val 0) ∧
   O.actualSample coordinates distinct ∈ D.traceEvent
    (S.labelFromInputs records output.root output.hashFpp output.gamma) opening trace := by
 obtain ⟨coordinates, distinct, indicesEq, small, supported⟩ := bad
 refine ⟨coordinates, distinct, indicesEq, ?_⟩
 refine no_implicit_lambda% ((N.mem_sample_event_iff _ _ _ _).2 ?_)
 exact Or.inl ⟨small, supported⟩

include ns pending wire decoded opening oracle output executed in
theorem lvcs_root_is_trace_event
  (records : RawRecords) (free : RecordsCollisionFree records)
  (digest : F.RawDigest)
  (recorded : (E.decsInput wire.hPiop output.heads
   (decoded.pcs.rcombiTails.map fieldWordsToGoldilocks), digest) ∈ records)
  (geometry : G.RecoveryGeometry ns wire decoded opening output records)
  (bad : V.CurrentLvcsRootEvent geometry.source opening decoded.pcs geometry.heads geometry.coordinates) :
  O.actualSample geometry.coordinates geometry.distinct ∈ D.traceEvent
   (S.labelFromInputs records output.root output.hashFpp output.gamma) opening
   (extract F.rawNext records 28 .decs digest) := by
 have headsEq : geometry.heads = output.heads := Option.some.inj
  (geometry.headsBuilt.symm.trans
   (P.pcs_execution_heads_are_lvcs_heads ns pending wire decoded opening oracle output executed))
 have calculated : S.calculatedCandidate
   (S.labelFromInputs records output.root output.hashFpp output.gamma) = some geometry.source :=
  geometry.calculated
 have same : ∀ combination,
   D.discrepancies (S.labelFromInputs records output.root output.hashFpp output.gamma) opening
     (extract F.rawNext records 28 .decs digest) combination =
    V.discrepancy geometry.source opening decoded.pcs geometry.heads combination := by
  intro combination
  simp only [D.discrepancies, calculated]
  rw [decs_candidate_some_eq%]
  rw [trace_polynomial_is_actual ns pending wire decoded opening oracle output
   executed records free digest recorded combination, ← headsEq]
  rfl
 refine no_implicit_lambda% ((N.mem_sample_event_iff _ _ _ _).2 ?_)
 refine no_implicit_lambda% (Or.inr ?_)
 obtain ⟨combination, nonzero, roots⟩ := bad
 refine ⟨combination, by rw [same]; exact nonzero, ?_⟩
 intro position member
 obtain ⟨j, _, rfl⟩ := Finset.mem_image.mp member
 rw [same]
 exact roots j

attribute [elab_without_expected_type] lvcs_root_is_trace_event

-- Finite binder types time out in the constructor-name style linter; proof checking is unchanged.
set_option linter.constructorNameAsVariable false in
include ns pending wire decoded opening oracle output executed in
/-- Ordinary PCS inclusion; parent derives source-record coverage from active claims. -/
theorem pcs_execution_event_or_recovery
  (records : RawRecords) (free : RecordsCollisionFree records)
  (covered : A.sourceRecords (A.pcsRecords ns pending wire decoded opening oracle) ⊆ records)
  (clean : output.pending = false) :
  ∃ digest : F.RawDigest, ∃ query : U.Query,
   oracle (E.decsInput wire.hPiop output.heads
    (decoded.pcs.rcombiTails.map fieldWordsToGoldilocks)) = digest ∧
   U.rawDecoder (actualRawBlocks oracle digest) = some query ∧
   (O.PriorBad ns decoded oracle output records ∨ G.MatrixBad records output ∨
    query ∈ D.traceEvent (S.labelFromInputs records output.root output.hashFpp output.gamma)
     opening (extract F.rawNext records 28 .decs digest) ∨
    ∃ geometry : G.RecoveryGeometry ns wire decoded opening output records,
     ∀ combination, V.actualCombinationPolynomial decoded.pcs geometry.heads combination =
      V.combinationPolynomial geometry.source opening combination) := by
 obtain ⟨digest, stream, query, hashEq, _raw, rawQuery, indicesEq, queryEq⟩ :=
  pcs_has_same_raw_query ns pending wire decoded opening oracle output executed clean
 obtain ⟨recordedDigest, parts⟩ := FL.pcs_execution_has_actual_log_parts
  ns pending wire decoded opening oracle output executed
 let input := E.decsInput wire.hPiop output.heads (decoded.pcs.rcombiTails.map fieldWordsToGoldilocks)
 have own : (input, recordedDigest) ∈ ((E.pcsProgram ns pending wire decoded opening).record oracle).2 := by
  rw [parts]
  simp only [List.mem_append, List.mem_singleton]
  exact Or.inl (Or.inl (Or.inl (Or.inl rfl)))
 have digestEq : recordedDigest = digest :=
  (Program.recorded_call oracle (E.pcsProgram ns pending wire decoded opening) _ own).trans hashEq
 have edge := (pcs_literal_payload
  ns pending wire decoded opening oracle output executed).2
 have unparsed := A.current_source_valid_input_is_unparsed .decs input (by exact Option.isSome_iff_exists.mpr ⟨_, edge⟩)
 have recorded : (input, digest) ∈ records := by
  refine no_implicit_lambda% (covered ?_)
  refine no_implicit_lambda% (Finset.mem_filter.mpr ?_)
  rw [← digestEq]
  exact ⟨List.mem_toFinset.mpr own, unparsed⟩
 refine ⟨digest, query, hashEq, rawQuery, ?_⟩
 rcases G.pcs_execution_has_geometry_or_named_bad_event
   ns pending wire decoded opening oracle output records executed clean with prior | priorRemainder
 · exact Or.inl prior
 · rcases priorRemainder with matrix | matrixRemainder
   · exact Or.inr (Or.inl matrix)
   · rcases matrixRemainder with small | nonemptyGeometry
     · obtain ⟨coordinates, distinct, coordinatesEq, member⟩ :=
         small_support_is_trace_event records output opening
           (extract F.rawNext records 28 .decs digest) small
       have same := coordinates_have_same_query (List.ofFn stream) output.indexes query
         indicesEq queryEq coordinates distinct coordinatesEq
       rw [same] at member
       apply Or.inr
       apply Or.inr
       apply Or.inl
       run_tac do
         let fvarId ← Lean.Elab.Tactic.getFVarId (Lean.mkIdent `member)
         Lean.Elab.Tactic.closeMainGoalUsing `exact fun expectedType _ => do
           let e := Lean.mkFVar fvarId
           let eType ← Lean.Meta.inferType e
           unless (← Lean.Meta.withAssignableSyntheticOpaque (Lean.Meta.isDefEq eType expectedType)) do
             Lean.Elab.Term.throwTypeMismatchError none expectedType eType e
           return e
     · rcases nonemptyGeometry with ⟨geometry⟩
       rcases NativePrivateSpendQ58CurrentRecoveryGeometry.geometry_has_identities_or_literal_lvcs_event
         ns wire decoded opening output records geometry with identities | root
       · exact Or.inr (Or.inr (Or.inr ⟨geometry, identities⟩))
       · have member := by
           with_reducible exact (lvcs_root_is_trace_event ns pending wire decoded opening oracle output executed records free digest recorded geometry root)
         have same := coordinates_have_same_query (List.ofFn stream) output.indexes query
           indicesEq queryEq geometry.coordinates geometry.distinct geometry.indicesEq
         rw [same] at member
         apply Or.inr
         apply Or.inr
         apply Or.inl
         run_tac do
           let fvarId ← Lean.Elab.Tactic.getFVarId (Lean.mkIdent `member)
           Lean.Elab.Tactic.closeMainGoalUsing `exact fun expectedType _ => do
             let e := Lean.mkFVar fvarId
             let eType ← Lean.Meta.inferType e
             unless (← Lean.Meta.withAssignableSyntheticOpaque (Lean.Meta.isDefEq eType expectedType)) do
               Lean.Elab.Term.throwTypeMismatchError none expectedType eType e
             return e

end
end HegemonCrypto.SmallWood.NativePrivateSpendQ58CurrentDecsLiteralInclusion
