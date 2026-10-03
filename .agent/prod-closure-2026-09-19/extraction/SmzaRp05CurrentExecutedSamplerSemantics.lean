import SmzaRp05ExecutablePcsClosureSampling
import SmzaRp05ExecutableChallengeStage
import HegemonCrypto.SmallWoodV8Smz9HonestRequestSchedule
import SmzaRp05Q38ExecutionCountBridge
import SmzaRp05CurrentDecsFrameReadback
import SmzaRp05CurrentRawFieldScan
import Q38Rp05CurrentPostfinal
import Q38Rp05RawInputPartition
import HegemonCrypto.SmallWoodV8Smz9RuntimeRandomness
import HegemonCrypto.SmallWoodTranscript

/-! # Deterministic semantics of the executed q38 sampler

This file links the executable byte-block scan and the bounded current-profile
source field reader at the level of the actual oracle outputs. It also exposes
the exact scan words and sorted collector result forced by a successful
`PcsStages.queryExecuted` with a clean pending flag.
-/

namespace HegemonCrypto.SmallWood.SmzaRp05CurrentExecutedSamplerSemantics

open HegemonCrypto.CanonicalBytes (Byte)
open SmzaRp05ExecutableMerkleVerifier (Oracle)
open SmzaRp05ExecutablePcsClosureStages (PcsStages)
open SmzaRp05ExecutablePcsClosure (queryResult)
open SmzaRp05ExecutablePcsClosureSampling (query_program_exact query_execution_clean)
open SmzaRp05ExecutableChallengeStage (FieldWord scan acceptedWords digestWords)
open V8Smz9HonestRequestSchedule (sourceFieldReadLoop NonleafProgram sourceDigestWords sourceDigest)
open V8Smz9HonestOpeningSchedule (sourceReturnedWords sourcePendingFailure)
open V8Smz9CoherentMerkleInstrument (rawDigestBits)
open V8Smz9CoherentMerkleGeometry (RawDigest)
open V8Smz9HiddenPatch (LeafIndex)
open V8Smz9RawCounterCompiler (digestCallCap)
open SmzaRp04RawRoleSampling (q38CandidateCount)
open V8Smz9RuntimeRandomness (IdealFieldCoin)
open SmzaQ38McaSourceBinding (Position)
open SmzaRp04RawRoleSampling (q38AcceptedFactorBound q38DomainSize q38SelectedIndexSet)
open SmzaQ38McaSourceBinding (Query)
open SmzaRp05Q38ExecutionCountBridge
  (accepted_bound_is_source_literal source_sorted_support_eq_counted_support
    sampled_targets_support targetSupport)
open SmzaRp05ExecutableChallengeStage (counterInput counterKeys)
open Q38Rp05CurrentPostfinal (currentFixedIndexKey currentFixedIndexXof)
open Q38Rp05RawInputPartition (Rp05OtherRawInput rp05RawBytes rp05_source_counter_key_is_literal_input rp05SourcePrefix)
open HegemonCrypto.CanonicalBytes (encodeLE)
open SmzaRp04RawRoleSampling (q38CandidateCount)
open SmzaRp05CurrentDecsFrameReadback
open HegemonCrypto.SmallWood.SmzaRp05CurrentRawFieldScan
open Q38Rp05PostFinalCompiler (collectIndices)

set_option autoImplicit false
set_option maxRecDepth 12000
set_option maxHeartbeats 1500000
noncomputable section

private def currentSamplerKey (bound : Nat) (largeEnough : 39162 ≤ bound)
    (digest : RawDigest) (counter : Fin (digestCallCap q38CandidateCount)) :
    Rp05OtherRawInput bound :=
  currentFixedIndexKey bound largeEnough (rawDigestBits digest) ⟨counter.val, by
    have cap : digestCallCap q38CandidateCount = 11 := by decide
    have h : counter.val < 11 := by simpa [cap] using counter.isLt
    exact Nat.lt_trans h (by decide)⟩

/-- Literal input bytes for each counter in the current source sampler. -/
private theorem current_sampler_key_is_literal_counter_input (bound : Nat)
    (largeEnough : 39162 ≤ bound) (digest : RawDigest)
    (counter : Fin (digestCallCap q38CandidateCount)) :
    rp05RawBytes (.inr (currentSamplerKey bound largeEnough digest counter)) =
      counterInput HegemonCrypto.SmallWoodTranscript.decsFixedSamplingDomain digest counter.val := by
  have sourceWords : sourceDigestWords (rawDigestBits digest) = digestWords digest :=
    source_digest_words_eq_executed_words digest
  have words :
      (sourceDigestWords (rawDigestBits digest)).flatMap (encodeLE 8) = List.ofFn digest := by
    rw [sourceWords]
    exact SmzaRp05CurrentDecsFrameReadback.digest_words_encode_exact digest
  simp only [currentSamplerKey, currentFixedIndexKey]
  rw [rp05_source_counter_key_is_literal_input]
  simp only [rp05SourcePrefix, counterInput,
    V8Smz9RawCounterCompiler.counterInput,
    V8Smz9HonestRequestSchedule.source_digest_word_count,
    ← List.flatMap_def]
  rw [words]
  rfl

private theorem ofFn_fin_val_eq_range_map {α : Type*} {n : Nat} (f : Nat → α) :
    List.ofFn (fun index : Fin n => f index.val) = (List.range n).map f := by
  rw [List.ofFn_eq_pmap]
  simp only [List.pmap_eq_map]

/-- The actual current source reader consumes byte-for-byte the executable
counter list. Consequently its interpreted output is the very scan result
recorded by `PcsStages.queryExecuted`, not an independent sampler run. -/
theorem current_source_xof_eq_executed_scan
    (bound : Nat) (largeEnough : 39162 ≤ bound) (digest : RawDigest)
    (oracle : Oracle) :
    NonleafProgram.interpret
        (fun key => rawDigestBits (oracle (rp05RawBytes (.inr key))))
        (currentFixedIndexXof bound largeEnough (rawDigestBits digest)) =
      scan oracle 50 []
        (counterKeys HegemonCrypto.SmallWoodTranscript.decsFixedSamplingDomain 50 digest) := by
  have cap : digestCallCap q38CandidateCount = 11 := by decide
  have keys :
      (List.ofFn (fun index : Fin 11 =>
        rp05RawBytes (.inr (currentFixedIndexKey bound largeEnough
          (rawDigestBits digest) ⟨index.val,
            Nat.lt_trans index.isLt (by decide)⟩)))) =
        counterKeys HegemonCrypto.SmallWoodTranscript.decsFixedSamplingDomain 50 digest := by
    let byValue (index : Fin 11) : Fin (2 ^ 64) :=
      ⟨index.val, Nat.lt_trans index.isLt (by decide)⟩
    let byMod (index : Fin 11) : Fin (2 ^ 64) :=
      ⟨index.val % (2 ^ 64), Nat.mod_lt _ (by norm_num)⟩
    have sameKeys :
        List.ofFn (fun index : Fin 11 =>
          rp05RawBytes (.inr (currentFixedIndexKey bound largeEnough
            (rawDigestBits digest) (byValue index)))) =
        List.ofFn (fun index : Fin 11 =>
          rp05RawBytes (.inr (currentFixedIndexKey bound largeEnough
            (rawDigestBits digest) (byMod index)))) := by
      apply congrArg List.ofFn
      funext index
      have counterEq : byValue index = byMod index := by
        apply Fin.ext
        exact (Nat.mod_eq_of_lt (Nat.lt_trans index.isLt (by decide))).symm
      exact congrArg (fun counter => rp05RawBytes
        (.inr (currentFixedIndexKey bound largeEnough
          (rawDigestBits digest) counter))) counterEq
    have rangeKeys := ofFn_fin_val_eq_range_map (n := 11) (f := fun index =>
      rp05RawBytes (.inr (currentFixedIndexKey bound largeEnough
        (rawDigestBits digest) ⟨index % (2 ^ 64), Nat.mod_lt _ (by norm_num)⟩)))
    rw [counterKeys, SmzaRp05ExecutableChallengeStage.callCap]
    calc
      _ = List.ofFn (fun index : Fin 11 =>
          rp05RawBytes (.inr (currentFixedIndexKey bound largeEnough
            (rawDigestBits digest) (byMod index)))) := sameKeys
      _ = (List.range 11).map (fun index =>
          rp05RawBytes (.inr (currentFixedIndexKey bound largeEnough
            (rawDigestBits digest) ⟨index % (2 ^ 64), Nat.mod_lt _ (by norm_num)⟩))) :=
        rangeKeys
      _ = (List.range 11).map (counterInput
          HegemonCrypto.SmallWoodTranscript.decsFixedSamplingDomain digest) := by
        apply List.map_congr_left
        intro index member
        have indexBound : index < 11 := List.mem_range.mp member
        have indexBelowCounter : index < 2 ^ 64 := Nat.lt_trans indexBound (by decide)
        let counter : Fin (digestCallCap q38CandidateCount) :=
          ⟨index, Nat.lt_of_lt_of_eq indexBound cap⟩
        have literal := current_sampler_key_is_literal_counter_input
          bound largeEnough digest counter
        have counterModEq :
            (⟨index, indexBelowCounter⟩ : Fin (2 ^ 64)) =
              ⟨index % (2 ^ 64), Nat.mod_lt _ (by norm_num)⟩ := by
          apply Fin.ext
          exact (Nat.mod_eq_of_lt indexBelowCounter).symm
        have physicalEq := congrArg (fun current => rp05RawBytes
          (.inr (currentFixedIndexKey bound largeEnough (rawDigestBits digest) current)))
          counterModEq
        exact physicalEq.symm.trans (by
          simpa [currentSamplerKey, counter] using literal)
      _ = counterKeys HegemonCrypto.SmallWoodTranscript.decsFixedSamplingDomain 50 digest := by
        norm_num [counterKeys, SmzaRp05ExecutableChallengeStage.callCap]
  have reader :
      NonleafProgram.interpret
          (fun key => rawDigestBits (oracle (rp05RawBytes (.inr key))))
          (sourceFieldReadLoop 50 []
            (List.ofFn fun index : Fin 11 => currentFixedIndexKey bound largeEnough
              (rawDigestBits digest) ⟨index.val,
                Nat.lt_trans index.isLt (by decide)⟩)) =
        scan oracle 50 []
          ((List.ofFn fun index : Fin 11 => currentFixedIndexKey bound largeEnough
            (rawDigestBits digest) ⟨index.val,
              Nat.lt_trans index.isLt (by decide)⟩).map
              (fun key => rp05RawBytes (.inr key))) := by
    exact HegemonCrypto.SmallWood.SmzaRp05CurrentRawFieldScan.source_field_reader_eq_executable_scan 50 []
      (List.ofFn fun index : Fin 11 => currentFixedIndexKey bound largeEnough
        (rawDigestBits digest) ⟨index.val,
          Nat.lt_trans index.isLt (by decide)⟩)
      (fun key => rp05RawBytes (.inr key)) oracle
  unfold currentFixedIndexXof
  exact reader.trans (congrArg (scan oracle 50 []) (by
    calc
      (List.ofFn fun index : Fin 11 => currentFixedIndexKey bound largeEnough
        (rawDigestBits digest) ⟨index.val,
          Nat.lt_trans index.isLt (by decide)⟩).map
        (fun key => rp05RawBytes (.inr key)) =
        List.ofFn (fun index : Fin 11 =>
        rp05RawBytes (.inr (currentFixedIndexKey bound largeEnough
          (rawDigestBits digest) ⟨index.val,
            Nat.lt_trans index.isLt (by decide)⟩))) := by
        rw [← List.ofFn_comp']
      _ = counterKeys HegemonCrypto.SmallWoodTranscript.decsFixedSamplingDomain 50 digest := keys))

/-- First-insertion collection is duplicate-free, including the early-stop
case. -/
theorem executable_collector_nodup (words : List FieldWord) (selected : List Nat)
    (selectedNodup : selected.Nodup) :
    (SmzaRp05ExecutableChallengeStage.collectIndices words selected).Nodup := by
  induction words generalizing selected with
  | nil => exact selectedNodup
  | cons word rest ih =>
      by_cases full : selected.length = 38
      · simpa [SmzaRp05ExecutableChallengeStage.collectIndices, full] using selectedNodup
      · by_cases accepted :
          word.val < (SmzaRp05ExecutableChallengeStage.modulus / 8388608) * 8388608
        · let index := word.val % 8388608
          by_cases duplicate : index ∈ selected
          · simp only [SmzaRp05ExecutableChallengeStage.collectIndices,
              if_neg full, if_pos accepted, index, if_pos duplicate]
            exact ih selected selectedNodup
          · simp only [SmzaRp05ExecutableChallengeStage.collectIndices,
              if_neg full, if_pos accepted, index, if_neg duplicate]
            exact ih (selected.concat index)
              (List.Nodup.concat (by simpa [index] using duplicate) selectedNodup)
        · simp only [SmzaRp05ExecutableChallengeStage.collectIndices,
            if_neg full, if_neg accepted]
          exact ih selected selectedNodup

/-- A successful actual PCS query with no deferred sampler failure exposes
the precise field words consumed by the executable scan and the exact sorted
index list used by the same `queryResult`. -/
theorem pcs_query_execution_exposes_clean_scan
    {ns : SmzaRp05LeafNamespace.Namespace} {pending : Bool} {hPiop : RawDigest}
    {wire : SmzaRp05PcsWireProjection.DecodedMiddleWire}
    {decs : SmzaRp05DecsResponseProjection.DecodedDecsResponseFields}
    {points : List HegemonCrypto.SmallWood.Goldilocks}
    {salt binding : List Byte} {statementBinding : List Nat}
    {tapes : List (List Byte)} {paths : List (List RawDigest)}
    {oracle : Oracle} {hashFpp : RawDigest} {finalPending : Bool}
    (stages : PcsStages ns pending hPiop wire decs points salt binding
      statementBinding tapes paths oracle hashFpp finalPending)
    (clean : stages.sampledPending = false) :
    pending = false ∧ ∃ words,
      scan oracle 50 []
        (SmzaRp05ExecutableChallengeStage.counterKeys
          HegemonCrypto.SmallWoodTranscript.decsFixedSamplingDomain
          50 stages.openingDigest) = some words ∧
      stages.indexes =
        (SmzaRp05ExecutableChallengeStage.collectIndices
          (SmzaRp05ExecutableChallengeStage.returnedWords 50 (some words)) []).mergeSort
          (fun left right => decide (left ≤ right)) ∧
      stages.indexes.length = 38 ∧ stages.indexes.Nodup := by
  obtain ⟨pendingFalse, words, scanResult⟩ :=
    query_execution_clean pending stages.openingDigest oracle
      stages.indexes stages.sampledPending stages.queryExecuted clean
  have exact := query_program_exact pending stages.openingDigest oracle
  have resultEq : queryResult pending
      (scan oracle 50 []
        (SmzaRp05ExecutableChallengeStage.counterKeys
          HegemonCrypto.SmallWoodTranscript.decsFixedSamplingDomain
          50 stages.openingDigest)) = some (stages.indexes, stages.sampledPending) := by
    exact exact.symm.trans stages.queryExecuted
  rw [scanResult, clean] at resultEq
  let sorted := (SmzaRp05ExecutableChallengeStage.collectIndices
    (SmzaRp05ExecutableChallengeStage.returnedWords 50 (some words)) []).mergeSort
      (fun left right => decide (left ≤ right))
  have resultShape : sorted.length = 38 ∧ sorted = stages.indexes ∧
      SmzaRp05ExecutableChallengeStage.pendingFailure pending (some words) = false := by
    simpa [queryResult, sorted] using resultEq
  rcases resultShape with ⟨enough, indexEq, _pendingGood⟩
  have nodup : sorted.Nodup := by
    dsimp [sorted]
    exact (executable_collector_nodup
      (SmzaRp05ExecutableChallengeStage.returnedWords 50 (some words)) [] (by simp)).mergeSort
  have indexesLength : stages.indexes.length = 38 := by
    rw [← indexEq]
    exact enough
  have indexesNodup : stages.indexes.Nodup := by
    rw [← indexEq]
    exact nodup
  exact ⟨pendingFalse, words, scanResult, indexEq.symm, indexesLength, indexesNodup⟩

def executableWordAsIdealCoin (word : FieldWord) : IdealFieldCoin :=
  ⟨word.val, by
    have modulusEq : SmzaRp05ExecutableChallengeStage.modulus =
        HegemonCrypto.SmallWood.V8Smz9RuntimeRandomness.fieldModulus := by
      norm_num [SmzaRp05ExecutableChallengeStage.modulus,
        HegemonCrypto.SmallWood.V8Smz9RuntimeRandomness.fieldModulus,
        Hegemon.Transaction.SmallWoodProductionConstraintRefinement.goldilocksModulus]
    rw [← modulusEq]
    exact word.isLt⟩

private theorem executable_threshold_eq_source :
    (SmzaRp05ExecutableChallengeStage.modulus / 8388608) * 8388608 =
      q38AcceptedFactorBound := by
  rw [accepted_bound_is_source_literal]
  norm_num [SmzaRp05ExecutableChallengeStage.modulus,
    HegemonCrypto.SmallWood.V8Smz9RuntimeRandomness.fieldModulus,
    Hegemon.Transaction.SmallWoodProductionConstraintRefinement.goldilocksModulus]

/-- The executable Nat collector and the checked q38 Fin collector have the
same outputs, after forgetting only Fin's bound proofs.  Both consume the
same accepted digest words; this equality identifies stopping at 38,
rejection, repeated indices, and first-insertion order. -/
private theorem executable_collector_eq_source_collector
    (words : List FieldWord) (selected : List LeafIndex) :
    (SmzaRp05ExecutableChallengeStage.collectIndices words
      (selected.map Fin.val)) =
      (Q38Rp05PostFinalCompiler.collectIndices (words.map executableWordAsIdealCoin)
        selected).map Fin.val := by
  induction words generalizing selected with
  | nil => rfl
  | cons word rest ih =>
      let index : LeafIndex :=
        ⟨word.val % 8388608, Nat.mod_lt _ (by decide)⟩
      have threshold :
          (SmzaRp05ExecutableChallengeStage.modulus / 8388608) * 8388608 =
            q38AcceptedFactorBound := executable_threshold_eq_source
      by_cases full : (selected.map Fin.val).length = 38
      · have fullFin : selected.length = 38 := by simpa using full
        simp only [SmzaRp05ExecutableChallengeStage.collectIndices, if_pos full]
        rw [Q38Rp05PostFinalCompiler.collectIndices.eq_def]
        simp only [List.map_cons]
        simp only [if_pos fullFin]
      · have notFullFin : selected.length ≠ 38 := by simpa using full
        by_cases accepted : word.val <
            (SmzaRp05ExecutableChallengeStage.modulus / 8388608) * 8388608
        · have acceptedSource :
              (executableWordAsIdealCoin word).val <
                Hegemon.Transaction.SmallWoodProductionConstraintRefinement.goldilocksModulus /
                  8388608 * 8388608 := by
            change word.val < _
            rw [← accepted_bound_is_source_literal, ← threshold]
            exact accepted
          have indexMem :
              (word.val % 8388608) ∈ selected.map Fin.val ↔ index ∈ selected := by
            constructor
            · intro member
              rcases List.mem_map.mp member with ⟨other, otherMem, valueEq⟩
              have finEq : index = other := by
                apply Fin.ext
                exact valueEq.symm
              rw [finEq]
              exact otherMem
            · intro member
              exact List.mem_map.mpr ⟨index, member, rfl⟩
          by_cases duplicate : (word.val % 8388608) ∈ selected.map Fin.val
          · have duplicateFin : index ∈ selected := indexMem.mp duplicate
            simp only [SmzaRp05ExecutableChallengeStage.collectIndices,
              if_neg full, if_pos accepted, if_pos duplicate]
            rw [Q38Rp05PostFinalCompiler.collectIndices.eq_def]
            simp only [List.map_cons]
            simp only [if_neg notFullFin, if_pos acceptedSource]
            change SmzaRp05ExecutableChallengeStage.collectIndices rest
                (List.map Fin.val selected) =
              List.map Fin.val
                (if index ∈ selected then
                  collectIndices (List.map executableWordAsIdealCoin rest) selected
                else
                  collectIndices (List.map executableWordAsIdealCoin rest)
                    (selected.concat index))
            rw [if_pos duplicateFin]
            exact ih selected
          · have freshFin : index ∉ selected := fun member => duplicate (indexMem.mpr member)
            simp only [SmzaRp05ExecutableChallengeStage.collectIndices,
              if_neg full, if_pos accepted, if_neg duplicate]
            rw [Q38Rp05PostFinalCompiler.collectIndices.eq_def]
            simp only [List.map_cons]
            simp only [if_neg notFullFin, if_pos acceptedSource]
            change SmzaRp05ExecutableChallengeStage.collectIndices rest
                ((List.map Fin.val selected).concat (word.val % 8388608)) =
              List.map Fin.val
                (if index ∈ selected then
                  collectIndices (List.map executableWordAsIdealCoin rest) selected
                else
                  collectIndices (List.map executableWordAsIdealCoin rest)
                    (selected.concat index))
            rw [if_neg freshFin]
            have mapConcat :
                (selected.concat index).map Fin.val =
                  (selected.map Fin.val).concat (word.val % 8388608) := by
              simp only [List.map_concat]
              rfl
            rw [← mapConcat]
            rw [ih (selected.concat index)]
        · have rejectedSource :
              ¬ (executableWordAsIdealCoin word).val <
                Hegemon.Transaction.SmallWoodProductionConstraintRefinement.goldilocksModulus /
                  8388608 * 8388608 := by
            change ¬ word.val < _
            rw [← accepted_bound_is_source_literal, ← threshold]
            exact accepted
          simp only [SmzaRp05ExecutableChallengeStage.collectIndices,
            if_neg full, if_neg accepted]
          rw [Q38Rp05PostFinalCompiler.collectIndices.eq_def]
          simp only [List.map_cons]
          simp only [if_neg notFullFin, if_neg rejectedSource]
          exact ih selected

private theorem list_toFinset_val_image (indices : List LeafIndex) :
    indices.toFinset.image Fin.val = (indices.map Fin.val).toFinset := by
  ext index
  simp

/-- A successful executed sampler selects exactly 38 source q38 positions.
The proof preserves the actual accepted-word list and uses the same collector
output rather than an independently sampled stream. -/
theorem executed_query_source_selection_card
    {ns : SmzaRp05LeafNamespace.Namespace} {pending : Bool} {hPiop : RawDigest}
    {wire : SmzaRp05PcsWireProjection.DecodedMiddleWire}
    {decs : SmzaRp05DecsResponseProjection.DecodedDecsResponseFields}
    {points : List HegemonCrypto.SmallWood.Goldilocks}
    {salt binding : List Byte} {statementBinding : List Nat}
    {tapes : List (List Byte)} {paths : List (List RawDigest)}
    {oracle : Oracle} {hashFpp : RawDigest} {finalPending : Bool}
    (stages : PcsStages ns pending hPiop wire decs points salt binding
      statementBinding tapes paths oracle hashFpp finalPending)
    (clean : stages.sampledPending = false) :
    ∃ words, scan oracle 50 []
      (SmzaRp05ExecutableChallengeStage.counterKeys
        HegemonCrypto.SmallWoodTranscript.decsFixedSamplingDomain
        50 stages.openingDigest) = some words ∧
      (q38SelectedIndexSet (words.map executableWordAsIdealCoin)).card = 38 := by
  obtain ⟨_, words, scanResult, indexesEq, indexesLength, _⟩ :=
    pcs_query_execution_exposes_clean_scan stages clean
  refine ⟨words, scanResult, ?_⟩
  let candidates := words.map executableWordAsIdealCoin
  let sourceSorted := Q38Rp05PostFinalCompiler.sortedIndices candidates
  have sourceLength : sourceSorted.length = 38 := by
    calc
      sourceSorted.length =
          (Q38Rp05PostFinalCompiler.collectIndices candidates []).length := by
        simp [sourceSorted, Q38Rp05PostFinalCompiler.sortedIndices]
      _ = (SmzaRp05ExecutableChallengeStage.collectIndices words []).length := by
        have collectorLength :=
          congrArg List.length (executable_collector_eq_source_collector words [])
        simpa using collectorLength.symm
      _ = ((SmzaRp05ExecutableChallengeStage.collectIndices
          (SmzaRp05ExecutableChallengeStage.returnedWords 50 (some words)) []).mergeSort
          (fun left right => decide (left ≤ right))).length := by
        simp [SmzaRp05ExecutableChallengeStage.returnedWords]
      _ = stages.indexes.length := by rw [indexesEq]
      _ = 38 := indexesLength
  rw [← source_sorted_support_eq_counted_support]
  calc
    _ = sourceSorted.length :=
      List.toFinset_card_of_nodup
        (Q38Rp05PostFinalCompiler.sorted_indices_nodup candidates)
    _ = 38 := sourceLength

/-- The source sampler's deferred-failure guard follows from the successful
executed query itself. This is a same-oracle parser fact, not a freshness
assumption about a classical log. -/
theorem executed_query_source_scope_finished
    {ns : SmzaRp05LeafNamespace.Namespace} {pending : Bool} {hPiop : RawDigest}
    {wire : SmzaRp05PcsWireProjection.DecodedMiddleWire}
    {decs : SmzaRp05DecsResponseProjection.DecodedDecsResponseFields}
    {points : List HegemonCrypto.SmallWood.Goldilocks}
    {salt binding : List Byte} {statementBinding : List Nat}
    {tapes : List (List Byte)} {paths : List (List RawDigest)}
    {oracle : Oracle} {hashFpp : RawDigest} {finalPending : Bool}
    (stages : PcsStages ns pending hPiop wire decs points salt binding
      statementBinding tapes paths oracle hashFpp finalPending)
    (clean : stages.sampledPending = false)
    (bound : Nat) (largeEnough : 39162 ≤ bound) :
    sourcePendingFailure pending
      (NonleafProgram.interpret
        (fun key => rawDigestBits (oracle (rp05RawBytes (.inr key))))
        (currentFixedIndexXof bound largeEnough
          (rawDigestBits stages.openingDigest))) = false := by
  obtain ⟨pendingFalse, words, scanResult, _, _, _⟩ :=
    pcs_query_execution_exposes_clean_scan stages clean
  rw [current_source_xof_eq_executed_scan bound largeEnough
    stages.openingDigest oracle, scanResult, pendingFalse]
  rfl

/-- The q38 source selector is forced by the same successful query that
produced the executable indexes. Its target support is exactly the counted
38-index set; only the deterministic field-point map is supplied. -/
theorem executed_query_source_selection
    {ns : SmzaRp05LeafNamespace.Namespace} {pending : Bool} {hPiop : RawDigest}
    {wire : SmzaRp05PcsWireProjection.DecodedMiddleWire}
    {decs : SmzaRp05DecsResponseProjection.DecodedDecsResponseFields}
    {points : List HegemonCrypto.SmallWood.Goldilocks}
    {salt binding : List Byte} {statementBinding : List Nat}
    {tapes : List (List Byte)} {paths : List (List RawDigest)}
    {oracle : Oracle} {hashFpp : RawDigest} {finalPending : Bool}
    (stages : PcsStages ns pending hPiop wire decs points salt binding
      statementBinding tapes paths oracle hashFpp finalPending)
    (clean : stages.sampledPending = false)
    (bound : Nat) (largeEnough : 39162 ≤ bound)
    (points6 : Fin 6 → HegemonCrypto.SmallWood.Goldilocks)
    (pointsDistinct : Function.Injective points6) :
    ∃ words, scan oracle 50 []
        (counterKeys HegemonCrypto.SmallWoodTranscript.decsFixedSamplingDomain
          50 stages.openingDigest) = some words ∧
      ∃ query : Query,
      (Q38Rp05PostFinalCompiler.sampledTargets points6 pointsDistinct
        (sourceReturnedWords 50
          (NonleafProgram.interpret
            (fun key => rawDigestBits (oracle (rp05RawBytes (.inr key))))
            (currentFixedIndexXof bound largeEnough
              (rawDigestBits stages.openingDigest))))).map
        SmzaRp05Q38ExecutionCountBridge.targetSupport = some query.val ∧
      query.val = q38SelectedIndexSet (words.map executableWordAsIdealCoin) ∧
      query.val.image Fin.val = stages.indexes.toFinset := by
  obtain ⟨words, scanResult, selectedCard⟩ :=
    executed_query_source_selection_card stages clean
  let candidates := words.map executableWordAsIdealCoin
  let sourceSorted := Q38Rp05PostFinalCompiler.sortedIndices candidates
  have sourceLength : sourceSorted.length = 38 := by
    calc
      sourceSorted.length = sourceSorted.toFinset.card :=
        (List.toFinset_card_of_nodup
          (Q38Rp05PostFinalCompiler.sorted_indices_nodup candidates)).symm
      _ = (q38SelectedIndexSet candidates).card := by
        rw [source_sorted_support_eq_counted_support]
        rfl
      _ = 38 := by simpa [candidates] using selectedCard
  obtain ⟨_, words', scanResult', indexesEq, _, _⟩ :=
    pcs_query_execution_exposes_clean_scan stages clean
  have wordsEq : words' = words := Option.some.inj (scanResult'.symm.trans scanResult)
  subst words'
  let sourceCollector := Q38Rp05PostFinalCompiler.collectIndices candidates []
  let executableCollector := SmzaRp05ExecutableChallengeStage.collectIndices words []
  have sourceSortPerm : List.Perm (sourceSorted.map Fin.val)
      (sourceCollector.map Fin.val) := by
    have perm := List.mergeSort_perm sourceCollector
      (fun left right => decide (left.val ≤ right.val))
    simpa [sourceSorted, sourceCollector, Q38Rp05PostFinalCompiler.sortedIndices] using
      perm.map Fin.val
  have collectorSame : sourceCollector.map Fin.val = executableCollector := by
    simpa [sourceCollector, executableCollector, candidates] using
      (executable_collector_eq_source_collector words []).symm
  have sourceMappedSet :
      (sourceSorted.map Fin.val).toFinset = executableCollector.toFinset := by
    calc
      (sourceSorted.map Fin.val).toFinset = (sourceCollector.map Fin.val).toFinset :=
        List.toFinset_eq_of_perm _ _ sourceSortPerm
      _ = executableCollector.toFinset := by rw [collectorSame]
  have executableSortPerm : List.Perm stages.indexes executableCollector := by
    rw [indexesEq]
    have perm := List.mergeSort_perm
      (SmzaRp05ExecutableChallengeStage.collectIndices
        (SmzaRp05ExecutableChallengeStage.returnedWords 50 (some words)) [])
      (fun left right => decide (left ≤ right))
    simpa [SmzaRp05ExecutableChallengeStage.returnedWords, executableCollector] using perm
  have selectedToIndexes :
      (q38SelectedIndexSet candidates).image Fin.val = stages.indexes.toFinset := by
    calc
      _ = sourceSorted.toFinset.image Fin.val :=
        congrArg (fun chosen : Finset Position => chosen.image Fin.val)
          (source_sorted_support_eq_counted_support candidates).symm
      _ = (sourceSorted.map Fin.val).toFinset := list_toFinset_val_image sourceSorted
      _ = executableCollector.toFinset := sourceMappedSet
      _ = stages.indexes.toFinset :=
        (List.toFinset_eq_of_perm _ _ executableSortPerm).symm
  have support :
      (Q38Rp05PostFinalCompiler.sampledTargets points6 pointsDistinct candidates).map
        SmzaRp05Q38ExecutionCountBridge.targetSupport =
          some (q38SelectedIndexSet candidates) := by
    rw [SmzaRp05Q38ExecutionCountBridge.sampled_targets_support]
    rw [if_pos sourceLength, source_sorted_support_eq_counted_support]
    rfl
  have candidatesAreWords : words.map executableWordAsIdealCoin = words := by
    change List.map (fun word : FieldWord => word) words = words
    exact List.map_id _
  have returnedCandidates : sourceReturnedWords 50 (some words) = candidates := by
    change words = words.map executableWordAsIdealCoin
    exact candidatesAreWords.symm
  have sourceOutput :
      NonleafProgram.interpret
          (fun key => rawDigestBits (oracle (rp05RawBytes (.inr key))))
          (currentFixedIndexXof bound largeEnough
            (rawDigestBits stages.openingDigest)) = some words := by
    calc
      _ = scan oracle 50 []
          (counterKeys HegemonCrypto.SmallWoodTranscript.decsFixedSamplingDomain
            50 stages.openingDigest) :=
          current_source_xof_eq_executed_scan bound largeEnough
            stages.openingDigest oracle
      _ = some words := scanResult
  let query : Query := ⟨q38SelectedIndexSet candidates, selectedCard⟩
  refine ⟨words, scanResult, query, ?_, rfl, selectedToIndexes⟩
  rw [sourceOutput]
  calc
    Option.map targetSupport
        (Q38Rp05PostFinalCompiler.sampledTargets points6 pointsDistinct
          (sourceReturnedWords 50 (some words))) =
      Option.map targetSupport
        (Q38Rp05PostFinalCompiler.sampledTargets points6 pointsDistinct candidates) := by
          exact congrArg
            (fun returned => Option.map targetSupport
              (Q38Rp05PostFinalCompiler.sampledTargets points6 pointsDistinct returned))
            returnedCandidates
    _ = some (q38SelectedIndexSet candidates) := support

end
end HegemonCrypto.SmallWood.SmzaRp05CurrentExecutedSamplerSemantics
