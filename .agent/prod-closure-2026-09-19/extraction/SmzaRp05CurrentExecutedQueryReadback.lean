import SmzaRp05CurrentPrequeryChronology
import SmzaRp05CurrentQueryReadback
import SmzaRp05ExecutablePcsClosureStages
import SmzaRp05CurrentDecsFrameReadback
import SmzaRp05CurrentExecutedSamplerSemantics
import SmzaRp05CurrentRawFieldScan

/-! # Same-oracle readback for the executed current DECS sampler

This adapter constructs the vector answer from the very `PcsStages.oracle`
used by `queryExecuted`.  The route-address equation is kept as a literal
input-address fact; no independently sampled vector, measured-table premise,
or freshness claim is introduced.  The q38 success and selected-target facts
remain the current source acceptance facts consumed by the existing decoder
lemma.
-/

namespace HegemonCrypto.SmallWood.SmzaRp05CurrentExecutedQueryReadback

open HegemonCrypto.CanonicalBytes (Byte)
open SmzaRp05ExecutableMerkleVerifier (Oracle)
open SmzaRp05ExecutablePcsClosureStages (PcsStages)
open SmzaRp05ExecutablePcsClosure (queryProgram)
open SmzaRp05CurrentQueryReadback
open SmzaRp05ConsumedFieldReadback
open SmzaRp04RawRoleSampling (actualDecsSampleOutput q38CandidateCount q38SelectedIndexSet)
open V8Smz9CoherentMerkleInstrument (rawDigestBits)
open V8Smz9CoherentMerkleGeometry (RawDigest)
open V8Smz9HiddenLeafQrom (DigestRegister)
open V8Smz9CoherentVectorMerkle (VectorOutput)
open Q38Rp05RawInputPartition (Rp05OtherRawInput rp05RawBytes)
open Q38Rp05CurrentPostfinal (currentFixedIndexKey)
open V8Smz9HonestRequestSchedule (NonleafProgram)
open V8Smz9HonestOpeningSchedule (sourcePendingFailure sourceReturnedWords)
open SmzaQ38McaSourceBinding (Query)
open Q38Rp05PostFinalCompiler (sampledTargets)
open SmzaRp05Q38ExecutionCountBridge (targetSupport)
open Q38Rp05CurrentPostfinal (currentFixedIndexXof)
open V8Smz9RawCounterCompiler (digestCallCap)
open SmzaRp05CurrentExecutedSamplerSemantics
open HegemonCrypto.SmallWood.SmzaRp05CurrentRawFieldScan
open HegemonCrypto.CanonicalBytes (encodeLE)
open SmzaRp05ExecutableChallengeStage (counterInput counterKeys digestWords scan)
open V8Smz9HonestRequestSchedule (sourceDigestWords sourceDigest)
open Q38Rp05RawInputPartition (rp05_source_counter_key_is_literal_input rp05SourcePrefix)
open V8SmzaOracleParser (profileDomain)

set_option autoImplicit false
noncomputable section

private def samplerKey (bound : Nat) (largeEnough : 39162 ≤ bound)
    (digest : DigestRegister) (counter : Fin (digestCallCap q38CandidateCount)) :
    Rp05OtherRawInput bound :=
  currentFixedIndexKey bound largeEnough digest ⟨counter.val, by
    have cap : digestCallCap q38CandidateCount = 11 := by decide
    have h : counter.val < 11 := by simpa [cap] using counter.isLt
    exact Nat.lt_trans h (by decide)⟩

/-- The bounded source-key constructor and the executable `fieldXof` use
identical SMZA-framed bytes for every actual DECS sampler counter. -/
theorem sampler_key_is_literal_counter_input (bound : Nat)
    (largeEnough : 39162 ≤ bound) (digest : RawDigest)
    (counter : Fin (digestCallCap q38CandidateCount)) :
    rp05RawBytes (.inr (samplerKey bound largeEnough (rawDigestBits digest) counter)) =
      counterInput HegemonCrypto.SmallWoodTranscript.decsFixedSamplingDomain digest counter.val := by
  have sourceWords : sourceDigestWords (rawDigestBits digest) = digestWords digest :=
    source_digest_words_eq_executed_words digest
  have words :
      (sourceDigestWords (rawDigestBits digest)).flatMap (encodeLE 8) = List.ofFn digest := by
    rw [sourceWords]
    exact SmzaRp05CurrentDecsFrameReadback.digest_words_encode_exact digest
  simp only [samplerKey, currentFixedIndexKey]
  rw [rp05_source_counter_key_is_literal_input]
  simp only [rp05SourcePrefix, SmzaRp05ExecutableChallengeStage.counterInput,
    V8Smz9RawCounterCompiler.counterInput,
    V8Smz9HonestRequestSchedule.source_digest_word_count,
    ← List.flatMap_def]
  rw [words]
  rfl

/-- The output vector is the full-vector view of the same raw verifier
oracle. `keyFor` is the physical key represented by a CMS counter, and
`routeAddress` states that this role route selects exactly the current
profile's sampler input. -/
def executedVector {Counter : Type*} (oracle : Oracle)
    {bound : Nat} (keyFor : Counter → Rp05OtherRawInput bound) :
    VectorOutput Counter :=
  fun counter => rawDigestBits (oracle (rp05RawBytes (.inr (keyFor counter))))

/-- Successful q38 execution, together with the current source selector's
guarded target result, yields the exact active DECS-sample output in a vector
read from the *same* verifier oracle.  The only route obligation is address
identity with the current-profile counter input; answer agreement is derived
by unfolding `executedVector`, not assumed as a measured-table premise. -/
theorem executed_query_supplies_current_readback
    {Counter : Type*} {ns : SmzaRp05LeafNamespace.Namespace}
    {pending : Bool} {hPiop : RawDigest}
    {wire : SmzaRp05PcsWireProjection.DecodedMiddleWire}
    {decs : SmzaRp05DecsResponseProjection.DecodedDecsResponseFields}
    {points : List HegemonCrypto.SmallWood.Goldilocks}
    {salt binding : List Byte} {statementBinding : List Nat}
    {tapes : List (List Byte)} {paths : List (List RawDigest)}
    {oracle : Oracle} {hashFpp : RawDigest} {finalPending : Bool}
    (stages : PcsStages ns pending hPiop wire decs points salt binding
      statementBinding tapes paths oracle hashFpp finalPending)
    (bound : Nat) (largeEnough : 39162 ≤ bound)
    (select : Fin (digestCallCap q38CandidateCount) ↪ Counter)
    (keyFor : Counter → Rp05OtherRawInput bound)
    (routeAddress : ∀ counter,
      keyFor (select counter) = samplerKey bound largeEnough
        (rawDigestBits stages.openingDigest) counter)
    (points6 : Fin 6 → HegemonCrypto.SmallWood.Goldilocks)
    (pointsDistinct : Function.Injective points6)
    (query : Query)
    (scopeFinished : sourcePendingFailure pending
      (NonleafProgram.interpret
        (fun key => rawDigestBits (oracle (rp05RawBytes (.inr key))))
        (currentFixedIndexXof bound largeEnough (rawDigestBits stages.openingDigest))) = false)
    (selected : (Q38Rp05PostFinalCompiler.sampledTargets points6 pointsDistinct
      (sourceReturnedWords 50
        (NonleafProgram.interpret
          (fun key => rawDigestBits (oracle (rp05RawBytes (.inr key))))
          (currentFixedIndexXof bound largeEnough
            (rawDigestBits stages.openingDigest))))).map targetSupport = some query.val)
    :
    actualDecsSampleOutput select (executedVector oracle keyFor) = some query := by
  have measured : ∀ counter ∈ consumedFieldKeys q38CandidateCount
      (fun index => rawDigestBits (currentQueryRawBlocks bound largeEnough
        (fun key => rawDigestBits (oracle (rp05RawBytes (.inr key))))
        (rawDigestBits stages.openingDigest) index))
      [] (List.ofFn fun index : Fin (digestCallCap q38CandidateCount) => index),
      rawDigestBits (currentQueryRawBlocks bound largeEnough
        (fun key => rawDigestBits (oracle (rp05RawBytes (.inr key))))
        (rawDigestBits stages.openingDigest) counter) =
        (executedVector oracle keyFor) (select counter) := by
    intro counter _
    simp only [currentQueryRawBlocks, executedVector]
    simp only [Equiv.symm_apply_apply]
    rw [routeAddress counter]
    rfl
  exact current_source_acceptance_supplies_query_read bound largeEnough
    (fun key => rawDigestBits (oracle (rp05RawBytes (.inr key))))
    (rawDigestBits stages.openingDigest) points6 pointsDistinct pending query
    select (executedVector oracle keyFor) measured scopeFinished selected

/-- Construct the DECS sampler's counter selector and measured vector from
the actual `PcsStages` oracle. A clean successful `queryExecuted` supplies
both the source parser's no-failure fact and the exact selected 38-position
support; neither is an independent premise. -/
theorem executed_query_supplies_its_actual_sampler_output
    {ns : SmzaRp05LeafNamespace.Namespace}
    {pending : Bool} {hPiop : RawDigest}
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
        (SmzaRp05ExecutableChallengeStage.counterKeys
          HegemonCrypto.SmallWoodTranscript.decsFixedSamplingDomain
          50 stages.openingDigest) = some words ∧
      ∃ query : Query,
      query.val = q38SelectedIndexSet (words.map executableWordAsIdealCoin) ∧
      query.val.image Fin.val = stages.indexes.toFinset ∧
      actualDecsSampleOutput
        (Function.Embedding.refl (Fin (digestCallCap q38CandidateCount)))
      (executedVector oracle
          (samplerKey bound largeEnough (rawDigestBits stages.openingDigest))) =
        some query := by
  obtain ⟨words, scanResult, query, selected, queryEq, selectedIndexes⟩ :=
    executed_query_source_selection stages clean bound largeEnough
      points6 pointsDistinct
  have scope := executed_query_source_scope_finished stages clean bound largeEnough
  let select : Fin (digestCallCap q38CandidateCount) ↪
      Fin (digestCallCap q38CandidateCount) :=
    Function.Embedding.refl _
  have output := executed_query_supplies_current_readback stages bound largeEnough
      select (samplerKey bound largeEnough (rawDigestBits stages.openingDigest))
      (by intro counter; rfl) points6 pointsDistinct query scope selected
  exact ⟨words, scanResult, query, queryEq, selectedIndexes, output⟩

end
end HegemonCrypto.SmallWood.SmzaRp05CurrentExecutedQueryReadback
