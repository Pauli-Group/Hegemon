import SmzaRp05CurrentRetainedQuerySupport
import SmzaRp05CurrentRecoveredQueryBridge

/-! The actual successful PCS stage either records a collision, has a
current-map MCA extraction failure, has a current-map LVCS miss, or recovers
all twelve claimed polynomials exactly. The query is explicitly identified
with the same stage's sampled indexes. No free table, response-readback,
recovered-row agreement, or twelve-check premise is supplied by the caller.
This is the deterministic inclusion, not an independent-sampling assertion
about terminal records and not yet the final Born-weight soundness bound. -/

namespace HegemonCrypto.SmallWood.SmzaRp05CurrentAcceptedQueryExtraction

open HegemonCrypto.CanonicalBytes (Byte)
open SmzaRp05ExecutablePcsClosureStages (PcsStages)
open SmzaRp05CurrentMaxAgreementRecovery
open SmzaRp05CurrentRetainedQuerySupport
open SmzaRp05CurrentRecoveredQueryBridge
open SmzaRp05CurrentQueryEventCore
open SmzaRp05CurrentQ38DetectionProbability
open SmzaRp05CurrentTwelveCalculated
open SmzaRp05GlobalOpeningReadback (GlobalQueryReadback)
open SmzaRp05FilteredDecoderInstability (RawRecords)
open SmzaRp05LeafNamespace (Namespace)
open SmzaRecordedTracePath (RecordsCollisionFree)
open V8SmzaOracleParser (RawDigest)
open HegemonCrypto.SmallWood.V8Smz9McaDecoder
  (DecodedSource responseDecoder)

set_option autoImplicit false
set_option maxRecDepth 10000
set_option maxHeartbeats 1000000
noncomputable section

attribute [local irreducible]
  HegemonCrypto.SmallWood.V8Smz9McaRecovery.querySampleFintype

def CurrentDecoderOutcome
    (data : Nat → Position → Goldilocks)
    (masks : Fin 5 → Position → Goldilocks)
    (response : ResponseRule) (coefficients : Coefficients)
    (heads tails : List (List Goldilocks)) (points : Fin 6 → Goldilocks)
    (query : Query) : Prop :=
  query ∈ currentAcceptedExtractionFailureEvent data masks response coefficients ∨
    ∃ candidate : DecodedSource Goldilocks (Fin 5) 140,
      responseDecoder SmzaRp05Q38CurrentRebinding.smz9EvaluationPoint
        405 data masks response coefficients = some candidate ∧
      (query ∈ currentLvcsBadQueryEvent candidate.data points
        (currentStageClaims heads tails) ∨
        ∀ combination, currentStageClaims heads tails combination =
          SmzaQ38LvcsOpening.rowCombination candidate.data points combination)

/-- Exact accepted-stage inclusion at the current 406-point map. The only
numeric premises are source-profile dimensions and decoder traversal fuel;
the collision branch, query support, readback, and decoder alternatives are
all derived from this same successful stage. -/
theorem accepted_stage_current_decoder_outcome
    {ns : Namespace} {pending : Bool} {hPiop : RawDigest}
    {wire : SmzaRp05PcsWireProjection.DecodedMiddleWire}
    {decs : SmzaRp05DecsResponseProjection.DecodedDecsResponseFields}
    {points : List Goldilocks} {salt binding : List Byte}
    {statementBinding : List Nat} {tapes : List (List Byte)}
    {paths : List (List RawDigest)}
    {oracle : SmzaRp05ExecutableMerkleVerifier.Oracle}
    {hashFpp : RawDigest} {finalPending : Bool}
    (stages : PcsStages ns pending hPiop wire decs points salt binding
      statementBinding tapes paths oracle hashFpp finalPending)
    (pointCount : points.length = 6) (clean : finalPending = false)
    (fuel : Nat) (enough : 25 ≤ fuel)
    (statementBindingLength : statementBinding.length = 138) :
    let records : RawRecords :=
      ((SmzaRp05ExecutableMerkleVerifier.recordedAttempt ns oracle stages.merkleInput).2 ++
        (stages.hashProgram.record oracle).2).toFinset
    ¬ RecordsCollisionFree records ∨
      ∃ coordinates : Fin 38 → Position,
        ∃ query : Query, ∃ input : V8SmzaOracleParser.RawInput,
          StrictMono coordinates ∧
          query.val = Finset.univ.image coordinates ∧
          (∀ j : Fin 38, (coordinates j).val = stages.indexes.getD j.val 0) ∧
          (input, hashFpp) ∈ records ∧
          CurrentDecoderOutcome
            (measuredDataTable ns records fuel stages.post.root)
            (measuredMaskTable ns records fuel stages.post.root)
            (SmzaRp05CurrentResponseInputDecoder.responseRuleOfRawInputSelection
              (fun _ : Coefficients => input))
            (SmzaRp05CurrentAcceptedQuerySupport.sampledCoefficients
              (SmzaRp05PcsHashFppMiddle.gammaRows stages.post))
            stages.heads (currentStageTails wire)
            (fun opening => points.getD opening.val 0) query := by
  classical
  let records : RawRecords :=
    ((SmzaRp05ExecutableMerkleVerifier.recordedAttempt ns oracle stages.merkleInput).2 ++
      (stages.hashProgram.record oracle).2).toFinset
  by_cases collisionFree : RecordsCollisionFree records
  · have stageSupport := terminal_stage_query_support_or_collision stages
      pointCount clean fuel enough statementBindingLength
    rcases stageSupport with collision | support
    · exact False.elim (collision collisionFree)
    · rcases support with ⟨coordinates, query, claims, polynomials, input,
        ordered, image, coordinateIndex, inputMember, _restored, checks, accepted⟩
      have bindingAt := measured_tables_match_decoded_oracle claims collisionFree
        fuel enough coordinates image
      have dataBinding : ∀ column : Fin 140, ∀ index, index ∈ query.val →
          measuredDataTable ns records fuel stages.post.root column.val index =
            SmzaQ38OracleExtraction.committedColumnValue
              (authenticatedReadbackOracle claims) column index := by
        intro column index member
        rw [image, Finset.mem_image] at member
        obtain ⟨j, _member, indexEq⟩ := member
        subst index
        exact bindingAt.1 j column
      refine Or.inr ⟨coordinates, query, input, ordered, image, coordinateIndex,
        List.mem_toFinset.mpr inputMember, ?_⟩
      exact accepted_current_checks_bad_or_recovered claims coordinates stages.heads
        (currentStageTails wire) (fun opening => points.getD opening.val 0)
        checks image (measuredDataTable ns records fuel stages.post.root)
        (measuredMaskTable ns records fuel stages.post.root)
        (SmzaRp05CurrentResponseInputDecoder.responseRuleOfRawInputSelection
          (fun _ : Coefficients => input))
        (SmzaRp05CurrentAcceptedQuerySupport.sampledCoefficients
          (SmzaRp05PcsHashFppMiddle.gammaRows stages.post)) accepted dataBinding
  · exact Or.inl collisionFree

/-- The same extraction alternative on a larger, actual execution record
set. Only containment of the two executed subprogram logs is needed; in
particular this does not assume equality between a local PCS log and the
full physical producer/verifier log. The root decoder is rerun on the full
record set, and all twelve checks bind to that very decoder. -/
theorem accepted_stage_retained_decoder_outcome
    {ns : Namespace} {pending : Bool} {hPiop : RawDigest}
    {wire : SmzaRp05PcsWireProjection.DecodedMiddleWire}
    {decs : SmzaRp05DecsResponseProjection.DecodedDecsResponseFields}
    {points : List Goldilocks} {salt binding : List Byte}
    {statementBinding : List Nat} {tapes : List (List Byte)}
    {paths : List (List RawDigest)}
    {oracle : SmzaRp05ExecutableMerkleVerifier.Oracle}
    {hashFpp : RawDigest} {finalPending : Bool}
    (stages : PcsStages ns pending hPiop wire decs points salt binding
      statementBinding tapes paths oracle hashFpp finalPending)
    (pointCount : points.length = 6) (clean : finalPending = false)
    (fuel : Nat) (enough : 25 ≤ fuel)
    (statementBindingLength : statementBinding.length = 138)
    (records : RawRecords)
    (merkleRetained : ∀ call,
      call ∈ (SmzaRp05ExecutableMerkleVerifier.recordedAttempt ns oracle
        stages.merkleInput).2 → call ∈ records)
    (hashRetained : ∀ call,
      call ∈ (stages.hashProgram.record oracle).2 → call ∈ records) :
    ¬ RecordsCollisionFree records ∨
      ∃ coordinates : Fin 38 → Position,
        ∃ query : Query, ∃ input : V8SmzaOracleParser.RawInput,
          StrictMono coordinates ∧
          query.val = Finset.univ.image coordinates ∧
          (∀ j : Fin 38, (coordinates j).val = stages.indexes.getD j.val 0) ∧
          (input, hashFpp) ∈ records ∧
          (input, hashFpp) ∈ (stages.hashProgram.record oracle).2 ∧
          CurrentDecoderOutcome
            (measuredDataTable ns records fuel stages.post.root)
            (measuredMaskTable ns records fuel stages.post.root)
            (SmzaRp05CurrentResponseInputDecoder.responseRuleOfRawInputSelection
              (fun _ : Coefficients => input))
            (SmzaRp05CurrentAcceptedQuerySupport.sampledCoefficients
              (SmzaRp05PcsHashFppMiddle.gammaRows stages.post))
            stages.heads (currentStageTails wire)
            (fun opening => points.getD opening.val 0) query := by
  classical
  by_cases collisionFree : RecordsCollisionFree records
  · let hashLog := (stages.hashProgram.record oracle).2
    obtain ⟨_, selected, _, _, programEq⟩ :=
      SmzaRp05CurrentAcceptedRoleSupport.selected_response_hash_program_input
        stages.post.root decs
        (stages.rows.map fun row => row.map SmzaRp05ExecutableRestore.toWord)
        (SmzaRp05PcsHashFppMiddle.gammaRows stages.post)
        (stages.decsPoints.map SmzaRp05ExecutableRestore.toWord)
        140 368 statementBinding stages.hashProgram stages.responseBuilt
    have oracleEq : oracle selected = hashFpp := by
      have executed := stages.hashExecuted
      rw [programEq, SmzaRp05ExecutableMerkleVerifier.Program.eval.eq_def] at executed
      exact Option.some.inj executed
    have inputCall : (selected, hashFpp) ∈ hashLog := by
      change (selected, hashFpp) ∈ (stages.hashProgram.record oracle).2
      simp [programEq, SmzaRp05ExecutableMerkleVerifier.Program.record,
        SmzaRp05ExecutableMerkleVerifier.ask, oracleEq]
    have sub : (hashLog ++ hashLog).toFinset ⊆ records := by
      intro call member
      have inHash : call ∈ hashLog := by
        simpa only [List.mem_toFinset, List.mem_append, or_self] using member
      exact hashRetained call inHash
    have responseCollisionFree : RecordsCollisionFree (hashLog ++ hashLog).toFinset := by
      intro a b digest left right
      exact collisionFree a b digest (sub left) (sub right)
    obtain ⟨coordinates, query, claims, polynomials, input,
        ordered, image, coordinateIndex, inputMember, _restored, checks, accepted⟩ :=
      same_stage_measured_root_query_support stages pointCount clean hashLog
        ⟨selected, inputCall⟩ responseCollisionFree records
        (by intro _ raw digest member _; exact merkleRetained (raw, digest) member)
        collisionFree fuel enough statementBindingLength
    have bindingAt := measured_tables_match_decoded_oracle claims collisionFree
      fuel enough coordinates image
    have dataBinding : ∀ column : Fin 140, ∀ index, index ∈ query.val →
        measuredDataTable ns records fuel stages.post.root column.val index =
          SmzaQ38OracleExtraction.committedColumnValue
            (authenticatedReadbackOracle claims) column index := by
      intro column index member
      rw [image, Finset.mem_image] at member
      obtain ⟨j, _member, indexEq⟩ := member
      subst index
      exact bindingAt.1 j column
    refine Or.inr ⟨coordinates, query, input, ordered, image, coordinateIndex,
      hashRetained (input, hashFpp) inputMember, inputMember, ?_⟩
    exact accepted_current_checks_bad_or_recovered claims coordinates stages.heads
      (currentStageTails wire) (fun opening => points.getD opening.val 0)
      checks image (measuredDataTable ns records fuel stages.post.root)
      (measuredMaskTable ns records fuel stages.post.root)
      (SmzaRp05CurrentResponseInputDecoder.responseRuleOfRawInputSelection
        (fun _ : Coefficients => input))
      (SmzaRp05CurrentAcceptedQuerySupport.sampledCoefficients
        (SmzaRp05PcsHashFppMiddle.gammaRows stages.post)) accepted dataBinding
  · exact Or.inl collisionFree

end
end HegemonCrypto.SmallWood.SmzaRp05CurrentAcceptedQueryExtraction
