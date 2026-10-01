import SmzaFixedAdvicePrefix
import HegemonCrypto.SmallWoodV8Smz9CoherentVectorMerkle

/-! Instantiate full-vector CMS instability with the selected q38 stage
geometry. The entire counter vector remains in the quantum query; the live
VC trace observes its relevant512-bit coordinate. Other-stage fixed advice
enters only through trace-stable postprocessing. -/

namespace HegemonCrypto.SmallWood.SmzaStageVectorInstability

open scoped BigOperators Classical
open HegemonCrypto.FiniteOracleDatabase HegemonCrypto.CmsClassicalDatabase
open HegemonCrypto.CmsCompressedOracle HegemonCrypto.CmsQuerySequence
open HegemonCrypto.CmsFullOperatorProof
open V8Smz9CoherentMerkleGeometry V8Smz9CoherentMerkleInstrument
open V8Smz9CoherentMerklePartition V8Smz9HiddenLeafQrom
open V8Smz9CoherentVectorMerkle
open SmzaChallengeStageTargets SmzaFixedAdvicePrefix

noncomputable section
set_option autoImplicit false
set_option exponentiation.threshold 1024
set_option maxRecDepth 10000

abbrev RawInput := V8SmzaOracleParser.RawInput

variable {Key Counter Answer : Type*}
variable [Fintype Key] [DecidableEq Key] [Fintype Counter] [DecidableEq Counter]

def stageVectorTrace (next : Next) (role : Role) (fuel : Nat)
    (keyBytes : Key → RawInput) (counter : Counter) (queries : List RawInput)
    (database : Database Key (VectorOutput Counter)) :=
  prefixTrace next role fuel (rawRecords keyBytes (vectorOutputBytes counter) database) queries

theorem stage_vector_step_change_bound
    (next : Next)
    (children : ∀ stage input edges, next stage input = some edges →
      ∀ edge ∈ edges, edge.2 ∈ V8SmzaOracleParser.rawChildren input)
    (role : Role) (fuel : Nat) (keyBytes : Key → RawInput) (counter : Counter)
    (queries : List RawInput) (cap : Nat) (queryBound : queries.length ≤ cap)
    (database : Database Key (VectorOutput Counter)) (recordBound : size database < cap)
    (key : Key) (event : Property Key (VectorOutput Counter))
    (changed : ∀ output, event (query database key output) →
      stageVectorTrace next role fuel keyBytes counter queries (query database key output) ≠
        stageVectorTrace next role fuel keyBytes counter queries database) :
    stepProbability event database key ≤ (3*cap : Rat)/(2^512 : Rat) := by
  by_cases absent : database key = none
  · let changedDigests := changedOutputs next
      (rawRecords keyBytes (vectorOutputBytes counter) database) (keyBytes key) fuel
      (selectedTargets role queries)
    have subset : successfulAnswers event database key ⊆
        Finset.univ.filter (fun vector : VectorOutput Counter =>
          rawDigestBits.symm (vector counter) ∈ changedDigests) := by
      intro output member
      apply Finset.mem_filter.mpr
      refine ⟨Finset.mem_univ _, Finset.mem_filter.mpr ⟨Finset.mem_univ _, ?_⟩⟩
      have changes := changed output (Finset.mem_filter.mp member).2
      simpa only [stageVectorTrace, prefixTrace, query_of_absent absent,
        raw_records_insert keyBytes (vectorOutputBytes counter) database key output absent,
        vectorOutputBytes] using changes
    have digestCard : (Finset.univ.filter fun output : DigestRegister =>
        rawDigestBits.symm output ∈ changedDigests).card = changedDigests.card :=
      equiv_event_card rawDigestBits.symm changedDigests
    calc
      stepProbability event database key ≤
          ((Finset.univ.filter fun vector : VectorOutput Counter =>
            rawDigestBits.symm (vector counter) ∈ changedDigests).card : Rat) /
            Fintype.card (VectorOutput Counter) := by
        apply div_le_div_of_nonneg_right
        · exact_mod_cast Finset.card_le_card subset
        · positivity
      _ = (changedDigests.card : Rat)/(2^512 : Rat) := by
        rw [coordinate_event_probability counter
          (fun output => rawDigestBits.symm output ∈ changedDigests), digestCard,
          V8Smz9RawCounterCompiler.digest_register_cardinality]
        simp only [Nat.cast_pow, Nat.cast_ofNat]
      _ ≤ _ := by
        have bound := selected_stage_change_probability_le next children role
          (rawRecords keyBytes (vectorOutputBytes counter) database) (keyBytes key)
          queries fuel cap (lt_of_le_of_lt (raw_records_card_le _ _ _) recordBound) queryBound
        simpa only [uniformChangeProbability, raw_digest_cardinality, Nat.cast_pow,
          Nat.cast_ofNat, changedDigests] using bound
  · rw [step_probability_eq_zero_of_never event database key]
    · positivity
    · intro output accepted
      apply changed output accepted
      simp [query, absent]

theorem stage_vector_value_instability
    (next : Next)
    (children : ∀ stage input edges, next stage input = some edges →
      ∀ edge ∈ edges, edge.2 ∈ V8SmzaOracleParser.rawChildren input)
    (role : Role) (fuel : Nat) (keyBytes : Key → RawInput) (counter : Counter)
    (queries : List RawInput) (cap : Nat) (queryBound : queries.length ≤ cap)
    (value : Database Key (VectorOutput Counter) → Answer)
    (stable : ∀ left right, stageVectorTrace next role fuel keyBytes counter queries left =
      stageVectorTrace next role fuel keyBytes counter queries right → value left = value right)
    (test : Answer → Prop) :
    InstabilityBound (fun database => test (value database)) cap ((3*cap : Rat)/(2^512 : Rat)) := by
  constructor
  · refine ⟨by positivity, ?_⟩
    intro database outside recordBound key
    apply stage_vector_step_change_bound next children role fuel keyBytes counter queries cap
      queryBound database recordBound key _
    intro output accepted same
    apply outside
    change test (value (query database key output)) at accepted
    simpa only [stable _ _ same] using accepted
  · refine ⟨by positivity, ?_⟩
    intro database inside recordBound key
    apply stage_vector_step_change_bound next children role fuel keyBytes counter queries cap
      queryBound database recordBound key _
    intro output rejected same
    apply rejected
    rw [stable _ _ same]
    exact inside

variable {Workspace : Type*} [Fintype Answer] [DecidableEq Answer] [AddGroup Answer]
variable [Fintype Workspace] [DecidableEq Workspace]

/-- Actual vector CMS query bound. Its assumptions are finite geometry,
reachable support, and deterministic trace postprocessing, not security success. -/
theorem selected_stage_full_vector_query_bound
    (next : Next)
    (children : ∀ stage input edges, next stage input = some edges →
      ∀ edge ∈ edges, edge.2 ∈ V8SmzaOracleParser.rawChildren input)
    (role : Role) (fuel : Nat) (keyBytes : Key → RawInput) (counter : Counter)
    (queries : List RawInput) (cap support : Nat)
    (queryBound : queries.length ≤ cap) (below : support < cap)
    (value : Database Key (VectorOutput Counter) → Answer)
    (stable : ∀ left right, stageVectorTrace next role fuel keyBytes counter queries left =
      stageVectorTrace next role fuel keyBytes counter queries right → value left = value right)
    (state : State Key (VectorOutput Counter) (VectorOutput Counter) (Answer × Workspace))
    (bounded : BoundedState support state) :
    normSquared (permute (answerShift value) (queryState vectorPhaseSystem cap state) -
      queryState vectorPhaseSystem cap (permute (answerShift value) state)) ≤
      (576*cap/(2^512 : Real))*normSquared state := by
  have result := full_answer_actual_query_bound vectorPhaseSystem cap support value
    (((3*cap : Rat)/(2^512 : Rat)) : Real)
    (fun test => by
      simpa only [Rat.cast_div] using
        (stage_vector_value_instability next children role fuel keyBytes counter queries cap
          queryBound value stable test).toReal) state below bounded
  convert result using 1
  push_cast
  ring

end

end HegemonCrypto.SmallWood.SmzaStageVectorInstability
