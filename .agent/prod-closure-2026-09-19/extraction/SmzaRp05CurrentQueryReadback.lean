import SmzaRp05ConsumedFieldReadback
import SmzaRp05CurrentFieldCounterParser
import SmzaRp05Q38ExecutionCountBridge
import Q38Rp05CurrentPostfinal

/-! The current SMZA fifty-word source XOF, pending-failure guard and q38
selector yield the counted role decoder on the same measured vector. The
source inputs use `currentFixedIndexKey`, not the historical SMZ9 framing.
No AcceptedChecks or physical-execution-certificate premise is introduced. -/
namespace HegemonCrypto.SmallWood.SmzaRp05CurrentQueryReadback

open SmzaRp05Q38ExecutionCountBridge
open SmzaRp05ConsumedFieldReadback
open SmzaRp04RawRoleSampling SmzaQ38McaSourceBinding
open Q38Rp05CurrentPostfinal Q38Rp05RawInputPartition
open V8Smz9HonestRequestSchedule V8Smz9HonestOpeningSchedule
open V8Smz9HiddenLeafQrom V8Smz9RawCounterCompiler
open V8Smz9CappedRawSampler V8Smz9CoherentMerkleInstrument
open V8Smz9CoherentVectorMerkle V8Smz9RuntimeRandomness
open V8Smz9WholeViewObservation V8Smz9ZeroKnowledge
open scoped Classical
noncomputable section
set_option autoImplicit false

open HegemonCrypto.SmallWood.SmzaRp05CurrentFieldCounterParser

theorem source_digest_of_raw_bits (digest : DigestRegister) :
    sourceDigestOfByteBlock (rawDigestBits.symm digest) = sourceDigest digest :=
  HegemonCrypto.SmallWood.SmzaRp05CurrentFieldCounterParser.source_digest_of_raw_bits digest

theorem source_field_loop_is_counter_parser {Other : Type} {blocks : Nat}
    (requested : Nat) (keys : Fin blocks → Other)
    (oracle : Other → DigestRegister) :
    NonleafProgram.interpret oracle (sourceFieldReadLoop requested [] (List.ofFn keys)) =
      parseCounterVector requested (fun counter => sourceDigest (oracle (keys counter))) :=
  HegemonCrypto.SmallWood.SmzaRp05CurrentFieldCounterParser.source_field_loop_is_counter_parser
    requested keys oracle

def currentQueryRawBlocks (bound : Nat) (largeEnough : 39162 ≤ bound)
    (oracle : Rp05OtherRawInput bound → DigestRegister) (digest : DigestRegister) :
    Fin (digestCallCap q38CandidateCount) → RawByteBlock :=
  fun counter => rawDigestBits.symm (oracle
    (currentFixedIndexKey bound largeEnough digest ⟨counter.val, by
      have cap : digestCallCap q38CandidateCount = 11 := by decide
      have h : counter.val < 11 := by simpa only [cap] using counter.isLt
      exact Nat.lt_trans h (by decide)⟩))

theorem current_query_xof_is_raw_field_sample
    (bound : Nat) (largeEnough : 39162 ≤ bound)
    (oracle : Rp05OtherRawInput bound → DigestRegister) (digest : DigestRegister) :
    NonleafProgram.interpret oracle (currentFixedIndexXof bound largeEnough digest) =
      (rawFieldSample (digestCallCap q38CandidateCount) q38CandidateCount
        (currentQueryRawBlocks bound largeEnough oracle digest)).map q38StreamCandidates := by
  unfold currentFixedIndexXof
  change NonleafProgram.interpret oracle
      (sourceFieldReadLoop 50 [] (List.ofFn fun counter : Fin 11 =>
        currentFixedIndexKey bound largeEnough digest
          ⟨counter.val, by omega⟩)) =
    (rawFieldSample 11 50 (currentQueryRawBlocks bound largeEnough oracle digest)).map
      q38StreamCandidates
  rw [source_field_loop_is_counter_parser]
  calc
    parseCounterVector 50 (fun counter : Fin 11 =>
        sourceDigest (oracle (currentFixedIndexKey bound largeEnough digest
          ⟨counter.val, by omega⟩))) =
      parseCounterVector 50 (fun counter : Fin 11 =>
        sourceDigestOfByteBlock
          ((currentQueryRawBlocks bound largeEnough oracle digest) counter)) := by
            apply congrArg (parseCounterVector 50)
            funext counter
            change sourceDigest (oracle
                (currentFixedIndexKey bound largeEnough digest
                  ⟨counter.val, by omega⟩)) =
              sourceDigestOfByteBlock (rawDigestBits.symm (oracle
                (currentFixedIndexKey bound largeEnough digest
                  ⟨counter.val, by omega⟩)))
            exact (source_digest_of_raw_bits
              (oracle (currentFixedIndexKey bound largeEnough digest
                ⟨counter.val, by omega⟩))).symm
    _ = _ := exact_literal_byte_counter_parser 50 _

/-- Literal accepted selector event, including deferred XOF rejection. -/
theorem current_failure_checked_query_event
    (bound : Nat) (largeEnough : 39162 ≤ bound)
    (oracle : Rp05OtherRawInput bound → DigestRegister) (digest : DigestRegister)
    (points : Fin 6 → Goldilocks) (distinct : Function.Injective points)
    (pending : Bool) (query : Query) :
    (let sampled := NonleafProgram.interpret oracle
        (currentFixedIndexXof bound largeEnough digest)
     sourcePendingFailure pending sampled = false ∧
       (Q38Rp05PostFinalCompiler.sampledTargets points distinct
         (sourceReturnedWords 50 sampled)).map targetSupport = some query.val) ↔
      (pending = false ∧
        rawDecsSampleOutput (currentQueryRawBlocks bound largeEnough oracle digest) = some query) := by
  dsimp only
  rw [current_query_xof_is_raw_field_sample]
  exact failure_checked_support_event points distinct pending _ query

/-- The only table/vector premise is the concrete same-execution coordinate
read: each selected measured digest is the source oracle output at that
literal current-profile counter key. Unused vector coordinates are unrestricted. -/
theorem current_query_decoder_of_measured_vector
    {Counter : Type*}
    (bound : Nat) (largeEnough : 39162 ≤ bound)
    (oracle : Rp05OtherRawInput bound → DigestRegister) (digest : DigestRegister)
    (select : Fin (digestCallCap q38CandidateCount) ↪ Counter)
    (vector : VectorOutput Counter)
    (measured : ∀ counter, vector (select counter) = oracle
      (currentFixedIndexKey bound largeEnough digest ⟨counter.val, by
        have cap : digestCallCap q38CandidateCount = 11 := by decide
        have h : counter.val < 11 := by simpa only [cap] using counter.isLt
        exact Nat.lt_trans h (by decide)⟩)) :
    actualDecsSampleOutput select vector =
      rawDecsSampleOutput (currentQueryRawBlocks bound largeEnough oracle digest) := by
  unfold actualDecsSampleOutput
  apply congrArg rawDecsSampleOutput
  funext counter
  change rawDigestBits.symm (vector (select counter)) = _
  rw [measured]
  rfl

/-- Stronger log-facing readback: only coordinates actually consumed by
the source XOF need agree with the measured vector. In particular, the
unread tail of the eleven-coordinate route is not an evidence obligation. -/
theorem current_query_decoder_of_consumed_vector
    {Counter : Type*}
    (bound : Nat) (largeEnough : 39162 ≤ bound)
    (oracle : Rp05OtherRawInput bound → DigestRegister) (digest : DigestRegister)
    (select : Fin (digestCallCap q38CandidateCount) ↪ Counter)
    (vector : VectorOutput Counter)
    (measured : ∀ counter ∈ consumedFieldKeys q38CandidateCount
        (fun index => rawDigestBits (currentQueryRawBlocks bound largeEnough oracle digest index))
        [] (List.ofFn (fun index : Fin (digestCallCap q38CandidateCount) => index)),
      rawDigestBits (currentQueryRawBlocks bound largeEnough oracle digest counter) =
        vector (select counter)) :
    actualDecsSampleOutput select vector =
      rawDecsSampleOutput (currentQueryRawBlocks bound largeEnough oracle digest) := by
  have samples := raw_field_sample_eq_of_consumed_agreement
    (digestCallCap q38CandidateCount) q38CandidateCount
    (fun index => rawDigestBits (currentQueryRawBlocks bound largeEnough oracle digest index))
    (fun index => vector (select index)) measured
  simp only [Equiv.symm_apply_apply] at samples
  exact congrArg (fun sampled => sampled.bind q38Decoder) samples.symm

/-- Supplies the `queryRead` field of `AcceptedFailureWitness` from the
actual source selector's guarded success and the measured raw coordinates. -/
theorem current_source_acceptance_supplies_query_read
    {Counter : Type*}
    (bound : Nat) (largeEnough : 39162 ≤ bound)
    (oracle : Rp05OtherRawInput bound → DigestRegister) (digest : DigestRegister)
    (points : Fin 6 → Goldilocks) (distinct : Function.Injective points)
    (pending : Bool) (query : Query)
    (select : Fin (digestCallCap q38CandidateCount) ↪ Counter)
    (vector : VectorOutput Counter)
    (measured : ∀ counter ∈ consumedFieldKeys q38CandidateCount
        (fun index => rawDigestBits (currentQueryRawBlocks bound largeEnough oracle digest index))
        [] (List.ofFn (fun index : Fin (digestCallCap q38CandidateCount) => index)),
      rawDigestBits (currentQueryRawBlocks bound largeEnough oracle digest counter) =
        vector (select counter))
    (scopeFinished : sourcePendingFailure pending
      (NonleafProgram.interpret oracle (currentFixedIndexXof bound largeEnough digest)) = false)
    (selected : (Q38Rp05PostFinalCompiler.sampledTargets points distinct
      (sourceReturnedWords 50
        (NonleafProgram.interpret oracle (currentFixedIndexXof bound largeEnough digest)))).map
          targetSupport = some query.val) :
    actualDecsSampleOutput select vector = some query := by
  rw [current_query_decoder_of_consumed_vector bound largeEnough oracle digest select vector measured]
  exact ((current_failure_checked_query_event bound largeEnough oracle digest
    points distinct pending query).1 ⟨scopeFinished, selected⟩).2

end
end HegemonCrypto.SmallWood.SmzaRp05CurrentQueryReadback
