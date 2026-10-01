import SmzaRp05CurrentGroupedRecordReadback
import SmzaRp05PhysicalAcceptedReplayLite
import SmzaRp05AdaptiveDynamicBad
import SmzaRp05CurrentFiniteGroupedProgram

/-! Actual branch claims retain nonchallenge raw records in the grouped
representative database. Challenge counters are deliberately not asserted to
occur in that database. The finite key embedding is explicit; the input's
representative and zero coordinate are derived from its parser result. -/
namespace HegemonCrypto.SmallWood.SmzaRp05CurrentGroupedClaimRetention

open HegemonCrypto.CmsOracleDatabaseBridge
open HegemonCrypto.FiniteOracleDatabase
open SmzaRp05ExecutableMerkleVerifier (Program Oracle)
open SmzaRp05PhysicalAcceptedReplayLite
open SmzaRp05GroupedSuffix
open SmzaRp05CurrentGroupedRecordReadback
open SmzaChallengeStageTargets (parseStageQuery)
open V8Smz9CoherentVectorMerkle (VectorOutput vectorOutputBytes)
open V8Smz9CoherentMerkleInstrument (rawRecords)
open SmzaRawDatabaseRecords (mem_raw_records_iff)
open V8SmzaOracleParser (RawInput RawDigest)

noncomputable section
set_option autoImplicit false

def groupedDecode (raw : RawInput) (vector : VectorOutput GroupCounter) : RawDigest :=
  vectorOutputBytes (groupCounterOf raw) vector

/-- A consistent compressed claim table supplies the literal decoded
answer for every call of the same branch. This is a pure replay statement,
not a commutation assertion about quantum projections. -/
theorem claims_supply_grouped_oracle_answers
    {Key Result : Type} [Fintype Key] [DecidableEq Key]
    (encode : RawInput → Key) (program : Program Result)
    (branch : Branches groupedDecode program)
    (database : Database Key (VectorOutput GroupCounter))
    (claims : ClaimsDatabaseEvent
      (branchClaims (branchKeys encode groupedDecode program branch)
        (branchAnswers encode groupedDecode program branch)) database)
    (fallback : RawDigest) :
    ∀ call ∈ answerLog groupedDecode program branch,
      groupedDecode call.1 call.2 =
        (match database (encode call.1) with
        | none => fallback
        | some vector => groupedDecode call.1 vector) := by
  intro call member
  have retained : database (encode call.1) = some call.2 := by
    apply claims (encode call.1, call.2)
    rw [branch_claims_eq_answer_log]
    exact List.mem_map.mpr ⟨call, member, rfl⟩
  rw [retained]

/-- Only the actual finite-key inclusion is supplied. Nonchallenge identity
and coordinate zero follow from the concrete grouped parser construction. -/
theorem claims_retain_nonchallenge_raw_log
    {Key Result : Type} [Fintype Key] [DecidableEq Key]
    (included : Key → GroupKey) (encode : RawInput → Key)
    (program : Program Result) (branch : Branches groupedDecode program)
    (represented : ∀ call ∈ answerLog groupedDecode program branch,
      included (encode call.1) = groupKeyOf call.1)
    (database : Database Key (VectorOutput GroupCounter))
    (claims : ClaimsDatabaseEvent
      (branchClaims (branchKeys encode groupedDecode program branch)
        (branchAnswers encode groupedDecode program branch)) database) :
    ∀ call ∈ rawLog groupedDecode program branch,
      parseStageQuery call.1 = none →
        call ∈ rawRecords (fun key => groupRepresentative (included key))
          (vectorOutputBytes groupZero) database := by
  classical
  intro call member notChallenge
  obtain ⟨answer, recorded, pairEq⟩ := List.mem_map.mp member
  subst call
  obtain ⟨representative, coordinate⟩ :=
    nonchallenge_input_is_group_representative answer.1 notChallenge
  have retained : database (encode answer.1) = some answer.2 := by
    apply claims (encode answer.1, answer.2)
    rw [branch_claims_eq_answer_log]
    exact List.mem_map.mpr ⟨answer, recorded, rfl⟩
  apply (mem_raw_records_iff _ _ _ _ _).mpr
  refine ⟨encode answer.1, answer.2, retained, ?_, ?_⟩
  · rw [represented answer recorded]
    exact representative.symm
  · change vectorOutputBytes groupZero answer.2 =
      vectorOutputBytes (groupCounterOf answer.1) answer.2
    change vectorOutputBytes groupZero answer.2 =
      vectorOutputBytes (groupAddress answer.1).2 answer.2
    rw [coordinate]

/-- Same-program specialization: the finite universe is constructed before
any answers, and its encoder represents every branch call by construction.
Neither answer agreement nor grouped-record retention is a caller premise. -/
theorem actual_program_grouped_claims_replay_and_retain
    {Result : Type} (program : Program Result)
    (branch : Branches groupedDecode program)
    (database : Database (SmzaRp05CurrentFiniteGroupedProgram.Key program)
      (VectorOutput GroupCounter))
    (claims : ClaimsDatabaseEvent
      (branchClaims
        (branchKeys (SmzaRp05CurrentFiniteGroupedProgram.encode program)
          groupedDecode program branch)
        (branchAnswers (SmzaRp05CurrentFiniteGroupedProgram.encode program)
          groupedDecode program branch)) database)
    (fallback : RawDigest) :
    let oracle : Oracle := fun raw =>
      match database (SmzaRp05CurrentFiniteGroupedProgram.encode program raw) with
      | none => fallback
      | some vector => groupedDecode raw vector
    program.record oracle =
      (branchResult groupedDecode program branch, rawLog groupedDecode program branch) ∧
      ∀ call ∈ rawLog groupedDecode program branch,
        parseStageQuery call.1 = none →
          call ∈ rawRecords
            (fun key => groupRepresentative
              (SmzaRp05CurrentFiniteGroupedProgram.included program key))
            (vectorOutputBytes groupZero) database := by
  let encode := SmzaRp05CurrentFiniteGroupedProgram.encode program
  have answers := claims_supply_grouped_oracle_answers encode program branch
    database claims fallback
  constructor
  · exact record_eq_of_branch_answers encode groupedDecode program branch _ answers
  · exact claims_retain_nonchallenge_raw_log
      (SmzaRp05CurrentFiniteGroupedProgram.included program) encode program branch
      (SmzaRp05CurrentFiniteGroupedProgram.answer_log_group_keys_represented
        groupedDecode program branch) database claims

end
end HegemonCrypto.SmallWood.SmzaRp05CurrentGroupedClaimRetention
