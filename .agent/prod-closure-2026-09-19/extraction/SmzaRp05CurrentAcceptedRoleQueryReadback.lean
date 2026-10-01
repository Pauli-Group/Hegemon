import SmzaRp05CurrentGroupedContext
import SmzaRp05CurrentGroupedClaimRetention
import SmzaRp05CurrentGroupedOracleVector
import SmzaRp05CurrentFiniteGroupedProgram
import SmzaRp05CurrentRoleLabels

/-! # Actual grouped role-call readback

An answer retained by one physical branch determines its exact finite
grouped key, role-prefix query target, and claimed vector. Claims retain the
same vector in the compressed database, whose answer at every role coordinate
is consequently fixed. This statement is independent of which role is the
active context role; it makes no earlier-role/fixed-fiber assumption. -/

namespace HegemonCrypto.SmallWood.SmzaRp05CurrentAcceptedRoleQueryReadback

open HegemonCrypto.CmsOracleDatabaseBridge (ClaimsDatabaseEvent)
open HegemonCrypto.FiniteOracleDatabase (Database)
open SmzaRp05CurrentGroupedClaimRetention (groupedDecode)
open SmzaRp05CurrentGroupedOracleVector
  (finiteGroupedDatabaseOracle stored_group_vector_answers_every_counter)
open SmzaRp05CurrentFiniteGroupedProgram (Key encode included)
open SmzaRp05PhysicalAcceptedReplayLite
  (Branches answerLog branchKeys branchAnswers branchClaims branch_claims_eq_answer_log)
open SmzaRp05GroupedSuffix
  (CanonicalRolePrefix GroupCounter groupEncode groupRepresentative)
open HegemonCrypto.SmallWood.SmzaChallengeStageTargets
  (Role StageQuery parseStageQuery roleStage)
open SmzaRp05CurrentGroupedContext
  (parsed_representative_determines_grouped_counter_calls)
open SmzaRp05CurrentRoleLabels (targetOfRaw target_of_parsed_role)
open SmzaRp05ExecutableMerkleVerifier (Program)
open V8SmzaOracleParser (RawInput RawDigest)
open V8Smz9CoherentVectorMerkle (VectorOutput)
open V8Smz9CoherentMerkleInstrument (rawDigestBits)

noncomputable section
set_option autoImplicit false

/-- A recorded answer at a current counter-zero role query fixes one finite
grouped key. The theorem returns the actual role-prefixed key and target,
claims-retained vector at that key, finite-oracle answer for the call, and
the oracle answer for every coordinate consumed by that role's current
decoder route. Instantiate it for any of the four challenge roles. -/
theorem current_actual_grouped_role_call_readback
    {Result : Type} (program : Program Result)
    (branch : Branches groupedDecode program)
    (call : RawInput × VectorOutput GroupCounter)
    (recorded : call ∈ answerLog groupedDecode program branch)
    (database : Database (Key program) (VectorOutput GroupCounter))
    (claims : ClaimsDatabaseEvent
      (branchClaims (branchKeys (encode program) groupedDecode program branch)
        (branchAnswers (encode program) groupedDecode program branch)) database)
    (fallback : RawDigest) (role : Role) (query : StageQuery)
    (parsed : parseStageQuery
      (groupRepresentative (included program (encode program call.1))) = some query)
    (queryRole : query.role = role) (counterZero : query.counter = 0) :
    ∃ rolePrefix : CanonicalRolePrefix,
      included program (encode program call.1) = Sum.inl rolePrefix ∧
      parseStageQuery (groupRepresentative (Sum.inl rolePrefix)) = some query ∧
      (∀ coordinate : GroupCounter,
        groupEncode (rolePrefix, coordinate) =
          SmzaRp05CurrentGroupedRecordReadback.canonicalQueryCounterInput
            query coordinate.val) ∧
      targetOfRaw role
        (groupRepresentative (included program (encode program call.1))) =
          (roleStage role, query.target) ∧
      database (encode program call.1) = some call.2 ∧
      finiteGroupedDatabaseOracle program database fallback call.1 =
        groupedDecode call.1 call.2 ∧
      (∀ coordinate : GroupCounter,
        finiteGroupedDatabaseOracle program database fallback
          (groupEncode (rolePrefix, coordinate)) =
            rawDigestBits.symm (call.2 coordinate)) := by
  obtain ⟨rolePrefix, keyIdentity, allCoordinates⟩ :=
    parsed_representative_determines_grouped_counter_calls
      (included program (encode program call.1)) query parsed counterZero
  have representativeQuery :
      parseStageQuery (groupRepresentative (Sum.inl rolePrefix)) = some query := by
    rw [← keyIdentity]
    exact parsed
  have targetRead := target_of_parsed_role role
    (groupRepresentative (included program (encode program call.1))) query
    parsed queryRole
  have stored : database (encode program call.1) = some call.2 := by
    apply claims (encode program call.1, call.2)
    rw [branch_claims_eq_answer_log]
    exact List.mem_map.mpr ⟨call, recorded, rfl⟩
  have oracleRead : finiteGroupedDatabaseOracle program database fallback call.1 =
      groupedDecode call.1 call.2 := by
    simp [finiteGroupedDatabaseOracle, stored, groupedDecode]
  refine ⟨rolePrefix, keyIdentity, representativeQuery, allCoordinates,
    targetRead, stored, oracleRead, ?_⟩
  intro coordinate
  exact stored_group_vector_answers_every_counter program database fallback
    (encode program call.1) rolePrefix keyIdentity call.2 stored coordinate

end
end HegemonCrypto.SmallWood.SmzaRp05CurrentAcceptedRoleQueryReadback
