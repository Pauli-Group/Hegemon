import SmzaRp05CurrentFixedEarlierAdvice
import SmzaRp05CurrentGroupedClaimRetention

/-! Exact common-origin bridge for fixed advice: on one nonzero physical
branch, the fixed lookup and the finite grouped database both retain the
same recorded vector. This does not assert that an arbitrary fixed table is
the database; the fixed value is obtained from the branch fiber, while the
database value is obtained from that branch's claims event. -/

namespace HegemonCrypto.SmallWood.SmzaRp05CurrentFixedAdviceClaimCell

open scoped Classical
open SmzaRp05CurrentAdaptiveExecution (Context CmsState)
open SmzaRp05ConditionedExecution
  (FixedTable ActiveMemory fixedVectorAtNonce fixedFiberToActive
    otherRoleTransform)
open SmzaRp05CurrentFixedEarlierAdvice
  (currentFixedVectorDecodedAt current_fixed_vector_decoded_from_actual_branch)
open SmzaRp05CurrentFiniteGroupedProgram (Key encode)
open SmzaRp05CurrentGroupedClaimRetention (groupedDecode)
open SmzaRp05CurrentGroupedOracleVector (finiteGroupedDatabaseOracle)
open SmzaRp05PhysicalAcceptedReplayLite
  (Branches answerLog branchKeys branchAnswers branchClaims branch_claims_eq_answer_log)
open SmzaRp05AdaptiveRetainedAdviceFixedReadback
  (nonzero_physical_branch_fixed_vector_readback)
open HegemonCrypto.CmsCompressedOracle (Basis)
open HegemonCrypto.CmsOracleDatabaseBridge (ClaimsDatabaseEvent)
open HegemonCrypto.FiniteOracleDatabase (Database)
open SmzaChallengeStageTargets (StageQuery parseStageQuery)
open SmzaRoleDomainConditioning (ActiveKey)
open SmzaRp05ExecutableMerkleVerifier (Program)
open V8SmzaOracleParser (RawInput RawDigest)
open V8Smz9CoherentVectorMerkle (VectorOutput)
open SmzaRp05CurrentAdaptiveExecution (Work)

noncomputable section
set_option autoImplicit false
set_option maxRecDepth 12000

/-- The active fixed-vector readback and the claims-retained finite key are
two consequences of the same physical answer record. The theorem keeps the
original vector and database key explicit for the later grouped-coordinate
decoder bridge. -/
theorem actual_branch_claimed_fixed_cell
    {BaseWork Result : Type}
    [Fintype BaseWork] [DecidableEq BaseWork]
    (producerProgram : Program Result)
    (ctx : Context
      (Key := SmzaRp05CurrentFiniteGroupedProgram.Key
        producerProgram)
      (Counter := SmzaRp05GroupedSuffix.GroupCounter)
      (BaseWork := BaseWork))
    (keyInjection : Function.Injective ctx.keyBytes)
    (blockCap : SmzaChallengeStageTargets.Role → Nat)
    (dummy : ActiveKey ctx.role blockCap ctx.keyBytes)
    (fixed : FixedTable ctx blockCap)
    (branch : Branches groupedDecode producerProgram)
    (state : CmsState
      (Key := SmzaRp05CurrentFiniteGroupedProgram.Key producerProgram)
      (Counter := SmzaRp05GroupedSuffix.GroupCounter)
      (BaseWork := BaseWork))
    (basis : Basis (ActiveKey ctx.role blockCap ctx.keyBytes)
      (VectorOutput SmzaRp05GroupedSuffix.GroupCounter)
      (VectorOutput SmzaRp05GroupedSuffix.GroupCounter)
      (ActiveMemory ctx))
    (nonzero : fixedFiberToActive ctx blockCap dummy fixed
      (otherRoleTransform ctx blockCap
        (SmzaRp05PhysicalAcceptedReplayLite.physicalRun
          (SmzaRp05CurrentFiniteGroupedProgram.encode producerProgram)
          groupedDecode producerProgram branch state)) basis ≠ 0)
    (database : Database
      (SmzaRp05CurrentFiniteGroupedProgram.Key producerProgram)
      (VectorOutput SmzaRp05GroupedSuffix.GroupCounter))
    (fallback : RawDigest)
    (claims : ClaimsDatabaseEvent
      (branchClaims
        (branchKeys (SmzaRp05CurrentFiniteGroupedProgram.encode producerProgram)
          groupedDecode producerProgram branch)
        (branchAnswers (SmzaRp05CurrentFiniteGroupedProgram.encode producerProgram)
          groupedDecode producerProgram branch)) database)
    (call : RawInput × VectorOutput SmzaRp05GroupedSuffix.GroupCounter)
    (recorded : call ∈ answerLog groupedDecode producerProgram branch)
    (query : StageQuery)
    (parsed : parseStageQuery
      (ctx.keyBytes (SmzaRp05CurrentFiniteGroupedProgram.encode producerProgram call.1)) =
        some query)
    (different : query.role ≠ ctx.role)
    (bounded : query.counter < blockCap query.role)
    (base : query.counter = 0)
    (statement : SmzaRp05StatementNamespace.Statement) :
    fixedVectorAtNonce ctx blockCap fixed query.role query.target query.nonce =
        some call.2 ∧
      database (SmzaRp05CurrentFiniteGroupedProgram.encode producerProgram call.1) =
        some call.2 ∧
      finiteGroupedDatabaseOracle producerProgram database
        fallback call.1 =
        groupedDecode call.1 call.2 ∧
      currentFixedVectorDecodedAt ctx blockCap fixed statement
        query.role query.target query.nonce =
        (match query.role with
         | .decsMatrix => SmzaRp05CurrentDecsMatrixSampling.currentActualDecsMatrixOutput
             (ctx.routes statement).decsMatrix call.2
         | .piopMatrix => SmzaRp04RawRoleSampling.actualPiopMatrixOutput
             (ctx.routes statement).piopMatrix call.2
         | .piopOpening => SmzaRp04RawRoleSampling.actualPiopOpeningOutput
             (ctx.routes statement).piopOpening call.2
         | .decsSample => SmzaRp04RawRoleSampling.actualDecsSampleOutput
             (ctx.routes statement).decsSample call.2) := by
  have actualFixed := nonzero_physical_branch_fixed_vector_readback
    ctx keyInjection blockCap dummy fixed
    (SmzaRp05CurrentFiniteGroupedProgram.encode producerProgram) groupedDecode
    producerProgram branch state basis nonzero call recorded query parsed different
    bounded base
  have stored : database
      (SmzaRp05CurrentFiniteGroupedProgram.encode producerProgram call.1) = some call.2 := by
    apply claims
      (SmzaRp05CurrentFiniteGroupedProgram.encode producerProgram call.1, call.2)
    rw [branch_claims_eq_answer_log]
    exact List.mem_map.mpr ⟨call, recorded, rfl⟩
  have oracleRead : finiteGroupedDatabaseOracle producerProgram database
      fallback call.1 =
        groupedDecode call.1 call.2 := by
    simp [finiteGroupedDatabaseOracle, stored, groupedDecode]
  exact ⟨actualFixed, stored, oracleRead,
    current_fixed_vector_decoded_from_actual_branch
      ctx keyInjection blockCap dummy fixed
      (SmzaRp05CurrentFiniteGroupedProgram.encode producerProgram) groupedDecode
      producerProgram branch state basis nonzero call recorded query parsed different
      bounded base statement⟩

end
end HegemonCrypto.SmallWood.SmzaRp05CurrentFixedAdviceClaimCell
