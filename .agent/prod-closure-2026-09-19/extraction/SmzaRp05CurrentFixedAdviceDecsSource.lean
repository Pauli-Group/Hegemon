import SmzaRp05CurrentFixedAdviceClaimCell
import SmzaRp05CurrentGroupedContext
import SmzaRp05CurrentExecutedEarlierAdvice
import SmzaRp05CurrentGroupedRoutes

/-! Current DECS fixed advice, the branch-retained grouped vector, and the
literal current source oracle are joined on one actual recorded branch call.
The grouped context fixes both representative bytes and value-preserving
counter routes; no free route or fixed-table/database equality is assumed. -/

namespace HegemonCrypto.SmallWood.SmzaRp05CurrentFixedAdviceDecsSource

open scoped Classical
open SmzaRp05CurrentGroupedContext (currentGroupedContext
  current_grouped_context_key_injective parsed_representative_determines_grouped_counter_calls)
open SmzaRp05CurrentGroupedRoutes (currentGroupedRoutes_decsMatrix_val)
open SmzaRp05CurrentFixedAdviceClaimCell (actual_branch_claimed_fixed_cell)
open SmzaRp05CurrentFixedEarlierAdvice
  (currentFixedVectorDecodedAt current_decs_matrix_decoder_from_stored_group_cell)
open SmzaRp05CurrentExecutedEarlierAdvice (currentOracleDecodedAt)
open SmzaRp05CurrentFiniteGroupedProgram (Key included encode)
open SmzaRp05CurrentGroupedOracleVector (finiteGroupedDatabaseOracle)
open SmzaRp05GroupedSuffix
  (GroupCounter groupEncode CanonicalRolePrefix groupRepresentative)
open SmzaRp05CurrentDecsMatrixSampling (currentActualDecsMatrixOutput)
open SmzaRp05ConditionedExecution
  (FixedTable ActiveMemory fixedFiberToActive otherRoleTransform)
open SmzaRp05CurrentAdaptiveExecution (CmsState Context)
open SmzaRp05PhysicalAcceptedReplayLite
  (Branches answerLog branchClaims branchKeys branchAnswers)
open HegemonCrypto.CmsCompressedOracle (Basis)
open HegemonCrypto.CmsOracleDatabaseBridge (ClaimsDatabaseEvent)
open HegemonCrypto.FiniteOracleDatabase (Database)
open SmzaChallengeStageTargets (Role StageQuery parseStageQuery)
open SmzaRoleDomainConditioning (ActiveKey)
open SmzaRp05ExecutableMerkleVerifier (Program)
open SmzaRp05CurrentGroupedClaimRetention (groupedDecode)
open V8SmzaOracleParser (RawDigest RawInput)
open V8Smz9CoherentVectorMerkle (VectorOutput)
open V8Smz9RawCounterCompiler (digestCallCap)
open HegemonCrypto.SmallWoodTranscript (decsCoefficientDomain)

noncomputable section
set_option autoImplicit false
set_option maxRecDepth 12000
set_option maxHeartbeats 1000000

abbrev ConcreteContext {Result BaseWork : Type}
    [Fintype BaseWork] [DecidableEq BaseWork]
    (program : Program Result) (model : SmzaRp05TracePrefixes.RelationModel)
    (bounded : SmzaRp05ConcreteSuffix.ModelWithinProtocol model)
    (ns : SmzaRp05LeafNamespace.Namespace) (role : Role)
    (advice : SmzaRp05TracePrefixes.AllEarlierTables model role)
    (outerFuel innerFuel : Nat)
    (authorizedOf : BaseWork → Finset (List HegemonCrypto.CanonicalBytes.Byte)) :=
  currentGroupedContext program model bounded ns role advice
    outerFuel innerFuel authorizedOf

/-- For a current DECS-matrix call on the same retained branch, the accepted
fixed-complement vector decodes exactly as the current source oracle. The
finite vector is obtained from the recorded call's claims, not postulated to
equal the fixed table; the fixed-table value is separately forced by the
nonzero physical fiber. -/
theorem current_decs_fixed_advice_matches_same_branch_source
    {Result BaseWork : Type} [Fintype BaseWork] [DecidableEq BaseWork]
    (program : Program Result) (model : SmzaRp05TracePrefixes.RelationModel)
    (boundedModel : SmzaRp05ConcreteSuffix.ModelWithinProtocol model)
    (ns : SmzaRp05LeafNamespace.Namespace) (role : Role)
    (advice : SmzaRp05TracePrefixes.AllEarlierTables model role)
    (outerFuel innerFuel : Nat)
    (authorizedOf : BaseWork → Finset (List HegemonCrypto.CanonicalBytes.Byte))
    (blockCap : Role → Nat)
    (dummy : ActiveKey
      (currentGroupedContext program model boundedModel ns role advice
        outerFuel innerFuel authorizedOf).role blockCap
      (currentGroupedContext program model boundedModel ns role advice
        outerFuel innerFuel authorizedOf).keyBytes)
    (fixed : FixedTable
      (currentGroupedContext program model boundedModel ns role advice
        outerFuel innerFuel authorizedOf) blockCap)
    (branch : Branches groupedDecode program)
    (state : CmsState
      (Key := Key program) (Counter := GroupCounter) (BaseWork := BaseWork))
    (basis : Basis
      (ActiveKey
        (currentGroupedContext program model boundedModel ns role advice
          outerFuel innerFuel authorizedOf).role blockCap
        (currentGroupedContext program model boundedModel ns role advice
          outerFuel innerFuel authorizedOf).keyBytes)
      (VectorOutput GroupCounter) (VectorOutput GroupCounter)
      (ActiveMemory (currentGroupedContext program model boundedModel ns role advice
        outerFuel innerFuel authorizedOf)))
    (nonzero : fixedFiberToActive
      (currentGroupedContext program model boundedModel ns role advice
        outerFuel innerFuel authorizedOf) blockCap dummy fixed
      (otherRoleTransform
        (currentGroupedContext program model boundedModel ns role advice
          outerFuel innerFuel authorizedOf) blockCap
        (SmzaRp05PhysicalAcceptedReplayLite.physicalRun
          (encode program) groupedDecode program branch state)) basis ≠ 0)
    (database : Database (Key program) (VectorOutput GroupCounter))
    (fallback : RawDigest)
    (claims : ClaimsDatabaseEvent
      (branchClaims (branchKeys (encode program) groupedDecode program branch)
        (branchAnswers (encode program) groupedDecode program branch)) database)
    (call : RawInput × VectorOutput GroupCounter)
    (recorded : call ∈ answerLog groupedDecode program branch)
    (statement : SmzaRp05StatementNamespace.Statement)
    (query : StageQuery)
    (parsed : parseStageQuery
      ((currentGroupedContext program model boundedModel ns role advice
        outerFuel innerFuel authorizedOf).keyBytes (encode program call.1)) =
          some query)
    (currentRole : query.role = .decsMatrix)
    (selectedRoleEarlier : .decsMatrix ≠ role)
    (positiveMatrixCap : 0 < blockCap .decsMatrix)
    (base : query.counter = 0) :
    currentFixedVectorDecodedAt
        (currentGroupedContext program model boundedModel ns role advice
          outerFuel innerFuel authorizedOf)
        blockCap fixed statement .decsMatrix query.target query.nonce =
      currentOracleDecodedAt model
        (finiteGroupedDatabaseOracle program database fallback)
        statement .decsMatrix query.target := by
  let ctx := currentGroupedContext program model boundedModel ns role advice
    outerFuel innerFuel authorizedOf
  have keyInjection := current_grouped_context_key_injective
    program model boundedModel ns role advice outerFuel innerFuel authorizedOf
  have parsedRep : parseStageQuery
      (groupRepresentative (included program (encode program call.1))) = some query := by
    change parseStageQuery
      ((currentGroupedContext program model boundedModel ns role advice
        outerFuel innerFuel authorizedOf).keyBytes (encode program call.1)) = some query
    exact parsed
  obtain ⟨rolePrefix, keyIdentity, allCalls⟩ :=
    parsed_representative_determines_grouped_counter_calls
      (included program (encode program call.1)) query parsedRep base
  have roleDifferent : query.role ≠ ctx.role := by
    change query.role ≠ role
    intro same
    exact selectedRoleEarlier (currentRole.symm.trans same)
  have roleBounded : query.counter < blockCap query.role := by
    simpa [currentRole, base] using positiveMatrixCap
  have actualCell := actual_branch_claimed_fixed_cell program ctx keyInjection
    blockCap dummy fixed branch state basis nonzero database fallback claims call
    recorded query parsed roleDifferent roleBounded base statement
  rcases actualCell with ⟨_fixedVector, stored, _oracleRead, fixedDecoder⟩
  have counterAddress : ∀ index : Fin (digestCallCap 700),
      SmzaRp05ExecutableChallengeStage.counterInput decsCoefficientDomain
        query.target index.val =
        groupEncode (rolePrefix, (ctx.routes statement).decsMatrix index) := by
    intro index
    have coordinate := allCalls ((ctx.routes statement).decsMatrix index)
    have routeValue : ((ctx.routes statement).decsMatrix index).val = index.val := rfl
    rw [routeValue] at coordinate
    calc
      SmzaRp05ExecutableChallengeStage.counterInput decsCoefficientDomain
          query.target index.val =
        SmzaRp05CurrentGroupedRecordReadback.canonicalQueryCounterInput
          query index.val := by
            simp only [SmzaRp05CurrentGroupedRecordReadback.canonicalQueryCounterInput,
              currentRole, SmzaChallengeStageTargets.roleDomain]
      _ = groupEncode (rolePrefix, (ctx.routes statement).decsMatrix index) :=
        coordinate.symm
  have decoder := current_decs_matrix_decoder_from_stored_group_cell
    program database fallback (encode program call.1) rolePrefix keyIdentity call.2
    stored model statement query.target (ctx.routes statement).decsMatrix counterAddress
  have fixedDecoder' : currentFixedVectorDecodedAt ctx blockCap fixed statement
      .decsMatrix query.target query.nonce =
      currentActualDecsMatrixOutput (ctx.routes statement).decsMatrix call.2 := by
    cases query with
    | mk queryRole target nonce counter =>
        cases currentRole
        exact fixedDecoder
  exact fixedDecoder'.trans decoder

end
end HegemonCrypto.SmallWood.SmzaRp05CurrentFixedAdviceDecsSource
