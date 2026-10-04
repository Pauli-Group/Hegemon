import SmzaRp05CurrentFixedAdviceClaimCell
import SmzaRp05CurrentGroupedContext
import SmzaRp05CurrentGroupedPiopDecoders
import SmzaRp05CurrentGroupedRoutes
import SmzaRp05CurrentExecutedEarlierAdvice

/-! Current fixed PIOP advice agrees with the literal source-oracle decoder
on the same branch-retained grouped cell. Opening readback is intentionally
per nonce; canonical first-success is handled only by the executed opening
stage and is not inferred from arbitrary other nonce cells. -/

namespace HegemonCrypto.SmallWood.SmzaRp05CurrentFixedAdvicePiopSource

open scoped Classical
open SmzaRp05CurrentGroupedContext (currentGroupedContext
  current_grouped_context_key_injective parsed_representative_determines_grouped_counter_calls)
open SmzaRp05CurrentGroupedRoutes
  (currentGroupedRoutes_piopMatrix_val currentGroupedRoutes_piopOpening_val)
open SmzaRp05CurrentFixedAdviceClaimCell (actual_branch_claimed_fixed_cell)
open SmzaRp05CurrentFixedEarlierAdvice (currentFixedVectorDecodedAt)
open SmzaRp05CurrentExecutedEarlierAdvice (currentOracleDecodedAt)
open SmzaRp05CurrentGroupedPiopDecoders
  (piop_matrix_decoder_from_stored_group_cell piop_opening_decoder_from_stored_group_cell)
open SmzaRp05CurrentFiniteGroupedProgram (Key included encode)
open SmzaRp05CurrentGroupedOracleVector (finiteGroupedDatabaseOracle)
open SmzaRp05GroupedSuffix (GroupCounter groupEncode CanonicalRolePrefix groupRepresentative)
open SmzaRp05ConditionedExecution
  (FixedTable ActiveMemory fixedFiberToActive otherRoleTransform)
open SmzaRp05CurrentAdaptiveExecution (CmsState)
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
open V8Smz9AdaptiveFiniteAccounting.Historical (piopOpenings)
open HegemonCrypto.SmallWoodTranscript (piopCoefficientDomain)

noncomputable section
set_option autoImplicit false
set_option maxRecDepth 12000
set_option maxHeartbeats 1000000

/-- The checked grouped context specializes its counter-preserving route to
the exact PIOP matrix input schedule. The retained claim from the same branch
supplies the stored full vector, and nonzero fiber readback supplies that
same vector to fixed advice. -/
theorem current_piop_matrix_fixed_advice_matches_same_branch_source
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
    (currentRole : query.role = .piopMatrix)
    (selectedRoleEarlier : .piopMatrix ≠ role)
    (positiveMatrixCap : 0 < blockCap .piopMatrix)
    (base : query.counter = 0) :
    currentFixedVectorDecodedAt
        (currentGroupedContext program model boundedModel ns role advice
          outerFuel innerFuel authorizedOf)
        blockCap fixed statement .piopMatrix query.target query.nonce =
      currentOracleDecodedAt model
        (finiteGroupedDatabaseOracle program database fallback)
        statement .piopMatrix query.target := by
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
  have counterAddress : ∀ index : Fin (digestCallCap (5 * model.width statement)),
      SmzaRp05ExecutableChallengeStage.counterInput piopCoefficientDomain
        query.target index.val =
        groupEncode (rolePrefix, (ctx.routes statement).piopMatrix index) := by
    intro index
    have coordinate := allCalls ((ctx.routes statement).piopMatrix index)
    have routeValue : ((ctx.routes statement).piopMatrix index).val = index.val := rfl
    rw [routeValue] at coordinate
    calc
      SmzaRp05ExecutableChallengeStage.counterInput piopCoefficientDomain
          query.target index.val =
        SmzaRp05CurrentGroupedRecordReadback.canonicalQueryCounterInput
          query index.val := by
            simp only [SmzaRp05CurrentGroupedRecordReadback.canonicalQueryCounterInput,
              currentRole, SmzaChallengeStageTargets.roleDomain]
      _ = groupEncode (rolePrefix, (ctx.routes statement).piopMatrix index) :=
        coordinate.symm
  have decoder := piop_matrix_decoder_from_stored_group_cell
    program database fallback (encode program call.1) rolePrefix keyIdentity call.2
    stored query.target (model.width statement) (ctx.routes statement).piopMatrix
    counterAddress
  have fixedDecoder' : currentFixedVectorDecodedAt ctx blockCap fixed statement
      .piopMatrix query.target query.nonce =
      SmzaRp04RawRoleSampling.actualPiopMatrixOutput
        (ctx.routes statement).piopMatrix call.2 := by
    cases query with
    | mk queryRole target nonce counter =>
        cases currentRole
        exact fixedDecoder
  exact fixedDecoder'.trans decoder

/-- A stored grouped cell fixes one nonce's PIOP-opening decoder. No
successful-stage or full first-success assumption is substituted for a
missing earlier nonce cell; the separate executed-opening theorem decides
which nonce is first. -/
theorem current_piop_opening_fixed_advice_matches_same_branch_source_nonce
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
    (currentRole : query.role = .piopOpening)
    (selectedRoleEarlier : .piopOpening ≠ role)
    (positiveOpeningCap : 0 < blockCap .piopOpening)
    (base : query.counter = 0) :
    currentFixedVectorDecodedAt
        (currentGroupedContext program model boundedModel ns role advice
          outerFuel innerFuel authorizedOf)
        blockCap fixed statement .piopOpening query.target query.nonce =
      SmzaRp04RawRoleSampling.actualPiopOpeningOutput
        (Equiv.refl (Fin (digestCallCap piopOpenings)))
        (SmzaRp05CurrentExecutedOpeningOutput.currentOpeningVector
          (finiteGroupedDatabaseOracle program database fallback)
          query.target query.nonce) := by
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
    simpa [currentRole, base] using positiveOpeningCap
  have actualCell := actual_branch_claimed_fixed_cell program ctx keyInjection
    blockCap dummy fixed branch state basis nonzero database fallback claims call
    recorded query parsed roleDifferent roleBounded base statement
  rcases actualCell with ⟨_fixedVector, stored, _oracleRead, fixedDecoder⟩
  have counterAddress : ∀ index : Fin (digestCallCap piopOpenings),
      SmzaRp05CurrentOpeningProgram.openingCounterInput
        query.target query.nonce index.val =
        groupEncode (rolePrefix, (ctx.routes statement).piopOpening index) := by
    intro index
    have coordinate := allCalls ((ctx.routes statement).piopOpening index)
    have routeValue : ((ctx.routes statement).piopOpening index).val = index.val := rfl
    rw [routeValue] at coordinate
    calc
      SmzaRp05CurrentOpeningProgram.openingCounterInput
          query.target query.nonce index.val =
        SmzaRp05CurrentGroupedRecordReadback.canonicalQueryCounterInput
          query index.val := by
            simp only [SmzaRp05CurrentGroupedRecordReadback.canonicalQueryCounterInput,
              currentRole]
      _ = groupEncode (rolePrefix, (ctx.routes statement).piopOpening index) :=
        coordinate.symm
  have decoder := piop_opening_decoder_from_stored_group_cell
    program database fallback (encode program call.1) rolePrefix keyIdentity call.2
    stored query.target query.nonce (ctx.routes statement).piopOpening counterAddress
  have fixedDecoder' : currentFixedVectorDecodedAt ctx blockCap fixed statement
      .piopOpening query.target query.nonce =
      SmzaRp04RawRoleSampling.actualPiopOpeningOutput
        (ctx.routes statement).piopOpening call.2 := by
    cases query with
    | mk queryRole target nonce counter =>
        cases currentRole
        exact fixedDecoder
  exact fixedDecoder'.trans decoder

end
end HegemonCrypto.SmallWood.SmzaRp05CurrentFixedAdvicePiopSource
