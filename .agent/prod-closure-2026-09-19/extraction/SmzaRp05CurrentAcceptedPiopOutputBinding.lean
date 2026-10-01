import SmzaRp05CurrentAcceptedRoleQueryReadback
import SmzaRp05CurrentGroupedPiopDecoders
import SmzaRp05CurrentGroupedRoutes
import SmzaRp05CertifiedReplayScheduleFrames
import SmzaRp05CurrentOpeningGroupIdentity
import SmzaRp05CurrentGroupedClaimRetention
import SmzaRp05CurrentFiniteGroupedProgram

/-! # Current grouped PIOP output binding

For an actual branch answer at a PIOP counter call, derive its canonical
grouped key, stored vector, and every-coordinate route from the executed
parser and same branch's claims. No parser receipt, database cell, or route
address is supplied independently.
-/

namespace HegemonCrypto.SmallWood.SmzaRp05CurrentAcceptedPiopOutputBinding

open HegemonCrypto.CmsOracleDatabaseBridge (ClaimsDatabaseEvent)
open HegemonCrypto.FiniteOracleDatabase (Database)
open HegemonCrypto.CanonicalBytes (Byte encodeLE)
open SmzaRp05ExecutableMerkleVerifier (Program)
open SmzaRp05CurrentGroupedClaimRetention (groupedDecode)
open SmzaRp05CurrentFiniteGroupedProgram
  (Key encode included answer_log_group_keys_represented)
open SmzaRp05CurrentGroupedOracleVector (finiteGroupedDatabaseOracle)
open SmzaRp05CurrentGroupedPiopDecoders
  (piop_matrix_decoder_from_stored_group_cell piop_opening_decoder_from_stored_group_cell)
open SmzaRp05CurrentGroupedRoutes (currentGroupedRoutes
  currentGroupedRoutes_piopMatrix_val currentGroupedRoutes_piopOpening_val)
open SmzaRp05CurrentAcceptedRoleQueryReadback (current_actual_grouped_role_call_readback)
open SmzaRp05CertifiedReplaySchedule (ordinary_counter_roundtrip)
open SmzaRp05CurrentOpeningGroupIdentity (opening_counter_call_group_address)
open SmzaRp05GroupedSuffix
  (CanonicalRolePrefix GroupCounter groupBlockCap groupZero groupKeyOf
    groupEncode groupRepresentative groupAddress group_address_encode group_block_cap_eq)
open SmzaRp05CurrentGroupedRecordReadback (canonicalQueryCounterInput)
open SmzaRp05TracePrefixes (RelationModel)
open SmzaRp05ConcreteSuffix (ModelWithinProtocol)
open SmzaChallengeStageTargets (Role StageQuery parseStageQuery)
open SmzaRp05CurrentOpeningProgram (openingCounterInput)
open SmzaRp05ExecutableChallengeStage (counterInput)
open SmzaRp05CurrentExecutedPiopMatrixReadback (currentPiopMatrixVector)
open SmzaRp05CurrentExecutedOpeningOutput (currentOpeningVector)
open SmzaRp04RawRoleSampling (actualPiopMatrixOutput actualPiopOpeningOutput)
open V8SmzaOracleParser (RawInput RawDigest)
open V8Smz9CoherentVectorMerkle (VectorOutput)
open V8Smz9RawCounterCompiler (digestCallCap)
open V8Smz9AdaptiveFiniteAccounting.Historical (piopOpenings)
open HegemonCrypto.SmallWoodTranscript (piopCoefficientDomain)

noncomputable section
set_option autoImplicit false
set_option maxRecDepth 12000
set_option maxHeartbeats 1000000

/-- A real counter-zero PIOP-matrix answer fixes the decoder over the actual
finite grouped database on the current route. -/
theorem actual_grouped_piop_matrix_route_output
    {Result : Type} (program : Program Result)
    (branch : SmzaRp05PhysicalAcceptedReplayLite.Branches groupedDecode program)
    (call : RawInput × VectorOutput GroupCounter)
    (recorded : call ∈ SmzaRp05PhysicalAcceptedReplayLite.answerLog groupedDecode program branch)
    (database : Database (Key program) (VectorOutput GroupCounter))
    (claims : ClaimsDatabaseEvent
      (SmzaRp05PhysicalAcceptedReplayLite.branchClaims
        (SmzaRp05PhysicalAcceptedReplayLite.branchKeys (encode program) groupedDecode program branch)
        (SmzaRp05PhysicalAcceptedReplayLite.branchAnswers (encode program) groupedDecode program branch))
      database)
    (fallback : RawDigest) (model : RelationModel)
    (bounded : ModelWithinProtocol model)
    (statement : SmzaRp05StatementNamespace.Statement) (digest : RawDigest)
    (inputEq : call.1 = counterInput piopCoefficientDomain digest 0) :
    actualPiopMatrixOutput (currentGroupedRoutes model bounded statement).piopMatrix call.2 =
      actualPiopMatrixOutput (Equiv.refl (Fin (digestCallCap (5 * model.width statement))))
        (currentPiopMatrixVector
          (finiteGroupedDatabaseOracle program database fallback) digest
          (model.width statement)) := by
  let query : StageQuery := ⟨.piopMatrix, digest, 0, 0⟩
  let leading : RawInput :=
    encodeLE 8 V8SmzaOracleParser.profileDomain.length ++
      V8SmzaOracleParser.profileDomain ++ encodeLE 8 piopCoefficientDomain.length ++
      piopCoefficientDomain ++ encodeLE 8 8 ++ List.ofFn digest
  let zeroCounter : Fin (2 ^ 64) := ⟨0, by norm_num⟩
  have parsedZero : parseStageQuery (leading ++ encodeLE 8 0) = some query := by
    change parseStageQuery (counterInput piopCoefficientDomain digest 0) = _
    simpa only [SmzaChallengeStageTargets.roleDomain,
      SmzaRp05ExecutableChallengeStage.counterInput, zeroCounter, Fin.val_mk, query] using
      ordinary_counter_roundtrip .piopMatrix (by decide) digest zeroCounter
  let rolePrefix : CanonicalRolePrefix :=
    ⟨.piopMatrix, leading, ⟨query, parsedZero, rfl⟩⟩
  have encoded : groupEncode (rolePrefix, groupZero) =
      counterInput piopCoefficientDomain digest 0 := by
    change leading ++ encodeLE 8 0 = _
    rfl
  have represented := answer_log_group_keys_represented
    groupedDecode program branch call recorded
  have keyIdentity : included program (encode program call.1) = Sum.inl rolePrefix := by
    calc
      included program (encode program call.1) = groupKeyOf call.1 := represented
      _ = Sum.inl rolePrefix := by
        change (groupAddress call.1).1 = Sum.inl rolePrefix
        rw [inputEq, ← encoded]
        exact congrArg Prod.fst (group_address_encode rolePrefix groupZero)
  have representativeParsed :
      parseStageQuery (groupRepresentative (Sum.inl rolePrefix)) = some query := by
    simpa only [groupRepresentative, groupEncode, rolePrefix, groupZero,
      V8Smz9CoherentVectorMerkle.canonicalRepresentative,
      V8Smz9RawCounterCompiler.boundedCounterInput,
      V8Smz9RawCounterCompiler.counterInput, Fin.val_mk] using parsedZero
  have parsed : parseStageQuery
      (groupRepresentative (included program (encode program call.1))) = some query := by
    rw [keyIdentity]
    exact representativeParsed
  obtain ⟨rolePrefix', keyIdentity', _, allCoordinates, _, stored, _, _⟩ :=
    current_actual_grouped_role_call_readback program branch call recorded database claims
      fallback .piopMatrix query parsed rfl rfl
  have counterAddress : ∀ index : Fin (digestCallCap (5 * model.width statement)),
      counterInput piopCoefficientDomain digest index.val =
        groupEncode (rolePrefix', (currentGroupedRoutes model bounded statement).piopMatrix index) := by
    intro index
    have coordinate := allCoordinates
      ((currentGroupedRoutes model bounded statement).piopMatrix index)
    have routeValue := currentGroupedRoutes_piopMatrix_val model bounded statement index
    rw [routeValue] at coordinate
    calc
      counterInput piopCoefficientDomain digest index.val =
          canonicalQueryCounterInput query index.val := by
        simp only [canonicalQueryCounterInput, query,
          SmzaChallengeStageTargets.roleDomain,
          HegemonCrypto.SmallWoodTranscript.piopCoefficientDomain]
      _ = groupEncode (rolePrefix', (currentGroupedRoutes model bounded statement).piopMatrix index) :=
        coordinate.symm
  exact piop_matrix_decoder_from_stored_group_cell program database fallback
    (encode program call.1) rolePrefix' keyIdentity' call.2 stored digest
    (model.width statement) (currentGroupedRoutes model bounded statement).piopMatrix
    counterAddress

/-- One actual opening-counter answer fixes all six coordinates at that
nonce's own grouped prefix; it does not identify other nonce cells. -/
theorem actual_grouped_piop_opening_route_output
    {Result : Type} (program : Program Result)
    (branch : SmzaRp05PhysicalAcceptedReplayLite.Branches groupedDecode program)
    (call : RawInput × VectorOutput GroupCounter)
    (recorded : call ∈ SmzaRp05PhysicalAcceptedReplayLite.answerLog groupedDecode program branch)
    (database : Database (Key program) (VectorOutput GroupCounter))
    (claims : ClaimsDatabaseEvent
      (SmzaRp05PhysicalAcceptedReplayLite.branchClaims
        (SmzaRp05PhysicalAcceptedReplayLite.branchKeys (encode program) groupedDecode program branch)
        (SmzaRp05PhysicalAcceptedReplayLite.branchAnswers (encode program) groupedDecode program branch))
      database)
    (fallback : RawDigest) (model : RelationModel)
    (bounded : ModelWithinProtocol model)
    (statement : SmzaRp05StatementNamespace.Statement) (digest : RawDigest)
    (nonce : Nat) (nonceBound : nonce < 2 ^ 32) (counter : GroupCounter)
    (inputEq : call.1 = openingCounterInput digest nonce counter.val) :
    actualPiopOpeningOutput (currentGroupedRoutes model bounded statement).piopOpening call.2 =
      actualPiopOpeningOutput (Equiv.refl (Fin (digestCallCap piopOpenings)))
        (currentOpeningVector
          (finiteGroupedDatabaseOracle program database fallback) digest nonce) := by
  obtain ⟨rolePrefix, addressEq, parsedZero, encoded⟩ :=
    opening_counter_call_group_address digest nonce nonceBound counter
  have represented := answer_log_group_keys_represented
    groupedDecode program branch call recorded
  have keyIdentity : included program (encode program call.1) = Sum.inl rolePrefix := by
    calc
      included program (encode program call.1) = groupKeyOf call.1 := represented
      _ = Sum.inl rolePrefix := by
        change (groupAddress call.1).1 = Sum.inl rolePrefix
        rw [inputEq, ← encoded]
        exact congrArg Prod.fst (group_address_encode rolePrefix counter)
  let query : StageQuery := ⟨.piopOpening, digest, nonce, 0⟩
  have representativeParsed :
      parseStageQuery (groupRepresentative (Sum.inl rolePrefix)) = some query := by
    simpa only [query] using parsedZero
  have parsed : parseStageQuery
      (groupRepresentative (included program (encode program call.1))) = some query := by
    rw [keyIdentity]
    exact representativeParsed
  obtain ⟨rolePrefix', keyIdentity', _, allCoordinates, _, stored, _, _⟩ :=
    current_actual_grouped_role_call_readback program branch call recorded database claims
      fallback .piopOpening query parsed rfl rfl
  have counterAddress : ∀ index : Fin (digestCallCap piopOpenings),
      openingCounterInput digest nonce index.val =
        groupEncode (rolePrefix', (currentGroupedRoutes model bounded statement).piopOpening index) := by
    intro index
    have coordinate := allCoordinates
      ((currentGroupedRoutes model bounded statement).piopOpening index)
    have routeValue := currentGroupedRoutes_piopOpening_val model bounded statement index
    rw [routeValue] at coordinate
    calc
      openingCounterInput digest nonce index.val =
          canonicalQueryCounterInput query index.val := by
        simp [canonicalQueryCounterInput, query]
      _ = groupEncode (rolePrefix', (currentGroupedRoutes model bounded statement).piopOpening index) :=
        coordinate.symm
  exact piop_opening_decoder_from_stored_group_cell program database fallback
    (encode program call.1) rolePrefix' keyIdentity' call.2 stored digest nonce
    (currentGroupedRoutes model bounded statement).piopOpening counterAddress

end
end HegemonCrypto.SmallWood.SmzaRp05CurrentAcceptedPiopOutputBinding
