import SmzaRp05CurrentAcceptedPiopRecordedOutputs
import SmzaRp05CurrentAcceptedRoleQueryReadback
import SmzaRp05CurrentOpeningGroupIdentity
import SmzaRp05CurrentFiniteGroupedProgram
import SmzaRp05CurrentGroupedClaimRetention
import SmzaRp05CurrentPiopRoleEvents
import SmzaRp05CurrentTracePrefixes406
import SmzaRp05AdaptiveDynamicBad
import SmzaRp05AcceptedRoleLabels
import SmzaRp04AuthorizedLabelTransport
import SmzaRp05FilteredReadback
import SmzaRp05FilteredDecoderInstability

/-! # Accepted PIOP opening call role readback

This small adapter preserves the selected opening answer-log pair from the
actual accepted execution and turns its canonical opening frame into the
same-branch grouped role readback. It is an input to, not a replacement for,
the current fixed-advice failure-event join.
-/

namespace HegemonCrypto.SmallWood.SmzaRp05CurrentAcceptedPiopFailureEvents

open HegemonCrypto.CmsOracleDatabaseBridge (ClaimsDatabaseEvent)
open HegemonCrypto.FiniteOracleDatabase (Database)
open SmzaRp05ExecutableMerkleVerifier (Program)
open SmzaRp05PhysicalAcceptedReplayLite (Branches answerLog branchClaims branchKeys branchAnswers)
open SmzaRp05CurrentGroupedClaimRetention (groupedDecode)
open SmzaRp05CurrentFiniteGroupedProgram (Key encode included answer_log_group_keys_represented)
open SmzaRp05CurrentGroupedOracleVector (finiteGroupedDatabaseOracle)
open SmzaRp05CurrentRoleLabels (targetOfRaw)
open SmzaRp05CurrentAcceptedRoleQueryReadback (current_actual_grouped_role_call_readback)
open SmzaRp05CurrentOpeningGroupIdentity (opening_counter_call_group_address)
open SmzaRp05GroupedSuffix
  (CanonicalRolePrefix GroupCounter groupZero groupKeyOf groupEncode
   groupRepresentative groupAddress group_address_encode group_block_cap_eq)
open SmzaChallengeStageTargets (StageQuery parseStageQuery)
open SmzaRp05CurrentOpeningProgram (openingCounterInput)
open SmzaRp05CurrentPiopRoleEvents (PiopRole currentPiopRoleEvent406)
open SmzaRp05CurrentAcceptedPiopRecordedOutputs (accepted_opening_call_and_vector)
open SmzaRp05CurrentProofWireProgram (ExistingProofFieldView)
open SmzaRp05ExecutablePcsClosureStatement (verifierProgram statementBindingWords)
open SmzaRp05ExecutablePcsClosure (ExecutionStages transcriptProgram)
open SmzaRp05ExecutablePcsClosureStages (PcsStages)
open SmzaRp05ExecutableFinalVerifier (ReconstructedTranscript)
open SmzaRp05CurrentGroupedOracleVector (finiteGroupedDatabaseOracle)
open V8SmzaOracleParser (RawDigest RawInput)
open V8Smz9CoherentVectorMerkle (VectorOutput)
open SmzaRp05RelationRefinement (RelationDsl)
open SmzaRp05CurrentGroupedRoutes (currentGroupedRoutes)
open SmzaRp05ConcreteSuffix (ModelWithinProtocol)
open HegemonCrypto.SmallWoodTranscript (piopCoefficientDomain)
open SmzaRp05TracePrefixes (RelationModel Trace EarlierTables AllEarlierTables TypedRoutes completeBad typedCompleteRawBad)
open SmzaRp05CurrentTracePrefixes406 (currentPrefixLabels406 currentRoleLabelsFromBytes406)
open SmzaRp05AdaptiveDynamicBad (roleEvent)
open SmzaDynamicDatabaseSoundness (DynamicBad)
open SmzaRp05AcceptedRoleLabels (causalTrace authorized_bad_of_readback)
open SmzaRp04AuthorizedLabelTransport (AuthorizedBad completeFilteredLabel)
open SmzaRp05FilteredReadback (globalLeafStatement)
open SmzaRp05FilteredDecoderInstability (globalOnlineNext)
open SmzaRp05CurrentRoleLabels (currentOuter targetOfRaw)
open SmzaChallengeStageTargets (Role InRoleDomain)
open V8Smz9CoherentMerkleGeometry (extract)
open V8Smz9CoherentMerkleInstrument (rawRecords)
open V8Smz9CoherentVectorMerkle (vectorOutputBytes)
open SmzaRp04StatementRecordFilter (nonleafFilter oneStatementFilter)
open SmzaRp05CurrentGroupedRoutes (currentGroupedRoutes)
open SmzaRp05ConcreteSuffix (ModelWithinProtocol)
open HegemonCrypto.CanonicalBytes (Byte)

noncomputable section
set_option autoImplicit false
set_option maxRecDepth 12000
set_option maxHeartbeats 1000000

/-- A selected opening call retained in this accepted branch determines its
canonical role query and grouped storage cell. The caller must supply the
actual call membership returned by `accepted_opening_call_and_vector`; no
independent parser receipt or database cell is assumed. -/
theorem accepted_opening_call_role_readback
    {Result : Type} (program : Program Result)
    (branch : Branches groupedDecode program)
    (database : Database (Key program) (VectorOutput GroupCounter))
    (claims : ClaimsDatabaseEvent
      (SmzaRp05PhysicalAcceptedReplayLite.branchClaims
        (SmzaRp05PhysicalAcceptedReplayLite.branchKeys (encode program) groupedDecode program branch)
        (SmzaRp05PhysicalAcceptedReplayLite.branchAnswers (encode program) groupedDecode program branch))
      database)
    (fallback digest : RawDigest) (nonce : Nat) (nonceBound : nonce < 2 ^ 32)
    (counter : GroupCounter) (output : VectorOutput GroupCounter)
    (recorded : (openingCounterInput digest nonce counter.val, output) ∈
      answerLog groupedDecode program branch) :
    ∃ rolePrefix : CanonicalRolePrefix,
      included program (encode program
        (openingCounterInput digest nonce counter.val)) =
          Sum.inl rolePrefix ∧
      parseStageQuery (groupRepresentative (included program (encode program
        (openingCounterInput digest nonce counter.val)))) =
          some ⟨.piopOpening, digest, nonce, 0⟩ ∧
      database (encode program (openingCounterInput digest nonce counter.val)) = some output := by
  obtain ⟨rolePrefix, addressEq, parsedZero, _encoded⟩ :=
    opening_counter_call_group_address digest nonce nonceBound counter
  have represented := answer_log_group_keys_represented
    groupedDecode program branch
      (openingCounterInput digest nonce counter.val, output) recorded
  have keyIdentity : included program (encode program
      (openingCounterInput digest nonce counter.val)) =
      Sum.inl rolePrefix := by
    calc
      included program (encode program
          (openingCounterInput digest nonce counter.val)) =
          groupKeyOf (openingCounterInput digest nonce counter.val) := represented
      _ = Sum.inl rolePrefix := by
        change (groupAddress (openingCounterInput digest nonce counter.val)).1 = _
        exact congrArg Prod.fst addressEq
  let query : StageQuery := ⟨.piopOpening, digest, nonce, 0⟩
  have parsedRepresentative :
      parseStageQuery (groupRepresentative (Sum.inl rolePrefix)) = some query := by
    simpa only [query] using parsedZero
  have parsed : parseStageQuery (groupRepresentative (included program (encode program
      (openingCounterInput digest nonce counter.val)))) = some query := by
    rw [keyIdentity]
    exact parsedRepresentative
  obtain ⟨_, _, _, _, _, stored, _, _⟩ :=
    current_actual_grouped_role_call_readback program branch
      (openingCounterInput digest nonce counter.val, output)
      recorded database claims fallback .piopOpening query parsed rfl rfl
  exact ⟨rolePrefix, keyIdentity, parsed, stored⟩

/-- Turn an exact current 406 PIOP causal bad witness, together with the raw
nonleaf and filtered-inner reads, into the corresponding dynamic role event.
The accepted-execution layer supplies these readbacks from its same database. -/
theorem current_piop_event_of_readbacks
    {Key Counter : Type*} [Fintype Key] [DecidableEq Key]
    [Fintype Counter] [DecidableEq Counter]
    (model : RelationModel) (ns : SmzaRp05LeafNamespace.Namespace)
    (keyBytes : Key → RawInput) (counter : Counter)
    (routes : TypedRoutes model Counter) (role : PiopRole)
    (advice : AllEarlierTables model role.toRole)
    (outerFuel innerFuel : Nat) (authorized : Finset (List Byte))
    (statement : SmzaRp05StatementNamespace.Statement)
    (fresh : statement.toBytes ∉ authorized)
    (key : Key) (vector : VectorOutput Counter)
    (database : Database Key (VectorOutput Counter))
    (query : StageQuery)
    (parsed : parseStageQuery (keyBytes key) = some query)
    (queryRole : query.role = role.toRole)
    (stored : database key = some vector)
    (outerReadback : currentOuter ns keyBytes role.toRole outerFuel
      (nonleafFilter (globalLeafStatement ns)
        (rawRecords keyBytes (vectorOutputBytes counter) database)) key =
          some statement.toBytes)
    (trace : Trace)
    (innerReadback : extract (globalOnlineNext ns)
      (oneStatementFilter (globalLeafStatement ns) statement.toBytes
        (rawRecords keyBytes (vectorOutputBytes counter) database)) innerFuel
      (targetOfRaw role.toRole (keyBytes key)).1
      (targetOfRaw role.toRole (keyBytes key)).2 = causalTrace trace role.toRole)
    (bad : completeBad (routes statement) role.toRole
      (currentPrefixLabels406 model ns statement role.toRole
        (advice statement) (causalTrace trace role.toRole)) vector) :
    currentPiopRoleEvent406 model ns keyBytes counter routes role advice
      outerFuel innerFuel authorized database := by
  classical
  unfold currentPiopRoleEvent406 roleEvent
  unfold SmzaDynamicDatabaseSoundness.DynamicBad
    SmzaRp05AdaptiveDynamicBad.selectedBad
  refine ⟨key, vector, stored, ?_, ?_⟩
  · exact ⟨query, parsed, queryRole⟩
  · have bytesLabel : currentRoleLabelsFromBytes406 model ns role.toRole
        advice statement.toBytes
        (extract (globalOnlineNext ns)
          (oneStatementFilter (globalLeafStatement ns) statement.toBytes
            (rawRecords keyBytes (vectorOutputBytes counter) database))
          innerFuel (targetOfRaw role.toRole (keyBytes key)).1
            (targetOfRaw role.toRole (keyBytes key)).2) =
        .decoded statement (currentPrefixLabels406 model ns statement role.toRole
          (advice statement) (causalTrace trace role.toRole)) := by
      have length : statement.toBytes.length = SmzaRp05LeafNamespace.preambleBytes :=
        SmzaRp05StatementNamespace.Statement.toBytes_length statement
      have roundtrip : SmzaRp05TracePrefixes.statementOfBytes
          statement.toBytes length = statement := by
        exact SmzaRp05StatementNamespace.Statement.toBytes_injective
          (SmzaRp05TracePrefixes.statement_of_bytes_roundtrip statement.toBytes length)
      simp only [currentRoleLabelsFromBytes406,
        SmzaRp05TracePrefixes.statementOfBytes?, dif_pos length, roundtrip]
      rw [innerReadback]
      rfl
    apply authorized_bad_of_readback (globalLeafStatement ns)
      (currentOuter ns keyBytes role.toRole outerFuel)
      (fun statementBytes records target =>
        SmzaRp05FilteredDecoderInstability.statementTraceDecoder
          (globalOnlineNext ns)
          (fun _ key => targetOfRaw role.toRole (keyBytes key))
          (fun statement _ trace => currentRoleLabelsFromBytes406 model ns
            role.toRole advice statement trace) innerFuel statementBytes records target)
      authorized (rawRecords keyBytes (vectorOutputBytes counter) database) key
      statement.toBytes vector
      (fun _ label output => typedCompleteRawBad model routes role.toRole label output)
      outerReadback fresh ?_
    change typedCompleteRawBad model routes role.toRole
      (currentRoleLabelsFromBytes406 model ns role.toRole advice statement.toBytes
        (extract (globalOnlineNext ns)
          (oneStatementFilter (globalLeafStatement ns) statement.toBytes
            (rawRecords keyBytes (vectorOutputBytes counter) database))
          innerFuel (targetOfRaw role.toRole (keyBytes key)).1
            (targetOfRaw role.toRole (keyBytes key)).2)) vector
    rw [bytesLabel]
    change completeBad (routes statement) role.toRole
      (currentPrefixLabels406 model ns statement role.toRole
        (advice statement) (causalTrace trace role.toRole)) vector
    exact bad

end
end HegemonCrypto.SmallWood.SmzaRp05CurrentAcceptedPiopFailureEvents
