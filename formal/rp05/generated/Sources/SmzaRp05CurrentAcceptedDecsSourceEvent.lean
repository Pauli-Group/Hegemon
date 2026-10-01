import SmzaRp05CurrentCausalSourceLabel
import SmzaRp05CurrentSourceRoleEvent
import SmzaRp05AcceptedRoleLabels
import SmzaRp05AdaptiveDynamicBad
import SmzaRp04StatementRecordFilter
import SmzaRp05FilteredDecoderInstability

/-! # DECS-sample source-bad readback into the counted 406 event

This is the deterministic constructor bridge for the DECS source role.  It
uses the same causal trace and same stored sampler vector as the accepted
execution.  The caller must derive the five strictly-earlier fixed-advice
cells from the supported fixed fiber; this file deliberately does not
identify fixed advice with the unrelated all-oracle advice.
-/

namespace HegemonCrypto.SmallWood.SmzaRp05CurrentAcceptedDecsSourceEvent

open HegemonCrypto.CanonicalBytes (Byte)
open HegemonCrypto.FiniteOracleDatabase (Database)
open SmzaRp05AcceptedRoleLabels (EarlierReadback CausalPayloads causalOracle causalTrace)
open SmzaRp05AdaptiveDynamicBad (roleEvent)
open SmzaRp04AuthorizedLabelTransport (completeFilteredLabel AuthorizedBad)
open SmzaRp05CurrentSourceRoleEvent
  (currentSourceRoleEvent406 currentSourceRoleBad406 currentSourceRoleLabelsFromBytes406)
open SmzaRp05CurrentCausalSourceLabel
  (current_causal_prefix_readback current_source_labels_of_statement_bytes)
open SmzaRp05TracePrefixes (Trace)
open SmzaRp05LeafNamespace (Namespace)
open SmzaRp05TracePrefixes (Payload)
open SmzaRp05CurrentMaxAgreementRecovery (Coefficients)
open SmzaQ38McaSourceBinding (Query)
open SmzaRp05TracePrefixes (RelationModel TypedRoutes AllEarlierTables)
open SmzaChallengeStageTargets (Role StageQuery parseStageQuery InRoleDomain)
open SmzaRp04StatementRecordFilter (oneStatementFilter nonleafFilter)
open V8Smz9CoherentMerkleInstrument (rawRecords)
open SmzaRp05FilteredDecoderInstability (globalOnlineNext rawTraceDecoder
  statementTraceDecoder)
open SmzaRp05FilteredReadback (globalLeafStatement)
open V8Smz9AdaptiveFiniteAccounting (baseOpeningPoints)
open V8Smz9CoherentMerkleGeometry (extract)
open SmzaRp05CurrentRoleLabels (preambleFromTrace targetOfRaw)
open V8Smz9CoherentVectorMerkle (VectorOutput vectorOutputBytes)
open V8SmzaOracleParser (RawInput RawDigest)

noncomputable section
set_option autoImplicit false
set_option maxRecDepth 12000
set_option maxHeartbeats 1000000

attribute [local irreducible]
  SmzaRp05CurrentTracePrefixes406.currentSourceDecoder406
  SmzaRp05CurrentTracePrefixes406.currentSourcePrefix406

private theorem role_le_decsSample (role : Role) :
    SmzaRp05TracePrefixes.roleOrder role ≤
      SmzaRp05TracePrefixes.roleOrder .decsSample := by
  cases role <;> decide

private def sampleAdviceAsEarlierReadback
    (model : RelationModel) (statement : SmzaRp05StatementNamespace.Statement)
    (advice : AllEarlierTables model .decsSample) :
    (role : Role) → SmzaRp05TracePrefixes.EarlierTables model statement role :=
  fun selected earlier before digest =>
    advice statement earlier
      (Nat.lt_of_lt_of_le before (role_le_decsSample selected)) digest

/-- Turn a source-bad predicate on the actual causal trace into the DECS
sample event on the same grouped database.  `stored` and `sampleRead` are
the concrete same-branch output-binding facts: the chosen vector is present
at this parsed DECS-sample key and its current sampler output is the very
query classified as bad.  The readbacks are exact decoders used by
`roleEvent`; no event membership is assumed. -/
theorem source_bad_on_same_causal_trace_yields_event
    {Key Counter : Type*}
    [Fintype Key] [DecidableEq Key]
    [Fintype Counter] [DecidableEq Counter]
    (model : RelationModel) (ns : Namespace)
    (keyBytes : Key → RawInput) (counter : Counter)
    (routes : TypedRoutes model Counter)
    (advice : AllEarlierTables model .decsSample)
    (outerFuel innerFuel : Nat)
    (authorized : Finset (List Byte))
    (database : Database Key (VectorOutput Counter))
    (statement : SmzaRp05StatementNamespace.Statement)
    (fresh : statement.toBytes ∉ authorized)
    (key : Key) (vector : VectorOutput Counter)
    (stored : database key = some vector)
    (stageQuery : StageQuery)
    (parsed : parseStageQuery (keyBytes key) = some stageQuery)
    (roleIsSample : stageQuery.role = .decsSample)
    (targetRead : targetOfRaw .decsSample (keyBytes key) = (.decs, stageQuery.target))
    (query : Query)
    (sampleRead : SmzaRp04RawRoleSampling.actualDecsSampleOutput
      (routes statement).decsSample vector = some query)
    (trace : Trace) (messages : CausalPayloads ns trace)
    (coefficients : Coefficients)
    (matrix : V8Smz9PiopSoundness.Matrix (model.width statement))
    (opening : V8Smz9PiopSoundness.Opening)
    (earlier : EarlierReadback model statement
      (sampleAdviceAsEarlierReadback model statement advice)
      messages coefficients matrix opening)
    (matrixGood : ¬ SmzaRp05CurrentUniversalMatrixLoss.currentMatrixBad
      (SmzaQ38McaSourceBinding.oracleData (causalOracle ns trace))
      (SmzaQ38McaSourceBinding.oracleMasks (causalOracle ns trace))
      coefficients)
    (sourceBad : SmzaRp05CurrentTracePrefixes406.currentSourceBad406
      (SmzaRp05CurrentTracePrefixes406.currentSourcePrefix406
        (causalOracle ns trace)
        messages.fpp coefficients (baseOpeningPoints opening.1)
        (SmzaRp05TracePrefixes.queryCoefficients messages.decs) matrixGood)
      query)
    (outerReadback : preambleFromTrace ns .decsSample
      (extract (globalOnlineNext ns)
        (nonleafFilter (globalLeafStatement ns)
          (rawRecords keyBytes (vectorOutputBytes counter) database))
        outerFuel .decs stageQuery.target) = some statement.toBytes)
    (innerReadback : extract (globalOnlineNext ns)
      (oneStatementFilter (globalLeafStatement ns) statement.toBytes
        (rawRecords keyBytes (vectorOutputBytes counter) database))
      innerFuel .decs stageQuery.target = causalTrace trace .decsSample) :
    currentSourceRoleEvent406 model ns keyBytes counter routes advice
      outerFuel innerFuel authorized database := by
  classical
  have adviceAtSample : sampleAdviceAsEarlierReadback model statement advice .decsSample =
      advice statement := by
    funext earlier
    funext before
    funext digest
    rfl
  have prefixReadbackFromCausal :
      SmzaRp05CurrentTracePrefixes406.currentSourcePrefixFromTrace406
        model ns statement (sampleAdviceAsEarlierReadback model statement advice .decsSample)
        trace =
      some (SmzaRp05CurrentTracePrefixes406.currentSourcePrefix406
        (causalOracle ns trace) messages.fpp coefficients (baseOpeningPoints opening.1)
        (SmzaRp05TracePrefixes.queryCoefficients messages.decs) matrixGood) := by
    exact current_causal_prefix_readback model ns statement trace messages
      (sampleAdviceAsEarlierReadback model statement advice)
      coefficients matrix opening earlier matrixGood
  have prefixReadback : SmzaRp05CurrentTracePrefixes406.currentSourcePrefixFromTrace406
      model ns statement (advice statement) trace =
      some (SmzaRp05CurrentTracePrefixes406.currentSourcePrefix406
        (causalOracle ns trace) messages.fpp coefficients (baseOpeningPoints opening.1)
        (SmzaRp05TracePrefixes.queryCoefficients messages.decs) matrixGood) := by
    rw [← adviceAtSample]
    exact prefixReadbackFromCausal
  have labelsReadback := current_source_labels_of_statement_bytes model ns statement advice
    trace _ prefixReadback
  have outerRead : rawTraceDecoder (globalOnlineNext ns)
      (fun selected => targetOfRaw .decsSample (keyBytes selected))
      (fun _ trace => preambleFromTrace ns .decsSample trace) outerFuel
      (nonleafFilter (globalLeafStatement ns)
        (rawRecords keyBytes (vectorOutputBytes counter) database)) key =
      some statement.toBytes := by
    simp only [rawTraceDecoder, targetRead]
    exact outerReadback
  unfold currentSourceRoleEvent406
  refine ⟨key, vector, stored, ?_, ?_⟩
  · exact ⟨stageQuery, parsed, roleIsSample⟩
  · apply SmzaRp05AcceptedRoleLabels.authorized_bad_of_readback
      (globalLeafStatement ns)
      (rawTraceDecoder (globalOnlineNext ns)
        (fun selected => targetOfRaw .decsSample (keyBytes selected))
        (fun _ trace => preambleFromTrace ns .decsSample trace) outerFuel)
      (statementTraceDecoder (globalOnlineNext ns)
        (fun _ selected => targetOfRaw .decsSample (keyBytes selected))
        (fun bytes _ trace => currentSourceRoleLabelsFromBytes406 model ns advice bytes trace)
        innerFuel)
      authorized (rawRecords keyBytes (vectorOutputBytes counter) database) key
      statement.toBytes vector
      (fun _ label output => currentSourceRoleBad406 model routes label output)
      outerRead fresh ?_
    change currentSourceRoleBad406 model routes
      (currentSourceRoleLabelsFromBytes406 model ns advice statement.toBytes
        (extract (globalOnlineNext ns)
          (oneStatementFilter (globalLeafStatement ns) statement.toBytes
            (rawRecords keyBytes (vectorOutputBytes counter) database))
          innerFuel (targetOfRaw .decsSample (keyBytes key)).1
            (targetOfRaw .decsSample (keyBytes key)).2)) vector
    rw [targetRead, innerReadback]
    simp only [causalTrace]
    rw [labelsReadback]
    exact ⟨query, sampleRead, sourceBad⟩

end
end HegemonCrypto.SmallWood.SmzaRp05CurrentAcceptedDecsSourceEvent
