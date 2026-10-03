import SmzaRp05CurrentCausalSourceLabel
import SmzaRp05CurrentSourceRoleEvent
import SmzaRp05AcceptedRoleLabels
import SmzaRp05AdaptiveDynamicBad
import SmzaRp04StatementRecordFilter
import SmzaRp05FilteredDecoderInstability

/-! # Same-trace DECS source-event bridge for role-indexed advice

This adapter consumes the full, role-indexed `EarlierReadback` produced by
the accepted fixed-advice lane.  Only its `.decsSample` advice is used by the
DECS source event; the other roles' earlier cells are deliberately preserved
in the readback rather than collapsed to the sample table.
-/

namespace HegemonCrypto.SmallWood.SmzaRp05CurrentAcceptedDecsSourceCoverage

open HegemonCrypto.CanonicalBytes (Byte)
open HegemonCrypto.FiniteOracleDatabase (Database)
open SmzaRp05AcceptedRoleLabels
  (EarlierReadback CausalPayloads causalOracle causalTrace)
open SmzaRp05AdaptiveDynamicBad (roleEvent)
open SmzaRp04AuthorizedLabelTransport (completeFilteredLabel AuthorizedBad)
open SmzaRp05CurrentSourceRoleEvent
  (currentSourceRoleEvent406 currentSourceRoleBad406 currentSourceRoleLabelsFromBytes406)
open SmzaRp05CurrentCausalSourceLabel
  (current_causal_prefix_readback current_source_labels_of_statement_bytes)
open SmzaRp05TracePrefixes (Trace)
open SmzaRp05LeafNamespace (Namespace)
open SmzaRp05TracePrefixes (Payload RelationModel TypedRoutes AllEarlierTables)
open SmzaChallengeStageTargets (Role StageQuery parseStageQuery)
open SmzaRp04StatementRecordFilter (oneStatementFilter nonleafFilter)
open V8Smz9CoherentMerkleInstrument (rawRecords)
open SmzaRp05FilteredDecoderInstability
  (globalOnlineNext rawTraceDecoder statementTraceDecoder)
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

/-- A DECS source-bad query on the same causal trace determines the concrete
DECS-sample event when the complete earlier-role readback is available.
`sampleAdvice` is exactly the family member consumed by the event's decoder;
the five-cell `earlier` witness remains tied to the original role-indexed
family.  All key/vector/parser and outer/inner-trace facts are explicit
same-record facts, so this lemma adds no event-membership assumption. -/
theorem source_bad_on_same_trace_yields_event_of_family
    {Key Counter : Type*}
    [Fintype Key] [DecidableEq Key]
    [Fintype Counter] [DecidableEq Counter]
    (model : RelationModel) (ns : Namespace)
    (keyBytes : Key → RawInput) (counter : Counter)
    (routes : TypedRoutes model Counter)
    (sampleAdvice : AllEarlierTables model .decsSample)
    (adviceFamily : (role : Role) → AllEarlierTables model role)
    (familyAtSample : adviceFamily .decsSample = sampleAdvice)
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
    (query : SmzaQ38McaSourceBinding.Query)
    (sampleRead : SmzaRp04RawRoleSampling.actualDecsSampleOutput
      (routes statement).decsSample vector = some query)
    (trace : Trace) (messages : CausalPayloads ns trace)
    (coefficients : SmzaRp05CurrentMaxAgreementRecovery.Coefficients)
    (matrix : V8Smz9PiopSoundness.Matrix (model.width statement))
    (opening : V8Smz9PiopSoundness.Opening)
    (earlier : EarlierReadback model statement
      (fun role => adviceFamily role statement)
      messages coefficients matrix opening)
    (matrixGood : ¬ SmzaRp05CurrentUniversalMatrixLoss.currentMatrixBad
      (SmzaQ38McaSourceBinding.oracleData (causalOracle ns trace))
      (SmzaQ38McaSourceBinding.oracleMasks (causalOracle ns trace)) coefficients)
    (sourceBad : SmzaRp05CurrentTracePrefixes406.currentSourceBad406
      (SmzaRp05CurrentTracePrefixes406.currentSourcePrefix406
        (causalOracle ns trace) messages.fpp coefficients (baseOpeningPoints opening.1)
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
    currentSourceRoleEvent406 model ns keyBytes counter routes sampleAdvice
      outerFuel innerFuel authorized database := by
  classical
  have familyAtSampleStatement : adviceFamily .decsSample statement =
      sampleAdvice statement := congrArg (fun table => table statement) familyAtSample
  have prefixReadbackFromCausal := current_causal_prefix_readback model ns statement
    trace messages (fun role => adviceFamily role statement)
    coefficients matrix opening earlier matrixGood
  have prefixReadback :
      SmzaRp05CurrentTracePrefixes406.currentSourcePrefixFromTrace406
        model ns statement (sampleAdvice statement) trace =
      some (SmzaRp05CurrentTracePrefixes406.currentSourcePrefix406
        (causalOracle ns trace) messages.fpp coefficients (baseOpeningPoints opening.1)
        (SmzaRp05TracePrefixes.queryCoefficients messages.decs) matrixGood) := by
    rw [← familyAtSampleStatement]
    exact prefixReadbackFromCausal
  have labelsReadback := current_source_labels_of_statement_bytes model ns statement
    sampleAdvice trace _ prefixReadback
  have outerRead : rawTraceDecoder (globalOnlineNext ns)
      (fun selected => targetOfRaw .decsSample (keyBytes selected))
      (fun _ currentTrace => preambleFromTrace ns .decsSample currentTrace) outerFuel
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
        (fun _ currentTrace => preambleFromTrace ns .decsSample currentTrace) outerFuel)
      (statementTraceDecoder (globalOnlineNext ns)
        (fun _ selected => targetOfRaw .decsSample (keyBytes selected))
        (fun bytes _ currentTrace =>
          currentSourceRoleLabelsFromBytes406 model ns sampleAdvice bytes currentTrace)
        innerFuel)
      authorized (rawRecords keyBytes (vectorOutputBytes counter) database) key
      statement.toBytes vector
      (fun _ label output => currentSourceRoleBad406 model routes label output)
      outerRead fresh ?_
    change currentSourceRoleBad406 model routes
      (currentSourceRoleLabelsFromBytes406 model ns sampleAdvice statement.toBytes
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
end HegemonCrypto.SmallWood.SmzaRp05CurrentAcceptedDecsSourceCoverage
