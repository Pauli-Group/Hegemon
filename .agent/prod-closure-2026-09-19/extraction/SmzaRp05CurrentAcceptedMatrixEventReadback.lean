import SmzaRp05CurrentMatrixRoleEvent
import SmzaRp05CurrentRoleLabels
import SmzaRp05AcceptedRoleLabels
import SmzaRp04AuthorizedLabelTransport
import SmzaRp05FilteredReadback
import SmzaRp05FilteredDecoderInstability

/-! # Constructing a current DECS-matrix role event from one execution

This small constructor turns actual database storage, parser/trace readbacks,
and the current matrix decoder result into the role-event witness. It does not
assume the event itself. The accepted-execution layer is responsible for
deriving these readbacks from the same verifier run.
-/

namespace HegemonCrypto.SmallWood.SmzaRp05CurrentAcceptedMatrixEventReadback

open scoped Classical
open HegemonCrypto.CanonicalBytes (Byte)
open HegemonCrypto.FiniteOracleDatabase (Database)
open HegemonCrypto.CmsClassicalDatabase
open SmzaRp05TracePrefixes
  (RelationModel TypedRoutes AllEarlierTables Trace rootOracle roleLabelsFromBytes)
open SmzaChallengeStageTargets (StageQuery Role parseStageQuery InRoleDomain)
open SmzaRp05LeafNamespace (Namespace)
open SmzaRp05CurrentMatrixRoleEvent
  (currentMatrixRoleEvent406 currentMatrixRoleBad currentMatrixRouteBad
    typedCurrentMatrixRouteBad)
open SmzaRp05CurrentRoleLabels (currentOuter targetOfRaw)
open SmzaRp05AdaptiveDynamicBad (roleEvent selectedBad)
open SmzaDynamicDatabaseSoundness (DynamicBad)
open SmzaRp05FilteredReadback (globalLeafStatement)
open SmzaRp05FilteredDecoderInstability (globalOnlineNext)
open SmzaRp04AuthorizedLabelTransport (AuthorizedLabel)
open V8Smz9CoherentVectorMerkle (VectorOutput vectorOutputBytes)
open V8Smz9CoherentMerkleGeometry (extract)
open SmzaRp04StatementRecordFilter (nonleafFilter oneStatementFilter)
open SmzaRp05AcceptedRoleLabels
  (causalTrace role_labels_from_statement_bytes authorized_bad_of_readback)
open SmzaRp05CurrentUniversalMatrixLoss (currentMatrixBad)
open SmzaRp05CurrentDecsMatrixSampling (currentActualDecsMatrixOutput)
open SmzaRp05ChallengeRecordErasure (global_extract_filtered_erase_challenge)
open V8Smz9CoherentMerkleInstrument (rawRecords)

noncomputable section
set_option autoImplicit false
set_option maxRecDepth 12000

local notation "Statement" => SmzaRp05StatementNamespace.Statement

set_option linter.unnecessarySeqFocus false in
/-- Challenge erasure is inert after the one-statement view, so a bad matrix
computed by the filtered classifier is the same bad matrix on the actual
grouped raw-record source used by the role event. -/
theorem current_matrix_bad_from_challenge_erased_records
    (ns : Namespace) (statement : Statement) (records :
      V8Smz9CoherentMerkleGeometry.Records V8SmzaOracleParser.RawInput
        V8SmzaOracleParser.RawDigest)
    (fuel : Nat) (target : V8SmzaOracleParser.RawDigest)
    (coefficients : SmzaRp05CurrentUniversalMatrixLoss.Coefficients)
    (bad : currentMatrixBad
      (SmzaQ38McaSourceBinding.oracleData
        (rootOracle ns (extract (globalOnlineNext ns)
          (oneStatementFilter (globalLeafStatement ns) statement.toBytes
            (SmzaRp05ChallengeRecordErasure.eraseChallengeRecords records))
          fuel .root target)))
      (SmzaQ38McaSourceBinding.oracleMasks
        (rootOracle ns (extract (globalOnlineNext ns)
          (oneStatementFilter (globalLeafStatement ns) statement.toBytes
            (SmzaRp05ChallengeRecordErasure.eraseChallengeRecords records))
          fuel .root target))) coefficients) :
    currentMatrixBad
      (SmzaQ38McaSourceBinding.oracleData
        (rootOracle ns (extract (globalOnlineNext ns)
          (oneStatementFilter (globalLeafStatement ns) statement.toBytes records)
          fuel .root target)))
      (SmzaQ38McaSourceBinding.oracleMasks
        (rootOracle ns (extract (globalOnlineNext ns)
          (oneStatementFilter (globalLeafStatement ns) statement.toBytes records)
          fuel .root target))) coefficients := by
  have extracted := global_extract_filtered_erase_challenge ns records
    (fun input => globalLeafStatement ns input = none ∨
      globalLeafStatement ns input = some statement.toBytes)
    fuel .root target
  have extracted' :
      extract (globalOnlineNext ns)
        (oneStatementFilter (globalLeafStatement ns) statement.toBytes
          (SmzaRp05ChallengeRecordErasure.eraseChallengeRecords records))
        fuel .root target =
    extract (globalOnlineNext ns)
        (oneStatementFilter (globalLeafStatement ns) statement.toBytes records)
        fuel .root target := by
    let view := fun input => globalLeafStatement ns input = none ∨
      globalLeafStatement ns input = some statement.toBytes
    have leftFilter :
        oneStatementFilter (globalLeafStatement ns) statement.toBytes
          (SmzaRp05ChallengeRecordErasure.eraseChallengeRecords records) =
        (SmzaRp05ChallengeRecordErasure.eraseChallengeRecords records).filter
          (fun record => view record.1) := by
      ext record
      simp [oneStatementFilter, view,
        SmzaRp04StatementRecordFilter.keepOneStatement]
    have rightFilter :
        records.filter (fun record => view record.1) =
          oneStatementFilter (globalLeafStatement ns) statement.toBytes records := by
      ext record
      simp [oneStatementFilter, view,
        SmzaRp04StatementRecordFilter.keepOneStatement]
    calc
      extract (globalOnlineNext ns)
          (oneStatementFilter (globalLeafStatement ns) statement.toBytes
            (SmzaRp05ChallengeRecordErasure.eraseChallengeRecords records))
          fuel .root target =
        extract (globalOnlineNext ns)
          ((SmzaRp05ChallengeRecordErasure.eraseChallengeRecords records).filter
            (fun record => view record.1)) fuel .root target := by
              exact congrArg (fun filtered =>
                extract (globalOnlineNext ns) filtered fuel .root target) leftFilter
      _ = extract (globalOnlineNext ns)
          (records.filter (fun record => view record.1)) fuel .root target := by
            convert extracted using 1 <;> congr 1 <;> ext record <;> simp [view]
      _ = extract (globalOnlineNext ns)
          (oneStatementFilter (globalLeafStatement ns) statement.toBytes records)
          fuel .root target := by
            exact congrArg (fun filtered =>
              extract (globalOnlineNext ns) filtered fuel .root target) rightFilter
  have rootEq := congrArg (rootOracle ns) extracted'
  rw [← rootEq]
  exact bad

/-- The actual current matrix role event follows from a concrete selected
key/vector, current decoder output, and both decoder readbacks on the same
database. `matrixBad` is a property of the trace-derived root oracle, not an
event-inclusion premise. -/
theorem current_matrix_role_event_of_execution_readbacks
    {Key Counter : Type*} [Fintype Key] [DecidableEq Key]
    [Fintype Counter] [DecidableEq Counter]
    (model : RelationModel) (ns : Namespace)
    (keyBytes : Key → V8SmzaOracleParser.RawInput)
    (counter : Counter)
    (routes : TypedRoutes model Counter)
    (advice : AllEarlierTables model .decsMatrix)
    (outerFuel innerFuel : Nat) (authorized : Finset (List Byte))
    (statement : Statement) (fresh : statement.toBytes ∉ authorized)
    (key : Key) (vector : VectorOutput Counter)
    (database : Database Key (VectorOutput Counter))
    (query : StageQuery)
    (parsed : parseStageQuery (keyBytes key) = some query)
    (queryRole : query.role = .decsMatrix)
    (stored : database key = some vector)
    (outerReadback : currentOuter ns keyBytes .decsMatrix outerFuel
      (nonleafFilter (globalLeafStatement ns)
        (rawRecords keyBytes (vectorOutputBytes counter) database)) key = some statement.toBytes)
    (trace : Trace)
    (innerReadback : extract (globalOnlineNext ns)
      (oneStatementFilter (globalLeafStatement ns) statement.toBytes
        (rawRecords keyBytes (vectorOutputBytes counter) database)) innerFuel .root query.target =
        causalTrace trace .decsMatrix)
    (coefficients : SmzaRp05CurrentUniversalMatrixLoss.Coefficients)
    (decoderRead : currentActualDecsMatrixOutput
      (routes statement).decsMatrix vector = some coefficients)
    (matrixBad : currentMatrixBad
      (SmzaQ38McaSourceBinding.oracleData
        (rootOracle ns (causalTrace trace .decsMatrix)))
      (SmzaQ38McaSourceBinding.oracleMasks
        (rootOracle ns (causalTrace trace .decsMatrix))) coefficients) :
    currentMatrixRoleEvent406 model ns keyBytes counter routes advice
      outerFuel innerFuel authorized database := by
  unfold currentMatrixRoleEvent406 currentMatrixRoleBad
  unfold roleEvent DynamicBad selectedBad
  refine ⟨key, vector, stored, ?_, ?_⟩
  · exact ⟨query, parsed, queryRole⟩
  · have labelBad : SmzaRp05CurrentMatrixRoleEvent.typedCurrentMatrixRouteBad
        model routes
        (roleLabelsFromBytes model ns .decsMatrix advice statement.toBytes
          (extract (globalOnlineNext ns)
            (oneStatementFilter (globalLeafStatement ns) statement.toBytes
              (rawRecords keyBytes (vectorOutputBytes counter) database))
            innerFuel (targetOfRaw .decsMatrix (keyBytes key)).1
              (targetOfRaw .decsMatrix (keyBytes key)).2)) vector := by
      have targetRead := SmzaRp05CurrentRoleLabels.target_of_parsed_role
        .decsMatrix (keyBytes key) query parsed queryRole
      rw [targetRead]
      change SmzaRp05CurrentMatrixRoleEvent.typedCurrentMatrixRouteBad
        model routes
        (roleLabelsFromBytes model ns .decsMatrix advice statement.toBytes
          (extract (globalOnlineNext ns)
            (oneStatementFilter (globalLeafStatement ns) statement.toBytes
              (rawRecords keyBytes (vectorOutputBytes counter) database))
            innerFuel .root query.target)) vector
      rw [innerReadback, role_labels_from_statement_bytes]
      change currentMatrixRouteBad (routes statement).decsMatrix
        (some (rootOracle ns (causalTrace trace .decsMatrix))) vector
      unfold currentMatrixRouteBad
      refine ⟨rootOracle ns (causalTrace trace .decsMatrix), rfl, ?_⟩
      exact ⟨coefficients, decoderRead, matrixBad⟩
    exact authorized_bad_of_readback (globalLeafStatement ns)
      (currentOuter ns keyBytes .decsMatrix outerFuel)
      (fun statementBytes records target =>
        SmzaRp05FilteredDecoderInstability.statementTraceDecoder
          (globalOnlineNext ns)
          (fun _ key => targetOfRaw .decsMatrix (keyBytes key))
          (fun statement _ trace =>
            roleLabelsFromBytes model ns .decsMatrix advice statement trace)
          innerFuel statementBytes records target)
      authorized
      (rawRecords keyBytes (vectorOutputBytes counter) database)
      key statement.toBytes vector
      (fun _ label output =>
        SmzaRp05CurrentMatrixRoleEvent.typedCurrentMatrixRouteBad
          model routes label output)
      outerReadback fresh labelBad

end
end HegemonCrypto.SmallWood.SmzaRp05CurrentAcceptedMatrixEventReadback
