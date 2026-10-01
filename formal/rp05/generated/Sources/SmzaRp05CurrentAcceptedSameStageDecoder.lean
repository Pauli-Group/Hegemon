import SmzaRp05CurrentDecodedPhysicalOutcome
import SmzaRp05CurrentGroupedVerifierReplay
import SmzaRp05ChallengeRecordErasure
import SmzaRp05CurrentMerkleRecordFreshness
import SmzaRp05CurrentFppRecordFreshness
import SmzaRp05PhysicalPcsRecordRetention
import SmzaRp05PhysicalHashFppRecordRetention
import SmzaRp05CurrentGroupedOracleVector
import SmzaRp05CurrentFiniteGroupedProgram
import SmzaRp05GroupedSuffix

/-! # Same-stage accepted current decoder outcome

Unlike an existential classifier wrapper, this theorem retains the actual
producer, verifier, transcript, execution, and PCS success equations used to
construct the decoder outcome. Downstream role-event proofs therefore consume
the same stages rather than matching independent existential witnesses.
-/

namespace HegemonCrypto.SmallWood.SmzaRp05CurrentAcceptedSameStageDecoder

open HegemonCrypto.CanonicalBytes (Byte)
open HegemonCrypto.CmsOracleDatabaseBridge (ClaimsDatabaseEvent)
open HegemonCrypto.FiniteOracleDatabase (Database)
open SmzaRp05ExecutableMerkleVerifier (Program Oracle)
open SmzaRp05PhysicalAcceptedReplayLite
  (Branches branchKeys branchAnswers branchClaims branchResult)
open SmzaRp05CurrentGroupedClaimRetention (groupedDecode)
open SmzaRp05CurrentGroupedVerifierReplay (accepted_grouped_claims_supply_verifier_replay)
open SmzaRp05CurrentFiniteGroupedProgram (Key encode included)
open SmzaRp05CurrentGroupedOracleVector (finiteGroupedDatabaseOracle)
open SmzaRp05GroupedSuffix (groupRepresentative groupZero GroupCounter)
open SmzaRp05ChallengeRecordErasure (eraseChallengeRecords)
open SmzaRp05CurrentMerkleRecordFreshness
  (recorded_attempt_calls_current_statement_or_nonleaf)
open SmzaRp05CurrentFppRecordFreshness (successful_response_hash_records_nonleaf)
open SmzaRp05ExecutableMerkleVerifier (recordedAttempt)
open SmzaRp05ExecutablePcsClosure (ExecutionStages)
open SmzaRp05ExecutablePcsClosureStages (PcsStages)
open SmzaRp05ExecutablePcsClosureStatement (verifierProgram statementBindingWords)
open SmzaRp05PhysicalPcsRecordRetention
  (pcs_merkle_records_retained execution_pcs_records_retained_in_verifier)
open SmzaRp05PhysicalHashFppRecordRetention (execution_hash_fpp_records_retained_in_verifier)
open SmzaRp05CurrentDecodedPhysicalOutcome (accepted_stage_nonchallenge_log_decoder_outcome)
open SmzaRp05CurrentRetainedQuerySupport (measuredDataTable measuredMaskTable)
open SmzaRp05CurrentAcceptedQueryExtraction (CurrentDecoderOutcome)
open SmzaRp05CurrentMaxAgreementRecovery (Position Query)
open SmzaRp05RelationRefinement (RelationDsl)
open SmzaRp05CurrentProofWireProgram (ExistingProofFieldView)
open SmzaRp05ExecutablePcsClosureSampling
open V8Smz9CoherentMerkleInstrument (rawRecords)
open V8Smz9CoherentVectorMerkle (VectorOutput vectorOutputBytes)
open V8SmzaOracleParser (RawDigest)
open SmzaChallengeStageTargets (parseStageQuery)

noncomputable section
set_option autoImplicit false
set_option maxRecDepth 12000

/-- Construct an accepted verifier's decoder outcome while returning every
success equation for the very same selected run and the exact PCS stages used
to classify it. -/
theorem accepted_grouped_branch_has_same_stage_decoder_outcome
    (producer : Program ExistingProofFieldView)
    (ns : SmzaRp05LeafNamespace.Namespace) (dsl : RelationDsl)
    (statement : SmzaRp05StatementNamespace.Statement) (pending : Bool)
    (nonce : Fin (2 ^ 32))
    (branch : Branches groupedDecode
      (producer.bind fun wire => verifierProgram ns dsl statement pending nonce wire))
    (accepted : branchResult groupedDecode
      (producer.bind fun wire => verifierProgram ns dsl statement pending nonce wire)
      branch = some ())
    (database : Database
      (Key (producer.bind fun wire => verifierProgram ns dsl statement pending nonce wire))
      (VectorOutput GroupCounter))
    (claims : ClaimsDatabaseEvent
      (branchClaims
        (branchKeys (encode (producer.bind fun wire =>
          verifierProgram ns dsl statement pending nonce wire)) groupedDecode
          (producer.bind fun wire => verifierProgram ns dsl statement pending nonce wire)
          branch)
        (branchAnswers (encode (producer.bind fun wire =>
          verifierProgram ns dsl statement pending nonce wire)) groupedDecode
          (producer.bind fun wire => verifierProgram ns dsl statement pending nonce wire)
          branch)) database)
    (fallback : RawDigest) (fuel : Nat) (enough : 25 ≤ fuel)
    (statementBindingLength : (statementBindingWords statement).length = 138) :
    let program := producer.bind fun wire =>
      verifierProgram ns dsl statement pending nonce wire
    let oracle := finiteGroupedDatabaseOracle program database fallback
    let sourceRecords := SmzaRp04StatementRecordFilter.oneStatementFilter
      (SmzaRp05FilteredReadback.globalLeafStatement ns) statement.toBytes
      (eraseChallengeRecords
        (rawRecords (fun key => groupRepresentative (included program key))
          (vectorOutputBytes groupZero) database))
    ∃ wire transcript,
      producer.eval oracle = some wire ∧
      (verifierProgram ns dsl statement pending nonce wire).eval oracle = some () ∧
      (SmzaRp05ExecutablePcsClosure.transcriptProgram ns dsl statement pending
        statement.toBytes (statementBindingWords statement) nonce wire).eval oracle =
          some transcript ∧
      ∃ execution : ExecutionStages ns dsl statement pending statement.toBytes
        (statementBindingWords statement) nonce wire oracle transcript,
      ∃ stages : PcsStages ns execution.openingPending wire.hPiop
        (SmzaRp05PcsToFinalProgram.sameProofRows execution.middle.pcs execution.piop)
        execution.decs
        (List.ofFn fun j : Fin 6 => V8Smz9PiopReconstruction.points execution.opening j)
        wire.salt statement.toBytes (statementBindingWords statement)
        wire.tapes wire.paths oracle execution.hashFpp execution.pcsPending,
      ¬ SmzaRecordedTracePath.RecordsCollisionFree sourceRecords ∨
        ∃ coordinates : Fin 38 → Position,
          ∃ query : Query, ∃ input : V8SmzaOracleParser.RawInput,
            StrictMono coordinates ∧
            query.val = Finset.univ.image coordinates ∧
            (∀ j : Fin 38, (coordinates j).val = stages.indexes.getD j.val 0) ∧
            (input, execution.hashFpp) ∈ sourceRecords ∧
            (input, execution.hashFpp) ∈ (stages.hashProgram.record oracle).2 ∧
            CurrentDecoderOutcome
              (measuredDataTable ns sourceRecords fuel stages.post.root)
              (measuredMaskTable ns sourceRecords fuel stages.post.root)
              (SmzaRp05CurrentResponseInputDecoder.responseRuleOfRawInputSelection
                (fun _ : SmzaRp05CurrentMaxAgreementRecovery.Coefficients => input))
              (SmzaRp05CurrentAcceptedQuerySupport.sampledCoefficients
                (SmzaRp05PcsHashFppMiddle.gammaRows stages.post))
              stages.heads (SmzaRp05CurrentTwelveCalculated.currentStageTails
                (SmzaRp05PcsToFinalProgram.sameProofRows execution.middle.pcs execution.piop))
              (fun opening =>
                (List.ofFn fun j : Fin 6 =>
                  V8Smz9PiopReconstruction.points execution.opening j).getD opening.val 0)
              query := by
  classical
  let program := producer.bind fun wire =>
    verifierProgram ns dsl statement pending nonce wire
  let oracle := finiteGroupedDatabaseOracle program database fallback
  let fullRecords := rawRecords
    (fun key => groupRepresentative (included program key))
    (vectorOutputBytes groupZero) database
  let erasedRecords := eraseChallengeRecords fullRecords
  let sourceRecords := SmzaRp04StatementRecordFilter.oneStatementFilter
    (SmzaRp05FilteredReadback.globalLeafStatement ns) statement.toBytes erasedRecords
  obtain ⟨wire, producerSuccess, verifierAccepted, nonchallengeRetained⟩ :=
    accepted_grouped_claims_supply_verifier_replay producer ns dsl statement pending
      nonce branch accepted database claims fallback
  obtain ⟨transcript, transcriptSuccess, transcriptClean, _rootEq, _finalCall⟩ :=
    SmzaRp05ExecutablePcsClosure.accepted_execution_constructs_transcript
      ns dsl statement pending statement.toBytes (statementBindingWords statement)
      nonce wire oracle verifierAccepted
  obtain ⟨execution⟩ :=
    SmzaRp05ExecutablePcsClosure.transcript_execution_has_stages
      ns dsl statement pending statement.toBytes (statementBindingWords statement)
      nonce wire oracle transcript transcriptSuccess
  obtain ⟨stages⟩ :=
    SmzaRp05ExecutablePcsClosureStages.pcs_execution_has_stages
      ns execution.openingPending wire.hPiop
      (SmzaRp05PcsToFinalProgram.sameProofRows execution.middle.pcs execution.piop)
      execution.decs
      (List.ofFn fun j : Fin 6 => V8Smz9PiopReconstruction.points execution.opening j)
      wire.salt statement.toBytes (statementBindingWords statement)
      wire.tapes wire.paths oracle execution.hashFpp execution.pcsPending
      execution.pcsExecuted
  have cleanStages :=
    SmzaRp05ExecutablePcsClosureSampling.execution_stages_clean_matrix
      ns dsl statement pending statement.toBytes (statementBindingWords statement)
      nonce wire oracle transcript execution transcriptClean
  have pointCount :
      (List.ofFn fun j : Fin 6 =>
        V8Smz9PiopReconstruction.points execution.opening j).length = 6 :=
    SmzaRp05CurrentTwelveCalculated.generated_opening_points_length execution.opening
  let merkleLog := (recordedAttempt ns oracle stages.merkleInput).2
  let hashLog := (stages.hashProgram.record oracle).2
  let stageLog := merkleLog ++ hashLog
  have pcsIntoVerifier := execution_pcs_records_retained_in_verifier ns dsl statement
    pending nonce wire oracle transcript execution transcriptSuccess
  have hashIntoVerifier := execution_hash_fpp_records_retained_in_verifier ns dsl
    statement pending nonce wire oracle transcript execution stages transcriptSuccess
  have merkleInPcs := pcs_merkle_records_retained ns execution.openingPending
    wire.hPiop (SmzaRp05PcsToFinalProgram.sameProofRows execution.middle.pcs execution.piop)
    execution.decs
    (List.ofFn fun j : Fin 6 => V8Smz9PiopReconstruction.points execution.opening j)
    wire.salt statement.toBytes (statementBindingWords statement)
    wire.tapes wire.paths oracle execution.hashFpp execution.pcsPending stages
    execution.pcsExecuted
  have bindingEq : stages.merkleInput.binding = statement.toBytes := by
    have built := stages.inputBuilt
    unfold SmzaRp05PcsMerklePayload.makeMerkleInput at built
    split at built
    · simp at built
    · have fields := Option.some.inj built
      exact (congrArg SmzaRp05ExecutableMerkleVerifier.Input.binding fields).symm
  have stageLogRetained : ∀ call, call ∈ stageLog →
      parseStageQuery call.1 = none → call ∈ sourceRecords := by
    intro call member parseNone
    have member' : call ∈ merkleLog ++ hashLog := by simpa only [stageLog] using member
    rcases List.mem_append.mp member' with merkleMember | hashMember
    · have verifierMember := pcsIntoVerifier call (merkleInPcs call.1 call.2 merkleMember)
      have fullMember := nonchallengeRetained call verifierMember parseNone
      have erasedMember : call ∈ erasedRecords := by
        change call ∈ eraseChallengeRecords fullRecords
        rw [SmzaRp05ChallengeRecordErasure.eraseChallengeRecords_eq_parse_none]
        exact Finset.mem_filter.mpr ⟨fullMember, parseNone⟩
      have classified := recorded_attempt_calls_current_statement_or_nonleaf
        ns oracle stages.merkleInput call merkleMember
      have statementOrNone :
          SmzaRp05FilteredReadback.globalLeafStatement ns call.1 = none ∨
            SmzaRp05FilteredReadback.globalLeafStatement ns call.1 = some statement.toBytes := by
        rcases classified with nonleaf | sameBinding
        · exact Or.inl nonleaf
        · exact Or.inr (by simpa only [bindingEq] using sameBinding)
      change call ∈ SmzaRp04StatementRecordFilter.oneStatementFilter
        (SmzaRp05FilteredReadback.globalLeafStatement ns) statement.toBytes erasedRecords
      exact Finset.mem_filter.mpr ⟨erasedMember, statementOrNone⟩
    · have verifierMember := hashIntoVerifier call hashMember
      have fullMember := nonchallengeRetained call verifierMember parseNone
      have erasedMember : call ∈ erasedRecords := by
        change call ∈ eraseChallengeRecords fullRecords
        rw [SmzaRp05ChallengeRecordErasure.eraseChallengeRecords_eq_parse_none]
        exact Finset.mem_filter.mpr ⟨fullMember, parseNone⟩
      change call ∈ SmzaRp04StatementRecordFilter.oneStatementFilter
        (SmzaRp05FilteredReadback.globalLeafStatement ns) statement.toBytes erasedRecords
      exact Finset.mem_filter.mpr ⟨erasedMember, Or.inl (by
        have fresh := successful_response_hash_records_nonleaf ns stages.post.root
          execution.decs
          (stages.rows.map fun row => row.map SmzaRp05ExecutableRestore.toWord)
          (SmzaRp05PcsHashFppMiddle.gammaRows stages.post)
          (stages.decsPoints.map SmzaRp05ExecutableRestore.toWord)
          (statementBindingWords statement) statementBindingLength stages.hashProgram
          stages.responseBuilt oracle call hashMember
        exact fresh)⟩
  have merkleInStageLog : ∀ call, call ∈ merkleLog → call ∈ stageLog := by
    intro call member
    exact List.mem_append.mpr (Or.inl member)
  have hashInStageLog : ∀ call, call ∈ hashLog → call ∈ stageLog := by
    intro call member
    exact List.mem_append.mpr (Or.inr member)
  have filteredOutcome := accepted_stage_nonchallenge_log_decoder_outcome
    stages pointCount cleanStages.1 fuel enough statementBindingLength sourceRecords
    stageLog stageLogRetained merkleInStageLog hashInStageLog
  exact ⟨wire, transcript, producerSuccess, verifierAccepted, transcriptSuccess,
    execution, stages, filteredOutcome⟩

end
end HegemonCrypto.SmallWood.SmzaRp05CurrentAcceptedSameStageDecoder
