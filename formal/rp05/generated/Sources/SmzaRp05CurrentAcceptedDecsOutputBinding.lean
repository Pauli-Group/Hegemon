import SmzaRp05CurrentAcceptedDecsMatrixCallReadback
import SmzaRp05ExecutablePcsClosureSampling
import SmzaRp05CurrentDecsGroupedTarget
import SmzaRp05CurrentAcceptedRoleQueryReadback
import SmzaRp05CurrentGroupedRoutes
import SmzaRp05CurrentFixedEarlierAdvice
import SmzaRp05CurrentExecutedDecsCoefficients
import SmzaRp05CurrentFixedAdviceOpeningSource
import SmzaRp05CurrentGroupedClaimRetention

/-! # Same-stage grouped DECS matrix output binding

The accepted verifier branch's actual DECS coefficient-XOF vector is the
vector consumed by the current grouped DECS-matrix route, and that route
decodes to the sampled coefficients from the *supplied* post-Merkle execution.
No decoder-success or vector-equality premise is supplied. -/

namespace HegemonCrypto.SmallWood.SmzaRp05CurrentAcceptedDecsOutputBinding

open HegemonCrypto.CanonicalBytes (Byte)
open HegemonCrypto.CmsOracleDatabaseBridge (ClaimsDatabaseEvent)
open HegemonCrypto.FiniteOracleDatabase (Database)
open SmzaRp05PhysicalAcceptedReplayLite
  (Branches branchResult branchKeys branchAnswers branchClaims answerLog rawLog)
open SmzaRp05CurrentGroupedClaimRetention (groupedDecode)
open SmzaRp05CurrentFiniteGroupedProgram (Key encode included)
open SmzaRp05CurrentGroupedOracleVector (finiteGroupedDatabaseOracle)
open SmzaRp05CurrentAcceptedDecsMatrixCallReadback
  (field_xof_decs_counter_zero_recorded post_merkle_records_retained_in_pcs)
open SmzaRp05CurrentDecsGroupedTarget (recorded_decs_call_has_grouped_target)
open SmzaRp05CurrentAcceptedRoleQueryReadback (current_actual_grouped_role_call_readback)
open SmzaRp05CurrentGroupedRoutes
  (currentGroupedRoutes currentGroupedRoutes_decsMatrix_val)
open SmzaRp05CurrentFixedEarlierAdvice (current_decs_matrix_decoder_from_stored_group_cell)
open SmzaRp05CurrentExecutedDecsCoefficients
  (executed_clean_post_merkle_actual_decs_coefficients)
open SmzaRp05CurrentFixedAdviceOpeningSource (verifier_record_pair_has_branch_answer)
open SmzaRp05CurrentExecutedEarlierAdvice (currentOracleDecodedAt)
open SmzaRp05CurrentDecsMatrixSampling (currentActualDecsMatrixOutput)
open SmzaRp05CurrentAcceptedQuerySupport (sampledCoefficients)
open SmzaRp05PcsHashFppMiddle (gammaRows)
open SmzaRp05ExecutablePcsClosure (ExecutionStages)
open SmzaRp05ExecutablePcsClosureStages (PcsStages)
open SmzaRp05CurrentProofWireProgram (ExistingProofFieldView)
open SmzaRp05ExecutableFinalVerifier (ReconstructedTranscript)
open SmzaRp05ExecutablePcsClosure (transcriptProgram)
open SmzaRp05ExecutableMerkleVerifier (Program Oracle)
open SmzaRp05ExecutablePcsClosureStatement (verifierProgram statementBindingWords)
open SmzaRp05LeafNamespace (Namespace)
open SmzaRp05RelationRefinement (RelationDsl)
open SmzaRp05TracePrefixes (RelationModel)
open SmzaRp05ConcreteSuffix (ModelWithinProtocol)
open SmzaRp05CurrentGroupedContext (currentGroupedContext)
open SmzaRp05GroupedSuffix (GroupCounter)
open SmzaChallengeStageTargets (StageQuery parseStageQuery)
open SmzaRp05ExecutableChallengeStage (counterInput fieldXof afterMerkle)
open SmzaRp05ExecutableChallengeStage (PostMerkle)
open HegemonCrypto.SmallWoodTranscript (decsCoefficientDomain)
open V8Smz9RawCounterCompiler (digestCallCap)
open V8SmzaOracleParser (RawDigest RawInput)
open V8Smz9CoherentVectorMerkle (VectorOutput)

noncomputable section
set_option autoImplicit false
set_option maxRecDepth 12000

/-- An actual counter-zero DECS-matrix call in the supplied accepted branch
stores the same vector as the literal current grouped route; its decoded
matrix is the sample made by the supplied PCS stages. -/
theorem same_stage_decs_counter_zero_decodes
    (producer : Program ExistingProofFieldView)
    (ns : Namespace) (dsl : RelationDsl)
    (statement : SmzaRp05StatementNamespace.Statement) (pending : Bool)
    (nonce : Fin (2 ^ 32))
    (branch : Branches groupedDecode
      (producer.bind fun wire => verifierProgram ns dsl statement pending nonce wire))
    (database : Database
      (Key (producer.bind fun wire => verifierProgram ns dsl statement pending nonce wire))
      (VectorOutput GroupCounter))
    (claims : ClaimsDatabaseEvent
      (branchClaims
        (branchKeys
          (encode (producer.bind fun wire => verifierProgram ns dsl statement pending nonce wire))
          groupedDecode
          (producer.bind fun wire => verifierProgram ns dsl statement pending nonce wire)
          branch)
        (branchAnswers
          (encode (producer.bind fun wire => verifierProgram ns dsl statement pending nonce wire))
          groupedDecode
          (producer.bind fun wire => verifierProgram ns dsl statement pending nonce wire)
          branch)) database)
    [Fintype RawDigest] (fallback : RawDigest)
    (model : RelationModel) (bounded : ModelWithinProtocol model)
    (wire : ExistingProofFieldView)
    (transcript : ReconstructedTranscript)
    (execution : ExecutionStages ns dsl statement pending statement.toBytes
      (statementBindingWords statement) nonce wire
      (finiteGroupedDatabaseOracle
        (producer.bind fun wire => verifierProgram ns dsl statement pending nonce wire)
        database fallback) transcript)
    (producerSuccess : producer.eval
      (finiteGroupedDatabaseOracle
        (producer.bind fun wire => verifierProgram ns dsl statement pending nonce wire)
        database fallback) = some wire)
    (pcs : PcsStages ns execution.openingPending wire.hPiop
      (SmzaRp05PcsToFinalProgram.sameProofRows execution.middle.pcs execution.piop)
      execution.decs
      (List.ofFn fun j : Fin 6 => V8Smz9PiopReconstruction.points execution.opening j)
      wire.salt statement.toBytes (statementBindingWords statement)
      wire.tapes wire.paths
      (finiteGroupedDatabaseOracle
        (producer.bind fun wire => verifierProgram ns dsl statement pending nonce wire)
        database fallback)
      execution.hashFpp execution.pcsPending)
    (verifierAccepted : (verifierProgram ns dsl statement pending nonce wire).eval
        (finiteGroupedDatabaseOracle
          (producer.bind fun wire => verifierProgram ns dsl statement pending nonce wire)
          database fallback) = some ())
    (transcriptSuccess : (transcriptProgram ns dsl statement pending statement.toBytes
      (statementBindingWords statement) nonce wire).eval
        (finiteGroupedDatabaseOracle
          (producer.bind fun wire => verifierProgram ns dsl statement pending nonce wire)
          database fallback) = some transcript) :
    branchResult groupedDecode
      (producer.bind fun wire => verifierProgram ns dsl statement pending nonce wire)
      branch = some () ∧
    ∃ vector,
      (counterInput decsCoefficientDomain pcs.post.root 0, vector) ∈
        answerLog groupedDecode
          (producer.bind fun wire => verifierProgram ns dsl statement pending nonce wire)
          branch ∧
      currentActualDecsMatrixOutput
        (currentGroupedRoutes model bounded statement).decsMatrix vector =
          some (sampledCoefficients (gammaRows pcs.post)) := by
  classical
  let actualProgram := producer.bind fun wire =>
    verifierProgram ns dsl statement pending nonce wire
  let oracle : Oracle := finiteGroupedDatabaseOracle actualProgram database fallback
  have replay := SmzaRp05CurrentGroupedClaimRetention.actual_program_grouped_claims_replay_and_retain
    actualProgram branch database claims fallback
  have branchRecord : actualProgram.record oracle =
      (branchResult groupedDecode actualProgram branch, rawLog groupedDecode actualProgram branch) := by
    change actualProgram.record
      (fun raw => match database (encode actualProgram raw) with
        | none => fallback
        | some vector => groupedDecode raw vector) = _
    exact replay.1
  have acceptedEval : actualProgram.eval oracle = some () := by
    change (producer.bind
      (fun wire => verifierProgram ns dsl statement pending nonce wire)).eval oracle = some ()
    rw [Program.eval_bind]
    rw [producerSuccess]
    simpa only [Option.bind_some] using verifierAccepted
  have branchAccepted : branchResult groupedDecode actualProgram branch = some () := by
    calc
      branchResult groupedDecode actualProgram branch = (actualProgram.record oracle).1 :=
        (congrArg Prod.fst branchRecord).symm
      _ = actualProgram.eval oracle := by simp [Program.record_result]
      _ = some () := acceptedEval
  obtain ⟨acceptedTranscript, acceptedTranscriptSuccess, transcriptClean, _rootEq,
      _rootMember⟩ :=
    SmzaRp05ExecutablePcsClosure.accepted_execution_constructs_transcript ns dsl statement
      pending statement.toBytes (statementBindingWords statement) nonce wire oracle verifierAccepted
  have transcriptEq : transcript = acceptedTranscript :=
    Option.some.inj (transcriptSuccess.symm.trans acceptedTranscriptSuccess)
  have transcriptCleanSupplied : transcript.pendingXofFailure = false := by
    rw [transcriptEq]
    exact transcriptClean
  have cleanStages :=
    SmzaRp05ExecutablePcsClosureSampling.execution_stages_clean_matrix ns dsl statement
      pending statement.toBytes (statementBindingWords statement) nonce wire oracle transcript
      execution transcriptCleanSupplied
  have postClean : pcs.post.pending = false := by
    exact pcs.pendingReturned.symm.trans cleanStages.1
  have postCore := SmzaRp05ExecutableChallengeStage.post_merkle_has_executed_core
    ns oracle pcs.merkleInput pcs.post pcs.postExecuted
  have fieldEval :
      (fieldXof decsCoefficientDomain 700 pcs.post.root).eval oracle =
        some pcs.post.sampled := by
    rw [fieldXof, SmzaRp05ExecutableChallengeStage.field_loop_executes_scan,
      postCore.2.1]
  have fieldMember := field_xof_decs_counter_zero_recorded 700 (by omega)
    pcs.post.root oracle
  have fieldInAfter :
      (counterInput decsCoefficientDomain pcs.post.root 0,
        oracle (counterInput decsCoefficientDomain pcs.post.root 0)) ∈
      ((afterMerkle pcs.merkleInput pcs.post.root).record oracle).2 := by
    unfold afterMerkle
    exact Program.bind_log_left oracle (fieldXof decsCoefficientDomain 700 pcs.post.root)
      (fun sampled => .done (some
        (⟨pcs.post.root, sampled,
          SmzaRp05ExecutableChallengeStage.pendingFailure pcs.merkleInput.pendingXofFailure sampled,
          SmzaRp05ExecutableChallengeStage.mcaValue pcs.merkleInput
            (SmzaRp05ExecutableChallengeStage.returnedWords 700 sampled)⟩ : PostMerkle)))
      pcs.post.sampled fieldEval fieldMember
  have postMember :
      (counterInput decsCoefficientDomain pcs.post.root 0,
        oracle (counterInput decsCoefficientDomain pcs.post.root 0)) ∈
      ((SmzaRp05ExecutableChallengeStage.postMerkleProgram ns pcs.merkleInput).record oracle).2 := by
    simpa only [SmzaRp05ExecutableChallengeStage.postMerkleProgram] using
      (Program.bind_log_right oracle
        (SmzaRp05ExecutableMerkleVerifier.merkleProgram ns pcs.merkleInput)
        (afterMerkle pcs.merkleInput) pcs.post.root postCore.1 fieldInAfter)
  have intoPcs := post_merkle_records_retained_in_pcs ns execution.openingPending wire.hPiop
    (SmzaRp05PcsToFinalProgram.sameProofRows execution.middle.pcs execution.piop)
    execution.decs
    (List.ofFn fun j : Fin 6 => V8Smz9PiopReconstruction.points execution.opening j)
    wire.salt statement.toBytes (statementBindingWords statement)
    wire.tapes wire.paths oracle execution.hashFpp execution.pcsPending pcs execution.pcsExecuted
  have intoVerifier :=
    SmzaRp05PhysicalPcsRecordRetention.execution_pcs_records_retained_in_verifier
      ns dsl statement pending nonce wire oracle transcript execution transcriptSuccess
  have pcsMember := intoVerifier _ (intoPcs _ postMember)
  have wholeMember :
      (counterInput decsCoefficientDomain pcs.post.root 0,
        oracle (counterInput decsCoefficientDomain pcs.post.root 0)) ∈
      (actualProgram.record oracle).2 := by
    exact Program.bind_log_right oracle producer
      (fun wire => verifierProgram ns dsl statement pending nonce wire) wire producerSuccess
      pcsMember
  obtain ⟨vector, vectorMember, _vectorEq⟩ :=
    verifier_record_pair_has_branch_answer (Key := Key actualProgram)
      actualProgram branch oracle branchRecord
      (counterInput decsCoefficientDomain pcs.post.root 0)
      (oracle (counterInput decsCoefficientDomain pcs.post.root 0)) wholeMember
  let query : StageQuery := ⟨.decsMatrix, pcs.post.root, 0, 0⟩
  have groupedTarget := recorded_decs_call_has_grouped_target actualProgram branch
    (counterInput decsCoefficientDomain pcs.post.root 0, vector) vectorMember pcs.post.root
    ⟨0, by
      have cap : digestCallCap 700 = 92 := by decide
      rw [cap]
      norm_num⟩ rfl
  obtain ⟨_targetPrefix, keyIdentity, representativeQuery, _target⟩ := groupedTarget
  have parsedRepresentative :
      parseStageQuery
        (SmzaRp05GroupedSuffix.groupRepresentative
          (included actualProgram (encode actualProgram
            (counterInput decsCoefficientDomain pcs.post.root 0)))) = some query := by
    rw [keyIdentity]
    simpa only [query] using representativeQuery
  obtain ⟨rolePrefix, roleKeyIdentity, _, coordinates, _, stored, _, _⟩ :=
    current_actual_grouped_role_call_readback actualProgram branch
      (counterInput decsCoefficientDomain pcs.post.root 0, vector) vectorMember
      database claims fallback .decsMatrix query parsedRepresentative rfl rfl
  let routes := currentGroupedRoutes model bounded statement
  have counterAddress : ∀ index : Fin (digestCallCap 700),
      counterInput decsCoefficientDomain query.target index.val =
        SmzaRp05GroupedSuffix.groupEncode (rolePrefix, routes.decsMatrix index) := by
    intro index
    have coordinate := coordinates (routes.decsMatrix index)
    rw [currentGroupedRoutes_decsMatrix_val] at coordinate
    calc
      counterInput decsCoefficientDomain query.target index.val =
          SmzaRp05CurrentGroupedRecordReadback.canonicalQueryCounterInput
            query index.val := by
        simp only [SmzaRp05CurrentGroupedRecordReadback.canonicalQueryCounterInput,
          query, decsCoefficientDomain, SmzaChallengeStageTargets.roleDomain]
      _ = SmzaRp05GroupedSuffix.groupEncode (rolePrefix, routes.decsMatrix index) :=
        coordinate.symm
  have decodedRoute := current_decs_matrix_decoder_from_stored_group_cell
    actualProgram database fallback (encode actualProgram
      (counterInput decsCoefficientDomain pcs.post.root 0)) rolePrefix roleKeyIdentity
    vector stored model statement pcs.post.root routes.decsMatrix counterAddress
  have actualSample := executed_clean_post_merkle_actual_decs_coefficients ns oracle
    pcs.merkleInput pcs.post pcs.postExecuted postClean
  have oracleDecoded :
      currentOracleDecodedAt model oracle statement .decsMatrix pcs.post.root =
        some (sampledCoefficients (gammaRows pcs.post)) := by
    change currentActualDecsMatrixOutput
      (Equiv.refl (Fin (digestCallCap (140 * 5))))
      (SmzaRp05CurrentExecutedMatrixReadback.currentDecsMatrixVector oracle pcs.post.root) = _
    exact actualSample
  refine ⟨branchAccepted, vector, vectorMember, ?_⟩
  exact decodedRoute.trans oracleDecoded

end
end HegemonCrypto.SmallWood.SmzaRp05CurrentAcceptedDecsOutputBinding
