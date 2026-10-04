import SmzaRp05CurrentExecutedQueryReadback
import SmzaRp05CurrentAcceptedRoleQueryReadback
import SmzaRp05CurrentGroupedRoutes
import SmzaRp05CurrentGroupedClaimRetention
import SmzaRp05CurrentFiniteGroupedProgram
import SmzaRp05CurrentFixedAdviceOpeningSource
import SmzaRp05CurrentPrequeryChronology
import SmzaRp05PhysicalPcsRecordRetention
import SmzaRp05ExecutablePcsClosureClean
import SmzaRp05CertifiedReplayScheduleFrames
import SmzaRp05CurrentProofWireProgram

/-! # Accepted current DECS-sample output binding

The counter-zero call of the actual q38 sampler is read from the accepted
PCS execution, retained by that branch's grouped claims, and used to replay
the current grouped DECS-sample decoder.  The replay is tied to the query
selected by the same `PcsStages` oracle; no call, vector, or sampler result is
chosen independently.
-/

namespace HegemonCrypto.SmallWood.SmzaRp05CurrentAcceptedDecsSampleOutputBinding

open HegemonCrypto.CanonicalBytes (Byte encodeLE)
open HegemonCrypto.CmsOracleDatabaseBridge (ClaimsDatabaseEvent)
open HegemonCrypto.FiniteOracleDatabase (Database)
open SmzaRp05ExecutableMerkleVerifier (Program Oracle)
open SmzaRp05ExecutablePcsClosure
  (queryProgram queryResult ExecutionStages)
open SmzaRp05ExecutablePcsClosureStages (PcsStages)
open SmzaRp05ExecutableChallengeStage (fieldXof counterInput)
open SmzaRp05ExecutablePcsClosureStatement (statementBindingWords verifierProgram)
open SmzaRp05PhysicalAcceptedReplayLite
  (Branches branchResult branchKeys branchAnswers answerLog rawLog)
open SmzaRp05CurrentGroupedClaimRetention (groupedDecode actual_program_grouped_claims_replay_and_retain)
open SmzaRp05CurrentFiniteGroupedProgram
  (Key encode included answer_log_group_keys_represented)
open SmzaRp05CurrentGroupedOracleVector (finiteGroupedDatabaseOracle)
open SmzaRp05CurrentAcceptedRoleQueryReadback (current_actual_grouped_role_call_readback)
open SmzaRp05CurrentFixedAdviceOpeningSource (verifier_record_pair_has_branch_answer)
open SmzaRp05CurrentGroupedRoutes (currentGroupedRoutes currentGroupedRoutes_decsSample_val)
open SmzaRp05CurrentGroupedRecordReadback (canonicalQueryCounterInput)
open SmzaRp05CurrentExecutedQueryReadback
  (executedVector sampler_key_is_literal_counter_input executed_query_supplies_its_actual_sampler_output)
open SmzaRp05ExecutablePcsClosureSampling (query_execution_clean)
open SmzaRp05CurrentPrequeryChronology (pcs_q38_record_split)
open SmzaRp05PhysicalPcsRecordRetention (execution_pcs_records_retained_in_verifier)
open SmzaRp05ExecutablePcsClosureClean (merkle_input_pending)
open SmzaRp05CertifiedReplaySchedule (ordinary_counter_roundtrip)
open SmzaRp05TracePrefixes (RelationModel)
open SmzaRp05ConcreteSuffix (ModelWithinProtocol)
open SmzaRp05ExecutableFinalVerifier (ReconstructedTranscript)
open SmzaRp05ExecutablePcsClosure (transcriptProgram)
open SmzaRp05RelationRefinement (RelationDsl)
open SmzaRp05LeafNamespace (Namespace)
open SmzaRp05CurrentProofWireProgram (ExistingProofFieldView)
open SmzaRp05ExecutablePcsClosureStages (PcsStages)
open SmzaRp05GroupedSuffix
  (CanonicalRolePrefix GroupCounter groupZero groupKeyOf groupEncode groupRepresentative
    groupAddress group_address_encode group_block_cap_eq)
open SmzaChallengeStageTargets (Role StageQuery parseStageQuery)
open SmzaRp04RawRoleSampling (actualDecsSampleOutput q38CandidateCount)
open SmzaRp04RawRoleSampling (rawDecsSampleOutput selectedRawBlocks)
open HegemonCrypto.SmallWoodTranscript (decsFixedSamplingDomain)
open V8SmzaOracleParser (RawDigest RawInput)
open V8Smz9CoherentVectorMerkle (VectorOutput)
open V8Smz9CoherentMerkleInstrument (rawDigestBits)
open V8Smz9HiddenLeafQrom (DigestRegister)
open V8Smz9RawCounterCompiler (digestCallCap)
open Q38Rp05RawInputPartition (Rp05OtherRawInput rp05RawBytes)
open Q38Rp05CurrentPostfinal (currentFixedIndexKey)
open SmzaQ38McaSourceBinding (Query)

noncomputable section
set_option autoImplicit false
set_option maxRecDepth 12000
set_option maxHeartbeats 1000000

private def currentSamplerKey (bound : Nat) (largeEnough : 39162 ≤ bound)
    (digest : RawDigest) (counter : Fin (digestCallCap q38CandidateCount)) :
    Rp05OtherRawInput bound :=
  currentFixedIndexKey bound largeEnough (rawDigestBits digest) ⟨counter.val, by
    have cap : digestCallCap q38CandidateCount = 11 := by decide
    have h : counter.val < 11 := by simpa only [cap] using counter.isLt
    exact Nat.lt_trans h (by decide)⟩

private theorem sample_counter_keys_cons (requested : Nat) (positive : 0 < requested)
    (digest : RawDigest) :
    SmzaRp05ExecutableChallengeStage.counterKeys decsFixedSamplingDomain requested digest =
      counterInput decsFixedSamplingDomain digest 0 ::
        (SmzaRp05ExecutableChallengeStage.counterKeys decsFixedSamplingDomain
          requested digest).tail := by
  unfold SmzaRp05ExecutableChallengeStage.counterKeys
  have capPositive : 0 < SmzaRp05ExecutableChallengeStage.callCap requested := by
    simp only [SmzaRp05ExecutableChallengeStage.callCap]
    split <;> omega
  cases cap : SmzaRp05ExecutableChallengeStage.callCap requested with
  | zero => omega
  | succ n =>
      change List.map (counterInput decsFixedSamplingDomain digest)
        (List.range (n + 1)) = _
      rw [List.range_succ_eq_map]
      simp only [List.map_cons, List.tail_cons]

private theorem first_sample_counter_recorded
    (requested : Nat) (positive : 0 < requested) (digest : RawDigest) (oracle : Oracle) :
    (counterInput decsFixedSamplingDomain digest 0,
      oracle (counterInput decsFixedSamplingDomain digest 0)) ∈
      ((fieldXof decsFixedSamplingDomain requested digest).record oracle).2 := by
  have keys := sample_counter_keys_cons requested positive digest
  have headRecord :
      (counterInput decsFixedSamplingDomain digest 0,
        oracle (counterInput decsFixedSamplingDomain digest 0)) ∈
      ((SmzaRp05ExecutableChallengeStage.fieldLoop requested []
        (SmzaRp05ExecutableChallengeStage.counterKeys decsFixedSamplingDomain
          requested digest)).record oracle).2 := by
    rw [keys]
    have notDone : ¬ (requested ≤ 0) := by omega
    simp only [SmzaRp05ExecutableChallengeStage.fieldLoop, List.length_nil]
    rw [if_neg notDone]
    simp only [Program.record]
    exact List.mem_cons_self
  simpa only [fieldXof] using headRecord

/-- A same-branch counter-zero DECS-sample answer is the vector consumed by
the current grouped route, and the resulting query is exactly the one
decoded from this execution's q38 sampler. -/
theorem accepted_current_decs_sample_output_binding
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
      (SmzaRp05PhysicalAcceptedReplayLite.branchClaims
        (branchKeys (encode (producer.bind fun wire => verifierProgram ns dsl statement pending nonce wire))
          groupedDecode (producer.bind fun wire => verifierProgram ns dsl statement pending nonce wire)
          branch)
        (branchAnswers (encode (producer.bind fun wire => verifierProgram ns dsl statement pending nonce wire))
          groupedDecode (producer.bind fun wire => verifierProgram ns dsl statement pending nonce wire)
          branch)) database)
    [Fintype RawDigest] (fallback : RawDigest)
    (model : RelationModel) (bounded : ModelWithinProtocol model)
    (wire : ExistingProofFieldView) (transcript : ReconstructedTranscript)
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
      (producer.bind fun wire => verifierProgram ns dsl statement pending nonce wire) branch = some () ∧
    ∃ vector query,
      (counterInput decsFixedSamplingDomain pcs.openingDigest 0,
        vector) ∈
        answerLog groupedDecode
          (producer.bind fun wire => verifierProgram ns dsl statement pending nonce wire) branch ∧
      actualDecsSampleOutput (currentGroupedRoutes model bounded statement).decsSample vector =
        some query ∧
      query.val.image Fin.val = pcs.indexes.toFinset ∧
      actualDecsSampleOutput (Function.Embedding.refl
        (Fin (digestCallCap q38CandidateCount)))
        (executedVector
          (finiteGroupedDatabaseOracle
            (producer.bind fun wire => verifierProgram ns dsl statement pending nonce wire)
            database fallback)
          (currentSamplerKey 39162 (by decide) pcs.openingDigest)) = some query := by
  classical
  let actualProgram := producer.bind fun candidate =>
    verifierProgram ns dsl statement pending nonce candidate
  let oracle : Oracle := finiteGroupedDatabaseOracle actualProgram database fallback
  have groupedReplay := actual_program_grouped_claims_replay_and_retain
    actualProgram branch database claims fallback
  have branchRecord : actualProgram.record oracle =
      (branchResult groupedDecode actualProgram branch,
        rawLog groupedDecode actualProgram branch) := by
    change actualProgram.record
      (fun raw => match database (encode actualProgram raw) with
        | none => fallback
        | some vector => groupedDecode raw vector) = _
    exact groupedReplay.1
  have acceptedEval : actualProgram.eval oracle = some () := by
    change (producer.bind
      (fun candidate => verifierProgram ns dsl statement pending nonce candidate)).eval oracle =
      some ()
    rw [Program.eval_bind]
    rw [producerSuccess]
    simpa only [Option.bind_some] using verifierAccepted
  have branchAccepted : branchResult groupedDecode actualProgram branch = some () := by
    calc
      branchResult groupedDecode actualProgram branch = (actualProgram.record oracle).1 :=
        (congrArg Prod.fst branchRecord).symm
      _ = actualProgram.eval oracle := by simp [Program.record_result]
      _ = some () := acceptedEval
  obtain ⟨acceptedTranscript, acceptedTranscriptSuccess, transcriptClean, _, _⟩ :=
    SmzaRp05ExecutablePcsClosure.accepted_execution_constructs_transcript ns dsl statement
      pending statement.toBytes (statementBindingWords statement) nonce wire oracle verifierAccepted
  have transcriptEq : transcript = acceptedTranscript :=
    Option.some.inj (transcriptSuccess.symm.trans acceptedTranscriptSuccess)
  have transcriptCleanCurrent : transcript.pendingXofFailure = false := by
    rw [transcriptEq]
    exact transcriptClean
  have cleanStages := SmzaRp05ExecutablePcsClosureSampling.execution_stages_clean_matrix
    ns dsl statement pending statement.toBytes (statementBindingWords statement)
    nonce wire oracle transcript execution transcriptCleanCurrent
  have postCore := SmzaRp05ExecutableChallengeStage.post_merkle_has_executed_core
    ns oracle pcs.merkleInput pcs.post pcs.postExecuted
  have postClean : pcs.post.pending = false := pcs.pendingReturned.symm.trans cleanStages.1
  obtain ⟨inputClean, _, _⟩ :=
    SmzaRp05ExecutableChallengeStage.finished_xof_has_exact_words _ _
      (postCore.2.2.1.symm.trans postClean)
  have merklePending := merkle_input_pending wire.salt statement.toBytes
    pcs.sampledPending pcs.indexes pcs.rows execution.decs.maskingEvals wire.tapes
    wire.paths pcs.merkleInput pcs.inputBuilt
  have sampleClean : pcs.sampledPending = false := merklePending.symm.trans inputClean
  have queryClean := query_execution_clean execution.openingPending pcs.openingDigest oracle
    pcs.indexes pcs.sampledPending pcs.queryExecuted sampleClean
  obtain ⟨_, queryWords, queryScan⟩ := queryClean
  have sampleFieldEval : (fieldXof decsFixedSamplingDomain 50 pcs.openingDigest).eval oracle =
      some (some queryWords) := by
    rw [fieldXof, SmzaRp05ExecutableChallengeStage.field_loop_executes_scan, queryScan]
  have firstRead := first_sample_counter_recorded 50 (by decide) pcs.openingDigest oracle
  have queryProgramRead :
      (counterInput decsFixedSamplingDomain pcs.openingDigest 0,
        oracle (counterInput decsFixedSamplingDomain pcs.openingDigest 0)) ∈
        ((queryProgram execution.openingPending pcs.openingDigest).record oracle).2 := by
    have member := Program.bind_log_left oracle
      (fieldXof decsFixedSamplingDomain 50 pcs.openingDigest)
      (fun sampled => .done (queryResult execution.openingPending sampled))
      (some queryWords) sampleFieldEval firstRead
    simpa only [queryProgram, queryResult] using member
  have pcsRead :
      (counterInput decsFixedSamplingDomain pcs.openingDigest 0,
        oracle (counterInput decsFixedSamplingDomain pcs.openingDigest 0)) ∈
        ((SmzaRp05ExecutablePcsClosure.pcsProgram ns execution.openingPending wire.hPiop
          (SmzaRp05PcsToFinalProgram.sameProofRows execution.middle.pcs execution.piop)
          execution.decs
          (List.ofFn fun j : Fin 6 => V8Smz9PiopReconstruction.points execution.opening j)
          wire.salt statement.toBytes (statementBindingWords statement)
          wire.tapes wire.paths).record oracle).2 := by
    rw [pcs_q38_record_split ns execution.openingPending wire.hPiop
      (SmzaRp05PcsToFinalProgram.sameProofRows execution.middle.pcs execution.piop)
      execution.decs
      (List.ofFn fun j : Fin 6 => V8Smz9PiopReconstruction.points execution.opening j)
      wire.salt statement.toBytes (statementBindingWords statement)
      wire.tapes wire.paths oracle execution.hashFpp execution.pcsPending pcs]
    simp only [List.mem_append]
    exact Or.inr (Or.inl queryProgramRead)
  have pcsToVerifier := execution_pcs_records_retained_in_verifier ns dsl statement
    pending nonce wire oracle transcript execution transcriptSuccess
  have verifierRead := pcsToVerifier _ pcsRead
  have wholeRead :
      (counterInput decsFixedSamplingDomain pcs.openingDigest 0,
        oracle (counterInput decsFixedSamplingDomain pcs.openingDigest 0)) ∈
        (actualProgram.record oracle).2 := by
    have recordSplit := Program.record_bind_success oracle producer
      (fun candidate => verifierProgram ns dsl statement pending nonce candidate)
      wire producerSuccess
    rw [recordSplit]
    exact List.mem_append_right _ verifierRead
  obtain ⟨actualOutput, outputRead, _⟩ :=
    verifier_record_pair_has_branch_answer (Key := Key actualProgram)
      actualProgram branch oracle branchRecord
      (counterInput decsFixedSamplingDomain pcs.openingDigest 0)
      (oracle (counterInput decsFixedSamplingDomain pcs.openingDigest 0)) wholeRead
  let query : StageQuery := ⟨.decsSample, pcs.openingDigest, 0, 0⟩
  let leading : RawInput :=
    encodeLE 8 V8SmzaOracleParser.profileDomain.length ++
      V8SmzaOracleParser.profileDomain ++
      encodeLE 8 decsFixedSamplingDomain.length ++ decsFixedSamplingDomain ++
      encodeLE 8 8 ++ List.ofFn pcs.openingDigest
  let zeroCounter : Fin (2 ^ 64) := ⟨0, by norm_num⟩
  have parsedZero : parseStageQuery (leading ++ encodeLE 8 0) = some query := by
    change parseStageQuery (counterInput decsFixedSamplingDomain pcs.openingDigest 0) = _
    simpa only [SmzaChallengeStageTargets.roleDomain,
      SmzaRp05ExecutableChallengeStage.counterInput, zeroCounter, Fin.val_mk, query] using
      ordinary_counter_roundtrip .decsSample (by decide) pcs.openingDigest zeroCounter
  let rolePrefix : CanonicalRolePrefix :=
    ⟨.decsSample, leading, ⟨query, parsedZero, rfl⟩⟩
  have encodedZero : groupEncode (rolePrefix, groupZero) =
      counterInput decsFixedSamplingDomain pcs.openingDigest 0 := by
    change leading ++ encodeLE 8 0 = _
    rfl
  have represented := answer_log_group_keys_represented groupedDecode actualProgram branch
    (counterInput decsFixedSamplingDomain pcs.openingDigest 0, actualOutput) outputRead
  have keyIdentity : included actualProgram (encode actualProgram
      (counterInput decsFixedSamplingDomain pcs.openingDigest 0)) = Sum.inl rolePrefix := by
    calc
      included actualProgram (encode actualProgram
          (counterInput decsFixedSamplingDomain pcs.openingDigest 0)) =
          groupKeyOf (counterInput decsFixedSamplingDomain pcs.openingDigest 0) := represented
      _ = Sum.inl rolePrefix := by
        change (groupAddress (counterInput decsFixedSamplingDomain pcs.openingDigest 0)).1 = _
        rw [← encodedZero]
        exact congrArg Prod.fst (group_address_encode rolePrefix groupZero)
  have representativeParsed :
      parseStageQuery (groupRepresentative (Sum.inl rolePrefix)) = some query := by
    simpa only [groupRepresentative, groupEncode, rolePrefix, groupZero,
      V8Smz9CoherentVectorMerkle.canonicalRepresentative,
      V8Smz9RawCounterCompiler.boundedCounterInput,
      V8Smz9RawCounterCompiler.counterInput, Fin.val_mk] using parsedZero
  have parsed : parseStageQuery
      (groupRepresentative (included actualProgram (encode actualProgram
        (counterInput decsFixedSamplingDomain pcs.openingDigest 0)))) = some query := by
    rw [keyIdentity]
    exact representativeParsed
  let call := (counterInput decsFixedSamplingDomain pcs.openingDigest 0, actualOutput)
  obtain ⟨rolePrefix', roleKeyIdentity, _, coordinates, _, stored, _, coordinateAnswers⟩ :=
    current_actual_grouped_role_call_readback actualProgram branch call outputRead
      database claims fallback .decsSample query parsed rfl rfl
  let routes := currentGroupedRoutes model bounded statement
  let selected := routes.decsSample
  have routeRead : ∀ index : Fin (digestCallCap q38CandidateCount),
      actualOutput (selected index) =
        (executedVector oracle
          (fun counter : Fin (digestCallCap q38CandidateCount) =>
            currentFixedIndexKey 39162 (by decide) (rawDigestBits pcs.openingDigest)
              ⟨counter.val, by
                have cap : digestCallCap q38CandidateCount = 11 := by decide
                have h : counter.val < 11 := by simpa only [cap] using counter.isLt
                exact Nat.lt_trans h (by decide)⟩)) index := by
    intro index
    have coordinate := coordinates (selected index)
    rw [currentGroupedRoutes_decsSample_val] at coordinate
    have canonical :
        canonicalQueryCounterInput query index.val =
          counterInput decsFixedSamplingDomain pcs.openingDigest index.val := by
      simp only [canonicalQueryCounterInput, query, decsFixedSamplingDomain,
        SmzaChallengeStageTargets.roleDomain]
    have literal := sampler_key_is_literal_counter_input 39162 (by decide)
      pcs.openingDigest index
    have rawEq : rp05RawBytes (.inr
          (currentSamplerKey 39162 (by decide) pcs.openingDigest index)) =
        groupEncode (rolePrefix', selected index) := by
      calc
        _ = counterInput decsFixedSamplingDomain pcs.openingDigest index.val := literal
        _ = canonicalQueryCounterInput query index.val := canonical.symm
        _ = groupEncode (rolePrefix', selected index) := coordinate.symm
    have oracleCoordinate := coordinateAnswers (selected index)
    calc
      actualOutput (selected index) =
          rawDigestBits (rawDigestBits.symm (actualOutput (selected index))) := by simp
      _ = rawDigestBits (oracle (groupEncode (rolePrefix', selected index))) := by
        rw [← oracleCoordinate]
      _ = rawDigestBits (oracle (rp05RawBytes (.inr
          (currentSamplerKey 39162 (by decide) pcs.openingDigest index)))) := by rw [← rawEq]
      _ = _ := rfl
  have groupedOutputEq :
      actualDecsSampleOutput selected actualOutput =
        actualDecsSampleOutput
          (Function.Embedding.refl (Fin (digestCallCap q38CandidateCount)))
          (executedVector oracle
            (currentSamplerKey 39162 (by decide) pcs.openingDigest)) := by
    unfold actualDecsSampleOutput
    apply congrArg rawDecsSampleOutput
    funext index
    simp only [selectedRawBlocks]
    rw [routeRead]
    rfl
  have querySelected := executed_query_supplies_its_actual_sampler_output
    (stages := pcs) sampleClean 39162 (by decide)
    (fun j : Fin 6 => V8Smz9PiopReconstruction.points execution.opening j)
    (by
      intro left right same
      exact (V8Smz9AdaptiveFiniteAccounting.full_admissible_linear_piop_exact
        execution.opening).pointsInjective same)
  obtain ⟨_, _, actualQuery, _, actualImage, actualQueryOutput⟩ := querySelected
  have groupedQuery : actualDecsSampleOutput selected actualOutput = some actualQuery := by
    rw [groupedOutputEq]
    exact actualQueryOutput
  exact ⟨branchAccepted, actualOutput, actualQuery, outputRead, groupedQuery,
    actualImage, actualQueryOutput⟩

end
end HegemonCrypto.SmallWood.SmzaRp05CurrentAcceptedDecsSampleOutputBinding
