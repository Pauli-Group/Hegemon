import SmzaRp05ContextAmbientMatrixEvent
import SmzaRp05AcceptedRoleLabels
import SmzaRp05CertifiedReplayScheduleFrames
import SmzaRp05CurrentAcceptedDecsOutputBinding
import SmzaRp05CurrentAcceptedEarlierAdvice
import SmzaRp05CurrentAcceptedFixedEarlierReadback
import SmzaRp05CurrentAcceptedPiopRecordedOutputs
import SmzaRp05CurrentAcceptedRoleQueryReadback
import SmzaRp05CurrentDecsGroupedTarget
import SmzaRp05CurrentExecutedQueryReadback
import SmzaRp05CurrentFiniteGroupedProgram
import SmzaRp05CurrentFixedAdviceDecsSource
import SmzaRp05CurrentFixedAdviceOpeningScan
import SmzaRp05CurrentFixedAdviceOpeningSource
import SmzaRp05CurrentGroupedClaimRetention
import SmzaRp05CurrentGroupedRoutes
import SmzaRp05CurrentPrequeryChronology
import SmzaRp05CurrentProofWireProgram
import SmzaRp05ExecutablePcsClosureClean
import SmzaRp05PhysicalPcsRecordRetention
import SmzaRp05TracePrefixes

/-! # Accepted current DECS-sample output binding

The counter-zero call of the actual q38 sampler is read from the accepted
PCS execution, retained by that branch's grouped claims, and used to replay
the current grouped DECS-sample decoder.  The replay is tied to the query
selected by the same `PcsStages` oracle; no call, vector, or sampler result is
chosen independently.
-/

namespace HegemonCrypto.SmallWood.SmzaRp05CurrentAcceptedDecsSampleOutputBindingAmbient

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
    (producer : Program SmzaRp05ContextAmbientDecoder.ParsedContext)
    (ns : Namespace) (dsl : RelationDsl)
    (c : SmzaRp05ContextAmbientDecoder.ParsedContext)
    (branch : Branches groupedDecode
      (producer.bind fun out => verifierProgram ns dsl out.statement out.pending out.nonce out.wire))
    (database : Database
      (Key (producer.bind fun out => verifierProgram ns dsl out.statement out.pending out.nonce out.wire))
      (VectorOutput GroupCounter))
    (claims : ClaimsDatabaseEvent
      (SmzaRp05PhysicalAcceptedReplayLite.branchClaims
        (branchKeys (encode (producer.bind fun out => verifierProgram ns dsl out.statement out.pending out.nonce out.wire))
          groupedDecode (producer.bind fun out => verifierProgram ns dsl out.statement out.pending out.nonce out.wire)
          branch)
        (branchAnswers (encode (producer.bind fun out => verifierProgram ns dsl out.statement out.pending out.nonce out.wire))
          groupedDecode (producer.bind fun out => verifierProgram ns dsl out.statement out.pending out.nonce out.wire)
          branch)) database)
    [Fintype RawDigest] (fallback : RawDigest)
    (model : RelationModel) (bounded : ModelWithinProtocol model)
    (transcript : ReconstructedTranscript)
    (execution : ExecutionStages ns dsl c.statement c.pending c.statement.toBytes
      (statementBindingWords c.statement) c.nonce c.wire
      (finiteGroupedDatabaseOracle
        (producer.bind fun out => verifierProgram ns dsl out.statement out.pending out.nonce out.wire)
        database fallback) transcript)
    (producerSuccess : producer.eval
      (finiteGroupedDatabaseOracle
        (producer.bind fun out => verifierProgram ns dsl out.statement out.pending out.nonce out.wire)
        database fallback) = some c)
    (pcs : PcsStages ns execution.openingPending c.wire.hPiop
      (SmzaRp05PcsToFinalProgram.sameProofRows execution.middle.pcs execution.piop)
      execution.decs
      (List.ofFn fun j : Fin 6 => V8Smz9PiopReconstruction.points execution.opening j)
      c.wire.salt c.statement.toBytes (statementBindingWords c.statement)
      c.wire.tapes c.wire.paths
      (finiteGroupedDatabaseOracle
        (producer.bind fun out => verifierProgram ns dsl out.statement out.pending out.nonce out.wire)
        database fallback)
      execution.hashFpp execution.pcsPending)
    (verifierAccepted : (verifierProgram ns dsl c.statement c.pending c.nonce c.wire).eval
        (finiteGroupedDatabaseOracle
          (producer.bind fun out => verifierProgram ns dsl out.statement out.pending out.nonce out.wire)
          database fallback) = some ())
    (transcriptSuccess : (transcriptProgram ns dsl c.statement c.pending c.statement.toBytes
      (statementBindingWords c.statement) c.nonce c.wire).eval
        (finiteGroupedDatabaseOracle
          (producer.bind fun out => verifierProgram ns dsl out.statement out.pending out.nonce out.wire)
          database fallback) = some transcript) :
    branchResult groupedDecode
      (producer.bind fun out => verifierProgram ns dsl out.statement out.pending out.nonce out.wire) branch = some () ∧
    ∃ vector query,
      (counterInput decsFixedSamplingDomain pcs.openingDigest 0,
        vector) ∈
        answerLog groupedDecode
          (producer.bind fun out => verifierProgram ns dsl out.statement out.pending out.nonce out.wire) branch ∧
      actualDecsSampleOutput (currentGroupedRoutes model bounded c.statement).decsSample vector =
        some query ∧
      query.val.image Fin.val = pcs.indexes.toFinset ∧
      actualDecsSampleOutput (Function.Embedding.refl
        (Fin (digestCallCap q38CandidateCount)))
        (executedVector
          (finiteGroupedDatabaseOracle
            (producer.bind fun out => verifierProgram ns dsl out.statement out.pending out.nonce out.wire)
            database fallback)
          (currentSamplerKey 39162 (by decide) pcs.openingDigest)) = some query := by
  classical
  let actualProgram := producer.bind fun candidate => verifierProgram ns dsl candidate.statement candidate.pending candidate.nonce candidate.wire
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
      (fun candidate => verifierProgram ns dsl candidate.statement candidate.pending candidate.nonce candidate.wire)).eval oracle =
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
    SmzaRp05ExecutablePcsClosure.accepted_execution_constructs_transcript ns dsl c.statement
      c.pending c.statement.toBytes (statementBindingWords c.statement) c.nonce c.wire oracle verifierAccepted
  have transcriptEq : transcript = acceptedTranscript :=
    Option.some.inj (transcriptSuccess.symm.trans acceptedTranscriptSuccess)
  have transcriptCleanCurrent : transcript.pendingXofFailure = false := by
    rw [transcriptEq]
    exact transcriptClean
  have cleanStages := SmzaRp05ExecutablePcsClosureSampling.execution_stages_clean_matrix
    ns dsl c.statement c.pending c.statement.toBytes (statementBindingWords c.statement)
    c.nonce c.wire oracle transcript execution transcriptCleanCurrent
  have postCore := SmzaRp05ExecutableChallengeStage.post_merkle_has_executed_core
    ns oracle pcs.merkleInput pcs.post pcs.postExecuted
  have postClean : pcs.post.pending = false := pcs.pendingReturned.symm.trans cleanStages.1
  obtain ⟨inputClean, _, _⟩ :=
    SmzaRp05ExecutableChallengeStage.finished_xof_has_exact_words _ _
      (postCore.2.2.1.symm.trans postClean)
  have merklePending := merkle_input_pending c.wire.salt c.statement.toBytes
    pcs.sampledPending pcs.indexes pcs.rows execution.decs.maskingEvals c.wire.tapes
    c.wire.paths pcs.merkleInput pcs.inputBuilt
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
        ((SmzaRp05ExecutablePcsClosure.pcsProgram ns execution.openingPending c.wire.hPiop
          (SmzaRp05PcsToFinalProgram.sameProofRows execution.middle.pcs execution.piop)
          execution.decs
          (List.ofFn fun j : Fin 6 => V8Smz9PiopReconstruction.points execution.opening j)
          c.wire.salt c.statement.toBytes (statementBindingWords c.statement)
          c.wire.tapes c.wire.paths).record oracle).2 := by
    rw [pcs_q38_record_split ns execution.openingPending c.wire.hPiop
      (SmzaRp05PcsToFinalProgram.sameProofRows execution.middle.pcs execution.piop)
      execution.decs
      (List.ofFn fun j : Fin 6 => V8Smz9PiopReconstruction.points execution.opening j)
      c.wire.salt c.statement.toBytes (statementBindingWords c.statement)
      c.wire.tapes c.wire.paths oracle execution.hashFpp execution.pcsPending pcs]
    simp only [List.mem_append]
    exact Or.inr (Or.inl queryProgramRead)
  have pcsToVerifier := execution_pcs_records_retained_in_verifier ns dsl c.statement
    c.pending c.nonce c.wire oracle transcript execution transcriptSuccess
  have verifierRead := pcsToVerifier _ pcsRead
  have wholeRead :
      (counterInput decsFixedSamplingDomain pcs.openingDigest 0,
        oracle (counterInput decsFixedSamplingDomain pcs.openingDigest 0)) ∈
        (actualProgram.record oracle).2 := by
    have recordSplit := Program.record_bind_success oracle producer
      (fun candidate => verifierProgram ns dsl candidate.statement candidate.pending candidate.nonce candidate.wire)
      c producerSuccess
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
  let routes := currentGroupedRoutes model bounded c.statement
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
end HegemonCrypto.SmallWood.SmzaRp05CurrentAcceptedDecsSampleOutputBindingAmbient

/-! # Fixed earlier-cell readback on one accepted execution

These adapters retain the supplied accepted execution and PCS stages. The
DECS-matrix readback uses the actual counter-zero call at that PCS root; the
PIOP-opening readback replays the entire canonical nonce scan on the same
branch, including failed earlier nonces.
-/

namespace HegemonCrypto.SmallWood.SmzaRp05CurrentAcceptedFixedEarlierCellsAmbient

open scoped Classical
open HegemonCrypto.CanonicalBytes (Byte)
open HegemonCrypto.CmsOracleDatabaseBridge (ClaimsDatabaseEvent)
open HegemonCrypto.FiniteOracleDatabase (Database)
open HegemonCrypto.CmsCompressedOracle (Basis)
open SmzaRp05ConditionedExecution
  (FixedTable ActiveMemory fixedCanonicalOpeningAt firstSome firstSome_append_selected
    canonicalOpeningNonceOrder)
open SmzaRp05CurrentFixedEarlierAdvice
  (currentFixedAdvice currentFixedDecodedAt currentFixedVectorDecodedAt)
open SmzaRp05CurrentAcceptedFixedEarlierReadback (currentFixedEarlierAdviceFamily)
open SmzaRp05CurrentAcceptedFixedEarlierReadback
  (currentFixedEarlierAdviceFamily_active currentFixedEarlierAdviceFamily_other)
open SmzaRp05CurrentFixedAdvicePiopSource
  (current_piop_opening_fixed_advice_matches_same_branch_source_nonce)
open SmzaRp05CurrentFixedAdviceDecsSource
  (current_decs_fixed_advice_matches_same_branch_source)
open SmzaRp05CurrentAcceptedDecsOutputBinding (same_stage_decs_counter_zero_decodes)
open SmzaRp05CurrentDecsGroupedTarget (recorded_decs_call_has_grouped_target)
open SmzaRp05CurrentGroupedRoutes (currentGroupedRoutes)
open SmzaRp05CurrentAcceptedRoleQueryReadback (current_actual_grouped_role_call_readback)
open SmzaRp05AcceptedRoleLabels (EarlierReadback CausalPayloads)
open SmzaRp05CurrentExecutedEarlierAdvice (currentOracleAllAdvice currentOracleDecodedAt)
open SmzaRp05CurrentAdaptiveExecution (Context)
open SmzaRp05CurrentFixedAdviceOpeningSource (verifier_record_pair_has_branch_answer)
open SmzaRp05CurrentOpeningSelectedRetention
  (successful_canonical_opening_retains_selected_nonce_call_in_verifier_record)
open SmzaRp05CurrentOpeningAttemptRetention
  (successful_canonical_opening_retains_failed_nonce_calls_in_verifier_record)
open SmzaRp05CurrentOpeningGroupIdentity (opening_counter_call_group_address)
open SmzaRp05CurrentCanonicalOpeningOutput (executed_opening_decode_is_raw_output)
open SmzaRp05CurrentExecutedOpeningOutput (execution_stages_current_raw_opening)
open SmzaRp05CurrentGroupedClaimRetention
  (groupedDecode actual_program_grouped_claims_replay_and_retain)
open SmzaRp05CurrentFiniteGroupedProgram
  (Key encode included answer_log_group_keys_represented)
open SmzaRp05CurrentGroupedOracleVector (finiteGroupedDatabaseOracle)
open SmzaRp05CurrentGroupedContext
  (currentGroupedContext current_grouped_context_key_injective)
open SmzaRp05PhysicalAcceptedReplayLite (Branches branchResult)
open SmzaRp05PhysicalAcceptedReplayLite (answerLog)
open SmzaRp05ExecutableMerkleVerifier (Program Oracle)
open SmzaRp05ExecutablePcsClosure
  (ExecutionStages verifierProgram transcriptProgram)
open SmzaRp05ExecutablePcsClosureStatement (statementBindingWords)
open SmzaRp05ExecutablePcsClosureStages (PcsStages)
open SmzaRp05CurrentProofWireProgram (ExistingProofFieldView)
open SmzaRp05ExecutableFinalVerifier (ReconstructedTranscript)
open SmzaRp05RelationRefinement (RelationDsl)
open SmzaRp05LeafNamespace (Namespace)
open SmzaRp05TracePrefixes (RelationModel AllEarlierTables)
open SmzaRp05ConcreteSuffix (ModelWithinProtocol)
open SmzaRp05CurrentAdaptiveExecution (CmsState)
open SmzaRp05CurrentGroupedRoutes (currentGroupedRoutes)
open SmzaRp05GroupedSuffix (GroupCounter groupRepresentative)
open SmzaChallengeStageTargets (StageQuery parseStageQuery)
open SmzaRoleDomainConditioning (ActiveKey)
open V8SmzaOracleParser (RawInput RawDigest)
open V8Smz9CoherentVectorMerkle (VectorOutput)
open SmzaRp05CurrentOpeningProgram (openingCounterInput)
open SmzaRp05ExecutablePcsClosureStatement (verifierProgram)
open SmzaRp05CurrentFiniteGroupedProgram (included)
open SmzaRp05ExecutableChallengeStage (counterInput)
open HegemonCrypto.SmallWoodTranscript (decsCoefficientDomain)
open SmzaRp05CurrentAcceptedRoleTraceReadback (accepted_decs_matrix_counter_parses)
open SmzaRp05CurrentAcceptedEarlierAdvice
  (accepted_execution_supplies_earlier_advice_of_nonchallenge_retention)
open SmzaRp05CurrentAcceptedRoleQueryReadback (current_actual_grouped_role_call_readback)
open SmzaRp05CurrentAcceptedDecsOutputBinding (same_stage_decs_counter_zero_decodes)
open SmzaRp05CurrentFiniteGroupedProgram (encode)
open SmzaRp05CurrentGroupedClaimRetention (groupedDecode)
open SmzaRp05CurrentGroupedRoutes (currentGroupedRoutes_decsMatrix_val)
open SmzaRp05CurrentGroupedContext (current_grouped_context_key_injective)
open SmzaRp05CurrentFixedAdviceDecsSource
  (current_decs_fixed_advice_matches_same_branch_source)
open SmzaRp05CurrentAcceptedPiopRecordedOutputs
  (accepted_matrix_call_and_vector accepted_opening_call_and_vector)

noncomputable section
set_option autoImplicit false
set_option maxRecDepth 12000
set_option maxHeartbeats 1000000


abbrev CurrentVerifierProgram (producer : Program ExistingProofFieldView)
    (ns : Namespace) (dsl : RelationDsl)
    (statement : SmzaRp05StatementNamespace.Statement) (pending : Bool)
    (nonce : Fin (2 ^ 32)) :=
  producer.bind fun wire => verifierProgram ns dsl statement pending nonce wire

private theorem selected_not_mem_prefix
    {α : Type} {selected : α} (before after : List α)
    (nodup : (before ++ selected :: after).Nodup) : selected ∉ before := by
  induction before with
  | nil => simp
  | cons head tail ih =>
      have nodup' : (head :: (tail ++ selected :: after)).Nodup := by
        simpa only [List.cons_append] using nodup
      rcases List.nodup_cons.mp nodup' with ⟨headNot, restNodup⟩
      intro member
      rcases List.mem_cons.mp member with same | member
      · subst head
        exact headNot (by simp)
      · exact ih restNodup member

private theorem same_prefix_before_selected
    {α : Type} (selected : α) (before₁ after₁ before₂ after₂ : List α)
    (nodup : (before₁ ++ selected :: after₁).Nodup)
    (split : before₁ ++ selected :: after₁ = before₂ ++ selected :: after₂) :
    before₁ = before₂ := by
  have nodup₂ : (before₂ ++ selected :: after₂).Nodup := by
    rw [← split]
    exact nodup
  have absent₁ := selected_not_mem_prefix before₁ after₁ nodup
  have absent₂ := selected_not_mem_prefix before₂ after₂ nodup₂
  induction before₁ generalizing before₂ with
  | nil =>
      cases before₂ with
      | nil => rfl
      | cons head₂ tail₂ =>
          have sameHead := congrArg List.head? split
          have headEq : selected = head₂ := Option.some.inj sameHead
          subst head₂
          exact False.elim (absent₂ (by simp))
  | cons head₁ tail₁ ih =>
      cases before₂ with
      | nil =>
          have sameHead := congrArg List.head? split
          have headEq : head₁ = selected := Option.some.inj sameHead
          subst head₁
          exact False.elim (absent₁ (by simp))
      | cons head₂ tail₂ =>
          have sameHead := congrArg List.head? split
          have heads : head₁ = head₂ := Option.some.inj sameHead
          subst head₂
          have tails : tail₁ ++ selected :: after₁ = tail₂ ++ selected :: after₂ :=
            (List.cons.inj split).2
          have tailNodup : (tail₁ ++ selected :: after₁).Nodup :=
            (List.nodup_cons.mp (by simpa only [List.cons_append] using nodup)).2
          have tail₂FullNodup : (tail₂ ++ selected :: after₂).Nodup := by
            have h : (head₁ :: (tail₂ ++ selected :: after₂)).Nodup := by
              simpa only [List.cons_append] using nodup₂
            exact (List.nodup_cons.mp h).2
          have absentTail₁ := selected_not_mem_prefix tail₁ after₁ tailNodup
          have absentTail₂ := selected_not_mem_prefix tail₂ after₂ tail₂FullNodup
          have tailEq := ih tail₂ tailNodup tails tail₂FullNodup
            absentTail₁ absentTail₂
          exact congrArg (List.cons head₁) tailEq

private theorem firstSome_map {Index Other Value : Type*}
    (read : Other → Option Value) (mapIndex : Index → Other) (items : List Index) :
    firstSome read (items.map mapIndex) =
      firstSome (fun index => read (mapIndex index)) items := by
  induction items with
  | nil => rfl
  | cons head tail ih =>
      simp only [List.map_cons, firstSome]
      cases read (mapIndex head) <;> simp only [ih]

private theorem ofFn_fin_val_eq_range_map {α : Type*} {n : Nat} (f : Nat → α) :
    List.ofFn (fun index : Fin n => f index.val) = (List.range n).map f := by
  rw [List.ofFn_eq_pmap]
  simp only [List.pmap_eq_map]

private def fixedEarlierFamilyAtModel
    {Key Counter BaseWork : Type} [Fintype Key] [DecidableEq Key]
    [Fintype Counter] [DecidableEq Counter]
    [Fintype BaseWork] [DecidableEq BaseWork]
    (ctx : Context (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (blockCap : SmzaChallengeStageTargets.Role → Nat)
    (fixed : FixedTable ctx blockCap) (oracle : Oracle)
    (statement : SmzaRp05StatementNamespace.Statement)
    (model : RelationModel) (modelEq : ctx.model = model) :
    (selected : SmzaChallengeStageTargets.Role) →
      SmzaRp05TracePrefixes.EarlierTables model statement selected :=
  fun selected => modelEq ▸
    currentFixedEarlierAdviceFamily ctx blockCap fixed oracle selected statement

/-- The actual DECS-sample advice table used by a nonzero fixed fiber has a
five-field `EarlierReadback`: the two cells selected at `.decsSample` are
forced by the same-branch fixed DECS-matrix and canonical PIOP-opening
readbacks; the other three cells remain the accepted current-oracle values.
The target digests are the causal payload roots from this supplied execution.
-/
theorem same_stage_fixed_decs_sample_earlier_readback
    {BaseWork : Type} [Fintype BaseWork] [DecidableEq BaseWork]
    (producer : Program SmzaRp05ContextAmbientDecoder.ParsedContext)
    (ns : Namespace) (dsl : RelationDsl)
    (c : SmzaRp05ContextAmbientDecoder.ParsedContext)
    (branch : Branches groupedDecode
      ((producer.bind fun out => verifierProgram ns dsl out.statement out.pending out.nonce out.wire)))
    (_accepted : branchResult groupedDecode
      ((producer.bind fun out => verifierProgram ns dsl out.statement out.pending out.nonce out.wire)) branch = some ())
    (database : Database (Key ((producer.bind fun out => verifierProgram ns dsl out.statement out.pending out.nonce out.wire)))
      (VectorOutput GroupCounter))
    (claims : ClaimsDatabaseEvent
      (SmzaRp05PhysicalAcceptedReplayLite.branchClaims
        (SmzaRp05PhysicalAcceptedReplayLite.branchKeys
          (encode ((producer.bind fun out => verifierProgram ns dsl out.statement out.pending out.nonce out.wire)))
          groupedDecode ((producer.bind fun out => verifierProgram ns dsl out.statement out.pending out.nonce out.wire)) branch)
        (SmzaRp05PhysicalAcceptedReplayLite.branchAnswers
          (encode ((producer.bind fun out => verifierProgram ns dsl out.statement out.pending out.nonce out.wire)))
          groupedDecode ((producer.bind fun out => verifierProgram ns dsl out.statement out.pending out.nonce out.wire)) branch))
      database)
    [Fintype RawDigest] (fallback : RawDigest)
    (certificates : SmzaRp05RelationRefinement.GeneratedCertificates dsl)
    (boundedModel : ModelWithinProtocol
      (SmzaRp05RelationRefinement.relationModel dsl certificates))
    (advice : AllEarlierTables
      (SmzaRp05RelationRefinement.relationModel dsl certificates) .decsSample)
    (outerFuel innerFuel : Nat)
    (authorizedOf : BaseWork → Finset (List Byte))
    (blockCap : SmzaChallengeStageTargets.Role → Nat)
    (dummy : ActiveKey
      (currentGroupedContext ((producer.bind fun out => verifierProgram ns dsl out.statement out.pending out.nonce out.wire))
        (SmzaRp05RelationRefinement.relationModel dsl certificates) boundedModel ns
        .decsSample advice outerFuel innerFuel authorizedOf).role blockCap
      (currentGroupedContext ((producer.bind fun out => verifierProgram ns dsl out.statement out.pending out.nonce out.wire))
        (SmzaRp05RelationRefinement.relationModel dsl certificates) boundedModel ns
        .decsSample advice outerFuel innerFuel authorizedOf).keyBytes)
    (fixed : FixedTable
      (currentGroupedContext ((producer.bind fun out => verifierProgram ns dsl out.statement out.pending out.nonce out.wire))
        (SmzaRp05RelationRefinement.relationModel dsl certificates) boundedModel ns
        .decsSample advice outerFuel innerFuel authorizedOf) blockCap)
    (state : CmsState
      (Key := Key ((producer.bind fun out => verifierProgram ns dsl out.statement out.pending out.nonce out.wire)))
      (Counter := GroupCounter) (BaseWork := BaseWork))
    (basis : Basis
      (ActiveKey
        (currentGroupedContext ((producer.bind fun out => verifierProgram ns dsl out.statement out.pending out.nonce out.wire))
          (SmzaRp05RelationRefinement.relationModel dsl certificates) boundedModel ns
          .decsSample advice outerFuel innerFuel authorizedOf).role blockCap
        (currentGroupedContext ((producer.bind fun out => verifierProgram ns dsl out.statement out.pending out.nonce out.wire))
          (SmzaRp05RelationRefinement.relationModel dsl certificates) boundedModel ns
          .decsSample advice outerFuel innerFuel authorizedOf).keyBytes)
      (VectorOutput GroupCounter) (VectorOutput GroupCounter)
      (ActiveMemory
        (currentGroupedContext ((producer.bind fun out => verifierProgram ns dsl out.statement out.pending out.nonce out.wire))
        (SmzaRp05RelationRefinement.relationModel dsl certificates) boundedModel ns
        .decsSample advice outerFuel innerFuel authorizedOf)))
    (nonzero : SmzaRp05ConditionedExecution.fixedFiberToActive
      (currentGroupedContext ((producer.bind fun out => verifierProgram ns dsl out.statement out.pending out.nonce out.wire))
        (SmzaRp05RelationRefinement.relationModel dsl certificates) boundedModel ns
        .decsSample advice outerFuel innerFuel authorizedOf)
      blockCap dummy fixed
      (SmzaRp05ConditionedExecution.otherRoleTransform
        (currentGroupedContext ((producer.bind fun out => verifierProgram ns dsl out.statement out.pending out.nonce out.wire))
          (SmzaRp05RelationRefinement.relationModel dsl certificates) boundedModel ns
          .decsSample advice outerFuel innerFuel authorizedOf)
        blockCap (SmzaRp05PhysicalAcceptedReplayLite.physicalRun
          (encode ((producer.bind fun out => verifierProgram ns dsl out.statement out.pending out.nonce out.wire)))
          groupedDecode ((producer.bind fun out => verifierProgram ns dsl out.statement out.pending out.nonce out.wire))
          branch state)) basis ≠ 0)
    (positiveDecsMatrixCap : 0 < blockCap .decsMatrix)
    (producerSuccess : producer.eval
      (finiteGroupedDatabaseOracle
        ((producer.bind fun out => verifierProgram ns dsl out.statement out.pending out.nonce out.wire)) database fallback) =
          some c)
    (verifierAccepted : (verifierProgram ns dsl c.statement c.pending c.nonce c.wire).eval
      (finiteGroupedDatabaseOracle
        ((producer.bind fun out => verifierProgram ns dsl out.statement out.pending out.nonce out.wire)) database fallback) =
          some ())
    (transcript : ReconstructedTranscript)
    (transcriptSuccess : (transcriptProgram ns dsl c.statement c.pending c.statement.toBytes
      (statementBindingWords c.statement) c.nonce c.wire).eval
        (finiteGroupedDatabaseOracle
          ((producer.bind fun out => verifierProgram ns dsl out.statement out.pending out.nonce out.wire)) database fallback) =
            some transcript)
    (execution : ExecutionStages ns dsl c.statement c.pending c.statement.toBytes
      (statementBindingWords c.statement) c.nonce c.wire
      (finiteGroupedDatabaseOracle
        ((producer.bind fun out => verifierProgram ns dsl out.statement out.pending out.nonce out.wire)) database fallback)
      transcript)
    (pcs : PcsStages ns execution.openingPending c.wire.hPiop
      (SmzaRp05PcsToFinalProgram.sameProofRows execution.middle.pcs execution.piop)
      execution.decs
      (List.ofFn fun j : Fin 6 => V8Smz9PiopReconstruction.points execution.opening j)
      c.wire.salt c.statement.toBytes (statementBindingWords c.statement)
      c.wire.tapes c.wire.paths
      (finiteGroupedDatabaseOracle
        ((producer.bind fun out => verifierProgram ns dsl out.statement out.pending out.nonce out.wire)) database fallback)
      execution.hashFpp execution.pcsPending)
    (fixedOpening : fixedCanonicalOpeningAt
      (currentGroupedContext ((producer.bind fun out => verifierProgram ns dsl out.statement out.pending out.nonce out.wire))
        (SmzaRp05RelationRefinement.relationModel dsl certificates) boundedModel ns
        .decsSample advice outerFuel innerFuel authorizedOf)
      blockCap fixed c.statement c.wire.hPiop = some execution.opening)
    {leafNs : Namespace} {trace : SmzaRp05TracePrefixes.Trace}
    (messages : CausalPayloads leafNs trace)
    (decsDigest : V8SmzaOracleParser.digestAt messages.decs.bytes 0 = c.wire.hPiop)
    (fppDigest : V8SmzaOracleParser.digestAt messages.fpp.bytes 0 = pcs.post.root)
    (oracleEarlier : EarlierReadback
      (SmzaRp05RelationRefinement.relationModel dsl certificates) c.statement
      (fun selected => currentOracleAllAdvice
        (SmzaRp05RelationRefinement.relationModel dsl certificates)
        (finiteGroupedDatabaseOracle
          ((producer.bind fun out => verifierProgram ns dsl out.statement out.pending out.nonce out.wire)) database fallback)
        selected c.statement)
      messages
      (SmzaRp05CurrentAcceptedQuerySupport.sampledCoefficients
        (SmzaRp05PcsHashFppMiddle.gammaRows pcs.post))
      execution.matrix execution.opening) :
    EarlierReadback (SmzaRp05RelationRefinement.relationModel dsl certificates) c.statement
      (fixedEarlierFamilyAtModel
        (currentGroupedContext ((producer.bind fun out => verifierProgram ns dsl out.statement out.pending out.nonce out.wire))
          (SmzaRp05RelationRefinement.relationModel dsl certificates) boundedModel ns
          .decsSample advice outerFuel innerFuel authorizedOf)
        blockCap fixed
        (finiteGroupedDatabaseOracle
          ((producer.bind fun out => verifierProgram ns dsl out.statement out.pending out.nonce out.wire)) database fallback)
        c.statement (SmzaRp05RelationRefinement.relationModel dsl certificates) (by rfl))
      messages
      (SmzaRp05CurrentAcceptedQuerySupport.sampledCoefficients
        (SmzaRp05PcsHashFppMiddle.gammaRows pcs.post))
      execution.matrix execution.opening := by
  classical
  let model := SmzaRp05RelationRefinement.relationModel dsl certificates
  let program := (producer.bind fun out => verifierProgram ns dsl out.statement out.pending out.nonce out.wire)
  let oracle := finiteGroupedDatabaseOracle program database fallback
  let ctx := currentGroupedContext program model boundedModel ns .decsSample advice
    outerFuel innerFuel authorizedOf
  have ctxModel : ctx.model = model := rfl
  have ctxRole : ctx.role = .decsSample := rfl
  have decsCall := SmzaRp05CurrentAcceptedDecsOutputBindingAmbient.same_stage_decs_counter_zero_decodes producer ns dsl c branch database claims fallback model boundedModel transcript execution
    producerSuccess pcs verifierAccepted transcriptSuccess
  rcases decsCall with ⟨_branchOk, vector, vectorRecorded, _actualDecs⟩
  let input := counterInput decsCoefficientDomain pcs.post.root 0
  have callRecorded : (input, vector) ∈ answerLog groupedDecode program branch := by
    simpa only [input] using vectorRecorded
  let query : StageQuery := ⟨.decsMatrix, pcs.post.root, 0, 0⟩
  have targetRead := recorded_decs_call_has_grouped_target program branch
    (input, vector) callRecorded pcs.post.root ⟨0, by decide⟩ rfl
  rcases targetRead with ⟨rolePrefix, keyIdentity, parsedRepresentative, _target⟩
  have parsed : parseStageQuery (ctx.keyBytes (encode program input)) = some query := by
    change parseStageQuery (groupRepresentative (included program (encode program input))) = _
    rw [keyIdentity]
    simpa only [query] using parsedRepresentative
  have fixedDecs := current_decs_fixed_advice_matches_same_branch_source
    program model boundedModel ns .decsSample advice outerFuel innerFuel authorizedOf
    blockCap dummy fixed branch state basis nonzero database fallback claims (input, vector)
    callRecorded c.statement query parsed rfl (by decide) positiveDecsMatrixCap rfl
  have fixedDecsCell : currentFixedAdvice ctx blockCap fixed c.statement .decsMatrix
      (by change SmzaRp05TracePrefixes.roleOrder .decsMatrix <
        SmzaRp05TracePrefixes.roleOrder .decsSample; decide)
      (V8SmzaOracleParser.digestAt messages.fpp.bytes 0) =
        some (SmzaRp05CurrentAcceptedQuerySupport.sampledCoefficients
          (SmzaRp05PcsHashFppMiddle.gammaRows pcs.post)) := by
    rw [fppDigest]
    change currentFixedVectorDecodedAt ctx blockCap fixed c.statement .decsMatrix
      pcs.post.root 0 = _
    rw [fixedDecs]
    change currentOracleDecodedAt model oracle c.statement .decsMatrix pcs.post.root = _
    simpa only [model, currentOracleAllAdvice, currentOracleDecodedAt, fppDigest] using
      oracleEarlier.sampleCoefficients
  have fixedOpeningCell : currentFixedAdvice ctx blockCap fixed c.statement .piopOpening
      (by change SmzaRp05TracePrefixes.roleOrder .piopOpening <
        SmzaRp05TracePrefixes.roleOrder .decsSample; decide)
      (V8SmzaOracleParser.digestAt messages.decs.bytes 0) =
        some execution.opening := by
    rw [decsDigest]
    simpa [currentFixedAdvice, currentFixedDecodedAt] using fixedOpening
  let adviceFamily := fixedEarlierFamilyAtModel ctx blockCap fixed oracle c.statement model ctxModel
  refine ⟨?_, ?_, ?_, ?_, ?_⟩
  · have notActive : SmzaChallengeStageTargets.Role.piopMatrix ≠ ctx.role := by
      rw [ctxRole]
      decide
    have sameAdvice : adviceFamily .piopMatrix =
        currentOracleAllAdvice model oracle .piopMatrix c.statement := by
      dsimp [adviceFamily, fixedEarlierFamilyAtModel]
      rw [currentFixedEarlierAdviceFamily_other ctx blockCap fixed oracle
        .piopMatrix notActive]
      rfl
    change adviceFamily .piopMatrix .decsMatrix _ _ = _
    rw [sameAdvice]
    exact oracleEarlier.matrixCoefficients
  · have notActive : SmzaChallengeStageTargets.Role.piopOpening ≠ ctx.role := by
      rw [ctxRole]
      decide
    have sameAdvice : adviceFamily .piopOpening =
        currentOracleAllAdvice model oracle .piopOpening c.statement := by
      dsimp [adviceFamily, fixedEarlierFamilyAtModel]
      rw [currentFixedEarlierAdviceFamily_other ctx blockCap fixed oracle
        .piopOpening notActive]
      rfl
    change adviceFamily .piopOpening .decsMatrix _ _ = _
    rw [sameAdvice]
    exact oracleEarlier.openingCoefficients
  · have notActive : SmzaChallengeStageTargets.Role.piopOpening ≠ ctx.role := by
      rw [ctxRole]
      decide
    have sameAdvice : adviceFamily .piopOpening =
        currentOracleAllAdvice model oracle .piopOpening c.statement := by
      dsimp [adviceFamily, fixedEarlierFamilyAtModel]
      rw [currentFixedEarlierAdviceFamily_other ctx blockCap fixed oracle
        .piopOpening notActive]
      rfl
    change adviceFamily .piopOpening .piopMatrix _ _ = _
    rw [sameAdvice]
    exact oracleEarlier.openingMatrix
  · have sameAdvice : adviceFamily .decsSample =
        currentFixedAdvice ctx blockCap fixed c.statement := by
      dsimp [adviceFamily, fixedEarlierFamilyAtModel]
      change currentFixedEarlierAdviceFamily ctx blockCap fixed oracle ctx.role c.statement = _
      rw [currentFixedEarlierAdviceFamily_active]
    change adviceFamily .decsSample .decsMatrix _ _ = _
    rw [sameAdvice]
    exact fixedDecsCell
  · have sameAdvice : adviceFamily .decsSample =
        currentFixedAdvice ctx blockCap fixed c.statement := by
      dsimp [adviceFamily, fixedEarlierFamilyAtModel]
      change currentFixedEarlierAdviceFamily ctx blockCap fixed oracle ctx.role c.statement = _
      rw [currentFixedEarlierAdviceFamily_active]
    change adviceFamily .decsSample .piopOpening _ _ = _
    rw [sameAdvice]
    exact fixedOpeningCell

/-- Same-stage counterpart of `accepted_current_fixed_opening_scan`. The
accepted branch, finite database, supplied producer result, transcript, and
PCS stages are one execution; the fixed advice scan is forced by every actual
selected and failed opening call of that execution. -/
theorem same_stage_current_fixed_opening_scan
    {BaseWork : Type} [Fintype BaseWork] [DecidableEq BaseWork]
    (producer : Program SmzaRp05ContextAmbientDecoder.ParsedContext)
    (ns : Namespace) (dsl : RelationDsl)
    (c : SmzaRp05ContextAmbientDecoder.ParsedContext)
    (branch : Branches groupedDecode
      ((producer.bind fun out => verifierProgram ns dsl out.statement out.pending out.nonce out.wire)))
    (_accepted : branchResult groupedDecode
      ((producer.bind fun out => verifierProgram ns dsl out.statement out.pending out.nonce out.wire)) branch = some ())
    (database : Database (Key ((producer.bind fun out => verifierProgram ns dsl out.statement out.pending out.nonce out.wire)))
      (VectorOutput GroupCounter))
    (claims : ClaimsDatabaseEvent
      (SmzaRp05PhysicalAcceptedReplayLite.branchClaims
        (SmzaRp05PhysicalAcceptedReplayLite.branchKeys
          (encode ((producer.bind fun out => verifierProgram ns dsl out.statement out.pending out.nonce out.wire)))
          groupedDecode ((producer.bind fun out => verifierProgram ns dsl out.statement out.pending out.nonce out.wire)) branch)
        (SmzaRp05PhysicalAcceptedReplayLite.branchAnswers
          (encode ((producer.bind fun out => verifierProgram ns dsl out.statement out.pending out.nonce out.wire)))
          groupedDecode ((producer.bind fun out => verifierProgram ns dsl out.statement out.pending out.nonce out.wire)) branch))
      database)
    (fallback : RawDigest)
    (model : RelationModel) (boundedModel : ModelWithinProtocol model)
    (role : SmzaChallengeStageTargets.Role)
    (advice : AllEarlierTables model role) (outerFuel innerFuel : Nat)
    (authorizedOf : BaseWork → Finset (List Byte))
    (blockCap : SmzaChallengeStageTargets.Role → Nat)
    (dummy : ActiveKey
      (currentGroupedContext ((producer.bind fun out => verifierProgram ns dsl out.statement out.pending out.nonce out.wire))
        model boundedModel ns role advice outerFuel innerFuel authorizedOf).role blockCap
      (currentGroupedContext ((producer.bind fun out => verifierProgram ns dsl out.statement out.pending out.nonce out.wire))
        model boundedModel ns role advice outerFuel innerFuel authorizedOf).keyBytes)
    (fixed : FixedTable
      (currentGroupedContext ((producer.bind fun out => verifierProgram ns dsl out.statement out.pending out.nonce out.wire))
        model boundedModel ns role advice outerFuel innerFuel authorizedOf) blockCap)
    (state : CmsState
      (Key := Key ((producer.bind fun out => verifierProgram ns dsl out.statement out.pending out.nonce out.wire)))
      (Counter := GroupCounter) (BaseWork := BaseWork))
    (basis : Basis
      (ActiveKey
        (currentGroupedContext ((producer.bind fun out => verifierProgram ns dsl out.statement out.pending out.nonce out.wire))
          model boundedModel ns role advice outerFuel innerFuel authorizedOf).role blockCap
        (currentGroupedContext ((producer.bind fun out => verifierProgram ns dsl out.statement out.pending out.nonce out.wire))
          model boundedModel ns role advice outerFuel innerFuel authorizedOf).keyBytes)
      (VectorOutput GroupCounter) (VectorOutput GroupCounter)
      (ActiveMemory
        (currentGroupedContext ((producer.bind fun out => verifierProgram ns dsl out.statement out.pending out.nonce out.wire))
          model boundedModel ns role advice outerFuel innerFuel authorizedOf)))
    (nonzero : SmzaRp05ConditionedExecution.fixedFiberToActive
      (currentGroupedContext ((producer.bind fun out => verifierProgram ns dsl out.statement out.pending out.nonce out.wire))
        model boundedModel ns role advice outerFuel innerFuel authorizedOf)
      blockCap dummy fixed
      (SmzaRp05ConditionedExecution.otherRoleTransform
        (currentGroupedContext ((producer.bind fun out => verifierProgram ns dsl out.statement out.pending out.nonce out.wire))
          model boundedModel ns role advice outerFuel innerFuel authorizedOf)
        blockCap (SmzaRp05PhysicalAcceptedReplayLite.physicalRun
          (encode ((producer.bind fun out => verifierProgram ns dsl out.statement out.pending out.nonce out.wire)))
          groupedDecode ((producer.bind fun out => verifierProgram ns dsl out.statement out.pending out.nonce out.wire))
          branch state)) basis ≠ 0)
    (selectedRoleEarlier : .piopOpening ≠ role)
    (positiveOpeningCap : 0 < blockCap .piopOpening)
    (producerSuccess : producer.eval
      (finiteGroupedDatabaseOracle
        ((producer.bind fun out => verifierProgram ns dsl out.statement out.pending out.nonce out.wire)) database fallback) =
          some c)
    (verifierAccepted : (verifierProgram ns dsl c.statement c.pending c.nonce c.wire).eval
      (finiteGroupedDatabaseOracle
        ((producer.bind fun out => verifierProgram ns dsl out.statement out.pending out.nonce out.wire)) database fallback) =
          some ())
    (transcript : ReconstructedTranscript)
    (transcriptSuccess : (transcriptProgram ns dsl c.statement c.pending c.statement.toBytes
      (statementBindingWords c.statement) c.nonce c.wire).eval
        (finiteGroupedDatabaseOracle
          ((producer.bind fun out => verifierProgram ns dsl out.statement out.pending out.nonce out.wire)) database fallback) =
            some transcript)
    (execution : ExecutionStages ns dsl c.statement c.pending c.statement.toBytes
      (statementBindingWords c.statement) c.nonce c.wire
      (finiteGroupedDatabaseOracle
        ((producer.bind fun out => verifierProgram ns dsl out.statement out.pending out.nonce out.wire)) database fallback)
      transcript)
    (pcs : PcsStages ns execution.openingPending c.wire.hPiop
      (SmzaRp05PcsToFinalProgram.sameProofRows execution.middle.pcs execution.piop)
      execution.decs
      (List.ofFn fun j : Fin 6 => V8Smz9PiopReconstruction.points execution.opening j)
      c.wire.salt c.statement.toBytes (statementBindingWords c.statement)
      c.wire.tapes c.wire.paths
      (finiteGroupedDatabaseOracle
        ((producer.bind fun out => verifierProgram ns dsl out.statement out.pending out.nonce out.wire)) database fallback)
      execution.hashFpp execution.pcsPending) :
    fixedCanonicalOpeningAt
      (currentGroupedContext ((producer.bind fun out => verifierProgram ns dsl out.statement out.pending out.nonce out.wire))
        model boundedModel ns role advice outerFuel innerFuel authorizedOf)
      blockCap fixed c.statement c.wire.hPiop = some execution.opening := by
  classical
  let program := (producer.bind fun out => verifierProgram ns dsl out.statement out.pending out.nonce out.wire)
  let oracle := finiteGroupedDatabaseOracle program database fallback
  let ctx := currentGroupedContext program model boundedModel ns role advice
    outerFuel innerFuel authorizedOf
  have recordEq := (actual_program_grouped_claims_replay_and_retain
    program branch database claims fallback).1
  obtain ⟨acceptedTranscript, acceptedTranscriptSuccess, transcriptClean,
      _finalEq, _finalCall⟩ :=
    SmzaRp05ExecutablePcsClosure.accepted_execution_constructs_transcript ns dsl c.statement
      c.pending c.statement.toBytes (statementBindingWords c.statement) c.nonce c.wire oracle
      verifierAccepted
  have sameTranscript : acceptedTranscript = transcript :=
    Option.some.inj (acceptedTranscriptSuccess.symm.trans transcriptSuccess)
  have suppliedTranscriptClean : transcript.pendingXofFailure = false := by
    rw [← sameTranscript]
    exact transcriptClean
  have stagesClean := SmzaRp05ExecutablePcsClosureSampling.execution_stages_clean_matrix
    ns dsl c.statement c.pending c.statement.toBytes (statementBindingWords c.statement) c.nonce c.wire oracle
    transcript execution suppliedTranscriptClean
  have openingClean := SmzaRp05ExecutablePcsClosureClean.pcs_stages_clean ns
    execution.openingPending c.wire.hPiop
    (SmzaRp05PcsToFinalProgram.sameProofRows execution.middle.pcs execution.piop)
    execution.decs
    (List.ofFn fun j : Fin 6 => V8Smz9PiopReconstruction.points execution.opening j)
    c.wire.salt c.statement.toBytes (statementBindingWords c.statement) c.wire.tapes c.wire.paths oracle
    execution.hashFpp execution.pcsPending pcs stagesClean.1
  have stagesOpeningSplit := execution_stages_current_raw_opening ns dsl c.statement c.pending
    c.statement.toBytes (statementBindingWords c.statement) c.nonce c.wire oracle transcript
    execution openingClean.1
  rcases stagesOpeningSplit with
    ⟨sourceBefore, sourceAfter, sourceOrder, sourcePrior, selectedDecoded, selected⟩
  obtain ⟨retainedBefore, retainedAfter, retainedOrder, failedCalls⟩ :=
    successful_canonical_opening_retains_failed_nonce_calls_in_verifier_record
      ns dsl c.statement c.pending c.nonce c.wire oracle transcript execution pcs openingClean.1
      transcriptSuccess
  have prefixEq := same_prefix_before_selected c.nonce.val
    sourceBefore sourceAfter retainedBefore retainedAfter
    (by rw [← sourceOrder]; exact List.nodup_range)
    (sourceOrder.symm.trans retainedOrder)
  have sourcePriorRetained : ∀ attempt ∈ retainedBefore,
      SmzaRp04RawRoleSampling.actualPiopOpeningOutput
        (Equiv.refl (Fin (V8Smz9RawCounterCompiler.digestCallCap
          V8Smz9AdaptiveFiniteAccounting.Historical.piopOpenings))).toEmbedding
        (SmzaRp05CurrentExecutedOpeningOutput.currentOpeningVector oracle c.wire.hPiop attempt) =
          none := by
    intro attempt member
    have memberSource : attempt ∈ sourceBefore := by simpa [prefixEq] using member
    exact executed_opening_decode_is_raw_output oracle c.wire.hPiop attempt none
      (sourcePrior attempt memberSource)
  have perNonceDecoder :
      ∀ (attemptIndex counter : Nat) (attemptBound : attemptIndex < 16)
      (counterBound : counter < 5)
      (recorded : (openingCounterInput c.wire.hPiop attemptIndex counter,
        oracle (openingCounterInput c.wire.hPiop attemptIndex counter)) ∈
          ((verifierProgram ns dsl c.statement c.pending c.nonce c.wire).record oracle).2),
      currentFixedVectorDecodedAt ctx blockCap fixed c.statement .piopOpening
        c.wire.hPiop attemptIndex =
      SmzaRp04RawRoleSampling.actualPiopOpeningOutput
        (Equiv.refl (Fin (V8Smz9RawCounterCompiler.digestCallCap
          V8Smz9AdaptiveFiniteAccounting.Historical.piopOpenings))).toEmbedding
        (SmzaRp05CurrentExecutedOpeningOutput.currentOpeningVector oracle c.wire.hPiop
          attemptIndex) := by
    intro attemptIndex counter attemptBound counterBound recorded
    let input := openingCounterInput c.wire.hPiop attemptIndex counter
    have verifierRecord := Program.record_bind_success oracle producer
      (fun actual => verifierProgram ns dsl actual.statement actual.pending actual.nonce actual.wire)
      c producerSuccess
    have recordedCombined : (input, oracle input) ∈ (program.record oracle).2 := by
      rw [verifierRecord]
      exact List.mem_append.mpr (Or.inr recorded)
    obtain ⟨output, answerMember, _digestEq⟩ := verifier_record_pair_has_branch_answer
      (Key := Key program) (program := program) branch oracle recordEq input
      (oracle input) recordedCombined
    have keyEq := answer_log_group_keys_represented groupedDecode program branch
      (input, output) answerMember
    obtain ⟨rolePrefixValue, addressEq, representativeParsed, _encoded⟩ :=
      opening_counter_call_group_address c.wire.hPiop attemptIndex (by omega)
        ⟨counter, by rw [SmzaRp05GroupedSuffix.group_block_cap_eq]; omega⟩
    have groupEq : SmzaRp05GroupedSuffix.groupKeyOf input = Sum.inl rolePrefixValue := by
      change (SmzaRp05GroupedSuffix.groupAddress input).1 = _
      exact congrArg Prod.fst addressEq
    let query : StageQuery := ⟨.piopOpening, c.wire.hPiop, attemptIndex, 0⟩
    have parsed : parseStageQuery (ctx.keyBytes (encode program input)) = some query := by
      change parseStageQuery (groupRepresentative (included program (encode program input))) = _
      rw [keyEq, groupEq]
      exact representativeParsed
    have nonceDecoder := current_piop_opening_fixed_advice_matches_same_branch_source_nonce
      program model boundedModel ns role advice outerFuel innerFuel authorizedOf blockCap dummy
      fixed branch state basis nonzero database fallback claims (input, output) answerMember
      c.statement query parsed rfl selectedRoleEarlier positiveOpeningCap rfl
    simpa only [query] using nonceDecoder
  have fixedPrior : ∀ attempt ∈ retainedBefore,
      currentFixedVectorDecodedAt ctx blockCap fixed c.statement .piopOpening
        c.wire.hPiop attempt = none := by
    intro attempt member
    have attemptBound : attempt < 16 := by
      have inRange : attempt ∈ List.range 16 := by
        rw [retainedOrder]
        exact List.mem_append.mpr (Or.inl member)
      exact List.mem_range.mp inRange
    obtain ⟨counter, counterBound, recorded⟩ := failedCalls attempt member
    rw [perNonceDecoder attempt counter attemptBound counterBound recorded,
      sourcePriorRetained attempt member]
    rfl
  have selectedRetention :=
    successful_canonical_opening_retains_selected_nonce_call_in_verifier_record
      ns dsl c.statement c.pending c.nonce c.wire oracle transcript execution pcs openingClean.1
      transcriptSuccess
  obtain ⟨selectedCounter, selectedBound, selectedRecorded⟩ := selectedRetention
  have selectedBound16 : c.nonce.val < 16 := by
    have inRange : c.nonce.val ∈ List.range 16 := by
      rw [sourceOrder]
      exact List.mem_append.mpr (Or.inr (by simp))
    exact List.mem_range.mp inRange
  have selectedDecode := perNonceDecoder c.nonce.val selectedCounter selectedBound16
    selectedBound selectedRecorded
  have fixedSelected : currentFixedVectorDecodedAt ctx blockCap fixed c.statement
      .piopOpening c.wire.hPiop c.nonce.val = some execution.opening :=
    selectedDecode.trans selected
  have mappedOrder : canonicalOpeningNonceOrder.map Fin.val = List.range 16 := by
    change (List.ofFn (id : Fin 16 → Fin 16)).map Fin.val = _
    rw [List.map_ofFn]
    exact (ofFn_fin_val_eq_range_map id).trans (List.map_id _)
  have fixedScan : firstSome
      (fun attempt : Nat => currentFixedVectorDecodedAt ctx blockCap fixed c.statement
        .piopOpening c.wire.hPiop attempt) (List.range 16) = some execution.opening := by
    rw [retainedOrder]
    simpa only [SmzaRp05TracePrefixes.RoleOutput] using firstSome_append_selected
      (fun attempt : Nat => currentFixedVectorDecodedAt ctx blockCap fixed c.statement
        .piopOpening c.wire.hPiop attempt)
      retainedBefore retainedAfter c.nonce.val execution.opening fixedPrior fixedSelected
  have fixedCanonical : firstSome
      (fun index : Fin 16 => currentFixedVectorDecodedAt ctx blockCap fixed c.statement
        .piopOpening c.wire.hPiop index.val) canonicalOpeningNonceOrder =
          some execution.opening := by
    have mappedScan : firstSome
        (fun attempt : Nat => currentFixedVectorDecodedAt ctx blockCap fixed c.statement
          .piopOpening c.wire.hPiop attempt)
        (canonicalOpeningNonceOrder.map Fin.val) = some execution.opening := by
      simpa only [mappedOrder] using fixedScan
    simpa only [firstSome_map, SmzaRp05TracePrefixes.RoleOutput] using mappedScan
  simpa only [fixedCanonicalOpeningAt, currentFixedVectorDecodedAt,
    SmzaRp05TracePrefixes.RoleOutput] using fixedCanonical

end
end HegemonCrypto.SmallWood.SmzaRp05CurrentAcceptedFixedEarlierCellsAmbient