import SmzaRp05CurrentAcceptedFixedEarlierReadback
import SmzaRp05CurrentFixedAdviceDecsSource
import SmzaRp05CurrentFixedAdvicePiopSource
import SmzaRp05CurrentAcceptedDecsOutputBinding
import SmzaRp05CurrentAcceptedPiopRecordedOutputs
import SmzaRp05CurrentDecsGroupedTarget
import SmzaRp05CurrentGroupedRoutes
import SmzaRp05CurrentAcceptedEarlierAdvice
import SmzaRp05CurrentGroupedClaimRetention
import SmzaRp05CurrentFiniteGroupedProgram
import SmzaRp05CurrentGroupedOracleVector
import SmzaRp05CurrentGroupedContext
import SmzaRp05AcceptedRoleLabels

/-! # Same-run fixed PIOP earlier-cell readback

The two PIOP-selected advice families retain their actual verifier branch.
Fixed DECS cells use its recorded DECS matrix call; the opening-role PIOP
matrix cell uses the recorded PIOP matrix sampler call. -/
namespace HegemonCrypto.SmallWood.SmzaRp05CurrentAcceptedFixedEarlierPiopCells

open scoped Classical
open HegemonCrypto.CanonicalBytes (Byte encodeLE)
open HegemonCrypto.CmsOracleDatabaseBridge (ClaimsDatabaseEvent)
open HegemonCrypto.CmsCompressedOracle (Basis)
open HegemonCrypto.FiniteOracleDatabase (Database)
open SmzaRp05ConditionedExecution
  (FixedTable ActiveMemory fixedFiberToActive otherRoleTransform)
open SmzaRp05CurrentFixedEarlierAdvice
  (currentFixedAdvice currentFixedVectorDecodedAt)
open SmzaRp05CurrentAcceptedFixedEarlierReadback
  (currentFixedEarlierAdviceFamily currentFixedEarlierAdviceFamily_active
    currentFixedEarlierAdviceFamily_other)
open SmzaRp05CurrentFixedAdviceDecsSource
  (current_decs_fixed_advice_matches_same_branch_source)
open SmzaRp05CurrentFixedAdvicePiopSource
  (current_piop_matrix_fixed_advice_matches_same_branch_source)
open SmzaRp05CurrentAcceptedDecsOutputBinding (same_stage_decs_counter_zero_decodes)
open SmzaRp05CurrentDecsGroupedTarget (recorded_decs_call_has_grouped_target)
open SmzaRp05CurrentAcceptedPiopRecordedOutputs (accepted_matrix_call_and_vector)
open SmzaRp05CurrentGroupedRoutes (currentGroupedRoutes)
open SmzaRp05AcceptedRoleLabels (EarlierReadback CausalPayloads)
open SmzaRp05CurrentExecutedEarlierAdvice (currentOracleAllAdvice currentOracleDecodedAt)
open SmzaRp05CurrentAdaptiveExecution (Context CmsState)
open SmzaRp05CurrentFixedAdviceOpeningSource (verifier_record_pair_has_branch_answer)
open SmzaRp05CurrentGroupedClaimRetention
  (groupedDecode actual_program_grouped_claims_replay_and_retain)
open SmzaRp05CurrentFiniteGroupedProgram
  (Key encode included answer_log_group_keys_represented)
open SmzaRp05CurrentGroupedOracleVector (finiteGroupedDatabaseOracle)
open SmzaRp05CurrentGroupedContext (currentGroupedContext)
open SmzaRp05PhysicalAcceptedReplayLite (Branches branchResult answerLog)
open SmzaRp05ExecutableMerkleVerifier (Program Oracle)
open SmzaRp05ExecutablePcsClosure
  (ExecutionStages transcriptProgram)
open SmzaRp05ExecutablePcsClosureStatement (statementBindingWords verifierProgram)
open SmzaRp05ExecutablePcsClosureStages (PcsStages)
open SmzaRp05CurrentProofWireProgram (ExistingProofFieldView)
open SmzaRp05ExecutableFinalVerifier (ReconstructedTranscript)
open SmzaRp05RelationRefinement (RelationDsl GeneratedCertificates relationModel)
open SmzaRp05LeafNamespace (Namespace)
open SmzaRp05TracePrefixes (RelationModel AllEarlierTables)
open SmzaRp05ConcreteSuffix (ModelWithinProtocol)
open SmzaRp05GroupedSuffix (GroupCounter groupRepresentative groupZero)
open SmzaChallengeStageTargets (Role StageQuery parseStageQuery)
open SmzaRoleDomainConditioning (ActiveKey)
open V8SmzaOracleParser (RawInput RawDigest)
open V8Smz9CoherentVectorMerkle (VectorOutput)
open SmzaRp05ExecutableChallengeStage (counterInput)
open SmzaRp05CurrentFiniteGroupedProgram (included encode)
open SmzaRp05CurrentAcceptedRoleTraceReadback (accepted_decs_matrix_counter_parses)
open SmzaRp05CurrentAcceptedEarlierAdvice
  (accepted_execution_supplies_earlier_advice_of_nonchallenge_retention)
open SmzaRp05CurrentAcceptedDecsOutputBinding (same_stage_decs_counter_zero_decodes)
open SmzaRp05CurrentGroupedRoutes (currentGroupedRoutes_decsMatrix_val)
open SmzaRp05CurrentGroupedContext (current_grouped_context_key_injective)
open SmzaRp05CurrentGroupedClaimRetention (groupedDecode)
open SmzaRp05CurrentGroupedRoutes (currentGroupedRoutes_piopMatrix_val)
open SmzaRp05GroupedSuffix
  (CanonicalRolePrefix groupKeyOf groupEncode groupAddress group_address_encode)
open SmzaRp05CertifiedReplaySchedule (ordinary_counter_roundtrip)
open SmzaRp05ExecutableChallengeStage (counterInput)
open HegemonCrypto.SmallWoodTranscript (decsCoefficientDomain piopCoefficientDomain)
open SmzaRp05PcsToFinalProgram (sameProofRows)

noncomputable section
set_option autoImplicit false
set_option maxRecDepth 16000
set_option maxHeartbeats 1500000
set_option linter.unusedSectionVars false

private def fixedEarlierFamilyAtModel
    {Key Counter BaseWork : Type} [Fintype Key] [DecidableEq Key]
    [Fintype Counter] [DecidableEq Counter]
    [Fintype BaseWork] [DecidableEq BaseWork]
    (ctx : Context (Key := Key) (Counter := Counter) (BaseWork := BaseWork))
    (blockCap : Role → Nat)
    (fixed : FixedTable ctx blockCap) (oracle : Oracle)
    (statement : SmzaRp05StatementNamespace.Statement)
    (model : RelationModel) (modelEq : ctx.model = model) :
    (selected : Role) → SmzaRp05TracePrefixes.EarlierTables model statement selected :=
  fun selected => modelEq ▸
    currentFixedEarlierAdviceFamily ctx blockCap fixed oracle selected statement

/-- A counter-zero PIOP matrix answer in the accepted grouped branch has the
canonical parser representative required by fixed-advice readback. -/
private theorem matrix_call_representative_parses
    {Result : Type} (program : Program Result)
    (branch : Branches groupedDecode program)
    (call : RawInput × VectorOutput GroupCounter)
    (recorded : call ∈ answerLog groupedDecode program branch)
    (digest : RawDigest)
    (inputEq : call.1 = counterInput piopCoefficientDomain digest 0) :
    parseStageQuery (groupRepresentative
      (included program (encode program call.1))) =
        some (⟨.piopMatrix, digest, 0, 0⟩ : StageQuery) := by
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
  have representativeParsed : parseStageQuery (groupRepresentative (Sum.inl rolePrefix)) =
      some query := by
    simpa only [groupRepresentative, groupEncode, rolePrefix, groupZero,
      V8Smz9CoherentVectorMerkle.canonicalRepresentative,
      V8Smz9RawCounterCompiler.boundedCounterInput,
      V8Smz9RawCounterCompiler.counterInput, Fin.val_mk] using parsedZero
  rw [keyIdentity]
  exact representativeParsed

-- The public wrappers below share one same-run proof. The role premise keeps
-- the fixed table active at a PIOP role; no table is supplied for a different
-- execution or verifier branch.
theorem same_stage_fixed_piop_earlier_readback
    {BaseWork : Type} [Fintype BaseWork] [DecidableEq BaseWork]
    (producer : Program ExistingProofFieldView)
    (ns : Namespace) (dsl : RelationDsl)
    (statement : SmzaRp05StatementNamespace.Statement) (pending : Bool)
    (nonce : Fin (2 ^ 32))
    (branch : Branches groupedDecode
      (producer.bind fun wire => verifierProgram ns dsl statement pending nonce wire))
    (_accepted : branchResult groupedDecode
      (producer.bind fun wire => verifierProgram ns dsl statement pending nonce wire)
      branch = some ())
    (database : Database (Key (producer.bind fun wire =>
      verifierProgram ns dsl statement pending nonce wire)) (VectorOutput GroupCounter))
    (claims : ClaimsDatabaseEvent
      (SmzaRp05PhysicalAcceptedReplayLite.branchClaims
        (SmzaRp05PhysicalAcceptedReplayLite.branchKeys
          (encode (producer.bind fun wire => verifierProgram ns dsl statement pending nonce wire))
          groupedDecode (producer.bind fun wire => verifierProgram ns dsl statement pending nonce wire) branch)
        (SmzaRp05PhysicalAcceptedReplayLite.branchAnswers
          (encode (producer.bind fun wire => verifierProgram ns dsl statement pending nonce wire))
          groupedDecode (producer.bind fun wire => verifierProgram ns dsl statement pending nonce wire) branch))
      database)
    [Fintype RawDigest] (fallback : RawDigest)
    (certificates : GeneratedCertificates dsl)
    (boundedModel : ModelWithinProtocol (relationModel dsl certificates))
    (role : Role) (roleIsPiop : role = .piopMatrix ∨ role = .piopOpening)
    (advice : AllEarlierTables (relationModel dsl certificates) role)
    (outerFuel innerFuel : Nat)
    (authorizedOf : BaseWork → Finset (List Byte))
    (blockCap : Role → Nat)
    (dummy : ActiveKey
      (currentGroupedContext (producer.bind fun wire =>
        verifierProgram ns dsl statement pending nonce wire)
        (relationModel dsl certificates) boundedModel ns role advice outerFuel innerFuel
        authorizedOf).role blockCap
      (currentGroupedContext (producer.bind fun wire =>
        verifierProgram ns dsl statement pending nonce wire)
        (relationModel dsl certificates) boundedModel ns role advice outerFuel innerFuel
        authorizedOf).keyBytes)
    (fixed : FixedTable
      (currentGroupedContext (producer.bind fun wire =>
        verifierProgram ns dsl statement pending nonce wire)
        (relationModel dsl certificates) boundedModel ns role advice outerFuel innerFuel
        authorizedOf) blockCap)
    (state : CmsState
      (Key := Key (producer.bind fun wire => verifierProgram ns dsl statement pending nonce wire))
      (Counter := GroupCounter) (BaseWork := BaseWork))
    (basis : Basis
      (ActiveKey
        (currentGroupedContext (producer.bind fun wire =>
          verifierProgram ns dsl statement pending nonce wire)
          (relationModel dsl certificates) boundedModel ns role advice outerFuel innerFuel
          authorizedOf).role blockCap
        (currentGroupedContext (producer.bind fun wire =>
          verifierProgram ns dsl statement pending nonce wire)
          (relationModel dsl certificates) boundedModel ns role advice outerFuel innerFuel
          authorizedOf).keyBytes)
      (VectorOutput GroupCounter) (VectorOutput GroupCounter)
      (ActiveMemory (currentGroupedContext (producer.bind fun wire =>
        verifierProgram ns dsl statement pending nonce wire)
        (relationModel dsl certificates) boundedModel ns role advice outerFuel innerFuel
        authorizedOf)))
    (nonzero : fixedFiberToActive
      (currentGroupedContext (producer.bind fun wire =>
        verifierProgram ns dsl statement pending nonce wire)
        (relationModel dsl certificates) boundedModel ns role advice outerFuel innerFuel
        authorizedOf) blockCap dummy fixed
      (otherRoleTransform
        (currentGroupedContext (producer.bind fun wire =>
          verifierProgram ns dsl statement pending nonce wire)
          (relationModel dsl certificates) boundedModel ns role advice outerFuel innerFuel
          authorizedOf) blockCap
        (SmzaRp05PhysicalAcceptedReplayLite.physicalRun
          (encode (producer.bind fun wire => verifierProgram ns dsl statement pending nonce wire))
          groupedDecode (producer.bind fun wire => verifierProgram ns dsl statement pending nonce wire)
          branch state)) basis ≠ 0)
    (positiveDecsMatrixCap : 0 < blockCap .decsMatrix)
    (positivePiopMatrixCap : 0 < blockCap .piopMatrix)
    (wire : ExistingProofFieldView)
    (producerSuccess : producer.eval
      (finiteGroupedDatabaseOracle
        (producer.bind fun wire => verifierProgram ns dsl statement pending nonce wire)
        database fallback) = some wire)
    (verifierAccepted : (verifierProgram ns dsl statement pending nonce wire).eval
      (finiteGroupedDatabaseOracle
        (producer.bind fun wire => verifierProgram ns dsl statement pending nonce wire)
        database fallback) = some ())
    (transcript : ReconstructedTranscript)
    (transcriptSuccess : (transcriptProgram ns dsl statement pending statement.toBytes
      (statementBindingWords statement) nonce wire).eval
        (finiteGroupedDatabaseOracle
          (producer.bind fun wire => verifierProgram ns dsl statement pending nonce wire)
          database fallback) = some transcript)
    (execution : ExecutionStages ns dsl statement pending statement.toBytes
      (statementBindingWords statement) nonce wire
      (finiteGroupedDatabaseOracle
        (producer.bind fun wire => verifierProgram ns dsl statement pending nonce wire)
        database fallback) transcript)
    (pcs : PcsStages ns execution.openingPending wire.hPiop
      (SmzaRp05PcsToFinalProgram.sameProofRows execution.middle.pcs execution.piop)
      execution.decs
      (List.ofFn fun j : Fin 6 => V8Smz9PiopReconstruction.points execution.opening j)
      wire.salt statement.toBytes (statementBindingWords statement) wire.tapes wire.paths
      (finiteGroupedDatabaseOracle
        (producer.bind fun wire => verifierProgram ns dsl statement pending nonce wire)
        database fallback) execution.hashFpp execution.pcsPending)
    {leafNs : Namespace} {trace : SmzaRp05TracePrefixes.Trace}
    (messages : CausalPayloads leafNs trace)
    (_decsDigest : V8SmzaOracleParser.digestAt messages.decs.bytes 0 = wire.hPiop)
    (fppDigest : V8SmzaOracleParser.digestAt messages.fpp.bytes 0 = pcs.post.root)
    (piopDigest : V8SmzaOracleParser.digestAt messages.piop.bytes 0 = execution.hashFpp)
    (oracleEarlier : EarlierReadback
      (relationModel dsl certificates) statement
      (fun selected => currentOracleAllAdvice (relationModel dsl certificates)
        (finiteGroupedDatabaseOracle
          (producer.bind fun wire => verifierProgram ns dsl statement pending nonce wire)
          database fallback) selected statement)
      messages
      (SmzaRp05CurrentAcceptedQuerySupport.sampledCoefficients
        (SmzaRp05PcsHashFppMiddle.gammaRows pcs.post))
      execution.matrix execution.opening) :
    EarlierReadback (relationModel dsl certificates) statement
      (fixedEarlierFamilyAtModel
        (currentGroupedContext (producer.bind fun wire =>
          verifierProgram ns dsl statement pending nonce wire)
          (relationModel dsl certificates) boundedModel ns role advice outerFuel innerFuel
          authorizedOf)
        blockCap fixed
        (finiteGroupedDatabaseOracle
          (producer.bind fun wire => verifierProgram ns dsl statement pending nonce wire)
          database fallback)
        statement (relationModel dsl certificates) (by rfl))
      messages
      (SmzaRp05CurrentAcceptedQuerySupport.sampledCoefficients
        (SmzaRp05PcsHashFppMiddle.gammaRows pcs.post))
      execution.matrix execution.opening := by
  rcases roleIsPiop with rfl | rfl
  · let role : Role := Role.piopMatrix
    classical
    let model := relationModel dsl certificates
    let program := producer.bind fun wire => verifierProgram ns dsl statement pending nonce wire
    let oracle := finiteGroupedDatabaseOracle
      (producer.bind fun wire => verifierProgram ns dsl statement pending nonce wire)
      database fallback
    let ctx := currentGroupedContext program model boundedModel ns role advice
      outerFuel innerFuel authorizedOf
    have ctxModel : ctx.model = model := rfl
    have ctxRole : ctx.role = role := rfl
    have decsCall := same_stage_decs_counter_zero_decodes producer ns dsl statement pending
      nonce branch database claims fallback model boundedModel wire transcript execution
      producerSuccess pcs verifierAccepted transcriptSuccess
    obtain ⟨_branchOk, decsVector, decsRecorded, _actualDecs⟩ := decsCall
    let decsInput := counterInput decsCoefficientDomain pcs.post.root 0
    have decsCallRecorded : (decsInput, decsVector) ∈ answerLog groupedDecode program branch := by
      simpa only [decsInput] using decsRecorded
    let decsQuery : StageQuery := ⟨.decsMatrix, pcs.post.root, 0, 0⟩
    have decsTarget := recorded_decs_call_has_grouped_target program branch
      (decsInput, decsVector) decsCallRecorded pcs.post.root ⟨0, by decide⟩ rfl
    rcases decsTarget with ⟨_decsPrefix, decsKey, decsRepresentative, _decsTarget⟩
    have decsParsed : parseStageQuery (ctx.keyBytes (encode program decsInput)) =
        some decsQuery := by
      change parseStageQuery (groupRepresentative (included program (encode program decsInput))) = _
      rw [decsKey]
      simpa only [decsQuery] using decsRepresentative
    have fixedDecs := current_decs_fixed_advice_matches_same_branch_source
      program model boundedModel ns role advice outerFuel innerFuel authorizedOf blockCap dummy
      fixed branch state basis nonzero database fallback claims (decsInput, decsVector)
      decsCallRecorded statement decsQuery decsParsed rfl
      (by simp [role])
      positiveDecsMatrixCap rfl
    have fixedDecsCell : currentFixedAdvice ctx blockCap fixed statement .decsMatrix
        (by
          change SmzaRp05TracePrefixes.roleOrder .decsMatrix <
            SmzaRp05TracePrefixes.roleOrder .piopMatrix
          decide)
        (V8SmzaOracleParser.digestAt messages.fpp.bytes 0) =
          some (SmzaRp05CurrentAcceptedQuerySupport.sampledCoefficients
            (SmzaRp05PcsHashFppMiddle.gammaRows pcs.post)) := by
      rw [fppDigest]
      change currentFixedVectorDecodedAt ctx blockCap fixed statement .decsMatrix
        pcs.post.root 0 = _
      rw [fixedDecs]
      change currentOracleDecodedAt model oracle statement .decsMatrix pcs.post.root = _
      simpa only [model, currentOracleAllAdvice, currentOracleDecodedAt, fppDigest] using
        oracleEarlier.sampleCoefficients
    obtain ⟨acceptedTranscript, acceptedTranscriptSuccess, transcriptClean,
        _finalEq, _finalCall⟩ :=
      SmzaRp05ExecutablePcsClosure.accepted_execution_constructs_transcript ns dsl
        statement pending statement.toBytes (statementBindingWords statement) nonce wire oracle
        verifierAccepted
    have sameTranscript : acceptedTranscript = transcript :=
      Option.some.inj (acceptedTranscriptSuccess.symm.trans transcriptSuccess)
    have suppliedTranscriptClean : transcript.pendingXofFailure = false := by
      rw [← sameTranscript]
      exact transcriptClean
    let piopInput := counterInput piopCoefficientDomain execution.hashFpp 0
    obtain ⟨piopVector, piopRecorded, _actualMatrix⟩ :=
      accepted_matrix_call_and_vector producer ns dsl statement pending nonce branch database
        claims fallback wire producerSuccess transcript transcriptSuccess execution pcs
        suppliedTranscriptClean certificates boundedModel
    let piopCall : RawInput × VectorOutput GroupCounter := (piopInput, piopVector)
    have piopCallRecorded : piopCall ∈ answerLog groupedDecode program branch := by
      simpa only [piopCall, piopInput] using piopRecorded
    have piopParsedRep := matrix_call_representative_parses program branch piopCall
      piopCallRecorded execution.hashFpp rfl
    have piopParsed : parseStageQuery (ctx.keyBytes (encode program piopInput)) =
        some (⟨.piopMatrix, execution.hashFpp, 0, 0⟩ : StageQuery) := by
      change parseStageQuery (groupRepresentative (included program (encode program piopInput))) = _
      simpa only [piopCall, piopInput] using piopParsedRep
    let adviceFamily := fixedEarlierFamilyAtModel ctx blockCap fixed oracle statement model ctxModel
    let adviceFamily := fixedEarlierFamilyAtModel ctx blockCap fixed oracle statement model ctxModel
    refine ⟨?_, ?_, ?_, ?_, ?_⟩
    · have sameAdvice : adviceFamily .piopMatrix =
          currentFixedAdvice ctx blockCap fixed statement := by
        dsimp [adviceFamily, fixedEarlierFamilyAtModel]
        change currentFixedEarlierAdviceFamily ctx blockCap fixed oracle ctx.role statement = _
        rw [currentFixedEarlierAdviceFamily_active]
      change adviceFamily .piopMatrix .decsMatrix _ _ = _
      rw [sameAdvice]
      exact fixedDecsCell
    · have notActive : .piopOpening ≠ ctx.role := by rw [ctxRole]; decide
      have sameAdvice : adviceFamily .piopOpening =
          currentOracleAllAdvice model oracle .piopOpening statement := by
        dsimp [adviceFamily, fixedEarlierFamilyAtModel]
        rw [currentFixedEarlierAdviceFamily_other ctx blockCap fixed oracle
          .piopOpening notActive]
        rfl
      change adviceFamily .piopOpening .decsMatrix _ _ = _
      rw [sameAdvice]
      exact oracleEarlier.openingCoefficients
    · have notActive : .piopOpening ≠ ctx.role := by rw [ctxRole]; decide
      have sameAdvice : adviceFamily .piopOpening =
          currentOracleAllAdvice model oracle .piopOpening statement := by
        dsimp [adviceFamily, fixedEarlierFamilyAtModel]
        rw [currentFixedEarlierAdviceFamily_other ctx blockCap fixed oracle
          .piopOpening notActive]
        rfl
      change adviceFamily .piopOpening .piopMatrix _ _ = _
      rw [sameAdvice]
      exact oracleEarlier.openingMatrix
    · have notActive : .decsSample ≠ ctx.role := by rw [ctxRole]; decide
      have sameAdvice : adviceFamily .decsSample =
          currentOracleAllAdvice model oracle .decsSample statement := by
        dsimp [adviceFamily, fixedEarlierFamilyAtModel]
        rw [currentFixedEarlierAdviceFamily_other ctx blockCap fixed oracle
          .decsSample notActive]
        rfl
      change adviceFamily .decsSample .decsMatrix _ _ = _
      rw [sameAdvice]
      exact oracleEarlier.sampleCoefficients
    · have notActive : .decsSample ≠ ctx.role := by rw [ctxRole]; decide
      have sameAdvice : adviceFamily .decsSample =
          currentOracleAllAdvice model oracle .decsSample statement := by
        dsimp [adviceFamily, fixedEarlierFamilyAtModel]
        rw [currentFixedEarlierAdviceFamily_other ctx blockCap fixed oracle
          .decsSample notActive]
        rfl
      change adviceFamily .decsSample .piopOpening _ _ = _
      rw [sameAdvice]
      exact oracleEarlier.sampleOpening
  · let role : Role := Role.piopOpening
    classical
    let model := relationModel dsl certificates
    let program := producer.bind fun wire => verifierProgram ns dsl statement pending nonce wire
    let oracle := finiteGroupedDatabaseOracle
      (producer.bind fun wire => verifierProgram ns dsl statement pending nonce wire)
      database fallback
    let ctx := currentGroupedContext program model boundedModel ns role advice
      outerFuel innerFuel authorizedOf
    have ctxModel : ctx.model = model := rfl
    have ctxRole : ctx.role = role := rfl
    have decsCall := same_stage_decs_counter_zero_decodes producer ns dsl statement pending
      nonce branch database claims fallback model boundedModel wire transcript execution
      producerSuccess pcs verifierAccepted transcriptSuccess
    obtain ⟨_branchOk, decsVector, decsRecorded, _actualDecs⟩ := decsCall
    let decsInput := counterInput decsCoefficientDomain pcs.post.root 0
    have decsCallRecorded : (decsInput, decsVector) ∈ answerLog groupedDecode program branch := by
      simpa only [decsInput] using decsRecorded
    let decsQuery : StageQuery := ⟨.decsMatrix, pcs.post.root, 0, 0⟩
    have decsTarget := recorded_decs_call_has_grouped_target program branch
      (decsInput, decsVector) decsCallRecorded pcs.post.root ⟨0, by decide⟩ rfl
    rcases decsTarget with ⟨_decsPrefix, decsKey, decsRepresentative, _decsTarget⟩
    have decsParsed : parseStageQuery (ctx.keyBytes (encode program decsInput)) =
        some decsQuery := by
      change parseStageQuery (groupRepresentative (included program (encode program decsInput))) = _
      rw [decsKey]
      simpa only [decsQuery] using decsRepresentative
    have fixedDecs := current_decs_fixed_advice_matches_same_branch_source
      program model boundedModel ns role advice outerFuel innerFuel authorizedOf blockCap dummy
      fixed branch state basis nonzero database fallback claims (decsInput, decsVector)
      decsCallRecorded statement decsQuery decsParsed rfl
      (by simp [role])
      positiveDecsMatrixCap rfl
    have fixedDecsCell : currentFixedAdvice ctx blockCap fixed statement .decsMatrix
        (by
          change SmzaRp05TracePrefixes.roleOrder .decsMatrix <
            SmzaRp05TracePrefixes.roleOrder .piopOpening
          decide)
        (V8SmzaOracleParser.digestAt messages.fpp.bytes 0) =
          some (SmzaRp05CurrentAcceptedQuerySupport.sampledCoefficients
            (SmzaRp05PcsHashFppMiddle.gammaRows pcs.post)) := by
      rw [fppDigest]
      change currentFixedVectorDecodedAt ctx blockCap fixed statement .decsMatrix
        pcs.post.root 0 = _
      rw [fixedDecs]
      change currentOracleDecodedAt model oracle statement .decsMatrix pcs.post.root = _
      simpa only [model, currentOracleAllAdvice, currentOracleDecodedAt, fppDigest] using
        oracleEarlier.sampleCoefficients
    obtain ⟨acceptedTranscript, acceptedTranscriptSuccess, transcriptClean,
        _finalEq, _finalCall⟩ :=
      SmzaRp05ExecutablePcsClosure.accepted_execution_constructs_transcript ns dsl
        statement pending statement.toBytes (statementBindingWords statement) nonce wire oracle
        verifierAccepted
    have sameTranscript : acceptedTranscript = transcript :=
      Option.some.inj (acceptedTranscriptSuccess.symm.trans transcriptSuccess)
    have suppliedTranscriptClean : transcript.pendingXofFailure = false := by
      rw [← sameTranscript]
      exact transcriptClean
    let piopInput := counterInput piopCoefficientDomain execution.hashFpp 0
    obtain ⟨piopVector, piopRecorded, _actualMatrix⟩ :=
      accepted_matrix_call_and_vector producer ns dsl statement pending nonce branch database
        claims fallback wire producerSuccess transcript transcriptSuccess execution pcs
        suppliedTranscriptClean certificates boundedModel
    let piopCall : RawInput × VectorOutput GroupCounter := (piopInput, piopVector)
    have piopCallRecorded : piopCall ∈ answerLog groupedDecode program branch := by
      simpa only [piopCall, piopInput] using piopRecorded
    have piopParsedRep := matrix_call_representative_parses program branch piopCall
      piopCallRecorded execution.hashFpp rfl
    have piopParsed : parseStageQuery (ctx.keyBytes (encode program piopInput)) =
        some (⟨.piopMatrix, execution.hashFpp, 0, 0⟩ : StageQuery) := by
      change parseStageQuery (groupRepresentative (included program (encode program piopInput))) = _
      simpa only [piopCall, piopInput] using piopParsedRep
    let adviceFamily := fixedEarlierFamilyAtModel ctx blockCap fixed oracle statement model ctxModel
    let adviceFamily := fixedEarlierFamilyAtModel ctx blockCap fixed oracle statement model ctxModel
    refine ⟨?_, ?_, ?_, ?_, ?_⟩
    · have notActive : .piopMatrix ≠ ctx.role := by rw [ctxRole]; decide
      have sameAdvice : adviceFamily .piopMatrix =
          currentOracleAllAdvice model oracle .piopMatrix statement := by
        dsimp [adviceFamily, fixedEarlierFamilyAtModel]
        rw [currentFixedEarlierAdviceFamily_other ctx blockCap fixed oracle
          .piopMatrix notActive]
        rfl
      change adviceFamily .piopMatrix .decsMatrix _ _ = _
      rw [sameAdvice]
      exact oracleEarlier.matrixCoefficients
    · have sameAdvice : adviceFamily .piopOpening =
          currentFixedAdvice ctx blockCap fixed statement := by
        dsimp [adviceFamily, fixedEarlierFamilyAtModel]
        change currentFixedEarlierAdviceFamily ctx blockCap fixed oracle ctx.role statement = _
        rw [currentFixedEarlierAdviceFamily_active]
      change adviceFamily .piopOpening .decsMatrix _ _ = _
      rw [sameAdvice]
      exact fixedDecsCell
    · have sameAdvice : adviceFamily .piopOpening =
          currentFixedAdvice ctx blockCap fixed statement := by
        dsimp [adviceFamily, fixedEarlierFamilyAtModel]
        change currentFixedEarlierAdviceFamily ctx blockCap fixed oracle ctx.role statement = _
        rw [currentFixedEarlierAdviceFamily_active]
      have oracleOpeningMatrix := oracleEarlier.openingMatrix
      rw [piopDigest] at oracleOpeningMatrix
      have fixedPiopMatrix := current_piop_matrix_fixed_advice_matches_same_branch_source
        program model boundedModel ns role advice outerFuel innerFuel authorizedOf blockCap dummy
        fixed branch state basis nonzero database fallback claims piopCall piopCallRecorded
        statement ⟨.piopMatrix, execution.hashFpp, 0, 0⟩ piopParsed rfl
        (by
          change Role.piopMatrix ≠ Role.piopOpening
          decide) positivePiopMatrixCap rfl
      have fixedPiopMatrixCell : currentFixedAdvice ctx blockCap fixed statement .piopMatrix
          (by
            change SmzaRp05TracePrefixes.roleOrder .piopMatrix <
              SmzaRp05TracePrefixes.roleOrder .piopOpening
            decide) (V8SmzaOracleParser.digestAt messages.piop.bytes 0) =
            some execution.matrix := by
        rw [piopDigest]
        change currentFixedVectorDecodedAt ctx blockCap fixed statement .piopMatrix
          execution.hashFpp 0 = some execution.matrix
        rw [fixedPiopMatrix]
        change currentOracleAllAdvice (relationModel dsl certificates)
          (finiteGroupedDatabaseOracle
            (producer.bind fun wire => verifierProgram ns dsl statement pending nonce wire)
            database fallback)
          .piopOpening statement .piopMatrix (by decide) execution.hashFpp = _
        exact oracleOpeningMatrix
      change adviceFamily .piopOpening .piopMatrix _ _ = _
      rw [sameAdvice]
      exact fixedPiopMatrixCell
    · have notActive : .decsSample ≠ ctx.role := by rw [ctxRole]; decide
      have sameAdvice : adviceFamily .decsSample =
          currentOracleAllAdvice model oracle .decsSample statement := by
        dsimp [adviceFamily, fixedEarlierFamilyAtModel]
        rw [currentFixedEarlierAdviceFamily_other ctx blockCap fixed oracle
          .decsSample notActive]
        rfl
      change adviceFamily .decsSample .decsMatrix _ _ = _
      rw [sameAdvice]
      exact oracleEarlier.sampleCoefficients
    · have notActive : .decsSample ≠ ctx.role := by rw [ctxRole]; decide
      have sameAdvice : adviceFamily .decsSample =
          currentOracleAllAdvice model oracle .decsSample statement := by
        dsimp [adviceFamily, fixedEarlierFamilyAtModel]
        rw [currentFixedEarlierAdviceFamily_other ctx blockCap fixed oracle
          .decsSample notActive]
        rfl
      change adviceFamily .decsSample .piopOpening _ _ = _
      rw [sameAdvice]
      exact oracleEarlier.sampleOpening


end
end HegemonCrypto.SmallWood.SmzaRp05CurrentAcceptedFixedEarlierPiopCells
