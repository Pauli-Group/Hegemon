import SmzaRp05CurrentAcceptedFixedEarlierReadback
import SmzaRp05CurrentFixedAdviceOpeningScan
import SmzaRp05CurrentFixedAdviceDecsSource
import SmzaRp05CurrentAcceptedDecsOutputBinding
import SmzaRp05CurrentAcceptedPiopRecordedOutputs
import SmzaRp05CurrentAcceptedEarlierAdvice
import SmzaRp05CurrentAcceptedDecsOutputBinding
import SmzaRp05CurrentDecsGroupedTarget
import SmzaRp05CurrentGroupedRoutes
import SmzaRp05TracePrefixes
import SmzaRp05AcceptedRoleLabels

/-! # Fixed earlier-cell readback on one accepted execution

These adapters retain the supplied accepted execution and PCS stages. The
DECS-matrix readback uses the actual counter-zero call at that PCS root; the
PIOP-opening readback replays the entire canonical nonce scan on the same
branch, including failed earlier nonces.
-/

namespace HegemonCrypto.SmallWood.SmzaRp05CurrentAcceptedFixedEarlierCells

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
    (producer : Program ExistingProofFieldView)
    (ns : Namespace) (dsl : RelationDsl)
    (statement : SmzaRp05StatementNamespace.Statement) (pending : Bool)
    (nonce : Fin (2 ^ 32))
    (branch : Branches groupedDecode
      (CurrentVerifierProgram producer ns dsl statement pending nonce))
    (_accepted : branchResult groupedDecode
      (CurrentVerifierProgram producer ns dsl statement pending nonce) branch = some ())
    (database : Database (Key (CurrentVerifierProgram producer ns dsl statement pending nonce))
      (VectorOutput GroupCounter))
    (claims : ClaimsDatabaseEvent
      (SmzaRp05PhysicalAcceptedReplayLite.branchClaims
        (SmzaRp05PhysicalAcceptedReplayLite.branchKeys
          (encode (CurrentVerifierProgram producer ns dsl statement pending nonce))
          groupedDecode (CurrentVerifierProgram producer ns dsl statement pending nonce) branch)
        (SmzaRp05PhysicalAcceptedReplayLite.branchAnswers
          (encode (CurrentVerifierProgram producer ns dsl statement pending nonce))
          groupedDecode (CurrentVerifierProgram producer ns dsl statement pending nonce) branch))
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
      (currentGroupedContext (CurrentVerifierProgram producer ns dsl statement pending nonce)
        (SmzaRp05RelationRefinement.relationModel dsl certificates) boundedModel ns
        .decsSample advice outerFuel innerFuel authorizedOf).role blockCap
      (currentGroupedContext (CurrentVerifierProgram producer ns dsl statement pending nonce)
        (SmzaRp05RelationRefinement.relationModel dsl certificates) boundedModel ns
        .decsSample advice outerFuel innerFuel authorizedOf).keyBytes)
    (fixed : FixedTable
      (currentGroupedContext (CurrentVerifierProgram producer ns dsl statement pending nonce)
        (SmzaRp05RelationRefinement.relationModel dsl certificates) boundedModel ns
        .decsSample advice outerFuel innerFuel authorizedOf) blockCap)
    (state : CmsState
      (Key := Key (CurrentVerifierProgram producer ns dsl statement pending nonce))
      (Counter := GroupCounter) (BaseWork := BaseWork))
    (basis : Basis
      (ActiveKey
        (currentGroupedContext (CurrentVerifierProgram producer ns dsl statement pending nonce)
          (SmzaRp05RelationRefinement.relationModel dsl certificates) boundedModel ns
          .decsSample advice outerFuel innerFuel authorizedOf).role blockCap
        (currentGroupedContext (CurrentVerifierProgram producer ns dsl statement pending nonce)
          (SmzaRp05RelationRefinement.relationModel dsl certificates) boundedModel ns
          .decsSample advice outerFuel innerFuel authorizedOf).keyBytes)
      (VectorOutput GroupCounter) (VectorOutput GroupCounter)
      (ActiveMemory
        (currentGroupedContext (CurrentVerifierProgram producer ns dsl statement pending nonce)
        (SmzaRp05RelationRefinement.relationModel dsl certificates) boundedModel ns
        .decsSample advice outerFuel innerFuel authorizedOf)))
    (nonzero : SmzaRp05ConditionedExecution.fixedFiberToActive
      (currentGroupedContext (CurrentVerifierProgram producer ns dsl statement pending nonce)
        (SmzaRp05RelationRefinement.relationModel dsl certificates) boundedModel ns
        .decsSample advice outerFuel innerFuel authorizedOf)
      blockCap dummy fixed
      (SmzaRp05ConditionedExecution.otherRoleTransform
        (currentGroupedContext (CurrentVerifierProgram producer ns dsl statement pending nonce)
          (SmzaRp05RelationRefinement.relationModel dsl certificates) boundedModel ns
          .decsSample advice outerFuel innerFuel authorizedOf)
        blockCap (SmzaRp05PhysicalAcceptedReplayLite.physicalRun
          (encode (CurrentVerifierProgram producer ns dsl statement pending nonce))
          groupedDecode (CurrentVerifierProgram producer ns dsl statement pending nonce)
          branch state)) basis ≠ 0)
    (positiveDecsMatrixCap : 0 < blockCap .decsMatrix)
    (wire : ExistingProofFieldView)
    (producerSuccess : producer.eval
      (finiteGroupedDatabaseOracle
        (CurrentVerifierProgram producer ns dsl statement pending nonce) database fallback) =
          some wire)
    (verifierAccepted : (verifierProgram ns dsl statement pending nonce wire).eval
      (finiteGroupedDatabaseOracle
        (CurrentVerifierProgram producer ns dsl statement pending nonce) database fallback) =
          some ())
    (transcript : ReconstructedTranscript)
    (transcriptSuccess : (transcriptProgram ns dsl statement pending statement.toBytes
      (statementBindingWords statement) nonce wire).eval
        (finiteGroupedDatabaseOracle
          (CurrentVerifierProgram producer ns dsl statement pending nonce) database fallback) =
            some transcript)
    (execution : ExecutionStages ns dsl statement pending statement.toBytes
      (statementBindingWords statement) nonce wire
      (finiteGroupedDatabaseOracle
        (CurrentVerifierProgram producer ns dsl statement pending nonce) database fallback)
      transcript)
    (pcs : PcsStages ns execution.openingPending wire.hPiop
      (SmzaRp05PcsToFinalProgram.sameProofRows execution.middle.pcs execution.piop)
      execution.decs
      (List.ofFn fun j : Fin 6 => V8Smz9PiopReconstruction.points execution.opening j)
      wire.salt statement.toBytes (statementBindingWords statement)
      wire.tapes wire.paths
      (finiteGroupedDatabaseOracle
        (CurrentVerifierProgram producer ns dsl statement pending nonce) database fallback)
      execution.hashFpp execution.pcsPending)
    (fixedOpening : fixedCanonicalOpeningAt
      (currentGroupedContext (CurrentVerifierProgram producer ns dsl statement pending nonce)
        (SmzaRp05RelationRefinement.relationModel dsl certificates) boundedModel ns
        .decsSample advice outerFuel innerFuel authorizedOf)
      blockCap fixed statement wire.hPiop = some execution.opening)
    {leafNs : Namespace} {trace : SmzaRp05TracePrefixes.Trace}
    (messages : CausalPayloads leafNs trace)
    (decsDigest : V8SmzaOracleParser.digestAt messages.decs.bytes 0 = wire.hPiop)
    (fppDigest : V8SmzaOracleParser.digestAt messages.fpp.bytes 0 = pcs.post.root)
    (oracleEarlier : EarlierReadback
      (SmzaRp05RelationRefinement.relationModel dsl certificates) statement
      (fun selected => currentOracleAllAdvice
        (SmzaRp05RelationRefinement.relationModel dsl certificates)
        (finiteGroupedDatabaseOracle
          (CurrentVerifierProgram producer ns dsl statement pending nonce) database fallback)
        selected statement)
      messages
      (SmzaRp05CurrentAcceptedQuerySupport.sampledCoefficients
        (SmzaRp05PcsHashFppMiddle.gammaRows pcs.post))
      execution.matrix execution.opening) :
    EarlierReadback (SmzaRp05RelationRefinement.relationModel dsl certificates) statement
      (fixedEarlierFamilyAtModel
        (currentGroupedContext (CurrentVerifierProgram producer ns dsl statement pending nonce)
          (SmzaRp05RelationRefinement.relationModel dsl certificates) boundedModel ns
          .decsSample advice outerFuel innerFuel authorizedOf)
        blockCap fixed
        (finiteGroupedDatabaseOracle
          (CurrentVerifierProgram producer ns dsl statement pending nonce) database fallback)
        statement (SmzaRp05RelationRefinement.relationModel dsl certificates) (by rfl))
      messages
      (SmzaRp05CurrentAcceptedQuerySupport.sampledCoefficients
        (SmzaRp05PcsHashFppMiddle.gammaRows pcs.post))
      execution.matrix execution.opening := by
  classical
  let model := SmzaRp05RelationRefinement.relationModel dsl certificates
  let program := CurrentVerifierProgram producer ns dsl statement pending nonce
  let oracle := finiteGroupedDatabaseOracle program database fallback
  let ctx := currentGroupedContext program model boundedModel ns .decsSample advice
    outerFuel innerFuel authorizedOf
  have ctxModel : ctx.model = model := rfl
  have ctxRole : ctx.role = .decsSample := rfl
  have decsCall := same_stage_decs_counter_zero_decodes producer ns dsl statement pending
    nonce branch database claims fallback model boundedModel wire transcript execution
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
    callRecorded statement query parsed rfl (by decide) positiveDecsMatrixCap rfl
  have fixedDecsCell : currentFixedAdvice ctx blockCap fixed statement .decsMatrix
      (by change SmzaRp05TracePrefixes.roleOrder .decsMatrix <
        SmzaRp05TracePrefixes.roleOrder .decsSample; decide)
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
  have fixedOpeningCell : currentFixedAdvice ctx blockCap fixed statement .piopOpening
      (by change SmzaRp05TracePrefixes.roleOrder .piopOpening <
        SmzaRp05TracePrefixes.roleOrder .decsSample; decide)
      (V8SmzaOracleParser.digestAt messages.decs.bytes 0) =
        some execution.opening := by
    rw [decsDigest]
    simpa [currentFixedAdvice, currentFixedDecodedAt] using fixedOpening
  let adviceFamily := fixedEarlierFamilyAtModel ctx blockCap fixed oracle statement model ctxModel
  refine ⟨?_, ?_, ?_, ?_, ?_⟩
  · have notActive : SmzaChallengeStageTargets.Role.piopMatrix ≠ ctx.role := by
      rw [ctxRole]
      decide
    have sameAdvice : adviceFamily .piopMatrix =
        currentOracleAllAdvice model oracle .piopMatrix statement := by
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
        currentOracleAllAdvice model oracle .piopOpening statement := by
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
        currentOracleAllAdvice model oracle .piopOpening statement := by
      dsimp [adviceFamily, fixedEarlierFamilyAtModel]
      rw [currentFixedEarlierAdviceFamily_other ctx blockCap fixed oracle
        .piopOpening notActive]
      rfl
    change adviceFamily .piopOpening .piopMatrix _ _ = _
    rw [sameAdvice]
    exact oracleEarlier.openingMatrix
  · have sameAdvice : adviceFamily .decsSample =
        currentFixedAdvice ctx blockCap fixed statement := by
      dsimp [adviceFamily, fixedEarlierFamilyAtModel]
      change currentFixedEarlierAdviceFamily ctx blockCap fixed oracle ctx.role statement = _
      rw [currentFixedEarlierAdviceFamily_active]
    change adviceFamily .decsSample .decsMatrix _ _ = _
    rw [sameAdvice]
    exact fixedDecsCell
  · have sameAdvice : adviceFamily .decsSample =
        currentFixedAdvice ctx blockCap fixed statement := by
      dsimp [adviceFamily, fixedEarlierFamilyAtModel]
      change currentFixedEarlierAdviceFamily ctx blockCap fixed oracle ctx.role statement = _
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
    (producer : Program ExistingProofFieldView)
    (ns : Namespace) (dsl : RelationDsl)
    (statement : SmzaRp05StatementNamespace.Statement) (pending : Bool)
    (nonce : Fin (2 ^ 32))
    (branch : Branches groupedDecode
      (CurrentVerifierProgram producer ns dsl statement pending nonce))
    (_accepted : branchResult groupedDecode
      (CurrentVerifierProgram producer ns dsl statement pending nonce) branch = some ())
    (database : Database (Key (CurrentVerifierProgram producer ns dsl statement pending nonce))
      (VectorOutput GroupCounter))
    (claims : ClaimsDatabaseEvent
      (SmzaRp05PhysicalAcceptedReplayLite.branchClaims
        (SmzaRp05PhysicalAcceptedReplayLite.branchKeys
          (encode (CurrentVerifierProgram producer ns dsl statement pending nonce))
          groupedDecode (CurrentVerifierProgram producer ns dsl statement pending nonce) branch)
        (SmzaRp05PhysicalAcceptedReplayLite.branchAnswers
          (encode (CurrentVerifierProgram producer ns dsl statement pending nonce))
          groupedDecode (CurrentVerifierProgram producer ns dsl statement pending nonce) branch))
      database)
    (fallback : RawDigest)
    (model : RelationModel) (boundedModel : ModelWithinProtocol model)
    (role : SmzaChallengeStageTargets.Role)
    (advice : AllEarlierTables model role) (outerFuel innerFuel : Nat)
    (authorizedOf : BaseWork → Finset (List Byte))
    (blockCap : SmzaChallengeStageTargets.Role → Nat)
    (dummy : ActiveKey
      (currentGroupedContext (CurrentVerifierProgram producer ns dsl statement pending nonce)
        model boundedModel ns role advice outerFuel innerFuel authorizedOf).role blockCap
      (currentGroupedContext (CurrentVerifierProgram producer ns dsl statement pending nonce)
        model boundedModel ns role advice outerFuel innerFuel authorizedOf).keyBytes)
    (fixed : FixedTable
      (currentGroupedContext (CurrentVerifierProgram producer ns dsl statement pending nonce)
        model boundedModel ns role advice outerFuel innerFuel authorizedOf) blockCap)
    (state : CmsState
      (Key := Key (CurrentVerifierProgram producer ns dsl statement pending nonce))
      (Counter := GroupCounter) (BaseWork := BaseWork))
    (basis : Basis
      (ActiveKey
        (currentGroupedContext (CurrentVerifierProgram producer ns dsl statement pending nonce)
          model boundedModel ns role advice outerFuel innerFuel authorizedOf).role blockCap
        (currentGroupedContext (CurrentVerifierProgram producer ns dsl statement pending nonce)
          model boundedModel ns role advice outerFuel innerFuel authorizedOf).keyBytes)
      (VectorOutput GroupCounter) (VectorOutput GroupCounter)
      (ActiveMemory
        (currentGroupedContext (CurrentVerifierProgram producer ns dsl statement pending nonce)
          model boundedModel ns role advice outerFuel innerFuel authorizedOf)))
    (nonzero : SmzaRp05ConditionedExecution.fixedFiberToActive
      (currentGroupedContext (CurrentVerifierProgram producer ns dsl statement pending nonce)
        model boundedModel ns role advice outerFuel innerFuel authorizedOf)
      blockCap dummy fixed
      (SmzaRp05ConditionedExecution.otherRoleTransform
        (currentGroupedContext (CurrentVerifierProgram producer ns dsl statement pending nonce)
          model boundedModel ns role advice outerFuel innerFuel authorizedOf)
        blockCap (SmzaRp05PhysicalAcceptedReplayLite.physicalRun
          (encode (CurrentVerifierProgram producer ns dsl statement pending nonce))
          groupedDecode (CurrentVerifierProgram producer ns dsl statement pending nonce)
          branch state)) basis ≠ 0)
    (selectedRoleEarlier : .piopOpening ≠ role)
    (positiveOpeningCap : 0 < blockCap .piopOpening)
    (wire : ExistingProofFieldView)
    (producerSuccess : producer.eval
      (finiteGroupedDatabaseOracle
        (CurrentVerifierProgram producer ns dsl statement pending nonce) database fallback) =
          some wire)
    (verifierAccepted : (verifierProgram ns dsl statement pending nonce wire).eval
      (finiteGroupedDatabaseOracle
        (CurrentVerifierProgram producer ns dsl statement pending nonce) database fallback) =
          some ())
    (transcript : ReconstructedTranscript)
    (transcriptSuccess : (transcriptProgram ns dsl statement pending statement.toBytes
      (statementBindingWords statement) nonce wire).eval
        (finiteGroupedDatabaseOracle
          (CurrentVerifierProgram producer ns dsl statement pending nonce) database fallback) =
            some transcript)
    (execution : ExecutionStages ns dsl statement pending statement.toBytes
      (statementBindingWords statement) nonce wire
      (finiteGroupedDatabaseOracle
        (CurrentVerifierProgram producer ns dsl statement pending nonce) database fallback)
      transcript)
    (pcs : PcsStages ns execution.openingPending wire.hPiop
      (SmzaRp05PcsToFinalProgram.sameProofRows execution.middle.pcs execution.piop)
      execution.decs
      (List.ofFn fun j : Fin 6 => V8Smz9PiopReconstruction.points execution.opening j)
      wire.salt statement.toBytes (statementBindingWords statement)
      wire.tapes wire.paths
      (finiteGroupedDatabaseOracle
        (CurrentVerifierProgram producer ns dsl statement pending nonce) database fallback)
      execution.hashFpp execution.pcsPending) :
    fixedCanonicalOpeningAt
      (currentGroupedContext (CurrentVerifierProgram producer ns dsl statement pending nonce)
        model boundedModel ns role advice outerFuel innerFuel authorizedOf)
      blockCap fixed statement wire.hPiop = some execution.opening := by
  classical
  let program := CurrentVerifierProgram producer ns dsl statement pending nonce
  let oracle := finiteGroupedDatabaseOracle program database fallback
  let ctx := currentGroupedContext program model boundedModel ns role advice
    outerFuel innerFuel authorizedOf
  have recordEq := (actual_program_grouped_claims_replay_and_retain
    program branch database claims fallback).1
  obtain ⟨acceptedTranscript, acceptedTranscriptSuccess, transcriptClean,
      _finalEq, _finalCall⟩ :=
    SmzaRp05ExecutablePcsClosure.accepted_execution_constructs_transcript ns dsl statement
      pending statement.toBytes (statementBindingWords statement) nonce wire oracle
      verifierAccepted
  have sameTranscript : acceptedTranscript = transcript :=
    Option.some.inj (acceptedTranscriptSuccess.symm.trans transcriptSuccess)
  have suppliedTranscriptClean : transcript.pendingXofFailure = false := by
    rw [← sameTranscript]
    exact transcriptClean
  have stagesClean := SmzaRp05ExecutablePcsClosureSampling.execution_stages_clean_matrix
    ns dsl statement pending statement.toBytes (statementBindingWords statement) nonce wire oracle
    transcript execution suppliedTranscriptClean
  have openingClean := SmzaRp05ExecutablePcsClosureClean.pcs_stages_clean ns
    execution.openingPending wire.hPiop
    (SmzaRp05PcsToFinalProgram.sameProofRows execution.middle.pcs execution.piop)
    execution.decs
    (List.ofFn fun j : Fin 6 => V8Smz9PiopReconstruction.points execution.opening j)
    wire.salt statement.toBytes (statementBindingWords statement) wire.tapes wire.paths oracle
    execution.hashFpp execution.pcsPending pcs stagesClean.1
  have stagesOpeningSplit := execution_stages_current_raw_opening ns dsl statement pending
    statement.toBytes (statementBindingWords statement) nonce wire oracle transcript
    execution openingClean.1
  rcases stagesOpeningSplit with
    ⟨sourceBefore, sourceAfter, sourceOrder, sourcePrior, selectedDecoded, selected⟩
  obtain ⟨retainedBefore, retainedAfter, retainedOrder, failedCalls⟩ :=
    successful_canonical_opening_retains_failed_nonce_calls_in_verifier_record
      ns dsl statement pending nonce wire oracle transcript execution pcs openingClean.1
      transcriptSuccess
  have prefixEq := same_prefix_before_selected nonce.val
    sourceBefore sourceAfter retainedBefore retainedAfter
    (by rw [← sourceOrder]; exact List.nodup_range)
    (sourceOrder.symm.trans retainedOrder)
  have sourcePriorRetained : ∀ attempt ∈ retainedBefore,
      SmzaRp04RawRoleSampling.actualPiopOpeningOutput
        (Equiv.refl (Fin (V8Smz9RawCounterCompiler.digestCallCap
          V8Smz9AdaptiveFiniteAccounting.Historical.piopOpenings))).toEmbedding
        (SmzaRp05CurrentExecutedOpeningOutput.currentOpeningVector oracle wire.hPiop attempt) =
          none := by
    intro attempt member
    have memberSource : attempt ∈ sourceBefore := by simpa [prefixEq] using member
    exact executed_opening_decode_is_raw_output oracle wire.hPiop attempt none
      (sourcePrior attempt memberSource)
  have perNonceDecoder :
      ∀ (attemptIndex counter : Nat) (attemptBound : attemptIndex < 16)
      (counterBound : counter < 5)
      (recorded : (openingCounterInput wire.hPiop attemptIndex counter,
        oracle (openingCounterInput wire.hPiop attemptIndex counter)) ∈
          ((verifierProgram ns dsl statement pending nonce wire).record oracle).2),
      currentFixedVectorDecodedAt ctx blockCap fixed statement .piopOpening
        wire.hPiop attemptIndex =
      SmzaRp04RawRoleSampling.actualPiopOpeningOutput
        (Equiv.refl (Fin (V8Smz9RawCounterCompiler.digestCallCap
          V8Smz9AdaptiveFiniteAccounting.Historical.piopOpenings))).toEmbedding
        (SmzaRp05CurrentExecutedOpeningOutput.currentOpeningVector oracle wire.hPiop
          attemptIndex) := by
    intro attemptIndex counter attemptBound counterBound recorded
    let input := openingCounterInput wire.hPiop attemptIndex counter
    have verifierRecord := Program.record_bind_success oracle producer
      (fun actualWire => verifierProgram ns dsl statement pending nonce actualWire)
      wire producerSuccess
    have recordedCombined : (input, oracle input) ∈ (program.record oracle).2 := by
      rw [verifierRecord]
      exact List.mem_append.mpr (Or.inr recorded)
    obtain ⟨output, answerMember, _digestEq⟩ := verifier_record_pair_has_branch_answer
      (Key := Key program) (program := program) branch oracle recordEq input
      (oracle input) recordedCombined
    have keyEq := answer_log_group_keys_represented groupedDecode program branch
      (input, output) answerMember
    obtain ⟨rolePrefixValue, addressEq, representativeParsed, _encoded⟩ :=
      opening_counter_call_group_address wire.hPiop attemptIndex (by omega)
        ⟨counter, by rw [SmzaRp05GroupedSuffix.group_block_cap_eq]; omega⟩
    have groupEq : SmzaRp05GroupedSuffix.groupKeyOf input = Sum.inl rolePrefixValue := by
      change (SmzaRp05GroupedSuffix.groupAddress input).1 = _
      exact congrArg Prod.fst addressEq
    let query : StageQuery := ⟨.piopOpening, wire.hPiop, attemptIndex, 0⟩
    have parsed : parseStageQuery (ctx.keyBytes (encode program input)) = some query := by
      change parseStageQuery (groupRepresentative (included program (encode program input))) = _
      rw [keyEq, groupEq]
      exact representativeParsed
    have nonceDecoder := current_piop_opening_fixed_advice_matches_same_branch_source_nonce
      program model boundedModel ns role advice outerFuel innerFuel authorizedOf blockCap dummy
      fixed branch state basis nonzero database fallback claims (input, output) answerMember
      statement query parsed rfl selectedRoleEarlier positiveOpeningCap rfl
    simpa only [query] using nonceDecoder
  have fixedPrior : ∀ attempt ∈ retainedBefore,
      currentFixedVectorDecodedAt ctx blockCap fixed statement .piopOpening
        wire.hPiop attempt = none := by
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
      ns dsl statement pending nonce wire oracle transcript execution pcs openingClean.1
      transcriptSuccess
  obtain ⟨selectedCounter, selectedBound, selectedRecorded⟩ := selectedRetention
  have selectedBound16 : nonce.val < 16 := by
    have inRange : nonce.val ∈ List.range 16 := by
      rw [sourceOrder]
      exact List.mem_append.mpr (Or.inr (by simp))
    exact List.mem_range.mp inRange
  have selectedDecode := perNonceDecoder nonce.val selectedCounter selectedBound16
    selectedBound selectedRecorded
  have fixedSelected : currentFixedVectorDecodedAt ctx blockCap fixed statement
      .piopOpening wire.hPiop nonce.val = some execution.opening :=
    selectedDecode.trans selected
  have mappedOrder : canonicalOpeningNonceOrder.map Fin.val = List.range 16 := by
    change (List.ofFn (id : Fin 16 → Fin 16)).map Fin.val = _
    rw [List.map_ofFn]
    exact (ofFn_fin_val_eq_range_map id).trans (List.map_id _)
  have fixedScan : firstSome
      (fun attempt : Nat => currentFixedVectorDecodedAt ctx blockCap fixed statement
        .piopOpening wire.hPiop attempt) (List.range 16) = some execution.opening := by
    rw [retainedOrder]
    simpa only [SmzaRp05TracePrefixes.RoleOutput] using firstSome_append_selected
      (fun attempt : Nat => currentFixedVectorDecodedAt ctx blockCap fixed statement
        .piopOpening wire.hPiop attempt)
      retainedBefore retainedAfter nonce.val execution.opening fixedPrior fixedSelected
  have fixedCanonical : firstSome
      (fun index : Fin 16 => currentFixedVectorDecodedAt ctx blockCap fixed statement
        .piopOpening wire.hPiop index.val) canonicalOpeningNonceOrder =
          some execution.opening := by
    have mappedScan : firstSome
        (fun attempt : Nat => currentFixedVectorDecodedAt ctx blockCap fixed statement
          .piopOpening wire.hPiop attempt)
        (canonicalOpeningNonceOrder.map Fin.val) = some execution.opening := by
      simpa only [mappedOrder] using fixedScan
    simpa only [firstSome_map, SmzaRp05TracePrefixes.RoleOutput] using mappedScan
  simpa only [fixedCanonicalOpeningAt, currentFixedVectorDecodedAt,
    SmzaRp05TracePrefixes.RoleOutput] using fixedCanonical

end
end HegemonCrypto.SmallWood.SmzaRp05CurrentAcceptedFixedEarlierCells
