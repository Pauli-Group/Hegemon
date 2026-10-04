import SmzaRp05CurrentOpeningGroupIdentity
import SmzaRp05CurrentOpeningSelectedRetention
import SmzaRp05CurrentFixedAdvicePiopSource
import SmzaRp05CurrentFixedAdviceOpeningSource
import SmzaRp05CurrentCanonicalOpeningOutput
import SmzaRp05CurrentExecutedOpeningOutput
import SmzaRp05CurrentGroupedClaimRetention
import SmzaRp05CurrentFiniteGroupedProgram
import SmzaRp05CurrentGroupedVerifierReplay
import SmzaRp05ExecutablePcsClosureClean
import SmzaRp05ExecutablePcsClosureSampling
import SmzaRp05FinalProgramMiddleExecution

/-! The current fixed-table opening scan is the literal canonical first
success over the same accepted verifier branch. Per-nonce vector equality is
derived from raw calls retained by the executed opening attempts and grouped
claims; no prior-nonce vector, parser receipt, or run-equality is assumed. -/

namespace HegemonCrypto.SmallWood.SmzaRp05CurrentFixedAdviceOpeningScan

open scoped Classical
open SmzaRp05ConditionedExecution
  (FixedTable fixedCanonicalOpeningAt firstSome firstSome_append_selected
    canonicalOpeningNonceOrder)
open SmzaRp05CurrentFixedEarlierAdvice (currentFixedVectorDecodedAt)
open SmzaRp05CurrentFixedAdvicePiopSource
  (current_piop_opening_fixed_advice_matches_same_branch_source_nonce)
open SmzaRp05CurrentFixedAdviceOpeningSource
  (verifier_record_pair_has_branch_answer)
open SmzaRp05CurrentOpeningSelectedRetention
  (successful_canonical_opening_retains_selected_nonce_call_in_verifier_record)
open SmzaRp05CurrentOpeningAttemptRetention
  (successful_canonical_opening_retains_failed_nonce_calls_in_verifier_record)
open SmzaRp05CurrentOpeningGroupIdentity (opening_counter_call_group_address)
open SmzaRp05CurrentCanonicalOpeningOutput
  (executed_opening_decode_is_raw_output)
open SmzaRp05CurrentExecutedOpeningOutput (execution_stages_current_raw_opening)
open SmzaRp05CurrentGroupedClaimRetention
  (groupedDecode actual_program_grouped_claims_replay_and_retain)
open SmzaRp05CurrentFiniteGroupedProgram (Key encode included answer_log_group_keys_represented)
open SmzaRp05CurrentGroupedOracleVector (finiteGroupedDatabaseOracle)
open SmzaRp05CurrentGroupedContext (currentGroupedContext
  current_grouped_context_key_injective)
open SmzaRp05PhysicalAcceptedReplayLite (Branches branchResult)
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
open HegemonCrypto.CmsCompressedOracle (Basis)
open HegemonCrypto.CmsOracleDatabaseBridge (ClaimsDatabaseEvent)
open HegemonCrypto.FiniteOracleDatabase (Database)
open V8SmzaOracleParser (RawInput RawDigest)
open V8Smz9CoherentVectorMerkle (VectorOutput vectorOutputBytes)
open HegemonCrypto.CanonicalBytes (Byte)
open V8Smz9PiopSoundness (Opening)
open SmzaRp05CurrentOpeningProgram (openingCounterInput)
open SmzaRp05ExecutablePcsClosureStatement (verifierProgram)
open SmzaRp05CurrentGroupedClaimRetention (actual_program_grouped_claims_replay_and_retain)
open SmzaRp05CurrentFixedAdvicePiopSource
  (current_piop_opening_fixed_advice_matches_same_branch_source_nonce)
open SmzaRp05CurrentOpeningSelectedRetention
  (successful_canonical_opening_retains_selected_nonce_call_in_verifier_record)
open SmzaRp05CurrentOpeningAttemptRetention
  (successful_canonical_opening_retains_failed_nonce_calls_in_verifier_record)
open SmzaRp05CurrentOpeningGroupIdentity (opening_counter_call_group_address)
open SmzaRp05CurrentFiniteGroupedProgram (answer_log_group_keys_represented)
open SmzaRp05CurrentFixedAdviceOpeningSource (verifier_record_pair_has_branch_answer)

noncomputable section

abbrev CurrentVerifierProgram (producer : Program ExistingProofFieldView)
    (ns : Namespace) (dsl : RelationDsl)
    (statement : SmzaRp05StatementNamespace.Statement) (pending : Bool)
    (nonce : Fin (2 ^ 32)) :=
  producer.bind fun wire => verifierProgram ns dsl statement pending
    statement.toBytes (statementBindingWords statement) nonce wire

set_option autoImplicit false
set_option maxRecDepth 12000
set_option maxHeartbeats 1000000

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

/- The concrete bridge below starts from an accepted physical grouped branch.
The accepted producer/verifier execution supplies the wire and stages; the
fixed-table cells are then forced by the retained calls of that same run. -/

theorem accepted_current_fixed_opening_scan
    {BaseWork : Type} [Fintype BaseWork] [DecidableEq BaseWork]
    (producer : Program ExistingProofFieldView)
    (ns : Namespace) (dsl : RelationDsl)
    (statement : SmzaRp05StatementNamespace.Statement) (pending : Bool)
    (nonce : Fin (2 ^ 32))
    (branch : Branches groupedDecode (CurrentVerifierProgram producer ns dsl statement pending nonce))
    (accepted : branchResult groupedDecode
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
      (SmzaRp05ConditionedExecution.ActiveMemory
        (currentGroupedContext (CurrentVerifierProgram producer ns dsl statement pending nonce)
          model boundedModel ns role advice outerFuel innerFuel authorizedOf)))
    (nonzero : SmzaRp05ConditionedExecution.fixedFiberToActive
      (currentGroupedContext (CurrentVerifierProgram producer ns dsl statement pending nonce)
        model boundedModel ns role advice outerFuel innerFuel authorizedOf)
      blockCap dummy fixed
      (SmzaRp05ConditionedExecution.otherRoleTransform
        (currentGroupedContext (CurrentVerifierProgram producer ns dsl statement pending nonce)
          model boundedModel ns role advice outerFuel innerFuel authorizedOf)
        blockCap
        (SmzaRp05PhysicalAcceptedReplayLite.physicalRun
          (encode (CurrentVerifierProgram producer ns dsl statement pending nonce))
          groupedDecode (CurrentVerifierProgram producer ns dsl statement pending nonce)
          branch state)) basis ≠ 0)
    (selectedRoleEarlier : .piopOpening ≠ role)
    (positiveOpeningCap : 0 < blockCap .piopOpening) :
    ∃ wire transcript,
      ∃ stages : ExecutionStages ns dsl statement pending statement.toBytes
        (statementBindingWords statement) nonce wire
        (finiteGroupedDatabaseOracle
          (CurrentVerifierProgram producer ns dsl statement pending nonce) database fallback)
        transcript,
      ∃ _pcs : PcsStages ns stages.openingPending wire.hPiop
        (SmzaRp05PcsToFinalProgram.sameProofRows stages.middle.pcs stages.piop)
        stages.decs
        (List.ofFn fun j : Fin 6 => V8Smz9PiopReconstruction.points stages.opening j)
        wire.salt statement.toBytes (statementBindingWords statement)
        wire.tapes wire.paths
        (finiteGroupedDatabaseOracle
          (CurrentVerifierProgram producer ns dsl statement pending nonce) database fallback)
        stages.hashFpp stages.pcsPending,
      fixedCanonicalOpeningAt
        (currentGroupedContext (CurrentVerifierProgram producer ns dsl statement pending nonce)
          model boundedModel ns role advice outerFuel innerFuel authorizedOf)
        blockCap fixed statement wire.hPiop = some stages.opening := by
  classical
  let program := CurrentVerifierProgram producer ns dsl statement pending nonce
  let oracle := finiteGroupedDatabaseOracle program database fallback
  let ctx := currentGroupedContext program model boundedModel ns role advice
    outerFuel innerFuel authorizedOf
  have claimsReplay := actual_program_grouped_claims_replay_and_retain
    program branch database claims fallback
  have recordEq := claimsReplay.1
  obtain ⟨wire, producerSuccess, verifierAccepted, _nonchallenge⟩ :=
    SmzaRp05CurrentGroupedVerifierReplay.accepted_grouped_claims_supply_verifier_replay
      producer ns dsl statement pending nonce branch accepted database claims fallback
  obtain ⟨transcript, transcriptSuccess, transcriptClean, _finalEq, _finalCall⟩ :=
    SmzaRp05ExecutablePcsClosure.accepted_execution_constructs_transcript ns dsl statement
      pending statement.toBytes (statementBindingWords statement) nonce wire oracle
      verifierAccepted
  obtain ⟨stages⟩ := SmzaRp05ExecutablePcsClosure.transcript_execution_has_stages ns dsl
    statement pending statement.toBytes (statementBindingWords statement) nonce wire oracle
    transcript transcriptSuccess
  obtain ⟨pcs⟩ := SmzaRp05ExecutablePcsClosureStages.pcs_execution_has_stages ns
    stages.openingPending wire.hPiop
    (SmzaRp05PcsToFinalProgram.sameProofRows stages.middle.pcs stages.piop)
    stages.decs
    (List.ofFn fun j : Fin 6 => V8Smz9PiopReconstruction.points stages.opening j)
    wire.salt statement.toBytes (statementBindingWords statement) wire.tapes wire.paths oracle
    stages.hashFpp stages.pcsPending stages.pcsExecuted
  have stagesClean := SmzaRp05ExecutablePcsClosureSampling.execution_stages_clean_matrix ns dsl
    statement pending statement.toBytes (statementBindingWords statement) nonce wire oracle
    transcript stages transcriptClean
  have openingClean := SmzaRp05ExecutablePcsClosureClean.pcs_stages_clean ns
    stages.openingPending wire.hPiop
    (SmzaRp05PcsToFinalProgram.sameProofRows stages.middle.pcs stages.piop)
    stages.decs
    (List.ofFn fun j : Fin 6 => V8Smz9PiopReconstruction.points stages.opening j)
    wire.salt statement.toBytes (statementBindingWords statement) wire.tapes wire.paths oracle
    stages.hashFpp stages.pcsPending pcs stagesClean.1
  have stagesOpeningSplit := execution_stages_current_raw_opening ns dsl statement pending
    statement.toBytes (statementBindingWords statement) nonce wire oracle transcript
    stages openingClean.1
  rcases stagesOpeningSplit with
    ⟨sourceBefore, sourceAfter, sourceOrder, sourcePrior, selectedDecoded, selected⟩
  obtain ⟨retainedBefore, retainedAfter, retainedOrder, failedCalls⟩ :=
    successful_canonical_opening_retains_failed_nonce_calls_in_verifier_record
      ns dsl statement pending nonce wire oracle transcript stages pcs openingClean.1
      transcriptSuccess
  have prefixEq := same_prefix_before_selected nonce.val
    sourceBefore sourceAfter retainedBefore retainedAfter
    (by rw [← sourceOrder]; exact List.nodup_range)
    (sourceOrder.symm.trans retainedOrder)
  have sourcePriorRetained : ∀ attempt ∈ retainedBefore,
      SmzaRp04RawRoleSampling.actualPiopOpeningOutput
        (Equiv.refl (Fin (V8Smz9RawCounterCompiler.digestCallCap
          V8Smz9AdaptiveFiniteAccounting.Historical.piopOpenings))).toEmbedding
        (SmzaRp05CurrentExecutedOpeningOutput.currentOpeningVector oracle wire.hPiop attempt) = none := by
    intro attempt member
    have memberSource : attempt ∈ sourceBefore := by simpa [prefixEq] using member
    exact executed_opening_decode_is_raw_output oracle wire.hPiop attempt none
      (sourcePrior attempt memberSource)
  have perNonceDecoder :
      ∀ (attemptIndex counter : Nat) (attemptBound : attemptIndex < 16)
      (counterBound : counter < 5)
      (recorded : (openingCounterInput wire.hPiop attemptIndex counter,
        oracle (openingCounterInput wire.hPiop attemptIndex counter)) ∈
          ((verifierProgram ns dsl statement pending statement.toBytes
            (statementBindingWords statement) nonce wire).record oracle).2),
      currentFixedVectorDecodedAt ctx blockCap fixed statement .piopOpening
        wire.hPiop attemptIndex =
      SmzaRp04RawRoleSampling.actualPiopOpeningOutput
        (Equiv.refl (Fin (V8Smz9RawCounterCompiler.digestCallCap
          V8Smz9AdaptiveFiniteAccounting.Historical.piopOpenings))).toEmbedding
        (SmzaRp05CurrentExecutedOpeningOutput.currentOpeningVector oracle wire.hPiop attemptIndex) := by
    intro attemptIndex counter attemptBound counterBound recorded
    let input := openingCounterInput wire.hPiop attemptIndex counter
    have verifierRecord := Program.record_bind_success oracle producer
      (fun actualWire => verifierProgram ns dsl statement pending statement.toBytes
        (statementBindingWords statement) nonce actualWire) wire producerSuccess
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
      ns dsl statement pending nonce wire oracle transcript stages pcs openingClean.1
      transcriptSuccess
  obtain ⟨selectedCounter, selectedBound, selectedRecorded⟩ := selectedRetention
  -- The same per-nonce grouped-cell argument as above, now at the transmitted
  -- nonce; the source execution supplies the selected decoder result.
  have selectedBound16 : nonce.val < 16 := by
    have inRange : nonce.val ∈ List.range 16 := by
      rw [sourceOrder]
      exact List.mem_append.mpr (Or.inr (by simp))
    exact List.mem_range.mp inRange
  have fixedSelected : currentFixedVectorDecodedAt ctx blockCap fixed statement
      .piopOpening wire.hPiop nonce.val = some stages.opening :=
    (perNonceDecoder nonce.val selectedCounter selectedBound16 selectedBound
      selectedRecorded).trans selected
  have mappedOrder : canonicalOpeningNonceOrder.map Fin.val = List.range 16 := by
    change (List.ofFn (id : Fin 16 → Fin 16)).map Fin.val = _
    rw [List.map_ofFn]
    exact (ofFn_fin_val_eq_range_map id).trans (List.map_id _)
  have fixedScan : firstSome
      (fun attempt : Nat => currentFixedVectorDecodedAt ctx blockCap fixed statement
        .piopOpening wire.hPiop attempt) (List.range 16) = some stages.opening := by
    rw [retainedOrder]
    simpa only [SmzaRp05TracePrefixes.RoleOutput] using firstSome_append_selected
      (fun attempt : Nat => currentFixedVectorDecodedAt ctx blockCap fixed statement
        .piopOpening wire.hPiop attempt)
      retainedBefore retainedAfter nonce.val stages.opening fixedPrior fixedSelected
  have fixedCanonical : firstSome
      (fun index : Fin 16 => currentFixedVectorDecodedAt ctx blockCap fixed statement
        .piopOpening wire.hPiop index.val) canonicalOpeningNonceOrder = some stages.opening := by
    have mappedScan : firstSome
        (fun attempt : Nat => currentFixedVectorDecodedAt ctx blockCap fixed statement
          .piopOpening wire.hPiop attempt)
        (canonicalOpeningNonceOrder.map Fin.val) = some stages.opening := by
      simpa only [mappedOrder] using fixedScan
    simpa only [firstSome_map, SmzaRp05TracePrefixes.RoleOutput] using mappedScan
  refine ⟨wire, transcript, stages, pcs, ?_⟩
  simpa only [fixedCanonicalOpeningAt, currentFixedVectorDecodedAt,
    SmzaRp05TracePrefixes.RoleOutput] using fixedCanonical

end
end HegemonCrypto.SmallWood.SmzaRp05CurrentFixedAdviceOpeningScan
