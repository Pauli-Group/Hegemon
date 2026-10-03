import SmzaRp05PhysicalPcsRecordRetention
import SmzaRp05CurrentFixedAdviceOpeningSource
import SmzaRp05CurrentGroupedVerifierReplay
import SmzaRp05CurrentAcceptedRoleQueryReadback
import SmzaRp05CurrentGroupedClaimRetention
import SmzaRp05CurrentFiniteGroupedProgram
import SmzaRp05CurrentGroupedOracleVector
import SmzaRp05CurrentAcceptedRoleTraceReadback

/-! # Same-run DECS-matrix counter-zero call

The first actual coefficient-XOF read is retained through the accepted PCS
and verifier programs, then converted to the same grouped branch answer. This
is the call needed to seed the current finite DECS-matrix role route; the
remaining coordinates are read from that one claimed vector. -/

namespace HegemonCrypto.SmallWood.SmzaRp05CurrentAcceptedDecsMatrixCallReadback

open HegemonCrypto.CmsOracleDatabaseBridge (ClaimsDatabaseEvent)
open HegemonCrypto.FiniteOracleDatabase (Database)
open SmzaRp05ExecutableMerkleVerifier (Program Oracle)
open SmzaRp05ExecutablePcsClosure
  (pcsProgram queryProgram widths deltas nativeFiveMcaGate406
    currentTwelveLvcsGate406 ExecutionStages)
open SmzaRp05ExecutablePcsClosureStages (PcsStages)
open SmzaRp05ExecutableChallengeStage (postMerkleProgram afterMerkle fieldXof counterInput)
open SmzaRp05PcsWireProjection (DecodedMiddleWire fieldWordsToGoldilocks)
open SmzaRp05DecsResponseProjection (DecodedDecsResponseFields)
open SmzaRp05LeafNamespace (Namespace)
open SmzaRp05RelationRefinement (RelationDsl)
open SmzaRp05ExecutablePcsClosureStatement (statementBindingWords verifierProgram)
open SmzaRp05CurrentProofWireProgram (ExistingProofFieldView)
open SmzaRp05PhysicalAcceptedReplayLite
  (Branches branchResult branchKeys branchAnswers branchClaims answerLog rawLog)
open SmzaRp05CurrentGroupedClaimRetention (groupedDecode claims_supply_grouped_oracle_answers)
open SmzaRp05CurrentGroupedClaimRetention (actual_program_grouped_claims_replay_and_retain)
open SmzaRp05CurrentFiniteGroupedProgram
  (Key encode included included_encode_of_reachable answer_log_input_reachable)
open SmzaRp05CurrentGroupedOracleVector (finiteGroupedDatabaseOracle)
open SmzaRp05GroupedSuffix (GroupCounter groupRepresentative groupZero)
open SmzaRp05CurrentGroupedRecordReadback
  (canonicalQueryPrefix canonicalQueryCounterInput grouped_coordinate_eq_canonical_query_counter_input)
open SmzaRp05CurrentAcceptedRoleQueryReadback (current_actual_grouped_role_call_readback)
open SmzaRp05CurrentFixedAdviceOpeningSource (verifier_record_pair_has_branch_answer)
open SmzaRp05CurrentAcceptedRoleTraceReadback (accepted_decs_matrix_counter_parses)
open SmzaRp05CurrentGroupedVerifierReplay (accepted_grouped_claims_supply_verifier_replay)
open SmzaRp05PhysicalPcsRecordRetention
  (execution_pcs_records_retained_in_verifier)
open SmzaRp05ExecutableFinalVerifier (ReconstructedTranscript)
open SmzaRp05TracePrefixes (RelationModel TypedRoutes)
open SmzaRp05CurrentGroupedContext (currentGroupedContext)
open SmzaChallengeStageTargets (Role StageQuery)
open HegemonCrypto.CanonicalBytes (Byte)
open V8SmzaOracleParser (RawInput RawDigest)
open V8Smz9CoherentVectorMerkle (VectorOutput vectorOutputBytes)
open V8Smz9CoherentMerkleInstrument (rawRecords)
open SmzaQ38McaSourceBinding (Query)

noncomputable section
set_option autoImplicit false
set_option maxRecDepth 12000
set_option maxHeartbeats 1000000
attribute [local irreducible]
  SmzaRp05ExecutableChallengeStage.postMerkleProgram
  SmzaRp05ExecutableChallengeStage.afterMerkle
  SmzaRp05ExecutableChallengeStage.scan
  SmzaRp05ExecutableChallengeStage.counterKeys
  SmzaRp05ExecutableMerkleVerifier.merkleProgram
  SmzaRp05ExecutableChallengeStage.mcaValue
  SmzaRp05ExecutableChallengeStage.returnedWords

private theorem decs_counter_keys_cons (requested : Nat) (positive : 0 < requested)
    (root : RawDigest) :
    SmzaRp05ExecutableChallengeStage.counterKeys
        HegemonCrypto.SmallWoodTranscript.decsCoefficientDomain requested root =
      counterInput HegemonCrypto.SmallWoodTranscript.decsCoefficientDomain root 0 ::
        (SmzaRp05ExecutableChallengeStage.counterKeys
          HegemonCrypto.SmallWoodTranscript.decsCoefficientDomain requested root).tail := by
  unfold SmzaRp05ExecutableChallengeStage.counterKeys
  have capPositive : 0 < SmzaRp05ExecutableChallengeStage.callCap requested := by
    simp only [SmzaRp05ExecutableChallengeStage.callCap]
    split <;> omega
  cases cap : SmzaRp05ExecutableChallengeStage.callCap requested with
  | zero => omega
  | succ n =>
      change List.map
        (counterInput HegemonCrypto.SmallWoodTranscript.decsCoefficientDomain root)
          (List.range (n + 1)) = _
      rw [List.range_succ_eq_map]
      simp only [List.map_cons, List.tail_cons]

/-- A positive-width DECS coefficient sampler always records its first read.
This statement is kept at the small `fieldLoop` level to avoid unfolding the
large post-Merkle/Merkle program. -/
theorem field_xof_decs_counter_zero_recorded
    (requested : Nat) (positive : 0 < requested) (root : RawDigest) (oracle : Oracle) :
    (counterInput HegemonCrypto.SmallWoodTranscript.decsCoefficientDomain root 0,
      oracle (counterInput HegemonCrypto.SmallWoodTranscript.decsCoefficientDomain root 0)) ∈
      ((fieldXof HegemonCrypto.SmallWoodTranscript.decsCoefficientDomain requested root).record
        oracle).2 := by
  have keys := decs_counter_keys_cons requested positive root
  have headRecord :
      (counterInput HegemonCrypto.SmallWoodTranscript.decsCoefficientDomain root 0,
        oracle (counterInput HegemonCrypto.SmallWoodTranscript.decsCoefficientDomain root 0)) ∈
      ((SmzaRp05ExecutableChallengeStage.fieldLoop requested []
        (SmzaRp05ExecutableChallengeStage.counterKeys
          HegemonCrypto.SmallWoodTranscript.decsCoefficientDomain requested root)).record
        oracle).2 := by
    rw [keys]
    have notDone : ¬ (requested ≤ 0) := by omega
    simp only [SmzaRp05ExecutableChallengeStage.fieldLoop, List.length_nil]
    rw [if_neg notDone]
    simp only [Program.record]
    exact List.mem_cons_self
  simpa [SmzaRp05ExecutableChallengeStage.fieldXof] using headRecord

/-- Lift every actual post-Merkle record to the accepted PCS record. -/
theorem post_merkle_records_retained_in_pcs
    (ns : Namespace) (pending : Bool) (hPiop : RawDigest)
    (wire : SmzaRp05PcsWireProjection.DecodedMiddleWire)
    (decs : SmzaRp05DecsResponseProjection.DecodedDecsResponseFields)
    (points : List HegemonCrypto.SmallWood.Goldilocks) (salt binding : List Byte)
    (statementBinding : List Nat) (tapes : List (List Byte)) (paths : List (List RawDigest))
    (oracle : Oracle) (hashFpp : RawDigest) (finalPending : Bool)
    (stages : PcsStages ns pending hPiop wire decs points salt binding statementBinding
      tapes paths oracle hashFpp finalPending)
    (executed : (pcsProgram ns pending hPiop wire decs points salt binding
      statementBinding tapes paths).eval oracle = some (hashFpp, finalPending)) :
    ∀ call, call ∈ ((postMerkleProgram ns stages.merkleInput).record oracle).2 →
      call ∈ ((pcsProgram ns pending hPiop wire decs points salt binding
        statementBinding tapes paths).record oracle).2 := by
  classical
  let afterQuery : List Nat × Bool → Program (RawDigest × Bool) :=
    fun (indexes, sampledPending) =>
      match SmzaRp05DecsPointProjection.fieldPoints 406 indexes with
      | none => .done none
      | some decsPoints =>
          match SmzaRp05LvcsWireProjection.reconstructRowsFromPcsFields
              wire.pcs points decsPoints wire.rowScalars 64 widths deltas 2 368 140 38 with
          | none => .done none
          | some rows =>
              if currentTwelveLvcsGate406 stages.heads
                  (wire.pcs.rcombiTails.map fieldWordsToGoldilocks)
                  points decsPoints rows then
                match SmzaRp05PcsMerklePayload.makeMerkleInput salt binding sampledPending
                    indexes rows decs.maskingEvals tapes paths with
                | none => .done none
                | some input =>
                    (postMerkleProgram ns input).bind fun post =>
                      match SmzaRp05DecsResponseProjection.hashFppProgram post.root decs
                          (rows.map fun row => row.map SmzaRp05ExecutableRestore.toWord)
                          (SmzaRp05PcsHashFppMiddle.gammaRows post)
                          (decsPoints.map fun point => SmzaRp05ExecutableRestore.toWord point)
                          140 368 statementBinding with
                      | none => .done none
                      | some hashProgram =>
                          match SmzaRp05DecsResponseProjection.restoredResponsePolynomials decs
                              (rows.map fun row => row.map SmzaRp05ExecutableRestore.toWord)
                              (SmzaRp05PcsHashFppMiddle.gammaRows post)
                              (decsPoints.map fun point => SmzaRp05ExecutableRestore.toWord point)
                              140 368 with
                          | none => .done none
                          | some polynomials =>
                              if nativeFiveMcaGate406 salt tapes indexes
                                  (rows.map fun row => row.map SmzaRp05ExecutableRestore.toWord)
                                  (SmzaRp05PcsHashFppMiddle.gammaRows post)
                                  decs.maskingEvals
                                  (decsPoints.map fun point => SmzaRp05ExecutableRestore.toWord point)
                                  polynomials then
                                hashProgram.bind fun digest => .done (some (digest, post.pending))
                              else .done none
              else .done none
  have programForm : pcsProgram ns pending hPiop wire decs points salt binding
      statementBinding tapes paths =
      (SmzaRp05ExecutableMerkleVerifier.ask stages.openingInput).bind fun openingDigest =>
        (queryProgram pending openingDigest).bind afterQuery := by
    unfold pcsProgram
    rw [stages.headsBuilt]
    dsimp only
    rw [stages.openingBuilt]
    congr 1
  rw [programForm] at executed
  obtain ⟨openingDigest, openingRead, afterOpening⟩ :=
    SmzaRp05FinalProgramMiddleExecution.program_bind_success oracle
      (SmzaRp05ExecutableMerkleVerifier.ask stages.openingInput) _
      (hashFpp, finalPending) executed
  have openingEq : openingDigest = stages.openingDigest :=
    Option.some.inj (openingRead.symm.trans stages.openingRead)
  subst openingDigest
  obtain ⟨queryPair, queryRead, afterQueryEval⟩ :=
    SmzaRp05FinalProgramMiddleExecution.program_bind_success oracle
      (queryProgram pending stages.openingDigest) _ (hashFpp, finalPending) afterOpening
  have queryEq : queryPair = (stages.indexes, stages.sampledPending) :=
    Option.some.inj (queryRead.symm.trans stages.queryExecuted)
  subst queryPair
  have inputSuccess :
      (afterQuery (stages.indexes, stages.sampledPending)).eval oracle =
        some (hashFpp, finalPending) := by
    simpa [afterQuery, stages.pointsBuilt, stages.rowsBuilt] using afterQueryEval
  have reduced := inputSuccess
  simp only [afterQuery, stages.pointsBuilt, stages.rowsBuilt] at reduced
  cases lvcsGate : currentTwelveLvcsGate406 stages.heads
      (wire.pcs.rcombiTails.map fieldWordsToGoldilocks) points stages.decsPoints stages.rows with
  | false => simp [lvcsGate, Program.eval] at reduced
  | true =>
      simp only [lvcsGate, stages.inputBuilt] at reduced
      have postLogIncluded : ((postMerkleProgram ns stages.merkleInput).record oracle).2 ⊆
          ((afterQuery (stages.indexes, stages.sampledPending)).record oracle).2 := by
        simpa [afterQuery, stages.pointsBuilt, stages.rowsBuilt, lvcsGate,
          stages.inputBuilt] using
          (Program.bind_log_left oracle (postMerkleProgram ns stages.merkleInput)
            (fun post =>
              match SmzaRp05DecsResponseProjection.hashFppProgram post.root decs
                  (stages.rows.map fun row => row.map SmzaRp05ExecutableRestore.toWord)
                  (SmzaRp05PcsHashFppMiddle.gammaRows post)
                  (stages.decsPoints.map fun point => SmzaRp05ExecutableRestore.toWord point)
                  140 368 statementBinding with
              | none => .done none
              | some hashProgram =>
                  match SmzaRp05DecsResponseProjection.restoredResponsePolynomials decs
                      (stages.rows.map fun row => row.map SmzaRp05ExecutableRestore.toWord)
                      (SmzaRp05PcsHashFppMiddle.gammaRows post)
                      (stages.decsPoints.map fun point => SmzaRp05ExecutableRestore.toWord point)
                      140 368 with
                  | none => .done none
                  | some polynomials =>
                      if nativeFiveMcaGate406 salt tapes stages.indexes
                          (stages.rows.map fun row => row.map SmzaRp05ExecutableRestore.toWord)
                          (SmzaRp05PcsHashFppMiddle.gammaRows post)
                          decs.maskingEvals
                          (stages.decsPoints.map fun point => SmzaRp05ExecutableRestore.toWord point)
                          polynomials then
                        hashProgram.bind fun digest => .done (some (digest, post.pending))
                      else .done none)
            stages.post stages.postExecuted)
      have querySubset := Program.bind_log_right oracle (queryProgram pending stages.openingDigest)
        afterQuery (stages.indexes, stages.sampledPending) stages.queryExecuted
      have askSubset := Program.bind_log_right oracle
        (SmzaRp05ExecutableMerkleVerifier.ask stages.openingInput)
        (fun digest => (queryProgram pending digest).bind afterQuery)
        stages.openingDigest stages.openingRead
      intro call member
      rw [programForm]
      exact askSubset (querySubset (postLogIncluded member))

/-- On an accepted grouped branch, the actual DECS matrix sampler's first
counter-zero oracle read is a same-branch answer-log call. This joins the
source PCS record, accepted verifier record, and grouped-claim branch; it
does not posit a role-event or a readback certificate. -/
theorem accepted_branch_has_decs_matrix_counter_zero_call
    (producer : Program ExistingProofFieldView)
    (ns : Namespace) (dsl : RelationDsl)
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
    [Fintype RawDigest] (fallback : RawDigest) :
    let actualProgram := producer.bind fun wire =>
      verifierProgram ns dsl statement pending nonce wire
    let oracle := finiteGroupedDatabaseOracle actualProgram database fallback
    ∃ wire transcript,
      ∃ execution : ExecutionStages ns dsl statement pending statement.toBytes
        (statementBindingWords statement) nonce wire oracle transcript,
      ∃ pcs : PcsStages ns execution.openingPending wire.hPiop
        (SmzaRp05PcsToFinalProgram.sameProofRows execution.middle.pcs execution.piop)
        execution.decs
        (List.ofFn fun j : Fin 6 => V8Smz9PiopReconstruction.points execution.opening j)
        wire.salt statement.toBytes (statementBindingWords statement)
        wire.tapes wire.paths oracle execution.hashFpp execution.pcsPending,
      ∃ output,
        (counterInput HegemonCrypto.SmallWoodTranscript.decsCoefficientDomain
          pcs.post.root 0, output) ∈ answerLog groupedDecode actualProgram branch ∧
        groupedDecode
          (counterInput HegemonCrypto.SmallWoodTranscript.decsCoefficientDomain
            pcs.post.root 0) output =
          oracle (counterInput HegemonCrypto.SmallWoodTranscript.decsCoefficientDomain
            pcs.post.root 0) := by
  classical
  let actualProgram := producer.bind fun wire =>
    verifierProgram ns dsl statement pending nonce wire
  let oracle : Oracle := finiteGroupedDatabaseOracle actualProgram database fallback
  obtain ⟨wire, producerSuccess, verifierAccepted, _nonchallengeRetained⟩ :=
    accepted_grouped_claims_supply_verifier_replay producer ns dsl statement pending nonce
      branch accepted database claims fallback
  obtain ⟨transcript, transcriptSuccess, _clean, _rootEq, _rootMember⟩ :=
    SmzaRp05ExecutablePcsClosure.accepted_execution_constructs_transcript ns dsl statement
      pending statement.toBytes (statementBindingWords statement) nonce wire oracle
      verifierAccepted
  obtain ⟨execution⟩ :=
    SmzaRp05ExecutablePcsClosure.transcript_execution_has_stages ns dsl statement pending
      statement.toBytes (statementBindingWords statement) nonce wire oracle transcript
      transcriptSuccess
  obtain ⟨pcs⟩ :=
    SmzaRp05ExecutablePcsClosureStages.pcs_execution_has_stages
      ns execution.openingPending wire.hPiop
      (SmzaRp05PcsToFinalProgram.sameProofRows execution.middle.pcs execution.piop)
      execution.decs
      (List.ofFn fun j : Fin 6 => V8Smz9PiopReconstruction.points execution.opening j)
      wire.salt statement.toBytes (statementBindingWords statement)
      wire.tapes wire.paths oracle execution.hashFpp execution.pcsPending
      execution.pcsExecuted
  have postCore := SmzaRp05ExecutableChallengeStage.post_merkle_has_executed_core
    ns oracle pcs.merkleInput pcs.post pcs.postExecuted
  have fieldEval :
      (fieldXof HegemonCrypto.SmallWoodTranscript.decsCoefficientDomain 700 pcs.post.root).eval
        oracle = some pcs.post.sampled := by
    rw [fieldXof, SmzaRp05ExecutableChallengeStage.field_loop_executes_scan,
      postCore.2.1]
  have fieldMember := field_xof_decs_counter_zero_recorded 700 (by omega)
    pcs.post.root oracle
  have fieldInAfter :
      (counterInput HegemonCrypto.SmallWoodTranscript.decsCoefficientDomain pcs.post.root 0,
        oracle (counterInput HegemonCrypto.SmallWoodTranscript.decsCoefficientDomain
          pcs.post.root 0)) ∈ ((afterMerkle pcs.merkleInput pcs.post.root).record oracle).2 := by
    unfold afterMerkle
    exact Program.bind_log_left oracle
      (fieldXof HegemonCrypto.SmallWoodTranscript.decsCoefficientDomain 700 pcs.post.root)
      (fun sampled => .done (some
        (⟨pcs.post.root, sampled,
          SmzaRp05ExecutableChallengeStage.pendingFailure pcs.merkleInput.pendingXofFailure sampled,
          SmzaRp05ExecutableChallengeStage.mcaValue pcs.merkleInput
            (SmzaRp05ExecutableChallengeStage.returnedWords 700 sampled)⟩ :
          SmzaRp05ExecutableChallengeStage.PostMerkle)))
      pcs.post.sampled fieldEval fieldMember
  have postMember :
      (counterInput HegemonCrypto.SmallWoodTranscript.decsCoefficientDomain pcs.post.root 0,
        oracle (counterInput HegemonCrypto.SmallWoodTranscript.decsCoefficientDomain
          pcs.post.root 0)) ∈ ((postMerkleProgram ns pcs.merkleInput).record oracle).2 := by
    simpa only [SmzaRp05ExecutableChallengeStage.postMerkleProgram] using
      (Program.bind_log_right oracle
        (SmzaRp05ExecutableMerkleVerifier.merkleProgram ns pcs.merkleInput)
        (afterMerkle pcs.merkleInput) pcs.post.root postCore.1 fieldInAfter)
  have postToPcs := post_merkle_records_retained_in_pcs ns execution.openingPending wire.hPiop
    (SmzaRp05PcsToFinalProgram.sameProofRows execution.middle.pcs execution.piop)
    execution.decs
    (List.ofFn fun j : Fin 6 => V8Smz9PiopReconstruction.points execution.opening j)
    wire.salt statement.toBytes (statementBindingWords statement)
    wire.tapes wire.paths oracle execution.hashFpp execution.pcsPending pcs execution.pcsExecuted
  have pcsToVerifier := execution_pcs_records_retained_in_verifier ns dsl statement pending
    nonce wire oracle transcript execution transcriptSuccess
  have actualRecord := actual_program_grouped_claims_replay_and_retain actualProgram branch
    database claims fallback
  have branchRecord : actualProgram.record oracle =
      (branchResult groupedDecode actualProgram branch, rawLog groupedDecode actualProgram branch) :=
    by
      change actualProgram.record
        (fun raw => match database (encode actualProgram raw) with
          | none => fallback
          | some vector => groupedDecode raw vector) = _
      exact actualRecord.1
  have verifierMember := pcsToVerifier _ (postToPcs
    (counterInput HegemonCrypto.SmallWoodTranscript.decsCoefficientDomain pcs.post.root 0,
      oracle (counterInput HegemonCrypto.SmallWoodTranscript.decsCoefficientDomain pcs.post.root 0))
    postMember)
  have wholeMember :
      (counterInput HegemonCrypto.SmallWoodTranscript.decsCoefficientDomain pcs.post.root 0,
        oracle (counterInput HegemonCrypto.SmallWoodTranscript.decsCoefficientDomain
          pcs.post.root 0)) ∈ (actualProgram.record oracle).2 := by
    have recordSplit := Program.record_bind_success oracle producer
      (fun candidate => verifierProgram ns dsl statement pending nonce candidate)
      wire producerSuccess
    rw [recordSplit]
    exact List.mem_append_right _ verifierMember
  obtain ⟨output, outputMember, outputEq⟩ :=
    verifier_record_pair_has_branch_answer (Key := Key actualProgram)
      actualProgram branch oracle branchRecord
      (counterInput HegemonCrypto.SmallWoodTranscript.decsCoefficientDomain pcs.post.root 0)
      (oracle (counterInput HegemonCrypto.SmallWoodTranscript.decsCoefficientDomain
        pcs.post.root 0)) wholeMember
  exact ⟨wire, transcript, execution, pcs, output, outputMember, outputEq⟩

end
end HegemonCrypto.SmallWood.SmzaRp05CurrentAcceptedDecsMatrixCallReadback
