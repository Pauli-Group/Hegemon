import SmzaRp05CurrentGroupedVerifierReplay
import SmzaRp05CurrentCausalNonchallengeRetention
import SmzaRp05CurrentAcceptedOuterReadback
import SmzaRp05CurrentDecsFrameReadback
import SmzaRp05CurrentFppFrameReadback
import SmzaRp05CurrentPiopFrameReadback
import SmzaRp05AcceptedRoleLabels
import SmzaRp05ChallengeRecordErasure
import SmzaRp05FilteredReadback
import SmzaRp04StatementRecordFilter

/-! # Filtered current role-trace readback from one accepted branch

The four wrapper records are individually derived from one accepted grouped
verifier branch, normalized payload constructors, and the branch's claims
database. Each is a nonleaf frame, so it survives challenge erasure and the
one-statement filter. The theorem does not require retention of every
verifier-log call in the filtered view. -/

namespace HegemonCrypto.SmallWood.SmzaRp05CurrentAcceptedFilteredRoleTraces

open HegemonCrypto.CanonicalBytes (Byte encodeLE)
open HegemonCrypto.CmsOracleDatabaseBridge (ClaimsDatabaseEvent)
open HegemonCrypto.FiniteOracleDatabase (Database)
open SmzaRp05ExecutableMerkleVerifier (Program Oracle ask)
open SmzaRp05ExecutablePcsClosure (ExecutionStages transcriptProgram)
open SmzaRp05ExecutablePcsClosureStages (PcsStages)
open SmzaRp05ExecutablePcsClosureStatement
  (statementBindingWords verifierProgram)
open SmzaRp05CurrentGroupedVerifierReplay (accepted_grouped_claims_supply_verifier_replay)
open SmzaRp05CurrentCausalNonchallengeRetention
  (accepted_execution_causal_record_memberships)
open SmzaRp05CurrentAcceptedOuterReadback
  (successful_pcs_root_query_readback statement_binding_words_encode_exact)
open SmzaRp05CurrentDecsFrameReadback (current_decs_opening_edge406)
open SmzaRp05CurrentFppFrameReadback (successful_response_program_has_current_fpp_edge)
open SmzaRp05CurrentPiopFrameReadback
  (current_final_normalized_payload current_final_piop_edge)
open SmzaRp05AcceptedRoleLabels
  (current_outer_readback_of_recorded_chain current_inner_readback_of_recorded_chain)
open SmzaRp05CurrentGroupedClaimRetention (groupedDecode)
open SmzaRp05CurrentFiniteGroupedProgram (Key encode included)
open SmzaRp05CurrentGroupedOracleVector (finiteGroupedDatabaseOracle)
open SmzaRp05GroupedSuffix (GroupCounter groupRepresentative groupZero)
open SmzaRp05PhysicalAcceptedReplayLite
  (Branches branchResult branchKeys branchAnswers branchClaims)
open SmzaRp05CurrentProofWireProgram (ExistingProofFieldView)
open SmzaRp05RelationRefinement (RelationDsl)
open SmzaRp05LeafNamespace (Namespace)
open SmzaRp05FilteredReadback (globalLeafStatement)
open SmzaRp05ChallengeRecordErasure
  (eraseChallengeRecords parse_stage_query_global_payload_none)
open SmzaRp04StatementRecordFilter (oneStatementFilter keepOneStatement)
open SmzaRp05FilteredDecoderInstability (globalNormalizedPayload globalOnlineNext)
open SmzaRp05CurrentRoleLabels (preambleFromTrace currentRawInputDecidableEq)
open HegemonCrypto.SmallWood.SmzaChallengeStageTargets (Role parseStageQuery)
open V8Smz9CoherentVectorMerkle (VectorOutput vectorOutputBytes)
open V8Smz9CoherentMerkleInstrument (rawRecords)
open V8SmzaOracleParser (RawInput RawDigest Payload)
open V8SmzaOnlineParser (payloadNext)
open SmzaRecordedTracePath (RecordsCollisionFree)

local notation "Statement" => SmzaRp05StatementNamespace.Statement
local notation "Records" => V8Smz9CoherentMerkleGeometry.Records RawInput RawDigest
local instance : DecidableEq RawInput := currentRawInputDecidableEq
local instance rawDigestDecidableEq [Fintype RawDigest] : DecidableEq RawDigest :=
  Fintype.decidablePiFintype

def currentOuterTarget (decsTarget piopTarget fppTarget rootTarget : RawDigest) :
    Role → V8SmzaOracleParser.Stage × RawDigest
  | .decsMatrix => (.root, rootTarget)
  | .piopMatrix => (.fpp, fppTarget)
  | .piopOpening => (.piop, piopTarget)
  | .decsSample => (.decs, decsTarget)

noncomputable section
set_option autoImplicit false
set_option maxRecDepth 12000
set_option maxHeartbeats 4000000

private theorem global_leaf_statement_none_of_normalized_nonleaf
    (ns : Namespace) (input : RawInput) (normalized : Payload)
    (read : globalNormalizedPayload ns input = some normalized)
    (notLeaf : normalized.kind ≠ .leaf) :
    globalLeafStatement ns input = none := by
  cases framed : V8SmzaOracleParser.parseFramed input with
  | none => simp [globalNormalizedPayload, framed] at read
  | some frame =>
      rcases frame with ⟨role, bytes⟩
      let salt := (bytes.drop SmzaRp05LeafNamespace.preambleBytes).take 32
      have normalizedRead : SmzaRp05LeafNamespace.normalizedPayload ns salt input =
          some normalized := by
        simpa [globalNormalizedPayload, framed, salt] using read
      cases leaf : SmzaRp05LeafNamespace.parseCurrentLeaf ns salt input with
      | none =>
          have leafNone : SmzaRp05LeafNamespace.leafStatement ns salt input = none := by
            simp [SmzaRp05LeafNamespace.leafStatement, leaf]
          unfold SmzaRp05FilteredReadback.globalLeafStatement
          simp only [framed]
          simpa [salt] using leafNone
      | some currentLeaf =>
          have payloadEq : normalized = currentLeaf.normalized := by
            have someEq : some currentLeaf.normalized = some normalized := by
              simpa [SmzaRp05LeafNamespace.normalizedPayload, leaf] using normalizedRead
            exact (Option.some.inj someEq).symm
          have kindEq : normalized.kind = .leaf := by
            rw [payloadEq]
            rfl
          exact (notLeaf kindEq).elim

private theorem actual_nonleaf_wrapper_survives_filtered_view
    (ns : Namespace) (statement : Statement) (fullRecords filteredRecords : Records)
    (input : RawInput) (output : RawDigest) (normalized : Payload)
    (normalizedRead : globalNormalizedPayload ns input = some normalized)
    (notLeaf : normalized.kind ≠ .leaf)
    (fullMember : (input, output) ∈ fullRecords)
    (filteredRecordsEq : filteredRecords = oneStatementFilter
      (globalLeafStatement ns) statement.toBytes
      (eraseChallengeRecords fullRecords)) :
    (input, output) ∈ filteredRecords := by
  classical
  have queryNone : parseStageQuery input = none := by
    cases parsed : parseStageQuery input with
    | none => rfl
    | some query =>
        have impossible := parse_stage_query_global_payload_none ns input query parsed
        rw [normalizedRead] at impossible
        cases impossible
  have erasedMember : (input, output) ∈ eraseChallengeRecords fullRecords := by
    apply Finset.mem_filter.mpr
    exact ⟨fullMember, by simp [queryNone]⟩
  have leafNone := global_leaf_statement_none_of_normalized_nonleaf
    ns input normalized normalizedRead notLeaf
  rw [filteredRecordsEq]
  apply Finset.mem_filter.mpr
  exact ⟨erasedMember, Or.inl leafNone⟩

/-- Exact-stage core: the same verifier acceptance, transcript success, and
nonchallenge record retention are consumed together with the supplied
`ExecutionStages`/`PcsStages`.  This lets downstream arguments reuse their
chosen physical execution rather than matching independent existentials. -/
theorem current_stages_supply_filtered_role_traces
    (producer : Program ExistingProofFieldView)
    (ns : Namespace) (dsl : RelationDsl) (statement : Statement)
    (pending : Bool) (nonce : Fin (2 ^ 32))
    (database : Database
      (Key (producer.bind fun wire => verifierProgram ns dsl statement pending nonce wire))
      (VectorOutput GroupCounter))
    (fallback : RawDigest)
    (wire : ExistingProofFieldView)
    (transcript : SmzaRp05ExecutableFinalVerifier.ReconstructedTranscript)
    (execution : ExecutionStages ns dsl statement pending statement.toBytes
      (statementBindingWords statement) nonce wire
      (finiteGroupedDatabaseOracle
        (producer.bind fun wire => verifierProgram ns dsl statement pending nonce wire)
        database fallback) transcript)
    (pcs : PcsStages ns execution.openingPending wire.hPiop
      (SmzaRp05PcsToFinalProgram.sameProofRows execution.middle.pcs execution.piop)
      execution.decs
      (List.ofFn fun j : Fin 6 => V8Smz9PiopReconstruction.points execution.opening j)
      wire.salt statement.toBytes (statementBindingWords statement)
      wire.tapes wire.paths
      (finiteGroupedDatabaseOracle
        (producer.bind fun wire => verifierProgram ns dsl statement pending nonce wire)
        database fallback) execution.hashFpp execution.pcsPending)
    (verifierAccepted : (verifierProgram ns dsl statement pending nonce wire).eval
      (finiteGroupedDatabaseOracle
        (producer.bind fun wire => verifierProgram ns dsl statement pending nonce wire)
        database fallback) = some ())
    (transcriptSuccess : (transcriptProgram ns dsl statement pending statement.toBytes
      (statementBindingWords statement) nonce wire).eval
      (finiteGroupedDatabaseOracle
        (producer.bind fun wire => verifierProgram ns dsl statement pending nonce wire)
        database fallback) = some transcript)
    [Fintype RawDigest] (fuel : Nat) (enough : 28 ≤ fuel)
    (collisionFree : RecordsCollisionFree
      (oneStatementFilter (globalLeafStatement ns) statement.toBytes
        (eraseChallengeRecords
          (rawRecords
            (fun key => groupRepresentative
              (included
                (producer.bind fun wire => verifierProgram ns dsl statement pending nonce wire)
                key))
            (vectorOutputBytes groupZero) database))))
    (nonchallengeRetained : ∀ call,
      call ∈ ((verifierProgram ns dsl statement pending nonce wire).record
        (finiteGroupedDatabaseOracle
          (producer.bind fun wire => verifierProgram ns dsl statement pending nonce wire)
          database fallback)).2 →
      parseStageQuery call.1 = none →
      call ∈ rawRecords
        (fun key => groupRepresentative
          (included
            (producer.bind fun wire => verifierProgram ns dsl statement pending nonce wire)
            key))
        (vectorOutputBytes groupZero) database) :
    let actualProgram := producer.bind fun wire =>
      verifierProgram ns dsl statement pending nonce wire
    let filteredRecords := oneStatementFilter (globalLeafStatement ns) statement.toBytes
      (eraseChallengeRecords
        (rawRecords (fun key => groupRepresentative (included actualProgram key))
          (vectorOutputBytes groupZero) database))
    (∀ role, preambleFromTrace ns role
      (V8Smz9CoherentMerkleGeometry.extract (globalOnlineNext ns) filteredRecords fuel
        (currentOuterTarget pcs.openingDigest wire.hPiop execution.hashFpp
          pcs.post.root role).1
        (currentOuterTarget pcs.openingDigest wire.hPiop execution.hashFpp
          pcs.post.root role).2) = some statement.toBytes) ∧
    let innerTrace := V8Smz9CoherentMerkleGeometry.extract (globalOnlineNext ns)
      filteredRecords fuel .decs pcs.openingDigest
    ∀ role, V8Smz9CoherentMerkleGeometry.extract (globalOnlineNext ns) filteredRecords fuel
      (currentOuterTarget pcs.openingDigest wire.hPiop execution.hashFpp
        pcs.post.root role).1
      (currentOuterTarget pcs.openingDigest wire.hPiop execution.hashFpp
        pcs.post.root role).2 = SmzaRp05AcceptedRoleLabels.causalTrace innerTrace role := by
  classical
  let actualProgram := producer.bind fun wire =>
    verifierProgram ns dsl statement pending nonce wire
  let oracle := finiteGroupedDatabaseOracle actualProgram database fallback
  let fullRecords := rawRecords
    (fun key => groupRepresentative (included actualProgram key))
    (vectorOutputBytes groupZero) database
  let filteredRecords := oneStatementFilter
    (globalLeafStatement ns) statement.toBytes (eraseChallengeRecords fullRecords)
  have filteredRecordsEq : filteredRecords = oneStatementFilter
      (globalLeafStatement ns) statement.toBytes (eraseChallengeRecords fullRecords) := rfl
  obtain ⟨openingFull, finalFull, hashRecordRetained⟩ :=
    accepted_execution_causal_record_memberships ns dsl statement pending nonce wire
      oracle transcript execution pcs fullRecords verifierAccepted transcriptSuccess
      nonchallengeRetained
  obtain ⟨decsRows, _rowsFormed, _framed, decsNormalized, decsNext⟩ :=
    current_decs_opening_edge406 ns wire.hPiop pcs.heads
      execution.middle.pcs.rcombiTails pcs.openingInput pcs.openingBuilt
  let decsPayload : Payload := ⟨.decs,
    (SmzaRp05ExecutableChallengeStage.digestWords wire.hPiop ++ decsRows).flatMap
      (encodeLE 8)⟩
  have piopNormalized := current_final_normalized_payload ns transcript
  have transcriptHash : transcript.hashFpp = execution.hashFpp := by
    have projected := congrArg
      SmzaRp05ExecutableFinalVerifier.ReconstructedTranscript.hashFpp
      execution.reconstructed
    simpa [SmzaRp05ExecutableReconstruction.reconstruct] using projected.symm
  have piopNext : globalOnlineNext ns .piop
      (SmzaRp05ExecutableFinalVerifier.finalInput transcript) =
      some [(.fpp, execution.hashFpp)] := by
    simpa [transcriptHash] using current_final_piop_edge ns transcript
  obtain ⟨fppInput, fppBytes, selectedAsk, _fppFrame, fppNormalized,
      fppNext, suffixWords⟩ :=
    successful_response_program_has_current_fpp_edge ns pcs.post.root execution.decs
      (pcs.rows.map fun row => row.map SmzaRp05ExecutableRestore.toWord)
      (SmzaRp05PcsHashFppMiddle.gammaRows pcs.post)
      (pcs.decsPoints.map fun point => SmzaRp05ExecutableRestore.toWord point)
      (statementBindingWords statement)
      (SmzaRp05ExecutablePcsClosureStatement.statement_binding_word_count statement)
      pcs.hashProgram pcs.responseBuilt
  have fppValue : oracle fppInput = execution.hashFpp := by
    have executed := pcs.hashExecuted
    rw [selectedAsk] at executed
    simpa [ask, Program.eval] using executed
  have fppHashMember : (fppInput, execution.hashFpp) ∈
      (pcs.hashProgram.record oracle).2 := by
    rw [selectedAsk]
    simp [ask, Program.record, fppValue]
  have fppFull := hashRecordRetained (fppInput, execution.hashFpp) fppHashMember
  let fppPayload : Payload := ⟨.fpp, fppBytes⟩
  obtain ⟨treeRoot, rootNormalized, rootStatement, rootNext, rootVerifierMember⟩ :=
    successful_pcs_root_query_readback ns dsl statement pending nonce wire oracle
      transcript execution pcs transcriptSuccess
  let rootInput := SmzaRp05ExecutableMerkleVerifier.rootInput
    pcs.merkleInput.salt pcs.merkleInput.binding treeRoot
  let rootPayload : Payload := ⟨.root,
    pcs.merkleInput.salt ++ List.ofFn treeRoot ++ pcs.merkleInput.binding⟩
  have rootChallengeNone : parseStageQuery rootInput = none := by
    cases parsed : parseStageQuery rootInput with
    | none => rfl
    | some query =>
        have impossible := parse_stage_query_global_payload_none ns rootInput query parsed
        rw [rootNormalized] at impossible
        cases impossible
  have rootFull : (rootInput, pcs.post.root) ∈ fullRecords :=
    nonchallengeRetained (rootInput, pcs.post.root) rootVerifierMember rootChallengeNone
  have retainFiltered : ∀ (input : RawInput) (output : RawDigest) (payload : Payload),
      globalNormalizedPayload ns input = some payload → payload.kind ≠ .leaf →
      (input, output) ∈ fullRecords → (input, output) ∈ filteredRecords := by
    intro input output payload normalized notLeaf fullMember
    exact actual_nonleaf_wrapper_survives_filtered_view ns statement fullRecords
      filteredRecords input output payload normalized notLeaf fullMember filteredRecordsEq
  have decsFiltered := retainFiltered pcs.openingInput pcs.openingDigest decsPayload
    decsNormalized (by change V8SmzaOracleParser.Kind.decs ≠
      V8SmzaOracleParser.Kind.leaf; decide) openingFull
  have piopFiltered := retainFiltered
    (SmzaRp05ExecutableFinalVerifier.finalInput transcript) wire.hPiop
    ⟨.piop, SmzaRp05ExecutableFinalVerifier.finalPayload transcript⟩
    piopNormalized (by change V8SmzaOracleParser.Kind.piop ≠
      V8SmzaOracleParser.Kind.leaf; decide) finalFull
  have fppFiltered := retainFiltered fppInput execution.hashFpp fppPayload
    fppNormalized (by change V8SmzaOracleParser.Kind.fpp ≠
      V8SmzaOracleParser.Kind.leaf; decide) fppFull
  have rootFiltered := retainFiltered rootInput pcs.post.root rootPayload
    rootNormalized (by change V8SmzaOracleParser.Kind.root ≠
      V8SmzaOracleParser.Kind.leaf; decide) rootFull
  have fppStatement : fppBytes.drop 16304 = statement.toBytes := by
    rw [suffixWords]
    exact statement_binding_words_encode_exact statement
  have statementCanonical : ns.canonicalPreamble statement.toBytes = true := by
    have core := SmzaRp05ExecutableChallengeStage.post_merkle_has_executed_core
      ns oracle pcs.merkleInput pcs.post pcs.postExecuted
    obtain ⟨shapeOk, _root, _recorded⟩ :=
      SmzaRp05CurrentAcceptedOuterReadback.successful_merkle_root_recorded
        ns oracle pcs.merkleInput pcs.post.root core.1
    have bindingEq : pcs.merkleInput.binding = statement.toBytes := by
      have built := pcs.inputBuilt
      unfold SmzaRp05PcsMerklePayload.makeMerkleInput at built
      split at built
      · simp at built
      · have fields := Option.some.inj built
        exact (congrArg SmzaRp05ExecutableMerkleVerifier.Input.binding fields).symm
    have shape := shapeOk
    simp only [SmzaRp05ExecutableMerkleVerifier.shapeValid, Bool.and_eq_true,
      decide_eq_true_eq] at shape
    simpa [bindingEq] using shape.1
  have rootValid : (payloadNext .root rootPayload).isSome := by
    have rootEdge : payloadNext .root rootPayload = some [(.tree 23, treeRoot)] := by
      have next := rootNext
      unfold globalOnlineNext at next
      rw [rootNormalized] at next
      exact next
    rw [rootEdge]
    rfl
  let target : Role → V8SmzaOracleParser.Stage × RawDigest := fun selected =>
    match selected with
    | .decsMatrix => (.root, pcs.post.root)
    | .piopMatrix => (.fpp, execution.hashFpp)
    | .piopOpening => (.piop, wire.hPiop)
    | .decsSample => (.decs, pcs.openingDigest)
  have targets : target .decsMatrix = (.root, pcs.post.root) ∧
      target .piopMatrix = (.fpp, execution.hashFpp) ∧
      target .piopOpening = (.piop, wire.hPiop) ∧
      target .decsSample = (.decs, pcs.openingDigest) :=
    ⟨rfl, rfl, rfl, rfl⟩
  have outer := current_outer_readback_of_recorded_chain ns filteredRecords
    collisionFree pcs.openingDigest wire.hPiop execution.hashFpp pcs.post.root
    pcs.openingInput (SmzaRp05ExecutableFinalVerifier.finalInput transcript)
    fppInput rootInput decsPayload
    ⟨.piop, SmzaRp05ExecutableFinalVerifier.finalPayload transcript⟩
    fppPayload rootPayload decsFiltered piopFiltered fppFiltered rootFiltered
    decsNormalized piopNormalized fppNormalized rootNormalized
    rfl rfl rfl rfl decsNext piopNext fppNext rootValid statement.toBytes
    rootStatement fppStatement statementCanonical statementCanonical fuel enough
    target targets
  have inner := current_inner_readback_of_recorded_chain ns filteredRecords
    collisionFree pcs.openingDigest wire.hPiop execution.hashFpp pcs.post.root
    pcs.openingInput (SmzaRp05ExecutableFinalVerifier.finalInput transcript) fppInput
    decsFiltered piopFiltered fppFiltered decsNext piopNext fppNext fuel enough
    target targets
  exact ⟨outer, inner⟩

/-- One accepted grouped branch supplies its actual staged execution and the
four outer/inner role readbacks on the exact challenge-erased,
one-statement-filtered database view. Only the four causal wrapper records
are transported into that view. `collisionFree` is the explicit collision
arm boundary for the current classifier; no all-log filtered-retention or
independent trace-equality premise is used. -/
theorem accepted_grouped_branch_supplies_filtered_role_traces
    (producer : Program ExistingProofFieldView)
    (ns : Namespace) (dsl : RelationDsl) (statement : Statement)
    (pending : Bool) (nonce : Fin (2 ^ 32))
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
    [Fintype RawDigest] (fallback : RawDigest) (fuel : Nat) (enough : 28 ≤ fuel)
    (collisionFree : RecordsCollisionFree
      (oneStatementFilter (globalLeafStatement ns) statement.toBytes
        (eraseChallengeRecords
          (rawRecords
            (fun key => groupRepresentative
              (included
                (producer.bind fun wire => verifierProgram ns dsl statement pending nonce wire)
                key))
            (vectorOutputBytes groupZero) database)))) :
    let actualProgram := producer.bind fun wire =>
      verifierProgram ns dsl statement pending nonce wire
    let oracle := finiteGroupedDatabaseOracle actualProgram database fallback
    let filteredRecords := oneStatementFilter (globalLeafStatement ns) statement.toBytes
      (eraseChallengeRecords
        (rawRecords (fun key => groupRepresentative (included actualProgram key))
          (vectorOutputBytes groupZero) database))
    ∃ wire transcript,
      ∃ execution : ExecutionStages ns dsl statement pending statement.toBytes
        (statementBindingWords statement) nonce wire oracle transcript,
      ∃ pcs : PcsStages ns execution.openingPending wire.hPiop
        (SmzaRp05PcsToFinalProgram.sameProofRows execution.middle.pcs execution.piop)
        execution.decs
        (List.ofFn fun j : Fin 6 => V8Smz9PiopReconstruction.points execution.opening j)
        wire.salt statement.toBytes (statementBindingWords statement)
        wire.tapes wire.paths oracle execution.hashFpp execution.pcsPending,
      (∀ role, preambleFromTrace ns role
        (V8Smz9CoherentMerkleGeometry.extract (globalOnlineNext ns) filteredRecords fuel
          (currentOuterTarget pcs.openingDigest wire.hPiop execution.hashFpp
            pcs.post.root role).1
          (currentOuterTarget pcs.openingDigest wire.hPiop execution.hashFpp
            pcs.post.root role).2) = some statement.toBytes) ∧
      let innerTrace := V8Smz9CoherentMerkleGeometry.extract (globalOnlineNext ns)
        filteredRecords fuel .decs pcs.openingDigest
      ∀ role, V8Smz9CoherentMerkleGeometry.extract (globalOnlineNext ns) filteredRecords fuel
        (currentOuterTarget pcs.openingDigest wire.hPiop execution.hashFpp
          pcs.post.root role).1
        (currentOuterTarget pcs.openingDigest wire.hPiop execution.hashFpp
          pcs.post.root role).2 = SmzaRp05AcceptedRoleLabels.causalTrace innerTrace role := by
  classical
  let actualProgram := producer.bind fun wire =>
    verifierProgram ns dsl statement pending nonce wire
  let oracle := finiteGroupedDatabaseOracle actualProgram database fallback
  let fullRecords := rawRecords
    (fun key => groupRepresentative (included actualProgram key))
    (vectorOutputBytes groupZero) database
  let erasedRecords := eraseChallengeRecords fullRecords
  let filteredRecords := oneStatementFilter
    (globalLeafStatement ns) statement.toBytes erasedRecords
  have filteredRecordsEq : filteredRecords = oneStatementFilter
      (globalLeafStatement ns) statement.toBytes (eraseChallengeRecords fullRecords) := rfl
  obtain ⟨wire, _producerSuccess, verifierAccepted, nonchallengeRetained⟩ :=
    accepted_grouped_claims_supply_verifier_replay producer ns dsl statement pending nonce
      branch accepted database claims fallback
  obtain ⟨transcript, transcriptSuccess, _clean, _rootEq, _finalMember⟩ :=
    SmzaRp05ExecutablePcsClosure.accepted_execution_constructs_transcript ns dsl statement
      pending statement.toBytes (statementBindingWords statement) nonce wire oracle
      verifierAccepted
  obtain ⟨execution⟩ :=
    SmzaRp05ExecutablePcsClosure.transcript_execution_has_stages ns dsl statement pending
      statement.toBytes (statementBindingWords statement) nonce wire oracle transcript
      transcriptSuccess
  obtain ⟨pcs⟩ :=
    SmzaRp05ExecutablePcsClosureStages.pcs_execution_has_stages ns execution.openingPending
      wire.hPiop
      (SmzaRp05PcsToFinalProgram.sameProofRows execution.middle.pcs execution.piop)
      execution.decs
      (List.ofFn fun j : Fin 6 => V8Smz9PiopReconstruction.points execution.opening j)
      wire.salt statement.toBytes (statementBindingWords statement)
      wire.tapes wire.paths oracle execution.hashFpp execution.pcsPending
      execution.pcsExecuted
/-
  obtain ⟨openingFull, finalFull, hashRecordRetained⟩ :=
    accepted_execution_causal_record_memberships ns dsl statement pending nonce wire
      oracle transcript execution pcs fullRecords verifierAccepted transcriptSuccess
      nonchallengeRetained
  obtain ⟨decsRows, _rowsFormed, _framed, decsNormalized, decsNext⟩ :=
    current_decs_opening_edge406 ns wire.hPiop pcs.heads
      execution.middle.pcs.rcombiTails pcs.openingInput pcs.openingBuilt
  let decsPayload : Payload := ⟨.decs,
    (SmzaRp05ExecutableChallengeStage.digestWords wire.hPiop ++ decsRows).flatMap
      (encodeLE 8)⟩
  have piopNormalized := current_final_normalized_payload ns transcript
  have transcriptHash : transcript.hashFpp = execution.hashFpp := by
    have projected := congrArg
      SmzaRp05ExecutableFinalVerifier.ReconstructedTranscript.hashFpp
      execution.reconstructed
    simpa [SmzaRp05ExecutableReconstruction.reconstruct] using projected.symm
  have piopNext : globalOnlineNext ns .piop
      (SmzaRp05ExecutableFinalVerifier.finalInput transcript) =
      some [(.fpp, execution.hashFpp)] := by
    simpa [transcriptHash] using current_final_piop_edge ns transcript
  obtain ⟨fppInput, fppBytes, selectedAsk, _fppFrame, fppNormalized,
      fppNext, suffixWords⟩ :=
    successful_response_program_has_current_fpp_edge ns pcs.post.root execution.decs
      (pcs.rows.map fun row => row.map SmzaRp05ExecutableRestore.toWord)
      (SmzaRp05PcsHashFppMiddle.gammaRows pcs.post)
      (pcs.decsPoints.map fun point => SmzaRp05ExecutableRestore.toWord point)
      (statementBindingWords statement)
      (SmzaRp05ExecutablePcsClosureStatement.statement_binding_word_count statement)
      pcs.hashProgram pcs.responseBuilt
  have fppValue : oracle fppInput = execution.hashFpp := by
    have executed := pcs.hashExecuted
    rw [selectedAsk] at executed
    simpa [ask, Program.eval] using executed
  have fppHashMember : (fppInput, execution.hashFpp) ∈
      (pcs.hashProgram.record oracle).2 := by
    rw [selectedAsk]
    simp [ask, Program.record, fppValue]
  have fppFull := hashRecordRetained (fppInput, execution.hashFpp) fppHashMember
  let fppPayload : Payload := ⟨.fpp, fppBytes⟩
  obtain ⟨treeRoot, rootNormalized, rootStatement, rootNext, rootVerifierMember⟩ :=
    successful_pcs_root_query_readback ns dsl statement pending nonce wire oracle
      transcript execution pcs transcriptSuccess
  let rootInput := SmzaRp05ExecutableMerkleVerifier.rootInput
    pcs.merkleInput.salt pcs.merkleInput.binding treeRoot
  let rootPayload : Payload := ⟨.root,
    pcs.merkleInput.salt ++ List.ofFn treeRoot ++ pcs.merkleInput.binding⟩
  have rootChallengeNone : parseStageQuery rootInput = none := by
    cases parsed : parseStageQuery rootInput with
    | none => rfl
    | some query =>
        have impossible := parse_stage_query_global_payload_none ns rootInput query parsed
        rw [rootNormalized] at impossible
        cases impossible
  have rootFull : (rootInput, pcs.post.root) ∈ fullRecords :=
    nonchallengeRetained (rootInput, pcs.post.root) rootVerifierMember rootChallengeNone
  have retainFiltered : ∀ (input : RawInput) (output : RawDigest) (payload : Payload),
      globalNormalizedPayload ns input = some payload → payload.kind ≠ .leaf →
      (input, output) ∈ fullRecords → (input, output) ∈ filteredRecords := by
    intro input output payload normalized notLeaf fullMember
    exact actual_nonleaf_wrapper_survives_filtered_view ns statement fullRecords
      filteredRecords input output payload normalized notLeaf fullMember filteredRecordsEq
  have decsFiltered := retainFiltered pcs.openingInput pcs.openingDigest decsPayload
    decsNormalized (by decide) openingFull
  have piopFiltered := retainFiltered
    (SmzaRp05ExecutableFinalVerifier.finalInput transcript) wire.hPiop
    ⟨.piop, SmzaRp05ExecutableFinalVerifier.finalPayload transcript⟩
    piopNormalized (by decide) finalFull
  have fppFiltered := retainFiltered fppInput execution.hashFpp fppPayload
    fppNormalized (by decide) fppFull
  have rootFiltered := retainFiltered rootInput pcs.post.root rootPayload
    rootNormalized (by decide) rootFull
  have fppStatement : fppBytes.drop 16304 = statement.toBytes := by
    rw [suffixWords]
    exact statement_binding_words_encode_exact statement
  have statementCanonical : ns.canonicalPreamble statement.toBytes = true := by
    have core := SmzaRp05ExecutableChallengeStage.post_merkle_has_executed_core
      ns oracle pcs.merkleInput pcs.post pcs.postExecuted
    obtain ⟨shapeOk, _root, _recorded⟩ :=
      SmzaRp05CurrentAcceptedOuterReadback.successful_merkle_root_recorded
        ns oracle pcs.merkleInput pcs.post.root core.1
    have bindingEq : pcs.merkleInput.binding = statement.toBytes := by
      have built := pcs.inputBuilt
      unfold SmzaRp05PcsMerklePayload.makeMerkleInput at built
      split at built
      · simp at built
      · have fields := Option.some.inj built
        exact (congrArg SmzaRp05ExecutableMerkleVerifier.Input.binding fields).symm
    have shape := shapeOk
    simp only [SmzaRp05ExecutableMerkleVerifier.shapeValid, Bool.and_eq_true,
      decide_eq_true_eq] at shape
    simpa [bindingEq] using shape.1
  have rootValid : (payloadNext .root rootPayload).isSome := by
    have rootEdge : payloadNext .root rootPayload = some [(.tree 23, treeRoot)] := by
      have next := rootNext
      unfold globalOnlineNext at next
      rw [rootNormalized] at next
      exact next
    rw [rootEdge]
    rfl
  let target : Role → V8SmzaOracleParser.Stage × RawDigest := fun selected =>
    match selected with
    | .decsMatrix => (.root, pcs.post.root)
    | .piopMatrix => (.fpp, execution.hashFpp)
    | .piopOpening => (.piop, wire.hPiop)
    | .decsSample => (.decs, pcs.openingDigest)
  have targets : target .decsMatrix = (.root, pcs.post.root) ∧
      target .piopMatrix = (.fpp, execution.hashFpp) ∧
      target .piopOpening = (.piop, wire.hPiop) ∧
      target .decsSample = (.decs, pcs.openingDigest) := by
    exact ⟨rfl, rfl, rfl, rfl⟩
  have outer := current_outer_readback_of_recorded_chain ns filteredRecords
    collisionFree pcs.openingDigest wire.hPiop execution.hashFpp pcs.post.root
    pcs.openingInput (SmzaRp05ExecutableFinalVerifier.finalInput transcript)
    fppInput rootInput decsPayload
    ⟨.piop, SmzaRp05ExecutableFinalVerifier.finalPayload transcript⟩
    fppPayload rootPayload decsFiltered piopFiltered fppFiltered rootFiltered
    decsNormalized piopNormalized fppNormalized rootNormalized
    rfl rfl rfl rfl decsNext piopNext fppNext rootValid statement.toBytes
    rootStatement fppStatement statementCanonical statementCanonical fuel enough
    target targets
  have inner := current_inner_readback_of_recorded_chain ns filteredRecords
    collisionFree pcs.openingDigest wire.hPiop execution.hashFpp pcs.post.root
    pcs.openingInput (SmzaRp05ExecutableFinalVerifier.finalInput transcript) fppInput
    decsFiltered piopFiltered fppFiltered decsNext piopNext fppNext fuel enough
    target targets
-/
  have exactStageTraces := current_stages_supply_filtered_role_traces
    producer ns dsl statement pending nonce database fallback wire transcript execution pcs
    verifierAccepted transcriptSuccess fuel enough collisionFree nonchallengeRetained
  exact ⟨wire, transcript, execution, pcs, exactStageTraces⟩

end
end HegemonCrypto.SmallWood.SmzaRp05CurrentAcceptedFilteredRoleTraces
