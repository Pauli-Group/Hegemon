import SmzaRp05CurrentAcceptedPiopExtractionFailureEvent
import SmzaRp05CurrentFullOrRoleExtraction
import SmzaRp05CurrentAcceptedMatrixFailureEvent
import SmzaRp05ConditionedExecution
import SmzaRp05CurrentAdviceDependentPhysicalMass
import SmzaRp05CurrentAcceptedXViewRoleCoverage
import SmzaRp05CurrentSelectedXViewClaims
import SmzaRp05CurrentSelectedCurrentAdviceEventMass
import SmzaRp05CurrentSelectedChallengeClaims
import SmzaRp05CurrentGroupedContext
import SmzaRp05CurrentGroupedClaimRetention
import SmzaRp05CurrentFiniteGroupedProgram
import SmzaRp05Current406ActiveFiberEvent
import SmzaRp05Current406EventSpec
import SmzaRp05CurrentMatrixRoleEvent
import SmzaRp05CurrentSourceRoleEvent
import SmzaRp05CurrentAcceptedDecsSampleOutputBinding
import SmzaRp05CurrentAcceptedQuerySupport
import SmzaRp05CurrentAcceptedDecsSourceEvent
import SmzaRp05CurrentAcceptedDecsSourceCoverage
import SmzaRp05CurrentAcceptedFilteredCausalSourceBad
import SmzaRp05CurrentAcceptedFilteredCausalRetention
import SmzaRp05CurrentAcceptedFixedEarlierCells
import SmzaRp05AdaptiveRetainedAdviceTransport
import SmzaRp05CurrentExecutedEarlierAdvice
import SmzaRp05CurrentAcceptedCausalPayloads
import SmzaRp05CurrentAcceptedCausalPayloadIdentity
import SmzaRp05CurrentCausalNonchallengeRetention
import SmzaRp05CurrentAcceptedNonleafRoleReadback
import SmzaRp05CurrentAcceptedFilteredRoleTraces
import SmzaRp05CurrentExecutedSamplerSemantics
import SmzaRp05CurrentGroupedOracleVector
import SmzaRp05CurrentGroupedRoutes
import SmzaRp05CurrentRoleLabels
import SmzaRp05ChallengeRecordErasure
import SmzaRp04StatementRecordFilter
import SmzaRp05FilteredReadback
import SmzaRp05FilteredDecoderInstability
import SmzaRp05CurrentTracePrefixes406
import SmzaRp05AcceptedRoleLabels
import SmzaRp05CertifiedReplayScheduleFrames
import SmzaRp05CurrentAcceptedRoleQueryReadback
import SmzaRp05ExecutableChallengeStage
import SmzaRp05FilteredDecoderInstability
import SmzaRp05ExecutablePcsClosureClean
import SmzaRp05ExecutablePcsClosureSampling
import SmzaRp05OrdinarySoundnessExecution
import SmzaRp05GeneratedCertificates
import SmzaRp05ContextAmbientSupport
import SmzaRp04StatementRecordFilter
import SmzaRp05AcceptedRoleLabels
import SmzaRp05ChallengeRecordErasure
import SmzaRp05ConcreteSuffix
import SmzaRp05CurrentAcceptedDecsMatrixCallReadback
import SmzaRp05CurrentAcceptedDecsOutputBinding
import SmzaRp05CurrentAcceptedFilteredRoleTraces
import SmzaRp05CurrentAcceptedMatrixEventReadback
import SmzaRp05CurrentAcceptedNonleafRoleReadback
import SmzaRp05CurrentAcceptedOuterReadback
import SmzaRp05CurrentAcceptedRoleQueryReadback
import SmzaRp05CurrentCausalNonchallengeRetention
import SmzaRp05CurrentDecsFrameReadback
import SmzaRp05CurrentDecsGroupedTarget
import SmzaRp05CurrentExecutedDecsCoefficients
import SmzaRp05CurrentFiniteGroupedProgram
import SmzaRp05CurrentFixedAdviceOpeningSource
import SmzaRp05CurrentFixedEarlierAdvice
import SmzaRp05CurrentFppFrameReadback
import SmzaRp05CurrentGroupedClaimRetention
import SmzaRp05CurrentGroupedContext
import SmzaRp05CurrentGroupedOracleVector
import SmzaRp05CurrentGroupedRoutes
import SmzaRp05CurrentGroupedVerifierReplay
import SmzaRp05CurrentPiopFrameReadback
import SmzaRp05ExecutablePcsClosureSampling
import SmzaRp05FilteredReadback
import SmzaRp05GroupedSuffix

/-! # Accepted current outer readback on the raw nonleaf view

The current statement-filter collision-free relation contains every
challenge-erased nonleaf wrapper.  The four actual wrapper records from one
accepted staged execution therefore suffice for the recorded-chain argument
on that smaller view.  Challenge records are removed only for that proof;
the decoder-inertness theorem transports the extracted preambles back to the
actual raw nonleaf view. -/

namespace HegemonCrypto.SmallWood.SmzaRp05CurrentAcceptedNonleafRoleReadbackAmbient

open HegemonCrypto.CanonicalBytes (Byte encodeLE)
open HegemonCrypto.FiniteOracleDatabase (Database)
open SmzaRp05ExecutableMerkleVerifier (Program Oracle)
open SmzaRp05ExecutablePcsClosure (ExecutionStages transcriptProgram)
open SmzaRp05ExecutablePcsClosureStages (PcsStages)
open SmzaRp05ExecutablePcsClosureStatement (statementBindingWords verifierProgram)
open SmzaRp05PhysicalAcceptedReplayLite (rawLog)
open SmzaRp05CurrentCausalNonchallengeRetention
  (accepted_execution_causal_record_memberships)
open SmzaRp05CurrentAcceptedOuterReadback (successful_pcs_root_query_readback)
open SmzaRp05CurrentDecsFrameReadback (current_decs_opening_edge406)
open SmzaRp05CurrentFppFrameReadback (successful_response_program_has_current_fpp_edge)
open SmzaRp05CurrentPiopFrameReadback
  (current_final_normalized_payload current_final_piop_edge)
open SmzaRp05AcceptedRoleLabels (current_outer_readback_of_recorded_chain)
open SmzaRp05CurrentGroupedClaimRetention (groupedDecode)
open SmzaRp05CurrentFiniteGroupedProgram (Key included)
open SmzaRp05CurrentGroupedOracleVector (finiteGroupedDatabaseOracle)
open SmzaRp05GroupedSuffix (groupRepresentative groupZero GroupCounter)
open SmzaRp05CurrentProofWireProgram (ExistingProofFieldView)
open SmzaRp05RelationRefinement (RelationDsl)
open SmzaRp05LeafNamespace (Namespace)
open SmzaRp05FilteredReadback (globalLeafStatement)
open SmzaRp05ChallengeRecordErasure
  (eraseChallengeRecords global_extract_filtered_erase_challenge
    parse_stage_query_global_payload_none)
open SmzaRp04StatementRecordFilter (oneStatementFilter nonleafFilter)
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

noncomputable section
set_option autoImplicit false
set_option maxRecDepth 12000
set_option maxHeartbeats 4000000

private theorem leaf_none_of_normalized_nonleaf
    (ns : Namespace) (input : RawInput) (normalized : Payload)
    (read : globalNormalizedPayload ns input = some normalized)
    (notLeaf : normalized.kind ≠ .leaf) :
    globalLeafStatement ns input = none := by
  cases framed : V8SmzaOracleParser.parseFramed input with
  | none => simp [globalNormalizedPayload, framed] at read
  | some frame =>
      rcases frame with ⟨_role, bytes⟩
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
          have someEq : some currentLeaf.normalized = some normalized := by
            simpa [SmzaRp05LeafNamespace.normalizedPayload, leaf] using normalizedRead
          have kindEq : normalized.kind = .leaf := by
            rw [← Option.some.inj someEq]
            rfl
          exact (notLeaf kindEq).elim

private theorem parse_none_of_normalized
    (ns : Namespace) (input : RawInput) (normalized : Payload)
    (read : globalNormalizedPayload ns input = some normalized) :
    parseStageQuery input = none := by
  cases parsed : parseStageQuery input with
  | none => rfl
  | some query =>
      have impossible := parse_stage_query_global_payload_none ns input query parsed
      rw [read] at impossible
      cases impossible

private theorem nonleaf_extract_eq_after_challenge_erasure
    (ns : Namespace) (records : Records) [Fintype RawDigest]
    (fuel : Nat) (stage : V8SmzaOracleParser.Stage) (target : RawDigest) :
    V8Smz9CoherentMerkleGeometry.extract (globalOnlineNext ns)
        (nonleafFilter (globalLeafStatement ns) records) fuel stage target =
      V8Smz9CoherentMerkleGeometry.extract (globalOnlineNext ns)
        (nonleafFilter (globalLeafStatement ns) (eraseChallengeRecords records))
        fuel stage target := by
  have erasedEq := global_extract_filtered_erase_challenge ns records
    (fun input => globalLeafStatement ns input = none) fuel stage target
  convert erasedEq.symm using 1 <;> congr 1 <;> ext record <;>
    simp [nonleafFilter]

theorem accepted_stages_raw_nonleaf_outer_preambles
    (program : Program Unit)
    (ns : Namespace) (dsl : RelationDsl) (statement : Statement)
    (pending : Bool) (nonce : Fin (2 ^ 32))
    (database : Database
      (Key program)
      (VectorOutput GroupCounter))
    (fallback : RawDigest)
    (wire : ExistingProofFieldView)
    (transcript : SmzaRp05ExecutableFinalVerifier.ReconstructedTranscript)
    (execution : ExecutionStages ns dsl statement pending statement.toBytes
      (statementBindingWords statement) nonce wire
      (finiteGroupedDatabaseOracle
        program
        database fallback) transcript)
    (pcs : PcsStages ns execution.openingPending wire.hPiop
      (SmzaRp05PcsToFinalProgram.sameProofRows execution.middle.pcs execution.piop)
      execution.decs
      (List.ofFn fun j : Fin 6 => V8Smz9PiopReconstruction.points execution.opening j)
      wire.salt statement.toBytes (statementBindingWords statement)
      wire.tapes wire.paths
      (finiteGroupedDatabaseOracle
        program
        database fallback) execution.hashFpp execution.pcsPending)
    (verifierAccepted : (verifierProgram ns dsl statement pending nonce wire).eval
      (finiteGroupedDatabaseOracle
        program
        database fallback) = some ())
    (transcriptSuccess : (transcriptProgram ns dsl statement pending statement.toBytes
      (statementBindingWords statement) nonce wire).eval
      (finiteGroupedDatabaseOracle
        program
        database fallback) = some transcript)
    [Fintype RawDigest] (fuel : Nat) (enough : 28 ≤ fuel)
    (collisionFree : RecordsCollisionFree
      (oneStatementFilter (globalLeafStatement ns) statement.toBytes
        (eraseChallengeRecords
          (rawRecords
            (fun key => groupRepresentative
              (included
                program
                key))
            (vectorOutputBytes groupZero) database))))
    (nonchallengeRetained : ∀ call,
      call ∈ ((verifierProgram ns dsl statement pending nonce wire).record
        (finiteGroupedDatabaseOracle
          program
          database fallback)).2 →
      parseStageQuery call.1 = none →
      call ∈ rawRecords
        (fun key => groupRepresentative
          (included
            program
            key))
        (vectorOutputBytes groupZero) database) :
    ∀ role, preambleFromTrace ns role
      (V8Smz9CoherentMerkleGeometry.extract (globalOnlineNext ns)
        (nonleafFilter (globalLeafStatement ns)
          (rawRecords
            (fun key => groupRepresentative
              (included
                program
                key))
            (vectorOutputBytes groupZero) database)) fuel
        (match role with
          | .decsMatrix => .root
          | .piopMatrix => .fpp
          | .piopOpening => .piop
          | .decsSample => .decs)
        (match role with
          | .decsMatrix => pcs.post.root
          | .piopMatrix => execution.hashFpp
          | .piopOpening => wire.hPiop
          | .decsSample => pcs.openingDigest)) = some statement.toBytes := by
  classical
  let actualProgram := program
  let oracle := finiteGroupedDatabaseOracle actualProgram database fallback
  let fullRecords := rawRecords
    (fun key => groupRepresentative (included actualProgram key))
    (vectorOutputBytes groupZero) database
  let erasedNonleafRecords := nonleafFilter (globalLeafStatement ns)
    (eraseChallengeRecords fullRecords)
  have erasedNonleafCollisionFree : RecordsCollisionFree erasedNonleafRecords := by
    intro input other output left right
    have left' : (input, output) ∈ erasedNonleafRecords := left
    have right' : (other, output) ∈ erasedNonleafRecords := right
    rcases Finset.mem_filter.mp left' with ⟨leftErased, leftNonleaf⟩
    rcases Finset.mem_filter.mp right' with ⟨rightErased, rightNonleaf⟩
    rcases Finset.mem_filter.mp leftErased with ⟨leftFull, leftNoChallenge⟩
    rcases Finset.mem_filter.mp rightErased with ⟨rightFull, rightNoChallenge⟩
    apply collisionFree input other output
    · exact Finset.mem_filter.mpr ⟨
        Finset.mem_filter.mpr ⟨leftFull, leftNoChallenge⟩, Or.inl leftNonleaf⟩
    · exact Finset.mem_filter.mpr ⟨
        Finset.mem_filter.mpr ⟨rightFull, rightNoChallenge⟩, Or.inl rightNonleaf⟩
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
    simpa [SmzaRp05ExecutableMerkleVerifier.ask, Program.eval] using executed
  have fppHashMember : (fppInput, execution.hashFpp) ∈
      (pcs.hashProgram.record oracle).2 := by
    rw [selectedAsk]
    simp [SmzaRp05ExecutableMerkleVerifier.ask, Program.record, fppValue]
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
    exact parse_none_of_normalized ns rootInput rootPayload rootNormalized
  have rootFull : (rootInput, pcs.post.root) ∈ fullRecords :=
    nonchallengeRetained (rootInput, pcs.post.root) rootVerifierMember rootChallengeNone
  have rootLeafNone := leaf_none_of_normalized_nonleaf ns rootInput rootPayload
    rootNormalized (by
      change V8SmzaOracleParser.Kind.root ≠ V8SmzaOracleParser.Kind.leaf
      decide)
  have rootErased : (rootInput, pcs.post.root) ∈ erasedNonleafRecords := by
    exact Finset.mem_filter.mpr ⟨
      Finset.mem_filter.mpr ⟨rootFull, by simp [rootChallengeNone]⟩, rootLeafNone⟩
  have fppChallengeNone := parse_none_of_normalized ns fppInput fppPayload fppNormalized
  have fppLeafNone := leaf_none_of_normalized_nonleaf ns fppInput fppPayload
    fppNormalized (by
      change V8SmzaOracleParser.Kind.fpp ≠ V8SmzaOracleParser.Kind.leaf
      decide)
  have fppErased : (fppInput, execution.hashFpp) ∈ erasedNonleafRecords := by
    exact Finset.mem_filter.mpr ⟨
      Finset.mem_filter.mpr ⟨
        fppFull, by simp [fppChallengeNone]⟩, fppLeafNone⟩
  have piopErased :
      (SmzaRp05ExecutableFinalVerifier.finalInput transcript, wire.hPiop) ∈
        erasedNonleafRecords := by
    let piopPayload : Payload := ⟨.piop,
      SmzaRp05ExecutableFinalVerifier.finalPayload transcript⟩
    have challengeNone := parse_none_of_normalized ns
      (SmzaRp05ExecutableFinalVerifier.finalInput transcript) piopPayload piopNormalized
    have leafNone := leaf_none_of_normalized_nonleaf ns
      (SmzaRp05ExecutableFinalVerifier.finalInput transcript) piopPayload
      piopNormalized (by
        change V8SmzaOracleParser.Kind.piop ≠ V8SmzaOracleParser.Kind.leaf
        decide)
    have member :
        (SmzaRp05ExecutableFinalVerifier.finalInput transcript, wire.hPiop) ∈ fullRecords :=
      finalFull
    exact Finset.mem_filter.mpr ⟨
      Finset.mem_filter.mpr ⟨
        member, by simp [challengeNone]⟩, leafNone⟩
  have decsErased : (pcs.openingInput, pcs.openingDigest) ∈ erasedNonleafRecords := by
    have leafNone := leaf_none_of_normalized_nonleaf ns pcs.openingInput decsPayload
      decsNormalized (by
        change V8SmzaOracleParser.Kind.decs ≠ V8SmzaOracleParser.Kind.leaf
        decide)
    have challengeNone := parse_none_of_normalized ns pcs.openingInput decsPayload decsNormalized
    exact Finset.mem_filter.mpr ⟨
      Finset.mem_filter.mpr ⟨
        openingFull, by simp [challengeNone]⟩, leafNone⟩
  have fppValid : (payloadNext .fpp fppPayload).isSome := by
    have next : payloadNext .fpp fppPayload = some [(.root, pcs.post.root)] := by
      have next := fppNext
      unfold globalOnlineNext at next
      rw [fppNormalized] at next
      exact next
    simp [next]
  have rootValid : (payloadNext .root rootPayload).isSome := by
    have next : payloadNext .root rootPayload = some [(.tree 23, treeRoot)] := by
      have next := rootNext
      unfold globalOnlineNext at next
      rw [rootNormalized] at next
      exact next
    simp [next]
  have decsCanonical : ns.canonicalPreamble statement.toBytes = true := by
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
  have fppStatement : fppBytes.drop 16304 = statement.toBytes := by
    rw [suffixWords]
    exact SmzaRp05CurrentAcceptedOuterReadback.statement_binding_words_encode_exact statement
  have rootCanonical : ns.canonicalPreamble statement.toBytes = true := decsCanonical
  have outer := current_outer_readback_of_recorded_chain ns erasedNonleafRecords
    erasedNonleafCollisionFree pcs.openingDigest wire.hPiop execution.hashFpp pcs.post.root
    pcs.openingInput (SmzaRp05ExecutableFinalVerifier.finalInput transcript)
    fppInput rootInput decsPayload
    ⟨.piop, SmzaRp05ExecutableFinalVerifier.finalPayload transcript⟩
    fppPayload rootPayload decsErased piopErased fppErased rootErased
    decsNormalized piopNormalized fppNormalized rootNormalized
    rfl rfl rfl rfl decsNext piopNext fppNext rootValid statement.toBytes
    rootStatement fppStatement rootCanonical rootCanonical fuel enough
    (fun role => match role with
      | .decsMatrix => (.root, pcs.post.root)
      | .piopMatrix => (.fpp, execution.hashFpp)
      | .piopOpening => (.piop, wire.hPiop)
      | .decsSample => (.decs, pcs.openingDigest))
    ⟨rfl, rfl, rfl, rfl⟩
  intro role
  have rawNonleaf_eq_erased (stage : V8SmzaOracleParser.Stage) (target : RawDigest) :
      V8Smz9CoherentMerkleGeometry.extract (globalOnlineNext ns)
          (nonleafFilter (globalLeafStatement ns) fullRecords) fuel stage target =
        V8Smz9CoherentMerkleGeometry.extract (globalOnlineNext ns)
          erasedNonleafRecords fuel stage target := by
    exact nonleaf_extract_eq_after_challenge_erasure ns fullRecords
      fuel stage target
  cases role with
  | decsMatrix =>
      change preambleFromTrace ns .decsMatrix
        (V8Smz9CoherentMerkleGeometry.extract (globalOnlineNext ns)
          (nonleafFilter (globalLeafStatement ns) fullRecords) fuel .root pcs.post.root) = _
      calc
        _ = preambleFromTrace ns .decsMatrix
            (V8Smz9CoherentMerkleGeometry.extract (globalOnlineNext ns)
              erasedNonleafRecords fuel .root pcs.post.root) :=
          congrArg (preambleFromTrace ns .decsMatrix)
            (rawNonleaf_eq_erased .root pcs.post.root)
        _ = some statement.toBytes := by
          simpa [erasedNonleafRecords] using outer .decsMatrix
  | piopMatrix =>
      change preambleFromTrace ns .piopMatrix
        (V8Smz9CoherentMerkleGeometry.extract (globalOnlineNext ns)
          (nonleafFilter (globalLeafStatement ns) fullRecords) fuel .fpp execution.hashFpp) = _
      calc
        _ = preambleFromTrace ns .piopMatrix
            (V8Smz9CoherentMerkleGeometry.extract (globalOnlineNext ns)
              erasedNonleafRecords fuel .fpp execution.hashFpp) :=
          congrArg (preambleFromTrace ns .piopMatrix)
            (rawNonleaf_eq_erased .fpp execution.hashFpp)
        _ = some statement.toBytes := by
          simpa [erasedNonleafRecords] using outer .piopMatrix
  | piopOpening =>
      change preambleFromTrace ns .piopOpening
        (V8Smz9CoherentMerkleGeometry.extract (globalOnlineNext ns)
          (nonleafFilter (globalLeafStatement ns) fullRecords) fuel .piop wire.hPiop) = _
      calc
        _ = preambleFromTrace ns .piopOpening
            (V8Smz9CoherentMerkleGeometry.extract (globalOnlineNext ns)
              erasedNonleafRecords fuel .piop wire.hPiop) :=
          congrArg (preambleFromTrace ns .piopOpening)
            (rawNonleaf_eq_erased .piop wire.hPiop)
        _ = some statement.toBytes := by
          simpa [erasedNonleafRecords] using outer .piopOpening
  | decsSample =>
      change preambleFromTrace ns .decsSample
        (V8Smz9CoherentMerkleGeometry.extract (globalOnlineNext ns)
          (nonleafFilter (globalLeafStatement ns) fullRecords) fuel .decs pcs.openingDigest) = _
      calc
        _ = preambleFromTrace ns .decsSample
            (V8Smz9CoherentMerkleGeometry.extract (globalOnlineNext ns)
              erasedNonleafRecords fuel .decs pcs.openingDigest) :=
          congrArg (preambleFromTrace ns .decsSample)
            (rawNonleaf_eq_erased .decs pcs.openingDigest)
        _ = some statement.toBytes := by
          simpa [erasedNonleafRecords] using outer .decsSample

end
end HegemonCrypto.SmallWood.SmzaRp05CurrentAcceptedNonleafRoleReadbackAmbient

/-! # Filtered current role-trace readback from one accepted branch

The four wrapper records are individually derived from one accepted grouped
verifier branch, normalized payload constructors, and the branch's claims
database. Each is a nonleaf frame, so it survives challenge erasure and the
one-statement filter. The theorem does not require retention of every
verifier-log call in the filtered view. -/

namespace HegemonCrypto.SmallWood.SmzaRp05CurrentAcceptedFilteredRoleTracesAmbient

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
    (program : Program Unit)
    (ns : Namespace) (dsl : RelationDsl) (statement : Statement)
    (pending : Bool) (nonce : Fin (2 ^ 32))
    (database : Database
      (Key program)
      (VectorOutput GroupCounter))
    (fallback : RawDigest)
    (wire : ExistingProofFieldView)
    (transcript : SmzaRp05ExecutableFinalVerifier.ReconstructedTranscript)
    (execution : ExecutionStages ns dsl statement pending statement.toBytes
      (statementBindingWords statement) nonce wire
      (finiteGroupedDatabaseOracle
        program
        database fallback) transcript)
    (pcs : PcsStages ns execution.openingPending wire.hPiop
      (SmzaRp05PcsToFinalProgram.sameProofRows execution.middle.pcs execution.piop)
      execution.decs
      (List.ofFn fun j : Fin 6 => V8Smz9PiopReconstruction.points execution.opening j)
      wire.salt statement.toBytes (statementBindingWords statement)
      wire.tapes wire.paths
      (finiteGroupedDatabaseOracle
        program
        database fallback) execution.hashFpp execution.pcsPending)
    (verifierAccepted : (verifierProgram ns dsl statement pending nonce wire).eval
      (finiteGroupedDatabaseOracle
        program
        database fallback) = some ())
    (transcriptSuccess : (transcriptProgram ns dsl statement pending statement.toBytes
      (statementBindingWords statement) nonce wire).eval
      (finiteGroupedDatabaseOracle
        program
        database fallback) = some transcript)
    [Fintype RawDigest] (fuel : Nat) (enough : 28 ≤ fuel)
    (collisionFree : RecordsCollisionFree
      (oneStatementFilter (globalLeafStatement ns) statement.toBytes
        (eraseChallengeRecords
          (rawRecords
            (fun key => groupRepresentative
              (included
                program
                key))
            (vectorOutputBytes groupZero) database))))
    (nonchallengeRetained : ∀ call,
      call ∈ ((verifierProgram ns dsl statement pending nonce wire).record
        (finiteGroupedDatabaseOracle
          program
          database fallback)).2 →
      parseStageQuery call.1 = none →
      call ∈ rawRecords
        (fun key => groupRepresentative
          (included
            program
            key))
        (vectorOutputBytes groupZero) database) :
    let actualProgram := program
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
  let actualProgram := program
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


end
end HegemonCrypto.SmallWood.SmzaRp05CurrentAcceptedFilteredRoleTracesAmbient

/-! # Same-stage grouped DECS matrix output binding

The accepted verifier branch's actual DECS coefficient-XOF vector is the
vector consumed by the current grouped DECS-matrix route, and that route
decodes to the sampled coefficients from the *supplied* post-Merkle execution.
No decoder-success or vector-equality premise is supplied. -/

namespace HegemonCrypto.SmallWood.SmzaRp05CurrentAcceptedDecsOutputBindingAmbient

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
    (producer : Program SmzaRp05ContextAmbientDecoder.ParsedContext)
    (ns : Namespace) (dsl : RelationDsl)
    (c : SmzaRp05ContextAmbientDecoder.ParsedContext)
    (branch : Branches groupedDecode
      (producer.bind fun c => verifierProgram ns dsl c.statement c.pending c.nonce c.wire))
    (database : Database
      (Key (producer.bind fun c => verifierProgram ns dsl c.statement c.pending c.nonce c.wire))
      (VectorOutput GroupCounter))
    (claims : ClaimsDatabaseEvent
      (branchClaims
        (branchKeys
          (encode (producer.bind fun c => verifierProgram ns dsl c.statement c.pending c.nonce c.wire))
          groupedDecode
          (producer.bind fun c => verifierProgram ns dsl c.statement c.pending c.nonce c.wire)
          branch)
        (branchAnswers
          (encode (producer.bind fun c => verifierProgram ns dsl c.statement c.pending c.nonce c.wire))
          groupedDecode
          (producer.bind fun c => verifierProgram ns dsl c.statement c.pending c.nonce c.wire)
          branch)) database)
    [Fintype RawDigest] (fallback : RawDigest)
    (model : RelationModel) (bounded : ModelWithinProtocol model)
    (transcript : ReconstructedTranscript)
    (execution : ExecutionStages ns dsl c.statement c.pending c.statement.toBytes
      (statementBindingWords c.statement) c.nonce c.wire
      (finiteGroupedDatabaseOracle
        (producer.bind fun c => verifierProgram ns dsl c.statement c.pending c.nonce c.wire)
        database fallback) transcript)
    (producerSuccess : producer.eval
      (finiteGroupedDatabaseOracle
        (producer.bind fun c => verifierProgram ns dsl c.statement c.pending c.nonce c.wire)
        database fallback) = some c)
    (pcs : PcsStages ns execution.openingPending c.wire.hPiop
      (SmzaRp05PcsToFinalProgram.sameProofRows execution.middle.pcs execution.piop)
      execution.decs
      (List.ofFn fun j : Fin 6 => V8Smz9PiopReconstruction.points execution.opening j)
      c.wire.salt c.statement.toBytes (statementBindingWords c.statement)
      c.wire.tapes c.wire.paths
      (finiteGroupedDatabaseOracle
        (producer.bind fun c => verifierProgram ns dsl c.statement c.pending c.nonce c.wire)
        database fallback)
      execution.hashFpp execution.pcsPending)
    (verifierAccepted : (verifierProgram ns dsl c.statement c.pending c.nonce c.wire).eval
        (finiteGroupedDatabaseOracle
          (producer.bind fun c => verifierProgram ns dsl c.statement c.pending c.nonce c.wire)
          database fallback) = some ())
    (transcriptSuccess : (transcriptProgram ns dsl c.statement c.pending c.statement.toBytes
      (statementBindingWords c.statement) c.nonce c.wire).eval
        (finiteGroupedDatabaseOracle
          (producer.bind fun c => verifierProgram ns dsl c.statement c.pending c.nonce c.wire)
          database fallback) = some transcript) :
    branchResult groupedDecode
      (producer.bind fun c => verifierProgram ns dsl c.statement c.pending c.nonce c.wire)
      branch = some () ∧
    ∃ vector,
      (counterInput decsCoefficientDomain pcs.post.root 0, vector) ∈
        answerLog groupedDecode
          (producer.bind fun c => verifierProgram ns dsl c.statement c.pending c.nonce c.wire)
          branch ∧
      currentActualDecsMatrixOutput
        (currentGroupedRoutes model bounded c.statement).decsMatrix vector =
          some (sampledCoefficients (gammaRows pcs.post)) := by
  classical
  let actualProgram := producer.bind fun c => verifierProgram ns dsl c.statement c.pending c.nonce c.wire
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
    change (producer.bind (fun c => verifierProgram ns dsl c.statement c.pending c.nonce c.wire)).eval oracle = some ()
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
    SmzaRp05ExecutablePcsClosure.accepted_execution_constructs_transcript ns dsl c.statement
      c.pending c.statement.toBytes (statementBindingWords c.statement) c.nonce c.wire oracle verifierAccepted
  have transcriptEq : transcript = acceptedTranscript :=
    Option.some.inj (transcriptSuccess.symm.trans acceptedTranscriptSuccess)
  have transcriptCleanSupplied : transcript.pendingXofFailure = false := by
    rw [transcriptEq]
    exact transcriptClean
  have cleanStages :=
    SmzaRp05ExecutablePcsClosureSampling.execution_stages_clean_matrix ns dsl c.statement
      c.pending c.statement.toBytes (statementBindingWords c.statement) c.nonce c.wire oracle transcript
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
  have intoPcs := post_merkle_records_retained_in_pcs ns execution.openingPending c.wire.hPiop
    (SmzaRp05PcsToFinalProgram.sameProofRows execution.middle.pcs execution.piop)
    execution.decs
    (List.ofFn fun j : Fin 6 => V8Smz9PiopReconstruction.points execution.opening j)
    c.wire.salt c.statement.toBytes (statementBindingWords c.statement)
    c.wire.tapes c.wire.paths oracle execution.hashFpp execution.pcsPending pcs execution.pcsExecuted
  have intoVerifier :=
    SmzaRp05PhysicalPcsRecordRetention.execution_pcs_records_retained_in_verifier
      ns dsl c.statement c.pending c.nonce c.wire oracle transcript execution transcriptSuccess
  have pcsMember := intoVerifier _ (intoPcs _ postMember)
  have wholeMember :
      (counterInput decsCoefficientDomain pcs.post.root 0,
        oracle (counterInput decsCoefficientDomain pcs.post.root 0)) ∈
      (actualProgram.record oracle).2 := by
    exact Program.bind_log_right oracle producer
      (fun out => verifierProgram ns dsl out.statement out.pending out.nonce out.wire) c producerSuccess
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
  let routes := currentGroupedRoutes model bounded c.statement
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
    vector stored model c.statement pcs.post.root routes.decsMatrix counterAddress
  have actualSample := executed_clean_post_merkle_actual_decs_coefficients ns oracle
    pcs.merkleInput pcs.post pcs.postExecuted postClean
  have oracleDecoded :
      currentOracleDecodedAt model oracle c.statement .decsMatrix pcs.post.root =
        some (sampledCoefficients (gammaRows pcs.post)) := by
    change currentActualDecsMatrixOutput
      (Equiv.refl (Fin (digestCallCap (140 * 5))))
      (SmzaRp05CurrentExecutedMatrixReadback.currentDecsMatrixVector oracle pcs.post.root) = _
    exact actualSample
  refine ⟨branchAccepted, vector, vectorMember, ?_⟩
  exact decodedRoute.trans oracleDecoded

end
end HegemonCrypto.SmallWood.SmzaRp05CurrentAcceptedDecsOutputBindingAmbient

/-! # Actual accepted DECS-matrix event from one execution

This joins the concrete counter-zero DECS call, grouped storage, filtered
readbacks, and the current decoder's bad-matrix result into the role event.
The grouped key, stored vector, and parsed role query are derived from the
same branch's answer log.
-/

namespace HegemonCrypto.SmallWood.SmzaRp05CurrentAcceptedMatrixFailureEventAmbient

open scoped Classical
open HegemonCrypto.CanonicalBytes (Byte)
open HegemonCrypto.CmsOracleDatabaseBridge (ClaimsDatabaseEvent)
open HegemonCrypto.FiniteOracleDatabase (Database)
open SmzaRp05ExecutableMerkleVerifier (Program Oracle)
open SmzaRp05PhysicalAcceptedReplayLite
  (Branches branchKeys branchAnswers branchClaims branchResult)
open SmzaRp05CurrentGroupedClaimRetention (groupedDecode)
open SmzaRp05CurrentFiniteGroupedProgram (Key encode included)
open SmzaRp05CurrentGroupedOracleVector (finiteGroupedDatabaseOracle)
open SmzaRp05GroupedSuffix (groupRepresentative groupZero GroupCounter)
open SmzaRp05ExecutablePcsClosure (ExecutionStages transcriptProgram)
open SmzaRp05ExecutablePcsClosureStages (PcsStages)
open SmzaRp05ExecutablePcsClosureStatement (verifierProgram statementBindingWords)
open SmzaRp05ExecutablePcsClosureSampling
open SmzaRp05ExecutableMerkleVerifier (recordedAttempt)
open SmzaRp05PhysicalPcsRecordRetention (execution_pcs_records_retained_in_verifier)
open SmzaRp05PhysicalHashFppRecordRetention (execution_hash_fpp_records_retained_in_verifier)
open SmzaRp05CurrentGroupedVerifierReplay (accepted_grouped_claims_supply_verifier_replay)
open SmzaRp05CurrentAcceptedDecsOutputBinding (same_stage_decs_counter_zero_decodes)
open SmzaRp05CurrentAcceptedRoleQueryReadback (current_actual_grouped_role_call_readback)
open SmzaRp05CurrentDecsGroupedTarget (recorded_decs_call_has_grouped_target)
open SmzaRp05CurrentAcceptedNonleafRoleReadback (accepted_stages_raw_nonleaf_outer_preambles)
open SmzaRp05CurrentAcceptedFilteredRoleTraces (current_stages_supply_filtered_role_traces)
open SmzaRp05CurrentAcceptedMatrixEventReadback
  (current_matrix_role_event_of_execution_readbacks
    current_matrix_bad_from_challenge_erased_records)
open SmzaRp05CurrentMatrixRoleEvent
  (currentMatrixRoleEvent406)
open SmzaRp05CurrentRoleLabels (currentOuter targetOfRaw currentRawInputDecidableEq)
open SmzaRp05TracePrefixes (RelationModel TypedRoutes AllEarlierTables rootOracle)
open SmzaRp05FilteredReadback (globalLeafStatement)
open SmzaRp05FilteredDecoderInstability (globalOnlineNext)
open SmzaRp05ChallengeRecordErasure (eraseChallengeRecords global_extract_filtered_erase_challenge)
open SmzaRp04StatementRecordFilter (oneStatementFilter nonleafFilter)
open SmzaRecordedTracePath (RecordsCollisionFree)
open HegemonCrypto.SmallWood.SmzaChallengeStageTargets (StageQuery parseStageQuery)
open SmzaRp05CurrentUniversalMatrixLoss (currentMatrixBad)
open SmzaRp05CurrentAcceptedQuerySupport (sampledCoefficients)
open SmzaRp05PcsHashFppMiddle (gammaRows)
open V8Smz9CoherentMerkleGeometry (extract)
open V8Smz9CoherentMerkleInstrument (rawRecords)
open V8Smz9CoherentVectorMerkle (VectorOutput vectorOutputBytes)
open SmzaRp05CurrentProofWireProgram (ExistingProofFieldView)
open SmzaRp05RelationRefinement (RelationDsl)
open SmzaRp05CurrentAcceptedFilteredRoleTraces (currentOuterTarget)
open SmzaRp05CurrentGroupedRoutes (currentGroupedRoutes)
open SmzaRp05ConcreteSuffix (ModelWithinProtocol)
open V8SmzaOracleParser (RawDigest RawInput)
open HegemonCrypto.SmallWoodTranscript (decsCoefficientDomain)

noncomputable section
set_option autoImplicit false
set_option maxRecDepth 12000

local notation "Statement" => SmzaRp05StatementNamespace.Statement
local instance : DecidableEq RawInput := currentRawInputDecidableEq
local instance rawDigestDecidableEq [Fintype RawDigest] : DecidableEq RawDigest :=
  Fintype.decidablePiFintype

set_option maxHeartbeats 1000000 in
/-- From one accepted execution's successful DECS matrix result, construct
the actual current-map matrix role event. The counter-zero call, grouped
storage cell, and role target are recovered from this branch's answer log;
outer and inner traces use the same database and stages. -/
theorem accepted_execution_matrix_bad_yields_role_event
    (producer : Program SmzaRp05ContextAmbientDecoder.ParsedContext)
    (ns : SmzaRp05LeafNamespace.Namespace) (dsl : RelationDsl)
    (c : SmzaRp05ContextAmbientDecoder.ParsedContext)
    (branch : Branches groupedDecode
      (producer.bind fun c => verifierProgram ns dsl c.statement c.pending c.nonce c.wire))
    (accepted : branchResult groupedDecode
      (producer.bind fun c => verifierProgram ns dsl c.statement c.pending c.nonce c.wire)
      branch = some ())
    (database : Database
      (Key (producer.bind fun c => verifierProgram ns dsl c.statement c.pending c.nonce c.wire))
      (VectorOutput GroupCounter))
    (claims : ClaimsDatabaseEvent
      (branchClaims
        (branchKeys (encode (producer.bind fun c => verifierProgram ns dsl c.statement c.pending c.nonce c.wire)) groupedDecode
          (producer.bind fun c => verifierProgram ns dsl c.statement c.pending c.nonce c.wire)
          branch)
        (branchAnswers (encode (producer.bind fun c => verifierProgram ns dsl c.statement c.pending c.nonce c.wire)) groupedDecode
          (producer.bind fun c => verifierProgram ns dsl c.statement c.pending c.nonce c.wire)
          branch)) database)
    (fallback : RawDigest) [Fintype RawDigest]
    (model : RelationModel) (bounded : ModelWithinProtocol model)
    (advice : AllEarlierTables model .decsMatrix)
    (outerFuel innerFuel : Nat) (outerEnough : 28 ≤ outerFuel)
    (innerEnough : 28 ≤ innerFuel) (authorized : Finset (List Byte))
    (fresh : c.statement.toBytes ∉ authorized)
    (transcript : SmzaRp05ExecutableFinalVerifier.ReconstructedTranscript)
    (execution : ExecutionStages ns dsl c.statement c.pending c.statement.toBytes
      (statementBindingWords c.statement) c.nonce c.wire
      (finiteGroupedDatabaseOracle
        (producer.bind fun c => verifierProgram ns dsl c.statement c.pending c.nonce c.wire)
        database fallback) transcript)
    (pcs : PcsStages ns execution.openingPending c.wire.hPiop
      (SmzaRp05PcsToFinalProgram.sameProofRows execution.middle.pcs execution.piop)
      execution.decs
      (List.ofFn fun j : Fin 6 => V8Smz9PiopReconstruction.points execution.opening j)
      c.wire.salt c.statement.toBytes (statementBindingWords c.statement)
      c.wire.tapes c.wire.paths
      (finiteGroupedDatabaseOracle
        (producer.bind fun c => verifierProgram ns dsl c.statement c.pending c.nonce c.wire)
        database fallback) execution.hashFpp execution.pcsPending)
    (producerSuccess : producer.eval
      (finiteGroupedDatabaseOracle
        (producer.bind fun c => verifierProgram ns dsl c.statement c.pending c.nonce c.wire)
        database fallback) = some c)
    (verifierAccepted : (verifierProgram ns dsl c.statement c.pending c.nonce c.wire).eval
      (finiteGroupedDatabaseOracle
        (producer.bind fun c => verifierProgram ns dsl c.statement c.pending c.nonce c.wire)
        database fallback) = some ())
    (transcriptSuccess : (transcriptProgram ns dsl c.statement c.pending c.statement.toBytes
      (statementBindingWords c.statement) c.nonce c.wire).eval
      (finiteGroupedDatabaseOracle
        (producer.bind fun c => verifierProgram ns dsl c.statement c.pending c.nonce c.wire)
        database fallback) = some transcript)
    (collisionFree : RecordsCollisionFree
      (oneStatementFilter (globalLeafStatement ns) c.statement.toBytes
        (eraseChallengeRecords
          (rawRecords (fun key => groupRepresentative
            (included (producer.bind fun c => verifierProgram ns dsl c.statement c.pending c.nonce c.wire) key))
            (vectorOutputBytes groupZero) database))))
    (matrixBad : currentMatrixBad
      (SmzaQ38McaSourceBinding.oracleData
        (rootOracle ns (extract (globalOnlineNext ns)
          (oneStatementFilter (globalLeafStatement ns) c.statement.toBytes
            (eraseChallengeRecords
              (rawRecords (fun key => groupRepresentative
                (included (producer.bind fun c => verifierProgram ns dsl c.statement c.pending c.nonce c.wire) key))
                (vectorOutputBytes groupZero) database)))
          innerFuel .root pcs.post.root)))
      (SmzaQ38McaSourceBinding.oracleMasks
        (rootOracle ns (extract (globalOnlineNext ns)
          (oneStatementFilter (globalLeafStatement ns) c.statement.toBytes
            (eraseChallengeRecords
              (rawRecords (fun key => groupRepresentative
                (included (producer.bind fun c => verifierProgram ns dsl c.statement c.pending c.nonce c.wire) key))
                (vectorOutputBytes groupZero) database)))
          innerFuel .root pcs.post.root)))
      (sampledCoefficients (gammaRows pcs.post))) :
    currentMatrixRoleEvent406 model ns
      (fun key => groupRepresentative
        (included (producer.bind fun c => verifierProgram ns dsl c.statement c.pending c.nonce c.wire) key))
      groupZero (currentGroupedRoutes model bounded)
      advice outerFuel innerFuel authorized database := by
  classical
  let program := producer.bind fun c => verifierProgram ns dsl c.statement c.pending c.nonce c.wire
  let fullRecords := rawRecords
    (fun key => groupRepresentative (included program key))
    (vectorOutputBytes groupZero) database
  let erasedRecords := eraseChallengeRecords fullRecords
  let filteredRecords := oneStatementFilter (globalLeafStatement ns)
    c.statement.toBytes erasedRecords
  obtain ⟨replayContext, producerSuccess₂, _verifierAccepted₂, retained⟩ :=
    SmzaRp05ContextPhysicalBind.accepted_bind_grouped_claims_replay producer
      (fun out => verifierProgram ns dsl out.statement out.pending out.nonce out.wire)
      branch () accepted database claims fallback
  have sameContext : c = replayContext := Option.some.inj
    (producerSuccess.symm.trans producerSuccess₂)
  subst replayContext
  have decsDecoded := SmzaRp05CurrentAcceptedDecsOutputBindingAmbient.same_stage_decs_counter_zero_decodes producer ns dsl c
    branch database claims fallback model bounded transcript execution
    producerSuccess pcs verifierAccepted transcriptSuccess
  have _acceptedBranch : branchResult groupedDecode program branch = some () := decsDecoded.1
  obtain ⟨vector, callRecorded, decoderRead⟩ := decsDecoded.2
  let callInput := SmzaRp05ExecutableChallengeStage.counterInput
    decsCoefficientDomain pcs.post.root 0
  have groupedTarget := recorded_decs_call_has_grouped_target program branch
    (callInput, vector) callRecorded pcs.post.root ⟨0, by decide⟩ rfl
  obtain ⟨_rolePrefix, keyIdentity, representativeParsed, targetRead⟩ := groupedTarget
  have representativeParsedAtKey : parseStageQuery
      (groupRepresentative (included program (encode program callInput))) =
      some ⟨.decsMatrix, pcs.post.root, 0, 0⟩ := by
    rw [keyIdentity]
    exact representativeParsed
  have roleRead := current_actual_grouped_role_call_readback program branch
    (callInput, vector) callRecorded database claims fallback .decsMatrix
    ⟨.decsMatrix, pcs.post.root, 0, 0⟩ representativeParsedAtKey rfl rfl
  obtain ⟨_rolePrefix, _keyIdentity, _representativeParsed, _coordinates,
    _target, stored, _answer, _allAnswers⟩ := roleRead
  have retainedOuter := SmzaRp05CurrentAcceptedNonleafRoleReadbackAmbient.accepted_stages_raw_nonleaf_outer_preambles
    program ns dsl c.statement c.pending c.nonce database fallback c.wire transcript execution pcs
    verifierAccepted transcriptSuccess outerFuel outerEnough collisionFree retained
  have filteredTraces := SmzaRp05CurrentAcceptedFilteredRoleTracesAmbient.current_stages_supply_filtered_role_traces
    program ns dsl c.statement c.pending c.nonce database fallback c.wire transcript execution pcs
    verifierAccepted transcriptSuccess innerFuel innerEnough collisionFree retained
  let keyBytes := fun key : Key program => groupRepresentative (included program key)
  have outerReadback : currentOuter ns keyBytes .decsMatrix outerFuel
      (nonleafFilter (globalLeafStatement ns) fullRecords) (encode program callInput) =
        some c.statement.toBytes := by
    unfold currentOuter
    change SmzaRp05CurrentRoleLabels.preambleFromTrace ns .decsMatrix
      (extract (globalOnlineNext ns) (nonleafFilter (globalLeafStatement ns) fullRecords)
        outerFuel (targetOfRaw .decsMatrix (keyBytes (encode program callInput))).1
        (targetOfRaw .decsMatrix (keyBytes (encode program callInput))).2) = _
    rw [targetRead]
    simpa only [program, fullRecords,
      SmzaRp05CurrentAcceptedFilteredRoleTracesAmbient.currentOuterTarget,
      SmzaChallengeStageTargets.roleStage] using retainedOuter .decsMatrix
  have filteredEraseEq := global_extract_filtered_erase_challenge ns fullRecords
    (fun input => globalLeafStatement ns input = none ∨
      globalLeafStatement ns input = some c.statement.toBytes)
    innerFuel .root pcs.post.root
  have innerReadback : extract (globalOnlineNext ns)
      (oneStatementFilter (globalLeafStatement ns) c.statement.toBytes fullRecords)
      innerFuel .root pcs.post.root =
      SmzaRp05AcceptedRoleLabels.causalTrace
        (extract (globalOnlineNext ns) filteredRecords innerFuel .decs pcs.openingDigest)
        .decsMatrix := by
    calc
      extract (globalOnlineNext ns)
          (oneStatementFilter (globalLeafStatement ns) c.statement.toBytes fullRecords)
          innerFuel .root pcs.post.root =
        extract (globalOnlineNext ns) filteredRecords innerFuel .root pcs.post.root :=
          filteredEraseEq.symm
      _ = SmzaRp05AcceptedRoleLabels.causalTrace
          (extract (globalOnlineNext ns) filteredRecords innerFuel .decs pcs.openingDigest)
          .decsMatrix := by
            simpa only [program, filteredRecords, erasedRecords, fullRecords,
              SmzaRp05CurrentAcceptedFilteredRoleTracesAmbient.currentOuterTarget]
              using filteredTraces.2 .decsMatrix
  have rawMatrixBad := current_matrix_bad_from_challenge_erased_records
    ns c.statement fullRecords innerFuel pcs.post.root
    (sampledCoefficients (gammaRows pcs.post)) matrixBad
  have rootReadback := congrArg (rootOracle ns) innerReadback
  have rawMatrixBadOnTrace := rootReadback ▸ rawMatrixBad
  exact current_matrix_role_event_of_execution_readbacks
    model ns keyBytes groupZero
    (currentGroupedRoutes model bounded)
    advice outerFuel innerFuel authorized c.statement fresh
    (encode program callInput) vector database
    ⟨.decsMatrix, pcs.post.root, 0, 0⟩
    representativeParsedAtKey
    rfl stored outerReadback
    (extract (globalOnlineNext ns) filteredRecords innerFuel .decs pcs.openingDigest)
    innerReadback (sampledCoefficients (gammaRows pcs.post)) decoderRead rawMatrixBadOnTrace

end
end HegemonCrypto.SmallWood.SmzaRp05CurrentAcceptedMatrixFailureEventAmbient

/-! # Selected accepted-execution support inside the current advice event

This module starts the four-role inclusion at the same accepted physical
branch and selected fixed fiber used by the scalar endpoint. The event-side
advice is constructed from that fixed fiber; the placeholder context advice
is not used as a classifier premise.
-/
namespace HegemonCrypto.SmallWood.SmzaRp05ContextAmbientMatrixSupport

open scoped Classical
open HegemonCrypto.CanonicalBytes (Byte)
open HegemonCrypto.CanonicalBytes (encodeLE)
open HegemonCrypto.CmsCompressedOracle (Basis)
open HegemonCrypto.CmsOracleSimulation
open HegemonCrypto.CmsAdaptiveClaimBridge (workspaceEventProjection)
open HegemonCrypto.CmsOracleDatabaseBridge (ClaimsDatabaseEvent)
open HegemonCrypto.FiniteOracleDatabase (Database)
open SmzaChallengeStageTargets (Role)
open SmzaRoleDomainConditioning (ActiveKey)
open SmzaRp05ConditionedExecution
  (ActiveState FixedTable XKey fixedFiberToActive otherRoleTransform mergeFixedActive
    activeXView)
open SmzaRp05CurrentAdaptiveExecution (Context)
open SmzaRp05CurrentAdaptiveExecution (CmsState)
open SmzaRp05ActualEventRecertification (event)
open SmzaRp05TracePrefixes (RelationModel AllEarlierTables)
open SmzaRp05ConcreteSuffix (ModelWithinProtocol)
open SmzaRp05GeneratedCertificates (currentDsl)
open SmzaRp05RelationRefinement (relationModel GeneratedCertificates)
open SmzaRp05ExecutableMerkleVerifier (Program)
open SmzaRp05ExecutablePcsClosureStatement (verifierProgram statementBindingWords)
open SmzaRp05CurrentProofWireProgram (ExistingProofFieldView)
open SmzaRp05CurrentFiniteGroupedProgram (Key encode included)
open SmzaRp05CurrentGroupedClaimRetention (groupedDecode)
open SmzaRp05ExecutableChallengeStage (counterInput)
open HegemonCrypto.SmallWoodTranscript (decsFixedSamplingDomain)
open SmzaRp05GroupedSuffix (GroupCounter groupRepresentative groupZero)
open SmzaRp05CurrentGroupedContext (currentGroupedContext)
open SmzaRp05CurrentSelectedChallengeClaims
  (recognizedActiveChallengeClaims nonchallengeRawKeySet
    nonchallenge_raw_key_set_unrecognized)
open SmzaRp05CurrentSelectedCurrentAdviceEventMass (selectedRoleState)
open SmzaRp05CurrentFullOrRoleExtraction (currentAcceptedXViewFailureRoleSelector)
open SmzaRp05CurrentAcceptedPiopExtractionFailureEvent
  (grouped_piop_failure_support_implies_current_advice_event_or_missing_claims)
open SmzaRp05CurrentAcceptedPiopExtractionFailureEvent
  (selected_xview_failure_role_replays_on_completion)
open SmzaRp05CurrentSelectedXViewClaims (selected_support_supplies_full_branch_claims)
open SmzaRp05CurrentAdviceDependentPhysicalMass (currentAdviceEventSpec)
open SmzaRp05CurrentAdviceDependentPhysicalMass
  (currentAdviceActiveContext currentAdviceContextAtFixed)
open SmzaRp05CurrentFixedEarlierAdvice (currentFixedAdvice)
open SmzaRp05CurrentAcceptedFixedEarlierReadback
  (currentFixedEarlierAdviceFamily currentFixedEarlierAdviceFamily_active)
open SmzaRp05CurrentGroupedOracleVector (finiteGroupedDatabaseOracle)
open SmzaRp05Current406ActiveFiberEvent (current406_base_merged_iff_active)
open SmzaRp05PhysicalAcceptedReplayLite
  (Branches branchKeys branchAnswers branchClaims branchResult physicalRun)
open SmzaRp05CurrentGroupedClaimRetention
  (actual_program_grouped_claims_replay_and_retain)
open SmzaRp05CurrentAcceptedMatrixFailureEvent
  (accepted_execution_matrix_bad_yields_role_event)
open SmzaRp05Current406EventSpec (current406Base current406EventSpec)
open SmzaRp05CurrentMatrixRoleEvent (currentMatrixRoleEvent406)
open SmzaRp05CurrentSourceRoleEvent (currentSourceMatrixRoleEvent406)
open SmzaRp05CurrentSourceRoleEvent (currentSourceRoleEvent406)
open SmzaRp05CurrentAcceptedDecsSampleOutputBinding
  (accepted_current_decs_sample_output_binding)
open SmzaRp05CurrentAcceptedQuerySupport (Position Query)
open SmzaRp05CurrentAcceptedDecsSourceEvent (source_bad_on_same_causal_trace_yields_event)
open SmzaRp05CurrentAcceptedDecsSourceCoverage
  (source_bad_on_same_trace_yields_event_of_family)
open SmzaRp05CurrentAcceptedFilteredCausalSourceBad
  (filtered_classifier_source_bad_to_causal)
open SmzaRp05CurrentAcceptedFilteredCausalRetention
  (accepted_execution_supplies_filtered_causal_records)
open SmzaRp05CurrentAcceptedFixedEarlierCells
  (same_stage_fixed_decs_sample_earlier_readback same_stage_current_fixed_opening_scan)
open SmzaRp05AdaptiveRetainedAdviceTransport (physical_run_to_mixed_same_fiber)
open SmzaRp05CurrentExecutedEarlierAdvice (currentOracleAllAdvice)
open SmzaRp05AcceptedRoleLabels (EarlierReadback CausalPayloads)
open SmzaRp05CurrentCausalNonchallengeRetention
  (accepted_execution_causal_record_memberships)
open SmzaRp05CurrentAcceptedNonleafRoleReadback
  (accepted_stages_raw_nonleaf_outer_preambles)
open SmzaRp05CurrentAcceptedFilteredRoleTraces
  (current_stages_supply_filtered_role_traces currentOuterTarget)
open SmzaRp05CurrentExecutedSamplerSemantics
  (pcs_query_execution_exposes_clean_scan)
open SmzaRp05CurrentGroupedRoutes (currentGroupedRoutes)
open SmzaRp05CurrentRoleLabels (targetOfRaw preambleFromTrace)
open SmzaRp05CurrentSelectedChallengeClaims
  (branchXRoleSelector nonchallengeRawKeySet nonchallenge_raw_key_set_unrecognized)
open SmzaRp05ChallengeRecordErasure
  (eraseChallengeRecords global_extract_filtered_erase_challenge)
open SmzaRp04StatementRecordFilter (oneStatementFilter nonleafFilter keepOneStatement)
open SmzaRp05FilteredReadback (globalLeafStatement)
open SmzaRp05FilteredDecoderInstability (globalOnlineNext)
open SmzaRp05CurrentTracePrefixes406 (currentSourceBad406 currentSourcePrefix406)
open SmzaRp05AcceptedRoleLabels (causalOracle causalTrace)
open SmzaRp05CertifiedReplaySchedule (ordinary_counter_roundtrip)
open SmzaRp05CurrentAcceptedRoleQueryReadback (current_actual_grouped_role_call_readback)
open SmzaRp05GroupedSuffix
  (CanonicalRolePrefix groupKeyOf groupEncode groupAddress group_address_encode)
open SmzaRp05Current406EventSpec (currentRoleEvent406Explicit)
open SmzaRp05CurrentAcceptedXViewRoleCoverage (noWitnessRoleFailure)
open SmzaChallengeStageTargets (StageQuery parseStageQuery)
open V8Smz9AdaptiveFiniteAccounting (baseOpeningPoints)
open V8Smz9CoherentVectorMerkle (VectorOutput)
open V8Smz9CoherentVectorMerkle (vectorOutputBytes)
open V8Smz9CoherentMerkleGeometry (extract)
open V8SmzaOracleParser (RawDigest)
open V8Smz9CoherentMerkleInstrument (rawRecords)
open SmzaRp05ChallengeRecordErasure (eraseChallengeRecords)
open Hegemon.Transaction.Poseidon2V8SemanticSpecification

attribute [local irreducible] SmzaRp05GeneratedCertificates.currentDsl

noncomputable section
set_option autoImplicit false
set_option maxRecDepth 12000
set_option maxHeartbeats 1600000
set_option linter.unusedSectionVars false

local instance : DecidableEq V8SmzaOracleParser.RawInput :=
  SmzaRp05CurrentRoleLabels.currentRawInputDecidableEq
local instance rawDigestDecidableEq [Fintype RawDigest] : DecidableEq RawDigest :=
  Fintype.decidablePiFintype

private def actualVerifierProgram (producer : Program ExistingProofFieldView)
    (ns : SmzaRp05LeafNamespace.Namespace)
    (statement : SmzaRp05StatementNamespace.Statement) (pending : Bool)
    (nonce : Fin (2 ^ 32)) : Program Unit :=
  producer.bind fun wire => verifierProgram ns currentDsl statement pending nonce wire

private def emptyInitialAdvice (model : RelationModel) (role : Role) :
    AllEarlierTables model role := fun _ _ _ _ => none

open SmzaRp05ContextAmbientDecoder (ParsedContext fixedNamespaceContextProgram)
open SmzaRp05ContextAmbientCoverage (ambientXViewFailureRoleSelector)

private def groupedRoleContext
    {BaseWork : Type} [Fintype BaseWork] [DecidableEq BaseWork]
    (producer : Program ParsedContext)
    (ns : SmzaRp05LeafNamespace.Namespace)
 (model : RelationModel)
    (bounded : ModelWithinProtocol model) (role : Role) :
    Context (Key := Key (fixedNamespaceContextProgram ns producer))
      (Counter := GroupCounter) (BaseWork := BaseWork) :=
  currentGroupedContext (fixedNamespaceContextProgram ns producer)
    model bounded ns role (emptyInitialAdvice model role) 28 28 (fun _ => ∅)

private def groupedFailureSelector
    {BaseWork : Type} [Fintype BaseWork] [DecidableEq BaseWork]
    (producer : Program ParsedContext)
    (ns : SmzaRp05LeafNamespace.Namespace)
 (fallback : RawDigest)
    (fuel : Nat) (model : RelationModel) (bounded : ModelWithinProtocol model)
    (role : Role)
    (branch : Branches groupedDecode
      (fixedNamespaceContextProgram ns producer)) :
    (view : XKey (nonchallengeRawKeySet
      (groupedRoleContext (BaseWork := BaseWork) producer ns
        model bounded role)) →
        Option (VectorOutput GroupCounter)) →
      SmzaRp05CurrentAdaptiveExecution.Work (Counter := GroupCounter)
        (BaseWork := BaseWork) → Prop :=
  let ctx := groupedRoleContext (BaseWork := BaseWork) producer ns
    model bounded role
  fun view _work => ambientXViewFailureRoleSelector producer ns
    fallback fuel ctx role branch view

theorem grouped_decs_matrix_failure_support_implies_current_advice_event_or_missing_claims
    {BaseWork : Type} [Fintype BaseWork] [DecidableEq BaseWork]
    (producer : Program ParsedContext)
    (ns : SmzaRp05LeafNamespace.Namespace)
 (fallback : RawDigest)
    (certificates : GeneratedCertificates currentDsl)
    (bounded : ModelWithinProtocol (relationModel currentDsl certificates))
    (blockCap : Role → Nat)
    (branch : Branches groupedDecode
      (fixedNamespaceContextProgram ns producer))
    (fixed : FixedTable
      (groupedRoleContext (BaseWork := BaseWork) producer ns
        (relationModel currentDsl certificates) bounded .decsMatrix) blockCap)
    (dummy : ActiveKey .decsMatrix blockCap
      (groupedRoleContext (BaseWork := BaseWork) producer ns
        (relationModel currentDsl certificates) bounded .decsMatrix).keyBytes)
    (initial : CmsState
      (Key := Key (fixedNamespaceContextProgram ns producer))
      (Counter := GroupCounter) (BaseWork := BaseWork))
    (basis : Basis (ActiveKey .decsMatrix blockCap
      (groupedRoleContext (BaseWork := BaseWork) producer ns
        (relationModel currentDsl certificates) bounded .decsMatrix).keyBytes)
      (VectorOutput GroupCounter) (VectorOutput GroupCounter)
      (SmzaRp05ConditionedExecution.ActiveMemory
        (groupedRoleContext (BaseWork := BaseWork) producer ns
          (relationModel currentDsl certificates) bounded .decsMatrix)))
    (cap : Nat)
    (support : selectedRoleState
      (groupedRoleContext (BaseWork := BaseWork) producer ns
        (relationModel currentDsl certificates) bounded .decsMatrix)
      blockCap (encode (fixedNamespaceContextProgram ns producer))
      groupedDecode (fixedNamespaceContextProgram ns producer)
      branch fixed
      (fixedFiberToActive
        (groupedRoleContext (BaseWork := BaseWork) producer ns
          (relationModel currentDsl certificates) bounded .decsMatrix)
        blockCap dummy fixed (otherRoleTransform
          (groupedRoleContext (BaseWork := BaseWork) producer ns
            (relationModel currentDsl certificates) bounded .decsMatrix)
          blockCap initial))
      (groupedFailureSelector (BaseWork := BaseWork) producer ns fallback 28 (relationModel currentDsl certificates)
        bounded .decsMatrix branch) basis ≠ 0) :
    event (currentAdviceEventSpec
      (groupedRoleContext (BaseWork := BaseWork) producer ns
        (relationModel currentDsl certificates) bounded .decsMatrix)
      blockCap fixed cap)
      (SmzaRp05ConditionedExecution.activeMemoryEquiv
        (groupedRoleContext (BaseWork := BaseWork) producer ns
          (relationModel currentDsl certificates) bounded .decsMatrix) basis.workspace)
      basis.database ∨
    ¬ ClaimsDatabaseEvent
      (recognizedActiveChallengeClaims
        (groupedRoleContext (BaseWork := BaseWork) producer ns
          (relationModel currentDsl certificates) bounded .decsMatrix)
        blockCap (encode (fixedNamespaceContextProgram ns producer))
        groupedDecode (fixedNamespaceContextProgram ns producer) branch)
      basis.database := by
  classical
  let model := relationModel currentDsl certificates
  let program := fixedNamespaceContextProgram ns producer
  let ctx := groupedRoleContext (BaseWork := BaseWork) producer ns model bounded .decsMatrix
  let select := groupedFailureSelector (BaseWork := BaseWork) producer ns fallback 28 model bounded .decsMatrix branch
  let fiberInitial := fixedFiberToActive ctx blockCap dummy fixed
    (otherRoleTransform ctx blockCap initial)
  by_cases challengeClaims : ClaimsDatabaseEvent
      (recognizedActiveChallengeClaims ctx blockCap (encode program) groupedDecode program branch)
      basis.database
  · have evidence := SmzaRp05ContextAmbientSupport.selected_ambient_failure_role_replays_on_completion
      producer ns fallback 28
      ctx blockCap (by intro key; rfl) branch fixed
      fiberInitial basis challengeClaims support
    rcases evidence with ⟨c, recordsCollisionFree, completionOracle, oracleEq, transcript, producerSuccess,
      verifierAccepted, transcriptSuccess, execution, pcs, coordinates, query, input,
      ordered, image, indexes, inputRecord, hashRecord, currentOutcome, labelOutcome,
      roleFailure⟩
    subst completionOracle
    have selectedJoin := selected_support_supplies_full_branch_claims ctx blockCap
      (encode program) groupedDecode program branch fixed
      fiberInitial select basis support challengeClaims
    have mergedClaims := selectedJoin.2.1
    let completed := mergeFixedActive ctx blockCap fixed basis.database
    let oracle := finiteGroupedDatabaseOracle program completed fallback
    have claims : ClaimsDatabaseEvent
        (branchClaims (branchKeys (encode program) groupedDecode program branch)
          (branchAnswers (encode program) groupedDecode program branch)) completed := by
      simpa only [completed] using mergedClaims
    have actualRecord := actual_program_grouped_claims_replay_and_retain
      program branch completed claims fallback
    have actualSuccess : program.eval oracle = some () := by
      change (fixedNamespaceContextProgram ns producer).eval
        oracle = some ()
      change producer.eval oracle = some c at producerSuccess
      change (verifierProgram ns currentDsl c.statement c.pending c.nonce c.wire).eval oracle = some ()
        at verifierAccepted
      rw [SmzaRp05ContextAmbientDecoder.fixedNamespaceContextProgram, Program.eval_bind, producerSuccess]
      exact verifierAccepted
    have accepted : branchResult groupedDecode program branch = some () := by
      have recordResult : (program.record oracle).1 = branchResult groupedDecode program branch :=
        congrArg Prod.fst actualRecord.1
      calc
        branchResult groupedDecode program branch = (program.record oracle).1 := recordResult.symm
        _ = program.eval oracle := Program.record_result oracle program
        _ = some () := actualSuccess
    have noWitness : noWitnessRoleFailure .decsMatrix ns c.statement c.pending c.nonce c.wire
        oracle transcript execution pcs
        (eraseChallengeRecords (rawRecords
          (fun key => groupRepresentative (included program key))
          (vectorOutputBytes groupZero) completed)) 28 input query := by
      have ctxRole : ctx.role = .decsMatrix := rfl
      rw [← ctxRole]
      simpa only [oracle, completed, program, actualVerifierProgram] using roleFailure
    dsimp only [noWitnessRoleFailure] at noWitness
    have matrixBad := noWitness
    have roleEvent := SmzaRp05CurrentAcceptedMatrixFailureEventAmbient.accepted_execution_matrix_bad_yields_role_event
      producer ns currentDsl c branch accepted completed claims
      fallback model bounded (currentFixedAdvice ctx blockCap fixed)
      28 28 (by decide) (by decide) ∅ (by simp) transcript execution pcs
      producerSuccess verifierAccepted transcriptSuccess recordsCollisionFree matrixBad
    let adjusted := { ctx with advice := currentFixedAdvice ctx blockCap fixed }
    have baseAccepted : current406Base adjusted ∅ completed := by
      change currentMatrixRoleEvent406 model ns ctx.keyBytes ctx.counter ctx.routes
        (currentFixedAdvice ctx blockCap fixed) ctx.outerFuel ctx.innerFuel ∅ completed
      exact roleEvent
    have activeEvent := (current406_base_merged_iff_active adjusted blockCap fixed
      basis.database ∅).mp baseAccepted
    have specEventEq : event (currentAdviceEventSpec ctx blockCap fixed cap)
        (SmzaRp05ConditionedExecution.activeMemoryEquiv ctx basis.workspace)
        basis.database =
      currentRoleEvent406Explicit adjusted.model adjusted.leafNamespace
        (fun key => adjusted.keyBytes key.val) adjusted.counter adjusted.routes adjusted.role
        adjusted.advice adjusted.outerFuel adjusted.innerFuel ∅ basis.database := by
      change currentRoleEvent406Explicit ctx.model ctx.leafNamespace
        (fun key => ctx.keyBytes key.val) ctx.counter ctx.routes ctx.role
        (currentFixedAdvice ctx blockCap fixed) ctx.outerFuel ctx.innerFuel ∅ basis.database =
        currentRoleEvent406Explicit adjusted.model adjusted.leafNamespace
          (fun key => adjusted.keyBytes key.val) adjusted.counter adjusted.routes adjusted.role
          adjusted.advice adjusted.outerFuel adjusted.innerFuel ∅ basis.database
      rfl
    rw [specEventEq]
    exact Or.inl activeEvent
  · exact Or.inr challengeClaims


end
end HegemonCrypto.SmallWood.SmzaRp05ContextAmbientMatrixSupport
