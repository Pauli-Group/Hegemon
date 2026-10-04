import SmzaRp05CurrentAcceptedOuterReadback
import SmzaRp05CurrentCausalNonchallengeRetention
import SmzaRp05CurrentDecsFrameReadback
import SmzaRp05CurrentFppFrameReadback
import SmzaRp05CurrentPiopFrameReadback
import SmzaRp05CurrentGroupedClaimRetention
import SmzaRp05CurrentFiniteGroupedProgram
import SmzaRp05CurrentGroupedOracleVector
import SmzaRp05GroupedSuffix
import SmzaRp05AcceptedRoleLabels
import SmzaRp05ChallengeRecordErasure
import SmzaRp05FilteredReadback
import SmzaRp04StatementRecordFilter

/-! # Accepted current outer readback on the raw nonleaf view

The current statement-filter collision-free relation contains every
challenge-erased nonleaf wrapper.  The four actual wrapper records from one
accepted staged execution therefore suffice for the recorded-chain argument
on that smaller view.  Challenge records are removed only for that proof;
the decoder-inertness theorem transports the extracted preambles back to the
actual raw nonleaf view. -/

namespace HegemonCrypto.SmallWood.SmzaRp05CurrentAcceptedNonleafRoleReadback

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
    ∀ role, preambleFromTrace ns role
      (V8Smz9CoherentMerkleGeometry.extract (globalOnlineNext ns)
        (nonleafFilter (globalLeafStatement ns)
          (rawRecords
            (fun key => groupRepresentative
              (included
                (producer.bind fun wire => verifierProgram ns dsl statement pending nonce wire)
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
  let actualProgram := producer.bind fun wire =>
    verifierProgram ns dsl statement pending nonce wire
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
end HegemonCrypto.SmallWood.SmzaRp05CurrentAcceptedNonleafRoleReadback
