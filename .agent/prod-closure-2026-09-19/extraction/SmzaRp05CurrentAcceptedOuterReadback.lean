import SmzaRp05CurrentAcceptedCausalPayloads
import SmzaRp05PhysicalPcsRecordRetention
import SmzaRp05ExecutableMerklePaths
import SmzaRp05AdaptiveRetainedAdviceParser

/-! # Accepted current outer/root readback

The root frame is normalized from the input built by the successful PCS
constructor. Its post-Merkle query is retained through the actual PCS and
verifier records; the root preamble is not an independent parser witness.
-/

namespace HegemonCrypto.SmallWood.SmzaRp05CurrentAcceptedOuterReadback

open HegemonCrypto.CanonicalBytes (Byte decodeLE encodeLE)
open SmzaRp05ExecutableMerkleVerifier
  (Oracle Program Input State rootInput shapeValid merkleProgram finish finalValid
    sequence levels ask)
open SmzaRp05ExecutableChallengeStage
  (PostMerkle postMerkleProgram post_merkle_has_executed_core)
open SmzaRp05ExecutablePcsClosure (ExecutionStages)
open SmzaRp05ExecutablePcsClosureStages (PcsStages)
open SmzaRp05PhysicalPcsRecordRetention
  (pcs_merkle_records_retained execution_pcs_records_retained_in_verifier)
open SmzaRp05PhysicalAcceptedReplayLite (rawLog basisOracle)
open SmzaRp05LeafNamespace (Namespace)
open SmzaRp05RelationRefinement (RelationDsl)
open SmzaRp05CurrentProofWireProgram (ExistingProofFieldView)
open SmzaRp05FilteredDecoderInstability (globalNormalizedPayload globalOnlineNext)
open SmzaRp05StatementNamespace (Statement)
open V8SmzaOracleParser (RawDigest)

local notation "Statement" => SmzaRp05StatementNamespace.Statement

set_option autoImplicit false
set_option maxRecDepth 12000
set_option maxHeartbeats 1000000
noncomputable section

private theorem fixedWidthByteChunks_flatMap (bytes : List Byte) (count : Nat)
    (enough : 8 * count ≤ bytes.length) :
    (List.range count).flatMap (fun i => (bytes.drop (8 * i)).take 8) =
      bytes.take (8 * count) := by
  induction count with
  | zero => simp
  | succ count ih =>
      have enoughPrefix : 8 * count ≤ bytes.length := by omega
      have split := List.take_append_drop (8 * count) bytes
      rw [List.range_succ, List.flatMap_append, ih enoughPrefix]
      have takeAppend :
          (bytes.take (8 * count) ++ bytes.drop (8 * count)).take (8 * count + 8) =
            bytes.take (8 * count) ++ (bytes.drop (8 * count)).take 8 := by
        rw [List.take_append]
        have prefixLength : (bytes.take (8 * count)).length = 8 * count := by
          simp [enoughPrefix]
        rw [prefixLength]
        simp
      rw [← split, Nat.mul_succ, takeAppend]
      simp [List.flatMap]

private theorem flatMap_eq_flatten_map {α β : Type} (values : List α)
    (f : α → List β) : values.flatMap f = (values.map f).flatten := by
  induction values with
  | nil => rfl
  | cons value values ih => simp [ih]

/-- The current response binding words are exactly the statement preamble bytes
after fixed-width little-endian re-encoding. -/
theorem statement_binding_words_encode_exact (statement : Statement) :
    (SmzaRp05ExecutablePcsClosureStatement.statementBindingWords statement).flatMap
      (encodeLE 8) = statement.toBytes := by
  let bytes := statement.toBytes
  have bytesLength : bytes.length = 8 * 138 := by
    simp [bytes, SmzaRp05StatementNamespace.Statement.toBytes_length,
      SmzaRp05LeafNamespace.preambleBytes]
  have chunkLength (i : Nat) (bound : i < 138) :
      ((bytes.drop (8 * i)).take 8).length = 8 := by
    simp only [List.length_take, List.length_drop]
    omega
  have encodedChunk (i : Nat) (bound : i < 138) :
      encodeLE 8 (decodeLE ((bytes.drop (8 * i)).take 8)) =
        (bytes.drop (8 * i)).take 8 := by
    have exact := SmzaRp05AdaptiveRetainedAdviceParser.encode_decode_le
      ((bytes.drop (8 * i)).take 8)
    simpa [chunkLength i bound] using exact
  have chunksReplace :
      ((List.range 138).map (fun i => encodeLE 8
        (decodeLE ((bytes.drop (8 * i)).take 8)))).flatten =
        ((List.range 138).map (fun i => (bytes.drop (8 * i)).take 8)).flatten := by
    congr 1
    apply List.map_congr_left
    intro i member
    exact encodedChunk i (List.mem_range.mp member)
  calc
    (SmzaRp05ExecutablePcsClosureStatement.statementBindingWords statement).flatMap
        (encodeLE 8) =
        ((List.range 138).map (fun i => encodeLE 8
          (decodeLE ((bytes.drop (8 * i)).take 8)))).flatten := by
          rw [flatMap_eq_flatten_map]
          change (((List.range 138).map (fun i =>
            encodeLE 8 (decodeLE ((statement.toBytes.drop (8 * i)).take 8)))).flatten) = _
          rfl
    _ = ((List.range 138).map (fun i => (bytes.drop (8 * i)).take 8)).flatten :=
      chunksReplace
    _ = (List.range 138).flatMap (fun i => (bytes.drop (8 * i)).take 8) := by
      symm
      exact flatMap_eq_flatten_map _ _
    _ = bytes.take (8 * 138) := fixedWidthByteChunks_flatMap bytes 138 (by omega)
    _ = bytes := by simp [bytesLength]
    _ = statement.toBytes := rfl

theorem successful_merkle_root_recorded
    (ns : Namespace) (oracle : Oracle)
    (input : Input) (target : RawDigest)
    (succeeded : (merkleProgram ns input).eval oracle = some target) :
    shapeValid ns input = true ∧ ∃ treeRoot,
      (rootInput input.salt input.binding treeRoot, target) ∈
        ((merkleProgram ns input).record oracle).2 := by
  by_cases shape : shapeValid ns input = true
  · have run :
        ((sequence 38 (SmzaRp05ExecutableMerkleVerifier.initialSlot ns input)).bind
          fun initial => (levels 23 initial).bind (finish input)).eval oracle = some target := by
      simpa only [merkleProgram, shape, if_pos] using succeeded
    obtain ⟨initial, started, afterSequence⟩ :=
      SmzaRp05FinalProgramMiddleExecution.program_bind_success oracle
        (sequence 38 (SmzaRp05ExecutableMerkleVerifier.initialSlot ns input))
        (fun initial => (levels 23 initial).bind (finish input)) target run
    obtain ⟨final, reduced, finishSuccess⟩ :=
      SmzaRp05FinalProgramMiddleExecution.program_bind_success oracle
        (levels 23 initial) (finish input) target afterSequence
    obtain ⟨complete, targetRead⟩ :=
      SmzaRp05ExecutableMerkleVerifier.successful_finish oracle input final target finishSuccess
    have valid : finalValid final = true := by
      simp only [finalValid, decide_eq_true_eq]
      exact complete
    have finishMember :
        (rootInput input.salt input.binding (final 0).hash, target) ∈
          ((finish input final).record oracle).2 := by
      have member :
          (rootInput input.salt input.binding (final 0).hash,
            oracle (rootInput input.salt input.binding (final 0).hash)) ∈
            ((finish input final).record oracle).2 := by
        simp [finish, valid, ask, Program.record]
      simpa only [targetRead] using member
    have afterLevels := Program.bind_log_right oracle (levels 23 initial)
      (finish input) final reduced finishMember
    have afterSequence := Program.bind_log_right oracle
      (sequence 38 (SmzaRp05ExecutableMerkleVerifier.initialSlot ns input))
      (fun initial => (levels 23 initial).bind (finish input)) initial started afterLevels
    refine ⟨shape, (final 0).hash, ?_⟩
    simpa only [merkleProgram, shape, if_pos] using afterSequence
  · have impossible : False := by
      simp [merkleProgram, shape, Program.eval] at succeeded
    exact impossible.elim

private theorem successful_make_merkle_input_fields
    (salt binding : List Byte) (pending : Bool) (indexes : List Nat)
    (rows : List (List HegemonCrypto.SmallWood.Goldilocks))
    (masks : SmzaRp05PcsWireProjection.FieldMatrix)
    (tapes : List (List Byte)) (paths : List (List RawDigest))
    (input : Input)
    (built : SmzaRp05PcsMerklePayload.makeMerkleInput salt binding pending
      indexes rows masks tapes paths = some input) :
    input.salt = salt ∧ input.binding = binding := by
  unfold SmzaRp05PcsMerklePayload.makeMerkleInput at built
  split at built
  · simp at built
  · have fields := Option.some.inj built
    exact ⟨(congrArg Input.salt fields).symm,
      (congrArg Input.binding fields).symm⟩

/-- The actual post-Merkle root query is normalized from constructor bytes,
and its digest output is retained in this accepted verifier's ordered
record. `treeRoot` is the root embedded in that exact query input; `target`
is its actual oracle answer returned by the post-Merkle stage. -/
theorem successful_pcs_root_query_readback
    (ns : Namespace) (dsl : RelationDsl) (statement : Statement) (pending : Bool)
    (nonce : Fin (2 ^ 32)) (wire : ExistingProofFieldView) (oracle : Oracle)
    (transcript : SmzaRp05ExecutableFinalVerifier.ReconstructedTranscript)
    (execution : ExecutionStages ns dsl statement pending statement.toBytes
      (SmzaRp05ExecutablePcsClosureStatement.statementBindingWords statement)
      nonce wire oracle transcript)
    (pcs : PcsStages ns execution.openingPending wire.hPiop
      (SmzaRp05PcsToFinalProgram.sameProofRows execution.middle.pcs execution.piop)
      execution.decs
      (List.ofFn fun j : Fin 6 => V8Smz9PiopReconstruction.points execution.opening j)
      wire.salt statement.toBytes
      (SmzaRp05ExecutablePcsClosureStatement.statementBindingWords statement)
      wire.tapes wire.paths oracle execution.hashFpp execution.pcsPending)
    (transcriptSuccess :
      (SmzaRp05ExecutablePcsClosure.transcriptProgram ns dsl statement pending
        statement.toBytes (SmzaRp05ExecutablePcsClosureStatement.statementBindingWords statement)
        nonce wire).eval oracle = some transcript) :
    ∃ treeRoot,
      let rootQuery := rootInput pcs.merkleInput.salt pcs.merkleInput.binding treeRoot
      (globalNormalizedPayload ns rootQuery =
        some ⟨.root, pcs.merkleInput.salt ++ List.ofFn treeRoot ++
          pcs.merkleInput.binding⟩) ∧
      (pcs.merkleInput.salt ++ List.ofFn treeRoot ++ pcs.merkleInput.binding).drop 96 =
        statement.toBytes ∧
      globalOnlineNext ns .root rootQuery = some [(.tree 23, treeRoot)] ∧
      (rootQuery, pcs.post.root) ∈
        ((SmzaRp05ExecutablePcsClosureStatement.verifierProgram ns dsl statement
          pending nonce wire).record oracle).2 := by
  have inputFields := successful_make_merkle_input_fields wire.salt statement.toBytes
    pcs.sampledPending pcs.indexes pcs.rows execution.decs.maskingEvals
    wire.tapes wire.paths pcs.merkleInput
    pcs.inputBuilt
  have core := post_merkle_has_executed_core ns oracle pcs.merkleInput pcs.post
    pcs.postExecuted
  obtain ⟨shapeOk, treeRoot, rootInMerkle⟩ := successful_merkle_root_recorded ns oracle
    pcs.merkleInput pcs.post.root core.1
  have shapeData : ns.canonicalPreamble pcs.merkleInput.binding = true ∧
      pcs.merkleInput.salt.length = 32 ∧
      ∀ j, pcs.merkleInput.indices j < 8388608 := by
    have h := shapeOk
    simp only [shapeValid, Bool.and_eq_true, decide_eq_true_eq] at h
    exact ⟨h.1, h.2.1, h.2.2.1⟩
  have saltLength : pcs.merkleInput.salt.length = 32 := shapeData.2.1
  have bindingEq : pcs.merkleInput.binding = statement.toBytes := inputFields.2
  have bindingLength : pcs.merkleInput.binding.length = 1104 := by
    rw [bindingEq]
    simpa [SmzaRp05LeafNamespace.preambleBytes] using
      SmzaRp05StatementNamespace.Statement.toBytes_length statement
  have normalized := SmzaRp05ExecutableMerkleVerifier.global_nonleaf_frame ns .root
    (pcs.merkleInput.salt ++ List.ofFn treeRoot ++ pcs.merkleInput.binding)
    (by decide) (by
      simp [V8SmzaOracleParser.payloadBytes, saltLength, bindingLength])
  have normalizedRoot : globalNormalizedPayload ns
      (rootInput pcs.merkleInput.salt pcs.merkleInput.binding treeRoot) =
        some ⟨.root,
          pcs.merkleInput.salt ++ List.ofFn treeRoot ++ pcs.merkleInput.binding⟩ := by
    simpa [rootInput] using normalized
  have headerLength : (pcs.merkleInput.salt ++ List.ofFn treeRoot).length = 96 := by
    simp [saltLength]
  have dropped :
    (pcs.merkleInput.salt ++ List.ofFn treeRoot ++ pcs.merkleInput.binding).drop 96 =
        statement.toBytes := by
    rw [show 96 = (pcs.merkleInput.salt ++ List.ofFn treeRoot).length
      from headerLength.symm]
    rw [List.drop_append_of_le_length (Nat.le_refl _)]
    simp [bindingEq]
  have rootNext := SmzaRp05ExecutableMerkleVerifier.root_parser_roundtrip ns
    pcs.merkleInput.salt pcs.merkleInput.binding treeRoot saltLength bindingLength
  have merkleRetained := pcs_merkle_records_retained ns execution.openingPending
    wire.hPiop
    (SmzaRp05PcsToFinalProgram.sameProofRows execution.middle.pcs execution.piop)
    execution.decs
    (List.ofFn fun j : Fin 6 => V8Smz9PiopReconstruction.points execution.opening j)
    wire.salt statement.toBytes
    (SmzaRp05ExecutablePcsClosureStatement.statementBindingWords statement)
    wire.tapes wire.paths oracle execution.hashFpp execution.pcsPending pcs
    execution.pcsExecuted
  have rootInAttempt :
      (rootInput pcs.merkleInput.salt pcs.merkleInput.binding treeRoot, pcs.post.root) ∈
        (SmzaRp05ExecutableMerkleVerifier.recordedAttempt ns oracle pcs.merkleInput).2 := by
    simpa [SmzaRp05ExecutableMerkleVerifier.recordedAttempt] using rootInMerkle
  have rootInPcs := merkleRetained _ _ rootInAttempt
  have verifierRetained := execution_pcs_records_retained_in_verifier ns dsl statement
    pending nonce wire oracle transcript execution transcriptSuccess
  have rootInVerifier := verifierRetained _ rootInPcs
  refine ⟨treeRoot, normalizedRoot, ?_, rootNext, ?_⟩
  · simpa [bindingEq] using dropped
  · simpa [rootInput, bindingEq] using rootInVerifier

end
end HegemonCrypto.SmallWood.SmzaRp05CurrentAcceptedOuterReadback
