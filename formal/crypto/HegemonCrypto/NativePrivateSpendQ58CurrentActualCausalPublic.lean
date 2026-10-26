import HegemonCrypto.NativePrivateSpendQ58CurrentCausalSourceJoin
import HegemonCrypto.NativePrivateSpendQ58CurrentFullLogReadback
import HegemonCrypto.NativePrivateSpendQ58CurrentActualTraceLabel

/-! Actual current root frames determine the causal public77 data. Root-log
membership, salt/binding shape and selected input are derived from the actual
ordinary Merkle/PCS execution. No F.Valid, recorded-root or event-support
certificate is an input. Collision-freedom is the existing separately paid
arm; source coverage is the same actual global raw-log transport. SOURCE ONLY.
-/
namespace HegemonCrypto.SmallWood.NativePrivateSpendQ58CurrentActualCausalPublic
open scoped Classical
open SmzaRp05ExecutableMerkleVerifier (Program Oracle ask sequence)
open SmzaRp05FilteredDecoderInstability (RawRecords)
open SmzaRecordedTracePath (RecordsCollisionFree selected_input_of_recorded)
open V8Smz9CoherentMerkleGeometry (extract)
namespace CM
export NativePrivateSpendQ58CurrentCompactMerkle
  (Namespace Input State rootInput shapeValid initialSlot levels finish finalValid merkleProgram
   acceptedResult recordedAttempt accepted_shape_valid accepted_has_executed_common_root root_parser_roundtrip)
end CM
namespace E
export NativePrivateSpendQ58CurrentExecutableVerifier (Wire Transcript ExecutionStages)
end E
namespace F
export NativePrivateSpendQ58CurrentFullStageEnvelope
  (RawDigest rawNext rawPayload raw_payload_frame rootInput payloadBytes)
end F
namespace FL
export NativePrivateSpendQ58CurrentFullLogReadback (fullRecords stages_merkle_and_fpp_logs_subset_full)
end FL
namespace AL
export NativePrivateSpendQ58CurrentActualTraceLabel (sourceRecords current_source_valid_input_is_unparsed)
end AL
namespace T
export NativePrivateSpendQ58CurrentTracePiopMass (traceInput)
end T
namespace CS
export NativePrivateSpendQ58CurrentCausalSourceJoin
  (causalBinding causalPublic rootTrace causalRelation SourceTemplate NativeDataReadback native_data_identifies_relation)
end CS
namespace SR
export NativePrivateSpendQ58CurrentSourceTraceReadback
  (recorded_current_fpp_trace_readback recorded_current_piop_trace_readback)
end SR
noncomputable section
set_option autoImplicit false
set_option Elab.async false
set_option maxHeartbeats 0
set_option maxRecDepth 0
-- Matching the bind/log interfaces must not normalize the 58-by-23 tree.
attribute [local irreducible] CM.merkleProgram SmzaRp05ExecutableMerkleVerifier.sequence CM.levels CM.initialSlot CM.finish

/-- The actual common-root execution supplies its literal root frame and the
namespace binding equality. No selected input/log certificate is supplied. -/
theorem accepted_current_merkle_records_same_namespace_root
    (ns : CM.Namespace) (oracle : Oracle) (input : CM.Input) (target : F.RawDigest)
    (accepted : CM.acceptedResult ns oracle input = some target) :
    input.salt.length = 32 ∧ input.binding = ns.binding ∧
      ∃ tree, (CM.rootInput input.salt ns.binding tree, target) ∈
        (CM.recordedAttempt ns oracle input).2 := by
  have shape := CM.accepted_shape_valid ns oracle input target accepted
  have data := shape
  simp only [CM.shapeValid, NativePrivateSpendQ58CurrentCompactMerkle.Namespace.canonicalPreamble, Bool.and_eq_true, decide_eq_true_eq] at data
  have binding : input.binding = ns.binding := data.1
  have salt : input.salt.length = 32 := data.2.1
  obtain ⟨_pending, initial, final, started, reduced, complete, targetEq⟩ :=
    CM.accepted_has_executed_common_root ns oracle input target accepted
  have valid : CM.finalValid final = true := by
    simp only [CM.finalValid, decide_eq_true_eq]
    exact complete
  have finalMember : (CM.rootInput input.salt input.binding (final 0).hash, target) ∈
      ((CM.finish input final).record oracle).2 := by
    unfold CM.finish
    rw [if_pos valid]
    rw [targetEq]
    exact List.mem_cons_self
  have treeMember := Program.bind_log_right oracle (CM.levels 23 initial)
    (CM.finish input) final reduced finalMember
  have wholeMember := Program.bind_log_right oracle (sequence 58 (CM.initialSlot ns input))
    (fun started => (CM.levels 23 started).bind (CM.finish input)) initial started treeMember
  have treeEq : CM.merkleProgram ns input =
      (sequence 58 (CM.initialSlot ns input)).bind
        (fun started => (CM.levels 23 started).bind (CM.finish input)) := by
    unfold CM.merkleProgram
    rw [if_pos shape]
  refine ⟨salt, binding, (final 0).hash, ?_⟩
  change (CM.rootInput input.salt ns.binding (final 0).hash, target) ∈
    ((CM.merkleProgram ns input).record oracle).2
  rw [treeEq, ← binding]
  exact wholeMember

/-- The actual current verifier derives the root frame in its complete log,
including exact salt shape and canonical public-binding bytes. -/
theorem actual_current_stages_record_same_namespace_root
    (ns : CM.Namespace) (relation : NativePrivateSpendQ58CurrentPublicOpening.Relation)
    (nonce : Fin (2^32)) (wire : E.Wire) (oracle : Oracle) (transcript : E.Transcript)
    (stages : E.ExecutionStages ns relation false nonce wire oracle transcript)
    (clean : transcript.pending = false) :
    stages.pcs.input.salt.length = 32 ∧ stages.pcs.input.binding = ns.binding ∧
      ∃ tree, (CM.rootInput stages.pcs.input.salt ns.binding tree, stages.pcs.root) ∈
        FL.fullRecords ns relation false nonce wire oracle := by
  have pcsClean := NativePrivateSpendQ58CurrentAcceptedLeafSupport.stages_pcs_pending_false
    ns relation false nonce wire oracle transcript stages clean
  have merkle := NativePrivateSpendQ58CurrentAcceptedLeafSupport.pcs_clean_merkle_accepted
    ns stages.openingPending wire stages.decoded stages.opening oracle stages.pcs stages.pcsExecuted pcsClean
  obtain ⟨salt, binding, tree, recorded⟩ :=
    accepted_current_merkle_records_same_namespace_root ns oracle stages.pcs.input stages.pcs.root merkle
  obtain ⟨included, _⟩ := FL.stages_merkle_and_fpp_logs_subset_full
    ns relation false nonce wire oracle transcript stages
  exact ⟨salt, binding, tree, included (List.mem_toFinset.mpr recorded)⟩

/-- Current collision-free recorded selection of the actual root frame
identifies all77 causal public words. This is not whole-tree extraction
agreement: only the actually recorded root input is used. -/
theorem recorded_actual_root_trace_has_same_causal_public
    (ns : CM.Namespace) (salt : List HegemonCrypto.CanonicalBytes.Byte)
    (saltLength : salt.length = 32) (tree target : F.RawDigest)
    (records : RawRecords) (free : RecordsCollisionFree records)
    (recorded : (CM.rootInput salt ns.binding tree, target) ∈ records) :
    CS.causalPublic .decsMatrix (extract F.rawNext records 25 .root target) =
      (fun i : Fin 77 => (V8SmzaOracleParser.wordAt ns.binding i.val : Goldilocks)) := by
  have edge := CM.root_parser_roundtrip salt ns.binding tree saltLength ns.bindingLength
  have path : SmzaRecordedTracePath.RecordedPath F.rawNext records .root target []
      (CM.rootInput salt ns.binding tree) :=
    .here V8SmzaOracleParser.Stage.root target (CM.rootInput salt ns.binding tree) recorded (by simp [edge])
  have readback := SmzaRecordedTracePath.recorded_path_readback F.rawNext records free
    .root target [] (CM.rootInput salt ns.binding tree) path 25 (by decide)
  have inputEq : T.traceInput (extract F.rawNext records 25 .root target) =
      CM.rootInput salt ns.binding tree := by
    unfold T.traceInput
    rw [readback]
    rfl
  have parsed := F.raw_payload_frame .root 89 (salt ++ List.ofFn tree ++ ns.binding)
    (by decide) (by simp [saltLength, ns.bindingLength])
    (by simp [F.payloadBytes, saltLength, ns.bindingLength])
  have prefixLength : (salt ++ List.ofFn tree).length = 96 := by simp [saltLength]
  have bindingDrop : (salt ++ List.ofFn tree ++ ns.binding).drop 96 = ns.binding := by
    rw [← prefixLength]
    simp
  funext i
  unfold CS.causalPublic CS.causalBinding
  simp only [CS.rootTrace, inputEq, CM.rootInput, F.rootInput, parsed, ite_true, bindingDrop]

/-- Only the root input is consulted by the deterministic public label. -/
private theorem causal_public_of_same_root_trace
    (role : SmzaChallengeStageTargets.Role)
    (trace root : NativePrivateSpendQ58CurrentFullStageEnvelope.Trace)
    (same : CS.rootTrace role trace = CS.rootTrace .decsMatrix root) :
    CS.causalPublic role trace = CS.causalPublic .decsMatrix root := by
  funext i
  unfold CS.causalPublic CS.causalBinding
  rw [same]

/-- The actual current PIOP source chains derive both role traces' public77
labels from their SAME actual root frame. Extra/missing unrelated tree
branches never enter this proof. Coverage is the original complete actual
verifier log supplied by the separately derived global observer claims. -/
theorem actual_current_completed_piop_traces_have_same_public
    (ns : CM.Namespace) (relation : NativePrivateSpendQ58CurrentPublicOpening.Relation)
    (nonce : Fin (2^32)) (wire : E.Wire) (oracle : Oracle) (transcript : E.Transcript)
    (stages : E.ExecutionStages ns relation false nonce wire oracle transcript)
    (clean : transcript.pending = false)
    (records : RawRecords) (free : RecordsCollisionFree records)
    (covered : AL.sourceRecords (FL.fullRecords ns relation false nonce wire oracle) ⊆ records)
    (finalRecorded : (NativePrivateSpendQ58CurrentExecutableVerifier.finalInput transcript, wire.hPiop) ∈
      ((NativePrivateSpendQ58CurrentExecutableVerifier.verifierProgram ns relation false nonce wire).record oracle).2) :
    CS.causalPublic .piopMatrix (extract F.rawNext records 26 .fpp stages.pcs.hashFpp) =
        (fun i : Fin 77 => (V8SmzaOracleParser.wordAt ns.binding i.val : Goldilocks)) ∧
      CS.causalPublic .piopOpening (extract F.rawNext records 27 .piop wire.hPiop) =
        (fun i : Fin 77 => (V8SmzaOracleParser.wordAt ns.binding i.val : Goldilocks)) := by
  obtain ⟨salt, _binding, tree, rootInFull⟩ :=
    actual_current_stages_record_same_namespace_root ns relation nonce wire oracle transcript stages clean
  have rootEdge := CM.root_parser_roundtrip stages.pcs.input.salt ns.binding tree salt ns.bindingLength
  have rootRecorded : (CM.rootInput stages.pcs.input.salt ns.binding tree, stages.pcs.root) ∈ records :=
    covered (Finset.mem_filter.mpr ⟨rootInFull,
      AL.current_source_valid_input_is_unparsed .root _ (by simp [rootEdge])⟩)
  have rootPublic := recorded_actual_root_trace_has_same_causal_public
    ns stages.pcs.input.salt salt tree stages.pcs.root records free rootRecorded
  obtain ⟨fppInput, fppInFull, fppEdge⟩ :=
    NativePrivateSpendQ58CurrentActualTraceLabel.stages_have_recorded_current_source_edge
      ns relation false nonce wire oracle transcript stages
  have fppRecorded : (fppInput, stages.pcs.hashFpp) ∈ records :=
    covered (Finset.mem_filter.mpr ⟨fppInFull,
      AL.current_source_valid_input_is_unparsed .fpp _ (by simp [fppEdge])⟩)
  have fppTrace := SR.recorded_current_fpp_trace_readback records free fppInput
    stages.pcs.hashFpp stages.pcs.root fppRecorded fppEdge
  have piopEdge := NativePrivateSpendQ58CurrentSourceTraceReadback.current_final_frame_has_literal_fpp_edge transcript
  have piopRecorded : (NativePrivateSpendQ58CurrentExecutableVerifier.finalInput transcript, wire.hPiop) ∈ records :=
    covered (Finset.mem_filter.mpr ⟨List.mem_toFinset.mpr finalRecorded,
      AL.current_source_valid_input_is_unparsed .piop _ (by simp [piopEdge])⟩)
  have piopTrace := SR.recorded_current_piop_trace_readback records free transcript wire.hPiop piopRecorded
  have fppSame : transcript.hashFpp = stages.pcs.hashFpp := by
    exact (congrArg NativePrivateSpendQ58CurrentExecutableVerifier.Transcript.hashFpp
      stages.reconstructed).symm
  constructor
  · apply (causal_public_of_same_root_trace .piopMatrix _ _ ?_).trans rootPublic
    change NativePrivateSpendQ58CurrentTracePiopMass.child
      (extract F.rawNext records 26 .fpp stages.pcs.hashFpp) 0 =
        extract F.rawNext records 25 .root stages.pcs.root
    rw [fppTrace]
    rfl
  · apply (causal_public_of_same_root_trace .piopOpening _ _ ?_).trans rootPublic
    change NativePrivateSpendQ58CurrentTracePiopMass.child
      (NativePrivateSpendQ58CurrentTracePiopMass.child
        (extract F.rawNext records 27 .piop wire.hPiop) 0) 0 =
      extract F.rawNext records 25 .root stages.pcs.root
    rw [piopTrace, fppSame, fppTrace]
    rfl

/-- Exact finite native constructor data identifies the relation of an actual
recorded current role trace. The binding premise is ordinary CSR/getter data,
not satisfiability, source validity or an event-inclusion assumption. -/
theorem actual_causal_public_identifies_native_relation
    (template : CS.SourceTemplate) (ns : CM.Namespace)
    (relation : NativePrivateSpendQ58CurrentPublicOpening.Relation)
    (role : SmzaChallengeStageTargets.Role)
    (trace : NativePrivateSpendQ58CurrentFullStageEnvelope.Trace)
    (publicReadout : CS.causalPublic role trace =
      (fun i : Fin 77 => (V8SmzaOracleParser.wordAt ns.binding i.val : Goldilocks)))
    (nativeData : CS.NativeDataReadback template
      (fun i : Fin 77 => (V8SmzaOracleParser.wordAt ns.binding i.val : Goldilocks)) relation) :
    relation = CS.causalRelation template role trace := by
  unfold CS.causalRelation
  rw [publicReadout]
  exact CS.native_data_identifies_relation template _ relation nativeData

end
end HegemonCrypto.SmallWood.NativePrivateSpendQ58CurrentActualCausalPublic
