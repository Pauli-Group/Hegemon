import HegemonCrypto.NativePrivateSpendQ58CurrentSourceTraceReadback
import HegemonCrypto.NativePrivateSpendQ58CurrentGroupedFiberGamma
import HegemonCrypto.NativePrivateSpendQ58CurrentGroupedGamma
import HegemonCrypto.NativePrivateSpendQ58CurrentClaimReplay
import HegemonCrypto.NativePrivateSpendQ58CurrentComplementReadback
import HegemonCrypto.NativePrivateSpendQ58CurrentActiveBranchClaims

/-! Literal current FPP/PIOP traces identify the calculated source label.
The unrestricted retained-response selector is identified with the actual
source-hash request by collision-free completed records, not by source-frame
invariance. The physical endpoint derives its stages and recorded DECS base
from the actual accepted branch replay. No geometry, desired candidate,
whole-view equality or per-key oracle agreement is an endpoint premise.
The restored-basis PCS endpoint separately uses the existing same-fiber
gamma theorem and an actual recorded DECS base vector for that PCS root.
SOURCE ONLY. Earlier-prefix transport, probability and kernel checks remain
separate; no accepted-invalid mass or G3 qualification is asserted. -/
namespace HegemonCrypto.SmallWood.NativePrivateSpendQ58CurrentActualTraceLabel

open SmzaRp05ExecutableMerkleVerifier (Program Oracle)
open SmzaRp05ExecutableChallengeStage (digestWords fieldLoop)
open SmzaRp05FilteredDecoderInstability (RawRecords)
open SmzaRecordedTracePath (RecordsCollisionFree readPath selected_input_of_recorded)
open V8Smz9CoherentMerkleGeometry (extract selectedInput)
open SmzaChallengeStageTargets (Role)
open V8Smz9CoherentVectorMerkle (VectorOutput)
open V8Smz9CoherentMerkleInstrument (rawRecords)
open HegemonCrypto.CmsCompressedOracle (Basis)
open HegemonCrypto.CmsOracleSimulation (globalDecompress)
open HegemonCrypto.FiniteOracleDatabase (Database)
open HegemonCrypto.CmsOracleDatabaseBridge (ClaimsDatabaseEvent)
open SmzaRp05PhysicalAcceptedReplayLite
  (Branches branchResult answerLog rawLog physicalRun basisOracle)
open scoped Classical
namespace F
export NativePrivateSpendQ58CurrentFullStageEnvelope
  (RawInput RawDigest Trace rawPayload rawNext payloadNext)
end F
namespace E
export NativePrivateSpendQ58CurrentExecutableVerifier
  (Wire DecodedFields Opening PcsOutput Transcript ExecutionStages fieldKeys fieldXof
    pcsProgram verifierProgram finalInput reconstruct accepted_execution_has_stages)
end E
namespace S
export NativePrivateSpendQ58CurrentSourceCandidate
  (SourceLabel calculatedCandidate labelFromInputs gammaAt pcs_execution_gamma_is_label_gamma
    pcs_execution_candidate_is_label_candidate)
end S
namespace T
export NativePrivateSpendQ58CurrentTracePiopMass (child traceInput childDigest fppLabel)
end T
namespace RR
export NativePrivateSpendQ58CurrentRetainedResponseReadback (priorInput sourceHashProgram)
end RR
namespace FL
export NativePrivateSpendQ58CurrentFullLogReadback
  (fppProgram fullRecords pcs_execution_has_actual_log_parts stages_pcs_log_subset_full
    stages_merkle_and_fpp_logs_subset_full stages_prior_bad_is_impossible_on_collision_free_full_log)
end FL
namespace SR
export NativePrivateSpendQ58CurrentSourceTraceReadback
  (successful_source_hash_has_literal_current_root_edge recorded_current_fpp_trace_readback
    recorded_current_piop_trace_readback current_final_frame_has_literal_fpp_edge)
end SR
namespace C
export NativePrivateSpendQ58CurrentRoleClassifier
  (FixedTable canonicalCurrentQueryBytes parseCurrentStageQuery RoleActive
    other_bounded_role_is_fixed fixed_vector_at_nonce_eq_actual_cell)
end C
namespace GF
export NativePrivateSpendQ58CurrentGammaFiber
  (currentRoleCaps fixedGamma gammaFromVector current_decs_base_vector_has_same_fiber_current_gamma)
end GF
namespace CG
export NativePrivateSpendQ58CurrentConstructorGrouping
  (Counter Key frame zero encode decode keyBytes key_bytes_injective
    frame_is_literal_current frame_parser_receipt recorded_current_base_parser)
export NativePrivateSpendQ58CurrentConstructorGrouping
  (coordinate current_frame_address stored_current_vector_answers_every_counter)
end CG
namespace FG
export NativePrivateSpendQ58CurrentGroupedFiberGamma
  (live current_same_fiber_fixed_gamma_is_completed_oracle_gamma)
end FG
namespace A
export NativePrivateSpendQ58ActiveEventProjection (ActiveKey Memory restoreBasis merge)
end A
namespace P
export NativePrivateSpendQ58PartitionTransport (CmsState FixedTable conditioned)
end P
namespace RG
export NativePrivateSpendQ58CurrentRecoveryGeometry
  (RecoveryGeometry MatrixBad SmallSupportBad pcs_execution_has_geometry_or_named_bad_event)
end RG
namespace CR
export NativePrivateSpendQ58CurrentClaimReplay
  (fullClaims claimOracle current_claims_store_every_branch_vector current_grouped_claims_replay_actual_program)
end CR
namespace AC
export NativePrivateSpendQ58CurrentActiveBranchClaims
  (live activeClaims fixedCompatible current_active_claims_complete_full_branch
    current_active_claims_replay_same_program current_claimed_source_record_is_in_active_database)
end AC
namespace O
export NativePrivateSpendQ58CurrentOrdinaryRecovery (PriorBad actualView)
end O
noncomputable section
set_option autoImplicit false
set_option Elab.async false
set_option maxHeartbeats 0
set_option maxRecDepth 0
local instance : DecidableEq F.RawInput :=
  @instDecidableEqList HegemonCrypto.CanonicalBytes.Byte
    (inferInstance : DecidableEq HegemonCrypto.CanonicalBytes.Byte)

private theorem records_collision_instance_transport {Input Digest : Type*}
    (left right : DecidableEq (Input × Digest))
    (prior : Finset (Input × Digest)) (records : List (Input × Digest))
    (good : RecordsCollisionFree
      (@Union.union (Finset (Input × Digest)) (@Finset.instUnion (Input × Digest) left)
        prior (@List.toFinset (Input × Digest) left records))) :
    RecordsCollisionFree
      (@Union.union (Finset (Input × Digest)) (@Finset.instUnion (Input × Digest) right)
        prior (@List.toFinset (Input × Digest) right records)) := by
  have same : left = right := Subsingleton.elim _ _
  cases same
  exact good

/-- Even the ANY-preimage response selector is forced to the actual raw
source request on this collision-free completed record. -/
theorem recorded_response_is_prior_input
    (records : RawRecords) (free : RecordsCollisionFree records)
    (input : F.RawInput) (target : F.RawDigest) (recorded : (input, target) ∈ records) :
    RR.priorInput records target = some input := by
  change selectedInput (fun (_ : Unit) (_ : F.RawInput) =>
    (some [] : Option (List (Unit × F.RawDigest)))) records () target = some input
  exact selected_input_of_recorded _ records free () target input recorded (by simp)

theorem current_fpp_edge_identifies_payload_digest
    (input : F.RawInput) (root : F.RawDigest)
    (edge : F.rawNext .fpp input = some [(.root, root)]) :
    V8SmzaOracleParser.digestAt
      (((F.rawPayload input).map V8SmzaOracleParser.Payload.bytes).getD []) 0 = root := by
  cases parsed : F.rawPayload input with
  | none => simp [F.rawNext, parsed] at edge
  | some payload =>
      cases kind : payload.kind <;> simp [F.rawNext, parsed, F.payloadNext, kind] at edge
      simpa only [parsed, Option.map_some, Option.getD_some] using edge

theorem current_piop_edge_identifies_payload_digest
    (input : F.RawInput) (fpp : F.RawDigest)
    (edge : F.rawNext .piop input = some [(.fpp, fpp)]) :
    V8SmzaOracleParser.digestAt
      (((F.rawPayload input).map V8SmzaOracleParser.Payload.bytes).getD []) 0 = fpp := by
  cases parsed : F.rawPayload input with
  | none => simp [F.rawNext, parsed] at edge
  | some payload =>
      cases kind : payload.kind <;> simp [F.rawNext, parsed, F.payloadNext, kind] at edge
      simpa only [parsed, Option.map_some, Option.getD_some] using edge

theorem current_source_valid_input_is_unparsed
    (stage : V8SmzaOracleParser.Stage) (input : F.RawInput)
    (valid : (F.rawNext stage input).isSome) : C.parseCurrentStageQuery input = none := by
  cases parsed : C.parseCurrentStageQuery input with
  | none => rfl
  | some query =>
      have inert := NativePrivateSpendQ58CurrentChallengeSourceDisjoint.current_parsed_challenge_has_no_source_edges
        stage input query parsed
      simp [inert] at valid

def sourceRecords (records : RawRecords) : RawRecords :=
  records.filter fun record => C.parseCurrentStageQuery record.1 = none

/-- Every source-grammar path remains recorded under source-only coverage.
Challenge records are not needed to prove this path readback. -/
theorem current_recorded_path_source_subset
    (left right : RawRecords) (covered : sourceRecords left ⊆ right)
    (stage : V8SmzaOracleParser.Stage) (target : F.RawDigest)
    (path : List Nat) (input : F.RawInput)
    (recorded : SmzaRecordedTracePath.RecordedPath F.rawNext left stage target path input) :
    SmzaRecordedTracePath.RecordedPath F.rawNext right stage target path input := by
  induction recorded with
  | here stage target input member valid =>
      exact SmzaRecordedTracePath.RecordedPath.here stage target input
        (covered (Finset.mem_filter.mpr ⟨member, current_source_valid_input_is_unparsed stage input valid⟩)) valid
  | step stage target input edges index childStage childTarget rest leaf member parsed address below ih =>
      have unparsed := current_source_valid_input_is_unparsed stage input (by simp [parsed])
      exact SmzaRecordedTracePath.RecordedPath.step stage target input edges index childStage childTarget rest leaf
        (covered (Finset.mem_filter.mpr ⟨member, unparsed⟩)) parsed address ih

/-- Actual success makes this source program's entire record one current
FPP frame. Thus source-only coverage also discharges its union-collision arm. -/
theorem successful_current_source_hash_record_is_single
    (oracle : Oracle) (root target : F.RawDigest)
    (fields : SmzaRp05DecsResponseProjection.DecodedDecsResponseFields)
    (rows gamma : List (List SmzaRp05ExecutableChallengeStage.FieldWord))
    (points : List SmzaRp05ExecutableChallengeStage.FieldWord)
    (common : List Nat) (commonLength : common.length = 77)
    (success : (RR.sourceHashProgram (digestWords root) fields rows gamma points common).eval oracle = some target) :
    ∃ input, ((RR.sourceHashProgram (digestWords root) fields rows gamma points common).record oracle).2 =
        [(input, target)] ∧ F.rawNext .fpp input = some [(.root, root)] := by
  obtain ⟨input, recorded, edge⟩ := SR.successful_source_hash_has_literal_current_root_edge
    oracle root target fields rows gamma points common commonLength success
  have length : ((RR.sourceHashProgram (digestWords root) fields rows gamma points common).record oracle).2.length = 1 := by
    cases built : NativePrivateSpendQ58CurrentAcceptedDecs.currentTranscript
        (digestWords root) fields rows gamma points with
    | none => simp [RR.sourceHashProgram, built, Program.eval] at success
    | some words => simp [RR.sourceHashProgram, built, SmzaRp05ExecutableMerkleVerifier.ask, Program.record]
  cases singleton : ((RR.sourceHashProgram (digestWords root) fields rows gamma points common).record oracle).2 with
  | nil => simp [singleton] at recorded
  | cons call rest =>
      cases rest with
      | nil =>
          have same : (input, target) = call := by
            simpa only [singleton, List.mem_singleton] using recorded
          exact ⟨input, congrArg List.singleton same.symm, edge⟩
      | cons next rest =>
          simp only [singleton, List.length_cons] at length
          omega

variable {Key Counter : Type}
variable [Fintype Key] [DecidableEq Key] [Fintype Counter] [DecidableEq Counter]

omit [Fintype Key] [DecidableEq Key] [Fintype Counter] [DecidableEq Counter]
/-- Fixed gamma is the only role-table input to this intermediate algebraic
lemma. The concrete physical endpoints below derive it from one recorded
other-role vector. No candidate or decoder-view equality is assumed. -/
theorem recorded_current_fpp_label_is_literal_inputs
    (selected : Role) (keyBytes : Key → F.RawInput)
    (fixed : C.FixedTable (Counter := Counter) selected GF.currentRoleCaps keyBytes)
    (decode : F.RawInput → VectorOutput Counter → F.RawDigest)
    (records : RawRecords) (free : RecordsCollisionFree records)
    (input : F.RawInput) (fpp root : F.RawDigest)
    (gamma : List (List SmzaRp05ExecutableChallengeStage.FieldWord))
    (recorded : (input, fpp) ∈ records)
    (edge : F.rawNext .fpp input = some [(.root, root)])
    (fixedGamma : GF.fixedGamma selected keyBytes fixed decode root = some gamma) :
    T.fppLabel selected keyBytes fixed decode (extract F.rawNext records 26 .fpp fpp) =
      S.labelFromInputs records root fpp gamma := by
  have trace := SR.recorded_current_fpp_trace_readback records free input fpp root recorded edge
  have response := recorded_response_is_prior_input records free input fpp recorded
  have digest : T.childDigest
      (.record input [extract F.rawNext records 25 .root root]) = root :=
    current_fpp_edge_identifies_payload_digest input root edge
  rw [trace]
  change
    ({
      rootTrace := extract F.rawNext records 25 .root root
      responseInput := some input
      gamma := (GF.fixedGamma selected keyBytes fixed decode
        (T.childDigest (.record input [extract F.rawNext records 25 .root root]))).getD [] } : S.SourceLabel) =
    ({
      rootTrace := extract F.rawNext records 25 .root root
      responseInput := RR.priorInput records fpp
      gamma := gamma } : S.SourceLabel)
  rw [digest, fixedGamma, response]
  rfl

def pcsRecords (ns : NativePrivateSpendQ58CurrentCompactMerkle.Namespace)
    (pending : Bool) (wire : E.Wire) (decoded : E.DecodedFields)
    (opening : E.Opening) (oracle : Oracle) : RawRecords :=
  ((E.pcsProgram ns pending wire decoded opening).record oracle).2.toFinset

/-- The actual successful PCS derives the source hash request and its root
edge, both in that PCS's own record. This uses no supplied raw lineage. -/
theorem pcs_execution_has_recorded_current_source_edge
    (ns : NativePrivateSpendQ58CurrentCompactMerkle.Namespace) (pending : Bool)
    (wire : E.Wire) (decoded : E.DecodedFields) (opening : E.Opening)
    (oracle : Oracle) (output : E.PcsOutput)
    (executed : (E.pcsProgram ns pending wire decoded opening).eval oracle = some output) :
    ∃ input, (input, output.hashFpp) ∈ pcsRecords ns pending wire decoded opening oracle ∧
      F.rawNext .fpp input = some [(.root, output.root)] := by
  obtain ⟨_, _, _, _, _, _, _, _, _, _, _, _, _, fppExecuted, _⟩ :=
    NativePrivateSpendQ58CurrentAcceptedPcsFacts.pcs_execution_has_actual_facts
      ns pending wire decoded opening oracle output executed
  obtain ⟨input, sourceRecorded, edge⟩ := SR.successful_source_hash_has_literal_current_root_edge
    oracle output.root output.hashFpp decoded.decs
    (output.rows.map fun row => row.map SmzaRp05ExecutableRestore.toWord)
    output.gamma (output.decsPoints.map SmzaRp05ExecutableRestore.toWord)
    (List.ofFn fun i : Fin 77 => V8SmzaOracleParser.wordAt ns.binding i.val)
    (by simp) fppExecuted
  obtain ⟨_, parts⟩ := FL.pcs_execution_has_actual_log_parts
    ns pending wire decoded opening oracle output executed
  refine ⟨input, List.mem_toFinset.mpr ?_, edge⟩
  change (input, output.hashFpp) ∈ ((E.pcsProgram ns pending wire decoded opening).record oracle).2
  rw [parts]
  simp only [List.mem_append]
  have present : (input, output.hashFpp) ∈ ((FL.fppProgram ns decoded output).record oracle).2 :=
    sourceRecorded
  exact Or.inr present

theorem literal_current_matrix_query_has_fpp_trace_target
    (records : RawRecords) (fpp : F.RawDigest) (nonce : Fin (2 ^ 32)) (counter : CG.Counter) :
    NativePrivateSpendQ58CurrentPrequeryEvents.sourceTrace 26 records
        (CG.frame .piopMatrix fpp nonce counter) =
      extract F.rawNext records 26 .fpp fpp := by
  unfold NativePrivateSpendQ58CurrentPrequeryEvents.sourceTrace
    NativePrivateSpendQ58CurrentPrequeryEvents.queryTarget
  rw [CG.frame_parser_receipt]
  rfl

theorem literal_current_opening_query_has_piop_trace_target
    (records : RawRecords) (piop : F.RawDigest) (nonce : Fin (2 ^ 32)) (counter : CG.Counter) :
    NativePrivateSpendQ58CurrentPrequeryEvents.sourceTrace 27 records
        (CG.frame .piopOpening piop nonce counter) =
      extract F.rawNext records 27 .piop piop := by
  unfold NativePrivateSpendQ58CurrentPrequeryEvents.sourceTrace
    NativePrivateSpendQ58CurrentPrequeryEvents.queryTarget
  rw [CG.frame_parser_receipt]
  rfl

theorem stages_have_recorded_current_source_edge
    (ns : NativePrivateSpendQ58CurrentCompactMerkle.Namespace)
    (relation : NativePrivateSpendQ58CurrentPublicOpening.Relation)
    (pending : Bool) (nonce : Fin (2 ^ 32)) (wire : E.Wire) (oracle : Oracle)
    (transcript : E.Transcript)
    (stages : E.ExecutionStages ns relation pending nonce wire oracle transcript) :
    ∃ input, (input, stages.pcs.hashFpp) ∈ FL.fullRecords ns relation pending nonce wire oracle ∧
      F.rawNext .fpp input = some [(.root, stages.pcs.root)] := by
  obtain ⟨input, recorded, edge⟩ := pcs_execution_has_recorded_current_source_edge
    ns stages.openingPending wire stages.decoded stages.opening oracle stages.pcs stages.pcsExecuted
  have included := FL.stages_pcs_log_subset_full ns relation pending nonce wire oracle transcript stages
  exact ⟨input, List.mem_toFinset.mpr (included (List.mem_toFinset.mp recorded)), edge⟩

/-- This recorded base exists even when the capped DECS scan exhausts.
The first literal raw request precedes all field-word rejection decisions. -/
theorem current_decs_base_is_in_field_log (oracle : Oracle) (root : F.RawDigest) :
    (CG.frame .decsMatrix root ⟨0, by decide⟩ CG.zero,
      oracle (CG.frame .decsMatrix root ⟨0, by decide⟩ CG.zero)) ∈
      ((E.fieldXof .decsMatrix 700 root).record oracle).2 := by
  let rest := (E.fieldKeys .decsMatrix 700 root).tail
  have keys : E.fieldKeys .decsMatrix 700 root =
      C.canonicalCurrentQueryBytes ⟨.decsMatrix, root, 0, 0⟩ :: rest := by rfl
  have literal := CG.frame_is_literal_current .decsMatrix root ⟨0, by decide⟩ CG.zero
  rw [literal]
  change (C.canonicalCurrentQueryBytes ⟨.decsMatrix, root, 0, 0⟩,
    oracle (C.canonicalCurrentQueryBytes ⟨.decsMatrix, root, 0, 0⟩)) ∈
    ((fieldLoop 700 [] (E.fieldKeys .decsMatrix 700 root)).record oracle).2
  rw [keys]
  change (C.canonicalCurrentQueryBytes ⟨.decsMatrix, root, 0, 0⟩,
    oracle (C.canonicalCurrentQueryBytes ⟨.decsMatrix, root, 0, 0⟩)) ∈
    (C.canonicalCurrentQueryBytes ⟨.decsMatrix, root, 0, 0⟩,
      oracle (C.canonicalCurrentQueryBytes ⟨.decsMatrix, root, 0, 0⟩)) :: _
  exact List.mem_cons_self

theorem stages_current_decs_base_is_in_full_log
    (ns : NativePrivateSpendQ58CurrentCompactMerkle.Namespace)
    (relation : NativePrivateSpendQ58CurrentPublicOpening.Relation)
    (pending : Bool) (nonce : Fin (2 ^ 32)) (wire : E.Wire) (oracle : Oracle)
    (transcript : E.Transcript)
    (stages : E.ExecutionStages ns relation pending nonce wire oracle transcript) :
    (CG.frame .decsMatrix stages.pcs.root ⟨0, by decide⟩ CG.zero,
      oracle (CG.frame .decsMatrix stages.pcs.root ⟨0, by decide⟩ CG.zero)) ∈
      ((E.verifierProgram ns relation pending nonce wire).record oracle).2 := by
  have included := FL.stages_pcs_log_subset_full ns relation pending nonce wire oracle transcript stages
  apply included
  obtain ⟨_, parts⟩ := FL.pcs_execution_has_actual_log_parts ns stages.openingPending wire
    stages.decoded stages.opening oracle stages.pcs stages.pcsExecuted
  rw [parts]
  simp only [List.mem_append]
  have present := current_decs_base_is_in_field_log oracle stages.pcs.root
  exact Or.inl (Or.inr present)

/-- BOTH final PIOP and FPP labels read the same literal current source
inputs. The source target is derived from reconstruction; it is not a label
chosen after observing a selected challenge vector. -/
theorem stages_current_traces_identify_literal_source_label
    (selected : Role) (keyBytes : Key → F.RawInput)
    (fixed : C.FixedTable (Counter := Counter) selected GF.currentRoleCaps keyBytes)
    (decode : F.RawInput → VectorOutput Counter → F.RawDigest)
    (ns : NativePrivateSpendQ58CurrentCompactMerkle.Namespace)
    (relation : NativePrivateSpendQ58CurrentPublicOpening.Relation)
    (pending : Bool) (nonce : Fin (2 ^ 32)) (wire : E.Wire) (oracle : Oracle)
    (transcript : E.Transcript)
    (stages : E.ExecutionStages ns relation pending nonce wire oracle transcript)
    (free : RecordsCollisionFree (FL.fullRecords ns relation pending nonce wire oracle))
    (finalRecorded : (E.finalInput transcript, wire.hPiop) ∈
      ((E.verifierProgram ns relation pending nonce wire).record oracle).2)
    (fixedGamma : GF.fixedGamma selected keyBytes fixed decode stages.pcs.root = some stages.pcs.gamma) :
    let records := FL.fullRecords ns relation pending nonce wire oracle
    let actual := S.labelFromInputs records stages.pcs.root stages.pcs.hashFpp stages.pcs.gamma
    T.fppLabel selected keyBytes fixed decode (extract F.rawNext records 26 .fpp stages.pcs.hashFpp) = actual ∧
      T.fppLabel selected keyBytes fixed decode
        (T.child (extract F.rawNext records 27 .piop wire.hPiop) 0) = actual ∧
      T.childDigest (extract F.rawNext records 27 .piop wire.hPiop) = stages.pcs.hashFpp := by
  let records := FL.fullRecords ns relation pending nonce wire oracle
  obtain ⟨input, recorded, edge⟩ := stages_have_recorded_current_source_edge
    ns relation pending nonce wire oracle transcript stages
  have source := recorded_current_fpp_label_is_literal_inputs selected keyBytes fixed decode
    records free input stages.pcs.hashFpp stages.pcs.root stages.pcs.gamma recorded edge fixedGamma
  have piop := SR.recorded_current_piop_trace_readback records free transcript wire.hPiop
    (List.mem_toFinset.mpr finalRecorded)
  have fpp : transcript.hashFpp = stages.pcs.hashFpp := by
    exact (congrArg (fun value : E.Transcript => value.hashFpp) stages.reconstructed).symm
  refine ⟨source, ?_, ?_⟩
  · rw [piop, fpp]
    exact source
  · rw [piop]
    exact (current_piop_edge_identifies_payload_digest (E.finalInput transcript) transcript.hashFpp
      (SR.current_final_frame_has_literal_fpp_edge transcript)).trans fpp

variable {Work : Type} [Fintype Work] [DecidableEq Work]

/-- A restored sparse-basis PCS execution identifies its literal FPP trace
with its calculated source. The gamma premise is DERIVED from the one actual
same-fiber recorded DECS vector by the frozen completion theorem. Geometry
is derived from PCS execution, leaving the actual named recovery arms. -/
theorem current_restored_pcs_trace_label_calculates_source_or_named_bad {Result : Type}
    (program : Program Result) (branch : Branches CG.decode program)
    (selected : Role) (piopSelected : selected = .piopMatrix ∨ selected = .piopOpening)
    (fixed : P.FixedTable (Counter := CG.Counter) (FG.live program selected))
    (state : P.CmsState (Key := CG.Key program) (Counter := CG.Counter) (Work := Work))
    (fiberBasis : Basis (CG.Key program) (VectorOutput CG.Counter) (VectorOutput CG.Counter) Work)
    (nonzero : P.conditioned (FG.live program selected) fixed
      (physicalRun (CG.encode program) CG.decode program branch state) fiberBasis ≠ 0)
    (activeBasis : Basis (A.ActiveKey (FG.live program selected))
      (VectorOutput CG.Counter) (VectorOutput CG.Counter)
      (A.Memory (Key := CG.Key program) (Counter := CG.Counter) (Work := Work)))
    (fallback : F.RawDigest)
    (ns : NativePrivateSpendQ58CurrentCompactMerkle.Namespace) (pending : Bool)
    (wire : E.Wire) (decoded : E.DecodedFields) (opening : E.Opening) (output : E.PcsOutput)
    (executed : (E.pcsProgram ns pending wire decoded opening).eval
      (basisOracle (CG.encode program) CG.decode
        (A.restoreBasis (FG.live program selected) fixed activeBasis) fallback) = some output)
    (clean : output.pending = false)
    (vector : VectorOutput CG.Counter)
    (recorded : (CG.frame .decsMatrix output.root ⟨0, by decide⟩ CG.zero, vector) ∈
      answerLog CG.decode program branch)
    (free : RecordsCollisionFree (pcsRecords ns pending wire decoded opening
      (basisOracle (CG.encode program) CG.decode
        (A.restoreBasis (FG.live program selected) fixed activeBasis) fallback))) :
    let oracle := basisOracle (CG.encode program) CG.decode
      (A.restoreBasis (FG.live program selected) fixed activeBasis) fallback
    let records := pcsRecords ns pending wire decoded opening oracle
    let traceLabel := T.fppLabel selected (CG.keyBytes program) fixed CG.decode
      (extract F.rawNext records 26 .fpp output.hashFpp)
    traceLabel = S.labelFromInputs records output.root output.hashFpp output.gamma ∧
      (O.PriorBad ns decoded oracle output records ∨ RG.MatrixBad records output ∨
        RG.SmallSupportBad records output ∨
        ∃ geometry : RG.RecoveryGeometry ns wire decoded opening output records,
          S.calculatedCandidate traceLabel = some geometry.source) := by
  let oracle := basisOracle (CG.encode program) CG.decode
    (A.restoreBasis (FG.live program selected) fixed activeBasis) fallback
  let records := pcsRecords ns pending wire decoded opening oracle
  have gamma := FG.current_same_fiber_fixed_gamma_is_completed_oracle_gamma program branch
    selected piopSelected fixed state fiberBasis nonzero output.root vector recorded activeBasis fallback
  have actualGamma := S.pcs_execution_gamma_is_label_gamma ns pending wire decoded opening oracle output executed
  have fixedGamma : GF.fixedGamma selected (CG.keyBytes program) fixed CG.decode output.root = some output.gamma :=
    gamma.trans (congrArg some actualGamma)
  obtain ⟨input, present, edge⟩ := pcs_execution_has_recorded_current_source_edge
    ns pending wire decoded opening oracle output executed
  have label := recorded_current_fpp_label_is_literal_inputs selected (CG.keyBytes program) fixed CG.decode
    records free input output.hashFpp output.root output.gamma present edge fixedGamma
  refine ⟨label, ?_⟩
  rcases RG.pcs_execution_has_geometry_or_named_bad_event ns pending wire decoded opening oracle output
      records executed clean with prior | matrix | small | ⟨geometry⟩
  · exact Or.inl prior
  · exact Or.inr (Or.inl matrix)
  · exact Or.inr (Or.inr (Or.inl small))
  · apply Or.inr; apply Or.inr; apply Or.inr
    rcases geometry with ⟨geometry⟩
    refine ⟨geometry, ?_⟩
    rw [label]
    exact geometry.calculated

/-- This endpoint uses ONE actual accepted physical branch. Its ordinary
execution and DECS base record are obtained from its nonzero standard view;
its fixed gamma is obtained from the conditioned fiber of THAT branch.
Neither a desired root, supplied stages/geometry, source-view equality nor
a callback selecting an unknown per-vector predicate is a premise. -/
theorem accepted_current_physical_branch_traces_calculate_source_or_named_bad
    (ns : NativePrivateSpendQ58CurrentCompactMerkle.Namespace)
    (relation : NativePrivateSpendQ58CurrentPublicOpening.Relation)
    (pending : Bool) (nonce : Fin (2 ^ 32)) (wire : E.Wire)
    (branch : Branches CG.decode (E.verifierProgram ns relation pending nonce wire))
    (selected : Role) (piopSelected : selected = .piopMatrix ∨ selected = .piopOpening)
    (fixed : P.FixedTable (Counter := CG.Counter)
      (FG.live (E.verifierProgram ns relation pending nonce wire) selected))
    (state : P.CmsState (Key := CG.Key (E.verifierProgram ns relation pending nonce wire))
      (Counter := CG.Counter) (Work := Work))
    (fiberBasis : Basis (CG.Key (E.verifierProgram ns relation pending nonce wire))
      (VectorOutput CG.Counter) (VectorOutput CG.Counter) Work)
    (nonzeroFiber : P.conditioned (FG.live (E.verifierProgram ns relation pending nonce wire) selected) fixed
      (physicalRun (CG.encode (E.verifierProgram ns relation pending nonce wire)) CG.decode
        (E.verifierProgram ns relation pending nonce wire) branch state) fiberBasis ≠ 0)
    (basis : Basis (CG.Key (E.verifierProgram ns relation pending nonce wire))
      (VectorOutput CG.Counter) (VectorOutput CG.Counter) Work)
    (nonzeroStandard : globalDecompress
      (physicalRun (CG.encode (E.verifierProgram ns relation pending nonce wire)) CG.decode
        (E.verifierProgram ns relation pending nonce wire) branch state) basis ≠ 0)
    (fallback : F.RawDigest)
    (accepted : branchResult CG.decode (E.verifierProgram ns relation pending nonce wire) branch = some ()) :
    let program := E.verifierProgram ns relation pending nonce wire
    let oracle := basisOracle (CG.encode program) CG.decode basis fallback
    let records := FL.fullRecords ns relation pending nonce wire oracle
    ¬ RecordsCollisionFree records ∨
      ∃ transcript, ∃ stages : E.ExecutionStages ns relation pending nonce wire oracle transcript,
        transcript.pending = false ∧
        let sourceLabel := S.labelFromInputs records stages.pcs.root stages.pcs.hashFpp stages.pcs.gamma
        T.fppLabel selected (CG.keyBytes program) fixed CG.decode
            (extract F.rawNext records 26 .fpp stages.pcs.hashFpp) = sourceLabel ∧
          T.fppLabel selected (CG.keyBytes program) fixed CG.decode
            (T.child (extract F.rawNext records 27 .piop wire.hPiop) 0) = sourceLabel ∧
          T.childDigest (extract F.rawNext records 27 .piop wire.hPiop) = stages.pcs.hashFpp ∧
          (RG.MatrixBad records stages.pcs ∨ RG.SmallSupportBad records stages.pcs ∨
            ∃ geometry : RG.RecoveryGeometry ns wire stages.decoded stages.opening stages.pcs records,
              S.calculatedCandidate sourceLabel = some geometry.source) := by
  let program := E.verifierProgram ns relation pending nonce wire
  let oracle := basisOracle (CG.encode program) CG.decode basis fallback
  let records := FL.fullRecords ns relation pending nonce wire oracle
  by_cases free : RecordsCollisionFree records
  · have replay := SmzaRp05PhysicalAcceptedReplayLite.accepted_branch_record_eq_physical_rawLog
      (CG.encode program) CG.decode program branch state basis fallback nonzeroStandard accepted
    have ordinary : program.eval oracle = some () :=
      (Program.record_result oracle program).symm.trans (congrArg Prod.fst replay)
    obtain ⟨transcript, ⟨stages⟩, clean, _finalDigest, finalRecorded⟩ :=
      E.accepted_execution_has_stages ns relation pending nonce wire oracle ordinary
    have base := stages_current_decs_base_is_in_full_log ns relation pending nonce wire oracle transcript stages
    have rawRecorded :
        (CG.frame .decsMatrix stages.pcs.root ⟨0, by decide⟩ CG.zero,
          oracle (CG.frame .decsMatrix stages.pcs.root ⟨0, by decide⟩ CG.zero)) ∈ rawLog CG.decode program branch := by
      have logEq := congrArg Prod.snd replay
      dsimp only [Prod.snd] at logEq
      rw [← logEq]
      exact base
    obtain ⟨call, recorded, same⟩ := List.mem_map.mp rawRecorded
    have inputEq : call.1 = CG.frame .decsMatrix stages.pcs.root ⟨0, by decide⟩ CG.zero :=
      congrArg Prod.fst same
    rcases call with ⟨input, vector⟩
    dsimp only at inputEq
    subst input
    have parsed := CG.recorded_current_base_parser program branch .decsMatrix stages.pcs.root
      ⟨0, by decide⟩ CG.zero vector recorded
    have fixedSame := GF.current_decs_base_vector_has_same_fiber_current_gamma selected piopSelected
      (CG.keyBytes program) (CG.key_bytes_injective program) fixed (CG.encode program) CG.decode
      program branch state fiberBasis nonzeroFiber
      (CG.frame .decsMatrix stages.pcs.root ⟨0, by decide⟩ CG.zero, vector) recorded stages.pcs.root parsed
    have standardGamma := NativePrivateSpendQ58CurrentGroupedGamma.current_gamma_from_same_branch_vector
      program branch state basis nonzeroStandard stages.pcs.root vector recorded fallback
    have actualGamma := S.pcs_execution_gamma_is_label_gamma ns stages.openingPending wire stages.decoded
      stages.opening oracle stages.pcs stages.pcsExecuted
    have vectorGamma : GF.gammaFromVector CG.decode stages.pcs.root vector = stages.pcs.gamma :=
      standardGamma.symm.trans actualGamma
    have fixedGamma : GF.fixedGamma selected (CG.keyBytes program) fixed CG.decode stages.pcs.root =
        some stages.pcs.gamma := fixedSame.trans (congrArg some vectorGamma)
    obtain ⟨matrixLabel, openingLabel, openingTarget⟩ := stages_current_traces_identify_literal_source_label
      selected (CG.keyBytes program) fixed CG.decode ns relation pending nonce wire oracle transcript stages
      free finalRecorded fixedGamma
    apply Or.inr
    refine ⟨transcript, stages, clean, matrixLabel, openingLabel, openingTarget, ?_⟩
    have pcsClean := NativePrivateSpendQ58CurrentAcceptedLeafSupport.stages_pcs_pending_false
      ns relation pending nonce wire oracle transcript stages clean
    rcases RG.pcs_execution_has_geometry_or_named_bad_event ns stages.openingPending wire stages.decoded
        stages.opening oracle stages.pcs records stages.pcsExecuted pcsClean with prior | matrix | small | ⟨geometry⟩
    · exact (FL.stages_prior_bad_is_impossible_on_collision_free_full_log ns relation pending nonce wire
        oracle transcript stages clean free prior).elim
    · exact Or.inl matrix
    · exact Or.inr (Or.inl small)
    · rcases geometry with ⟨geometry⟩
      exact Or.inr (Or.inr ⟨geometry, geometry.calculated⟩)
  · exact Or.inl free

/-- Completed records may additionally contain the producer's raw source
requests. Containment is used to derive actual current edges, not to assert
that adding these records preserves a source label. Both extractors and the
ANY-preimage selector below use exactly the SAME completed record. -/
theorem stages_in_completed_record_identify_literal_source_label
    (selected : Role) (keyBytes : Key → F.RawInput)
    (fixed : C.FixedTable (Counter := Counter) selected GF.currentRoleCaps keyBytes)
    (decode : F.RawInput → VectorOutput Counter → F.RawDigest)
    (ns : NativePrivateSpendQ58CurrentCompactMerkle.Namespace)
    (relation : NativePrivateSpendQ58CurrentPublicOpening.Relation)
    (pending : Bool) (nonce : Fin (2 ^ 32)) (wire : E.Wire) (oracle : Oracle)
    (transcript : E.Transcript)
    (stages : E.ExecutionStages ns relation pending nonce wire oracle transcript)
    (records : RawRecords) (free : RecordsCollisionFree records)
    (covered : sourceRecords (FL.fullRecords ns relation pending nonce wire oracle) ⊆ records)
    (finalRecorded : (E.finalInput transcript, wire.hPiop) ∈
      ((E.verifierProgram ns relation pending nonce wire).record oracle).2)
    (fixedGamma : GF.fixedGamma selected keyBytes fixed decode stages.pcs.root = some stages.pcs.gamma) :
    let actual := S.labelFromInputs records stages.pcs.root stages.pcs.hashFpp stages.pcs.gamma
    T.fppLabel selected keyBytes fixed decode (extract F.rawNext records 26 .fpp stages.pcs.hashFpp) = actual ∧
      T.fppLabel selected keyBytes fixed decode
        (T.child (extract F.rawNext records 27 .piop wire.hPiop) 0) = actual ∧
      T.childDigest (extract F.rawNext records 27 .piop wire.hPiop) = stages.pcs.hashFpp := by
  obtain ⟨input, inVerifier, edge⟩ := stages_have_recorded_current_source_edge
    ns relation pending nonce wire oracle transcript stages
  have inputUnparsed := current_source_valid_input_is_unparsed .fpp input (by simp [edge])
  have source := recorded_current_fpp_label_is_literal_inputs selected keyBytes fixed decode
    records free input stages.pcs.hashFpp stages.pcs.root stages.pcs.gamma
    (covered (Finset.mem_filter.mpr ⟨inVerifier, inputUnparsed⟩)) edge fixedGamma
  have finalUnparsed := current_source_valid_input_is_unparsed .piop (E.finalInput transcript)
    (by simp [SR.current_final_frame_has_literal_fpp_edge transcript])
  have piop := SR.recorded_current_piop_trace_readback records free transcript wire.hPiop
    (covered (Finset.mem_filter.mpr ⟨List.mem_toFinset.mpr finalRecorded, finalUnparsed⟩))
  have fpp : transcript.hashFpp = stages.pcs.hashFpp := by
    exact (congrArg (fun value : E.Transcript => value.hashFpp) stages.reconstructed).symm
  refine ⟨source, ?_, ?_⟩
  · rw [piop, fpp]
    exact source
  · rw [piop]
    exact (current_piop_edge_identifies_payload_digest (E.finalInput transcript) transcript.hashFpp
      (SR.current_final_frame_has_literal_fpp_edge transcript)).trans fpp

/-- Coverage of the SAME completed producer+verifier record discharges
the missing/collision/path arms. No earlier role-cut coverage is inferred. -/
theorem stages_prior_bad_is_impossible_on_collision_free_completed_record
    (ns : NativePrivateSpendQ58CurrentCompactMerkle.Namespace)
    (relation : NativePrivateSpendQ58CurrentPublicOpening.Relation)
    (pending : Bool) (nonce : Fin (2 ^ 32)) (wire : E.Wire) (oracle : Oracle)
    (transcript : E.Transcript)
    (stages : E.ExecutionStages ns relation pending nonce wire oracle transcript)
    (clean : transcript.pending = false)
    (records : RawRecords) (free : RecordsCollisionFree records)
    (covered : sourceRecords (FL.fullRecords ns relation pending nonce wire oracle) ⊆ records) :
    ¬ O.PriorBad ns stages.decoded oracle stages.pcs records := by
  intro bad
  obtain ⟨raw, present, _edge⟩ := stages_have_recorded_current_source_edge
    ns relation pending nonce wire oracle transcript stages
  have rawUnparsed := current_source_valid_input_is_unparsed .fpp raw (by simp [_edge])
  have sourcePresent := covered (Finset.mem_filter.mpr ⟨present, rawUnparsed⟩)
  obtain ⟨_, fppSubset⟩ := FL.stages_merkle_and_fpp_logs_subset_full
    ns relation pending nonce wire oracle transcript stages
  obtain ⟨_, _, _, _, _, _, _, _, _, _, _, _, _, fppExecuted, _⟩ :=
    NativePrivateSpendQ58CurrentAcceptedPcsFacts.pcs_execution_has_actual_facts
      ns stages.openingPending wire stages.decoded stages.opening oracle stages.pcs stages.pcsExecuted
  obtain ⟨fppInput, singleton, fppEdge⟩ := successful_current_source_hash_record_is_single
    oracle stages.pcs.root stages.pcs.hashFpp stages.decoded.decs
    (stages.pcs.rows.map fun row => row.map SmzaRp05ExecutableRestore.toWord)
    stages.pcs.gamma (stages.pcs.decsPoints.map SmzaRp05ExecutableRestore.toWord)
    (List.ofFn fun i : Fin 77 => V8SmzaOracleParser.wordAt ns.binding i.val) (by simp) fppExecuted
  have fppCovered : ((FL.fppProgram ns stages.decoded stages.pcs).record oracle).2.toFinset ⊆ records :=
    by
      intro call member
      have sourceSingleton : ((FL.fppProgram ns stages.decoded stages.pcs).record oracle).2 =
          [(fppInput, stages.pcs.hashFpp)] := singleton
      have same : call = (fppInput, stages.pcs.hashFpp) := by
        simpa [sourceSingleton] using member
      subst call
      exact covered (Finset.mem_filter.mpr ⟨fppSubset member,
        current_source_valid_input_is_unparsed .fpp fppInput (by simp [fppEdge])⟩)
  have unionFree : RecordsCollisionFree
      (records ∪ ((FL.fppProgram ns stages.decoded stages.pcs).record oracle).2.toFinset) := by
    rw [Finset.union_eq_left.mpr fppCovered]
    exact free
  rcases bad with missing | collision | collision | ⟨coordinates, _distinct, indicesEq, j, missing⟩
  · exact missing ⟨raw, sourcePresent⟩
  · exact collision (records_collision_instance_transport _ _ records
      ((FL.fppProgram ns stages.decoded stages.pcs).record oracle).2 unionFree)
  · exact collision free
  · obtain ⟨actualCoordinates, actualIndices, paths⟩ :=
      NativePrivateSpendQ58CurrentFullLogReadback.stages_root_paths_are_in_full_log
        ns relation pending nonce wire oracle transcript stages clean
    obtain ⟨_, sampledPending, _, _, _, _, _, _, inputEq, _⟩ :=
      NativePrivateSpendQ58CurrentAcceptedPcsFacts.pcs_execution_has_actual_facts
        ns stages.openingPending wire stages.decoded stages.opening oracle stages.pcs stages.pcsExecuted
    obtain ⟨_, _, _, _, _, _, _, _, _, _, _, _, inputIndices, _⟩ :=
      NativePrivateSpendQ58CurrentAcceptedLeafSupport.merkle_input_actual_fields
        wire.salt ns.binding sampledPending stages.pcs.indexes stages.pcs.rows
        stages.decoded.decs.maskingEvals wire.tapes wire.paths stages.pcs.input inputEq
    have same : coordinates j = actualCoordinates j := by
      apply Fin.ext
      exact (indicesEq j).trans ((inputIndices j).symm.trans (actualIndices j).symm)
    apply missing
    rw [same]
    exact current_recorded_path_source_subset _ _ covered
      _ _ _ _ (paths j)

/-- Pure current grouping readback from a stored base vector. Its database
can be an arbitrary sparse claim database; no nonzero standard view is used. -/
theorem stored_current_decs_base_determines_claim_gamma {Result : Type}
    (program : Program Result) (database : Database (CG.Key program) (VectorOutput CG.Counter))
    (fallback : F.RawDigest) (root : F.RawDigest) (vector : VectorOutput CG.Counter)
    (stored : database (CG.encode program (CG.frame .decsMatrix root ⟨0, by decide⟩ CG.zero)) = some vector) :
    S.gammaAt (CR.claimOracle program database fallback) root = GF.gammaFromVector CG.decode root vector := by
  let basis : Basis (CG.Key program) (VectorOutput CG.Counter) (VectorOutput CG.Counter) PUnit :=
    { input := CG.encode program []
      phase := 0
      workspace := PUnit.unit
      database := database }
  have oracleEq : CR.claimOracle program database fallback =
      basisOracle (CG.encode program) CG.decode basis fallback := by
    funext raw
    unfold CR.claimOracle basisOracle
    dsimp only [basis]
    cases database (CG.encode program raw) <;> rfl
  apply NativePrivateSpendQ58CurrentSourceCandidate.gamma_at_congr_on_current_decs_keys
  intro input member
  change input ∈ (List.range (SmzaRp05ExecutableChallengeStage.callCap 700)).map
    (fun counter => C.canonicalCurrentQueryBytes ⟨.decsMatrix, root, 0, counter⟩) at member
  rcases List.mem_map.mp member with ⟨counter, inRange, rfl⟩
  have bounded : counter < 840376 := by
    have small := List.mem_range.mp inRange
    rw [NativePrivateSpendQ58CurrentExecutableVerifier.literal_request_counts.2.1] at small
    omega
  let c : CG.Counter := ⟨counter, bounded⟩
  have literal : C.canonicalCurrentQueryBytes ⟨.decsMatrix, root, 0, counter⟩ =
      CG.frame .decsMatrix root ⟨0, by decide⟩ c :=
    (CG.frame_is_literal_current .decsMatrix root ⟨0, by decide⟩ c).symm
  rw [literal]
  have answered := CG.stored_current_vector_answers_every_counter program basis .decsMatrix root
    ⟨0, by decide⟩ vector stored c fallback
  have coord : CG.coordinate (CG.frame .decsMatrix root ⟨0, by decide⟩ c) = c :=
    congrArg Prod.snd (CG.current_frame_address _ _ _ _)
  rw [oracleEq]
  simpa only [CG.decode, coord,
    V8Smz9CoherentVectorMerkle.vectorOutputBytes] using answered

/-- Compatibility is literal equality of this branch's inactive recorded
vectors to its fixed table, not an oracle-agreement or candidate callback. -/
theorem compatible_recorded_decs_base_has_fixed_gamma {Result : Type}
    (program : Program Result) (branch : Branches CG.decode program)
    (selected : Role) (piopSelected : selected = .piopMatrix ∨ selected = .piopOpening)
    (fixed : P.FixedTable (Counter := CG.Counter) (AC.live program selected GF.currentRoleCaps))
    (compatible : AC.fixedCompatible program selected GF.currentRoleCaps fixed branch)
    (root : F.RawDigest) (vector : VectorOutput CG.Counter)
    (recorded : (CG.frame .decsMatrix root ⟨0, by decide⟩ CG.zero, vector) ∈
      answerLog CG.decode program branch) :
    GF.fixedGamma selected (CG.keyBytes program) fixed CG.decode root =
      some (GF.gammaFromVector CG.decode root vector) := by
  have parsed := CG.recorded_current_base_parser program branch .decsMatrix root
    ⟨0, by decide⟩ CG.zero vector recorded
  have different : Role.decsMatrix ≠ selected := by
    rcases piopSelected with matrix | opening
    · rw [matrix]; decide
    · rw [opening]; decide
  have inactive : ¬AC.live program selected GF.currentRoleCaps
      (CG.encode program (CG.frame .decsMatrix root ⟨0, by decide⟩ CG.zero)) :=
    C.other_bounded_role_is_fixed selected GF.currentRoleCaps (CG.keyBytes program) _
      ⟨.decsMatrix, root, 0, 0⟩ parsed different (by
        change 0 < GF.currentRoleCaps .decsMatrix
        decide)
  have same := compatible (CG.frame .decsMatrix root ⟨0, by decide⟩ CG.zero, vector) recorded inactive
  have cell := C.fixed_vector_at_nonce_eq_actual_cell selected GF.currentRoleCaps
    (CG.keyBytes program) (CG.key_bytes_injective program) fixed
    ⟨CG.encode program (CG.frame .decsMatrix root ⟨0, by decide⟩ CG.zero), inactive⟩
    ⟨.decsMatrix, root, 0, 0⟩ parsed rfl
  have sameCell : fixed
      ⟨CG.encode program (CG.frame .decsMatrix root ⟨0, by decide⟩ CG.zero), inactive⟩ =
      vector := by
    simpa only [Prod.fst, Prod.snd] using same
  have fixedVector : NativePrivateSpendQ58CurrentRoleClassifier.fixedVectorAtNonce selected GF.currentRoleCaps
      (CG.keyBytes program) fixed .decsMatrix root 0 = some vector := cell.trans (congrArg some sameCell)
  simpa only [GF.fixedGamma, Option.map_some] using
    congrArg (Option.map (GF.gammaFromVector CG.decode root)) fixedVector

/-- Actual source calls of the completed producer+verifier branch are in the
sparse ACTIVE database. Extra source records there are retained. Challenge
counter records are erased only by the proven current grammar exclusion. -/
theorem current_claimed_program_source_records_are_in_active_database {Result : Type}
    (program : Program Result) (branch : Branches CG.decode program)
    (selected : Role)
    (fixed : P.FixedTable (Counter := CG.Counter) (AC.live program selected GF.currentRoleCaps))
    (database : Database (A.ActiveKey (AC.live program selected GF.currentRoleCaps)) (VectorOutput CG.Counter))
    (compatible : AC.fixedCompatible program selected GF.currentRoleCaps fixed branch)
    (claims : ClaimsDatabaseEvent (AC.activeClaims program selected GF.currentRoleCaps branch) database)
    (fallback : F.RawDigest) :
    sourceRecords ((program.record
      (CR.claimOracle program (A.merge (AC.live program selected GF.currentRoleCaps) fixed database) fallback)).2.toFinset) ⊆
      sourceRecords (rawRecords
        (fun key : A.ActiveKey (AC.live program selected GF.currentRoleCaps) => CG.keyBytes program key.val)
        (V8Smz9CoherentVectorMerkle.vectorOutputBytes CG.zero) database) := by
  have replay := AC.current_active_claims_replay_same_program program selected GF.currentRoleCaps
    fixed branch database compatible claims fallback
  intro record member
  obtain ⟨inProgram, unparsed⟩ := Finset.mem_filter.mp member
  have inRawLog : record ∈ rawLog CG.decode program branch := by
    have logEq := congrArg Prod.snd replay
    dsimp only [Prod.snd] at logEq
    rw [← logEq]
    exact List.mem_toFinset.mp inProgram
  obtain ⟨call, recorded, same⟩ := List.mem_map.mp inRawLog
  have source : C.parseCurrentStageQuery call.1 = none := by
    rw [congrArg Prod.fst same]
    exact unparsed
  have retained := AC.current_claimed_source_record_is_in_active_database program selected GF.currentRoleCaps
    branch database claims call recorded source
  exact Finset.mem_filter.mpr ⟨by simpa only [same] using retained, unparsed⟩

/-- The endpoint needed by the actual active-claims projector. ONE branch's
fixed compatibility plus its literal active claims derives full replay; no
physical nonzero premise is supplied here. The source candidate and geometry
use the SAME source-only sparse ACTIVE records, including all extra source
records. RR.priorInput is never applied to an unfiltered full raw log.
The actual matrix/opening traces are read from that active database, with
challenge-frame erasure proved by CurrentComplementReadback. Actual stages,
DECS base membership, final raw PIOP frame and geometry are derived.
Probability of claims/conformance, collisions and first-valid nonce handling
remains with the parent integration; this theorem asserts no G3 result. -/
theorem accepted_current_claimed_fiber_traces_calculate_source_or_named_bad
    (producer : Program E.Wire) (ns : NativePrivateSpendQ58CurrentCompactMerkle.Namespace)
    (relation : NativePrivateSpendQ58CurrentPublicOpening.Relation)
    (pending : Bool) (nonce : Fin (2 ^ 32))
    (branch : Branches CG.decode (producer.bind (E.verifierProgram ns relation pending nonce)))
    (selected : Role) (piopSelected : selected = .piopMatrix ∨ selected = .piopOpening)
    (fixed : P.FixedTable (Counter := CG.Counter)
      (AC.live (producer.bind (E.verifierProgram ns relation pending nonce)) selected GF.currentRoleCaps))
    (compatible : AC.fixedCompatible (producer.bind (E.verifierProgram ns relation pending nonce))
      selected GF.currentRoleCaps fixed branch)
    (database : Database (A.ActiveKey
      (AC.live (producer.bind (E.verifierProgram ns relation pending nonce)) selected GF.currentRoleCaps))
      (VectorOutput CG.Counter))
    (claims : ClaimsDatabaseEvent
      (AC.activeClaims (producer.bind (E.verifierProgram ns relation pending nonce)) selected GF.currentRoleCaps branch) database)
    (fallback : F.RawDigest)
    (accepted : branchResult CG.decode (producer.bind (E.verifierProgram ns relation pending nonce)) branch = some ()) :
    let program := producer.bind (E.verifierProgram ns relation pending nonce)
    let oracle := CR.claimOracle program (A.merge (AC.live program selected GF.currentRoleCaps) fixed database) fallback
    let raw := rawRecords
      (fun key : A.ActiveKey (AC.live program selected GF.currentRoleCaps) => CG.keyBytes program key.val)
      (V8Smz9CoherentVectorMerkle.vectorOutputBytes CG.zero) database
    let records := sourceRecords raw
    ∃ wire, producer.eval oracle = some wire ∧
      (¬ RecordsCollisionFree records ∨
        ∃ transcript, ∃ stages : E.ExecutionStages ns relation pending nonce wire oracle transcript,
          transcript.pending = false ∧
          let sourceLabel := S.labelFromInputs records stages.pcs.root stages.pcs.hashFpp stages.pcs.gamma
          T.fppLabel selected (CG.keyBytes program) fixed CG.decode
              (extract F.rawNext raw 26 .fpp stages.pcs.hashFpp) = sourceLabel ∧
            T.fppLabel selected (CG.keyBytes program) fixed CG.decode
              (T.child (extract F.rawNext raw 27 .piop wire.hPiop) 0) = sourceLabel ∧
            T.childDigest (extract F.rawNext raw 27 .piop wire.hPiop) = stages.pcs.hashFpp ∧
            T.traceInput (extract F.rawNext raw 27 .piop wire.hPiop) = E.finalInput transcript ∧
            (RG.MatrixBad records stages.pcs ∨ RG.SmallSupportBad records stages.pcs ∨
              ∃ geometry : RG.RecoveryGeometry ns wire stages.decoded stages.opening stages.pcs records,
                S.calculatedCandidate sourceLabel = some geometry.source)) := by
  let program := producer.bind (E.verifierProgram ns relation pending nonce)
  let merged := A.merge (AC.live program selected GF.currentRoleCaps) fixed database
  let oracle := CR.claimOracle program merged fallback
  let raw := rawRecords
    (fun key : A.ActiveKey (AC.live program selected GF.currentRoleCaps) => CG.keyBytes program key.val)
    (V8Smz9CoherentVectorMerkle.vectorOutputBytes CG.zero) database
  let records := sourceRecords raw
  have replay := AC.current_active_claims_replay_same_program program selected GF.currentRoleCaps
    fixed branch database compatible claims fallback
  have allClaims := AC.current_active_claims_complete_full_branch program selected GF.currentRoleCaps
    fixed branch database compatible claims
  have ordinary : program.eval oracle = some () :=
    (Program.record_result oracle program).symm.trans ((congrArg Prod.fst replay).trans accepted)
  obtain ⟨wire, produced, verifierAccepted⟩ := SmzaRp05FinalProgramMiddleExecution.program_bind_success
    oracle producer (E.verifierProgram ns relation pending nonce) () ordinary
  refine ⟨wire, produced, ?_⟩
  by_cases free : RecordsCollisionFree records
  · have parts := Program.record_bind_success oracle producer
      (E.verifierProgram ns relation pending nonce) wire produced
    have allSources := current_claimed_program_source_records_are_in_active_database
      program branch selected fixed database compatible claims fallback
    have covered : sourceRecords (FL.fullRecords ns relation pending nonce wire oracle) ⊆ records := by
      intro call member
      obtain ⟨present, unparsed⟩ := Finset.mem_filter.mp member
      apply allSources
      apply Finset.mem_filter.mpr
      refine ⟨List.mem_toFinset.mpr ?_, unparsed⟩
      rw [congrArg Prod.snd parts]
      exact List.mem_append.mpr (Or.inr (List.mem_toFinset.mp present))
    obtain ⟨transcript, ⟨stages⟩, clean, _finalDigest, finalRecorded⟩ :=
      E.accepted_execution_has_stages ns relation pending nonce wire oracle verifierAccepted
    have base := stages_current_decs_base_is_in_full_log ns relation pending nonce wire oracle transcript stages
    have rawRecorded :
        (CG.frame .decsMatrix stages.pcs.root ⟨0, by decide⟩ CG.zero,
          oracle (CG.frame .decsMatrix stages.pcs.root ⟨0, by decide⟩ CG.zero)) ∈ rawLog CG.decode program branch := by
      have logEq := congrArg Prod.snd replay
      have partsEq := congrArg Prod.snd parts
      dsimp only [Prod.snd] at logEq partsEq
      rw [← logEq, partsEq]
      exact List.mem_append.mpr (Or.inr base)
    obtain ⟨call, recorded, same⟩ := List.mem_map.mp rawRecorded
    have inputEq : call.1 = CG.frame .decsMatrix stages.pcs.root ⟨0, by decide⟩ CG.zero :=
      congrArg Prod.fst same
    rcases call with ⟨input, vector⟩
    dsimp only at inputEq
    subst input
    have fixedSame := compatible_recorded_decs_base_has_fixed_gamma program branch selected piopSelected
      fixed compatible stages.pcs.root vector recorded
    have stored := CR.current_claims_store_every_branch_vector program branch merged allClaims
      (CG.frame .decsMatrix stages.pcs.root ⟨0, by decide⟩ CG.zero, vector) recorded
    have claimedGamma := stored_current_decs_base_determines_claim_gamma program merged fallback
      stages.pcs.root vector stored
    have actualGamma := S.pcs_execution_gamma_is_label_gamma ns stages.openingPending wire stages.decoded
      stages.opening oracle stages.pcs stages.pcsExecuted
    have vectorGamma : GF.gammaFromVector CG.decode stages.pcs.root vector = stages.pcs.gamma :=
      claimedGamma.symm.trans actualGamma
    have fixedGamma : GF.fixedGamma selected (CG.keyBytes program) fixed CG.decode stages.pcs.root =
        some stages.pcs.gamma := fixedSame.trans (congrArg some vectorGamma)
    obtain ⟨matrixLabel, openingLabel, openingTarget⟩ := stages_in_completed_record_identify_literal_source_label
      selected (CG.keyBytes program) fixed CG.decode ns relation pending nonce wire oracle transcript stages
      records free covered finalRecorded fixedGamma
    have eraseFpp : extract F.rawNext records 26 .fpp stages.pcs.hashFpp =
        extract F.rawNext raw 26 .fpp stages.pcs.hashFpp := by
      simpa only [records, sourceRecords] using
        NativePrivateSpendQ58CurrentComplementReadback.current_extract_erases_challenge_records
          raw 26 .fpp stages.pcs.hashFpp
    have erasePiop : extract F.rawNext records 27 .piop wire.hPiop =
        extract F.rawNext raw 27 .piop wire.hPiop := by
      simpa only [records, sourceRecords] using
        NativePrivateSpendQ58CurrentComplementReadback.current_extract_erases_challenge_records
          raw 27 .piop wire.hPiop
    have finalUnparsed := current_source_valid_input_is_unparsed .piop (E.finalInput transcript)
      (by simp [SR.current_final_frame_has_literal_fpp_edge transcript])
    have finalPresent := covered (Finset.mem_filter.mpr ⟨List.mem_toFinset.mpr finalRecorded, finalUnparsed⟩)
    have finalTrace := SR.recorded_current_piop_trace_readback records free transcript wire.hPiop finalPresent
    have actualFrame : T.traceInput (extract F.rawNext raw 27 .piop wire.hPiop) = E.finalInput transcript := by
      rw [← erasePiop, finalTrace]
      rfl
    apply Or.inr
    refine ⟨transcript, stages, clean, ?_, ?_, ?_, actualFrame, ?_⟩
    · rw [← eraseFpp]; exact matrixLabel
    · rw [← erasePiop]; exact openingLabel
    · rw [← erasePiop]; exact openingTarget
    · have pcsClean := NativePrivateSpendQ58CurrentAcceptedLeafSupport.stages_pcs_pending_false
        ns relation pending nonce wire oracle transcript stages clean
      rcases RG.pcs_execution_has_geometry_or_named_bad_event ns stages.openingPending wire stages.decoded
          stages.opening oracle stages.pcs records stages.pcsExecuted pcsClean with prior | matrix | small | ⟨geometry⟩
      · exact (stages_prior_bad_is_impossible_on_collision_free_completed_record ns relation pending nonce wire
          oracle transcript stages clean records free covered prior).elim
      · exact Or.inl matrix
      · exact Or.inr (Or.inl small)
      · rcases geometry with ⟨geometry⟩
        exact Or.inr (Or.inr ⟨geometry, geometry.calculated⟩)
  · exact Or.inl free

end
end HegemonCrypto.SmallWood.NativePrivateSpendQ58CurrentActualTraceLabel
