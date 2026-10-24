import HegemonCrypto.NativePrivateSpendQ58CurrentRecoveryGeometry
import HegemonCrypto.NativePrivateSpendQ58CurrentPiopRecordJoin
import HegemonCrypto.NativePrivateSpendQ58CurrentScalarChecks
import HegemonCrypto.NativePrivateSpendQ58CurrentScalarEventBridge
private def g3_aej01_progress (phase : String) : IO Unit := do -- G3_ACCEPTED_EVENT_JOIN_BUILD_PROGRESS01
  match ← IO.getEnv "HEGEMON_G3_SCALAR_PROGRESS_PATH" with -- G3_ACCEPTED_EVENT_JOIN_BUILD_PROGRESS01
  | some path => IO.FS.withFile (System.FilePath.mk path) IO.FS.Mode.append (fun handle => do handle.putStrLn phase; handle.flush) -- G3_ACCEPTED_EVENT_JOIN_BUILD_PROGRESS01
  | none => pure () -- G3_ACCEPTED_EVENT_JOIN_BUILD_PROGRESS01
elab "g3_aej01_entry " phase:str : command => -- G3_ACCEPTED_EVENT_JOIN_BUILD_PROGRESS01
  Lean.Elab.Command.liftIO (g3_aej01_progress phase.getString) -- G3_ACCEPTED_EVENT_JOIN_BUILD_PROGRESS01
elab "g3_aej01_checked " id:ident : command => do -- G3_ACCEPTED_EVENT_JOIN_BUILD_PROGRESS01
  let names ← Lean.Elab.Command.liftCoreM (Lean.Elab.realizeGlobalConstWithInfos id) -- G3_ACCEPTED_EVENT_JOIN_BUILD_PROGRESS01
  let env ← Lean.getEnv -- G3_ACCEPTED_EVENT_JOIN_BUILD_PROGRESS01
  for name in names do -- G3_ACCEPTED_EVENT_JOIN_BUILD_PROGRESS01
    match env.toKernelEnv.find? name with -- G3_ACCEPTED_EVENT_JOIN_BUILD_PROGRESS01
    | some (.thmInfo _) => Lean.Elab.Command.liftIO (g3_aej01_progress ("PHASE AEJ01_CHECKED " ++ id.getId.toString)) -- G3_ACCEPTED_EVENT_JOIN_BUILD_PROGRESS01
    | some (.defnInfo _) => Lean.Elab.Command.liftIO (g3_aej01_progress ("PHASE AEJ01_CHECKED " ++ id.getId.toString)) -- G3_ACCEPTED_EVENT_JOIN_BUILD_PROGRESS01
    | _ => Lean.throwError "AEJ01 checked kernel environment does not contain a definition or theorem" -- G3_ACCEPTED_EVENT_JOIN_BUILD_PROGRESS01

elab "g3_aej03_step " label:str " => " tac:tactic : tactic => do -- G3_ACCEPTED_EVENT_JOIN_BUILD_PROGRESS03
  (liftM (g3_aej01_progress ("PHASE AEJ03_" ++ label.getString ++ "_ENTRY")) : Lean.Elab.Tactic.TacticM Unit) -- G3_ACCEPTED_EVENT_JOIN_BUILD_PROGRESS03
  Lean.Elab.Tactic.evalTactic tac -- G3_ACCEPTED_EVENT_JOIN_BUILD_PROGRESS03
  (liftM (g3_aej01_progress ("PHASE AEJ03_" ++ label.getString ++ "_END")) : Lean.Elab.Tactic.TacticM Unit) -- G3_ACCEPTED_EVENT_JOIN_BUILD_PROGRESS03

/-! Ordinary current wire acceptance to a current satisfying assignment or
literal same-execution bad events. All stages, recovery geometry, twelve
identities and scalar checks below are derived outputs of ordinary eval.
No desired Satisfies, WholeResponseRecovered, TwelveChecks, prequery source
certificate or replay-success callback is a premise. Missing prior inputs
remain bad arms; this deterministic join does not give those arms zero mass.
SOURCE ONLY: neither a kernel result nor the physical conditional bound. -/
namespace HegemonCrypto.SmallWood.NativePrivateSpendQ58CurrentAcceptedEventJoin

open Polynomial
open SmzaRp05ExecutableMerkleVerifier (Program Oracle)
open SmzaRp05FilteredDecoderInstability (RawRecords)
open SmzaRecordedTracePath (RecordsCollisionFree)
open V8Smz9PiopSoundness
open scoped Classical
noncomputable section
set_option autoImplicit false
set_option Elab.async false
set_option maxHeartbeats 0
set_option maxRecDepth 0

namespace E
export NativePrivateSpendQ58CurrentExecutableVerifier
  (Wire Opening Transcript ExecutionStages verifierProgram points)
end E
namespace M
export NativePrivateSpendQ58CurrentCompactMerkle (Namespace)
end M
namespace C
export NativePrivateSpendQ58CurrentPublicOpening (Relation)
end C
namespace D
export NativePrivateSpendQ58CurrentDecodedRelation
  (Decoded decodedValues candidate)
end D
namespace O
export NativePrivateSpendQ58CurrentOrdinaryRecovery
  (PriorBad producerPrior producer_record_is_actual_prefix)
end O
namespace G
export NativePrivateSpendQ58CurrentRecoveryGeometry
  (RecoveryGeometry MatrixBad SmallSupportBad pcs_execution_has_geometry_or_named_bad_event
   geometry_has_identities_or_literal_lvcs_event)
end G
namespace V
export NativePrivateSpendQ58CurrentLvcsEventJoin
  (CurrentLvcsRootEvent actualCombinationPolynomial combinationPolynomial)
end V
namespace P
export NativePrivateSpendQ58CurrentPiopRecordJoin
  (priorResponse accepted_current_final_binds_prior_response_or_bad)
end P
namespace Q
export NativePrivateSpendQ58CurrentPiopEvents
  (currentMatrixEvent current_decoded_openings_have_witness_or_named_piop_events)
end Q

g3_aej01_entry "PHASE AEJ01_ENTRY PiopBad" -- G3_ACCEPTED_EVENT_JOIN_BUILD_PROGRESS01
/-- The PIOP event keeps the actual current1344594-column matrix and six
current admissible points. It never casts a legacy Opening or source. -/
def PiopBad (relation : C.Relation) (source : D.Decoded)
    (matrix : Matrix 1344594) (response : ClaimedTranscript) (opening : E.Opening) : Prop :=
  (¬ PiopExtraction.FullySatisfied (D.candidate relation source).system ∧
    matrix ∈ Q.currentMatrixEvent (D.candidate relation source)) ∨
  (¬ PiopExtraction.AffineBatchAccepts (D.candidate relation source).system
      (maskSum (D.candidate relation source)) matrix ∧
    NativePrivateSpendQ58CurrentPiopEvents.CurrentOpeningChecks
      (D.candidate relation source) matrix response opening)
g3_aej01_checked PiopBad -- G3_ACCEPTED_EVENT_JOIN_BUILD_PROGRESS01

g3_aej01_entry "PHASE AEJ01_ENTRY StageBad" -- G3_ACCEPTED_EVENT_JOIN_BUILD_PROGRESS01
/-- Every geometry here is derived from that very successful current PCS
call. It is an existential bad-event output, never a supplied certificate. -/
def StageBad (ns : M.Namespace) (relation : C.Relation) (pending : Bool)
    (nonce : Fin (2 ^ 32)) (wire : E.Wire) (oracle : Oracle) (prior : RawRecords)
    (transcript : E.Transcript)
    (stages : E.ExecutionStages ns relation pending nonce wire oracle transcript) : Prop :=
  O.PriorBad ns stages.decoded oracle stages.pcs prior ∨
  G.MatrixBad prior stages.pcs ∨
  G.SmallSupportBad prior stages.pcs ∨
  ∃ geometry : G.RecoveryGeometry ns wire stages.decoded stages.opening stages.pcs prior,
    V.CurrentLvcsRootEvent geometry.source stages.opening stages.decoded.pcs
      geometry.heads geometry.coordinates ∨
    PiopBad relation geometry.source stages.matrix (P.priorResponse prior wire.hPiop) stages.opening
g3_aej01_checked StageBad -- G3_ACCEPTED_EVENT_JOIN_BUILD_PROGRESS01

g3_aej01_entry "PHASE AEJ01_ENTRY LiteralBad" -- G3_ACCEPTED_EVENT_JOIN_BUILD_PROGRESS01
/-- Literal absent PIOP preimage, raw collision, current recovery, LVCS and
PIOP failure alternatives of the actual accepted ordinary execution. -/
def LiteralBad (ns : M.Namespace) (relation : C.Relation) (pending : Bool)
    (nonce : Fin (2 ^ 32)) (wire : E.Wire) (oracle : Oracle) (prior : RawRecords) : Prop :=
  (¬ ∃ raw, (raw, wire.hPiop) ∈ prior) ∨
  (¬ RecordsCollisionFree
    (prior ∪ ((E.verifierProgram ns relation pending nonce wire).record oracle).2.toFinset)) ∨
  ∃ transcript, ∃ stages : E.ExecutionStages ns relation pending nonce wire oracle transcript,
    transcript.pending = false ∧ StageBad ns relation pending nonce wire oracle prior transcript stages
g3_aej01_checked LiteralBad -- G3_ACCEPTED_EVENT_JOIN_BUILD_PROGRESS01

g3_aej01_entry "PHASE AEJ01_ENTRY current_matrix_event_of_affine" -- G3_ACCEPTED_EVENT_JOIN_BUILD_PROGRESS01
private theorem current_matrix_event_of_affine {width : Nat}
    (candidate : Candidate width) (matrix : Matrix width)
    (affine : PiopExtraction.AffineBatchAccepts candidate.system (maskSum candidate) matrix) :
    matrix ∈ Q.currentMatrixEvent candidate :=
  Finset.mem_filter.mpr ⟨Finset.mem_univ matrix, affine⟩
g3_aej01_checked current_matrix_event_of_affine -- G3_ACCEPTED_EVENT_JOIN_BUILD_PROGRESS01

g3_aej01_entry "PHASE AEJ04_ENTRY records_collision_instance_transport" -- G3_ACCEPTED_EVENT_JOIN_BUILD_PROGRESS04
private theorem records_collision_instance_transport {Input Digest : Type*}
    (left right : DecidableEq (Input × Digest))
    (prior : Finset (Input × Digest)) (records : List (Input × Digest))
    (bad : ¬ RecordsCollisionFree
      (@Union.union (Finset (Input × Digest)) (@Finset.instUnion (Input × Digest) left) prior (@List.toFinset (Input × Digest) left records))) :
    ¬ RecordsCollisionFree
      (@Union.union (Finset (Input × Digest)) (@Finset.instUnion (Input × Digest) right) prior (@List.toFinset (Input × Digest) right records)) := by
  have same : left = right := Subsingleton.elim _ _
  cases same
  exact bad
g3_aej01_checked records_collision_instance_transport -- G3_ACCEPTED_EVENT_JOIN_BUILD_PROGRESS04

g3_aej01_entry "PHASE AEJ01_ENTRY ordinary_current_acceptance_has_witness_or_literal_bad" -- G3_ACCEPTED_EVENT_JOIN_BUILD_PROGRESS01
/-- Actual verifierProgram acceptance DERIVES the current witness or one of
the exact named bad events. No stage, decoder success, source validity,
scalar readout or desired relation acceptance appears among the premises. -/
theorem ordinary_current_acceptance_has_witness_or_literal_bad
    (ns : M.Namespace) (relation : C.Relation) (pending : Bool)
    (nonce : Fin (2 ^ 32)) (wire : E.Wire) (oracle : Oracle) (prior : RawRecords)
    (accepted : (E.verifierProgram ns relation pending nonce wire).eval oracle = some ()) :
    (∃ source : D.Decoded,
      NativePrivateSpendQ58CurrentPublicOpening.Satisfies relation (D.decodedValues source)) ∨
    LiteralBad ns relation pending nonce wire oracle prior := by
  with_reducible
    unfold LiteralBad
    g3_aej03_step "RESPONSE_RCASES" =>
      rcases P.accepted_current_final_binds_prior_response_or_bad
          ns relation pending nonce wire oracle prior accepted with
        missing | collision | ⟨transcript, stages, clean, _recorded, responseEq⟩
    · exact Or.inr (Or.inl missing)
    · exact Or.inr (Or.inr (Or.inl
        (records_collision_instance_transport
          (by
            letI : DecidableEq SmzaRp05FilteredDecoderInstability.RawInput :=
              NativePrivateSpendQ58CurrentPiopRecordJoin.instDecidableEqRawInput
            exact inferInstance)
          (inferInstance : DecidableEq
            (SmzaRp05FilteredDecoderInstability.RawInput ×
              SmzaRp05FilteredDecoderInstability.RawDigest))
          prior ((E.verifierProgram ns relation pending nonce wire).record oracle).2
          collision)))
    · have pcsClean := NativePrivateSpendQ58CurrentAcceptedLeafSupport.stages_pcs_pending_false
        ns relation pending nonce wire oracle transcript stages clean
      have badStage : StageBad ns relation pending nonce wire oracle prior transcript stages →
          LiteralBad ns relation pending nonce wire oracle prior := by
        unfold LiteralBad
        intro bad
        exact Or.inr (Or.inr ⟨transcript, stages, clean, bad⟩)
      unfold StageBad LiteralBad at badStage
      rcases G.pcs_execution_has_geometry_or_named_bad_event ns stages.openingPending
          wire stages.decoded stages.opening oracle stages.pcs prior stages.pcsExecuted pcsClean with
        priorBad | matrixBad | supportBad | ⟨geometry⟩
      · exact Or.inr (badStage (Or.inl priorBad))
      · exact Or.inr (badStage (Or.inr (Or.inl matrixBad)))
      · exact Or.inr (badStage (Or.inr (Or.inr (Or.inl supportBad))))
      · rcases geometry with ⟨geometry⟩
        rcases G.geometry_has_identities_or_literal_lvcs_event ns wire stages.decoded
            stages.opening stages.pcs prior geometry with identities | lvcsBad
        · have actualHeads :=
            NativePrivateSpendQ58CurrentAcceptedPcsFacts.pcs_execution_heads_are_lvcs_heads
              ns stages.openingPending wire stages.decoded stages.opening oracle
              stages.pcs stages.pcsExecuted
          have headsEq : geometry.heads = stages.pcs.heads :=
            Option.some.inj (geometry.headsBuilt.symm.trans actualHeads)
          have actualIdentities : ∀ combination,
              V.actualCombinationPolynomial stages.decoded.pcs stages.pcs.heads combination =
                V.combinationPolynomial geometry.source stages.opening combination := by
            intro combination
            rw [← headsEq]
            exact identities combination
          g3_aej03_step "SCALAR_AGREEMENT" =>
            obtain ⟨witnessReadout, nonlinearReadout, linearReadout⟩ :=
              NativePrivateSpendQ58CurrentScalarEventBridge.current_same_execution_scalar_agreement
                ns stages.openingPending wire stages.decoded stages.opening oracle stages.pcs
                geometry.source stages.decodedEq stages.pcsExecuted actualIdentities
          g3_aej03_step "SCALAR_CHECKS" =>
            have checks := NativePrivateSpendQ58CurrentScalarChecks.current_opened_scalars_derive_piop_checks
              relation geometry.source stages.matrix stages.opening stages.decoded.piop
              witnessReadout nonlinearReadout linearReadout
          have currentChecks : NativePrivateSpendQ58CurrentPiopEvents.CurrentOpeningChecks
              (D.candidate relation geometry.source) stages.matrix
              (P.priorResponse prior wire.hPiop) stages.opening := by
            with_reducible
              exact Eq.mpr
                (congrArg (fun response : ClaimedTranscript =>
                  NativePrivateSpendQ58CurrentPiopEvents.CurrentOpeningChecks
                    (D.candidate relation geometry.source) stages.matrix response stages.opening)
                  responseEq)
                checks
          by_cases satisfied : PiopExtraction.FullySatisfied
              (D.candidate relation geometry.source).system
          · exact Or.inl ⟨geometry.source,
              NativePrivateSpendQ58CurrentDecodedRelation.fully_satisfied_implies_current_relation
                relation geometry.source satisfied⟩
          · by_cases affine : PiopExtraction.AffineBatchAccepts
                (D.candidate relation geometry.source).system
                (maskSum (D.candidate relation geometry.source)) stages.matrix
            · have matrixBad : PiopBad relation geometry.source stages.matrix
                  (P.priorResponse prior wire.hPiop) stages.opening := by
                with_reducible
                  unfold PiopBad
                  exact Or.inl ⟨satisfied, current_matrix_event_of_affine (D.candidate relation geometry.source) stages.matrix affine⟩
              exact Or.inr (badStage
                (Or.inr (Or.inr (Or.inr ⟨geometry, Or.inr matrixBad⟩))))
            · have openingBad : PiopBad relation geometry.source stages.matrix
                  (P.priorResponse prior wire.hPiop) stages.opening := by
                with_reducible
                  unfold PiopBad
                  exact Or.inr ⟨affine, currentChecks⟩
              exact Or.inr (badStage
                (Or.inr (Or.inr (Or.inr ⟨geometry, Or.inr openingBad⟩))))
        · exact Or.inr (badStage
            (Or.inr (Or.inr (Or.inr ⟨geometry, Or.inl lvcsBad⟩))))
g3_aej01_checked ordinary_current_acceptance_has_witness_or_literal_bad -- G3_ACCEPTED_EVENT_JOIN_BUILD_PROGRESS01

g3_aej01_entry "PHASE AEJ01_ENTRY producer_current_acceptance_has_actual_prefix_and_witness_or_literal_bad" -- G3_ACCEPTED_EVENT_JOIN_BUILD_PROGRESS01
/-- The prior table is obtained from the actual producer's record. Failed
producer queries remain in it; the final record belongs to the same run. -/
theorem producer_current_acceptance_has_actual_prefix_and_witness_or_literal_bad
    (producer : Program E.Wire) (ns : M.Namespace) (relation : C.Relation)
    (pending : Bool) (nonce : Fin (2 ^ 32)) (oracle : Oracle)
    (accepted : (producer.bind (E.verifierProgram ns relation pending nonce)).eval oracle = some ()) :
    ∃ wire, producer.eval oracle = some wire ∧
      ((producer.bind (E.verifierProgram ns relation pending nonce)).record oracle).2 =
        (producer.record oracle).2 ++
          ((E.verifierProgram ns relation pending nonce wire).record oracle).2 ∧
      ((∃ source : D.Decoded,
        NativePrivateSpendQ58CurrentPublicOpening.Satisfies relation (D.decodedValues source)) ∨
       LiteralBad ns relation pending nonce wire oracle (O.producerPrior producer oracle)) := by
  obtain ⟨wire, produced, verifierAccepted⟩ :=
    SmzaRp05FinalProgramMiddleExecution.program_bind_success oracle producer
      (E.verifierProgram ns relation pending nonce) () accepted
  exact ⟨wire, produced, O.producer_record_is_actual_prefix producer oracle wire produced _,
    ordinary_current_acceptance_has_witness_or_literal_bad ns relation pending nonce wire
      oracle (O.producerPrior producer oracle) verifierAccepted⟩
g3_aej01_checked producer_current_acceptance_has_actual_prefix_and_witness_or_literal_bad -- G3_ACCEPTED_EVENT_JOIN_BUILD_PROGRESS01

end
end HegemonCrypto.SmallWood.NativePrivateSpendQ58CurrentAcceptedEventJoin
