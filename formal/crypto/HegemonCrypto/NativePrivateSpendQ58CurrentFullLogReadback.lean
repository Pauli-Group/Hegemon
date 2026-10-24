import HegemonCrypto.NativePrivateSpendQ58CurrentSourceCandidate
import HegemonCrypto.NativePrivateSpendQ58CurrentAcceptedEventJoin

/-! The current PCS raw stages are contained in the SAME ordinary verifier
record. This is final-log coverage, not an earlier-cut coverage assumption.
It closes absent final-stage inputs and preserves collisions. Earlier role
queries are handled by the dynamic trace label, including late insertions.
SOURCE ONLY: no kernel or probability result is asserted. -/
namespace HegemonCrypto.SmallWood.NativePrivateSpendQ58CurrentFullLogReadback
open NativePrivateSpendQ58CurrentExecutableVerifier
open SmzaRp05ExecutableMerkleVerifier (Program Oracle Log ask)
open SmzaRp05ExecutableChallengeStage (returnedWords digestWords)
open SmzaRp05FilteredDecoderInstability (RawRecords)
open SmzaRecordedTracePath
open scoped Classical
noncomputable section
set_option autoImplicit false
set_option Elab.async false
set_option maxHeartbeats 0
set_option maxRecDepth 0
namespace S
export NativePrivateSpendQ58CurrentSourceCandidate (preMatrixLog stages_verifier_has_pre_matrix_log)
end S
namespace RR
export NativePrivateSpendQ58CurrentRetainedResponseReadback (sourceHashProgram responseInput)
end RR
namespace AD
export NativePrivateSpendQ58CurrentAcceptedDecs (currentTranscript currentRestore)
end AD
namespace F
export NativePrivateSpendQ58CurrentFullStageEnvelope (rawNext)
end F

def fppProgram (ns : CM.Namespace) (decoded : DecodedFields) (output : PcsOutput) :=
  RR.sourceHashProgram (digestWords output.root) decoded.decs
    (output.rows.map fun row => row.map SmzaRp05ExecutableRestore.toWord)
    output.gamma (output.decsPoints.map SmzaRp05ExecutableRestore.toWord)
    (List.ofFn fun i : Fin 77 => V8SmzaOracleParser.wordAt ns.binding i.val)

def fullRecords (ns : CM.Namespace) (relation : NativePrivateSpendQ58CurrentPublicOpening.Relation)
    (pending : Bool) (nonce : Fin (2 ^ 32)) (wire : Wire) (oracle : Oracle) : RawRecords :=
  ((verifierProgram ns relation pending nonce wire).record oracle).2.toFinset

/-- Exact record decomposition derived from one successful current PCS
execution. No supplied stage log or membership fact is required. -/
theorem pcs_execution_has_actual_log_parts
    (ns : CM.Namespace) (pending : Bool) (wire : Wire) (decoded : DecodedFields)
    (opening : Opening) (oracle : Oracle) (output : PcsOutput)
    (executed : (pcsProgram ns pending wire decoded opening).eval oracle = some output) :
    ∃ openingDigest,
      ((pcsProgram ns pending wire decoded opening).record oracle).2 =
        [(decsInput wire.hPiop output.heads
          (decoded.pcs.rcombiTails.map SmzaRp05PcsWireProjection.fieldWordsToGoldilocks), openingDigest)] ++
        ((queryProgram pending openingDigest).record oracle).2 ++
        ((CM.merkleProgram ns output.input).record oracle).2 ++
        ((fieldXof .decsMatrix 700 output.root).record oracle).2 ++
        ((fppProgram ns decoded output).record oracle).2 := by
  obtain ⟨openingDigest, sampledPending, sampled, headsBuilt, hashEq, queryEq,
    pointsEq, rowsEq, inputEq, merkleEq, gammaExecuted, gammaEq, restoreEq, fppEq, _⟩ :=
    NativePrivateSpendQ58CurrentAcceptedPcsFacts.pcs_execution_has_actual_facts
      ns pending wire decoded opening oracle output executed
  have guard : ¬ (output.heads.length ≠ 12 ∨ decoded.pcs.rcombiTails.length ≠ 12 ∨
      output.heads.any (fun row => decide (row.length ≠ 13115)) ∨
      decoded.pcs.rcombiTails.any (fun row => decide (row.length ≠ 58))) := by
    intro bad
    simp only [pcsProgram, headsBuilt, if_pos bad, Program.eval] at executed
    cases executed
  have askEq : (ask (decsInput wire.hPiop output.heads
      (decoded.pcs.rcombiTails.map SmzaRp05PcsWireProjection.fieldWordsToGoldilocks))).eval
        oracle = some openingDigest := by
    simp only [ask, Program.eval, hashEq]
  refine ⟨openingDigest, ?_⟩
  simp only [pcsProgram, headsBuilt, if_neg guard]
  rw [Program.record_bind_success oracle (ask _) _ openingDigest askEq]
  rw [Program.record_bind_success oracle (queryProgram pending openingDigest)
    _ (output.indexes, sampledPending) queryEq]
  simp only [pointsEq, rowsEq, inputEq]
  rw [Program.record_bind_success oracle (CM.merkleProgram ns output.input) _ output.root merkleEq]
  rw [Program.record_bind_success oracle (fieldXof .decsMatrix 700 output.root)
    _ sampled gammaExecuted]
  simp only [gammaEq, restoreEq]
  rw [Program.record_bind_success oracle
    (RR.sourceHashProgram (digestWords output.root) decoded.decs
      (output.rows.map fun row => row.map SmzaRp05ExecutableRestore.toWord)
      output.gamma (output.decsPoints.map SmzaRp05ExecutableRestore.toWord)
      (List.ofFn fun i : Fin 77 => V8SmzaOracleParser.wordAt ns.binding i.val))
    _ output.hashFpp fppEq]
  simp only [fppProgram, ask, Program.record, hashEq, List.append_nil, List.append_assoc]

theorem stages_pcs_log_subset_full
    (ns : CM.Namespace) (relation : NativePrivateSpendQ58CurrentPublicOpening.Relation)
    (pending : Bool) (nonce : Fin (2 ^ 32)) (wire : Wire) (oracle : Oracle)
    (transcript : Transcript) (stages : ExecutionStages ns relation pending nonce wire oracle transcript) :
    ((pcsProgram ns stages.openingPending wire stages.decoded stages.opening).record oracle).2 ⊆
      ((verifierProgram ns relation pending nonce wire).record oracle).2 := by
  rw [S.stages_verifier_has_pre_matrix_log ns relation pending nonce wire oracle transcript stages]
  intro call member
  exact List.mem_append.mpr (Or.inl (List.mem_append.mpr (Or.inr member)))

theorem stages_merkle_and_fpp_logs_subset_full
    (ns : CM.Namespace) (relation : NativePrivateSpendQ58CurrentPublicOpening.Relation)
    (pending : Bool) (nonce : Fin (2 ^ 32)) (wire : Wire) (oracle : Oracle)
    (transcript : Transcript) (stages : ExecutionStages ns relation pending nonce wire oracle transcript) :
    ((CM.merkleProgram ns stages.pcs.input).record oracle).2.toFinset ⊆
        fullRecords ns relation pending nonce wire oracle ∧
      ((fppProgram ns stages.decoded stages.pcs).record oracle).2.toFinset ⊆
        fullRecords ns relation pending nonce wire oracle := by
  obtain ⟨openingDigest, parts⟩ := pcs_execution_has_actual_log_parts
    ns stages.openingPending wire stages.decoded stages.opening oracle stages.pcs stages.pcsExecuted
  have included := stages_pcs_log_subset_full ns relation pending nonce wire oracle transcript stages
  constructor <;> intro call member <;> apply List.mem_toFinset.mpr <;> apply included
  · rw [parts]
    simp only [List.mem_append]
    have present := List.mem_toFinset.mp member
    tauto
  · rw [parts]
    simp only [List.mem_append]
    have present := List.mem_toFinset.mp member
    tauto

theorem stages_fpp_preimage_is_in_full_log
    (ns : CM.Namespace) (relation : NativePrivateSpendQ58CurrentPublicOpening.Relation)
    (pending : Bool) (nonce : Fin (2 ^ 32)) (wire : Wire) (oracle : Oracle)
    (transcript : Transcript) (stages : ExecutionStages ns relation pending nonce wire oracle transcript) :
    ∃ raw, (raw, stages.pcs.hashFpp) ∈ fullRecords ns relation pending nonce wire oracle := by
  obtain ⟨_, _, _, _, _, _, _, _, _, _, _, _, _, fppEq, _⟩ :=
    NativePrivateSpendQ58CurrentAcceptedPcsFacts.pcs_execution_has_actual_facts
      ns stages.openingPending wire stages.decoded stages.opening oracle stages.pcs stages.pcsExecuted
  obtain ⟨_, supported⟩ := stages_merkle_and_fpp_logs_subset_full ns relation pending nonce wire
    oracle transcript stages
  cases built : AD.currentTranscript (digestWords stages.pcs.root) stages.decoded.decs
      (stages.pcs.rows.map fun row => row.map SmzaRp05ExecutableRestore.toWord)
      stages.pcs.gamma (stages.pcs.decsPoints.map SmzaRp05ExecutableRestore.toWord) with
  | none =>
      simp only [RR.sourceHashProgram, built, Program.eval] at fppEq
      cases fppEq
  | some words =>
      let raw := RR.responseInput (words ++
        List.ofFn fun i : Fin 77 => V8SmzaOracleParser.wordAt ns.binding i.val)
      have same : oracle raw = stages.pcs.hashFpp := Option.some.inj (by
        simpa only [RR.sourceHashProgram, built, ask, Program.eval] using fppEq)
      refine ⟨raw, supported (List.mem_toFinset.mpr ?_)⟩
      simp only [fppProgram, RR.sourceHashProgram, built]
      change (raw, stages.pcs.hashFpp) ∈ [(raw, oracle raw)]
      exact List.mem_singleton.mpr (congrArg (fun digest => (raw, digest)) same.symm)

theorem recorded_path_subset
    (left right : RawRecords) (included : left ⊆ right)
    (stage : NativePrivateSpendQ58CurrentFullStageEnvelope.Stage)
    (target : V8SmzaOracleParser.RawDigest) (path : List Nat)
    (raw : V8SmzaOracleParser.RawInput)
    (recorded : RecordedPath F.rawNext left stage target path raw) :
    RecordedPath F.rawNext right stage target path raw := by
  induction recorded with
  | here stage target raw member valid =>
      exact RecordedPath.here stage target raw (included member) valid
  | step stage target input edges index childStage childTarget rest leaf member parsed address below ih =>
      exact RecordedPath.step stage target input edges index childStage childTarget rest leaf
        (included member) parsed address ih

/-- Accepted current Merkle execution supplies every literal root-to-leaf
path in the full verifier log. No earlier prefix coverage is inferred. -/
theorem stages_root_paths_are_in_full_log
    (ns : CM.Namespace) (relation : NativePrivateSpendQ58CurrentPublicOpening.Relation)
    (pending : Bool) (nonce : Fin (2 ^ 32)) (wire : Wire) (oracle : Oracle)
    (transcript : Transcript) (stages : ExecutionStages ns relation pending nonce wire oracle transcript)
    (clean : transcript.pending = false) :
    ∃ coordinates : Fin 58 → NativePrivateSpendQ58CurrentOrdinaryRecovery.Position,
      (∀ j, (coordinates j).val = stages.pcs.input.indices j) ∧
      ∀ j, RecordedPath F.rawNext (fullRecords ns relation pending nonce wire oracle)
        .root stages.pcs.root (0 :: SmzaRp05FilteredReadback.indexPath (coordinates j) 23)
        (NativePrivateSpendQ58CurrentCompactMerkle.encodeLeaf stages.pcs.input.binding (stages.pcs.input.payloads j)) := by
  have pcsClean := NativePrivateSpendQ58CurrentAcceptedLeafSupport.stages_pcs_pending_false
    ns relation pending nonce wire oracle transcript stages clean
  have merkleAccepted := NativePrivateSpendQ58CurrentAcceptedLeafSupport.pcs_clean_merkle_accepted
    ns stages.openingPending wire stages.decoded stages.opening oracle stages.pcs stages.pcsExecuted pcsClean
  obtain ⟨coordinates, indexEq, paths⟩ := NativePrivateSpendQ58CurrentCompactMerkle.accepted_recorded_paths ns oracle stages.pcs.input
    stages.pcs.root merkleAccepted
  obtain ⟨included, _⟩ := stages_merkle_and_fpp_logs_subset_full ns relation pending nonce wire
    oracle transcript stages
  refine ⟨coordinates, indexEq, ?_⟩
  intro j
  exact recorded_path_subset _ _ included _ _ _ _ (paths j)

/-- Full same-execution coverage discharges absent final FPP/path arms;
collision-freedom is used only on this good branch and remains a final bad
event otherwise. It says nothing about earlier selected-role prefixes. -/
theorem stages_prior_bad_is_impossible_on_collision_free_full_log
    (ns : CM.Namespace) (relation : NativePrivateSpendQ58CurrentPublicOpening.Relation)
    (pending : Bool) (nonce : Fin (2 ^ 32)) (wire : Wire) (oracle : Oracle)
    (transcript : Transcript) (stages : ExecutionStages ns relation pending nonce wire oracle transcript)
    (clean : transcript.pending = false)
    (free : RecordsCollisionFree (fullRecords ns relation pending nonce wire oracle)) :
    ¬ NativePrivateSpendQ58CurrentOrdinaryRecovery.PriorBad ns stages.decoded oracle stages.pcs
      (fullRecords ns relation pending nonce wire oracle) := by
  intro bad
  obtain ⟨raw, present⟩ := stages_fpp_preimage_is_in_full_log ns relation pending nonce wire oracle
    transcript stages
  obtain ⟨_, fppSubset⟩ := stages_merkle_and_fpp_logs_subset_full ns relation pending nonce wire
    oracle transcript stages
  have unionFree : RecordsCollisionFree (fullRecords ns relation pending nonce wire oracle ∪
      ((fppProgram ns stages.decoded stages.pcs).record oracle).2.toFinset) := by
    have same := Finset.union_eq_left.mpr fppSubset
    rw [same]
    exact free
  rcases bad with missing | collision | collision | ⟨coordinates, _distinct, indicesEq, j, missing⟩
  · exact missing ⟨raw, present⟩
  · exact collision unionFree
  · exact collision free
  · obtain ⟨actualCoordinates, actualIndices, paths⟩ := stages_root_paths_are_in_full_log
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
    exact paths j

namespace A
export NativePrivateSpendQ58CurrentAcceptedEventJoin
  (PiopBad StageBad LiteralBad ordinary_current_acceptance_has_witness_or_literal_bad)
end A
namespace G
export NativePrivateSpendQ58CurrentRecoveryGeometry (MatrixBad SmallSupportBad RecoveryGeometry)
end G
namespace V
export NativePrivateSpendQ58CurrentLvcsEventJoin (CurrentLvcsRootEvent)
end V
namespace D
export NativePrivateSpendQ58CurrentDecodedRelation (Decoded decodedValues)
end D

def FullCurrentBad (ns : CM.Namespace) (relation : NativePrivateSpendQ58CurrentPublicOpening.Relation)
    (pending : Bool) (nonce : Fin (2 ^ 32)) (wire : Wire) (oracle : Oracle) : Prop :=
  ¬ RecordsCollisionFree (fullRecords ns relation pending nonce wire oracle) ∨
  ∃ transcript, ∃ stages : ExecutionStages ns relation pending nonce wire oracle transcript,
    transcript.pending = false ∧
    (G.MatrixBad (fullRecords ns relation pending nonce wire oracle) stages.pcs ∨
     G.SmallSupportBad (fullRecords ns relation pending nonce wire oracle) stages.pcs ∨
     ∃ geometry : G.RecoveryGeometry ns wire stages.decoded stages.opening stages.pcs
       (fullRecords ns relation pending nonce wire oracle),
       V.CurrentLvcsRootEvent geometry.source stages.opening stages.decoded.pcs
         geometry.heads geometry.coordinates ∨
       A.PiopBad relation geometry.source stages.matrix
         (NativePrivateSpendQ58CurrentPiopRecordJoin.priorResponse
           (fullRecords ns relation pending nonce wire oracle) wire.hPiop) stages.opening)

/-- Completed ordinary acceptance to a current satisfying assignment OR
literal current raw collision/matrix/support/LVCS/PIOP events on its OWN full
record. No prior table, desired source/witness, path coverage, scalar readout
or stage certificate is supplied. Earlier/missing preimages are not waived:
the full-log label can acquire them late, charged by current dynamic changes. -/
theorem accepted_current_wire_has_witness_or_literal_full_event
    (ns : CM.Namespace) (relation : NativePrivateSpendQ58CurrentPublicOpening.Relation)
    (pending : Bool) (nonce : Fin (2 ^ 32)) (wire : Wire) (oracle : Oracle)
    (accepted : (verifierProgram ns relation pending nonce wire).eval oracle = some ()) :
    (∃ source : D.Decoded,
      NativePrivateSpendQ58CurrentPublicOpening.Satisfies relation (D.decodedValues source)) ∨
    FullCurrentBad ns relation pending nonce wire oracle := by
  by_cases free : RecordsCollisionFree (fullRecords ns relation pending nonce wire oracle)
  · rcases A.ordinary_current_acceptance_has_witness_or_literal_bad ns relation pending nonce wire oracle
        (fullRecords ns relation pending nonce wire oracle) accepted with witness | bad
    · exact Or.inl witness
    · rcases bad with missing | collision | ⟨transcript, stages, clean, stageBad⟩
      · obtain ⟨transcript, _stages, _clean, _equal, recorded⟩ :=
          accepted_execution_has_stages ns relation pending nonce wire oracle accepted
        exact (missing ⟨finalInput transcript, List.mem_toFinset.mpr recorded⟩).elim
      · have same : fullRecords ns relation pending nonce wire oracle ∪
            ((verifierProgram ns relation pending nonce wire).record oracle).2.toFinset =
              fullRecords ns relation pending nonce wire oracle := by
          unfold fullRecords
          exact Finset.union_self _
        exact (collision (by rw [same]; exact free)).elim
      · apply Or.inr
        apply Or.inr
        refine ⟨transcript, stages, clean, ?_⟩
        rcases stageBad with priorBad | matrixBad | smallBad | geometryBad
        · exact (stages_prior_bad_is_impossible_on_collision_free_full_log ns relation pending nonce wire
            oracle transcript stages clean free priorBad).elim
        · exact Or.inl matrixBad
        · exact Or.inr (Or.inl smallBad)
        · exact Or.inr (Or.inr geometryBad)
  · exact Or.inr (Or.inl free)

end
end HegemonCrypto.SmallWood.NativePrivateSpendQ58CurrentFullLogReadback
