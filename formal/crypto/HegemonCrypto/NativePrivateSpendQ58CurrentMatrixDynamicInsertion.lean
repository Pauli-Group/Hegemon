import HegemonCrypto.NativePrivateSpendQ58CurrentClaimMatrixReadback
import HegemonCrypto.NativePrivateSpendQ58CurrentSameDatabaseEventJoin

/-! Exact current matrix-arm insertion on the SAME sparse active database.
Replay derives the literal matrix base vector for the supplied actual stages.
The base parser derives its database-dependent FPP trace label. The final
accepted-invalid theorem obtains those stages and geometry from the retained
same-database join, then replaces its matrix PIOP arm with literal DynamicBad.
No oracle agreement, event-inclusion callback or probability is supplied.
SOURCE ONLY: kernel validation and initialized density composition are separate. -/
namespace HegemonCrypto.SmallWood.NativePrivateSpendQ58CurrentMatrixDynamicInsertion

open HegemonCrypto.FiniteOracleDatabase (Database)
open HegemonCrypto.CmsOracleDatabaseBridge (ClaimsDatabaseEvent)
open SmzaRp05ExecutableMerkleVerifier (Program Oracle)
open SmzaRp05PhysicalAcceptedReplayLite (Branches branchResult answerLog rawLog branch_claims_eq_answer_log)
open V8Smz9CoherentVectorMerkle (VectorOutput vectorOutputBytes)
open V8Smz9CoherentMerkleInstrument (rawRecords)
open V8Smz9CoherentMerkleGeometry (extract)
open V8Smz9PiopSoundness (Matrix ClaimedTranscript maskSum)
open SmzaRecordedTracePath (RecordsCollisionFree)
open SmzaChallengeStageTargets (Role)
open SmzaDynamicDatabaseSoundness (DynamicBad)
open scoped Classical

namespace E
export NativePrivateSpendQ58CurrentExecutableVerifier
  (Wire Transcript ExecutionStages verifierProgram reconstruct)
end E
namespace G
export NativePrivateSpendQ58CurrentConstructorGrouping
  (Key Counter RawDigest encode decode keyBytes zero recorded_current_base_parser)
end G
namespace AC
export NativePrivateSpendQ58CurrentActiveBranchClaims
  (live activeClaims fixedCompatible current_active_claims_replay_same_program
   current_active_claims_complete_full_branch current_recorded_active_claim_is_selected)
end AC
namespace A
export NativePrivateSpendQ58ActiveEventProjection (ActiveKey merge)
end A
namespace PT
export NativePrivateSpendQ58PartitionTransport (FixedTable)
end PT
namespace GF
export NativePrivateSpendQ58CurrentGammaFiber (currentRoleCaps)
end GF
namespace Q
export NativePrivateSpendQ58CurrentClaimReplay
  (claimOracle fullClaims current_claims_store_every_branch_vector)
end Q
namespace MR
export NativePrivateSpendQ58CurrentClaimMatrixReadback
  (base matrixSelect matrix_base_in_full_log stored_matrix_decodes_execution)
end MR
namespace C
export NativePrivateSpendQ58CurrentRoleClassifier (RoleActive parseCurrentStageQuery)
end C
namespace P
export NativePrivateSpendQ58CurrentPrequeryEvents (currentLabel sourceTrace queryTarget queryStage)
end P
namespace F
export NativePrivateSpendQ58CurrentFullStageEnvelope (rawNext)
end F
namespace TM
export NativePrivateSpendQ58CurrentTracePiopMass (matrixBad fppLabel traceInput)
end TM
namespace S
export NativePrivateSpendQ58CurrentSourceCandidate (calculatedCandidate)
end S
namespace R
export NativePrivateSpendQ58CurrentRecoveryGeometry (RecoveryGeometry MatrixBad SmallSupportBad)
end R
namespace L
export NativePrivateSpendQ58CurrentActualTraceLabel (sourceRecords)
end L
namespace D
export NativePrivateSpendQ58CurrentDecodedRelation (Decoded decodedValues candidate)
end D
namespace U
export NativePrivateSpendQ58CurrentPublicOpening (Relation Satisfies)
end U
namespace M
export NativePrivateSpendQ58CurrentCompactMerkle (Namespace)
end M
namespace V
export NativePrivateSpendQ58CurrentLvcsEventJoin (CurrentLvcsRootEvent)
end V
namespace B
export NativePrivateSpendQ58CurrentAcceptedEventJoin (PiopBad)
end B
namespace PI
export NativePrivateSpendQ58CurrentPiopEvents (currentMatrixEvent CurrentOpeningChecks)
end PI
namespace PR
export NativePrivateSpendQ58CurrentPiopRecordJoin (rawResponse)
end PR
namespace J
export NativePrivateSpendQ58CurrentSameDatabaseEventJoin
  (accepted_invalid_current_branch_has_same_database_literal_event)
end J

noncomputable section
set_option autoImplicit false
set_option Elab.async false
set_option maxHeartbeats 0
set_option maxRecDepth 0

def currentProgram (producer : Program E.Wire) (ns : M.Namespace) (relation : U.Relation)
    (pending : Bool) (nonce : Fin (2^32)) : Program Unit :=
  producer.bind (E.verifierProgram ns relation pending nonce)

def matrixLive {Result : Type} (program : Program Result) :=
  AC.live program .piopMatrix GF.currentRoleCaps

abbrev MatrixFixed {Result : Type} (program : Program Result) :=
  PT.FixedTable (Counter := G.Counter) (matrixLive program)

abbrev MatrixDatabase {Result : Type} (program : Program Result) :=
  Database (A.ActiveKey (matrixLive program)) (VectorOutput G.Counter)

def activeBytes {Result : Type} (program : Program Result) :=
  fun key : A.ActiveKey (matrixLive program) => G.keyBytes program key.val

def currentRaw {Result : Type} (program : Program Result) (database : MatrixDatabase program) :=
  rawRecords (activeBytes program) (vectorOutputBytes G.zero) database

def currentOracle {Result : Type} (program : Program Result) (fixed : MatrixFixed program)
    (database : MatrixDatabase program) (fallback : G.RawDigest) : Oracle :=
  Q.claimOracle program (A.merge (matrixLive program) fixed database) fallback

/-- The exact matrix DynamicBad used by the current per-label density. -/
def matrixDynamicBad {Result : Type} (program : Program Result) (relation : U.Relation)
    (fixed : MatrixFixed program) (database : MatrixDatabase program) : Prop :=
  DynamicBad (P.currentLabel (activeBytes program) G.zero 26)
    (fun trace key vector => TM.matrixBad relation (G.keyBytes program) fixed G.decode
      MR.matrixSelect trace key.val vector) database

/-- A current counter-zero parser receipt determines the label on the same
sparse database, including every extra recorded source frame there. -/
theorem recorded_matrix_base_has_actual_fpp_label {Result : Type}
    (program : Program Result) (database : MatrixDatabase program) (target : G.RawDigest)
    (active : matrixLive program (G.encode program (MR.base target)))
    (parsed : C.parseCurrentStageQuery
      (G.keyBytes program (G.encode program (MR.base target))) = some ⟨.piopMatrix, target, 0, 0⟩) :
    P.currentLabel (activeBytes program) G.zero 26 database
      ⟨G.encode program (MR.base target), active⟩ =
      extract F.rawNext (currentRaw program database) 26 .fpp target := by
  unfold P.currentLabel P.sourceTrace P.queryTarget activeBytes currentRaw
  rw [parsed]
  rfl

private theorem matrix_arm_conjunction_right {left right : Prop}
    (proof : left ∧ right) : right := proof.2

section Current
variable (producer : Program E.Wire) (ns : M.Namespace) (relation : U.Relation)
variable (pending : Bool) (nonce : Fin (2^32))
local notation "program" => currentProgram producer ns relation pending nonce

/-- This derives the base vector of THESE stages, rather than selecting a
second existential transcript with a potentially different stage object. -/
theorem exact_stages_matrix_vector
    (branch : Branches G.decode program) (fixed : MatrixFixed program)
    (database : MatrixDatabase program)
    (compatible : AC.fixedCompatible program .piopMatrix GF.currentRoleCaps fixed branch)
    (claims : ClaimsDatabaseEvent
      (AC.activeClaims program .piopMatrix GF.currentRoleCaps branch) database)
    (fallback : G.RawDigest) (wire : E.Wire) (transcript : E.Transcript)
    (stages : E.ExecutionStages ns relation pending nonce wire
      (currentOracle program fixed database fallback) transcript)
    (produced : producer.eval (currentOracle program fixed database fallback) = some wire)
    (clean : transcript.pending = false) :
    ∃ vector, ∃ active : matrixLive program (G.encode program (MR.base stages.pcs.hashFpp)),
      (MR.base stages.pcs.hashFpp, vector) ∈ answerLog G.decode program branch ∧
      C.parseCurrentStageQuery (G.keyBytes program (G.encode program (MR.base stages.pcs.hashFpp))) =
        some ⟨.piopMatrix, stages.pcs.hashFpp, 0, 0⟩ ∧
      database ⟨G.encode program (MR.base stages.pcs.hashFpp), active⟩ = some vector ∧
      SmzaRp04RawRoleSampling.rawPiopMatrixOutput 1344594
        (SmzaRp04RawRoleSampling.selectedRawBlocks MR.matrixSelect vector) = some stages.matrix := by
  let merged := A.merge (matrixLive program) fixed database
  let oracle := currentOracle program fixed database fallback
  have replay := AC.current_active_claims_replay_same_program program .piopMatrix GF.currentRoleCaps
    fixed branch database compatible claims fallback
  have allClaims := AC.current_active_claims_complete_full_branch program .piopMatrix GF.currentRoleCaps
    fixed branch database compatible claims
  have parts := Program.record_bind_success oracle producer
    (E.verifierProgram ns relation pending nonce) wire produced
  have rawRecorded : (MR.base stages.pcs.hashFpp, oracle (MR.base stages.pcs.hashFpp)) ∈
      rawLog G.decode program branch := by
    have logEq : (Program.record oracle program).2 = rawLog G.decode program branch :=
      congrArg Prod.snd replay
    have partsEq : (Program.record oracle program).2 =
        (Program.record oracle producer).2 ++
          (Program.record oracle (E.verifierProgram ns relation pending nonce wire)).2 :=
      congrArg Prod.snd parts
    rw [← logEq, partsEq]
    exact List.mem_append.mpr (Or.inr
      (MR.matrix_base_in_full_log ns relation pending nonce wire oracle transcript stages))
  obtain ⟨call, recorded, same⟩ := List.mem_map.mp rawRecorded
  have inputEq := congrArg Prod.fst same
  rcases call with ⟨input, vector⟩
  dsimp only at inputEq
  subst input
  have parsed : C.parseCurrentStageQuery
      (G.keyBytes program (G.encode program (MR.base stages.pcs.hashFpp))) =
      some ⟨.piopMatrix, stages.pcs.hashFpp, 0, 0⟩ := by
    unfold MR.base
    exact G.recorded_current_base_parser program branch .piopMatrix stages.pcs.hashFpp
      (0 : Fin (2 ^ 32)) G.zero vector recorded
  have active : matrixLive program (G.encode program (MR.base stages.pcs.hashFpp)) := by
    unfold matrixLive AC.live C.RoleActive
    rw [parsed]
    exact Or.inl rfl
  have fullMember : (G.encode program (MR.base stages.pcs.hashFpp), vector) ∈ Q.fullClaims program branch := by
    rw [Q.fullClaims, branch_claims_eq_answer_log]
    exact List.mem_map.mpr ⟨_, recorded, rfl⟩
  have chosen := AC.current_recorded_active_claim_is_selected program .piopMatrix GF.currentRoleCaps
    branch _ fullMember active
  have stored := Q.current_claims_store_every_branch_vector program branch merged allClaims _ recorded
  have finalClean : stages.finalPending = false := by
    have samePending := congrArg (fun tr : E.Transcript => tr.pending) stages.reconstructed
    simpa only [E.reconstruct] using samePending.trans clean
  exact ⟨vector, active, recorded, parsed, claims _ chosen,
    MR.stored_matrix_decodes_execution program merged fallback stages.pcs.hashFpp vector stored
      stages.pcs.pending stages.finalPending stages.matrix stages.matrixExecuted finalClean⟩

/-- Concrete geometry and its matrix event arm are intermediate outputs of
the accepted join. Their source equality is read at THIS sparse FPP trace. -/
theorem actual_matrix_arm_is_dynamic_bad
    (branch : Branches G.decode program) (fixed : MatrixFixed program)
    (database : MatrixDatabase program)
    (compatible : AC.fixedCompatible program .piopMatrix GF.currentRoleCaps fixed branch)
    (claims : ClaimsDatabaseEvent
      (AC.activeClaims program .piopMatrix GF.currentRoleCaps branch) database)
    (fallback : G.RawDigest) (wire : E.Wire) (transcript : E.Transcript)
    (stages : E.ExecutionStages ns relation pending nonce wire
      (currentOracle program fixed database fallback) transcript)
    (produced : producer.eval (currentOracle program fixed database fallback) = some wire)
    (clean : transcript.pending = false)
    (geometry : R.RecoveryGeometry ns wire stages.decoded stages.opening stages.pcs
      (L.sourceRecords (currentRaw program database)))
    (calculated : S.calculatedCandidate (TM.fppLabel .piopMatrix (G.keyBytes program) fixed G.decode
      (extract F.rawNext (currentRaw program database) 26 .fpp stages.pcs.hashFpp)) = some geometry.source)
    (matrixArm : ¬ PiopExtraction.FullySatisfied (D.candidate relation geometry.source).system ∧
      stages.matrix ∈ PI.currentMatrixEvent (D.candidate relation geometry.source)) :
    matrixDynamicBad program relation fixed database := by
  obtain ⟨vector, active, recorded, parsed, stored, decoded⟩ :=
    exact_stages_matrix_vector producer ns relation pending nonce branch fixed database
      compatible claims fallback wire transcript stages produced clean
  have label := recorded_matrix_base_has_actual_fpp_label program database stages.pcs.hashFpp active parsed
  refine ⟨⟨G.encode program (MR.base stages.pcs.hashFpp), active⟩, vector, stored, ?_⟩
  change TM.matrixBad relation (G.keyBytes program) fixed G.decode MR.matrixSelect
    (P.currentLabel (activeBytes program) G.zero 26 database
      ⟨G.encode program (MR.base stages.pcs.hashFpp), active⟩)
    (G.encode program (MR.base stages.pcs.hashFpp)) vector
  rw [label]
  unfold TM.matrixBad
  rw [calculated]
  constructor
  · refine ⟨⟨.piopMatrix, stages.pcs.hashFpp, 0, 0⟩, ?_, ?_, ?_⟩
    · exact parsed
    · rfl
    · rfl
  · constructor
    · exact matrixArm.1
    · refine ⟨stages.matrix, ?_, ?_⟩
      · exact decoded
      · with_reducible
          exact no_implicit_lambda% (@matrix_arm_conjunction_right
              (¬ PiopExtraction.FullySatisfied (D.candidate relation geometry.source).system)
              (stages.matrix ∈ PI.currentMatrixEvent (D.candidate relation geometry.source))
              matrixArm)

/-- Actual acceptance derives the stages and geometry before matrix insertion.
All remaining named arms stay visible; there is no supplied inclusion law. -/
theorem accepted_invalid_branch_has_matrix_dynamic_or_other_literal_event
    (branch : Branches G.decode program) (fixed : MatrixFixed program)
    (database : MatrixDatabase program)
    (compatible : AC.fixedCompatible program .piopMatrix GF.currentRoleCaps fixed branch)
    (claims : ClaimsDatabaseEvent
      (AC.activeClaims program .piopMatrix GF.currentRoleCaps branch) database)
    (fallback : G.RawDigest) (accepted : branchResult G.decode program branch = some ())
    (invalid : ¬∃ source : D.Decoded, U.Satisfies relation (D.decodedValues source)) :
    let oracle := currentOracle program fixed database fallback
    let raw := currentRaw program database
    let records := L.sourceRecords raw
    ∃ wire, producer.eval oracle = some wire ∧
      (¬ RecordsCollisionFree records ∨
        ∃ transcript, ∃ stages : E.ExecutionStages ns relation pending nonce wire oracle transcript,
          transcript.pending = false ∧
          (R.MatrixBad records stages.pcs ∨ R.SmallSupportBad records stages.pcs ∨
            ∃ geometry : R.RecoveryGeometry ns wire stages.decoded stages.opening stages.pcs records,
              S.calculatedCandidate (TM.fppLabel .piopMatrix (G.keyBytes program) fixed G.decode
                (extract F.rawNext raw 26 .fpp stages.pcs.hashFpp)) = some geometry.source ∧
              (V.CurrentLvcsRootEvent geometry.source stages.opening stages.decoded.pcs
                geometry.heads geometry.coordinates ∨
                (¬ PiopExtraction.AffineBatchAccepts (D.candidate relation geometry.source).system
                    (maskSum (D.candidate relation geometry.source)) stages.matrix ∧
                  PI.CurrentOpeningChecks (D.candidate relation geometry.source) stages.matrix
                    (PR.rawResponse (TM.traceInput (extract F.rawNext raw 27 .piop wire.hPiop))) stages.opening) ∨
                matrixDynamicBad program relation fixed database))) := by
  obtain ⟨wire, produced, event⟩ := J.accepted_invalid_current_branch_has_same_database_literal_event
    producer ns relation pending nonce branch .piopMatrix (Or.inl rfl)
      fixed compatible database claims fallback accepted invalid
  refine ⟨wire, produced, ?_⟩
  rcases event with collision | ⟨transcript, stages, clean, failure⟩
  · exact Or.inl collision
  · apply Or.inr
    refine ⟨transcript, stages, clean, ?_⟩
    rcases failure with matrix | small | ⟨geometry, calculated, event⟩
    · exact Or.inl matrix
    · exact Or.inr (Or.inl small)
    · apply Or.inr
      apply Or.inr
      refine ⟨geometry, calculated, ?_⟩
      rcases event with lvcs | piop
      · exact Or.inl lvcs
      · rcases piop with matrixArm | openingArm
        · exact Or.inr (Or.inr
            (actual_matrix_arm_is_dynamic_bad producer ns relation pending nonce branch fixed database
              compatible claims fallback wire transcript stages produced clean geometry calculated matrixArm))
        · exact Or.inr (Or.inl openingArm)

end Current
end
end HegemonCrypto.SmallWood.NativePrivateSpendQ58CurrentMatrixDynamicInsertion
