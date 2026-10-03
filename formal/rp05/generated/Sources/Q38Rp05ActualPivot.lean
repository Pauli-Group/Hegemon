import Q38Rp05ClippedCallbacks
import Q38Rp05PhaseStoppingBound
import Q38Rp05HistoryGameJoin
import Q38Rp05RealReadoutAdapter
import Q38Rp05RealLeafProduct
import Q38Rp05UniformAverageTransport

/-! Actual bounded real/public request pivot on one stopped CMS state.
The Unit register avoids adding a measurement of adversary workspace. -/
namespace HegemonCrypto.SmallWood.Q38Rp05ActualPivot

open HegemonCrypto.CanonicalBytes
open HegemonCrypto.CmsCompressedOracle
open HegemonCrypto.CmsOracleSimulation
open HegemonCrypto.CmsQuerySequence
open HegemonCrypto.CmsOracleDatabaseBridge
open HegemonCrypto.SmallWood.V8Smz9HiddenLeafQrom
open HegemonCrypto.SmallWood.V8Smz9HiddenPatch
open HegemonCrypto.SmallWood.V8Smz9ZeroKnowledge
open HegemonCrypto.SmallWood.V8Smz9CurrentPrivacyGame
open HegemonCrypto.SmallWood.V8Smz9EagerOracleGame
open HegemonCrypto.SmallWood.V8Smz9EagerPrivacy
open HegemonCrypto.SmallWood.V8Smz9HonestWholeViewGames
open HegemonCrypto.SmallWood.V8Smz9RuntimeDistribution
open HegemonCrypto.SmallWood.V8Smz9CurrentPrivacyComposition
open HegemonCrypto.SmallWood.V8SmzaMathPrivacy
open HegemonCrypto.SmallWood.V8SmzaRemainingAlgebra
open HegemonCrypto.SmallWood.V8SmzaControlledFreshSwap
open HegemonCrypto.SmallWood.V8SmzaCmsControlledSwap
open HegemonCrypto.SmallWood.Q38CmsInitializedResampling
open HegemonCrypto.SmallWood.Q38CmsAdaptiveWholeViewApplication
open HegemonCrypto.SmallWood.Q38CmsPhaseDecodeIsometry
open HegemonCrypto.SmallWood.Q38WholeViewCmsSemantics
open HegemonCrypto.SmallWood.Q38Rp05RawInputPartition
open HegemonCrypto.SmallWood.Q38Rp05LeafSupport
open HegemonCrypto.SmallWood.Q38Rp05MaskRecovery (rp05PackValues)
open HegemonCrypto.SmallWood.Q38Rp05ChronologicalAlgebra
open HegemonCrypto.SmallWood.Q38Rp05CurrentCompleteRequest
open HegemonCrypto.SmallWood.Q38Rp05CurrentFreshBound
open HegemonCrypto.SmallWood.Q38Rp05HistoryFreshBound
open HegemonCrypto.SmallWood.Q38Rp05RealReadoutAdapter
open HegemonCrypto.SmallWood.Q38Rp05RealLeafProduct
open HegemonCrypto.SmallWood.Q38Rp05MeasuredInstrument
open HegemonCrypto.SmallWood.Q38Rp05ExecutionBridge
open HegemonCrypto.SmallWood.Q38Rp05RecordedRequest
open HegemonCrypto.SmallWood.Q38Rp05RetainedKernelJoin
open HegemonCrypto.SmallWood.Q38Rp05HistoryGameJoin
open HegemonCrypto.SmallWood.Q38Rp05AdaptiveScheduler
open HegemonCrypto.SmallWood.Q38Rp05UniformAverageTransport
open HegemonCrypto.SmallWood.Q38Rp05StoppedRefinement
open HegemonCrypto.SmallWood.Q38Rp05ClippedCallbacks
open HegemonCrypto.SmallWood.Q38Rp05OpenedOverlay
open HegemonCrypto.SmallWood.Q38Rp05OpeningSchedule
open HegemonCrypto.SmallWood.SmzaRp05CsrNormalization
open HegemonCrypto.SmallWood.SmzaRp05StatementNamespace
open HegemonCrypto.SmallWood.SmzaRp05RelationRefinement
open Hegemon.Transaction.Poseidon2V8RelationProgram
open V8Smz9MixedMaskCompiler (MixedProgram)
open scoped BigOperators Classical

noncomputable section
set_option autoImplicit false
set_option Elab.async false
set_option maxRecDepth 10000
set_option maxHeartbeats 2000000

private theorem phase_family_average
    {Input Workspace : Type} [Fintype Input] [DecidableEq Input]
    [Fintype Workspace] [DecidableEq Workspace]
    (randomized : Bool) (program : Program Input Workspace)
    (family : OracleRegisterFamily
      (Input := Input) (Output := DigestRegister)
      (Phase := DigestRegister) (Workspace := Workspace)) :
    phaseRun randomized program (phaseEncode (totalOracleFamilyState family)) =
      uniformAverage (fun oracle : Input → DigestRegister =>
        run randomized program oracle (familyGameState family oracle)) := by
  rw [phase_run_eq_database_run, phase_decode_encode,
    databaseRun_totalOracleFamilyState]
  apply congrArg uniformAverage
  funext oracle
  exact databaseRun_oracleState randomized program oracle
    (familyGameState family oracle)

variable {bound : Nat} {Work : Type} [Fintype Work] [DecidableEq Work]
local notation "OracleInput" => Rp05FullRawInput bound
local notation "W" => Unit × Work
attribute [local instance]
  HegemonCrypto.SmallWood.Q38Rp05CurrentCompleteRequest.tailLeafIndexDecidableEq
attribute [local irreducible] realLeafBatch uniformAverage phaseRun
  V8Smz9HonestWholeViewGames.run V8Smz9MixedMaskCompiler.run

def loss (total : Nat) : ℝ :=
  2 * Real.sqrt (4 * (total : ℝ) * (2 ^ 512 : ℝ)⁻¹) + 4 * (total : ℝ) / (2 : ℝ)^256

theorem loss_nonnegative (total : Nat) : 0 ≤ loss total := by
  unfold loss
  positivity

theorem phase_run_same_family (program : Program OracleInput W)
    (reached : ResponseCmsState OracleInput W)
    (supported : TotalDatabaseSupport (phaseDecode reached)) :
    phaseRun true program reached =
      uniformAverage (fun oracle : OracleInput → DigestRegister =>
        run true program oracle
          (familyGameState (canonicalTotalFamily (phaseDecode reached)) oracle)) := by
  have sameState :
      phaseEncode (totalOracleFamilyState (canonicalTotalFamily (phaseDecode reached))) =
        reached := by
    rw [total_oracle_family_canonical_eq (phaseDecode reached) supported,
      phase_encode_decode]
  calc
    phaseRun true program reached =
        phaseRun true program
          (phaseEncode (totalOracleFamilyState (canonicalTotalFamily (phaseDecode reached)))) :=
      congrArg (phaseRun true program) sameState.symm
    _ = _ :=
      phase_family_average true program (canonicalTotalFamily (phaseDecode reached))

omit [DecidableEq Work] in
theorem real_request_current_source (data : Request bound)
    (next : Bytes → MixedProgram OracleInput W) (oracle : OracleInput → DigestRegister)
    (state : GameState (Input := OracleInput) (Work := W)) :
    V8Smz9MixedMaskCompiler.run true (realRequest data next) oracle state =
      uniformAverage (fun base : RemainingCoins Goldilocks =>
        uniformAverage (fun masks : Q × D =>
          uniformAverage (fun tapes : LeafIndex → LeafTape =>
            let labels := fun index => oracle (Sum.inl (rp05SourceLeafInput
              data.statement data.salt
              (q38PhysicalSuffix (currentHeads data.witness base masks.1)
                base.2.2 masks.2 index) index (tapes index)))
            run true (V8Smz9MixedMaskCompiler.compile
              (next (currentRequestResult data.largeEnough data.dsl data.statement
                data.witness data.salt data.widthBound base masks tapes labels oracle)) [])
                oracle state))) := by
  simp only [realRequest, V8Smz9MixedMaskCompiler.run]
  apply congrArg uniformAverage
  funext base
  apply congrArg uniformAverage
  funext masks
  rw [real_leaf_batch_product]
  apply uniform_average_congr_instances
  intro tapes
  rw [mixed_nonleaf_executes, current_request_result_eq_recorded,
    V8Smz9MixedMaskCompiler.compile_executes, V8Smz9MixedMaskCompiler.effective_empty]
  simp only [id_eq]

/-- Exact real-side identification, with no new history measurement. -/
theorem real_pivot_eq_unswapped (data : Request bound)
    (next : Bytes → MixedProgram OracleInput W)
    (reached : ResponseCmsState OracleInput W)
    (supported : TotalDatabaseSupport (phaseDecode reached)) :
    phaseRun true (V8Smz9MixedMaskCompiler.compile (realRequest data next) []) reached =
      historyFreshProbability false data.largeEnough (fun _ : Unit => data.dsl)
        (fun _ => data.statement) (fun _ => data.witness) (fun _ => data.salt)
        (fun _ => data.widthBound)
        (fun _ bytes => V8Smz9MixedMaskCompiler.compile (next bytes) [])
        (coreOfCmsState reached) () := by
  let family := canonicalTotalFamily (phaseDecode reached)
  have initialized := initialized_phase_family_of_same_reached
    (Index := LeafIndex) reached supported
  have unitCore : historyCore () (coreOfCmsState reached) = coreOfCmsState reached := by
    funext basis
    simp [historyCore]
  rw [phase_run_same_family _ reached supported]
  simp_rw [V8Smz9MixedMaskCompiler.compile_executes,
    V8Smz9MixedMaskCompiler.effective_empty, real_request_current_source]
  unfold historyFreshProbability
  simp only [Bool.false_eq_true, if_false, unitCore]
  rw [← initialized, current_fresh_unswapped_source_average]
  rw [uniform_average_comm]
  apply congrArg uniformAverage
  funext base
  rw [uniform_average_comm]
  apply congrArg uniformAverage
  funext masks
  rw [uniform_average_comm]

/-- Actual clipped-context pivot bound. Clipping is observationally exact by
the expanded real/public budget, and gives the P9 theorem its all-byte bound.
The relation, support, and query premises are not desired game inequalities. -/
theorem actual_pivot_bound
    (components : RelationProgramComponents) (nonlinearRoot : Fin 818 → Nat)
    (nodeDegree : Nat → Nat)
    (certificates : GeneratedCertificates (normalizedDsl components nonlinearRoot nodeDegree))
    (data : Request bound)
    (currentDsl : data.dsl = normalizedDsl components nonlinearRoot nodeDegree)
    (accepted : components.AcceptsPacked (currentPublicWords data.statement)
      (rp05PackValues data.witness))
    (abortPoints : Fin 6 → Goldilocks)
    (abortAdmissible : Smz9WitnessInterpolationAdmissible abortPoints)
    (abortNonzero : ∀ index, abortPoints index ≠ 0) (abortTargets : Targets abortPoints)
    (next : Bytes → MixedProgram OracleInput W) (total : Nat)
    (realBudget : V8Smz9MixedMaskCompiler.queryCount (realRequest data next) ≤ total)
    (publicBudget : V8Smz9MixedMaskCompiler.queryCount
      (publicRequest data.largeEnough data.dsl data.statement data.salt data.widthBound next) ≤ total)
    (reached : ResponseCmsState OracleInput W)
    (bounded : BoundedState total reached)
    (supported : TotalDatabaseSupport (phaseDecode reached)) :
    |phaseRun true (V8Smz9MixedMaskCompiler.compile (realRequest data next) []) reached -
      phaseRun true (V8Smz9MixedMaskCompiler.compile
        (publicRequest data.largeEnough data.dsl data.statement data.salt data.widthBound next) []) reached| ≤
      loss total * normSquared reached := by
  let clipped := fun bytes => clip total (next bytes)
  let future := fun bytes => V8Smz9MixedMaskCompiler.compile (clipped bytes) []
  have futureBudget (bytes : Bytes) : queryCount (future bytes) ≤ total :=
    compiled_clip_query_bound total (next bytes)
  rw [← real_request_clipped_eq data next total realBudget,
    ← public_request_clipped_eq data next total publicBudget]
  let family := canonicalTotalFamily (phaseDecode reached)
  have global := global_total_support_of_decoded_total reached supported
  have sameHistory : historyFamily () reached = family := by
    have sameState : historyReached () reached = reached := by
      funext basis
      simp [historyReached]
    simp only [historyFamily, sameState, family]
  have changed := history_fresh_changed_eq_complete_request data.largeEnough
    (fun _ : Unit => data.dsl) (fun _ => data.statement) (fun _ => data.witness)
    (fun _ => data.salt) (fun _ => data.widthBound) (fun _ => future) reached global ()
  rw [sameHistory] at changed
  have freshBound := current_history_fresh_reached_bound data.largeEnough
    (fun _ : Unit => data.dsl) (fun _ => data.statement) (fun _ => data.witness)
    (fun _ => data.salt) (fun _ => data.widthBound) (fun _ => future)
    reached total bounded supported
  simp only [Fintype.sum_unique] at freshBound
  rw [changed, ← real_pivot_eq_unswapped data clipped reached supported] at freshBound
  have retainedFor
      (dsl : RelationDsl)
      (same : dsl = normalizedDsl components nonlinearRoot nodeDegree)
      (width : 5 * dsl.width data.statement ≤ 2 ^ 24) :
      |uniformAverage (fun oracle : OracleInput → DigestRegister =>
          run true
            (currentCompleteHonestRequest data.largeEnough dsl
              data.statement data.witness data.salt width future)
            oracle (familyGameState family oracle)) -
        uniformAverage (fun oracle : OracleInput → DigestRegister =>
          publicSimulatorProbability data.largeEnough dsl
            data.statement data.salt width abortPoints
            oracle (familyGameState family oracle) future)| ≤
        (4 * (total : ℝ) / (2 : ℝ)^256) *
          normSquared (totalOracleFamilyState family) := by
    subst dsl
    exact complete_request_family_vs_public_bound_mass
      components nonlinearRoot nodeDegree certificates
      data.largeEnough data.statement data.witness data.salt
      width abortPoints abortAdmissible abortNonzero abortTargets
      family future total futureBudget accepted
  have retained := retainedFor data.dsl currentDsl data.widthBound
  have familyMass : normSquared (totalOracleFamilyState family) = normSquared reached := by
    rw [total_oracle_family_canonical_eq _ supported, phase_decode_norm_squared]
  rw [familyMass] at retained
  have publicEq : phaseRun true (V8Smz9MixedMaskCompiler.compile
      (publicRequest data.largeEnough data.dsl data.statement data.salt data.widthBound clipped) []) reached =
      uniformAverage (fun oracle : OracleInput → DigestRegister =>
        publicSimulatorProbability data.largeEnough data.dsl data.statement data.salt
          data.widthBound abortPoints oracle (familyGameState family oracle) future) := by
    rw [phase_run_same_family _ reached supported]
    apply congrArg uniformAverage
    funext oracle
    rw [V8Smz9MixedMaskCompiler.compile_executes, V8Smz9MixedMaskCompiler.effective_empty]
    exact public_request_executes _ _ _ _ _ _ _ _ _
  rw [← publicEq] at retained
  calc
    _ ≤ |phaseRun true (V8Smz9MixedMaskCompiler.compile (realRequest data clipped) []) reached -
          uniformAverage (fun oracle : OracleInput → DigestRegister =>
            run true (currentCompleteHonestRequest data.largeEnough data.dsl data.statement
              data.witness data.salt data.widthBound future) oracle (familyGameState family oracle))| +
        |uniformAverage (fun oracle : OracleInput → DigestRegister =>
            run true (currentCompleteHonestRequest data.largeEnough data.dsl data.statement
              data.witness data.salt data.widthBound future) oracle (familyGameState family oracle)) -
          phaseRun true (V8Smz9MixedMaskCompiler.compile
            (publicRequest data.largeEnough data.dsl data.statement data.salt data.widthBound clipped) []) reached| :=
      abs_sub_le _ _ _
    _ ≤ _ := add_le_add (by simpa only [abs_sub_comm] using freshBound) retained
    _ = _ := by unfold loss; ring

end
end HegemonCrypto.SmallWood.Q38Rp05ActualPivot
