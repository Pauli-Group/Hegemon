import Q38Rp05ExecutionBridgeBase
import Q38Rp05ExecutionBridgeEnvironmentAlgebra
import Q38Rp05ExecutionBridgeIgnoredEnvironment
import HegemonCrypto.SmallWoodV8Smz9RunHomogeneity
import HegemonCrypto.CmsOracleDatabaseBridge

/-!
# RP05 initialized-CMS execution bridge

This file records two distinct exact identities.  First, after controlled
swaps we can decode the complete persistent database, reconstruct its
canonical total-oracle family, and execute the same seven-constructor
`Program` on every named oracle branch.  That family remains tape-dependent,
so this identity alone is deliberately *not* advertised as the common-state
input to the adaptive-opening theorem.  Second, the literal RP05
`Program.freshInput` batch is reduced to the finite old-oracle/full-overlay
law while retaining the old-oracle-indexed prior state.

The terminal reads below are explicitly CURRENT reads.  On each canonical
branch they return `oracle (key i)`; reinstalling those answers with the RP05
batch-update function leaves that complete oracle unchanged.  Thus the saved
fresh-label registers are never substituted for current database answers.
-/
namespace HegemonCrypto.SmallWood.Q38Rp05ExecutionBridge

open HegemonCrypto.FiniteOracleDatabase
open HegemonCrypto.CmsCompressedOracle
open HegemonCrypto.CmsOracleDatabaseBridge
open HegemonCrypto.CmsOracleSimulation
open HegemonCrypto.CmsQuerySequence
open HegemonCrypto.SmallWood.V8Smz9HiddenLeafQrom
open HegemonCrypto.SmallWood.V8Smz9HiddenPatch
open HegemonCrypto.SmallWood.V8Smz9RuntimeDistribution
open HegemonCrypto.SmallWood.V8Smz9CurrentPrivacyGame
open HegemonCrypto.SmallWood.V8Smz9HonestWholeViewGames
open HegemonCrypto.SmallWood.V8Smz9RunHomogeneity
open HegemonCrypto.SmallWood.Q38WholeViewCmsSemantics
open HegemonCrypto.SmallWood.Q38CmsAdaptiveWholeViewApplication
open HegemonCrypto.SmallWood.Q38CmsInitializedResampling
open HegemonCrypto.SmallWood.V8SmzaCmsControlledSwap
open HegemonCrypto.SmallWood.V8SmzaControlledFreshSwap
open HegemonCrypto.SmallWood.V8SmzaCmsSwapConjugation
open HegemonCrypto.SmallWood.V8SmzaCmsIndexedSwap
open HegemonCrypto.SmallWood.Q38Rp05LeafSupport
open HegemonCrypto.SmallWood.Q38ConcreteAdaptivePrivacy
open HegemonCrypto.SmallWood.SmzaRp05StatementNamespace
open scoped BigOperators Classical

local notation "Statement" => SmzaRp05StatementNamespace.Statement

noncomputable section
set_option autoImplicit false
set_option Elab.async false
set_option maxHeartbeats 2000000
set_option maxRecDepth 10000
set_option exponentiation.threshold 512
set_option linter.unusedSectionVars false

variable {Other Branch BaseWork : Type}
variable [Fintype Other] [DecidableEq Other]
variable [Fintype Branch] [DecidableEq Branch]
variable [Fintype BaseWork] [DecidableEq BaseWork]

local notation "FullInput" => Rp05LeafInput ⊕ Other
local notation "FullWork" =>
  (LeafIndex → DigestRegister) × (Branch × BaseWork)
local notation "FullCore" =>
  Core FullInput Branch
    (FullInput × DigestRegister × BaseWork) DigestRegister

/- Generic uniform-environment and indexed/list-swap family algebra is defined in
   Q38Rp05ExecutionBridgeEnvironmentAlgebra.lean. -/

section EnvironmentExecution

variable {Input Work Environment : Type}
variable [Fintype Input] [DecidableEq Input]
variable [Fintype Work] [DecidableEq Work] [Fintype Environment]

/-- Concrete initialized phase representative of a complete oracle family
with an independent flat saved-label table. -/
def initializedPhaseFamily
    (family : OracleRegisterFamily
      (Input := Input) (Output := DigestRegister)
      (Phase := DigestRegister) (Workspace := Work)) :
    ResponseCmsState Input ((Environment → DigestRegister) × Work) :=
  globalDecompress (responseFourierState
    (appendUniformEnvironmentState
      (totalOracleFamilyState family)))

/-- Fixed-classical-branch CMS execution identity.  It combines the actual
compressed indexed swaps, response-basis decoding, the complete-oracle family
and the seven-constructor interpreter.  The only family on the right is the
explicit inverse finite swap of the original `family`; no canonical family is
introduced after the tape-dependent operation. -/
theorem phase_run_compressed_swaps_as_explicit_family
    (randomized : Bool) (keys : Environment → Input)
    (indices : List Environment)
    (family : OracleRegisterFamily
      (Input := Input) (Output := DigestRegister)
      (Phase := DigestRegister) (Workspace := Work))
    (program : Program Input ((Environment → DigestRegister) × Work)) :
    phaseRun randomized program
        (compressedSwapList keys indices (initializedPhaseFamily family)) =
      databaseRun randomized program
        (totalOracleFamilyState
          (inverseSwapListFamily keys indices
            (uniformEnvironmentFamily family))) := by
  rw [phase_run_eq_database_run]
  unfold phaseDecode initializedPhaseFamily
  rw [global_swap_list_intertwining, global_decompress_involutive,
    response_fourier_inverse_raw_swap_list_fourier,
    append_uniform_environment_total_family,
    raw_swap_list_environment_family]

theorem phase_run_compressed_swaps_trace_environment
    (randomized : Bool) (keys : Environment → Input)
    (indices : List Environment)
    (family : OracleRegisterFamily
      (Input := Input) (Output := DigestRegister)
      (Phase := DigestRegister) (Workspace := Work))
    (program : Program Input Work) :
    phaseRun randomized
        (liftEnvironmentProgram
          (Environment := Environment → DigestRegister) program)
        (compressedSwapList keys indices (initializedPhaseFamily family)) =
      uniformAverage (fun oracle : Input → DigestRegister =>
        ∑ labels : Environment → DigestRegister,
          V8Smz9HonestWholeViewGames.run randomized program oracle
            (environmentFiber labels
              (familyGameState
                (inverseSwapListFamily keys indices
                  (uniformEnvironmentFamily family)) oracle))) := by
  rw [phase_run_compressed_swaps_as_explicit_family]
  rw [databaseRun_totalOracleFamilyState]
  apply congrArg uniformAverage
  funext oracle
  rw [databaseRun_oracleState]
  exact run_lift_environment_program randomized program oracle _

omit [Fintype Input] [Fintype Work] [DecidableEq Work] in
theorem traced_inverse_family_fiber
    (keys : Environment → Input) (indices : List Environment)
    (family : OracleRegisterFamily
      (Input := Input) (Output := DigestRegister)
      (Phase := DigestRegister) (Workspace := Work))
    (oracle : Input → DigestRegister)
    (labels : Environment → DigestRegister) :
    environmentFiber labels
        (familyGameState
          (inverseSwapListFamily keys indices
            (uniformEnvironmentFamily family)) oracle) =
      let old := undoSwapOracleLabelsList keys indices (oracle, labels)
      HegemonCrypto.CmsCompressedOracle.inverseSqrtOutputCard
        (Output := Environment → DigestRegister) •
        familyGameState family old.1 := by
  dsimp only
  ext basis
  simp [environmentFiber, familyGameState, inverse_swap_list_family_apply,
    uniformEnvironmentFamily, mul_comm,
    HegemonCrypto.CmsCompressedOracle.inverseSqrtOutputCard]

theorem phase_run_compressed_swaps_as_old_prior_average
    (randomized : Bool) (keys : Environment → Input)
    (indices : List Environment)
    (family : OracleRegisterFamily
      (Input := Input) (Output := DigestRegister)
      (Phase := DigestRegister) (Workspace := Work))
    (program : Program Input Work) :
    phaseRun randomized
        (liftEnvironmentProgram
          (Environment := Environment → DigestRegister) program)
        (compressedSwapList keys indices (initializedPhaseFamily family)) =
      uniformAverage (fun oracle : Input → DigestRegister =>
        uniformAverage (fun labels : Environment → DigestRegister =>
          let old := undoSwapOracleLabelsList keys indices (oracle, labels)
          V8Smz9HonestWholeViewGames.run randomized program oracle
            (familyGameState family old.1))) := by
  rw [phase_run_compressed_swaps_trace_environment]
  apply congrArg uniformAverage
  funext oracle
  rw [uniformAverage_eq_sum_div]
  simp_rw [traced_inverse_family_fiber (keys := keys) (indices := indices)
    (family := family) (oracle := oracle)]
  simp_rw [run_smul]
  simp_rw [HegemonCrypto.CmsKernelBounds.normSq_inverseSqrtOutputCard]
  change (∑ labels : Environment → DigestRegister,
      1 / (Fintype.card (Environment → DigestRegister) : ℝ) *
        V8Smz9HonestWholeViewGames.run randomized program oracle
          (familyGameState family
            (undoSwapOracleLabelsList keys indices (oracle, labels)).1)) = _
  rw [← Finset.mul_sum]
  ring

/-- Finite change of variables from final `(oracle, oldLabels)` coordinates
back to the original complete oracle and independent fresh-label table.  The
prior state is consequently indexed by the original oracle, while the
program runs against the forward-swapped persistent oracle. -/
theorem phase_run_compressed_swaps_as_forward_overlay
    (randomized : Bool) (keys : Environment → Input)
    (indices : List Environment)
    (family : OracleRegisterFamily
      (Input := Input) (Output := DigestRegister)
      (Phase := DigestRegister) (Workspace := Work))
    (program : Program Input Work) :
    phaseRun randomized
        (liftEnvironmentProgram
          (Environment := Environment → DigestRegister) program)
        (compressedSwapList keys indices (initializedPhaseFamily family)) =
      uniformAverage (fun oldOracle : Input → DigestRegister =>
        uniformAverage (fun freshLabels : Environment → DigestRegister =>
          let final := swapOracleLabelsList keys indices
            (oldOracle, freshLabels)
          V8Smz9HonestWholeViewGames.run randomized program final.1
            (familyGameState family oldOracle))) := by
  rw [phase_run_compressed_swaps_as_old_prior_average]
  calc
    uniformAverage (fun oracle : Input → DigestRegister =>
        uniformAverage (fun labels : Environment → DigestRegister =>
          let old := undoSwapOracleLabelsList keys indices (oracle, labels)
          V8Smz9HonestWholeViewGames.run randomized program oracle
            (familyGameState family old.1))) =
      uniformAverage (fun pair :
          (Input → DigestRegister) × (Environment → DigestRegister) =>
        let old := undoSwapOracleLabelsList keys indices pair
        V8Smz9HonestWholeViewGames.run randomized program pair.1
          (familyGameState family old.1)) := by
        exact (V8Smz9HonestLeafBatch.uniform_average_product
          (A := Input → DigestRegister) (B := Environment → DigestRegister)
          (fun oracle labels =>
            let old := undoSwapOracleLabelsList keys indices (oracle, labels)
            V8Smz9HonestWholeViewGames.run randomized program oracle
              (familyGameState family old.1))).symm
    _ = uniformAverage (fun pair :
          (Input → DigestRegister) × (Environment → DigestRegister) =>
        let final := swapOracleLabelsList keys indices pair
        V8Smz9HonestWholeViewGames.run randomized program final.1
          (familyGameState family pair.1)) := by
        let equivalence := swapOracleLabelsListEquiv keys indices
        have changed := V8Smz9CurrentPrivacyGame.uniform_average_equiv
          equivalence
          (fun final : (Input → DigestRegister) ×
              (Environment → DigestRegister) =>
            let old := undoSwapOracleLabelsList keys indices final
            V8Smz9HonestWholeViewGames.run randomized program final.1
              (familyGameState family old.1))
        have inverseAfter (pair :
            (Input → DigestRegister) × (Environment → DigestRegister)) :
            undoSwapOracleLabelsList keys indices
                (swapOracleLabelsList keys indices pair) = pair := by
          have inverse := Equiv.symm_apply_apply equivalence pair
          change (swapOracleLabelsListEquiv keys indices).symm
            (swapOracleLabelsListEquiv keys indices pair) = pair at inverse
          simpa only [swap_oracle_labels_list_equiv_apply,
            swap_oracle_labels_list_equiv_symm_apply] using inverse
        simpa [equivalence, inverseAfter] using changed.symm
    _ = uniformAverage (fun oldOracle : Input → DigestRegister =>
        uniformAverage (fun freshLabels : Environment → DigestRegister =>
          let final := swapOracleLabelsList keys indices
            (oldOracle, freshLabels)
          V8Smz9HonestWholeViewGames.run randomized program final.1
            (familyGameState family oldOracle))) :=
      V8Smz9HonestLeafBatch.uniform_average_product
        (A := Input → DigestRegister) (B := Environment → DigestRegister)
        (fun oldOracle freshLabels =>
          let final := swapOracleLabelsList keys indices (oldOracle, freshLabels)
          V8Smz9HonestWholeViewGames.run randomized program final.1
            (familyGameState family oldOracle))

/-- Final fixed-classical-branch bridge.  The left is the actual initialized
phase state, actual compressed swaps, CURRENT sequential reads, and a
syntactically label-blind continuation.  The right retains the original
oracle-indexed prior and runs on the literal full overlay. -/
theorem averaged_compressed_swaps_current_reads_eq_full_overlay
    {Tape : Type} [Fintype Tape] [Nonempty Tape]
    (count : Nat) (sites : Fin count → Environment)
    (siteDistinct : Function.Injective sites)
    (keys : Tape → Environment → FullInput)
    (keyDistinct : ∀ tapes,
      Function.Injective (fun i => keys tapes (sites i)))
    (family : OracleRegisterFamily
      (Input := FullInput) (Output := DigestRegister)
      (Phase := DigestRegister) (Workspace := Work))
    (next : Tape → (Fin count → DigestRegister) →
      Program FullInput Work) :
    uniformAverage (fun tapes : Tape =>
      phaseRun true
        (liftEnvironmentProgram
          (Environment := Environment → DigestRegister)
          (readCurrentAnswers count (fun i => keys tapes (sites i))
            (next tapes)))
        (compressedSwapList (keys tapes) (List.ofFn sites)
          (initializedPhaseFamily family))) =
      uniformAverage (fun tapes : Tape =>
        uniformAverage (fun oldOracle : FullInput → DigestRegister =>
          uniformAverage (fun freshLabels : Environment → DigestRegister =>
            let outputs := fun i => freshLabels (sites i)
            let overlay := updateRp05Batch count
              (fun i => keys tapes (sites i)) outputs oldOracle
            V8Smz9HonestWholeViewGames.run true (next tapes outputs) overlay
              (familyGameState family oldOracle)))) := by
  apply congrArg uniformAverage
  funext tapes
  rw [phase_run_compressed_swaps_as_forward_overlay true
    (keys tapes) (List.ofFn sites) family
    (readCurrentAnswers count (fun i => keys tapes (sites i)) (next tapes))]
  apply congrArg uniformAverage
  funext oldOracle
  apply congrArg uniformAverage
  funext freshLabels
  dsimp only
  let final := swapOracleLabelsList (keys tapes) (List.ofFn sites)
    (oldOracle, freshLabels)
  let outputs := fun i => freshLabels (sites i)
  let overlay := updateRp05Batch count
    (fun i => keys tapes (sites i)) outputs oldOracle
  have finalOracle : final.1 = overlay := by
    exact swap_oracle_labels_list_first_is_update count (keys tapes) sites
      siteDistinct (keyDistinct tapes) oldOracle freshLabels
  rw [read_current_answers_execution]
  rw [finalOracle]
  congr 2
  funext i
  exact update_rp05_batch_at count (fun i => keys tapes (sites i)) outputs
    oldOracle (keyDistinct tapes) i

/-- The actual oracle-family state on one unnormalised outcome of a complete
instrument.  No branch is renormalised and the branch map may depend on the
entire pre-existing public/adversary workspace. -/
def instrumentBranchFamily {branchCount : Nat}
    (operation : Instrument Input Work branchCount)
    (branch : Fin branchCount)
    (family : OracleRegisterFamily
      (Input := Input) (Output := DigestRegister)
      (Phase := DigestRegister) (Workspace := Work)) :
    OracleRegisterFamily
      (Input := Input) (Output := DigestRegister)
      (Phase := DigestRegister) (Workspace := Work) :=
  fun oracle register =>
    operation.branch branch (familyGameState family oracle) register

omit [DecidableEq Input] [DecidableEq Work] in
@[simp]
theorem family_game_state_instrumentBranchFamily {branchCount : Nat}
    (operation : Instrument Input Work branchCount)
    (branch : Fin branchCount)
    (family : OracleRegisterFamily
      (Input := Input) (Output := DigestRegister)
      (Phase := DigestRegister) (Workspace := Work))
    (oracle : Input → DigestRegister) :
    familyGameState (instrumentBranchFamily operation branch family) oracle =
      operation.branch branch (familyGameState family oracle) := by
  ext basis
  rfl

/-- Complete measured-branch lift of the fixed-branch overlay identity.
Every outcome keeps its own unnormalised instrument state, tape-dependent key
family, selected sites and continuation.  The branch is summed, not sampled
uniformly, and no key/state independence is assumed. -/
theorem instrument_branch_sum_compressed_swaps_current_reads_eq_full_overlay
    {Tape : Type} [Fintype Tape] [Nonempty Tape]
    {branchCount : Nat}
    (operation : Instrument FullInput Work branchCount)
    (family : OracleRegisterFamily
      (Input := FullInput) (Output := DigestRegister)
      (Phase := DigestRegister) (Workspace := Work))
    (count : Fin branchCount → Nat)
    (sites : (branch : Fin branchCount) →
      Fin (count branch) → Environment)
    (siteDistinct : ∀ branch, Function.Injective (sites branch))
    (keys : Fin branchCount → Tape → Environment → FullInput)
    (keyDistinct : ∀ branch tapes,
      Function.Injective (fun i => keys branch tapes (sites branch i)))
    (next : (branch : Fin branchCount) → Tape →
      (Fin (count branch) → DigestRegister) → Program FullInput Work) :
    (∑ branch : Fin branchCount,
      uniformAverage (fun tapes : Tape =>
        phaseRun true
          (liftEnvironmentProgram
            (Environment := Environment → DigestRegister)
            (readCurrentAnswers (count branch)
              (fun i => keys branch tapes (sites branch i))
              (next branch tapes)))
          (compressedSwapList (keys branch tapes)
            (List.ofFn (sites branch))
            (initializedPhaseFamily
              (instrumentBranchFamily operation branch family))))) =
      ∑ branch : Fin branchCount,
        uniformAverage (fun tapes : Tape =>
          uniformAverage (fun oldOracle : FullInput → DigestRegister =>
            uniformAverage
              (fun freshLabels : Environment → DigestRegister =>
                let outputs := fun i => freshLabels (sites branch i)
                let overlay := updateRp05Batch (count branch)
                  (fun i => keys branch tapes (sites branch i))
                  outputs oldOracle
                V8Smz9HonestWholeViewGames.run true
                  (next branch tapes outputs) overlay
                  (operation.branch branch
                    (familyGameState family oldOracle))))) := by
  apply Finset.sum_congr rfl
  intro branch _
  rw [averaged_compressed_swaps_current_reads_eq_full_overlay
    (count branch) (sites branch) (siteDistinct branch)
    (keys branch) (keyDistinct branch)
    (instrumentBranchFamily operation branch family) (next branch)]
  apply congrArg uniformAverage
  funext tapes
  apply congrArg uniformAverage
  funext oldOracle
  apply congrArg uniformAverage
  funext freshLabels
  rw [family_game_state_instrumentBranchFamily]

/-- Quadratic homogeneity of a comparison bound.  Rescaling both branch
states by the same amplitude scales their probability difference by its
squared norm, not its norm.  With `scalar = sqrt(m)` this is the required
`m * delta` branch weight. -/
theorem run_difference_smul_bound
    (randomized : Bool) (leftProgram rightProgram : Program Input Work)
    (leftOracle rightOracle : Input → DigestRegister)
    (leftState rightState : GameState (Input := Input) (Work := Work))
    (scalar : ℂ) (delta : ℝ)
    (bound :
      |V8Smz9HonestWholeViewGames.run randomized leftProgram leftOracle leftState -
        V8Smz9HonestWholeViewGames.run randomized rightProgram rightOracle rightState| ≤
        delta) :
    |V8Smz9HonestWholeViewGames.run randomized leftProgram leftOracle
        (scalar • leftState) -
      V8Smz9HonestWholeViewGames.run randomized rightProgram rightOracle
        (scalar • rightState)| ≤
      Complex.normSq scalar * delta := by
  rw [run_smul, run_smul, ← mul_sub, abs_mul,
    abs_of_nonneg (Complex.normSq_nonneg scalar)]
  exact mul_le_mul_of_nonneg_left bound (Complex.normSq_nonneg scalar)

/-- Finite unnormalised branch aggregation.  There is no Cauchy--Schwarz or
square-root branch-count loss: each normalized comparison is weighted by its
actual quadratic branch mass. -/
theorem sum_run_difference_smul_bound
    {branchCount : Nat}
    (randomized : Bool)
    (leftProgram rightProgram : Fin branchCount → Program Input Work)
    (leftOracle rightOracle : Fin branchCount → Input → DigestRegister)
    (leftState rightState : Fin branchCount →
      GameState (Input := Input) (Work := Work))
    (scalar : Fin branchCount → ℂ) (delta : Fin branchCount → ℝ)
    (bound : ∀ branch,
      |V8Smz9HonestWholeViewGames.run randomized (leftProgram branch)
          (leftOracle branch) (leftState branch) -
        V8Smz9HonestWholeViewGames.run randomized (rightProgram branch)
          (rightOracle branch) (rightState branch)| ≤ delta branch) :
    |(∑ branch,
        V8Smz9HonestWholeViewGames.run randomized (leftProgram branch)
          (leftOracle branch) (scalar branch • leftState branch)) -
      (∑ branch,
        V8Smz9HonestWholeViewGames.run randomized (rightProgram branch)
          (rightOracle branch) (scalar branch • rightState branch))| ≤
      ∑ branch, Complex.normSq (scalar branch) * delta branch := by
  rw [← Finset.sum_sub_distrib]
  exact (Finset.abs_sum_le_sum_abs _ _).trans
    (Finset.sum_le_sum fun branch _ =>
      run_difference_smul_bound randomized
        (leftProgram branch) (rightProgram branch)
        (leftOracle branch) (rightOracle branch)
        (leftState branch) (rightState branch)
        (scalar branch) (delta branch) (bound branch))

/-- A normalized fixed-branch comparison lifts through a complete measured
instrument with no branch-count loss.  Each unnormalised branch is charged by
its Born mass, and `Instrument.complete` sums those masses back to the norm of
the incoming state.  This includes zero-mass branches because the homogeneous
all-state lifting lemma handles the zero vector directly. -/
theorem complete_instrument_quadratic_comparison
    {branchCount : Nat} (operation : Instrument Input Work branchCount)
    (left right : Fin branchCount →
      GameState (Input := Input) (Work := Work) → ℝ)
    (leftHomogeneous : ∀ branch, QuadraticallyHomogeneous (left branch))
    (rightHomogeneous : ∀ branch, QuadraticallyHomogeneous (right branch))
    (delta : ℝ)
    (normalizedBound : ∀ branch state, ‖state‖ = 1 →
      |left branch state - right branch state| ≤ delta)
    (state : GameState (Input := Input) (Work := Work)) :
    |∑ branch, left branch (operation.branch branch state) -
        ∑ branch, right branch (operation.branch branch state)| ≤
      delta * ‖state‖ ^ 2 := by
  rw [← Finset.sum_sub_distrib]
  calc
    _ ≤ ∑ branch,
        |left branch (operation.branch branch state) -
          right branch (operation.branch branch state)| :=
      Finset.abs_sum_le_sum_abs _ _
    _ ≤ ∑ branch, delta * ‖operation.branch branch state‖ ^ 2 := by
      apply Finset.sum_le_sum
      intro branch _
      exact normalized_comparison_lifts_to_all_states
        (left branch) (right branch) (leftHomogeneous branch)
        (rightHomogeneous branch) delta (normalizedBound branch)
        (operation.branch branch state)
    _ = delta * ‖state‖ ^ 2 := by
      rw [← Finset.mul_sum, operation.complete]

/-- Evaluation of one raw swap on a complete named database.  The inverse
pair is the same transposition: the selected final database value becomes the
old saved label and the selected final label becomes the old oracle value. -/
theorem indexed_raw_swap_uniform_family_at_total
    (key : Input) (index : Environment)
    (family : OracleRegisterFamily
      (Input := Input) (Output := DigestRegister)
      (Phase := DigestRegister) (Workspace := Work))
    (oracle : Input → DigestRegister)
    (registerInput : Input) (phase : DigestRegister)
    (labels : Environment → DigestRegister) (work : Work) :
    indexedRawSwap key index
        (totalOracleFamilyState (uniformEnvironmentFamily family))
        { input := registerInput
          phase := phase
          workspace := (labels, work)
          database := totalDatabase oracle } =
    totalOracleFamilyState (inverseIndexedSwapFamily key index family)
        { input := registerInput
          phase := phase
          workspace := (labels, work)
          database := totalDatabase oracle } := by
  rw [indexed_raw_swap_environment_family_at_total key index
    (uniformEnvironmentFamily family) oracle registerInput phase labels work]
  rfl

end EnvironmentExecution
end
end HegemonCrypto.SmallWood.Q38Rp05ExecutionBridge
