import Q38Rp05CurrentTailDefinition
import Q38Rp05CurrentCompleteProgram
import Q38Rp05CurrentInitializedRequest
import Q38Rp05CurrentPhaseFamily
import Q38Rp05MeasuredInstrument

/-!
# Current complete-request FRESH comparison

The continuation in this file is literal: it measures all CURRENT RP05 leaf
answers and runs `currentRequestTail`, including DECS, response-indexed PIOP,
the final digest, both opening samplers, byte serialization and `next`.
The old overwritten labels remain a private environment throughout.

The endpoint averages the actual base/Q/D source coins. Its only initial
state hypotheses are an initialized query execution and its resource and
normalization conditions. There is no external reprogramming theorem or
desired probability inequality among its arguments. This is FRESH only;
selection feedback, public algebra transport and adaptive-request induction
must still be composed to obtain the full ZK experiment.
-/
namespace HegemonCrypto.SmallWood.Q38Rp05CurrentFreshBound

open HegemonCrypto.CanonicalBytes
open HegemonCrypto.CmsCompressedOracle
open HegemonCrypto.CmsOracleSimulation
open HegemonCrypto.CmsQuerySequence
open HegemonCrypto.SmallWood.V8Smz9HiddenLeafQrom
open HegemonCrypto.SmallWood.V8Smz9HiddenPatch
open HegemonCrypto.SmallWood.V8Smz9EagerPrivacy
open HegemonCrypto.SmallWood.V8Smz9EagerOracleGame
open HegemonCrypto.SmallWood.V8Smz9HonestWholeViewGames
open HegemonCrypto.SmallWood.V8Smz9RuntimeDistribution
open HegemonCrypto.SmallWood.V8Smz9CurrentPrivacyGame
open HegemonCrypto.SmallWood.V8Smz9CurrentPrivacyComposition
open HegemonCrypto.SmallWood.V8Smz9MeasuredRunContinuity
open HegemonCrypto.SmallWood.V8SmzaRemainingAlgebra
open HegemonCrypto.SmallWood.V8SmzaControlledFreshSwap
open HegemonCrypto.SmallWood.V8SmzaCmsControlledSwap
open HegemonCrypto.SmallWood.V8SmzaCmsIndexedSwap
open HegemonCrypto.SmallWood.Q38CmsResamplingCoordinates
open HegemonCrypto.SmallWood.Q38CmsInitializedResampling
open HegemonCrypto.SmallWood.Q38CmsAdaptiveWholeViewApplication
open HegemonCrypto.SmallWood.Q38CmsAdaptiveWholeViewBound
open HegemonCrypto.SmallWood.Q38WholeViewCmsSemantics
open HegemonCrypto.SmallWood.Q38Rp05LeafSupport
open HegemonCrypto.SmallWood.Q38ConcreteAdaptivePrivacy
open HegemonCrypto.SmallWood.Q38Rp05RawInputPartition
open HegemonCrypto.SmallWood.Q38Rp05ChronologicalAlgebra
open HegemonCrypto.SmallWood.Q38Rp05RequestCompiler
open HegemonCrypto.SmallWood.Q38Rp05OpenedOverlay
open HegemonCrypto.SmallWood.Q38Rp05ExecutionBridge
open HegemonCrypto.SmallWood.Q38Rp05MeasuredInstrument
open HegemonCrypto.SmallWood.Q38Rp05CurrentCompleteRequest
open HegemonCrypto.SmallWood.SmzaRp05StatementNamespace
open HegemonCrypto.SmallWood.SmzaRp05RelationRefinement
open scoped BigOperators Classical

noncomputable section
set_option autoImplicit false
set_option Elab.async false
set_option maxHeartbeats 2000000
set_option maxRecDepth 10000

variable {bound : Nat} {Branch Work : Type}
variable [Fintype Branch] [DecidableEq Branch]
variable [Fintype Work] [DecidableEq Work]

private def defaultLeafIndexDecidableEq : DecidableEq LeafIndex := inferInstance

attribute [local instance] tailLeafIndexDecidableEq
attribute [local irreducible] readCurrentAnswers updateRp05Batch
  compressedSwapList currentRequestTail liftEnvironmentProgram
  initializedPhaseFamily phaseRun uniformAverage
  V8Smz9HonestWholeViewGames.run

local notation "Statement" => HegemonCrypto.SmallWood.SmzaRp05StatementNamespace.Statement
local notation "Byte" => HegemonCrypto.CanonicalBytes.Byte
local notation "Rp05LeafInput" => HegemonCrypto.SmallWood.Q38Rp05LeafSupport.Rp05LeafInput
local notation "OracleInput" => Rp05FullRawInput bound
local notation "FullWork" => (LeafIndex → DigestRegister) × (Branch × Work)
local notation "FullCore" =>
  Core OracleInput Branch (OracleInput × DigestRegister × Work) DigestRegister

/-- Transport the complete checked bound through equality of the index
dictionary, instead of evaluating the concrete finite function enumeration. -/
private theorem fresh_bound_for_leaf_dictionary
    {Other : Type} [Fintype Other] [DecidableEq Other]
    (dec : DecidableEq LeafIndex)
    (preamble : Branch → Statement)
    (salt : Branch → Fin 32 → Byte)
    (data : Branch → LeafIndex → Fin 1176 → Byte)
    (indices : List LeafIndex)
    (core : Core (Rp05LeafInput ⊕ Other) Branch
      ((Rp05LeafInput ⊕ Other) × DigestRegister × Work) DigestRegister → ℂ)
    (queries : Nat) :
    letI : DecidableEq LeafIndex := dec
    ∀ (_bounded : BoundedState queries
        (initializedFreshState (Index := LeafIndex) core))
      (_coreSubnormalized : ∑ basis, ‖core basis‖ ^ 2 ≤ 1)
      (randomized : Bool)
      (program : (LeafIndex → LeafTape) → Program (Rp05LeafInput ⊕ Other)
        ((LeafIndex → DigestRegister) × (Branch × Work)))
      (_baseSupport : TotalDatabaseSupport (globalDecompress
        (initializedFreshState (Index := LeafIndex) core))),
      |uniformAverage (fun tapes : LeafIndex → LeafTape =>
          phaseRun randomized (program tapes)
            (controlledCompressed (rp05Selected preamble salt data tapes)
              indices (initializedFreshState core))) -
        uniformAverage (fun tapes : LeafIndex → LeafTape =>
          phaseRun randomized (program tapes)
            (initializedFreshState (Index := LeafIndex) core))| ≤
        2 * Real.sqrt (4 * (queries : ℝ) * (2 ^ 512 : ℝ)⁻¹) := by
  have same : dec = defaultLeafIndexDecidableEq := Subsingleton.elim _ _
  subst dec
  letI : DecidableEq LeafIndex := defaultLeafIndexDecidableEq
  intro bounded coreSubnormalized randomized program baseSupport
  exact rp05_initialized_dependent_phase_run_bound
    (Other := Other) (Branch := Branch) (BaseWork := Work)
    preamble salt data indices core queries bounded coreSubnormalized
    randomized program baseSupport

/-- The fixed-source-coin CURRENT readout and the complete current-profile
tail, with overwritten answers kept inaccessible in the environment. -/
def currentFreshContinuation
    (largeEnough : 39162 ≤ bound)
    (dsl : RelationDsl) (statement : Statement)
    (values : WitnessPackingValues Goldilocks)
    (salt : SaltBytes) (widthBound : 5 * dsl.width statement ≤ 2 ^ 24)
    (base : RemainingCoins Goldilocks) (masks : Q × D)
    (next : Except String (List Byte) → Program OracleInput (Branch × Work))
    (tapes : LeafIndex → LeafTape) : Program OracleInput FullWork :=
  liftEnvironmentProgram (Environment := LeafIndex → DigestRegister)
    (readCurrentAnswers 8388608
      (fun index => Sum.inl (rp05SourceLeafInput statement salt
        (q38PhysicalSuffix (currentHeads values base masks.1)
          base.2.2 masks.2 index) index (tapes index)))
      (fun labels => currentRequestTail largeEnough dsl statement values salt
        widthBound base masks tapes labels next))

/-- A fixed request may retain arbitrary earlier branch registers without
making its leaf addresses depend on those registers. The controlled swap
then equals the ordinary swap on the entire retained workspace. -/
theorem controlled_constant_current_keys
    (keys : LeafIndex → OracleInput) (indices : List LeafIndex)
    (state : ResponseCmsState OracleInput FullWork) :
    controlledCompressed (fun _ : Branch => keys) indices state =
      compressedSwapList keys indices state := by
  have sliced (branch : Branch) (current : ResponseCmsState OracleInput FullWork) :
      slice branch (compressedSwapList keys indices current) =
        compressedSwapList keys indices (slice branch current) := by
    induction indices generalizing current with
    | nil => simp only [compressedSwapList]
    | cons index tail ih =>
        simp only [compressedSwapList]
        rw [ih, slice_indexed_compressed]
  funext basis
  have pointwise := congrFun (sliced basis.workspace.2.1 state)
    { input := basis.input
      phase := basis.phase
      workspace := (basis.workspace.1, basis.workspace.2.2)
      database := basis.database }
  exact pointwise.symm

/-- The changed side is exactly the complete source request's fresh-input
game on the SAME old-oracle-indexed family. This rules out interpreting the
auxiliary overwritten-answer register as the fresh label readout. -/
theorem current_fresh_changed_eq_complete_request
    (largeEnough : 39162 ≤ bound)
    (dsl : RelationDsl) (statement : Statement)
    (values : WitnessPackingValues Goldilocks)
    (salt : SaltBytes) (widthBound : 5 * dsl.width statement ≤ 2 ^ 24)
    (next : Except String (List Byte) → Program OracleInput (Branch × Work))
    (family : OracleRegisterFamily (Input := OracleInput) (Output := DigestRegister)
      (Phase := DigestRegister) (Workspace := Branch × Work)) :
    uniformAverage (fun base : RemainingCoins Goldilocks =>
        uniformAverage (fun masks : Q × D =>
          uniformAverage (fun tapes : LeafIndex → LeafTape =>
            phaseRun true (currentFreshContinuation largeEnough dsl statement
              values salt widthBound base masks next tapes)
              (controlledCompressed
                (rp05Selected (fun _ : Branch => statement) (fun _ => salt)
                  (fun _ => q38PhysicalSuffix (currentHeads values base masks.1)
                    base.2.2 masks.2) tapes)
                (List.ofFn (id : Fin 8388608 → LeafIndex))
                (initializedPhaseFamily family))))) =
      uniformAverage (fun oracle : OracleInput → DigestRegister =>
        run true (currentCompleteHonestRequest largeEnough dsl statement values
          salt widthBound next) oracle (familyGameState family oracle)) := by
  have identity := current_initialized_request_oracle_average largeEnough dsl
    statement values salt widthBound next family
  have changed :
      ∀ (base : RemainingCoins Goldilocks) (masks : Q × D)
        (tapes : LeafIndex → LeafTape),
      controlledCompressed
          (rp05Selected (fun _ : Branch => statement) (fun _ => salt)
            (fun _ => q38PhysicalSuffix (currentHeads values base masks.1)
              base.2.2 masks.2) tapes)
          (List.ofFn (id : Fin 8388608 → LeafIndex))
          (initializedPhaseFamily family) =
        compressedSwapList
          (fun index => (Sum.inl (rp05SourceLeafInput statement salt
            (q38PhysicalSuffix (currentHeads values base masks.1)
              base.2.2 masks.2 index) index (tapes index)) : OracleInput))
          (List.ofFn (id : Fin 8388608 → LeafIndex))
          (initializedPhaseFamily family) := by
    intro base masks tapes
    exact controlled_constant_current_keys _ _ _
  simp_rw [changed]
  simpa only [currentFreshContinuation] using identity

/-- Derived initialized RP05 bound, specialized to the literal complete
request continuation rather than an arbitrary unidentified program. -/
theorem current_fresh_continuation_bound
    (largeEnough : 39162 ≤ bound)
    (dsl : RelationDsl) (statement : Statement)
    (values : WitnessPackingValues Goldilocks)
    (salt : SaltBytes) (widthBound : 5 * dsl.width statement ≤ 2 ^ 24)
    (base : RemainingCoins Goldilocks) (masks : Q × D)
    (next : Except String (List Byte) → Program OracleInput (Branch × Work))
    (system : PhaseSystem DigestRegister DigestRegister)
    (queryBound : Nat)
    (steps : List (DatabaseIndependentContraction
      (Input := OracleInput) (Output := DigestRegister)
      (Phase := DigestRegister) (Workspace := Branch × Work)))
    (initialRegisters : RegisterBasis (Input := OracleInput)
      (Phase := DigestRegister) (Workspace := Branch × Work) → ℂ)
    (capacity : steps.length ≤ queryBound)
    (initialSubnormalized : Subnormalized
      (partialRandomOracleState (Output := DigestRegister) ∅ initialRegisters)) :
    let reached := rawRun system queryBound
      (steps.map DatabaseIndependentContraction.toDatabaseBlindContraction)
      (partialRandomOracleState (Output := DigestRegister) ∅ initialRegisters)
    let initialized := initializedFreshState (Index := LeafIndex)
      (coreOfCmsState reached)
    |uniformAverage (fun tapes : LeafIndex → LeafTape =>
        phaseRun true (currentFreshContinuation largeEnough dsl statement
          values salt widthBound base masks next tapes)
          (controlledCompressed
            (rp05Selected (fun _ : Branch => statement) (fun _ => salt)
              (fun _ => q38PhysicalSuffix (currentHeads values base masks.1)
                base.2.2 masks.2) tapes)
            (List.ofFn (id : Fin 8388608 → LeafIndex)) initialized)) -
      uniformAverage (fun tapes : LeafIndex → LeafTape =>
        phaseRun true (currentFreshContinuation largeEnough dsl statement
          values salt widthBound base masks next tapes) initialized)| ≤
      2 * Real.sqrt (4 * (queryBound : ℝ) * (2 ^ 512 : ℝ)⁻¹) := by
  dsimp only
  let initial : ResponseCmsState OracleInput (Branch × Work) :=
    partialRandomOracleState (Output := DigestRegister) ∅ initialRegisters
  let blindSteps :=
    steps.map DatabaseIndependentContraction.toDatabaseBlindContraction
  let reached : ResponseCmsState OracleInput (Branch × Work) :=
    rawRun system queryBound blindSteps initial
  let core : FullCore → ℂ := coreOfCmsState reached
  have boundedInitial : BoundedState 0 initial := by
    exact partial_random_oracle_empty_bounded initialRegisters
  have capacityBlind : 0 + blindSteps.length ≤ queryBound := by
    simpa only [blindSteps, List.length_map, zero_add] using capacity
  have bounded : BoundedState queryBound
      (initializedFreshState (Index := LeafIndex) core) := by
    exact raw_run_initializedFreshState_bounded system queryBound blindSteps
      initial 0 capacityBlind boundedInitial
  have reachedSubnormalized : Subnormalized reached := by
    exact raw_run_subnormalized_of_bounded system queryBound blindSteps
      initial 0 capacityBlind boundedInitial initialSubnormalized
  have coreSubnormalized : (∑ basis : FullCore, ‖core basis‖ ^ 2) ≤ 1 := by
    rw [show (∑ basis : FullCore, ‖core basis‖ ^ 2) = normSquared reached by
      exact coreOfCmsState_mass reached]
    exact reachedSubnormalized
  have baseSupport : TotalDatabaseSupport (globalDecompress
      (initializedFreshState (Index := LeafIndex) core)) := by
    exact raw_run_initializedFreshState_total_support (Index := LeafIndex)
      system queryBound steps initialRegisters capacity
  exact fresh_bound_for_leaf_dictionary
    (Other := Rp05OtherRawInput bound) (Branch := Branch) (Work := Work)
    tailLeafIndexDecidableEq
    (fun _ : Branch => statement) (fun _ => salt)
    (fun _ => q38PhysicalSuffix (currentHeads values base masks.1)
      base.2.2 masks.2)
    (List.ofFn (id : Fin 8388608 → LeafIndex)) core queryBound bounded
    coreSubnormalized true
    (currentFreshContinuation largeEnough dsl statement values salt widthBound
      base masks next) baseSupport

/-- The source base and joint mask samplers do not multiply the FRESH loss.
Every sampled continuation uses the SAME reached state and persistent
database; its keys and continuation depend on the same source coins. -/
theorem current_complete_request_fresh_bound
    (largeEnough : 39162 ≤ bound)
    (dsl : RelationDsl) (statement : Statement)
    (values : WitnessPackingValues Goldilocks)
    (salt : SaltBytes) (widthBound : 5 * dsl.width statement ≤ 2 ^ 24)
    (next : Except String (List Byte) → Program OracleInput (Branch × Work))
    (system : PhaseSystem DigestRegister DigestRegister)
    (queryBound : Nat)
    (steps : List (DatabaseIndependentContraction
      (Input := OracleInput) (Output := DigestRegister)
      (Phase := DigestRegister) (Workspace := Branch × Work)))
    (initialRegisters : RegisterBasis (Input := OracleInput)
      (Phase := DigestRegister) (Workspace := Branch × Work) → ℂ)
    (capacity : steps.length ≤ queryBound)
    (initialSubnormalized : Subnormalized
      (partialRandomOracleState (Output := DigestRegister) ∅ initialRegisters)) :
    let reached := rawRun system queryBound
      (steps.map DatabaseIndependentContraction.toDatabaseBlindContraction)
      (partialRandomOracleState (Output := DigestRegister) ∅ initialRegisters)
    let initialized := initializedFreshState (Index := LeafIndex)
      (coreOfCmsState reached)
    |uniformAverage (fun base : RemainingCoins Goldilocks =>
        uniformAverage (fun masks : Q × D =>
          uniformAverage (fun tapes : LeafIndex → LeafTape =>
            phaseRun true (currentFreshContinuation largeEnough dsl statement
              values salt widthBound base masks next tapes)
              (controlledCompressed
                (rp05Selected (fun _ : Branch => statement) (fun _ => salt)
                  (fun _ => q38PhysicalSuffix (currentHeads values base masks.1)
                    base.2.2 masks.2) tapes)
                (List.ofFn (id : Fin 8388608 → LeafIndex)) initialized)))) -
      uniformAverage (fun base : RemainingCoins Goldilocks =>
        uniformAverage (fun masks : Q × D =>
          uniformAverage (fun tapes : LeafIndex → LeafTape =>
            phaseRun true (currentFreshContinuation largeEnough dsl statement
              values salt widthBound base masks next tapes) initialized)))| ≤
      2 * Real.sqrt (4 * (queryBound : ℝ) * (2 ^ 512 : ℝ)⁻¹) := by
  dsimp only
  apply (average_difference_abs_le _ _).trans
  apply (average_mono _ _ fun base => ?_).trans_eq
    (uniform_average_const _)
  apply (average_difference_abs_le _ _).trans
  apply (average_mono _ _ fun masks => ?_).trans_eq
    (uniform_average_const _)
  exact current_fresh_continuation_bound largeEnough dsl statement values
    salt widthBound base masks next system queryBound steps initialRegisters
    capacity initialSubnormalized

/-- FRESH for the literal complete current request. The left side is its
fresh-input source game; the right measures honest CURRENT leaf answers and
then executes exactly the same full byte-producing tail. Both games retain
the same pre-request oracle family and arbitrary future `next` program.
All family support and normalization obligations are derived below. -/
theorem current_complete_source_fresh_vs_current_reads
    (largeEnough : 39162 ≤ bound)
    (dsl : RelationDsl) (statement : Statement)
    (values : WitnessPackingValues Goldilocks)
    (salt : SaltBytes) (widthBound : 5 * dsl.width statement ≤ 2 ^ 24)
    (next : Except String (List Byte) → Program OracleInput (Branch × Work))
    (system : PhaseSystem DigestRegister DigestRegister)
    (queryBound : Nat)
    (steps : List (DatabaseIndependentContraction
      (Input := OracleInput) (Output := DigestRegister)
      (Phase := DigestRegister) (Workspace := Branch × Work)))
    (initialRegisters : RegisterBasis (Input := OracleInput)
      (Phase := DigestRegister) (Workspace := Branch × Work) → ℂ)
    (capacity : steps.length ≤ queryBound)
    (initialSubnormalized : Subnormalized
      (partialRandomOracleState (Output := DigestRegister) ∅ initialRegisters)) :
    let reached := rawRun system queryBound
      (steps.map DatabaseIndependentContraction.toDatabaseBlindContraction)
      (partialRandomOracleState (Output := DigestRegister) ∅ initialRegisters)
    let family := canonicalTotalFamily (phaseDecode reached)
    |phaseRun true
        (currentCompleteHonestRequest largeEnough dsl statement values salt
          widthBound next) (phaseEncode (totalOracleFamilyState family)) -
      uniformAverage (fun base : RemainingCoins Goldilocks =>
        uniformAverage (fun masks : Q × D =>
          uniformAverage (fun tapes : LeafIndex → LeafTape =>
            phaseRun true (currentFreshContinuation largeEnough dsl statement
              values salt widthBound base masks next tapes)
              (initializedPhaseFamily family))))| ≤
      2 * Real.sqrt (4 * (queryBound : ℝ) * (2 ^ 512 : ℝ)⁻¹) := by
  dsimp only
  let reached : ResponseCmsState OracleInput (Branch × Work) :=
    rawRun system queryBound
      (steps.map DatabaseIndependentContraction.toDatabaseBlindContraction)
      (partialRandomOracleState (Output := DigestRegister) ∅ initialRegisters)
  let family := canonicalTotalFamily (phaseDecode reached)
  have total : TotalDatabaseSupport (globalDecompress reached) := by
    unfold reached
    rw [compressed_run_is_uniform_random_oracle_purification
      system queryBound steps initialRegisters capacity]
    exact total_oracle_family_has_total_database_support _
  have decodedTotal : TotalDatabaseSupport (phaseDecode reached) := by
    exact total_database_support_response_fourier_inverse _ total
  have align : initializedPhaseFamily (Environment := LeafIndex) family =
      initializedFreshState (Index := LeafIndex) (coreOfCmsState reached) :=
    initialized_phase_family_of_same_reached reached decodedTotal
  have comparison := current_complete_request_fresh_bound largeEnough dsl
    statement values salt widthBound next system queryBound steps
    initialRegisters capacity initialSubnormalized
  change |(_ : ℝ) - _| ≤ _ at comparison
  rw [← align] at comparison
  rw [current_fresh_changed_eq_complete_request largeEnough dsl statement
    values salt widthBound next family] at comparison
  rw [current_complete_request_phase_run_family largeEnough dsl statement
    values salt widthBound next family]
  exact comparison

end
end HegemonCrypto.SmallWood.Q38Rp05CurrentFreshBound
