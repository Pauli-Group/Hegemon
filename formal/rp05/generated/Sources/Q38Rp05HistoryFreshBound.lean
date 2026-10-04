import Q38Rp05CurrentFreshMassBound

/-!
# FRESH for history-selected complete RP05 continuations

Histories are the pre-existing classical workspace register of one reached
core. Projection retains the same database and every other register. The
source request parameters and byte-indexed future program may depend on that
history; no normalized-history execution or per-history probability estimate
is supplied as a hypothesis.
-/
namespace HegemonCrypto.SmallWood.Q38Rp05HistoryFreshBound

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
open HegemonCrypto.SmallWood.Q38CmsInitializedResampling
open HegemonCrypto.SmallWood.Q38CmsAdaptiveWholeViewApplication
open HegemonCrypto.SmallWood.Q38WholeViewCmsSemantics
open HegemonCrypto.SmallWood.Q38ConcreteAdaptivePrivacy
open HegemonCrypto.SmallWood.Q38Rp05LeafSupport
open HegemonCrypto.SmallWood.Q38Rp05RawInputPartition
open HegemonCrypto.SmallWood.Q38Rp05ChronologicalAlgebra
open HegemonCrypto.SmallWood.Q38Rp05OpenedOverlay
open HegemonCrypto.SmallWood.Q38Rp05CurrentFreshBound
open HegemonCrypto.SmallWood.Q38Rp05CurrentFreshMassBound
open HegemonCrypto.SmallWood.Q38Rp05CurrentCompleteRequest (tailLeafIndexDecidableEq)
open HegemonCrypto.SmallWood.SmzaRp05StatementNamespace
open HegemonCrypto.SmallWood.SmzaRp05RelationRefinement
open scoped BigOperators Classical

noncomputable section
set_option autoImplicit false
set_option Elab.async false
set_option maxHeartbeats 2000000
set_option maxRecDepth 10000

variable {bound : Nat} {History Work : Type}
variable [Fintype History] [DecidableEq History]
variable [Fintype Work] [DecidableEq Work]

private def defaultLeafIndexDecidableEq : DecidableEq LeafIndex := inferInstance
attribute [local instance] tailLeafIndexDecidableEq

local notation "Statement" => HegemonCrypto.SmallWood.SmzaRp05StatementNamespace.Statement
local notation "Byte" => HegemonCrypto.CanonicalBytes.Byte
local notation "OracleInput" => Rp05FullRawInput bound
local notation "FullWork" => (LeafIndex → DigestRegister) × (History × Work)
local notation "FullCore" =>
  Core OracleInput History (OracleInput × DigestRegister × Work) DigestRegister

/-- Equality of the finite index dictionaries transports the entire
homogeneous bound, without enumerating the concrete tape-function space. -/
private theorem history_fresh_mass_for_leaf_dictionary
    {Other : Type} [Fintype Other] [DecidableEq Other]
    (dec : DecidableEq LeafIndex)
    (preamble : History → Statement)
    (salt : History → Fin 32 → Byte)
    (data : History → LeafIndex → Fin 1176 → Byte)
    (indices : List LeafIndex)
    (core : Core (Rp05LeafInput ⊕ Other) History
      ((Rp05LeafInput ⊕ Other) × DigestRegister × Work) DigestRegister → ℂ)
    (queries : Nat) :
    letI : DecidableEq LeafIndex := dec
    ∀ (_bounded : BoundedState queries
        (initializedFreshState (Index := LeafIndex) core))
      (randomized : Bool)
      (program : (LeafIndex → LeafTape) → Program (Rp05LeafInput ⊕ Other)
        ((LeafIndex → DigestRegister) × (History × Work)))
      (_baseSupport : TotalDatabaseSupport (globalDecompress
        (initializedFreshState (Index := LeafIndex) core))),
      |uniformAverage (fun tapes : LeafIndex → LeafTape =>
          phaseRun randomized (program tapes)
            (controlledCompressed (rp05Selected preamble salt data tapes)
              indices (initializedFreshState core))) -
        uniformAverage (fun tapes : LeafIndex → LeafTape =>
          phaseRun randomized (program tapes)
            (initializedFreshState (Index := LeafIndex) core))| ≤
        (2 * Real.sqrt (4 * (queries : ℝ) * (2 ^ 512 : ℝ)⁻¹)) *
          ∑ basis, ‖core basis‖ ^ 2 := by
  have same : dec = defaultLeafIndexDecidableEq := Subsingleton.elim _ _
  subst dec
  letI : DecidableEq LeafIndex := defaultLeafIndexDecidableEq
  intro bounded randomized program baseSupport
  exact rp05_initialized_dependent_phase_run_bound_mass
    (Other := Other) (Branch := History) (Work := Work)
    preamble salt data indices core queries bounded randomized program baseSupport

/-- Orthogonal projection onto an existing history value. No oracle entry
or surviving amplitude is changed. -/
def historyCore (history : History) (core : FullCore → ℂ) : FullCore → ℂ :=
  fun basis => if basis.1 = history then core basis else 0

def historyState (history : History)
    (state : ResponseCmsState OracleInput FullWork) :
    ResponseCmsState OracleInput FullWork :=
  fun basis => if basis.workspace.2.1 = history then state basis else 0

omit [Fintype History] [Fintype Work] [DecidableEq Work] in
theorem initialized_history_core
    (history : History) (core : FullCore → ℂ) :
    initializedFreshState (Index := LeafIndex) (historyCore history core) =
      historyState history (initializedFreshState (Index := LeafIndex) core) := by
  funext basis
  by_cases same : basis.workspace.2.1 = history <;>
    simp only [initializedFreshState, historyCore, historyState, same,
      if_true, if_false, zero_mul]

/-- Database decompression commutes with classical-history projection. The
matrix action changes only database cells, not the measured history. -/
theorem decompress_at_history_state
    (key : OracleInput) (history : History)
    (state : ResponseCmsState OracleInput FullWork) :
    decompressAt key (historyState history state) =
      historyState history (decompressAt key state) := by
  funext basis
  rw [decompress_at_eq_sum_kernel]
  by_cases same : basis.workspace.2.1 = history
  · simp only [historyState, same, if_true]
    exact (decompress_at_eq_sum_kernel key state basis).symm
  · simp [historyState, same]

theorem global_decompress_history_state
    (history : History) (state : ResponseCmsState OracleInput FullWork) :
    globalDecompress (historyState history state) =
      historyState history (globalDecompress state) := by
  have everyList (keys : List OracleInput) :
      decompressList keys (historyState history state) =
        historyState history (decompressList keys state) := by
    induction keys with
    | nil => rfl
    | cons key tail ih =>
        rw [decompress_list_cons, decompress_list_cons, ih,
          decompress_at_history_state]
  exact everyList _

omit [Fintype History] [Fintype Work] [DecidableEq Work] in
theorem history_state_bounded
    (history : History) (state : ResponseCmsState OracleInput FullWork)
    (queries : Nat) (bounded : BoundedState queries state) :
    BoundedState queries (historyState history state) := by
  unfold BoundedState
  funext basis
  have original := congrFun bounded basis
  by_cases same : basis.workspace.2.1 = history
  · simpa only [HegemonCrypto.CmsCompressedOracle.project, historyState,
      same, if_true] using original
  · simp only [HegemonCrypto.CmsCompressedOracle.project, historyState,
      same, if_false, ite_self]

omit [Fintype History] [Fintype Work] [DecidableEq Work] in
theorem history_core_bounded
    (history : History) (core : FullCore → ℂ) (queries : Nat)
    (bounded : BoundedState queries
      (initializedFreshState (Index := LeafIndex) core)) :
    BoundedState queries
      (initializedFreshState (Index := LeafIndex) (historyCore history core)) := by
  rw [initialized_history_core]
  exact history_state_bounded history _ queries bounded

theorem history_core_total_support
    (history : History) (core : FullCore → ℂ)
    (supported : TotalDatabaseSupport (globalDecompress
      (initializedFreshState (Index := LeafIndex) core))) :
    TotalDatabaseSupport (globalDecompress
      (initializedFreshState (Index := LeafIndex) (historyCore history core))) := by
  rw [initialized_history_core, global_decompress_history_state]
  intro basis absent
  by_cases same : basis.workspace.2.1 = history
  · simp only [historyState, same, if_true]
    exact supported basis absent
  · simp [historyState, same]

omit [DecidableEq Work] in
/-- The finite history measurement is complete on the original core. There
is no count of histories and no division by a history probability. -/
theorem history_core_mass_complete (core : FullCore → ℂ) :
    (∑ history : History, ∑ basis : FullCore,
      ‖historyCore history core basis‖^2) =
      ∑ basis : FullCore, ‖core basis‖^2 := by
  rw [Finset.sum_comm]
  apply Finset.sum_congr rfl
  intro basis _
  simp only [historyCore, apply_ite, norm_zero, ite_pow, zero_pow (by decide : 2 ≠ 0),
    Finset.sum_ite_eq, Finset.mem_univ, if_true]

/-- Probability mass of the literal complete continuation on one actual
history. `swapped=true` is the independent-label overlay side; false is the
ordinary CURRENT-leaf-read side. All history-specific source coins retain
their exact uniform law. -/
def historyFreshProbability
    (swapped : Bool) (largeEnough : 39162 ≤ bound)
    (dsl : History → RelationDsl) (statement : History → Statement)
    (values : History → WitnessPackingValues Goldilocks)
    (salt : History → SaltBytes)
    (widthBound : ∀ history, 5 * (dsl history).width (statement history) ≤ 2 ^ 24)
    (next : History → Except String (List Byte) → Program OracleInput (History × Work))
    (core : FullCore → ℂ) (history : History) : ℝ :=
  uniformAverage fun base : RemainingCoins Goldilocks =>
    uniformAverage fun masks : Q × D =>
      uniformAverage fun tapes : LeafIndex → LeafTape =>
        let initialized := initializedFreshState (Index := LeafIndex)
          (historyCore history core)
        let current := if swapped then
          controlledCompressed
            (rp05Selected (fun _ : History => statement history)
              (fun _ => salt history)
              (fun _ => q38PhysicalSuffix (currentHeads (values history) base masks.1)
                base.2.2 masks.2) tapes)
            (List.ofFn (id : Fin 8388608 → LeafIndex)) initialized
          else initialized
        phaseRun true
          (currentFreshContinuation largeEnough (dsl history) (statement history)
            (values history) (salt history) (widthBound history) base masks
            (next history) tapes) current

/-- The current request may depend on every already-observed history. The
derived bound pays its original Born mass, including aborted/zero branches.
No game-distance premise or normalized-history reachability is needed. -/
theorem current_history_fresh_branch_bound
    (largeEnough : 39162 ≤ bound)
    (dsl : History → RelationDsl) (statement : History → Statement)
    (values : History → WitnessPackingValues Goldilocks)
    (salt : History → SaltBytes)
    (widthBound : ∀ history, 5 * (dsl history).width (statement history) ≤ 2 ^ 24)
    (next : History → Except String (List Byte) → Program OracleInput (History × Work))
    (core : FullCore → ℂ) (queries : Nat)
    (bounded : BoundedState queries (initializedFreshState (Index := LeafIndex) core))
    (supported : TotalDatabaseSupport (globalDecompress
      (initializedFreshState (Index := LeafIndex) core)))
    (history : History) :
    |historyFreshProbability true largeEnough dsl statement values salt widthBound
        next core history -
      historyFreshProbability false largeEnough dsl statement values salt widthBound
        next core history| ≤
      (2 * Real.sqrt (4 * (queries : ℝ) * (2 ^ 512 : ℝ)⁻¹)) *
        ∑ basis : FullCore, ‖historyCore history core basis‖^2 := by
  unfold historyFreshProbability
  simp only [if_true, Bool.false_eq_true, if_false]
  apply (average_difference_abs_le _ _).trans
  apply (average_mono _ _ fun base => ?_).trans_eq (uniform_average_const _)
  apply (average_difference_abs_le _ _).trans
  apply (average_mono _ _ fun masks => ?_).trans_eq (uniform_average_const _)
  exact history_fresh_mass_for_leaf_dictionary
    (Other := Rp05OtherRawInput bound) (History := History) (Work := Work)
    tailLeafIndexDecidableEq
    (fun _ : History => statement history) (fun _ => salt history)
    (fun _ => q38PhysicalSuffix (currentHeads (values history) base masks.1)
      base.2.2 masks.2)
    (List.ofFn (id : Fin 8388608 → LeafIndex)) (historyCore history core) queries
    (history_core_bounded history core queries bounded) true
    (currentFreshContinuation largeEnough (dsl history) (statement history)
      (values history) (salt history) (widthBound history) base masks (next history))
    (history_core_total_support history core supported)

/-- One full history-selected FRESH hop costs delta times the original
incoming mass. Every statement/witness choice and both literal complete
continuations use projections of the SAME original core. -/
theorem current_history_fresh_bound
    (largeEnough : 39162 ≤ bound)
    (dsl : History → RelationDsl) (statement : History → Statement)
    (values : History → WitnessPackingValues Goldilocks)
    (salt : History → SaltBytes)
    (widthBound : ∀ history, 5 * (dsl history).width (statement history) ≤ 2 ^ 24)
    (next : History → Except String (List Byte) → Program OracleInput (History × Work))
    (core : FullCore → ℂ) (queries : Nat)
    (bounded : BoundedState queries (initializedFreshState (Index := LeafIndex) core))
    (supported : TotalDatabaseSupport (globalDecompress
      (initializedFreshState (Index := LeafIndex) core))) :
    |(∑ history : History,
        historyFreshProbability true largeEnough dsl statement values salt widthBound
          next core history) -
      (∑ history : History,
        historyFreshProbability false largeEnough dsl statement values salt widthBound
          next core history)| ≤
      (2 * Real.sqrt (4 * (queries : ℝ) * (2 ^ 512 : ℝ)⁻¹)) *
        ∑ basis : FullCore, ‖core basis‖^2 := by
  rw [← Finset.sum_sub_distrib]
  apply (Finset.abs_sum_le_sum_abs _ _).trans
  calc
    _ ≤ ∑ history : History,
        (2 * Real.sqrt (4 * (queries : ℝ) * (2 ^ 512 : ℝ)⁻¹)) *
          ∑ basis : FullCore, ‖historyCore history core basis‖^2 := by
      exact Finset.sum_le_sum fun history _ =>
        current_history_fresh_branch_bound largeEnough dsl statement values
          salt widthBound next core queries bounded supported history
    _ = _ := by rw [← Finset.mul_sum, history_core_mass_complete]

/-- Concrete real-prefix endpoint. The history register belongs to this one
initialized query execution. Its two support invariants are derived, and the
bound is charged against its actual reached mass with no normalization. -/
theorem current_history_fresh_raw_run_bound
    (largeEnough : 39162 ≤ bound)
    (dsl : History → RelationDsl) (statement : History → Statement)
    (values : History → WitnessPackingValues Goldilocks)
    (salt : History → SaltBytes)
    (widthBound : ∀ history, 5 * (dsl history).width (statement history) ≤ 2 ^ 24)
    (next : History → Except String (List Byte) → Program OracleInput (History × Work))
    (system : PhaseSystem DigestRegister DigestRegister)
    (queryBound : Nat)
    (steps : List (DatabaseIndependentContraction
      (Input := OracleInput) (Output := DigestRegister)
      (Phase := DigestRegister) (Workspace := History × Work)))
    (initialRegisters : RegisterBasis (Input := OracleInput)
      (Phase := DigestRegister) (Workspace := History × Work) → ℂ)
    (capacity : steps.length ≤ queryBound) :
    let reached := rawRun system queryBound
      (steps.map DatabaseIndependentContraction.toDatabaseBlindContraction)
      (partialRandomOracleState (Output := DigestRegister) ∅ initialRegisters)
    let core := coreOfCmsState reached
    |(∑ history : History,
        historyFreshProbability true largeEnough dsl statement values salt widthBound
          next core history) -
      (∑ history : History,
        historyFreshProbability false largeEnough dsl statement values salt widthBound
          next core history)| ≤
      (2 * Real.sqrt (4 * (queryBound : ℝ) * (2 ^ 512 : ℝ)⁻¹)) *
        normSquared reached := by
  dsimp only
  let initial : ResponseCmsState OracleInput (History × Work) :=
    partialRandomOracleState (Output := DigestRegister) ∅ initialRegisters
  let blindSteps :=
    steps.map DatabaseIndependentContraction.toDatabaseBlindContraction
  let reached : ResponseCmsState OracleInput (History × Work) :=
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
  have supported : TotalDatabaseSupport (globalDecompress
      (initializedFreshState (Index := LeafIndex) core)) := by
    exact raw_run_initializedFreshState_total_support (Index := LeafIndex)
      system queryBound steps initialRegisters capacity
  have comparison := current_history_fresh_bound largeEnough dsl statement
    values salt widthBound next core queryBound bounded supported
  have mass : (∑ basis : FullCore, ‖core basis‖^2) = normSquared reached :=
    coreOfCmsState_mass reached
  rw [mass] at comparison
  exact comparison

end
end HegemonCrypto.SmallWood.Q38Rp05HistoryFreshBound
