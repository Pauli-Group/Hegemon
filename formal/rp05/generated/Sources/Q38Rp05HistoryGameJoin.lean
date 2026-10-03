import Q38Rp05RetainedKernelJoin
import Q38Rp05HistoryFreshBound

/-! Same-family history P7 to complete-request P8/P9/P10 join.
Source only; no kernel-validation claim is made. -/
namespace HegemonCrypto.SmallWood.Q38Rp05HistoryGameJoin

open HegemonCrypto.CanonicalBytes
open HegemonCrypto.CmsCompressedOracle
open HegemonCrypto.CmsOracleSimulation
open HegemonCrypto.CmsOracleDatabaseBridge
open HegemonCrypto.CmsQuerySequence
open HegemonCrypto.SmallWood.V8Smz9HiddenLeafQrom
open HegemonCrypto.SmallWood.V8Smz9HiddenPatch
open HegemonCrypto.SmallWood.V8Smz9ZeroKnowledge
open HegemonCrypto.SmallWood.V8Smz9CurrentPrivacyGame
open HegemonCrypto.SmallWood.V8Smz9CurrentPrivacyComposition
open HegemonCrypto.SmallWood.V8Smz9EagerPrivacy
open HegemonCrypto.SmallWood.V8Smz9EagerOracleGame
open HegemonCrypto.SmallWood.V8Smz9HonestWholeViewGames
open HegemonCrypto.SmallWood.V8Smz9MeasuredRunContinuity
open HegemonCrypto.SmallWood.V8SmzaRemainingAlgebra
open HegemonCrypto.SmallWood.V8SmzaMathPrivacy (Targets)
open HegemonCrypto.SmallWood.V8SmzaControlledFreshSwap
open HegemonCrypto.SmallWood.V8SmzaCmsControlledSwap
open HegemonCrypto.SmallWood.Q38CmsInitializedResampling
open HegemonCrypto.SmallWood.Q38CmsAdaptiveWholeViewApplication
open HegemonCrypto.SmallWood.Q38CmsAdaptiveWholeViewBound (total_oracle_family_norm_squared)
open HegemonCrypto.SmallWood.Q38CmsPhaseDecodeIsometry
open HegemonCrypto.SmallWood.Q38WholeViewCmsSemantics
open HegemonCrypto.SmallWood.Q38Rp05RawInputPartition
open HegemonCrypto.SmallWood.Q38Rp05CurrentCompleteRequest
open HegemonCrypto.SmallWood.Q38Rp05CurrentAdaptiveOpening
open HegemonCrypto.SmallWood.Q38Rp05CurrentFreshBound
open HegemonCrypto.SmallWood.Q38Rp05HistoryFreshBound
open HegemonCrypto.SmallWood.Q38Rp05MeasuredInstrument
open HegemonCrypto.SmallWood.Q38Rp05ExecutionBridge
open HegemonCrypto.SmallWood.Q38Rp05MaskRecovery (rp05PackValues)
open HegemonCrypto.SmallWood.Q38Rp05RetainedKernelJoin
open HegemonCrypto.SmallWood.SmzaRp05CsrNormalization
open HegemonCrypto.SmallWood.SmzaRp05StatementNamespace
open HegemonCrypto.SmallWood.SmzaRp05RelationRefinement
open Hegemon.Transaction.Poseidon2V8RelationProgram
open scoped BigOperators Classical

noncomputable section
set_option autoImplicit false
set_option Elab.async false
set_option maxRecDepth 10000
set_option maxHeartbeats 2000000

local notation "Statement" => HegemonCrypto.SmallWood.SmzaRp05StatementNamespace.Statement
local notation "Byte" => HegemonCrypto.CanonicalBytes.Byte

variable {bound : Nat} {History Work : Type}
variable [Fintype History] [DecidableEq History]
variable [Fintype Work] [DecidableEq Work]

attribute [local instance] tailLeafIndexDecidableEq

local notation "OracleInput" => Rp05FullRawInput bound

def historyReached (history : History)
    (reached : ResponseCmsState OracleInput (History × Work)) :
    ResponseCmsState OracleInput (History × Work) :=
  fun basis => if basis.workspace.1 = history then reached basis else 0

omit [Fintype History] [Fintype Work] [DecidableEq Work] in
theorem history_reached_core (history : History)
    (reached : ResponseCmsState OracleInput (History × Work)) :
    coreOfCmsState (historyReached history reached) =
      historyCore history (coreOfCmsState reached) := rfl

theorem global_decompress_history_reached (history : History)
    (reached : ResponseCmsState OracleInput (History × Work)) :
    globalDecompress (historyReached history reached) =
      historyReached history (globalDecompress reached) := by
  have single (key : OracleInput) (state : ResponseCmsState OracleInput (History × Work)) :
      decompressAt key (historyReached history state) =
        historyReached history (decompressAt key state) := by
    funext basis
    rw [decompress_at_eq_sum_kernel]
    by_cases same : basis.workspace.1 = history
    · simp only [historyReached, same, if_true]
      exact (decompress_at_eq_sum_kernel key state basis).symm
    · simp [historyReached, same]
  have every (keys : List OracleInput) :
      decompressList keys (historyReached history reached) =
        historyReached history (decompressList keys reached) := by
    induction keys with
    | nil => rfl
    | cons key tail ih =>
      rw [decompress_list_cons, decompress_list_cons, ih, single]
  exact every _

theorem history_reached_decoded_support (history : History)
    (reached : ResponseCmsState OracleInput (History × Work))
    (supported : TotalDatabaseSupport (globalDecompress reached)) :
    TotalDatabaseSupport (phaseDecode (historyReached history reached)) := by
  apply total_database_support_response_fourier_inverse
  rw [global_decompress_history_reached]
  intro basis absent
  by_cases same : basis.workspace.1 = history
  · simpa only [historyReached, same, if_true] using supported basis absent
  · simp [historyReached, same]

def historyFamily (history : History)
    (reached : ResponseCmsState OracleInput (History × Work)) :
    OracleRegisterFamily (Input := OracleInput) (Output := DigestRegister)
      (Phase := DigestRegister) (Workspace := History × Work) :=
  canonicalTotalFamily (phaseDecode (historyReached history reached))

/-- This is the missing changed-side game identity. Each history is a
projection of the original reached state BEFORE tape-dependent swaps. The
family is not reconstructed from the already-swapped state. -/
theorem history_fresh_changed_eq_complete_request
    (largeEnough : 39162 ≤ bound)
    (dsl : History → RelationDsl) (statement : History → Statement)
    (values : History → WitnessPackingValues Goldilocks)
    (salt : History → SaltBytes)
    (widthBound : ∀ history, 5 * (dsl history).width (statement history) ≤ 2 ^ 24)
    (next : History → Except String (List Byte) → Program OracleInput (History × Work))
    (reached : ResponseCmsState OracleInput (History × Work))
    (supported : TotalDatabaseSupport (globalDecompress reached))
    (history : History) :
    historyFreshProbability true largeEnough dsl statement values salt widthBound
        next (coreOfCmsState reached) history =
      uniformAverage (fun oracle : OracleInput → DigestRegister =>
        run true (currentCompleteHonestRequest largeEnough (dsl history)
          (statement history) (values history) (salt history) (widthBound history)
          (next history)) oracle
          (familyGameState (historyFamily history reached) oracle)) := by
  have initialized := initialized_phase_family_of_same_reached
    (Index := LeafIndex) (historyReached history reached)
    (history_reached_decoded_support history reached supported)
  rw [history_reached_core] at initialized
  unfold historyFreshProbability
  simp only [if_true]
  rw [← initialized]
  exact current_fresh_changed_eq_complete_request largeEnough (dsl history)
    (statement history) (values history) (salt history) (widthBound history)
    (next history) (historyFamily history reached)

theorem history_family_mass_complete
    (reached : ResponseCmsState OracleInput (History × Work))
    (supported : TotalDatabaseSupport (globalDecompress reached)) :
    (∑ history : History,
      normSquared (totalOracleFamilyState (historyFamily history reached))) =
      normSquared reached := by
  have each (history : History) :
      normSquared (totalOracleFamilyState (historyFamily history reached)) =
      ∑ basis, ‖historyCore history (coreOfCmsState reached) basis‖^2 := by
    unfold historyFamily
    rw [total_oracle_family_canonical_eq _
      (history_reached_decoded_support history reached supported),
      phase_decode_norm_squared]
    rw [← coreOfCmsState_mass (historyReached history reached), history_reached_core]
  simp_rw [each]
  rw [history_core_mass_complete, coreOfCmsState_mass]

theorem complete_request_family_vs_public_bound_mass
    (components : RelationProgramComponents)
    (nonlinearRoot : Fin 818 → Nat) (nodeDegree : Nat → Nat)
    (certificates : GeneratedCertificates
      (normalizedDsl components nonlinearRoot nodeDegree))
    (largeEnough : 39162 ≤ bound) (statement : Statement)
    (values : WitnessPackingValues Goldilocks) (salt : SaltBytes)
    (widthBound : 5 * (normalizedDsl components nonlinearRoot nodeDegree).width
      statement ≤ 2 ^ 24)
    (abortPoints : Fin 6 → Goldilocks)
    (abortAdmissible : Smz9WitnessInterpolationAdmissible abortPoints)
    (abortNonzero : ∀ index, abortPoints index ≠ 0)
    (abortTargets : Targets abortPoints)
    (family : OracleRegisterFamily (Input := OracleInput) (Output := DigestRegister)
      (Phase := DigestRegister) (Workspace := History × Work))
    (next : Except String (List Byte) → Program OracleInput (History × Work))
    (queries : Nat) (bounded : ∀ bytes, queryCount (next bytes) ≤ queries)
    (accepted : components.AcceptsPacked (currentPublicWords statement)
      (rp05PackValues values)) :
    |uniformAverage (fun oracle : OracleInput → DigestRegister =>
        run true (currentCompleteHonestRequest largeEnough
          (normalizedDsl components nonlinearRoot nodeDegree) statement values
          salt widthBound next) oracle (familyGameState family oracle)) -
      uniformAverage (fun oracle : OracleInput → DigestRegister =>
        publicSimulatorProbability largeEnough
          (normalizedDsl components nonlinearRoot nodeDegree) statement salt
          widthBound abortPoints oracle (familyGameState family oracle) next)| ≤
      (4 * (queries : ℝ) / (2 : ℝ)^256) *
        normSquared (totalOracleFamilyState family) := by
  rw [total_oracle_family_norm_squared]
  apply uniform_average_distance_le_mass
  intro oracle
  exact complete_request_vs_public_simulator_bound_mass components nonlinearRoot
    nodeDegree certificates largeEnough statement values salt widthBound abortPoints
    abortAdmissible abortNonzero abortTargets oracle (familyGameState family oracle)
    next queries bounded accepted

def historyPublicProbability
    (largeEnough : 39162 ≤ bound)
    (dsl : RelationDsl) (statement : History → Statement)
    (salt : History → SaltBytes)
    (widthBound : ∀ history, 5 * dsl.width (statement history) ≤ 2 ^ 24)
    (abortPoints : Fin 6 → Goldilocks)
    (next : History → Except String (List Byte) → Program OracleInput (History × Work))
    (reached : ResponseCmsState OracleInput (History × Work)) (history : History) : ℝ :=
  uniformAverage fun oracle : OracleInput → DigestRegister =>
    publicSimulatorProbability largeEnough dsl (statement history) (salt history)
      (widthBound history) abortPoints oracle
      (familyGameState (historyFamily history reached) oracle) (next history)

/-- A complete history-selected CURRENT request: ordinary current hash reads
versus the witness-free public simulator, on the same initialized real prefix.
All prior support, same-family identities, actual byte/overlay transport and
history weights are derived. No desired game inequality is a hypothesis.
This is the adjacent-request theorem used by a reverse-hybrid scheduler. -/
theorem current_history_real_vs_public_raw_run_bound
    (components : RelationProgramComponents)
    (nonlinearRoot : Fin 818 → Nat) (nodeDegree : Nat → Nat)
    (certificates : GeneratedCertificates
      (normalizedDsl components nonlinearRoot nodeDegree))
    (largeEnough : 39162 ≤ bound) (statement : History → Statement)
    (values : History → WitnessPackingValues Goldilocks) (salt : History → SaltBytes)
    (widthBound : ∀ history,
      5 * (normalizedDsl components nonlinearRoot nodeDegree).width
        (statement history) ≤ 2 ^ 24)
    (abortPoints : Fin 6 → Goldilocks)
    (abortAdmissible : Smz9WitnessInterpolationAdmissible abortPoints)
    (abortNonzero : ∀ index, abortPoints index ≠ 0)
    (abortTargets : Targets abortPoints)
    (next : History → Except String (List Byte) → Program OracleInput (History × Work))
    (continuationQueries : Nat)
    (continuationBound : ∀ history bytes,
      queryCount (next history bytes) ≤ continuationQueries)
    (accepted : ∀ history,
      components.AcceptsPacked (currentPublicWords (statement history))
        (rp05PackValues (values history)))
    (system : PhaseSystem DigestRegister DigestRegister)
    (queryBound : Nat)
    (steps : List (DatabaseIndependentContraction
      (Input := OracleInput) (Output := DigestRegister)
      (Phase := DigestRegister) (Workspace := History × Work)))
    (initialRegisters : RegisterBasis (Input := OracleInput)
      (Phase := DigestRegister) (Workspace := History × Work) → ℂ)
    (capacity : steps.length ≤ queryBound) :
    let dsl := normalizedDsl components nonlinearRoot nodeDegree
    let reached := rawRun system queryBound
      (steps.map DatabaseIndependentContraction.toDatabaseBlindContraction)
      (partialRandomOracleState (Output := DigestRegister) ∅ initialRegisters)
    |(∑ history : History,
        historyFreshProbability false largeEnough (fun _ => dsl) statement values
          salt widthBound next (coreOfCmsState reached) history) -
      (∑ history : History,
        historyPublicProbability largeEnough dsl statement salt widthBound abortPoints
          next reached history)| ≤
      ((2 * Real.sqrt (4 * (queryBound : ℝ) * (2 ^ 512 : ℝ)⁻¹)) +
        4 * (continuationQueries : ℝ) / (2 : ℝ)^256) * normSquared reached := by
  dsimp only
  let dsl := normalizedDsl components nonlinearRoot nodeDegree
  let reached : ResponseCmsState OracleInput (History × Work) :=
    rawRun system queryBound
      (steps.map DatabaseIndependentContraction.toDatabaseBlindContraction)
      (partialRandomOracleState (Output := DigestRegister) ∅ initialRegisters)
  have supported : TotalDatabaseSupport (globalDecompress reached) := by
    unfold reached
    rw [compressed_run_is_uniform_random_oracle_purification
      system queryBound steps initialRegisters capacity]
    exact total_oracle_family_has_total_database_support _
  let real := ∑ history : History,
    historyFreshProbability false largeEnough (fun _ => dsl) statement values salt
      widthBound next (coreOfCmsState reached) history
  let fresh := ∑ history : History,
    historyFreshProbability true largeEnough (fun _ => dsl) statement values salt
      widthBound next (coreOfCmsState reached) history
  let publicMass := ∑ history : History,
    historyPublicProbability largeEnough dsl statement salt widthBound abortPoints
      next reached history
  have freshBound : |real - fresh| ≤
      (2 * Real.sqrt (4 * (queryBound : ℝ) * (2 ^ 512 : ℝ)⁻¹)) *
        normSquared reached := by
    rw [abs_sub_comm]
    exact current_history_fresh_raw_run_bound largeEnough (fun _ => dsl)
      statement values salt widthBound next system queryBound steps initialRegisters
      capacity
  have retainedBound : |fresh - publicMass| ≤
      (4 * (continuationQueries : ℝ) / (2 : ℝ)^256) * normSquared reached := by
    change |(∑ history : History,
        historyFreshProbability true largeEnough (fun _ => dsl) statement values
          salt widthBound next (coreOfCmsState reached) history) -
      (∑ history : History,
        historyPublicProbability largeEnough dsl statement salt widthBound abortPoints
          next reached history)| ≤ _
    rw [← Finset.sum_sub_distrib]
    apply (Finset.abs_sum_le_sum_abs _ _).trans
    calc
      _ ≤ ∑ history : History,
          (4 * (continuationQueries : ℝ) / (2 : ℝ)^256) *
            normSquared (totalOracleFamilyState (historyFamily history reached)) := by
        apply Finset.sum_le_sum
        intro history _
        rw [history_fresh_changed_eq_complete_request largeEnough (fun _ => dsl)
          statement values salt widthBound next reached supported history]
        exact complete_request_family_vs_public_bound_mass components nonlinearRoot
          nodeDegree certificates largeEnough (statement history) (values history)
          (salt history) (widthBound history) abortPoints abortAdmissible abortNonzero
          abortTargets (historyFamily history reached) (next history)
          continuationQueries (continuationBound history) (accepted history)
      _ = _ := by
        rw [← Finset.mul_sum, history_family_mass_complete reached supported]
  change |real - publicMass| ≤ _
  calc
    _ ≤ |real - fresh| + |fresh - publicMass| := abs_sub_le _ _ _
    _ ≤ _ := add_le_add freshBound retainedBound
    _ = _ := by ring

end
end HegemonCrypto.SmallWood.Q38Rp05HistoryGameJoin
