import Q38Rp05HistoryFreshBound
import Q38Rp05CurrentFixedOracle

/-! Real-side FRESH adapter. Empty swaps remove only the unused fresh-label
environment; CURRENT answers and the old-oracle-indexed prior are unchanged.
All results are source-only pending kernel validation. -/
namespace HegemonCrypto.SmallWood.Q38Rp05RealReadoutAdapter

open HegemonCrypto.CanonicalBytes
open HegemonCrypto.CmsCompressedOracle
open HegemonCrypto.CmsOracleSimulation
open HegemonCrypto.CmsQuerySequence
open HegemonCrypto.SmallWood.V8Smz9HiddenLeafQrom
open HegemonCrypto.SmallWood.V8Smz9HiddenPatch
open HegemonCrypto.SmallWood.V8Smz9EagerPrivacy
open HegemonCrypto.SmallWood.V8Smz9EagerOracleGame
open HegemonCrypto.SmallWood.V8Smz9HonestWholeViewGames
open HegemonCrypto.SmallWood.V8Smz9CurrentPrivacyGame
open HegemonCrypto.SmallWood.V8Smz9CurrentPrivacyComposition
open HegemonCrypto.SmallWood.V8SmzaRemainingAlgebra
open HegemonCrypto.SmallWood.V8SmzaCmsIndexedSwap
open HegemonCrypto.SmallWood.V8SmzaControlledFreshSwap
open HegemonCrypto.SmallWood.Q38CmsInitializedResampling
open HegemonCrypto.SmallWood.Q38CmsAdaptiveWholeViewApplication
open HegemonCrypto.SmallWood.Q38WholeViewCmsSemantics
open HegemonCrypto.SmallWood.Q38ConcreteAdaptivePrivacy
open HegemonCrypto.SmallWood.Q38Rp05LeafSupport
open HegemonCrypto.SmallWood.Q38Rp05RawInputPartition
open HegemonCrypto.SmallWood.Q38Rp05ChronologicalAlgebra
open HegemonCrypto.SmallWood.Q38Rp05OpenedOverlay
open HegemonCrypto.SmallWood.Q38Rp05ExecutionBridge
open HegemonCrypto.SmallWood.Q38Rp05CurrentCompleteRequest
open HegemonCrypto.SmallWood.Q38Rp05CurrentFreshBound
open HegemonCrypto.SmallWood.Q38Rp05HistoryFreshBound
open HegemonCrypto.SmallWood.SmzaRp05StatementNamespace
open HegemonCrypto.SmallWood.SmzaRp05RelationRefinement
open scoped BigOperators Classical

noncomputable section
set_option autoImplicit false
set_option Elab.async false
set_option maxHeartbeats 2000000

attribute [local irreducible] phaseRun initializedPhaseFamily
  uniformAverage liftEnvironmentProgram compressedSwapList swapOracleLabelsList
  V8Smz9HonestWholeViewGames.run

/-- Appending and privately retaining an unused uniform answer register has
exactly zero effect on any original-oracle program, including its future. -/
theorem phase_run_initialized_private_environment
    {Input Work Environment : Type}
    [Fintype Input] [DecidableEq Input] [Fintype Work] [DecidableEq Work]
    [Fintype Environment] [environmentDecidableEq : DecidableEq Environment]
    (randomized : Bool) (keys : Environment → Input)
    (family : OracleRegisterFamily (Input := Input) (Output := DigestRegister)
      (Phase := DigestRegister) (Workspace := Work))
    (program : Program Input Work) :
    phaseRun randomized
        (liftEnvironmentProgram (Environment := Environment → DigestRegister) program)
        (initializedPhaseFamily family) =
      uniformAverage (fun oracle : Input → DigestRegister =>
          run randomized program oracle (familyGameState family oracle)) := by
  have dictionary : environmentDecidableEq = Classical.decEq Environment :=
    Subsingleton.elim _ _
  subst environmentDecidableEq
  have empty := phase_run_compressed_swaps_as_forward_overlay randomized
    keys [] family program
  simpa only [compressedSwapList, swapOracleLabelsList, uniform_average_const]
    using empty

variable {bound : Nat} {History Work : Type}
variable [Fintype History] [DecidableEq History]
variable [Fintype Work] [DecidableEq Work]
local notation "Statement" => HegemonCrypto.SmallWood.SmzaRp05StatementNamespace.Statement
local notation "Byte" => HegemonCrypto.CanonicalBytes.Byte
local notation "OracleInput" => Rp05FullRawInput bound
attribute [local instance] tailLeafIndexDecidableEq

/-- Exact real-side source identity at fixed source coins. All 2^23 leaf
answers are ordinary CURRENT reads; `next` still runs with mode true. Thus
this theorem does not accidentally change later simulated requests to false.
The output is the literal complete request's bytes/error on the same H. -/
theorem current_fresh_unswapped_eq_real_source
    (largeEnough : 39162 ≤ bound)
    (dsl : RelationDsl) (statement : Statement)
    (values : WitnessPackingValues Goldilocks)
    (salt : SaltBytes) (widthBound : 5 * dsl.width statement ≤ 2 ^ 24)
    (base : RemainingCoins Goldilocks) (masks : Q × D)
    (tapes : LeafIndex → LeafTape)
    (next : Except String (List Byte) → Program OracleInput (History × Work))
    (family : OracleRegisterFamily (Input := OracleInput) (Output := DigestRegister)
      (Phase := DigestRegister) (Workspace := History × Work)) :
    phaseRun true (currentFreshContinuation largeEnough dsl statement values
        salt widthBound base masks next tapes) (initializedPhaseFamily family) =
      uniformAverage (fun oracle : OracleInput → DigestRegister =>
        let labels := fun index => oracle (Sum.inl (rp05SourceLeafInput statement salt
          (q38PhysicalSuffix (currentHeads values base masks.1)
            base.2.2 masks.2 index) index (tapes index)))
        run true (next (currentRequestResult largeEnough dsl statement values
          salt widthBound base masks tapes labels oracle))
          oracle (familyGameState family oracle)) := by
  unfold currentFreshContinuation
  rw [phase_run_initialized_private_environment true
    (fun index => (Sum.inl (rp05SourceLeafInput statement salt
      (q38PhysicalSuffix (currentHeads values base masks.1)
        base.2.2 masks.2 index) index (tapes index)) : OracleInput))]
  apply congrArg uniformAverage
  funext oracle
  rw [read_current_answers_execution, current_request_tail_fixed_oracle]

/-- Same real-side identity after all actual source coins are drawn. No
source coin is replaced and no total-oracle table is resampled between them.
Finite Fubini may move the outer oracle average to match the stopped tree. -/
theorem current_fresh_unswapped_source_average
    (largeEnough : 39162 ≤ bound)
    (dsl : RelationDsl) (statement : Statement)
    (values : WitnessPackingValues Goldilocks)
    (salt : SaltBytes) (widthBound : 5 * dsl.width statement ≤ 2 ^ 24)
    (next : Except String (List Byte) → Program OracleInput (History × Work))
    (family : OracleRegisterFamily (Input := OracleInput) (Output := DigestRegister)
      (Phase := DigestRegister) (Workspace := History × Work)) :
    (uniformAverage fun base : RemainingCoins Goldilocks =>
      uniformAverage fun masks : Q × D =>
        uniformAverage fun tapes : LeafIndex → LeafTape =>
          phaseRun true (currentFreshContinuation largeEnough dsl statement values
            salt widthBound base masks next tapes) (initializedPhaseFamily family)) =
    uniformAverage (fun base : RemainingCoins Goldilocks =>
      uniformAverage (fun masks : Q × D =>
        uniformAverage (fun tapes : LeafIndex → LeafTape =>
          uniformAverage (fun oracle : OracleInput → DigestRegister =>
            let labels := fun index => oracle (Sum.inl (rp05SourceLeafInput statement salt
              (q38PhysicalSuffix (currentHeads values base masks.1)
                base.2.2 masks.2 index) index (tapes index)))
            run true (next (currentRequestResult largeEnough dsl statement values
              salt widthBound base masks tapes labels oracle))
              oracle (familyGameState family oracle))))) := by
  apply congrArg uniformAverage
  funext base
  apply congrArg uniformAverage
  funext masks
  apply congrArg uniformAverage
  funext tapes
  exact current_fresh_unswapped_eq_real_source largeEnough dsl statement values
    salt widthBound base masks tapes next family

/-- Decoded complete-database support also holds before the response-basis
Fourier inverse. Fourier conversion does not change any database coordinate. -/
theorem global_total_support_of_decoded_total
    {Input Work : Type} [Fintype Input] [DecidableEq Input]
    [Fintype Work] [DecidableEq Work]
    (state : ResponseCmsState Input Work)
    (supported : TotalDatabaseSupport (phaseDecode state)) :
    TotalDatabaseSupport (globalDecompress state) := by
  have forward : TotalDatabaseSupport (responseFourierState (phaseDecode state)) := by
    intro basis absent
    have zero (response : DigestRegister) :
        phaseDecode state { basis with phase := response } = 0 :=
      supported _ absent
    simp [responseFourierState, digestResponseFourier, zero]
  simpa only [phaseDecode, response_fourier_inverse_right] using forward

/-- Scheduler-ready history FRESH at ANY bounded, decoded-total reached
state. The actual gate/read/instrument prefix supplies these invariants; it
need not be recast as a fixed rawRun list or a normalized history. -/
theorem current_history_fresh_reached_bound
    (largeEnough : 39162 ≤ bound)
    (dsl : History → RelationDsl) (statement : History → Statement)
    (values : History → WitnessPackingValues Goldilocks)
    (salt : History → SaltBytes)
    (widthBound : ∀ history, 5 * (dsl history).width (statement history) ≤ 2 ^ 24)
    (next : History → Except String (List Byte) → Program OracleInput (History × Work))
    (reached : ResponseCmsState OracleInput (History × Work)) (queries : Nat)
    (bounded : BoundedState queries reached)
    (supported : TotalDatabaseSupport (phaseDecode reached)) :
    |(∑ history : History, historyFreshProbability true largeEnough dsl statement
        values salt widthBound next (coreOfCmsState reached) history) -
      (∑ history : History, historyFreshProbability false largeEnough dsl statement
        values salt widthBound next (coreOfCmsState reached) history)| ≤
      (2 * Real.sqrt (4 * (queries : ℝ) * (2 ^ 512 : ℝ)⁻¹)) * normSquared reached := by
  have bound := current_history_fresh_bound largeEnough dsl statement values
    salt widthBound next (coreOfCmsState reached) queries
    (initializedFreshState_bounded_of_core_state_bounded reached queries bounded)
    (initializedFreshState_total_support_of_core_state reached
      (global_total_support_of_decoded_total reached supported))
  rw [coreOfCmsState_mass] at bound
  exact bound

end
end HegemonCrypto.SmallWood.Q38Rp05RealReadoutAdapter
