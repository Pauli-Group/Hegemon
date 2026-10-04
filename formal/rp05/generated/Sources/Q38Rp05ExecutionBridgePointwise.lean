import Q38Rp05ExecutionBridgeEnvironment

/-!
# Pointwise initialized RP05 overlay execution

This version of the execution bridge keeps the site count and saved-label
environment abstract. Specializing it to the current leaf index requires no
elaboration of a finite table of all leaf tapes.
-/
namespace HegemonCrypto.SmallWood.Q38Rp05ExecutionBridge

open HegemonCrypto.CmsOracleSimulation
open HegemonCrypto.SmallWood.V8Smz9HiddenLeafQrom
open HegemonCrypto.SmallWood.V8Smz9HonestWholeViewGames
open HegemonCrypto.SmallWood.V8Smz9CurrentPrivacyGame
open HegemonCrypto.SmallWood.V8SmzaCmsIndexedSwap
open HegemonCrypto.SmallWood.Q38WholeViewCmsSemantics
open HegemonCrypto.SmallWood.Q38Rp05LeafSupport
open HegemonCrypto.SmallWood.Q38ConcreteAdaptivePrivacy
open scoped Classical

noncomputable section
set_option autoImplicit false
set_option Elab.async false
set_option maxHeartbeats 2000000
set_option maxRecDepth 10000

variable {Other Work Environment : Type}
variable [Fintype Other] [DecidableEq Other]
variable [Fintype Work] [DecidableEq Work] [Fintype Environment]

local notation "FullInput" => Rp05LeafInput ⊕ Other

/-- For one fixed tape table, the initialized compressed-swap execution of
current reads is the complete forward overlay on the same old-oracle-indexed
family. The saved overwritten labels never replace the current oracle reads.
All finite spaces and the site count remain symbolic in this proof. -/
theorem compressed_swaps_current_reads_eq_full_overlay_at
    (count : Nat) (sites : Fin count → Environment)
    (siteDistinct : Function.Injective sites)
    (keys : Environment → FullInput)
    (keyDistinct : Function.Injective (fun i => keys (sites i)))
    (family : OracleRegisterFamily
      (Input := FullInput) (Output := DigestRegister)
      (Phase := DigestRegister) (Workspace := Work))
    (next : (Fin count → DigestRegister) → Program FullInput Work) :
    phaseRun true
        (liftEnvironmentProgram
          (Environment := Environment → DigestRegister)
          (readCurrentAnswers count (fun i => keys (sites i)) next))
        (compressedSwapList keys (List.ofFn sites)
          (initializedPhaseFamily family)) =
      uniformAverage (fun oldOracle : FullInput → DigestRegister =>
        uniformAverage (fun freshLabels : Environment → DigestRegister =>
          let outputs := fun i => freshLabels (sites i)
          let overlay := updateRp05Batch count
            (fun i => keys (sites i)) outputs oldOracle
          V8Smz9HonestWholeViewGames.run true (next outputs) overlay
            (familyGameState family oldOracle))) := by
  rw [phase_run_compressed_swaps_as_forward_overlay true
    keys (List.ofFn sites) family
    (readCurrentAnswers count (fun i => keys (sites i)) next)]
  apply congrArg uniformAverage
  funext oldOracle
  apply congrArg uniformAverage
  funext freshLabels
  dsimp only
  let final := swapOracleLabelsList keys (List.ofFn sites)
    (oldOracle, freshLabels)
  let outputs := fun i => freshLabels (sites i)
  let overlay := updateRp05Batch count
    (fun i => keys (sites i)) outputs oldOracle
  have finalOracle : final.1 = overlay := by
    exact swap_oracle_labels_list_first_is_update count keys sites
      siteDistinct keyDistinct oldOracle freshLabels
  rw [read_current_answers_execution]
  rw [finalOracle]
  congr 2
  funext i
  exact update_rp05_batch_at count (fun i => keys (sites i)) outputs
    oldOracle keyDistinct i

end
end HegemonCrypto.SmallWood.Q38Rp05ExecutionBridge
