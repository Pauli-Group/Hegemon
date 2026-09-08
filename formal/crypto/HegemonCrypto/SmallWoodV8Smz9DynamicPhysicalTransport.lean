import HegemonCrypto.SmallWoodV8Smz9DynamicTransport

/-! The actual randomized-leaf source interpreter is the physical observer
transported by the source Q/M bijection. Current leaf updates, future programs,
the quantum state, and the raw nonleaf history are retained throughout. -/

namespace HegemonCrypto.SmallWood.V8Smz9DynamicPhysicalTransport

open Hegemon.Transaction.Poseidon2V8SemanticSpecification
open V8Smz9RuntimeRandomness V8Smz9HonestHybrid V8Smz9EagerPrivacy
open V8Smz9HiddenLeafQrom V8Smz9HiddenPatch V8Smz9EagerOracleGame
open V8Smz9SingleProofPrivacy V8Smz9CurrentPrivacyGame V8Smz9CurrentPrivacyComposition
open V8Smz9CurrentPublicContext V8Smz9CurrentProgramPiop V8Smz9ZeroKnowledge
open V8Smz9HonestWholeViewGames V8Smz9HonestFinalGame V8Smz9HonestLeafBatch
open V8Smz9HonestRequestSchedule V8Smz9HonestOpeningSchedule V8Smz9DynamicRequest V8Smz9DynamicTransport
open V8Smz9RuntimeDistribution V8Smz9WholeViewObservation V8Smz9RawCounterCompiler
open scoped BigOperators Classical

noncomputable section
set_option maxHeartbeats 400000
set_option maxRecDepth 10000

variable {Work : Type} [Fintype Work]

def actualLeafOverlay {bound : Nat} (oracle : FullRawInput bound → DigestRegister)
    (values : WitnessPackingValues Goldilocks) (base : SourceRemainingCoins Goldilocks)
    (masks : JointMaskCoins Goldilocks) (salt : SaltBytes)
    (tapes : LeafIndex → LeafTape) (labels : LeafIndex → DigestRegister) : FullRawInput bound → DigestRegister :=
  fullSourceOverlay (fun input => oracle (Sum.inl input)) (fun input => oracle (Sum.inr input))
    labels Finset.univ (fun _ => canonicalLeafHeader salt)
    (fullPhysicalSuffix (currentJointHeads values base masks.1) base.2.2 masks.2) tapes

theorem actual_leaf_overlay_nonleaf {bound : Nat} (oracle : FullRawInput bound → DigestRegister)
    (values : WitnessPackingValues Goldilocks) (base : SourceRemainingCoins Goldilocks)
    (masks : JointMaskCoins Goldilocks) (salt : SaltBytes)
    (tapes : LeafIndex → LeafTape) (labels : LeafIndex → DigestRegister) (input : OtherRawInput bound) :
    actualLeafOverlay oracle values base masks salt tapes labels (Sum.inr input) = oracle (Sum.inr input) := rfl

theorem actual_leaf_overlay_final_key (bound : Nat) (largeEnough : 25029 ≤ bound)
    (oracle : FullRawInput bound → DigestRegister)
    (values : WitnessPackingValues Goldilocks) (base : SourceRemainingCoins Goldilocks)
    (masks : JointMaskCoins Goldilocks) (salt : SaltBytes)
    (tapes : LeafIndex → LeafTape) (labels : LeafIndex → DigestRegister)
    (digestPrefix : V8Smz9HonestWholeViewFinalInput.Prefix) (transcript : PiopCoefficients Goldilocks) :
    actualLeafOverlay oracle values base masks salt tapes labels
      (sourceFinalKey bound largeEnough digestPrefix transcript) =
      oracle (sourceFinalKey bound largeEnough digestPrefix transcript) := by
  rw [← source_final_other_key_is_final_key]
  exact actual_leaf_overlay_nonleaf _ _ _ _ _ _ _ _

attribute [local irreducible] V8Smz9HonestWholeViewGames.run actualLeafOverlay
  sourceComputedPrefix sourceDynamicPrefinal sourceComputedPiopTranscript sourceFinalKey

/-- Exact source batch execution, not a distribution-equivalence premise.
The all-leaf update buffer is the genuine source physical table. -/
theorem randomized_source_prefix_keeps_actual_leaf_overlay
    (bound : Nat) (largeEnough : 25029 ≤ bound)
    (statementBinding : List Nat) (bindingFits : 15704 + 8 * statementBinding.length ≤ bound)
    (statement : V8PublicStatement) (values : WitnessPackingValues Goldilocks)
    (base : SourceRemainingCoins Goldilocks) (masks : JointMaskCoins Goldilocks)
    (salt : SaltBytes) (retainedRows : Nat) (rowBound : retainedRows ≤ 20605)
    (next : (LeafIndex → LeafTape) → (LeafIndex → DigestRegister) →
      PrefinalResult → DecsFullCoefficients Goldilocks → PiopCoefficients Goldilocks →
      DigestRegister → Bool → Program (FullRawInput bound) Work)
    (oracle : FullRawInput bound → DigestRegister)
    (initial : GameState (Input := FullRawInput bound) (Work := Work)) :
    run true (sourceAllLeavesThenComputedPrefix bound largeEnough statementBinding bindingFits
      statement values base masks salt retainedRows rowBound next) oracle initial =
    uniformAverage (fun tapes : LeafIndex → LeafTape => uniformAverage (fun labels : LeafIndex → DigestRegister =>
      run true (sourceComputedPrefix bound largeEnough statementBinding bindingFits statement values
        base masks salt labels retainedRows rowBound (next tapes labels))
        (actualLeafOverlay oracle values base masks salt tapes labels) initial)) := by
  unfold sourceAllLeavesThenComputedPrefix allCurrentSourceLeaves
  rw [source_leaf_batch_randomized_execution]
  apply congrArg uniformAverage
  funext tapes
  apply congrArg uniformAverage
  funext labels
  have updates := all_source_updates_are_full_overlay (fun _ => canonicalLeafHeader salt)
    (fullPhysicalSuffix (currentJointHeads values base masks.1) base.2.2 masks.2) tapes labels oracle
  simpa only [actualLeafOverlay, id_eq] using congrArg (fun updated => run true
    (sourceComputedPrefix bound largeEnough statementBinding bindingFits statement values
      base masks salt labels retainedRows rowBound (next tapes labels)) updated initial) updates

/-- The same nonleaf table computes the entire history and the final digest,
while the current source leaf table stays in the future oracle. -/
theorem source_computed_prefix_after_leaf_overlay
    (bound : Nat) (largeEnough : 25029 ≤ bound)
    (statementBinding : List Nat) (bindingFits : 15704 + 8 * statementBinding.length ≤ bound)
    (statement : V8PublicStatement) (values : WitnessPackingValues Goldilocks)
    (base : SourceRemainingCoins Goldilocks) (masks : JointMaskCoins Goldilocks)
    (salt : SaltBytes) (tapes : LeafIndex → LeafTape) (labels : LeafIndex → DigestRegister)
    (retainedRows : Nat) (rowBound : retainedRows ≤ 20605)
    (next : PrefinalResult → DecsFullCoefficients Goldilocks → PiopCoefficients Goldilocks →
      DigestRegister → Bool → Program (FullRawInput bound) Work)
    (oracle : FullRawInput bound → DigestRegister)
    (initial : GameState (Input := FullRawInput bound) (Work := Work)) :
    run true (sourceComputedPrefix bound largeEnough statementBinding bindingFits statement values
      base masks salt labels retainedRows rowBound next)
      (actualLeafOverlay oracle values base masks salt tapes labels) initial =
      let computed := NonleafProgram.interpret (fun input => oracle (Sum.inr input))
        (sourceDynamicPrefinal bound largeEnough statementBinding bindingFits salt labels
          (sourceComputedDecsResponse values base masks) retainedRows rowBound)
      let transcript := sourceComputedPiopTranscript statement values base masks retainedRows computed.1.piopGamma
      run true (next computed.1 computed.2 transcript
        (oracle (sourceFinalKey bound largeEnough (sourceDigestPrefix computed.1.hashFpp) transcript))
        (sourcePendingFailure (sourcePendingFailure false computed.1.decsGamma) computed.1.piopGamma))
        (actualLeafOverlay oracle values base masks salt tapes labels) initial := by
  rw [source_computed_prefix_execution]
  simp only [actual_leaf_overlay_nonleaf, actual_leaf_overlay_final_key]

def physicalOutputObservation (bound : Nat) (largeEnough : 25029 ≤ bound)
    (statementBinding : List Nat) (bindingFits : 15704 + 8 * statementBinding.length ≤ bound)
    (values : WitnessPackingValues Goldilocks) (salt : SaltBytes)
    (retainedRows : Nat) (rowBound : retainedRows ≤ 20605)
    (next : (LeafIndex → LeafTape) → (LeafIndex → DigestRegister) →
      PrefinalResult → DecsFullCoefficients Goldilocks → PiopCoefficients Goldilocks →
      DigestRegister → Bool → Program (FullRawInput bound) Work)
    (oracle : FullRawInput bound → DigestRegister)
    (initial : GameState (Input := FullRawInput bound) (Work := Work))
    (base : SourceRemainingCoins Goldilocks) (labels : LeafIndex → DigestRegister)
    (masks : JointMaskCoins Goldilocks) (output : JointMaskOutputs Goldilocks) : ℝ :=
  let stageResult := sourcePublicPrefinal bound largeEnough statementBinding bindingFits salt retainedRows rowBound
    (fun input => oracle (Sum.inr input)) labels output.1
  uniformAverage fun tapes : LeafIndex → LeafTape =>
    run true (next tapes labels stageResult output.1 output.2
      (oracle (sourceFinalKey bound largeEnough (sourceDigestPrefix stageResult.hashFpp) output.2))
      (sourcePendingFailure (sourcePendingFailure false stageResult.decsGamma) stageResult.piopGamma))
      (actualLeafOverlay oracle values base masks salt tapes labels) initial

/-- This is the actual source program observation after leaf randomization,
with no supplied probability or game-equality field. -/
theorem randomized_source_prefix_is_physical_output_observation
    (bound : Nat) (largeEnough : 25029 ≤ bound)
    (statementBinding : List Nat) (bindingFits : 15704 + 8 * statementBinding.length ≤ bound)
    (statement : V8PublicStatement) (values : WitnessPackingValues Goldilocks)
    (base : SourceRemainingCoins Goldilocks) (masks : JointMaskCoins Goldilocks)
    (salt : SaltBytes) (retainedRows : Nat) (rowBound : retainedRows ≤ 20605)
    (next : (LeafIndex → LeafTape) → (LeafIndex → DigestRegister) →
      PrefinalResult → DecsFullCoefficients Goldilocks → PiopCoefficients Goldilocks →
      DigestRegister → Bool → Program (FullRawInput bound) Work)
    (oracle : FullRawInput bound → DigestRegister)
    (initial : GameState (Input := FullRawInput bound) (Work := Work)) :
    run true (sourceAllLeavesThenComputedPrefix bound largeEnough statementBinding bindingFits
      statement values base masks salt retainedRows rowBound next) oracle initial =
    uniformAverage (fun labels : LeafIndex → DigestRegister =>
      physicalOutputObservation bound largeEnough statementBinding bindingFits values salt retainedRows rowBound
        next oracle initial base labels masks
        (sourceDynamicOutputs bound largeEnough statementBinding bindingFits statement values salt retainedRows rowBound
          (fun input => oracle (Sum.inr input)) base masks labels)) := by
  rw [randomized_source_prefix_keeps_actual_leaf_overlay, uniform_average_comm]
  apply congrArg uniformAverage
  funext labels
  unfold physicalOutputObservation
  apply congrArg uniformAverage
  funext tapes
  rw [source_computed_prefix_after_leaf_overlay]
  simp only [sourceDynamicOutputs, source_dynamic_prefinal_exact_execution, sourcePublicPrefinal]

/-- The complete measured future and current physical oracle are carried
through the triangular Q/M bijection. This is a proved equality of the actual
randomized-leaf interpreter, not an endpoint-shaped equality premise. -/
theorem randomized_source_prefix_physical_mask_transport
    (bound : Nat) (largeEnough : 25029 ≤ bound)
    (statementBinding : List Nat) (bindingFits : 15704 + 8 * statementBinding.length ≤ bound)
    (statement : V8PublicStatement) (values : WitnessPackingValues Goldilocks)
    (salt : SaltBytes) (retainedRows : Nat) (rowBound : retainedRows ≤ 20605)
    (next : (LeafIndex → LeafTape) → (LeafIndex → DigestRegister) →
      PrefinalResult → DecsFullCoefficients Goldilocks → PiopCoefficients Goldilocks →
      DigestRegister → Bool → Program (FullRawInput bound) Work)
    (oracle : FullRawInput bound → DigestRegister)
    (initial : GameState (Input := FullRawInput bound) (Work := Work)) :
    uniformAverage (fun base : SourceRemainingCoins Goldilocks =>
      uniformAverage (fun masks : JointMaskCoins Goldilocks =>
        run true (sourceAllLeavesThenComputedPrefix bound largeEnough statementBinding bindingFits
          statement values base masks salt retainedRows rowBound next) oracle initial)) =
    uniformAverage (fun labels => uniformAverage (fun output : JointMaskOutputs Goldilocks =>
      uniformAverage (fun base : SourceRemainingCoins Goldilocks =>
        physicalOutputObservation bound largeEnough statementBinding bindingFits values salt retainedRows rowBound
          next oracle initial base labels
          (jointMaskInverse
            (sourcePublicDecsGamma bound largeEnough statementBinding bindingFits salt retainedRows rowBound
              (fun input => oracle (Sum.inr input)) labels)
            (currentJointHeads values base) base.2.2
            (currentJointUnmasked statement
              (sourcePublicBatching bound largeEnough statementBinding bindingFits salt retainedRows rowBound
                (fun input => oracle (Sum.inr input)) labels) values base) output) output))) := by
  simp_rw [randomized_source_prefix_is_physical_output_observation]
  exact chronological_dynamic_source_transport bound largeEnough statementBinding bindingFits statement values
    salt retainedRows rowBound (fun input => oracle (Sum.inr input))
    (physicalOutputObservation bound largeEnough statementBinding bindingFits values salt retainedRows rowBound
      next oracle initial)

end
end HegemonCrypto.SmallWood.V8Smz9DynamicPhysicalTransport
