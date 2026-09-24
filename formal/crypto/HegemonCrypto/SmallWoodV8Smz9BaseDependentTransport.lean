import HegemonCrypto.SmallWoodV8Smz9DynamicPhysicalTransport

/-! The physical Q/M transport with a continuation retaining the original
source base coins. Dependence on these coins is explicit on both sides; no
base-independence or additional endpoint-correspondence premise is introduced.
-/

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

/-- The complete measured future may use the same original base coins as the
source request. The chronological bijection already permits an arbitrary
base-dependent observer, so retaining this dependence requires no new law. -/
theorem randomized_source_prefix_physical_mask_transport_base_dependent
    (bound : Nat) (largeEnough : 25029 ≤ bound)
    (statementBinding : List Nat) (bindingFits : 15704 + 8 * statementBinding.length ≤ bound)
    (statement : V8PublicStatement) (values : WitnessPackingValues Goldilocks)
    (salt : SaltBytes) (retainedRows : Nat) (rowBound : retainedRows ≤ 20605)
    (next : SourceRemainingCoins Goldilocks → (LeafIndex → LeafTape) →
      (LeafIndex → DigestRegister) → PrefinalResult → DecsFullCoefficients Goldilocks →
      PiopCoefficients Goldilocks → DigestRegister → Bool → Program (FullRawInput bound) Work)
    (oracle : FullRawInput bound → DigestRegister)
    (initial : GameState (Input := FullRawInput bound) (Work := Work)) :
    uniformAverage (fun base : SourceRemainingCoins Goldilocks =>
      uniformAverage (fun masks : JointMaskCoins Goldilocks =>
        run true (sourceAllLeavesThenComputedPrefix bound largeEnough statementBinding bindingFits
          statement values base masks salt retainedRows rowBound (next base)) oracle initial)) =
    uniformAverage (fun labels => uniformAverage (fun output : JointMaskOutputs Goldilocks =>
      uniformAverage (fun base : SourceRemainingCoins Goldilocks =>
        physicalOutputObservation bound largeEnough statementBinding bindingFits values salt retainedRows rowBound
          (next base) oracle initial base labels
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
    (fun base labels masks output =>
      physicalOutputObservation bound largeEnough statementBinding bindingFits values salt retainedRows rowBound
        (next base) oracle initial base labels masks output)


end
end HegemonCrypto.SmallWood.V8Smz9DynamicPhysicalTransport
