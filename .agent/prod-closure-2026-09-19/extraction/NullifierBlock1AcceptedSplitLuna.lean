import NullifierBlock1SourceBalanceSplitLuna
import NullifierBlock1FrameDefinitionsLuna

/-! Accepted block-one last-frame readback on the proven source-balance
classes: lanes 0--1 and 4--15. Lanes 2--3 are intentionally excluded. -/

namespace HegemonCrypto.SmallWood.SmzaRp05NullifierSource

open _root_.Hegemon.Transaction.Poseidon2V8RelationProgram
open _root_.Hegemon.Transaction.Poseidon2V8SemanticSpecification
open _root_.Hegemon.Transaction.Poseidon2V8DecoderRefinement
  (hashInitialIndex)
open _root_.HegemonCrypto.SmallWood.V8Smz9SemanticDenseRange
open _root_.HegemonCrypto.SmallWood.V8Smz9SemanticDecoder
open _root_.HegemonCrypto.SmallWood.SmzaRp05NullifierBinding
open _root_.HegemonCrypto.SmallWood.SmzaRp05TypedRelation
open _root_.HegemonCrypto.SmallWood.SmzaRp05AccumulatorHashBridge
open _root_.HegemonCrypto.SmallWood.V8Smz9SemanticPoseidonKernelBinding
open _root_.Hegemon.Transaction
open scoped Classical

noncomputable section
set_option autoImplicit false
set_option maxRecDepth 10000
set_option maxHeartbeats 4000000

/-- Accepted block-one lane readback for either input, on lanes 0--1 and
4--15. The missing middle low lanes 2--3 are not covered. -/
theorem accepted_block1_lanes01_4to15_last_frame_readback
    {components : RelationProgramComponents}
    (certificate : KernelCertificate components)
    {publicWords packed : List Nat}
    (accepted : components.AcceptsPacked publicWords packed)
    (input : Fin 2) (lane : Fin 16)
    (laneClass : lane.val < 2 ∨ 4 ≤ lane.val)
    (previousCallBound : nullifierFirstCall input < 128)
    (values : List Nat)
    (oneNode negativeNode positiveNode : Nat)
    (powerNode : Nat → Nat) (constantNode : InitialCell → Nat)
    (equation : csrFieldSum values packed
      (initialTerms oneNode negativeNode positiveNode powerNode
        (input, (1 : Fin 2), lane)) =
        (values.getD (constantNode (input, (1 : Fin 2), lane)) 0 : Goldilocks))
    (one : (values.getD oneNode 0 : Goldilocks) = 1)
    (negative : (values.getD negativeNode 0 : Goldilocks) = -1)
    (constant :
      (values.getD (constantNode (input, (1 : Fin 2), lane)) 0 : Goldilocks) =
        (initialConstant (input, (1 : Fin 2), lane) : Goldilocks)) :
    (packed.getD
        (hashInitialIndex (callOf (input, (1 : Fin 2), lane)) lane.val) 0 : Goldilocks) =
      ((lastFrame (nullifierPreimage packed input)
          (packedFinalState packed (nullifierFirstCall input))).getD lane.val 0 : Goldilocks) ∧
      Hegemon.Transaction.Poseidon2Width16Kernel.permutation
          (packedInitialState packed (nullifierFirstCall input)) =
        packedFinalState packed (nullifierFirstCall input) := by
  have sourceBalance :
      csrFieldSum values packed
        (block1SourceTerms negativeNode positiveNode input lane.val) =
        -((if lane.val < 4 then
            (nullifierPreimage packed input).getD (8 + lane.val) 0
          else 0 : Nat) : Goldilocks) := by
    rcases laneClass with low | high
    · exact block1_source_balance_lanes01 values packed input lane
        negativeNode positiveNode negative low
    · exact block1_source_balance_lanes4to15 values packed input lane
        negativeNode positiveNode high
  exact accepted_block1_lane_last_frame_readback_from_definitions
    certificate accepted input lane previousCallBound values oneNode negativeNode
    positiveNode powerNode constantNode sourceBalance equation one negative constant

end
end HegemonCrypto.SmallWood.SmzaRp05NullifierSource
