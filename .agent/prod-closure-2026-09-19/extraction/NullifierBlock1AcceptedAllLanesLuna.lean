import NullifierBlock1AcceptedSplitLuna
import NullifierBlock1SourceBalanceLanes2to3Luna

/-! Full block-one accepted readback by composing the four checked source
branches. This file is prepared only; no Lean check is run here. -/

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
open _root_.HegemonCrypto.SmallWood.V8Smz9Poseidon2TemplateRefinement
open _root_.Hegemon.Transaction
open scoped Classical

noncomputable section
set_option autoImplicit false
set_option maxRecDepth 10000
set_option maxHeartbeats 4000000

/-- Accepted block-one lane readback for either input and every lane. Source
balance is derived from the checked 0--1, 2--3, and 4--15 branches; the
middle lanes additionally require positive-node value one and canonical
packed words for the field-subtraction embedding. -/
theorem accepted_block1_all_lanes_last_frame_readback
    {components : RelationProgramComponents}
    (certificate : KernelCertificate components)
    {publicWords packed : List Nat}
    (accepted : components.AcceptsPacked publicWords packed)
    (input : Fin 2) (lane : Fin 16)
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
    (positive : (values.getD positiveNode 0 : Goldilocks) = 1)
    (packedCanonical : ∀ index, packed.getD index 0 <
      _root_.Hegemon.Transaction.Poseidon2V8RelationProgram.fieldModulus)
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
    by_cases low : lane.val < 2
    · exact block1_source_balance_lanes01 values packed input lane
        negativeNode positiveNode negative low
    · by_cases laneTwo : lane.val = 2
      · have laneEq : lane = (2 : Fin 16) := Fin.ext laneTwo
        subst lane
        have lane2Source := block1_source_balance_lane2_both_inputs values packed input
          negativeNode positiveNode negative positive packedCanonical
        change csrFieldSum values packed
            (block1SourceTerms negativeNode positiveNode input 2) =
          -((nullifierPreimage packed input).getD 10 0 : Goldilocks)
        exact lane2Source
      · by_cases laneThree : lane.val = 3
        · have laneEq : lane = (3 : Fin 16) := Fin.ext laneThree
          subst lane
          have lane3Source := block1_source_balance_lane3_both_inputs values packed input
            negativeNode positiveNode negative positive packedCanonical
          change csrFieldSum values packed
              (block1SourceTerms negativeNode positiveNode input 3) =
            -((nullifierPreimage packed input).getD 11 0 : Goldilocks)
          exact lane3Source
        · have high : 4 ≤ lane.val := by omega
          exact block1_source_balance_lanes4to15 values packed input lane
            negativeNode positiveNode high
  exact accepted_block1_lane_last_frame_readback_from_definitions
    certificate accepted input lane previousCallBound values oneNode negativeNode
    positiveNode powerNode constantNode sourceBalance equation one negative constant

end
end HegemonCrypto.SmallWood.SmzaRp05NullifierSource
