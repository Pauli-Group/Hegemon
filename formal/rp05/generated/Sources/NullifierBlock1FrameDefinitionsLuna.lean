import NullifierBlock1LastFrameLuna

/-! Definition-level block-one frame and packed-final-state readbacks. -/

namespace HegemonCrypto.SmallWood.SmzaRp05NullifierSource

open _root_.Hegemon.Transaction.Poseidon2V8RelationProgram
open _root_.Hegemon.Transaction.Poseidon2V8SemanticSpecification
open _root_.Hegemon.Transaction.Poseidon2V8DecoderRefinement
  (hashInitialIndex hashFinalIndex)
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

private theorem packedFinalState_getD_local (packed : List Nat)
    (call lane : Nat) (bound : lane < 16) :
    (packedFinalState packed call).getD lane 0 =
      packed.getD (hashFinalIndex call lane) 0 := by
  simp only [packedFinalState, packedWord, List.getD_eq_getElem?_getD,
    List.getElem?_map, List.getElem?_range bound,
    Option.map_some, Option.getD_some]

private theorem lastFrame_getD_block1_balance_local
    (inputs state : List Nat) (lane : Nat) (bound : lane < 16) :
    ((lastFrame inputs state).getD lane 0 : Goldilocks) =
      (state.getD lane 0 : Goldilocks) +
        ((if lane < 4 then inputs.getD (8 + lane) 0 else 0 : Nat) : Goldilocks) +
        ((if lane = 11 then 1 else 0 : Nat) : Goldilocks) := by
  unfold lastFrame
  rw [List.getD_eq_getElem?_getD, List.getElem?_map,
    List.getElem?_range bound, Option.map_some, Option.getD_some]
  by_cases hLow : lane < 4
  · have hNotEleven : lane ≠ 11 := by omega
    simp only [if_pos hLow, if_neg hNotEleven,
      V8Smz9Poseidon2TemplateRefinement.cast_fieldAdd,
      Nat.cast_zero]
    ring
  · by_cases hEleven : lane = 11
    · simp only [if_neg hLow, if_pos hEleven,
        V8Smz9Poseidon2TemplateRefinement.cast_fieldAdd,
        Nat.cast_zero, Nat.cast_one]
      ring
    · simp only [if_neg hLow, if_neg hEleven,
        Nat.cast_zero]
      ring

/-- Replace the two explicit last-frame premises by their exact list
definitions and accepted evidence for the previous hash call. The direct
packed-row/final-list correspondence is a list-map identity; acceptance is
needed separately to identify that list with the previous call's permutation. -/
theorem accepted_block1_lane_last_frame_readback_from_definitions
    {components : RelationProgramComponents}
    (certificate : KernelCertificate components)
    {publicWords packed : List Nat}
    (accepted : components.AcceptsPacked publicWords packed)
    (input : Fin 2) (lane : Fin 16)
    (previousCallBound : nullifierFirstCall input < 128)
    (values : List Nat)
    (oneNode negativeNode positiveNode : Nat)
    (powerNode : Nat → Nat) (constantNode : InitialCell → Nat)
    (sourceBalance :
      csrFieldSum values packed
        (block1SourceTerms negativeNode positiveNode input lane.val) =
        -((if lane.val < 4 then
            (nullifierPreimage packed input).getD (8 + lane.val) 0
          else 0 : Nat) : Goldilocks))
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
  have previousFinal :
      (packed.getD (hashFinalIndex (nullifierFirstCall input) lane.val) 0 : Goldilocks) =
        ((packedFinalState packed (nullifierFirstCall input)).getD lane.val 0 : Goldilocks) := by
    exact congrArg (fun word : Nat => (word : Goldilocks))
      (packedFinalState_getD_local packed (nullifierFirstCall input) lane.val lane.isLt).symm
  have constantCell :
      initialConstant (input, (1 : Fin 2), lane) =
        (if lane.val = 11 then 1 else 0 : Nat) := rfl
  have frameBalance :
      ((lastFrame (nullifierPreimage packed input)
          (packedFinalState packed (nullifierFirstCall input))).getD lane.val 0 : Goldilocks) =
        ((packedFinalState packed (nullifierFirstCall input)).getD lane.val 0 : Goldilocks) +
          ((if lane.val < 4 then
              (nullifierPreimage packed input).getD (8 + lane.val) 0
            else 0 : Nat) : Goldilocks) +
          (initialConstant (input, (1 : Fin 2), lane) : Goldilocks) := by
    rw [lastFrame_getD_block1_balance_local _ _ _ lane.isLt, constantCell]
  have acceptedPreviousState :=
    accepted_hash_call_state certificate accepted previousCallBound
  constructor
  · exact accepted_block1_lane_last_frame_readback
      values packed input lane oneNode negativeNode positiveNode powerNode
      constantNode sourceBalance equation one negative constant previousFinal frameBalance
  · exact acceptedPreviousState

end
end HegemonCrypto.SmallWood.SmzaRp05NullifierSource
