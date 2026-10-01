import SmzaRp05NullifierSourceCsrBase

/-! Generic block-one CSR-to-last-frame algebra for symbolic input and lane. -/

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
open _root_.Hegemon.Transaction
open scoped Classical

noncomputable section
set_option autoImplicit false
set_option maxHeartbeats 4000000

/-- The exact source tail in block one. This contains at most two terms and
never the 32-term position branch. -/
def block1SourceTerms (negativeNode positiveNode : Nat) (input : Fin 2)
    (lane : Nat) : List (Nat × Nat) :=
  if lane ≥ 8 then []
  else if lane < 4 then
    let word := 6 + lane
    let noteCall := inputNoteFirstCall input + word / 8
    let noteLane := word % 8
    if word < 8 then [(hashInitialIndex noteCall noteLane, negativeNode)]
    else [(hashInitialIndex noteCall noteLane, negativeNode),
      (hashFinalIndex (noteCall - 1) noteLane, positiveNode)]
  else []

theorem initial_terms_block1_split
    (oneNode negativeNode positiveNode : Nat) (powerNode : Nat → Nat)
    (input : Fin 2) (lane : Fin 16) :
    initialTerms oneNode negativeNode positiveNode powerNode
        (input, (1 : Fin 2), lane) =
      [(hashInitialIndex
          (callOf (input, (1 : Fin 2), lane)) lane.val, oneNode)] ++
        [(hashFinalIndex (nullifierFirstCall input) lane.val, negativeNode)] ++
        block1SourceTerms negativeNode positiveNode input lane.val := by
  simp [initialTerms, block1SourceTerms]

private theorem singleton_csr_sum (values packed : List Nat)
    (index node : Nat) :
    csrFieldSum values packed [(index, node)] =
      (values.getD node 0 : Goldilocks) *
        (packed.getD index 0 : Goldilocks) := by
  simp [csrFieldSum]

private theorem two_negative_terms_algebra {h p d c : Goldilocks}
    (equation : h + -p + -d = c) : h = p + d + c := by
  calc
    h = h + (-p + p) + (-d + d) := by simp only [neg_add_cancel, add_zero]
    _ = (h + -p + -d) + (p + d) := by ring
    _ = c + (p + d) := by rw [equation]
    _ = p + d + c := by ring

/-- For either input and every block-one lane, a factored accepted CSR row
implies the exact last-frame readback. `sourceBalance` discharges the note-word
terms for lanes 0--3 and is zero for lanes 4--15; `frameBalance` records the
small last-frame lane update (including the lane-eleven `+1`). -/
theorem accepted_block1_lane_last_frame_readback
    (values packed : List Nat) (input : Fin 2) (lane : Fin 16)
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
        (initialConstant (input, (1 : Fin 2), lane) : Goldilocks))
    (previousFinal :
      (packed.getD (hashFinalIndex (nullifierFirstCall input) lane.val) 0 : Goldilocks) =
        ((packedFinalState packed (nullifierFirstCall input)).getD lane.val 0 : Goldilocks))
    (frameBalance :
      ((lastFrame (nullifierPreimage packed input)
          (packedFinalState packed (nullifierFirstCall input))).getD lane.val 0 : Goldilocks) =
        ((packedFinalState packed (nullifierFirstCall input)).getD lane.val 0 : Goldilocks) +
          ((if lane.val < 4 then
              (nullifierPreimage packed input).getD (8 + lane.val) 0
            else 0 : Nat) : Goldilocks) +
          (initialConstant (input, (1 : Fin 2), lane) : Goldilocks)) :
    (packed.getD
        (hashInitialIndex (callOf (input, (1 : Fin 2), lane)) lane.val) 0 : Goldilocks) =
      ((lastFrame (nullifierPreimage packed input)
          (packedFinalState packed (nullifierFirstCall input))).getD lane.val 0 : Goldilocks) := by
  have shape := initial_terms_block1_split oneNode negativeNode positiveNode
    powerNode input lane
  have rowEquation := equation
  rw [shape, csr_sum_append, csr_sum_append] at rowEquation
  rw [singleton_csr_sum, singleton_csr_sum, one, negative,
    sourceBalance, constant] at rowEquation
  rw [previousFinal] at rowEquation
  simp only [one_mul, neg_one_mul] at rowEquation
  have currentValue :
      (packed.getD
        (hashInitialIndex (callOf (input, (1 : Fin 2), lane)) lane.val) 0 : Goldilocks) =
        ((packedFinalState packed (nullifierFirstCall input)).getD lane.val 0 : Goldilocks) +
          ((if lane.val < 4 then
              (nullifierPreimage packed input).getD (8 + lane.val) 0
            else 0 : Nat) : Goldilocks) +
          (initialConstant (input, (1 : Fin 2), lane) : Goldilocks) := by
    exact two_negative_terms_algebra rowEquation
  rw [← frameBalance] at currentValue
  exact currentValue

end
end HegemonCrypto.SmallWood.SmzaRp05NullifierSource
