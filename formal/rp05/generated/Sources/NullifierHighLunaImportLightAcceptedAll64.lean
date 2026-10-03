import SmzaRp05NullifierSourceCsrBase
import NullifierBlock0Lanes0to6BothInputsBaseLuna
import NullifierLane7BothInputsBlock0Luna
import NullifierHighLanesBlock0Luna
import NullifierBlock1AcceptedAllLanesLuna

/-! Import-light accepted source readback for all 64 initial cells. It
composes the checked block-zero lane families and the checked block-one
accepted all-lane wrapper without importing the older quadrant chain. -/

namespace HegemonCrypto.SmallWood.SmzaRp05NullifierSource

open _root_.Hegemon.Transaction.Poseidon2V8RelationProgram
open _root_.Hegemon.Transaction.Poseidon2V8SemanticSpecification
open _root_.Hegemon.Transaction.Poseidon2V8DecoderRefinement
  (hashInitialIndex)
open _root_.HegemonCrypto.SmallWood.V8Smz9SemanticDenseRange
open _root_.HegemonCrypto.SmallWood.V8Smz9SemanticDecoder
open _root_.HegemonCrypto.SmallWood.SmzaRp05AccumulatorHashBridge
open _root_.HegemonCrypto.SmallWood.SmzaRp05NullifierBinding
open _root_.HegemonCrypto.SmallWood.SmzaRp05TypedRelation
open _root_.HegemonCrypto.SmallWood.V8Smz9Poseidon2TemplateRefinement
open _root_.Hegemon.Transaction.Poseidon2Width16Kernel
open _root_.Hegemon.Transaction
open scoped Classical

noncomputable section
set_option autoImplicit false
set_option maxRecDepth 100000
set_option maxHeartbeats 4000000

/-- Accepted initial-cell readback for all inputs, blocks, and lanes using
only the import-light checked block-zero and block-one lane results. -/
theorem accepted_initial_cell_field_luna_import_light_all64
    {components : RelationProgramComponents}
    (initial : InitialCertificate components)
    (kernel : KernelCertificate components)
    {publicWords packed : List Nat}
    (accepted : components.AcceptsPacked publicWords packed)
    (cell : InitialCell) :
    (packed.getD (hashInitialIndex (callOf cell) cell.2.2.val) 0 : Goldilocks) =
      ((if cell.2.1.val = 0 then
          firstFrame (nullifierPreimage packed cell.1)
        else lastFrame (nullifierPreimage packed cell.1)
          (packedFinalState packed (nullifierFirstCall cell.1))).getD
        cell.2.2.val 0 : Goldilocks) := by
  obtain ⟨values, evaluated, equation⟩ :=
    accepted_initial_cell_equation initial accepted cell
  have one : (values.getD initial.oneNode 0 : Goldilocks) = 1 := by
    simpa [SourceTerm.eval] using
      csr_node_value initial.canonical evaluated initial.oneRealizes
  have negative : (values.getD initial.negativeNode 0 : Goldilocks) = -1 := by
    simpa [SourceTerm.eval] using
      csr_node_value initial.canonical evaluated initial.negativeRealizes
  have positive : (values.getD initial.positiveNode 0 : Goldilocks) = 1 := by
    simpa [SourceTerm.eval] using
      csr_node_value initial.canonical evaluated initial.positiveRealizes
  have powers : ∀ bit, bit < 32 →
      (values.getD (initial.powerNode bit) 0 : Goldilocks) =
        -(2 ^ bit : Goldilocks) := by
    intro bit bound
    have source := csr_node_value initial.canonical evaluated
      (initial.powerRealizes bit bound)
    simpa [SourceTerm.eval] using source
  have constant :
      (values.getD (initial.constantNode cell) 0 : Goldilocks) =
        (initialConstant cell : Goldilocks) := by
    simpa [SourceTerm.eval] using
      csr_node_value initial.canonical evaluated (initial.constantRealizes cell)
  have position := position_terms_field values packed cell.1
    initial.powerNode powers
  have packedCanonical : ∀ index, packed.getD index 0 <
      Hegemon.Transaction.Poseidon2V8RelationProgram.fieldModulus := by
    intro index
    exact packed_word_canonical accepted.2.1 index
  rcases cell with ⟨input, block, lane⟩
  fin_cases block
  · by_cases low : lane.val < 7
    · exact accepted_block0_lanes0to6_readback_both_inputs
        values packed input lane initial.oneNode initial.negativeNode
        initial.positiveNode initial.powerNode initial.constantNode
        equation one negative constant low
    · by_cases seven : lane.val = 7
      · have laneEq : lane = (7 : Fin 16) := Fin.ext seven
        subst lane
        have constantZero :
            (values.getD
              (initial.constantNode (input, (0 : Fin 2), (7 : Fin 16))) 0 : Goldilocks) = 0 := by
          simpa [initialConstant] using constant
        exact accepted_block0_lane7_readback_any_input values packed input
          initial.oneNode initial.negativeNode initial.positiveNode
          initial.powerNode initial.constantNode equation one constantZero position
      · have high : 8 ≤ lane.val := by omega
        exact accepted_block0_high_lane_frame_readback values packed input lane
          initial.oneNode initial.negativeNode initial.positiveNode
          initial.powerNode initial.constantNode high equation one constant
  · exact (accepted_block1_all_lanes_last_frame_readback
        kernel accepted input lane (by
          unfold nullifierFirstCall
          split <;> have := input.isLt <;> omega)
        values initial.oneNode initial.negativeNode initial.positiveNode
        initial.powerNode initial.constantNode equation one negative positive
        packedCanonical constant).1

end
end HegemonCrypto.SmallWood.SmzaRp05NullifierSource
