import NullifierLane7FrameReadbackLuna

/-! Input-generic accepted-cell contract for block zero, lane seven. -/

namespace HegemonCrypto.SmallWood.SmzaRp05NullifierSource

open _root_.Hegemon.Transaction.Poseidon2V8DecoderRefinement
  (hashInitialIndex)
open _root_.HegemonCrypto.SmallWood.V8Smz9SemanticDenseRange
open _root_.HegemonCrypto.SmallWood.V8Smz9SemanticDecoder
open _root_.HegemonCrypto.SmallWood.SmzaRp05NullifierBinding
open _root_.HegemonCrypto.SmallWood.SmzaRp05TypedRelation
open _root_.Hegemon.Transaction
open scoped Classical

noncomputable section
set_option autoImplicit false
set_option maxHeartbeats 4000000

/-- For either input, a block-zero lane-seven accepted CSR equation determines
the copied hash value from the exact first-frame preimage lane. The premises
are field-level accepted-cell evidence, not a construction of that evidence
from the production acceptance path. -/
theorem accepted_block0_lane7_readback_any_input
    (values packed : List Nat) (input : Fin 2)
    (oneNode negativeNode positiveNode : Nat)
    (powerNode : Nat → Nat) (constantNode : InitialCell → Nat)
    (equation : csrFieldSum values packed
      (initialTerms oneNode negativeNode positiveNode powerNode
        (input, (0 : Fin 2), (7 : Fin 16))) =
        (values.getD
          (constantNode (input, (0 : Fin 2), (7 : Fin 16))) 0 : Goldilocks))
    (one : (values.getD oneNode 0 : Goldilocks) = 1)
    (constantZero :
      (values.getD
        (constantNode (input, (0 : Fin 2), (7 : Fin 16))) 0 : Goldilocks) = 0)
    (position : csrFieldSum values packed (positionTerms input powerNode) =
      -(projectPosition packed input.val : Goldilocks)) :
    (packed.getD
        (hashInitialIndex (callOf (input, (0 : Fin 2), (7 : Fin 16))) 7) 0 : Goldilocks) =
      ((firstFrame (nullifierPreimage packed input)).getD 7 0 : Goldilocks) := by
  exact initial_lane7_field_implies_first_frame_readback
    values packed input (0 : Fin 2) (7 : Fin 16)
    oneNode negativeNode positiveNode powerNode constantNode
    rfl rfl equation one constantZero position

end
end HegemonCrypto.SmallWood.SmzaRp05NullifierSource
