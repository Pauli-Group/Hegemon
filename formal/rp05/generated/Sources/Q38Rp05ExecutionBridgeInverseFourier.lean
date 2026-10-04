import Q38Rp05ExecutionBridgeListFourier

namespace HegemonCrypto.SmallWood.Q38Rp05ExecutionBridge

open HegemonCrypto.SmallWood.V8Smz9HiddenLeafQrom
open HegemonCrypto.SmallWood.Q38WholeViewCmsSemantics
open HegemonCrypto.SmallWood.V8SmzaCmsIndexedSwap
open scoped BigOperators Classical

noncomputable section
set_option autoImplicit false
set_option Elab.async false
set_option maxHeartbeats 2000000
set_option maxRecDepth 10000

section IndexedRawEnvironment

variable {Input Work Index : Type}
variable [Fintype Input] [DecidableEq Input]
variable [Fintype Work] [DecidableEq Work]
variable [Fintype Index] [DecidableEq Index]

theorem response_fourier_inverse_raw_swap_list_fourier
    (keys : Index → Input) (indices : List Index)
    (state : ResponseCmsState Input ((Index → DigestRegister) × Work)) :
    responseFourierInverseState
        (rawSwapList keys indices (responseFourierState state)) =
      rawSwapList keys indices state := by
  rw [raw_swap_list_response_fourier_state,
    response_fourier_inverse_left]

end IndexedRawEnvironment
end

end HegemonCrypto.SmallWood.Q38Rp05ExecutionBridge
