import Q38Rp05ExecutionBridgeTransportFourier

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

omit [Fintype Input] in
theorem indexed_raw_swap_response_fourier_state
    (key : Input) (index : Index)
    (state : ResponseCmsState Input ((Index → DigestRegister) × Work)) :
    indexedRawSwap key index (responseFourierState state) =
      responseFourierState (indexedRawSwap key index state) := by
  unfold indexedRawSwap
  rw [transport_response_fourier_state, raw_swap_response_fourier_state,
    transport_response_fourier_state]

end IndexedRawEnvironment
end

end HegemonCrypto.SmallWood.Q38Rp05ExecutionBridge
