import Q38Rp05ExecutionBridgeIndexedFourier
import Q38Rp05ExecutionBridgeListMap

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
theorem raw_swap_list_response_fourier_state
    (keys : Index → Input) (indices : List Index)
    (state : ResponseCmsState Input ((Index → DigestRegister) × Work)) :
    rawSwapList keys indices (responseFourierState state) =
      responseFourierState (rawSwapList keys indices state) := by
  exact listAction_commute
    (step := fun index state => indexedRawSwap (keys index) index state)
    (run := rawSwapList keys)
    (runNil := by intro state; rfl)
    (runCons := by intro index remaining state; rfl)
    (transform := responseFourierState)
    (fun index state => indexed_raw_swap_response_fourier_state
      (keys index) index state) indices state

end IndexedRawEnvironment
end

end HegemonCrypto.SmallWood.Q38Rp05ExecutionBridge
