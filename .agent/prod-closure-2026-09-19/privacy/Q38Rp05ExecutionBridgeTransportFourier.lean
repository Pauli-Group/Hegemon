import Q38Rp05ExecutionBridgeRawFourier
import Q38CmsIndexedSwap

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

variable {Input Work : Type}
variable [Fintype Input] [DecidableEq Input]
variable [Fintype Work] [DecidableEq Work]

omit [Fintype Input] [Fintype Work] [DecidableEq Input] [DecidableEq Work] in
theorem transport_response_fourier_state {OtherWork : Type}
    [Fintype OtherWork] [DecidableEq OtherWork]
    (equivalence : Work ≃ OtherWork) (state : ResponseCmsState Input Work) :
    transportWorkspace equivalence (responseFourierState state) =
      responseFourierState (transportWorkspace equivalence state) := by
  funext basis
  simp [transportWorkspace, responseFourierState, digestResponseFourier]

end IndexedRawEnvironment
end

end HegemonCrypto.SmallWood.Q38Rp05ExecutionBridge
