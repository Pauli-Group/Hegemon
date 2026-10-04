import Q38WholeViewCmsSemantics
import Q38CmsSwapConjugation

namespace HegemonCrypto.SmallWood.Q38Rp05ExecutionBridge

open HegemonCrypto.SmallWood.V8Smz9HiddenLeafQrom
open HegemonCrypto.SmallWood.V8Smz9HiddenPatch
open HegemonCrypto.SmallWood.Q38WholeViewCmsSemantics
open HegemonCrypto.SmallWood.V8SmzaCmsSwapConjugation
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

omit [Fintype Input] [Fintype Work] [DecidableEq Work] in
theorem raw_swap_response_fourier_state
    (key : Input)
    (state : ResponseCmsState Input (DigestRegister × Work)) :
    rawSwap key (responseFourierState state) =
      responseFourierState (rawSwap key state) := by
  funext basis
  cases value : basis.database key <;>
    simp [rawSwap, swapBasis, value, responseFourierState,
      digestResponseFourier]

end IndexedRawEnvironment
end

end HegemonCrypto.SmallWood.Q38Rp05ExecutionBridge
