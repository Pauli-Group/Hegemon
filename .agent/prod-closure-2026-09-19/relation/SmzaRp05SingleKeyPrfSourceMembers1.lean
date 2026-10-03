import SmzaRp05SingleKeyPrfSourceData
import Mathlib.Tactic.FinCases
import Mathlib.Data.Fintype.Basic

namespace HegemonCrypto.SmallWood.SmzaRp05SingleKeyPrfSourceMembers1
open HegemonCrypto.SmallWood.SmzaRp05Components
open HegemonCrypto.SmallWood.SmzaRp05SingleKeyPrfSourceData
set_option autoImplicit false
set_option maxRecDepth 1000000
set_option maxHeartbeats 1000000

theorem initial (lane : Fin 6) :
    initialAttempt ⟨lane.val + 6, by omega⟩ ∈ program.csrAttempts := by
  fin_cases lane <;> decide

end HegemonCrypto.SmallWood.SmzaRp05SingleKeyPrfSourceMembers1
