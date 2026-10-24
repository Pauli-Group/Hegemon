import SmzaRp05SupplyClosureCsrChunks
import SmzaRp05SingleKeyPrfSourceData
import Mathlib.Tactic.FinCases
import Mathlib.Data.Fintype.Basic

namespace HegemonCrypto.SmallWood.SmzaRp05SingleKeyPrfSourceMembers2
open HegemonCrypto.SmallWood.SmzaRp05Components
open HegemonCrypto.SmallWood.SmzaRp05SingleKeyPrfSourceData
set_option autoImplicit false
set_option maxRecDepth 1000000
set_option maxHeartbeats 1000000

theorem initial (lane : Fin 4) :
    initialAttempt ⟨lane.val + 12, by omega⟩ ∈ program.csrAttempts := by
  apply SmzaRp05SupplyClosureCsrChunks.chunk_member
    (chunk := (15736 + (lane.val + 12)) / 32) (by omega)
  fin_cases lane <;> decide +revert

theorem legacyFirstTwo (lane : Fin 2) :
    legacyAttempt ⟨lane.val, by omega⟩ ∈ program.csrAttempts := by
  apply SmzaRp05SupplyClosureCsrChunks.chunk_member
    (chunk := (15752 + lane.val) / 32) (by omega)
  fin_cases lane <;> decide +revert

end HegemonCrypto.SmallWood.SmzaRp05SingleKeyPrfSourceMembers2
