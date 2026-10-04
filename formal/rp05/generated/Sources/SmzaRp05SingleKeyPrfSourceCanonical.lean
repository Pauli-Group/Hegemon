import SmzaRp05Components
import HegemonCrypto.SmallWoodV8Smz9ProgramCanonicality

/-! Isolated canonicality proof for the current RP05 CSR expression table. -/
namespace HegemonCrypto.SmallWood.SmzaRp05SingleKeyPrfSourceCanonical

open Hegemon.Transaction.Poseidon2V8RelationProgram
open HegemonCrypto.SmallWood.SmzaRp05Components
open HegemonCrypto.SmallWood.V8Smz9ProgramCanonicality

set_option autoImplicit false
set_option maxRecDepth 1000000
set_option maxHeartbeats 1000000

theorem csrCanonical :
    ({ expressions := program.csrExpressions, roots := [] } :
      ExpressionProgram).Canonical true := by
  apply (checkExpressionProgram_eq_true _ _).mp
  decide

end HegemonCrypto.SmallWood.SmzaRp05SingleKeyPrfSourceCanonical
