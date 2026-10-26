import SmzaRp05Components
import HegemonCrypto.SmallWoodV8Smz9ProgramCanonicality
import SmzaRp05CsrFinite
import HegemonCrypto.SmallWoodV8Smz9SemanticBinding

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
  have canonicalFalse :
      ({ expressions := program.csrExpressions, roots := [] } :
        ExpressionProgram).Canonical false := by
    simpa [program] using
      HegemonCrypto.SmallWood.SmzaRp05CsrFiniteData.csrProgramCanonical
  constructor
  · intro node expression found
    exact HegemonCrypto.SmallWood.V8Smz9SemanticBinding.canonical_without_rows_allows_rows
      (canonicalFalse.1 node expression found)
  · simp

end HegemonCrypto.SmallWood.SmzaRp05SingleKeyPrfSourceCanonical
