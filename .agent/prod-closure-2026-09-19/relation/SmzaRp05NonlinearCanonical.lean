import SmzaRp05Components
import HegemonCrypto.SmallWoodV8Smz9ProgramCanonicality

/-! Exact canonicality of the SHA-512-pinned current RP05 nonlinear DAG and root table. -/
namespace HegemonCrypto.SmallWood.SmzaRp05NonlinearCanonical

open Hegemon.Transaction.Poseidon2V8RelationProgram
open HegemonCrypto.SmallWood.V8Smz9ProgramCanonicality
open SmzaRp05Components

set_option autoImplicit false
set_option maxRecDepth 1000000
set_option maxHeartbeats 1000000
set_option Elab.async false

theorem canonical : program.nonlinearExecutable.Canonical true := by
  apply (checkExpressionProgram_eq_true _ _).mp
  decide

end HegemonCrypto.SmallWood.SmzaRp05NonlinearCanonical
