import Mathlib.Tactic.IrreducibleDef

namespace HegemonCrypto.SmallWood.NativePrivateSpendQ58PublicFactorization
set_option autoImplicit false
set_option Elab.async false
set_option maxHeartbeats 0
set_option maxRecDepth 0

/-- Same addition, behind a kernel-irreducible value with its proved defining equation. -/
irreducible_def transcriptAdd {α : Type*} [Add α] (left right : α) : α := left + right

end HegemonCrypto.SmallWood.NativePrivateSpendQ58PublicFactorization
