import SmzaRp05PairedDagEdgeSupport

/-! Exact special-node directed-edge checks outside the low and high ranges. -/
namespace HegemonCrypto.SmallWood.SmzaRp05PairedDagSpecialEdges

open HegemonCrypto.SmallWood.SmzaRp05PairedHashDagData

set_option autoImplicit false
set_option maxRecDepth 1000000
set_option maxHeartbeats 1000000
set_option Elab.async false

theorem checked_special_1387 : directedEdgeCheck 1387 = true := by decide
theorem checked_special_1390 : directedEdgeCheck 1390 = true := by decide
theorem checked_special_1393 : directedEdgeCheck 1393 = true := by decide

end HegemonCrypto.SmallWood.SmzaRp05PairedDagSpecialEdges
