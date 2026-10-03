import SmzaRp05NullifierRootChunk00

/-! Finite exact current/reference root-shape checks for wires 256 through 275. -/
namespace HegemonCrypto.SmallWood.SmzaRp05NullifierRootChunk07

open HegemonCrypto.SmallWood.SmzaRp05NullifierRootChunk00

set_option autoImplicit false
set_option maxRecDepth 1000000
set_option maxHeartbeats 1000000
set_option Elab.async false

private theorem root_chunk07_checked :
    (List.range 20).all (fun i => decide (RootShape (256 + i))) = true := by
  decide

theorem root_shape (i : Nat) (bound : i < 20) : RootShape (256 + i) := by
  have checked := (List.all_eq_true.mp root_chunk07_checked) i
    (List.mem_range.mpr bound)
  exact decide_eq_true_eq.mp checked

end HegemonCrypto.SmallWood.SmzaRp05NullifierRootChunk07
