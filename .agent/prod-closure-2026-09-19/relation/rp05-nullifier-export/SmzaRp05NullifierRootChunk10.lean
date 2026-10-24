import SmzaRp05NullifierRootChunk00

/-! Finite exact current/reference root-shape checks for wires 316 through 331. -/
namespace HegemonCrypto.SmallWood.SmzaRp05NullifierRootChunk10

open HegemonCrypto.SmallWood.SmzaRp05NullifierRootChunk00

set_option autoImplicit false
set_option maxRecDepth 1000000
set_option maxHeartbeats 1000000
set_option Elab.async false

private theorem root_chunk10_part0_checked :
    (List.range 8).all (fun i => decide (RootShape (316 + i))) = true := by
  decide

private theorem root_chunk10_part1_checked :
    (List.range 8).all (fun i => decide (RootShape (324 + i))) = true := by
  decide

private theorem root_chunk10_checked :
    (List.range 16).all (fun i => decide (RootShape (316 + i))) = true := by
  apply List.all_eq_true.mpr
  intro i member
  have bound : i < 16 := List.mem_range.mp member
  by_cases below : i < 8
  · exact (List.all_eq_true.mp root_chunk10_part0_checked) i
      (List.mem_range.mpr below)
  have localBound : i - 8 < 8 := by omega
  have one := (List.all_eq_true.mp root_chunk10_part1_checked)
    (i - 8) (List.mem_range.mpr localBound)
  have indexEq : 324 + (i - 8) = 316 + i := by omega
  simpa only [indexEq] using one

theorem root_shape (i : Nat) (bound : i < 16) : RootShape (316 + i) := by
  have checked := (List.all_eq_true.mp root_chunk10_checked) i
    (List.mem_range.mpr bound)
  exact decide_eq_true_eq.mp checked

end HegemonCrypto.SmallWood.SmzaRp05NullifierRootChunk10
