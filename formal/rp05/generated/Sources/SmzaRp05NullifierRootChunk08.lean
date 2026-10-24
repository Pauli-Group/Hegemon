import SmzaRp05NullifierRootChunk00

/-! Finite exact current/reference root-shape checks for wires 276 through 295. -/
namespace HegemonCrypto.SmallWood.SmzaRp05NullifierRootChunk08

open HegemonCrypto.SmallWood.SmzaRp05NullifierRootChunk00

set_option autoImplicit false
set_option maxRecDepth 1000000
set_option maxHeartbeats 1000000
set_option Elab.async false

private theorem root_chunk08_part0_checked :
    (List.range 10).all (fun i => decide (RootShape (276 + i))) = true := by
  decide

private theorem root_chunk08_part1_checked :
    (List.range 10).all (fun i => decide (RootShape (286 + i))) = true := by
  decide

private theorem root_chunk08_checked :
    (List.range 20).all (fun i => decide (RootShape (276 + i))) = true := by
  apply List.all_eq_true.mpr
  intro i member
  have bound : i < 20 := List.mem_range.mp member
  by_cases below : i < 10
  · exact (List.all_eq_true.mp root_chunk08_part0_checked) i
      (List.mem_range.mpr below)
  have localBound : i - 10 < 10 := by omega
  have one := (List.all_eq_true.mp root_chunk08_part1_checked)
    (i - 10) (List.mem_range.mpr localBound)
  have indexEq : 286 + (i - 10) = 276 + i := by omega
  simpa only [indexEq] using one

theorem root_shape (i : Nat) (bound : i < 20) : RootShape (276 + i) := by
  have checked := (List.all_eq_true.mp root_chunk08_checked) i
    (List.mem_range.mpr bound)
  exact decide_eq_true_eq.mp checked

end HegemonCrypto.SmallWood.SmzaRp05NullifierRootChunk08
