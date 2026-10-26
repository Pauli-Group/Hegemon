import SmzaRp05NullifierRootChunk00

/-! Finite exact current/reference root-shape checks for wires 96 through 175. -/
namespace HegemonCrypto.SmallWood.SmzaRp05NullifierRootChunk02

open HegemonCrypto.SmallWood.SmzaRp05NullifierRootChunk00

set_option autoImplicit false
set_option maxRecDepth 1000000
set_option maxHeartbeats 1000000
set_option Elab.async false

private theorem root_chunk02_part0_checked :
    (List.range 16).all (fun i => decide (RootShape (96 + i))) = true := by
  decide

private theorem root_chunk02_part1_checked :
    (List.range 16).all (fun i => decide (RootShape (112 + i))) = true := by
  decide

private theorem root_chunk02_part2_checked :
    (List.range 16).all (fun i => decide (RootShape (128 + i))) = true := by
  decide

private theorem root_chunk02_part3_checked :
    (List.range 16).all (fun i => decide (RootShape (144 + i))) = true := by
  decide

private theorem root_chunk02_part4_checked :
    (List.range 16).all (fun i => decide (RootShape (160 + i))) = true := by
  decide

private theorem root_chunk02_checked :
    (List.range 80).all (fun i => decide (RootShape (96 + i))) = true := by
  apply List.all_eq_true.mpr
  intro i member
  have bound : i < 80 := List.mem_range.mp member
  by_cases below0 : i < 16
  · exact (List.all_eq_true.mp root_chunk02_part0_checked) i
      (List.mem_range.mpr below0)
  by_cases below1 : i < 32
  · have localBound : i - 16 < 16 := by omega
    have one := (List.all_eq_true.mp root_chunk02_part1_checked)
      (i - 16) (List.mem_range.mpr localBound)
    have indexEq : 112 + (i - 16) = 96 + i := by omega
    simpa only [indexEq] using one
  by_cases below2 : i < 48
  · have localBound : i - 32 < 16 := by omega
    have one := (List.all_eq_true.mp root_chunk02_part2_checked)
      (i - 32) (List.mem_range.mpr localBound)
    have indexEq : 128 + (i - 32) = 96 + i := by omega
    simpa only [indexEq] using one
  by_cases below3 : i < 64
  · have localBound : i - 48 < 16 := by omega
    have one := (List.all_eq_true.mp root_chunk02_part3_checked)
      (i - 48) (List.mem_range.mpr localBound)
    have indexEq : 144 + (i - 48) = 96 + i := by omega
    simpa only [indexEq] using one
  have localBound : i - 64 < 16 := by omega
  have one := (List.all_eq_true.mp root_chunk02_part4_checked)
    (i - 64) (List.mem_range.mpr localBound)
  have indexEq : 160 + (i - 64) = 96 + i := by omega
  simpa only [indexEq] using one

theorem root_shape (i : Nat) (bound : i < 80) : RootShape (96 + i) := by
  have checked := (List.all_eq_true.mp root_chunk02_checked) i
    (List.mem_range.mpr bound)
  exact decide_eq_true_eq.mp checked

end HegemonCrypto.SmallWood.SmzaRp05NullifierRootChunk02
