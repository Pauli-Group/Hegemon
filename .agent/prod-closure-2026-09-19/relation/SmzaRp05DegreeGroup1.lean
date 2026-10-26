import SmzaRp05DegreeFastExpression

/-! Isolated four-block finite degree check for RP05 DAG nodes 512 through 1023. -/
namespace HegemonCrypto.SmallWood.SmzaRp05DegreeCertificateData

set_option autoImplicit false
set_option maxRecDepth 1000000
set_option maxHeartbeats 1000000
set_option Elab.async false

-- Keep each finite kernel reduction bounded to one existing 128-node block.
private theorem fast_degree_block_512 :
    (List.range 128).all (fun i => fastDegreeCheck (512 + i)) = true := by
  decide

private theorem fast_degree_block_640 :
    (List.range 128).all (fun i => fastDegreeCheck (640 + i)) = true := by
  decide

private theorem fast_degree_block_768 :
    (List.range 128).all (fun i => fastDegreeCheck (768 + i)) = true := by
  decide

private theorem fast_degree_block_896 :
    (List.range 128).all (fun i => fastDegreeCheck (896 + i)) = true := by
  decide

private theorem degree_block_of_fast (base : Nat)
    (checked : (List.range 128).all (fun i => fastDegreeCheck (base + i)) = true) :
    (List.range 128).all (fun i => degreeCheck (base + i)) = true := by
  apply List.all_eq_true.mpr
  intro i member
  have one := (List.all_eq_true.mp checked) i member
  simpa only [fastDegreeCheck_eq_degreeCheck] using one

theorem degree_group_1 :
    (List.range 4).all (fun j =>
      (List.range 128).all (fun i => degreeCheck ((4 * 1 + j) * 128 + i))) = true := by
  apply List.all_eq_true.mpr
  intro j member
  have bound : j < 4 := List.mem_range.mp member
  have cases : j = 0 ∨ j = 1 ∨ j = 2 ∨ j = 3 := by omega
  rcases cases with rfl | rfl | rfl | rfl
  · exact degree_block_of_fast 512 fast_degree_block_512
  · exact degree_block_of_fast 640 fast_degree_block_640
  · exact degree_block_of_fast 768 fast_degree_block_768
  · exact degree_block_of_fast 896 fast_degree_block_896

end HegemonCrypto.SmallWood.SmzaRp05DegreeCertificateData
