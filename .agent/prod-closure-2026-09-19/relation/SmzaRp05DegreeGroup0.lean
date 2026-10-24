import SmzaRp05DegreeFastExpression

/-! Bounded four-block pilot for RP05 DAG node degrees 0 through 511. -/
namespace HegemonCrypto.SmallWood.SmzaRp05DegreeCertificateData

set_option autoImplicit false
set_option maxRecDepth 1000000
set_option maxHeartbeats 1000000
set_option Elab.async false

-- Keep each finite kernel reduction bounded to one existing 128-node block.
private theorem fast_degree_block_0 :
    (List.range 128).all (fun i => fastDegreeCheck (0 + i)) = true := by
  decide

private theorem fast_degree_block_128 :
    (List.range 128).all (fun i => fastDegreeCheck (128 + i)) = true := by
  decide

private theorem fast_degree_block_256 :
    (List.range 128).all (fun i => fastDegreeCheck (256 + i)) = true := by
  decide

private theorem fast_degree_block_384 :
    (List.range 128).all (fun i => fastDegreeCheck (384 + i)) = true := by
  decide

private theorem degree_block_of_fast (base : Nat)
    (checked : (List.range 128).all (fun i => fastDegreeCheck (base + i)) = true) :
    (List.range 128).all (fun i => degreeCheck (base + i)) = true := by
  apply List.all_eq_true.mpr
  intro i member
  have one := (List.all_eq_true.mp checked) i member
  simpa only [fastDegreeCheck_eq_degreeCheck] using one

theorem degree_group_0 :
    (List.range 4).all (fun j =>
      (List.range 128).all (fun i => degreeCheck ((4 * 0 + j) * 128 + i))) = true := by
  apply List.all_eq_true.mpr
  intro j member
  have bound : j < 4 := List.mem_range.mp member
  have cases : j = 0 ∨ j = 1 ∨ j = 2 ∨ j = 3 := by omega
  rcases cases with rfl | rfl | rfl | rfl
  · exact degree_block_of_fast 0 fast_degree_block_0
  · exact degree_block_of_fast 128 fast_degree_block_128
  · exact degree_block_of_fast 256 fast_degree_block_256
  · exact degree_block_of_fast 384 fast_degree_block_384

end HegemonCrypto.SmallWood.SmzaRp05DegreeCertificateData
