import SmzaRp05PairedHashDagData

/-! Small arithmetic adapter for projecting finite directed-edge blocks. -/
namespace HegemonCrypto.SmallWood.SmzaRp05PairedDagEdgeSupport

open HegemonCrypto.SmallWood.SmzaRp05PairedHashDagData

set_option autoImplicit false

theorem block_sound (offset count node : Nat)
    (checked : (List.range count).all
      (fun i => directedEdgeCheck (offset + i)) = true)
    (lower : offset ≤ node) (upper : node < offset + count) :
    directedEdgeCheck node = true := by
  have offsetBound : node - offset < count := by
    rw [Nat.sub_lt_iff_lt_add lower]
    simpa [Nat.add_comm] using upper
  have one := (List.all_eq_true.mp checked) (node - offset)
    (List.mem_range.mpr offsetBound)
  have same : offset + (node - offset) = node := Nat.add_sub_of_le lower
  simpa [same] using one

theorem paired_root_block_sound (offset count wire : Nat)
    (checked : (List.range count).all
      (fun i => pairedRootCheck (offset + i)) = true)
    (lower : offset ≤ wire) (upper : wire < offset + count) :
    pairedRootCheck wire = true := by
  have offsetBound : wire - offset < count := by
    rw [Nat.sub_lt_iff_lt_add lower]
    simpa [Nat.add_comm] using upper
  have one := (List.all_eq_true.mp checked) (wire - offset)
    (List.mem_range.mpr offsetBound)
  have same : offset + (wire - offset) = wire := Nat.add_sub_of_le lower
  simpa [same] using one

end HegemonCrypto.SmallWood.SmzaRp05PairedDagEdgeSupport
