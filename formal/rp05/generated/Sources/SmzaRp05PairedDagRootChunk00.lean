import SmzaRp05PairedDagEdgeSupport

/-! Finite paired-root schedule checks for wires 0 through 127. -/
namespace HegemonCrypto.SmallWood.SmzaRp05PairedDagRootChunk00

open HegemonCrypto.SmallWood.SmzaRp05PairedHashDagData
open HegemonCrypto.SmallWood.SmzaRp05PairedDagEdgeSupport

set_option autoImplicit false
set_option maxRecDepth 1000000
set_option maxHeartbeats 1000000
set_option Elab.async false

private theorem paired_roots_00_checked :
    (List.range 128).all (fun i => pairedRootCheck (0 + i)) = true := by
  decide

theorem paired_root_check_00 (wire : Nat) (lower : 0 ≤ wire)
    (upper : wire < 128) : pairedRootCheck wire = true :=
  paired_root_block_sound 0 128 wire paired_roots_00_checked lower upper

end HegemonCrypto.SmallWood.SmzaRp05PairedDagRootChunk00
