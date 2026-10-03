import SmzaRp05PairedDagEdgeSupport

/-! Finite paired-root schedule checks for wires 256 through 331. -/
namespace HegemonCrypto.SmallWood.SmzaRp05PairedDagRootChunk02

open HegemonCrypto.SmallWood.SmzaRp05PairedHashDagData
open HegemonCrypto.SmallWood.SmzaRp05PairedDagEdgeSupport

set_option autoImplicit false
set_option maxRecDepth 1000000
set_option maxHeartbeats 1000000
set_option Elab.async false

private theorem paired_roots_02_checked :
    (List.range 76).all (fun i => pairedRootCheck (256 + i)) = true := by
  decide

theorem paired_root_check_02 (wire : Nat) (lower : 256 ≤ wire)
    (upper : wire < 332) : pairedRootCheck wire = true :=
  paired_root_block_sound 256 76 wire paired_roots_02_checked lower upper

end HegemonCrypto.SmallWood.SmzaRp05PairedDagRootChunk02
