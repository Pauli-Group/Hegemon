import SmzaRp05PairedDagEdgeSupport

/-! Finite paired-root schedule checks for wires 128 through 255. -/
namespace HegemonCrypto.SmallWood.SmzaRp05PairedDagRootChunk01

open HegemonCrypto.SmallWood.SmzaRp05PairedHashDagData
open HegemonCrypto.SmallWood.SmzaRp05PairedDagEdgeSupport

set_option autoImplicit false
set_option maxRecDepth 1000000
set_option maxHeartbeats 1000000
set_option Elab.async false

private theorem paired_roots_01_checked :
    (List.range 128).all (fun i => pairedRootCheck (128 + i)) = true := by
  decide

theorem paired_root_check_01 (wire : Nat) (lower : 128 ≤ wire)
    (upper : wire < 256) : pairedRootCheck wire = true :=
  paired_root_block_sound 128 128 wire paired_roots_01_checked lower upper

end HegemonCrypto.SmallWood.SmzaRp05PairedDagRootChunk01
