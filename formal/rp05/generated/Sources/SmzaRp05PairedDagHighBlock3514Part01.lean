import SmzaRp05PairedDagEdgeSupport

/-! Exact 16-node directed-edge check for current/reference DAG nodes 3530 through 3545. -/
namespace HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock3514Part01

open HegemonCrypto.SmallWood.SmzaRp05PairedHashDagData
open HegemonCrypto.SmallWood.SmzaRp05PairedDagEdgeSupport

set_option autoImplicit false
set_option maxRecDepth 1000000
set_option maxHeartbeats 1000000
set_option Elab.async false

private theorem edge_part_3530_checked :
    (List.range 16).all (fun i => directedEdgeCheck (3530 + i)) = true := by
  decide

theorem edge_subblock_3530 (node : Nat) (lower : 3530 ≤ node)
    (upper : node < 3546) : directedEdgeCheck node = true :=
  block_sound 3530 16 node edge_part_3530_checked lower upper

end HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock3514Part01
