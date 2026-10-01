import SmzaRp05PairedDagEdgeSupport

/-! Exact 16-node directed-edge check for current/reference DAG nodes 3498 through 3513. -/
namespace HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock3386Part07

open HegemonCrypto.SmallWood.SmzaRp05PairedHashDagData
open HegemonCrypto.SmallWood.SmzaRp05PairedDagEdgeSupport

set_option autoImplicit false
set_option maxRecDepth 1000000
set_option maxHeartbeats 1000000
set_option Elab.async false

private theorem edge_part_3498_checked :
    (List.range 16).all (fun i => directedEdgeCheck (3498 + i)) = true := by
  decide

theorem edge_subblock_3498 (node : Nat) (lower : 3498 ≤ node)
    (upper : node < 3514) : directedEdgeCheck node = true :=
  block_sound 3498 16 node edge_part_3498_checked lower upper

end HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock3386Part07
