import SmzaRp05PairedDagEdgeSupport

/-! Exact 16-node directed-edge check for current/reference DAG nodes 6442 through 6457. -/
namespace HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock6330Part07

open HegemonCrypto.SmallWood.SmzaRp05PairedHashDagData
open HegemonCrypto.SmallWood.SmzaRp05PairedDagEdgeSupport

set_option autoImplicit false
set_option maxRecDepth 1000000
set_option maxHeartbeats 1000000
set_option Elab.async false

private theorem edge_part_6442_checked :
    (List.range 16).all (fun i => directedEdgeCheck (6442 + i)) = true := by
  decide

theorem edge_subblock_6442 (node : Nat) (lower : 6442 ≤ node)
    (upper : node < 6458) : directedEdgeCheck node = true :=
  block_sound 6442 16 node edge_part_6442_checked lower upper

end HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock6330Part07
