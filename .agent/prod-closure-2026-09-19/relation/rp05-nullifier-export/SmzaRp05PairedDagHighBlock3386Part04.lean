import SmzaRp05PairedDagEdgeSupport

/-! Exact 16-node directed-edge check for current/reference DAG nodes 3450 through 3465. -/
namespace HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock3386Part04

open HegemonCrypto.SmallWood.SmzaRp05PairedHashDagData
open HegemonCrypto.SmallWood.SmzaRp05PairedDagEdgeSupport

set_option autoImplicit false
set_option maxRecDepth 1000000
set_option maxHeartbeats 1000000
set_option Elab.async false

private theorem edge_part_3450_checked :
    (List.range 16).all (fun i => directedEdgeCheck (3450 + i)) = true := by
  decide

theorem edge_subblock_3450 (node : Nat) (lower : 3450 ≤ node)
    (upper : node < 3466) : directedEdgeCheck node = true :=
  block_sound 3450 16 node edge_part_3450_checked lower upper

end HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock3386Part04
