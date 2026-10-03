import SmzaRp05PairedDagEdgeSupport

/-! Exact 16-node directed-edge check for current/reference DAG nodes 3578 through 3593. -/
namespace HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock3514Part04

open HegemonCrypto.SmallWood.SmzaRp05PairedHashDagData
open HegemonCrypto.SmallWood.SmzaRp05PairedDagEdgeSupport

set_option autoImplicit false
set_option maxRecDepth 1000000
set_option maxHeartbeats 1000000
set_option Elab.async false

private theorem edge_part_3578_checked :
    (List.range 16).all (fun i => directedEdgeCheck (3578 + i)) = true := by
  decide

theorem edge_subblock_3578 (node : Nat) (lower : 3578 ≤ node)
    (upper : node < 3594) : directedEdgeCheck node = true :=
  block_sound 3578 16 node edge_part_3578_checked lower upper

end HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock3514Part04
