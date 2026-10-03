import SmzaRp05PairedDagEdgeSupport

/-! Exact 16-node directed-edge check for current/reference DAG nodes 7034 through 7049. -/
namespace HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock6970Part04

open HegemonCrypto.SmallWood.SmzaRp05PairedHashDagData
open HegemonCrypto.SmallWood.SmzaRp05PairedDagEdgeSupport

set_option autoImplicit false
set_option maxRecDepth 1000000
set_option maxHeartbeats 1000000
set_option Elab.async false

private theorem edge_part_7034_checked :
    (List.range 16).all (fun i => directedEdgeCheck (7034 + i)) = true := by
  decide

theorem edge_subblock_7034 (node : Nat) (lower : 7034 ≤ node)
    (upper : node < 7050) : directedEdgeCheck node = true :=
  block_sound 7034 16 node edge_part_7034_checked lower upper

end HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock6970Part04
