import SmzaRp05PairedDagEdgeSupport

/-! Exact 16-node directed-edge check for current/reference DAG nodes 5642 through 5657. -/
namespace HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock5562Part05

open HegemonCrypto.SmallWood.SmzaRp05PairedHashDagData
open HegemonCrypto.SmallWood.SmzaRp05PairedDagEdgeSupport

set_option autoImplicit false
set_option maxRecDepth 1000000
set_option maxHeartbeats 1000000
set_option Elab.async false

private theorem edge_part_5642_checked :
    (List.range 16).all (fun i => directedEdgeCheck (5642 + i)) = true := by
  decide

theorem edge_subblock_5642 (node : Nat) (lower : 5642 ≤ node)
    (upper : node < 5658) : directedEdgeCheck node = true :=
  block_sound 5642 16 node edge_part_5642_checked lower upper

end HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock5562Part05
