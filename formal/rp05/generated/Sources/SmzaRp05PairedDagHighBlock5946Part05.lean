import SmzaRp05PairedDagEdgeSupport

/-! Exact 16-node directed-edge check for current/reference DAG nodes 6026 through 6041. -/
namespace HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock5946Part05

open HegemonCrypto.SmallWood.SmzaRp05PairedHashDagData
open HegemonCrypto.SmallWood.SmzaRp05PairedDagEdgeSupport

set_option autoImplicit false
set_option maxRecDepth 1000000
set_option maxHeartbeats 1000000
set_option Elab.async false

private theorem edge_part_6026_checked :
    (List.range 16).all (fun i => directedEdgeCheck (6026 + i)) = true := by
  decide

theorem edge_subblock_6026 (node : Nat) (lower : 6026 ≤ node)
    (upper : node < 6042) : directedEdgeCheck node = true :=
  block_sound 6026 16 node edge_part_6026_checked lower upper

end HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock5946Part05
