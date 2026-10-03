import SmzaRp05PairedDagEdgeSupport

/-! Exact 16-node directed-edge check for current/reference DAG nodes 3818 through 3833. -/
namespace HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock3770Part03

open HegemonCrypto.SmallWood.SmzaRp05PairedHashDagData
open HegemonCrypto.SmallWood.SmzaRp05PairedDagEdgeSupport

set_option autoImplicit false
set_option maxRecDepth 1000000
set_option maxHeartbeats 1000000
set_option Elab.async false

private theorem edge_part_3818_checked :
    (List.range 16).all (fun i => directedEdgeCheck (3818 + i)) = true := by
  decide

theorem edge_subblock_3818 (node : Nat) (lower : 3818 ≤ node)
    (upper : node < 3834) : directedEdgeCheck node = true :=
  block_sound 3818 16 node edge_part_3818_checked lower upper

end HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock3770Part03
