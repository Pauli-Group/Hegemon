import SmzaRp05PairedDagEdgeSupport

/-! Exact 16-node directed-edge check for current/reference DAG nodes 3850 through 3865. -/
namespace HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock3770Part05

open HegemonCrypto.SmallWood.SmzaRp05PairedHashDagData
open HegemonCrypto.SmallWood.SmzaRp05PairedDagEdgeSupport

set_option autoImplicit false
set_option maxRecDepth 1000000
set_option maxHeartbeats 1000000
set_option Elab.async false

private theorem edge_part_3850_checked :
    (List.range 16).all (fun i => directedEdgeCheck (3850 + i)) = true := by
  decide

theorem edge_subblock_3850 (node : Nat) (lower : 3850 ≤ node)
    (upper : node < 3866) : directedEdgeCheck node = true :=
  block_sound 3850 16 node edge_part_3850_checked lower upper

end HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock3770Part05
