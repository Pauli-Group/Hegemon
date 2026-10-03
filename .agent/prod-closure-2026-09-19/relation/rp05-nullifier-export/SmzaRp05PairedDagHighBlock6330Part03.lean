import SmzaRp05PairedDagEdgeSupport

/-! Exact 16-node directed-edge check for current/reference DAG nodes 6378 through 6393. -/
namespace HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock6330Part03

open HegemonCrypto.SmallWood.SmzaRp05PairedHashDagData
open HegemonCrypto.SmallWood.SmzaRp05PairedDagEdgeSupport

set_option autoImplicit false
set_option maxRecDepth 1000000
set_option maxHeartbeats 1000000
set_option Elab.async false

private theorem edge_part_6378_checked :
    (List.range 16).all (fun i => directedEdgeCheck (6378 + i)) = true := by
  decide

theorem edge_subblock_6378 (node : Nat) (lower : 6378 ≤ node)
    (upper : node < 6394) : directedEdgeCheck node = true :=
  block_sound 6378 16 node edge_part_6378_checked lower upper

end HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock6330Part03
