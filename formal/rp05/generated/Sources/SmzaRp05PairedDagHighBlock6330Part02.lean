import SmzaRp05PairedDagEdgeSupport

/-! Exact 16-node directed-edge check for current/reference DAG nodes 6362 through 6377. -/
namespace HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock6330Part02

open HegemonCrypto.SmallWood.SmzaRp05PairedHashDagData
open HegemonCrypto.SmallWood.SmzaRp05PairedDagEdgeSupport

set_option autoImplicit false
set_option maxRecDepth 1000000
set_option maxHeartbeats 1000000
set_option Elab.async false

private theorem edge_part_6362_checked :
    (List.range 16).all (fun i => directedEdgeCheck (6362 + i)) = true := by
  decide

theorem edge_subblock_6362 (node : Nat) (lower : 6362 ≤ node)
    (upper : node < 6378) : directedEdgeCheck node = true :=
  block_sound 6362 16 node edge_part_6362_checked lower upper

end HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock6330Part02
