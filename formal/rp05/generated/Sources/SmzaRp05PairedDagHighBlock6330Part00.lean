import SmzaRp05PairedDagEdgeSupport

/-! Exact 16-node directed-edge check for current/reference DAG nodes 6330 through 6345. -/
namespace HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock6330Part00

open HegemonCrypto.SmallWood.SmzaRp05PairedHashDagData
open HegemonCrypto.SmallWood.SmzaRp05PairedDagEdgeSupport

set_option autoImplicit false
set_option maxRecDepth 1000000
set_option maxHeartbeats 1000000
set_option Elab.async false

private theorem edge_part_6330_checked :
    (List.range 16).all (fun i => directedEdgeCheck (6330 + i)) = true := by
  decide

theorem edge_subblock_6330 (node : Nat) (lower : 6330 ≤ node)
    (upper : node < 6346) : directedEdgeCheck node = true :=
  block_sound 6330 16 node edge_part_6330_checked lower upper

end HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock6330Part00
