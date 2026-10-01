import SmzaRp05PairedDagEdgeSupport

/-! Exact 16-node directed-edge check for current/reference DAG nodes 6490 through 6505. -/
namespace HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock6458Part02

open HegemonCrypto.SmallWood.SmzaRp05PairedHashDagData
open HegemonCrypto.SmallWood.SmzaRp05PairedDagEdgeSupport

set_option autoImplicit false
set_option maxRecDepth 1000000
set_option maxHeartbeats 1000000
set_option Elab.async false

private theorem edge_part_6490_checked :
    (List.range 16).all (fun i => directedEdgeCheck (6490 + i)) = true := by
  decide

theorem edge_subblock_6490 (node : Nat) (lower : 6490 ≤ node)
    (upper : node < 6506) : directedEdgeCheck node = true :=
  block_sound 6490 16 node edge_part_6490_checked lower upper

end HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock6458Part02
