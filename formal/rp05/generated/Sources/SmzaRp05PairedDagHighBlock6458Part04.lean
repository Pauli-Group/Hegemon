import SmzaRp05PairedDagEdgeSupport

/-! Exact 16-node directed-edge check for current/reference DAG nodes 6522 through 6537. -/
namespace HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock6458Part04

open HegemonCrypto.SmallWood.SmzaRp05PairedHashDagData
open HegemonCrypto.SmallWood.SmzaRp05PairedDagEdgeSupport

set_option autoImplicit false
set_option maxRecDepth 1000000
set_option maxHeartbeats 1000000
set_option Elab.async false

private theorem edge_part_6522_checked :
    (List.range 16).all (fun i => directedEdgeCheck (6522 + i)) = true := by
  decide

theorem edge_subblock_6522 (node : Nat) (lower : 6522 ≤ node)
    (upper : node < 6538) : directedEdgeCheck node = true :=
  block_sound 6522 16 node edge_part_6522_checked lower upper

end HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock6458Part04
