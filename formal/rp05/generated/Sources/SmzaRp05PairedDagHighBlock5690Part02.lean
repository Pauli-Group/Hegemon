import SmzaRp05PairedDagEdgeSupport

/-! Exact 16-node directed-edge check for current/reference DAG nodes 5722 through 5737. -/
namespace HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock5690Part02

open HegemonCrypto.SmallWood.SmzaRp05PairedHashDagData
open HegemonCrypto.SmallWood.SmzaRp05PairedDagEdgeSupport

set_option autoImplicit false
set_option maxRecDepth 1000000
set_option maxHeartbeats 1000000
set_option Elab.async false

private theorem edge_part_5722_checked :
    (List.range 16).all (fun i => directedEdgeCheck (5722 + i)) = true := by
  decide

theorem edge_subblock_5722 (node : Nat) (lower : 5722 ≤ node)
    (upper : node < 5738) : directedEdgeCheck node = true :=
  block_sound 5722 16 node edge_part_5722_checked lower upper

end HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock5690Part02
