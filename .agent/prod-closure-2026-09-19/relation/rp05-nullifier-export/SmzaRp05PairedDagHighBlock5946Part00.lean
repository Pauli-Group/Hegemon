import SmzaRp05PairedDagEdgeSupport

/-! Exact 16-node directed-edge check for current/reference DAG nodes 5946 through 5961. -/
namespace HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock5946Part00

open HegemonCrypto.SmallWood.SmzaRp05PairedHashDagData
open HegemonCrypto.SmallWood.SmzaRp05PairedDagEdgeSupport

set_option autoImplicit false
set_option maxRecDepth 1000000
set_option maxHeartbeats 1000000
set_option Elab.async false

private theorem edge_part_5946_checked :
    (List.range 16).all (fun i => directedEdgeCheck (5946 + i)) = true := by
  decide

theorem edge_subblock_5946 (node : Nat) (lower : 5946 ≤ node)
    (upper : node < 5962) : directedEdgeCheck node = true :=
  block_sound 5946 16 node edge_part_5946_checked lower upper

end HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock5946Part00
