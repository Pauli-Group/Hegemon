import SmzaRp05PairedDagEdgeSupport

/-! Exact 16-node directed-edge check for current/reference DAG nodes 5578 through 5593. -/
namespace HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock5562Part01

open HegemonCrypto.SmallWood.SmzaRp05PairedHashDagData
open HegemonCrypto.SmallWood.SmzaRp05PairedDagEdgeSupport

set_option autoImplicit false
set_option maxRecDepth 1000000
set_option maxHeartbeats 1000000
set_option Elab.async false

private theorem edge_part_5578_checked :
    (List.range 16).all (fun i => directedEdgeCheck (5578 + i)) = true := by
  decide

theorem edge_subblock_5578 (node : Nat) (lower : 5578 ≤ node)
    (upper : node < 5594) : directedEdgeCheck node = true :=
  block_sound 5578 16 node edge_part_5578_checked lower upper

end HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock5562Part01
