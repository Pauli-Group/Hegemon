import SmzaRp05PairedDagEdgeSupport

/-! Exact 16-node directed-edge check for current/reference DAG nodes 5802 through 5817. -/
namespace HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock5690Part07

open HegemonCrypto.SmallWood.SmzaRp05PairedHashDagData
open HegemonCrypto.SmallWood.SmzaRp05PairedDagEdgeSupport

set_option autoImplicit false
set_option maxRecDepth 1000000
set_option maxHeartbeats 1000000
set_option Elab.async false

private theorem edge_part_5802_checked :
    (List.range 16).all (fun i => directedEdgeCheck (5802 + i)) = true := by
  decide

theorem edge_subblock_5802 (node : Nat) (lower : 5802 ≤ node)
    (upper : node < 5818) : directedEdgeCheck node = true :=
  block_sound 5802 16 node edge_part_5802_checked lower upper

end HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock5690Part07
