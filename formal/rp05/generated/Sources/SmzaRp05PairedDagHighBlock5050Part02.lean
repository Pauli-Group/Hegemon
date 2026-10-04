import SmzaRp05PairedDagEdgeSupport

/-! Exact 16-node directed-edge check for current/reference DAG nodes 5082 through 5097. -/
namespace HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock5050Part02

open HegemonCrypto.SmallWood.SmzaRp05PairedHashDagData
open HegemonCrypto.SmallWood.SmzaRp05PairedDagEdgeSupport

set_option autoImplicit false
set_option maxRecDepth 1000000
set_option maxHeartbeats 1000000
set_option Elab.async false

private theorem edge_part_5082_checked :
    (List.range 16).all (fun i => directedEdgeCheck (5082 + i)) = true := by
  decide

theorem edge_subblock_5082 (node : Nat) (lower : 5082 ≤ node)
    (upper : node < 5098) : directedEdgeCheck node = true :=
  block_sound 5082 16 node edge_part_5082_checked lower upper

end HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock5050Part02
