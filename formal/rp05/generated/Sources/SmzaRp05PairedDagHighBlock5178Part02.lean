import SmzaRp05PairedDagEdgeSupport

/-! Exact 16-node directed-edge check for current/reference DAG nodes 5210 through 5225. -/
namespace HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock5178Part02

open HegemonCrypto.SmallWood.SmzaRp05PairedHashDagData
open HegemonCrypto.SmallWood.SmzaRp05PairedDagEdgeSupport

set_option autoImplicit false
set_option maxRecDepth 1000000
set_option maxHeartbeats 1000000
set_option Elab.async false

private theorem edge_part_5210_checked :
    (List.range 16).all (fun i => directedEdgeCheck (5210 + i)) = true := by
  decide

theorem edge_subblock_5210 (node : Nat) (lower : 5210 ≤ node)
    (upper : node < 5226) : directedEdgeCheck node = true :=
  block_sound 5210 16 node edge_part_5210_checked lower upper

end HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock5178Part02
