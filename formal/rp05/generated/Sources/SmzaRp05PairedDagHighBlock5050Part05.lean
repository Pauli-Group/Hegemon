import SmzaRp05PairedDagEdgeSupport

/-! Exact 16-node directed-edge check for current/reference DAG nodes 5130 through 5145. -/
namespace HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock5050Part05

open HegemonCrypto.SmallWood.SmzaRp05PairedHashDagData
open HegemonCrypto.SmallWood.SmzaRp05PairedDagEdgeSupport

set_option autoImplicit false
set_option maxRecDepth 1000000
set_option maxHeartbeats 1000000
set_option Elab.async false

private theorem edge_part_5130_checked :
    (List.range 16).all (fun i => directedEdgeCheck (5130 + i)) = true := by
  decide

theorem edge_subblock_5130 (node : Nat) (lower : 5130 ≤ node)
    (upper : node < 5146) : directedEdgeCheck node = true :=
  block_sound 5130 16 node edge_part_5130_checked lower upper

end HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock5050Part05
