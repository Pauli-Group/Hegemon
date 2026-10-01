import SmzaRp05PairedDagEdgeSupport

/-! Exact 16-node directed-edge check for current/reference DAG nodes 5514 through 5529. -/
namespace HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock5434Part05

open HegemonCrypto.SmallWood.SmzaRp05PairedHashDagData
open HegemonCrypto.SmallWood.SmzaRp05PairedDagEdgeSupport

set_option autoImplicit false
set_option maxRecDepth 1000000
set_option maxHeartbeats 1000000
set_option Elab.async false

private theorem edge_part_5514_checked :
    (List.range 16).all (fun i => directedEdgeCheck (5514 + i)) = true := by
  decide

theorem edge_subblock_5514 (node : Nat) (lower : 5514 ≤ node)
    (upper : node < 5530) : directedEdgeCheck node = true :=
  block_sound 5514 16 node edge_part_5514_checked lower upper

end HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock5434Part05
