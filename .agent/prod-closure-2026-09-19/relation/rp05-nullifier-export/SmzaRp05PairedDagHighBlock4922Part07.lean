import SmzaRp05PairedDagEdgeSupport

/-! Exact 16-node directed-edge check for current/reference DAG nodes 5034 through 5049. -/
namespace HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock4922Part07

open HegemonCrypto.SmallWood.SmzaRp05PairedHashDagData
open HegemonCrypto.SmallWood.SmzaRp05PairedDagEdgeSupport

set_option autoImplicit false
set_option maxRecDepth 1000000
set_option maxHeartbeats 1000000
set_option Elab.async false

private theorem edge_part_5034_checked :
    (List.range 16).all (fun i => directedEdgeCheck (5034 + i)) = true := by
  decide

theorem edge_subblock_5034 (node : Nat) (lower : 5034 ≤ node)
    (upper : node < 5050) : directedEdgeCheck node = true :=
  block_sound 5034 16 node edge_part_5034_checked lower upper

end HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock4922Part07
