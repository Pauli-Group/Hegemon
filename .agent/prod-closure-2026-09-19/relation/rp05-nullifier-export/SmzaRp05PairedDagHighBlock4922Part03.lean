import SmzaRp05PairedDagEdgeSupport

/-! Exact 16-node directed-edge check for current/reference DAG nodes 4970 through 4985. -/
namespace HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock4922Part03

open HegemonCrypto.SmallWood.SmzaRp05PairedHashDagData
open HegemonCrypto.SmallWood.SmzaRp05PairedDagEdgeSupport

set_option autoImplicit false
set_option maxRecDepth 1000000
set_option maxHeartbeats 1000000
set_option Elab.async false

private theorem edge_part_4970_checked :
    (List.range 16).all (fun i => directedEdgeCheck (4970 + i)) = true := by
  decide

theorem edge_subblock_4970 (node : Nat) (lower : 4970 ≤ node)
    (upper : node < 4986) : directedEdgeCheck node = true :=
  block_sound 4970 16 node edge_part_4970_checked lower upper

end HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock4922Part03
