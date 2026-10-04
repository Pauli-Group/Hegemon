import SmzaRp05PairedDagEdgeSupport

/-! Exact 16-node directed-edge check for current/reference DAG nodes 6746 through 6761. -/
namespace HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock6714Part02

open HegemonCrypto.SmallWood.SmzaRp05PairedHashDagData
open HegemonCrypto.SmallWood.SmzaRp05PairedDagEdgeSupport

set_option autoImplicit false
set_option maxRecDepth 1000000
set_option maxHeartbeats 1000000
set_option Elab.async false

private theorem edge_part_6746_checked :
    (List.range 16).all (fun i => directedEdgeCheck (6746 + i)) = true := by
  decide

theorem edge_subblock_6746 (node : Nat) (lower : 6746 ≤ node)
    (upper : node < 6762) : directedEdgeCheck node = true :=
  block_sound 6746 16 node edge_part_6746_checked lower upper

end HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock6714Part02
