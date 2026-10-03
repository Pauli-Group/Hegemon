import SmzaRp05PairedDagEdgeSupport

/-! Exact 16-node directed-edge check for current/reference DAG nodes 7514 through 7529. -/
namespace HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock7482Part02

open HegemonCrypto.SmallWood.SmzaRp05PairedHashDagData
open HegemonCrypto.SmallWood.SmzaRp05PairedDagEdgeSupport

set_option autoImplicit false
set_option maxRecDepth 1000000
set_option maxHeartbeats 1000000
set_option Elab.async false

private theorem edge_part_7514_checked :
    (List.range 16).all (fun i => directedEdgeCheck (7514 + i)) = true := by
  decide

theorem edge_subblock_7514 (node : Nat) (lower : 7514 ≤ node)
    (upper : node < 7530) : directedEdgeCheck node = true :=
  block_sound 7514 16 node edge_part_7514_checked lower upper

end HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock7482Part02
