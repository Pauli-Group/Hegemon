import SmzaRp05PairedDagEdgeSupport

/-! Exact 16-node directed-edge check for current/reference DAG nodes 6906 through 6921. -/
namespace HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock6842Part04

open HegemonCrypto.SmallWood.SmzaRp05PairedHashDagData
open HegemonCrypto.SmallWood.SmzaRp05PairedDagEdgeSupport

set_option autoImplicit false
set_option maxRecDepth 1000000
set_option maxHeartbeats 1000000
set_option Elab.async false

private theorem edge_part_6906_checked :
    (List.range 16).all (fun i => directedEdgeCheck (6906 + i)) = true := by
  decide

theorem edge_subblock_6906 (node : Nat) (lower : 6906 ≤ node)
    (upper : node < 6922) : directedEdgeCheck node = true :=
  block_sound 6906 16 node edge_part_6906_checked lower upper

end HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock6842Part04
