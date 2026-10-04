import SmzaRp05PairedDagEdgeSupport

/-! Exact 16-node directed-edge check for current/reference DAG nodes 6858 through 6873. -/
namespace HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock6842Part01

open HegemonCrypto.SmallWood.SmzaRp05PairedHashDagData
open HegemonCrypto.SmallWood.SmzaRp05PairedDagEdgeSupport

set_option autoImplicit false
set_option maxRecDepth 1000000
set_option maxHeartbeats 1000000
set_option Elab.async false

private theorem edge_part_6858_checked :
    (List.range 16).all (fun i => directedEdgeCheck (6858 + i)) = true := by
  decide

theorem edge_subblock_6858 (node : Nat) (lower : 6858 ≤ node)
    (upper : node < 6874) : directedEdgeCheck node = true :=
  block_sound 6858 16 node edge_part_6858_checked lower upper

end HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock6842Part01
