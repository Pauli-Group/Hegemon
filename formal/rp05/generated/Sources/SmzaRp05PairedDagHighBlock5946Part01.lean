import SmzaRp05PairedDagEdgeSupport

/-! Exact 16-node directed-edge check for current/reference DAG nodes 5962 through 5977. -/
namespace HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock5946Part01

open HegemonCrypto.SmallWood.SmzaRp05PairedHashDagData
open HegemonCrypto.SmallWood.SmzaRp05PairedDagEdgeSupport

set_option autoImplicit false
set_option maxRecDepth 1000000
set_option maxHeartbeats 1000000
set_option Elab.async false

private theorem edge_part_5962_checked :
    (List.range 16).all (fun i => directedEdgeCheck (5962 + i)) = true := by
  decide

theorem edge_subblock_5962 (node : Nat) (lower : 5962 ≤ node)
    (upper : node < 5978) : directedEdgeCheck node = true :=
  block_sound 5962 16 node edge_part_5962_checked lower upper

end HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock5946Part01
