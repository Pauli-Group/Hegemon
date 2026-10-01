import SmzaRp05PairedDagEdgeSupport

/-! Exact 16-node directed-edge check for current/reference DAG nodes 5930 through 5945. -/
namespace HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock5818Part07

open HegemonCrypto.SmallWood.SmzaRp05PairedHashDagData
open HegemonCrypto.SmallWood.SmzaRp05PairedDagEdgeSupport

set_option autoImplicit false
set_option maxRecDepth 1000000
set_option maxHeartbeats 1000000
set_option Elab.async false

private theorem edge_part_5930_checked :
    (List.range 16).all (fun i => directedEdgeCheck (5930 + i)) = true := by
  decide

theorem edge_subblock_5930 (node : Nat) (lower : 5930 ≤ node)
    (upper : node < 5946) : directedEdgeCheck node = true :=
  block_sound 5930 16 node edge_part_5930_checked lower upper

end HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock5818Part07
