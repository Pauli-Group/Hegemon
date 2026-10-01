import SmzaRp05PairedDagEdgeSupport

/-! Exact 16-node directed-edge check for current/reference DAG nodes 3930 through 3945. -/
namespace HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock3898Part02

open HegemonCrypto.SmallWood.SmzaRp05PairedHashDagData
open HegemonCrypto.SmallWood.SmzaRp05PairedDagEdgeSupport

set_option autoImplicit false
set_option maxRecDepth 1000000
set_option maxHeartbeats 1000000
set_option Elab.async false

private theorem edge_part_3930_checked :
    (List.range 16).all (fun i => directedEdgeCheck (3930 + i)) = true := by
  decide

theorem edge_subblock_3930 (node : Nat) (lower : 3930 ≤ node)
    (upper : node < 3946) : directedEdgeCheck node = true :=
  block_sound 3930 16 node edge_part_3930_checked lower upper

end HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock3898Part02
