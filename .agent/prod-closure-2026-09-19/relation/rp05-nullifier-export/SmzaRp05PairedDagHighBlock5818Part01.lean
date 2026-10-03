import SmzaRp05PairedDagEdgeSupport

/-! Exact 16-node directed-edge check for current/reference DAG nodes 5834 through 5849. -/
namespace HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock5818Part01

open HegemonCrypto.SmallWood.SmzaRp05PairedHashDagData
open HegemonCrypto.SmallWood.SmzaRp05PairedDagEdgeSupport

set_option autoImplicit false
set_option maxRecDepth 1000000
set_option maxHeartbeats 1000000
set_option Elab.async false

private theorem edge_part_5834_checked :
    (List.range 16).all (fun i => directedEdgeCheck (5834 + i)) = true := by
  decide

theorem edge_subblock_5834 (node : Nat) (lower : 5834 ≤ node)
    (upper : node < 5850) : directedEdgeCheck node = true :=
  block_sound 5834 16 node edge_part_5834_checked lower upper

end HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock5818Part01
