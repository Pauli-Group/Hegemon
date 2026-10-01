import SmzaRp05PairedDagEdgeSupport

/-! Exact 16-node directed-edge check for current/reference DAG nodes 3962 through 3977. -/
namespace HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock3898Part04

open HegemonCrypto.SmallWood.SmzaRp05PairedHashDagData
open HegemonCrypto.SmallWood.SmzaRp05PairedDagEdgeSupport

set_option autoImplicit false
set_option maxRecDepth 1000000
set_option maxHeartbeats 1000000
set_option Elab.async false

private theorem edge_part_3962_checked :
    (List.range 16).all (fun i => directedEdgeCheck (3962 + i)) = true := by
  decide

theorem edge_subblock_3962 (node : Nat) (lower : 3962 ≤ node)
    (upper : node < 3978) : directedEdgeCheck node = true :=
  block_sound 3962 16 node edge_part_3962_checked lower upper

end HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock3898Part04
