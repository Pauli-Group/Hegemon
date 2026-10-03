import SmzaRp05PairedDagEdgeSupport

/-! Exact 16-node directed-edge check for current/reference DAG nodes 3834 through 3849. -/
namespace HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock3770Part04

open HegemonCrypto.SmallWood.SmzaRp05PairedHashDagData
open HegemonCrypto.SmallWood.SmzaRp05PairedDagEdgeSupport

set_option autoImplicit false
set_option maxRecDepth 1000000
set_option maxHeartbeats 1000000
set_option Elab.async false

private theorem edge_part_3834_checked :
    (List.range 16).all (fun i => directedEdgeCheck (3834 + i)) = true := by
  decide

theorem edge_subblock_3834 (node : Nat) (lower : 3834 ≤ node)
    (upper : node < 3850) : directedEdgeCheck node = true :=
  block_sound 3834 16 node edge_part_3834_checked lower upper

end HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock3770Part04
