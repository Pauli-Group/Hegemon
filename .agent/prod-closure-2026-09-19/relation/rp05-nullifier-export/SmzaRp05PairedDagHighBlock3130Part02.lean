import SmzaRp05PairedDagEdgeSupport

/-! Exact 16-node directed-edge check for current/reference DAG nodes 3162 through 3177. -/
namespace HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock3130Part02

open HegemonCrypto.SmallWood.SmzaRp05PairedHashDagData
open HegemonCrypto.SmallWood.SmzaRp05PairedDagEdgeSupport

set_option autoImplicit false
set_option maxRecDepth 1000000
set_option maxHeartbeats 1000000
set_option Elab.async false

private theorem edge_block_3162_checked :
    (List.range 16).all (fun i => directedEdgeCheck (3162 + i)) = true := by
  decide

theorem edge_subblock_3162 (node : Nat) (lower : 3162 ≤ node)
    (upper : node < 3178) : directedEdgeCheck node = true :=
  block_sound 3162 16 node edge_block_3162_checked lower upper

end HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock3130Part02
