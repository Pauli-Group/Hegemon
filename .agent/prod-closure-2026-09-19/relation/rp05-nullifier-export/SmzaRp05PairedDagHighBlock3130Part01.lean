import SmzaRp05PairedDagEdgeSupport

/-! Exact 16-node directed-edge check for current/reference DAG nodes 3146 through 3161. -/
namespace HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock3130Part01

open HegemonCrypto.SmallWood.SmzaRp05PairedHashDagData
open HegemonCrypto.SmallWood.SmzaRp05PairedDagEdgeSupport

set_option autoImplicit false
set_option maxRecDepth 1000000
set_option maxHeartbeats 1000000
set_option Elab.async false

private theorem edge_block_3146_checked :
    (List.range 16).all (fun i => directedEdgeCheck (3146 + i)) = true := by
  decide

theorem edge_subblock_3146 (node : Nat) (lower : 3146 ≤ node)
    (upper : node < 3162) : directedEdgeCheck node = true :=
  block_sound 3146 16 node edge_block_3146_checked lower upper

end HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock3130Part01
