import SmzaRp05PairedDagEdgeSupport

/-! Exact 16-node directed-edge check for current/reference DAG nodes 3194 through 3209. -/
namespace HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock3130Part04

open HegemonCrypto.SmallWood.SmzaRp05PairedHashDagData
open HegemonCrypto.SmallWood.SmzaRp05PairedDagEdgeSupport

set_option autoImplicit false
set_option maxRecDepth 1000000
set_option maxHeartbeats 1000000
set_option Elab.async false

private theorem edge_block_3194_checked :
    (List.range 16).all (fun i => directedEdgeCheck (3194 + i)) = true := by
  decide

theorem edge_subblock_3194 (node : Nat) (lower : 3194 ≤ node)
    (upper : node < 3210) : directedEdgeCheck node = true :=
  block_sound 3194 16 node edge_block_3194_checked lower upper

end HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock3130Part04
