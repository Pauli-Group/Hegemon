import SmzaRp05PairedDagEdgeSupport

/-! Exact 16-node directed-edge check for current/reference DAG nodes 3226 through 3241. -/
namespace HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock3130Part06

open HegemonCrypto.SmallWood.SmzaRp05PairedHashDagData
open HegemonCrypto.SmallWood.SmzaRp05PairedDagEdgeSupport

set_option autoImplicit false
set_option maxRecDepth 1000000
set_option maxHeartbeats 1000000
set_option Elab.async false

private theorem edge_block_3226_checked :
    (List.range 16).all (fun i => directedEdgeCheck (3226 + i)) = true := by
  decide

theorem edge_subblock_3226 (node : Nat) (lower : 3226 ≤ node)
    (upper : node < 3242) : directedEdgeCheck node = true :=
  block_sound 3226 16 node edge_block_3226_checked lower upper

end HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock3130Part06
