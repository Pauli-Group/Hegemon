import SmzaRp05PairedDagEdgeSupport

/-! Exact 16-node directed-edge check for current/reference DAG nodes 3242 through 3257. -/
namespace HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock3130Part07

open HegemonCrypto.SmallWood.SmzaRp05PairedHashDagData
open HegemonCrypto.SmallWood.SmzaRp05PairedDagEdgeSupport

set_option autoImplicit false
set_option maxRecDepth 1000000
set_option maxHeartbeats 1000000
set_option Elab.async false

private theorem edge_block_3242_checked :
    (List.range 16).all (fun i => directedEdgeCheck (3242 + i)) = true := by
  decide

theorem edge_subblock_3242 (node : Nat) (lower : 3242 ≤ node)
    (upper : node < 3258) : directedEdgeCheck node = true :=
  block_sound 3242 16 node edge_block_3242_checked lower upper

end HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock3130Part07
