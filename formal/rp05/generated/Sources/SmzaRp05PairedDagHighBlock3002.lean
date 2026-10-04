import SmzaRp05PairedDagEdgeSupport

/-! Exact single-block directed-edge check for current/reference DAG nodes 3002 through 3129. -/
namespace HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock3002

open HegemonCrypto.SmallWood.SmzaRp05PairedHashDagData
open HegemonCrypto.SmallWood.SmzaRp05PairedDagEdgeSupport

set_option autoImplicit false
set_option maxRecDepth 1000000
set_option maxHeartbeats 1000000
set_option Elab.async false

private theorem edge_block_3002_checked :
    (List.range 128).all (fun i => directedEdgeCheck (3002 + i)) = true := by
  decide

theorem edge_block_3002 (node : Nat) (lower : 3002 ≤ node)
    (upper : node < 3130) : directedEdgeCheck node = true :=
  block_sound 3002 128 node edge_block_3002_checked lower upper

end HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock3002
