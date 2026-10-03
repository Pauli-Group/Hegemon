import SmzaRp05PairedDagEdgeSupport

/-! Exact 16-node directed-edge check for current/reference DAG nodes 3322 through 3337. -/
namespace HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock3258Part04

open HegemonCrypto.SmallWood.SmzaRp05PairedHashDagData
open HegemonCrypto.SmallWood.SmzaRp05PairedDagEdgeSupport

set_option autoImplicit false
set_option maxRecDepth 1000000
set_option maxHeartbeats 1000000
set_option Elab.async false

private theorem edge_part_3322_checked :
    (List.range 16).all (fun i => directedEdgeCheck (3322 + i)) = true := by
  decide

theorem edge_subblock_3322 (node : Nat) (lower : 3322 ≤ node)
    (upper : node < 3338) : directedEdgeCheck node = true :=
  block_sound 3322 16 node edge_part_3322_checked lower upper

end HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock3258Part04
