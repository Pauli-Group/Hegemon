import SmzaRp05PairedDagEdgeSupport

/-! Exact 16-node directed-edge check for current/reference DAG nodes 6394 through 6409. -/
namespace HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock6330Part04

open HegemonCrypto.SmallWood.SmzaRp05PairedHashDagData
open HegemonCrypto.SmallWood.SmzaRp05PairedDagEdgeSupport

set_option autoImplicit false
set_option maxRecDepth 1000000
set_option maxHeartbeats 1000000
set_option Elab.async false

private theorem edge_part_6394_checked :
    (List.range 16).all (fun i => directedEdgeCheck (6394 + i)) = true := by
  decide

theorem edge_subblock_6394 (node : Nat) (lower : 6394 ≤ node)
    (upper : node < 6410) : directedEdgeCheck node = true :=
  block_sound 6394 16 node edge_part_6394_checked lower upper

end HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock6330Part04
