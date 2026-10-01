import SmzaRp05PairedDagEdgeSupport

/-! Exact 16-node directed-edge check for current/reference DAG nodes 6266 through 6281. -/
namespace HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock6202Part04

open HegemonCrypto.SmallWood.SmzaRp05PairedHashDagData
open HegemonCrypto.SmallWood.SmzaRp05PairedDagEdgeSupport

set_option autoImplicit false
set_option maxRecDepth 1000000
set_option maxHeartbeats 1000000
set_option Elab.async false

private theorem edge_part_6266_checked :
    (List.range 16).all (fun i => directedEdgeCheck (6266 + i)) = true := by
  decide

theorem edge_subblock_6266 (node : Nat) (lower : 6266 ≤ node)
    (upper : node < 6282) : directedEdgeCheck node = true :=
  block_sound 6266 16 node edge_part_6266_checked lower upper

end HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock6202Part04
