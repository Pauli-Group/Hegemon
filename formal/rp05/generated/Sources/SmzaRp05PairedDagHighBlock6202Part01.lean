import SmzaRp05PairedDagEdgeSupport

/-! Exact 16-node directed-edge check for current/reference DAG nodes 6218 through 6233. -/
namespace HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock6202Part01

open HegemonCrypto.SmallWood.SmzaRp05PairedHashDagData
open HegemonCrypto.SmallWood.SmzaRp05PairedDagEdgeSupport

set_option autoImplicit false
set_option maxRecDepth 1000000
set_option maxHeartbeats 1000000
set_option Elab.async false

private theorem edge_part_6218_checked :
    (List.range 16).all (fun i => directedEdgeCheck (6218 + i)) = true := by
  decide

theorem edge_subblock_6218 (node : Nat) (lower : 6218 ≤ node)
    (upper : node < 6234) : directedEdgeCheck node = true :=
  block_sound 6218 16 node edge_part_6218_checked lower upper

end HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock6202Part01
