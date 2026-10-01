import SmzaRp05PairedDagEdgeSupport

/-! Exact 16-node directed-edge check for current/reference DAG nodes 5306 through 5321. -/
namespace HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock5306Part00

open HegemonCrypto.SmallWood.SmzaRp05PairedHashDagData
open HegemonCrypto.SmallWood.SmzaRp05PairedDagEdgeSupport

set_option autoImplicit false
set_option maxRecDepth 1000000
set_option maxHeartbeats 1000000
set_option Elab.async false

private theorem edge_part_5306_checked :
    (List.range 16).all (fun i => directedEdgeCheck (5306 + i)) = true := by
  decide

theorem edge_subblock_5306 (node : Nat) (lower : 5306 ≤ node)
    (upper : node < 5322) : directedEdgeCheck node = true :=
  block_sound 5306 16 node edge_part_5306_checked lower upper

end HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock5306Part00
