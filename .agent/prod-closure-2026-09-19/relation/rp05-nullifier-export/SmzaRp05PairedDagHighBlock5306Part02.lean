import SmzaRp05PairedDagEdgeSupport

/-! Exact 16-node directed-edge check for current/reference DAG nodes 5338 through 5353. -/
namespace HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock5306Part02

open HegemonCrypto.SmallWood.SmzaRp05PairedHashDagData
open HegemonCrypto.SmallWood.SmzaRp05PairedDagEdgeSupport

set_option autoImplicit false
set_option maxRecDepth 1000000
set_option maxHeartbeats 1000000
set_option Elab.async false

private theorem edge_part_5338_checked :
    (List.range 16).all (fun i => directedEdgeCheck (5338 + i)) = true := by
  decide

theorem edge_subblock_5338 (node : Nat) (lower : 5338 ≤ node)
    (upper : node < 5354) : directedEdgeCheck node = true :=
  block_sound 5338 16 node edge_part_5338_checked lower upper

end HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock5306Part02
