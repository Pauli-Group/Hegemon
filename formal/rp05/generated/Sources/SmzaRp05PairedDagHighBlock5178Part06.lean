import SmzaRp05PairedDagEdgeSupport

/-! Exact 16-node directed-edge check for current/reference DAG nodes 5274 through 5289. -/
namespace HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock5178Part06

open HegemonCrypto.SmallWood.SmzaRp05PairedHashDagData
open HegemonCrypto.SmallWood.SmzaRp05PairedDagEdgeSupport

set_option autoImplicit false
set_option maxRecDepth 1000000
set_option maxHeartbeats 1000000
set_option Elab.async false

private theorem edge_part_5274_checked :
    (List.range 16).all (fun i => directedEdgeCheck (5274 + i)) = true := by
  decide

theorem edge_subblock_5274 (node : Nat) (lower : 5274 ≤ node)
    (upper : node < 5290) : directedEdgeCheck node = true :=
  block_sound 5274 16 node edge_part_5274_checked lower upper

end HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock5178Part06
