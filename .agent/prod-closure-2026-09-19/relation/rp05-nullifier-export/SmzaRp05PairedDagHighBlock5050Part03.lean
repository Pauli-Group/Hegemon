import SmzaRp05PairedDagEdgeSupport

/-! Exact 16-node directed-edge check for current/reference DAG nodes 5098 through 5113. -/
namespace HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock5050Part03

open HegemonCrypto.SmallWood.SmzaRp05PairedHashDagData
open HegemonCrypto.SmallWood.SmzaRp05PairedDagEdgeSupport

set_option autoImplicit false
set_option maxRecDepth 1000000
set_option maxHeartbeats 1000000
set_option Elab.async false

private theorem edge_part_5098_checked :
    (List.range 16).all (fun i => directedEdgeCheck (5098 + i)) = true := by
  decide

theorem edge_subblock_5098 (node : Nat) (lower : 5098 ≤ node)
    (upper : node < 5114) : directedEdgeCheck node = true :=
  block_sound 5098 16 node edge_part_5098_checked lower upper

end HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock5050Part03
