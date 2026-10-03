import SmzaRp05PairedDagEdgeSupport

/-! Exact 16-node directed-edge check for current/reference DAG nodes 3290 through 3305. -/
namespace HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock3258Part02

open HegemonCrypto.SmallWood.SmzaRp05PairedHashDagData
open HegemonCrypto.SmallWood.SmzaRp05PairedDagEdgeSupport

set_option autoImplicit false
set_option maxRecDepth 1000000
set_option maxHeartbeats 1000000
set_option Elab.async false

private theorem edge_part_3290_checked :
    (List.range 16).all (fun i => directedEdgeCheck (3290 + i)) = true := by
  decide

theorem edge_subblock_3290 (node : Nat) (lower : 3290 ≤ node)
    (upper : node < 3306) : directedEdgeCheck node = true :=
  block_sound 3290 16 node edge_part_3290_checked lower upper

end HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock3258Part02
