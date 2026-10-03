import SmzaRp05PairedDagEdgeSupport

/-! Exact 16-node directed-edge check for current/reference DAG nodes 3306 through 3321. -/
namespace HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock3258Part03

open HegemonCrypto.SmallWood.SmzaRp05PairedHashDagData
open HegemonCrypto.SmallWood.SmzaRp05PairedDagEdgeSupport

set_option autoImplicit false
set_option maxRecDepth 1000000
set_option maxHeartbeats 1000000
set_option Elab.async false

private theorem edge_part_3306_checked :
    (List.range 16).all (fun i => directedEdgeCheck (3306 + i)) = true := by
  decide

theorem edge_subblock_3306 (node : Nat) (lower : 3306 ≤ node)
    (upper : node < 3322) : directedEdgeCheck node = true :=
  block_sound 3306 16 node edge_part_3306_checked lower upper

end HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock3258Part03
