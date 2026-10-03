import SmzaRp05PairedDagEdgeSupport

/-! Exact 16-node directed-edge check for current/reference DAG nodes 7050 through 7065. -/
namespace HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock6970Part05

open HegemonCrypto.SmallWood.SmzaRp05PairedHashDagData
open HegemonCrypto.SmallWood.SmzaRp05PairedDagEdgeSupport

set_option autoImplicit false
set_option maxRecDepth 1000000
set_option maxHeartbeats 1000000
set_option Elab.async false

private theorem edge_part_7050_checked :
    (List.range 16).all (fun i => directedEdgeCheck (7050 + i)) = true := by
  decide

theorem edge_subblock_7050 (node : Nat) (lower : 7050 ≤ node)
    (upper : node < 7066) : directedEdgeCheck node = true :=
  block_sound 7050 16 node edge_part_7050_checked lower upper

end HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock6970Part05
