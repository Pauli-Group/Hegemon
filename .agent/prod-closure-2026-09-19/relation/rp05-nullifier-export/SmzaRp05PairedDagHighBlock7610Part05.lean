import SmzaRp05PairedDagEdgeSupport

/-! Exact 16-node directed-edge check for current/reference DAG nodes 7690 through 7705. -/
namespace HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock7610Part05

open HegemonCrypto.SmallWood.SmzaRp05PairedHashDagData
open HegemonCrypto.SmallWood.SmzaRp05PairedDagEdgeSupport

set_option autoImplicit false
set_option maxRecDepth 1000000
set_option maxHeartbeats 1000000
set_option Elab.async false

private theorem edge_part_7690_checked :
    (List.range 16).all (fun i => directedEdgeCheck (7690 + i)) = true := by
  decide

theorem edge_subblock_7690 (node : Nat) (lower : 7690 ≤ node)
    (upper : node < 7706) : directedEdgeCheck node = true :=
  block_sound 7690 16 node edge_part_7690_checked lower upper

end HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock7610Part05
