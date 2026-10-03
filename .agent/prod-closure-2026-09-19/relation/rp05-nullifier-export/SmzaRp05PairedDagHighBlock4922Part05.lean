import SmzaRp05PairedDagEdgeSupport

/-! Exact 16-node directed-edge check for current/reference DAG nodes 5002 through 5017. -/
namespace HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock4922Part05

open HegemonCrypto.SmallWood.SmzaRp05PairedHashDagData
open HegemonCrypto.SmallWood.SmzaRp05PairedDagEdgeSupport

set_option autoImplicit false
set_option maxRecDepth 1000000
set_option maxHeartbeats 1000000
set_option Elab.async false

private theorem edge_part_5002_checked :
    (List.range 16).all (fun i => directedEdgeCheck (5002 + i)) = true := by
  decide

theorem edge_subblock_5002 (node : Nat) (lower : 5002 ≤ node)
    (upper : node < 5018) : directedEdgeCheck node = true :=
  block_sound 5002 16 node edge_part_5002_checked lower upper

end HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock4922Part05
