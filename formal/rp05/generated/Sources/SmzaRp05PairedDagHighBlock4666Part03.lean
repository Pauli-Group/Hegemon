import SmzaRp05PairedDagEdgeSupport

/-! Exact 16-node directed-edge check for current/reference DAG nodes 4714 through 4729. -/
namespace HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock4666Part03

open HegemonCrypto.SmallWood.SmzaRp05PairedHashDagData
open HegemonCrypto.SmallWood.SmzaRp05PairedDagEdgeSupport

set_option autoImplicit false
set_option maxRecDepth 1000000
set_option maxHeartbeats 1000000
set_option Elab.async false

private theorem edge_part_4714_checked :
    (List.range 16).all (fun i => directedEdgeCheck (4714 + i)) = true := by
  decide

theorem edge_subblock_4714 (node : Nat) (lower : 4714 ≤ node)
    (upper : node < 4730) : directedEdgeCheck node = true :=
  block_sound 4714 16 node edge_part_4714_checked lower upper

end HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock4666Part03
