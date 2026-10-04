import SmzaRp05PairedDagEdgeSupport

/-! Exact 16-node directed-edge check for current/reference DAG nodes 6922 through 6937. -/
namespace HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock6842Part05

open HegemonCrypto.SmallWood.SmzaRp05PairedHashDagData
open HegemonCrypto.SmallWood.SmzaRp05PairedDagEdgeSupport

set_option autoImplicit false
set_option maxRecDepth 1000000
set_option maxHeartbeats 1000000
set_option Elab.async false

private theorem edge_part_6922_checked :
    (List.range 16).all (fun i => directedEdgeCheck (6922 + i)) = true := by
  decide

theorem edge_subblock_6922 (node : Nat) (lower : 6922 ≤ node)
    (upper : node < 6938) : directedEdgeCheck node = true :=
  block_sound 6922 16 node edge_part_6922_checked lower upper

end HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock6842Part05
