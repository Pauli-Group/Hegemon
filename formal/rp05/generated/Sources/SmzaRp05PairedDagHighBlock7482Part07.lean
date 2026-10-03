import SmzaRp05PairedDagEdgeSupport

/-! Exact 16-node directed-edge check for current/reference DAG nodes 7594 through 7609. -/
namespace HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock7482Part07

open HegemonCrypto.SmallWood.SmzaRp05PairedHashDagData
open HegemonCrypto.SmallWood.SmzaRp05PairedDagEdgeSupport

set_option autoImplicit false
set_option maxRecDepth 1000000
set_option maxHeartbeats 1000000
set_option Elab.async false

private theorem edge_part_7594_checked :
    (List.range 16).all (fun i => directedEdgeCheck (7594 + i)) = true := by
  decide

theorem edge_subblock_7594 (node : Nat) (lower : 7594 ≤ node)
    (upper : node < 7610) : directedEdgeCheck node = true :=
  block_sound 7594 16 node edge_part_7594_checked lower upper

end HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock7482Part07
