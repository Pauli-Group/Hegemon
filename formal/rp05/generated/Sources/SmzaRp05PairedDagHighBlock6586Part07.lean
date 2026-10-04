import SmzaRp05PairedDagEdgeSupport

/-! Exact 16-node directed-edge check for current/reference DAG nodes 6698 through 6713. -/
namespace HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock6586Part07

open HegemonCrypto.SmallWood.SmzaRp05PairedHashDagData
open HegemonCrypto.SmallWood.SmzaRp05PairedDagEdgeSupport

set_option autoImplicit false
set_option maxRecDepth 1000000
set_option maxHeartbeats 1000000
set_option Elab.async false

private theorem edge_part_6698_checked :
    (List.range 16).all (fun i => directedEdgeCheck (6698 + i)) = true := by
  decide

theorem edge_subblock_6698 (node : Nat) (lower : 6698 ≤ node)
    (upper : node < 6714) : directedEdgeCheck node = true :=
  block_sound 6698 16 node edge_part_6698_checked lower upper

end HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock6586Part07
