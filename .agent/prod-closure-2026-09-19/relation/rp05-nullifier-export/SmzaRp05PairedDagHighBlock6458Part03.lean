import SmzaRp05PairedDagEdgeSupport

/-! Exact 16-node directed-edge check for current/reference DAG nodes 6506 through 6521. -/
namespace HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock6458Part03

open HegemonCrypto.SmallWood.SmzaRp05PairedHashDagData
open HegemonCrypto.SmallWood.SmzaRp05PairedDagEdgeSupport

set_option autoImplicit false
set_option maxRecDepth 1000000
set_option maxHeartbeats 1000000
set_option Elab.async false

private theorem edge_part_6506_checked :
    (List.range 16).all (fun i => directedEdgeCheck (6506 + i)) = true := by
  decide

theorem edge_subblock_6506 (node : Nat) (lower : 6506 ≤ node)
    (upper : node < 6522) : directedEdgeCheck node = true :=
  block_sound 6506 16 node edge_part_6506_checked lower upper

end HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock6458Part03
