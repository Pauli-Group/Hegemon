import SmzaRp05PairedDagEdgeSupport

/-! Exact 16-node directed-edge check for current/reference DAG nodes 6954 through 6969. -/
namespace HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock6842Part07

open HegemonCrypto.SmallWood.SmzaRp05PairedHashDagData
open HegemonCrypto.SmallWood.SmzaRp05PairedDagEdgeSupport

set_option autoImplicit false
set_option maxRecDepth 1000000
set_option maxHeartbeats 1000000
set_option Elab.async false

private theorem edge_part_6954_checked :
    (List.range 16).all (fun i => directedEdgeCheck (6954 + i)) = true := by
  decide

theorem edge_subblock_6954 (node : Nat) (lower : 6954 ≤ node)
    (upper : node < 6970) : directedEdgeCheck node = true :=
  block_sound 6954 16 node edge_part_6954_checked lower upper

end HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock6842Part07
