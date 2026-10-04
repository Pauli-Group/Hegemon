import SmzaRp05PairedDagEdgeSupport

/-! Exact 16-node directed-edge check for current/reference DAG nodes 3786 through 3801. -/
namespace HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock3770Part01

open HegemonCrypto.SmallWood.SmzaRp05PairedHashDagData
open HegemonCrypto.SmallWood.SmzaRp05PairedDagEdgeSupport

set_option autoImplicit false
set_option maxRecDepth 1000000
set_option maxHeartbeats 1000000
set_option Elab.async false

private theorem edge_part_3786_checked :
    (List.range 16).all (fun i => directedEdgeCheck (3786 + i)) = true := by
  decide

theorem edge_subblock_3786 (node : Nat) (lower : 3786 ≤ node)
    (upper : node < 3802) : directedEdgeCheck node = true :=
  block_sound 3786 16 node edge_part_3786_checked lower upper

end HegemonCrypto.SmallWood.SmzaRp05PairedDagHighBlock3770Part01
